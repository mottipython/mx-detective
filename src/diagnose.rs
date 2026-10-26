use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::dns::DnsResolver;
use crate::models::{CheckItem, DiagnosticResult, MxHost, ServerResult, Severity};
use crate::policy;
use crate::ports::PortProber;
use crate::smtp::{ProbeOptions, SmtpProber};

/// Addresses tested per MX host and address family, and in total.
const MAX_IPS_PER_FAMILY: usize = 4;
const MAX_TARGETS: usize = 24;

#[derive(Debug, Clone)]
pub struct DiagnosticOptions {
    pub domain: String,
    pub host_override: Option<String>,
    pub port: u16,
    pub timeout: Duration,
    pub recipient: Option<String>,
    pub test_relay: bool,
    pub dkim_selector: Option<String>,
    /// Test only the most preferred MX host instead of every address of every host.
    pub primary_only: bool,
    pub ipv6: bool,
    pub dnsbl: bool,
    /// Postmaster, catch-all and VRFY/EXPN probes.
    pub extended: bool,
}

impl Default for DiagnosticOptions {
    fn default() -> Self {
        Self {
            domain: String::new(),
            host_override: None,
            port: 25,
            timeout: Duration::from_secs(5),
            recipient: None,
            test_relay: true,
            dkim_selector: None,
            primary_only: false,
            ipv6: true,
            dnsbl: true,
            extended: true,
        }
    }
}

struct Target {
    hostname: String,
    priority: u16,
    addr: SocketAddr,
}

/// True when this machine has a route to the IPv6 internet. Connecting a UDP socket
/// sends nothing; it only asks the kernel for a route.
pub fn has_ipv6_route() -> bool {
    UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2001:4860:4860::8888]:53"))
        .is_ok()
}

pub fn run(opts: &DiagnosticOptions, progress: &dyn Fn(&str)) -> DiagnosticResult {
    let domain = opts.domain.trim().trim_end_matches('.').to_lowercase();
    let resolver = DnsResolver::new(opts.timeout);
    let mut result = DiagnosticResult::new(domain.clone(), opts.host_override.clone());

    progress(&format!(
        "Querying MX, A/AAAA, PTR, SPF, DMARC and DKIM records for {}...",
        domain
    ));
    let (mut dns, dns_checks) = resolver.resolve_all(&domain, opts.dkim_selector.as_deref());
    result.checks.extend(dns_checks);

    progress("Checking DNSSEC, DANE/TLSA, MTA-STS, TLS-RPT and BIMI...");
    policy::check_dnssec(&resolver, &domain, &mut dns, &mut result.checks);
    policy::check_dane_records(&resolver, &mut dns, &mut result.checks);
    policy::check_mta_sts(&resolver, &domain, opts.timeout, &mut dns, &mut result.checks);
    policy::check_tls_rpt(&resolver, &domain, &mut dns, &mut result.checks);
    policy::check_bimi(&resolver, &domain, &mut dns, &mut result.checks);
    if opts.dnsbl {
        progress("Checking MX IPs against DNS blocklists...");
        policy::check_dnsbl(&resolver, &mut dns, &mut result.checks);
    }

    let v6_ok = opts.ipv6 && has_ipv6_route();
    let hosts: Vec<MxHost> = match &opts.host_override {
        Some(h) => vec![override_host(&resolver, h)],
        None => dns
            .mx_hosts
            .iter()
            .filter(|h| !h.is_null_mx && !h.hostname.is_empty())
            .cloned()
            .collect(),
    };
    let targets = pick_targets(&hosts, opts.port, opts.primary_only, v6_ok);
    let any_v6_published = hosts.iter().any(|h| !h.ipv6_addresses.is_empty());
    if opts.ipv6 && !v6_ok && any_v6_published {
        result.checks.push(CheckItem::new(
            "IPV6_NOT_TESTED",
            "NETWORK",
            Severity::Info,
            "IPv6 Not Tested (No IPv6 Route From This Machine)",
            "The MX hosts publish AAAA records, but this machine has no IPv6 connectivity, so only IPv4 was tested.",
        ));
    }

    result.target_host = targets
        .first()
        .map(|t| t.hostname.clone())
        .or_else(|| opts.host_override.clone());
    result.target_ip = targets.first().map(|t| t.addr.ip().to_string());

    let Some(primary) = targets.first() else {
        result.dns = Some(dns);
        result.calculate_score();
        return result;
    };

    progress(&format!(
        "Probing mail ports (25, 587, 465, 2525) on {}...",
        primary.hostname
    ));
    let (probes, port_checks, p25_blocked) =
        PortProber::new(opts.timeout).probe_mail_ports(&primary.hostname, primary.addr.ip());
    result.port_probes = probes;
    result.port_25_blocked_suspected = p25_blocked && opts.port == 25;
    // Port 25 only matters as the port under test.
    result.checks.extend(port_checks.into_iter().map(|mut c| {
        if opts.port != 25 && c.check_id == "PORT_25_CLOSED" {
            c.severity = Severity::Info;
        }
        c
    }));

    progress(&format!(
        "Running SMTP sessions against {} address(es) on {} host(s)...",
        targets.len(),
        {
            let mut names: Vec<&str> = targets.iter().map(|t| t.hostname.as_str()).collect();
            names.dedup();
            names.len()
        }
    ));
    let prober = SmtpProber::new(opts.timeout);
    let sessions: Vec<(ServerResult, Vec<CheckItem>)> = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|t| {
                let probe_opts = ProbeOptions {
                    domain: Some(domain.clone()),
                    test_relay: opts.test_relay,
                    recipient: opts.recipient.clone(),
                    audit_tls: true,
                    tlsa: hosts
                        .iter()
                        .chain(dns.mx_hosts.iter())
                        .find(|h| h.hostname == t.hostname)
                        .map(|h| h.tlsa_records.clone())
                        .unwrap_or_default(),
                    extended: opts.extended,
                };
                let prober = &prober;
                s.spawn(move || {
                    let (smtp, tls, checks) = prober.probe(&t.hostname, t.addr, &probe_opts);
                    (
                        ServerResult {
                            hostname: t.hostname.clone(),
                            ip: t.addr.ip().to_string(),
                            priority: t.priority,
                            smtp,
                            tls,
                        },
                        checks,
                    )
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let labelled: Vec<(String, Vec<CheckItem>)> = sessions
        .iter()
        .map(|(s, c)| (format!("{} ({})", s.hostname, s.ip), c.clone()))
        .collect();
    result.checks.extend(merge_checks(labelled));
    result.servers = sessions.into_iter().map(|(s, _)| s).collect();

    cross_checks(&mut result, &dns, &hosts, v6_ok);

    if let Some(first) = result.servers.first() {
        result.smtp = Some(first.smtp.clone());
        result.tls = first.tls.clone();
    }
    result.dns = Some(dns);
    result.calculate_score();
    result
}

fn override_host(resolver: &DnsResolver, host: &str) -> MxHost {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let mut mx = MxHost {
        hostname: host.clone(),
        ..Default::default()
    };
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => mx.ipv4_addresses.push(v4.to_string()),
        Ok(IpAddr::V6(v6)) => mx.ipv6_addresses.push(v6.to_string()),
        Err(_) => {
            mx.ipv4_addresses = resolver.query_a(&host).unwrap_or_default();
            mx.ipv6_addresses = resolver.query_aaaa(&host).unwrap_or_default();
            if let Ok((recs, ad)) = resolver.query_tlsa(&host) {
                mx.tlsa_records = recs;
                mx.tlsa_dnssec_valid = ad;
            }
        }
    }
    mx
}

fn pick_targets(hosts: &[MxHost], port: u16, primary_only: bool, v6_ok: bool) -> Vec<Target> {
    let mut out = Vec::new();
    let per_family = if primary_only { 1 } else { MAX_IPS_PER_FAMILY };
    for h in hosts.iter().take(if primary_only { 1 } else { usize::MAX }) {
        let v6: &[String] = if v6_ok { &h.ipv6_addresses } else { &[] };
        for ip in h
            .ipv4_addresses
            .iter()
            .take(per_family)
            .chain(v6.iter().take(per_family))
        {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                out.push(Target {
                    hostname: h.hostname.clone(),
                    priority: h.priority,
                    addr: SocketAddr::new(addr, port),
                });
            }
        }
    }
    out.truncate(MAX_TARGETS);
    out
}

/// Collapses the same finding from several servers into one, listing where it was
/// seen, so one misconfiguration shared by ten servers is not scored ten times.
pub fn merge_checks(per_target: Vec<(String, Vec<CheckItem>)>) -> Vec<CheckItem> {
    let total = per_target.len();
    if total <= 1 {
        return per_target.into_iter().flat_map(|(_, c)| c).collect();
    }
    let mut order: Vec<String> = Vec::new();
    let mut grouped: BTreeMap<String, (CheckItem, Vec<String>)> = BTreeMap::new();
    for (label, checks) in per_target {
        for c in checks {
            let key = format!("{}|{:?}", c.check_id, c.severity);
            match grouped.get_mut(&key) {
                Some((_, labels)) => {
                    if !labels.contains(&label) {
                        labels.push(label.clone());
                    }
                }
                None => {
                    order.push(key.clone());
                    grouped.insert(key, (c, vec![label.clone()]));
                }
            }
        }
    }
    order
        .into_iter()
        .filter_map(|k| grouped.remove(&k))
        .map(|(mut c, labels)| {
            if labels.len() == total {
                c.message = format!("{} [all {} servers tested]", c.message, total);
            } else {
                c.message = format!(
                    "{} [{} of {} servers: {}]",
                    c.message,
                    labels.len(),
                    total,
                    labels.join(", ")
                );
            }
            c
        })
        .collect()
}

fn cross_checks(result: &mut DiagnosticResult, dns: &crate::models::DnsReport, hosts: &[MxHost], v6_ok: bool) {
    let label = |s: &ServerResult| format!("{} ({})", s.hostname, s.ip);

    // MTA-STS enforce: every server must offer STARTTLS with a trusted, matching certificate.
    if let Some(sts) = &dns.mta_sts {
        if sts.policy_fetched && sts.mode.as_deref() == Some("enforce") {
            let failing: Vec<String> = result
                .servers
                .iter()
                .filter(|s| s.smtp.esmtp_supported)
                .filter(|s| {
                    !s.tls
                        .as_ref()
                        .map(|t| t.handshake_success && t.chain_verified)
                        .unwrap_or(false)
                })
                .map(label)
                .collect();
            if !failing.is_empty() {
                result.checks.push(CheckItem::new("MTA_STS_ENFORCE_TLS_FAIL", "TLS", Severity::Critical, "MTA-STS Enforce Mode but TLS Fails Verification", format!("The policy is in enforce mode, so MTA-STS senders (Gmail, Outlook, Yahoo) will not deliver to: {}. They need STARTTLS with a publicly trusted certificate matching the MX name.", failing.join(", "))).fix("Fix the certificate on these servers, or switch the policy to mode: testing until it is fixed."));
            }
        }
    }

    // DANE: a host that publishes TLSA but cannot do TLS is undeliverable for DANE senders.
    for s in &result.servers {
        let has_tlsa = hosts
            .iter()
            .chain(dns.mx_hosts.iter())
            .any(|h| h.hostname == s.hostname && !h.tlsa_records.is_empty() && h.tlsa_dnssec_valid == Some(true));
        let tls_ok = s.tls.as_ref().map(|t| t.handshake_success).unwrap_or(false);
        if has_tlsa && s.smtp.esmtp_supported && !tls_ok {
            result.checks.push(CheckItem::new(format!("DANE_NO_TLS_{}", s.ip), "TLS", Severity::Critical, format!("DANE Published but TLS Unavailable ({})", label(s)), "This host has DNSSEC-signed TLSA records, so DANE senders require TLS, but the STARTTLS handshake did not succeed. They will defer mail.").fix("Restore STARTTLS on this server or withdraw the TLSA records."));
        }
    }

    // IPv6 broken while IPv4 works on the same host: senders that prefer IPv6 time out first.
    if v6_ok {
        let mut by_host: BTreeMap<&str, (bool, bool, bool)> = BTreeMap::new(); // (v4 ok, v6 tried, v6 ok)
        for s in &result.servers {
            let e = by_host.entry(s.hostname.as_str()).or_default();
            if s.ip.contains(':') {
                e.1 = true;
                e.2 |= s.smtp.connected;
            } else {
                e.0 |= s.smtp.connected;
            }
        }
        let broken: Vec<&str> = by_host
            .iter()
            .filter(|(_, (v4, tried, v6))| *v4 && *tried && !*v6)
            .map(|(h, _)| *h)
            .collect();
        if !broken.is_empty() {
            result.checks.push(CheckItem::new("IPV6_BROKEN", "NETWORK", Severity::Warning, "SMTP Fails over IPv6 but Works over IPv4", format!("{} publish AAAA records but port 25 does not answer over IPv6. Senders that prefer IPv6 (Gmail does) wait for a timeout on every message before falling back.", broken.join(", "))).fix("Fix the IPv6 listener or firewall, or remove the AAAA records."));
        }
    }

    // Addresses of one MX host should behave the same.
    let mut by_host: BTreeMap<&str, Vec<&ServerResult>> = BTreeMap::new();
    for s in &result.servers {
        by_host.entry(s.hostname.as_str()).or_default().push(s);
    }
    for (host, servers) in by_host {
        if servers.len() < 2 {
            continue;
        }
        let mut diffs = Vec::new();
        let differs = |f: &dyn Fn(&ServerResult) -> String| {
            let vals: Vec<String> = servers.iter().map(|s| format!("{}={}", s.ip, f(s))).collect();
            let first = f(servers[0]);
            if servers.iter().any(|s| f(s) != first) {
                Some(vals.join(", "))
            } else {
                None
            }
        };
        if let Some(d) = differs(&|s| if s.smtp.connected { "reachable" } else { "unreachable" }.to_string()) {
            diffs.push(format!("reachability ({})", d));
        }
        let reachable: Vec<&&ServerResult> = servers.iter().filter(|s| s.smtp.connected).collect();
        if reachable.len() >= 2 {
            let first_tls = reachable[0].smtp.starttls_advertised;
            if reachable.iter().any(|s| s.smtp.starttls_advertised != first_tls) {
                diffs.push("STARTTLS offered on some addresses only".to_string());
            }
            let trust = |s: &ServerResult| s.tls.as_ref().map(|t| t.chain_verified).unwrap_or(false);
            let first_trust = trust(reachable[0]);
            if reachable.iter().any(|s| trust(s) != first_trust) {
                diffs.push("certificate trusted on some addresses only".to_string());
            }
        }
        if !diffs.is_empty() {
            result.checks.push(
                CheckItem::new(
                    format!("MX_INCONSISTENT_{}", host),
                    "NETWORK",
                    Severity::Warning,
                    format!("Addresses of {} Behave Differently", host),
                    format!(
                        "Senders pick one address at random, so delivery depends on luck: {}.",
                        diffs.join("; ")
                    ),
                )
                .fix("Bring every server behind this name to the same configuration."),
            );
        }
    }
}
