use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

use crate::models::{CheckItem, DkimKey, DnsReport, MxHost, Severity, TlsaRecord};
use crate::platform;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_TLSA: u16 = 52;

/// Selectors used by common mail providers and sending services. DNS cannot list
/// selectors, so these are tried in parallel; --dkim-selector adds others.
#[rustfmt::skip]
pub const DKIM_SELECTORS: &[&str] = &[
    // Generic and MTA defaults (cPanel, Plesk, DirectAdmin, Postfix/OpenDKIM, Exim)
    "default", "dkim", "dkim1", "dkim2", "mail", "email", "smtp", "mx", "mta", "key1", "key2", "key3", "s1", "s2",
    "s3", "s1024", "s2048", "sig1", "sig2", "x", "dk", "domainkey", "selector", "k1", "k2", "k3",
    // Google Workspace / Gmail
    "google", "google2048", "20161025", "20210112", "20221208", "20230601",
    // Microsoft 365
    "selector1", "selector2",
    // Amazon SES (custom MAIL FROM setups), SendGrid, Mailgun, Mailchimp/Mandrill
    "amazonses", "smtpapi", "sm", "em", "mailo", "krs", "mg", "mailgun", "pic", "mandrill", "mte1", "mte2",
    // Postmark, SparkPost, Mailjet, Brevo/Sendinblue, MailerLite, Klaviyo, Constant Contact
    "pm", "pm2", "sparkpost", "scph0316", "mailjet", "brevo1", "brevo2", "sib", "mlsend", "mlsend2", "litesrv",
    "kl", "kl2", "ctct1", "ctct2", "cm",
    // CRM and helpdesk senders
    "hs1", "hs2", "sf1", "sf2", "zendesk1", "zendesk2", "fd", "fd2", "intercom", "ic", "everlytickey1",
    "everlytickey2",
    // Mailbox providers and hosts
    "zoho", "zmail", "fm1", "fm2", "fm3", "mesmtp", "protonmail", "protonmail2", "protonmail3", "yahoo",
    "s1-ionos", "s2-ionos", "gm1", "gm2", "gm3", "ovh", "mimecast", "turbo-smtp", "mxvault", "shopify",
    "mailchannels",
];

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

/// Public resolvers that validate DNSSEC, asked only to read the AD bit when the
/// system resolver does not validate.
/// A long-standing DNSSEC-signed name, used to check that a resolver validates.
/// DKIM selectors queried at the same time.
const DKIM_PARALLEL_LOOKUPS: usize = 16;

const DNSSEC_PROBE_NAME: &str = "ietf.org";

const VALIDATING_RESOLVERS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Mx(u16, String),
    Txt(String),
    Ptr(String),
    Cname(String),
    Tlsa(TlsaRecord),
    Other,
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub data: RData,
}

#[derive(Debug, Clone, Default)]
pub struct DnsMessage {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub authentic_data: bool,
    pub answers: Vec<ResourceRecord>,
}

impl DnsMessage {
    pub fn mx(&self) -> Vec<(u16, String)> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Mx(p, h) => Some((*p, h.clone())),
                _ => None,
            })
            .collect()
    }

    /// Addresses from A and AAAA answers.
    pub fn ips(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(ip) => Some(ip.to_string()),
                RData::Aaaa(ip) => Some(ip.to_string()),
                _ => None,
            })
            .collect()
    }

    pub fn txt(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Txt(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn ptr(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Ptr(p) => Some(p.trim_end_matches('.').to_string()),
                _ => None,
            })
            .collect()
    }

    pub fn tlsa(&self) -> Vec<TlsaRecord> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Tlsa(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }
}

pub struct DnsResolver {
    nameservers: Vec<SocketAddr>,
    timeout: Duration,
    /// First resolver shown to validate DNSSEC, found on first use.
    validator: OnceLock<Option<SocketAddr>>,
}

impl DnsResolver {
    pub fn new(timeout: Duration) -> Self {
        let mut servers = Self::system_nameservers();
        if servers.is_empty() {
            servers.extend(VALIDATING_RESOLVERS.iter().filter_map(|s| s.parse::<SocketAddr>().ok()));
        }
        Self::with_nameservers(servers, timeout)
    }

    pub fn with_nameservers(nameservers: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            nameservers,
            timeout,
            validator: OnceLock::new(),
        }
    }

    fn system_nameservers() -> Vec<SocketAddr> {
        platform::system_dns_servers()
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 53))
            .collect()
    }

    pub fn resolve_all(&self, domain: &str, custom_selector: Option<&str>) -> (DnsReport, Vec<CheckItem>) {
        let clean_domain = domain.trim().trim_end_matches('.').to_lowercase();
        let mut checks = Vec::new();
        let mut report = DnsReport {
            domain: clean_domain.clone(),
            dmarc_pct: 100,
            ..Default::default()
        };

        self.check_mx_records(&clean_domain, &mut report, &mut checks);
        self.check_ips_and_rdns(&mut report, &mut checks);
        self.check_spf(&clean_domain, &mut report, &mut checks);
        self.check_dmarc(&clean_domain, &mut report, &mut checks);
        self.check_dkim(&clean_domain, custom_selector, &mut report, &mut checks);

        (report, checks)
    }

    fn check_mx_records(&self, domain: &str, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        match self.query_mx(domain) {
            Ok(records) if !records.is_empty() => {
                report.has_mx_records = true;
                let mut sorted_records = records;
                sorted_records.sort_by_key(|r| r.0);

                for (pref, host) in sorted_records {
                    let host = host.trim_end_matches('.').to_lowercase();
                    let is_null = host.is_empty() || host == ".";
                    report.mx_hosts.push(MxHost {
                        hostname: host,
                        priority: pref,
                        is_null_mx: is_null,
                        ..Default::default()
                    });
                }

                if report.mx_hosts.iter().any(|h| h.is_null_mx) {
                    checks.push(
                        CheckItem::new(
                            "DNS_NULL_MX",
                            "DNS",
                            Severity::Notice,
                            "RFC 7505 Null MX Record Configured",
                            format!(
                                "Domain '{}' publishes a Null MX ('0 .'), explicitly rejecting all email.",
                                domain
                            ),
                        )
                        .fix("Remove Null MX and add valid MX records if this domain is intended to receive mail."),
                    );
                    return;
                }

                if report.mx_hosts.len() == 1 {
                    checks.push(
                        CheckItem::new(
                            "DNS_MX_SINGLE",
                            "DNS",
                            Severity::Notice,
                            "Single MX Host (No Redundancy)",
                            format!(
                                "Domain '{}' has only 1 MX record ({}) configured.",
                                domain, report.mx_hosts[0].hostname
                            ),
                        )
                        .fix("Configure at least 2 distinct MX servers for high availability."),
                    );
                } else {
                    checks.push(CheckItem::new(
                        "DNS_MX_REDUNDANCY",
                        "DNS",
                        Severity::Pass,
                        "MX Redundancy Present",
                        format!("Found {} MX records configured for redundancy.", report.mx_hosts.len()),
                    ));
                }
            }
            _ => {
                // Fallback to the domain's own address (RFC 5321 §5.1)
                let v4 = self.query_a(domain).unwrap_or_default();
                let v6 = self.query_aaaa(domain).unwrap_or_default();
                if !v4.is_empty() || !v6.is_empty() {
                    report.fallback_to_a = true;
                    report.mx_hosts.push(MxHost {
                        hostname: domain.to_string(),
                        ..Default::default()
                    });
                    checks.push(
                        CheckItem::new(
                            "DNS_MX_FALLBACK_A",
                            "DNS",
                            Severity::Warning,
                            "No MX Record (RFC 5321 Fallback to Root A)",
                            format!(
                                "No MX records found for '{}'; SMTP relies on root A-record fallback.",
                                domain
                            ),
                        )
                        .fix("Publish explicit MX records to guarantee reliable email routing."),
                    );
                    return;
                }

                checks.push(
                    CheckItem::new(
                        "DNS_NO_MX_OR_A",
                        "DNS",
                        Severity::Critical,
                        "No Mail Exchanger Discovered",
                        format!(
                            "Domain '{}' has neither MX nor A records. Incoming mail cannot be delivered.",
                            domain
                        ),
                    )
                    .fix("Add an MX record pointing to your mail server hostname."),
                );
            }
        }
    }

    fn check_ips_and_rdns(&self, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        let (mut no_ptr, mut mismatched, mut valid) = (Vec::new(), Vec::new(), 0);
        for mx in &mut report.mx_hosts {
            if mx.is_null_mx || mx.hostname.is_empty() {
                continue;
            }

            if let Ok(msg) = self.lookup(&mx.hostname, DNS_TYPE_A) {
                mx.is_cname = msg.answers.iter().any(|r| {
                    r.rtype == DNS_TYPE_CNAME && r.name.trim_end_matches('.').eq_ignore_ascii_case(&mx.hostname)
                });
                mx.ipv4_addresses = msg.ips();
            }
            mx.ipv6_addresses = self.query_aaaa(&mx.hostname).unwrap_or_default();

            if mx.is_cname {
                checks.push(CheckItem::new("DNS_MX_IS_CNAME", "DNS", Severity::Warning, format!("MX Target Is a CNAME ({})", mx.hostname), format!("'{}' is an alias (CNAME). RFC 2181 §10.3 and RFC 5321 §5.1 say an MX must point at a name with its own A/AAAA records; some senders refuse or mishandle this.", mx.hostname)).fix("Point the MX record at the canonical hostname the CNAME resolves to."));
            }

            if mx.ipv4_addresses.is_empty() && mx.ipv6_addresses.is_empty() {
                checks.push(
                    CheckItem::new(
                        format!("DNS_NO_IP_{}", mx.hostname),
                        "DNS",
                        Severity::Critical,
                        format!("MX Host Has No Address ({})", mx.hostname),
                        format!(
                            "Hostname '{}' resolves to neither an IPv4 nor an IPv6 address.",
                            mx.hostname
                        ),
                    )
                    .fix("Create A (and ideally AAAA) records for this MX hostname."),
                );
                continue;
            }

            let ips: Vec<String> = mx.ipv4_addresses.iter().chain(&mx.ipv6_addresses).cloned().collect();
            for ip in ips {
                let ptrs = self.query_ptr(&ip).unwrap_or_default();
                let matched = ptrs.iter().any(|ptr| {
                    let fwd = if ip.contains(':') {
                        self.query_aaaa(ptr)
                    } else {
                        self.query_a(ptr)
                    };
                    fwd.map(|addrs| addrs.iter().any(|a| same_ip(a, &ip))).unwrap_or(false)
                });
                match (ptrs.first(), matched) {
                    (None, _) => no_ptr.push(format!("{} ({})", ip, mx.hostname)),
                    (Some(p), false) => mismatched.push(format!("{} -> {}", ip, p)),
                    (Some(_), true) => valid += 1,
                }
                mx.fcrdns_valid.insert(ip.clone(), matched);
                mx.ptr_records.insert(ip, ptrs);
            }
        }

        // Reverse DNS decides whether mail *sent* from these IPs is accepted; it does not
        // affect receiving, so for MX hosts it is a notice rather than a warning.
        if valid > 0 {
            checks.push(CheckItem::new(
                "DNS_PTR_VALID",
                "DNS",
                Severity::Pass,
                "Valid Forward-Confirmed Reverse DNS",
                format!(
                    "{} MX address(es) have a PTR record that resolves back to the same address.",
                    valid
                ),
            ));
        }
        if !no_ptr.is_empty() {
            checks.push(
                CheckItem::new(
                    "DNS_NO_PTR",
                    "DNS",
                    Severity::Notice,
                    format!("Missing Reverse DNS (PTR) on {} MX Address(es)", no_ptr.len()),
                    format!("No PTR record: {}. Receiving still works, but Gmail, Yahoo and Microsoft reject mail sent from addresses without one.", no_ptr.join(", ")),
                )
                .fix("If these servers also send mail, ask the IP owner (hosting provider or ISP) to set a PTR record."),
            );
        }
        if !mismatched.is_empty() {
            checks.push(
                CheckItem::new(
                    "DNS_FCRDNS_MISMATCH",
                    "DNS",
                    Severity::Notice,
                    format!("Reverse DNS Does Not Resolve Back on {} Address(es)", mismatched.len()),
                    format!("The PTR name does not point back to the address: {}. Senders checking forward-confirmed reverse DNS will distrust mail sent from them.", mismatched.join(", ")),
                )
                .fix("Give the PTR hostname an A/AAAA record pointing back to the same address."),
            );
        }

        let any_v6 = report.mx_hosts.iter().any(|h| !h.ipv6_addresses.is_empty());
        let hosts = report.mx_hosts.iter().filter(|h| !h.is_null_mx).count();
        if hosts > 0 {
            checks.push(CheckItem::new("DNS_MX_IPV6", "DNS", if any_v6 { Severity::Pass } else { Severity::Info }, if any_v6 { "MX Hosts Reachable over IPv6" } else { "No IPv6 Addresses on MX Hosts" }.to_string(), if any_v6 {
                    format!(
                        "{} of {} MX hosts publish AAAA records.",
                        report.mx_hosts.iter().filter(|h| !h.ipv6_addresses.is_empty()).count(),
                        hosts
                    )
                } else {
                    "No MX host has an AAAA record, so IPv6-only senders cannot deliver. This is common and rarely a problem.".to_string()
                }));
        }
    }

    pub fn parse_spf_mechanisms(raw_spf: &str) -> Vec<String> {
        raw_spf.split_whitespace().skip(1).map(|s| s.to_string()).collect()
    }

    /// Splits an SPF term into its lowercase name and its argument, ignoring the qualifier.
    pub fn spf_term(term: &str) -> (String, Option<String>) {
        let t = term.trim_start_matches(['+', '-', '~', '?']);
        if let Some((name, arg)) = t.split_once('=') {
            return (name.to_ascii_lowercase(), Some(arg.to_string()));
        }
        match t.find([':', '/']) {
            Some(i) => {
                let arg = t[i..].strip_prefix(':').map(|a| a.to_string());
                (t[..i].to_ascii_lowercase(), arg)
            }
            None => (t.to_ascii_lowercase(), None),
        }
    }

    fn spf_records_at(&self, name: &str) -> Result<Vec<String>, String> {
        Ok(self
            .query_txt(name)?
            .into_iter()
            .filter(|t| {
                let l = t.trim().to_ascii_lowercase();
                l == "v=spf1" || l.starts_with("v=spf1 ")
            })
            .collect())
    }

    /// Counts DNS-querying terms across the include/redirect tree, as RFC 7208 §4.6.4
    /// requires; the 10-lookup limit applies to the whole evaluation.
    fn spf_walk(&self, record: &str, depth: usize, seen: &mut HashSet<String>, stats: &mut SpfStats) {
        if depth > 10 {
            stats.problems.push("include chain deeper than 10 levels".to_string());
            return;
        }
        let terms = Self::parse_spf_mechanisms(record);
        let has_all = terms.iter().any(|t| Self::spf_term(t).0 == "all");
        for term in &terms {
            let (name, arg) = Self::spf_term(term);
            match name.as_str() {
                "a" | "mx" | "exists" => stats.lookups += 1,
                "ptr" => {
                    stats.lookups += 1;
                    stats.has_ptr = true;
                }
                "include" | "redirect" => {
                    stats.lookups += 1;
                    if name == "redirect" && has_all {
                        continue; // redirect is ignored when "all" is present
                    }
                    let Some(target) = arg else { continue };
                    if target.contains('%') {
                        stats
                            .problems
                            .push(format!("{}={} uses macros; not followed", name, target));
                        continue;
                    }
                    let key = target.to_ascii_lowercase();
                    if !seen.insert(key.clone()) {
                        stats
                            .problems
                            .push(format!("'{}' is included more than once (loop or duplicate)", target));
                        continue;
                    }
                    match self.spf_records_at(&key) {
                        Ok(recs) if recs.len() == 1 => self.spf_walk(&recs[0], depth + 1, seen, stats),
                        Ok(recs) if recs.is_empty() => {
                            stats.voids += 1;
                            stats.broken_includes.push(target.clone());
                        }
                        Ok(_) => stats
                            .problems
                            .push(format!("'{}' publishes more than one SPF record", target)),
                        Err(e) => stats.problems.push(format!("lookup of '{}' failed: {}", target, e)),
                    }
                }
                _ => {}
            }
        }
    }

    fn check_spf(&self, domain: &str, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        let Ok(spf_records) = self.spf_records_at(domain) else {
            return;
        };

        if spf_records.is_empty() {
            checks.push(
                CheckItem::new(
                    "SPF_MISSING",
                    "SECURITY",
                    Severity::Warning,
                    "Missing SPF Record",
                    format!("Domain '{}' lacks an SPF TXT record.", domain),
                )
                .fix("Publish a 'v=spf1 ... -all' record to authorize legitimate senders and prevent spoofing."),
            );
            return;
        }

        if spf_records.len() > 1 {
            report.spf_multiple = true;
            checks.push(CheckItem::new("SPF_MULTIPLE_RECORDS", "SECURITY", Severity::Critical, "Multiple SPF Records Detected (RFC 7208 PermError)", format!("Found {} SPF records. RFC 7208 §3.2 strictly prohibits more than one SPF record per domain.", spf_records.len())).fix("Merge all SPF rules into a single 'v=spf1' record. Multiple records result in immediate evaluation failure.").details(format!("Found: {:?}", spf_records)));
        }

        let raw_spf = &spf_records[0];
        report.spf_record = Some(raw_spf.clone());
        let mechanisms = Self::parse_spf_mechanisms(raw_spf);
        report.spf_mechanisms = mechanisms.clone();

        let mut stats = SpfStats::default();
        let mut seen = HashSet::new();
        seen.insert(domain.to_string());
        self.spf_walk(raw_spf, 0, &mut seen, &mut stats);
        report.spf_lookup_count = stats.lookups;
        report.spf_void_lookups = stats.voids;

        if stats.lookups > 10 {
            checks.push(CheckItem::new("SPF_LOOKUP_LIMIT_EXCEEDED", "SECURITY", Severity::Critical, format!("SPF Lookup Limit Exceeded ({} > 10)", stats.lookups), format!("Evaluating this SPF record, including everything it includes, takes {} DNS lookups. RFC 7208 §4.6.4 caps it at 10, so receivers return PermError and SPF fails for all your mail.", stats.lookups)).fix("Remove unused includes, replace a/mx with ip4/ip6 ranges, or flatten nested includes."));
        } else {
            checks.push({
                let near = stats.lookups >= 9;
                let c = CheckItem::new(
                    "SPF_LOOKUPS_OK",
                    "SECURITY",
                    if near { Severity::Notice } else { Severity::Pass },
                    format!("SPF Uses {} of 10 Allowed DNS Lookups", stats.lookups),
                    "Counted across all nested includes and redirects, as receivers do.",
                );
                if near {
                    c.fix("You are close to the limit; one more include will break SPF.")
                } else {
                    c
                }
            });
        }

        if !stats.broken_includes.is_empty() {
            checks.push(CheckItem::new("SPF_BROKEN_INCLUDE", "SECURITY", Severity::Critical, "SPF Includes a Name With No SPF Record", format!("These includes have no SPF record, which makes the whole evaluation a PermError (RFC 7208 §5.2): {}", stats.broken_includes.join(", "))).fix("Remove the dead include or correct its spelling."));
        }
        if stats.voids > 2 {
            checks.push(CheckItem::new("SPF_VOID_LOOKUPS", "SECURITY", Severity::Warning, format!("Too Many Void SPF Lookups ({})", stats.voids), "More than 2 lookups returned nothing; RFC 7208 §4.6.4 says receivers should treat this as PermError.").fix("Remove includes that point at names without records."));
        }
        if !stats.problems.is_empty() {
            checks.push(CheckItem::new(
                "SPF_TREE_PROBLEMS",
                "SECURITY",
                Severity::Notice,
                "Problems in the SPF Include Tree",
                stats.problems.join("; "),
            ));
        }

        if stats.has_ptr {
            checks.push(
                CheckItem::new(
                    "SPF_PTR_DEPRECATED",
                    "SECURITY",
                    Severity::Warning,
                    "Deprecated 'ptr' Mechanism Used in SPF",
                    "The 'ptr' mechanism is deprecated per RFC 7208 §5.5 and should not be used in SPF records.",
                )
                .fix("Replace 'ptr' with explicit 'ip4', 'ip6', or 'include' mechanisms."),
            );
        }

        let all_mech = mechanisms.iter().find(|m| Self::spf_term(m).0 == "all");
        let has_redirect = mechanisms.iter().any(|m| Self::spf_term(m).0 == "redirect");
        if let Some(all_mech) = all_mech {
            report.spf_qualifier = Some(all_mech.clone());
            match all_mech.as_str() {
                "-all" => checks.push(CheckItem::new(
                    "SPF_STRICT_ALL",
                    "SECURITY",
                    Severity::Pass,
                    "Strict SPF Policy (-all)",
                    "SPF policy specifies strict HardFail enforcement (-all).",
                )),
                "~all" => checks.push(CheckItem::new(
                    "SPF_SOFTFAIL",
                    "SECURITY",
                    Severity::Pass,
                    "SPF SoftFail Policy (~all)",
                    "SPF policy specifies SoftFail enforcement (~all).",
                )),
                "?all" => checks.push(
                    CheckItem::new(
                        "SPF_NEUTRAL",
                        "SECURITY",
                        Severity::Warning,
                        "Weak SPF Policy (?all)",
                        "SPF policy ends with '?all' (Neutral), offering zero spoofing protection.",
                    )
                    .fix("Update '?all' to '~all' or '-all'."),
                ),
                _ => checks.push(
                    CheckItem::new(
                        "SPF_PASS_ALL",
                        "SECURITY",
                        Severity::Critical,
                        "Dangerous SPF Policy (+all)",
                        "SPF ends with '+all', authorizing every host on the Internet to send as your domain.",
                    )
                    .fix("Change '+all' to '-all'."),
                ),
            }
        } else if !has_redirect {
            checks.push(
                CheckItem::new(
                    "SPF_NO_ALL",
                    "SECURITY",
                    Severity::Warning,
                    "SPF Missing Terminating 'all' Mechanism",
                    "SPF record lacks a terminating 'all' qualifier (such as -all or ~all).",
                )
                .fix("Append '-all' or '~all' at the end of the SPF record."),
            );
        }
    }

    pub fn parse_dmarc_tags(raw_dmarc: &str) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        for part in raw_dmarc.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                tags.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        tags
    }

    fn check_dmarc(&self, domain: &str, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        let dmarc_host = format!("_dmarc.{}", domain);
        let Ok(txts) = self.query_txt(&dmarc_host) else { return };
        let dmarc_records: Vec<String> = txts
            .into_iter()
            .filter(|t| t.trim().to_ascii_uppercase().starts_with("V=DMARC1"))
            .collect();

        if dmarc_records.is_empty() {
            checks.push(
                CheckItem::new(
                    "DMARC_MISSING",
                    "SECURITY",
                    Severity::Warning,
                    "Missing DMARC Record",
                    format!("No DMARC record found at '{}'.", dmarc_host),
                )
                .fix(format!(
                    "Create a TXT record at '_dmarc.{}' (e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{}').",
                    domain, domain
                )),
            );
            return;
        }
        if dmarc_records.len() > 1 {
            checks.push(
                CheckItem::new(
                    "DMARC_MULTIPLE",
                    "SECURITY",
                    Severity::Critical,
                    "Multiple DMARC Records",
                    format!(
                        "Found {} DMARC records; RFC 7489 §6.6.3 says receivers then apply no DMARC policy at all.",
                        dmarc_records.len()
                    ),
                )
                .fix("Keep exactly one v=DMARC1 record.")
                .details(format!("{:?}", dmarc_records)),
            );
        }

        let raw_dmarc = &dmarc_records[0];
        report.dmarc_record = Some(raw_dmarc.clone());
        let tags = Self::parse_dmarc_tags(raw_dmarc);

        let policy = tags.get("p").map(|s| s.to_lowercase()).unwrap_or_default();
        report.dmarc_policy = Some(policy.clone());
        report.dmarc_rua = tags.get("rua").cloned();
        report.dmarc_ruf = tags.get("ruf").cloned();
        report.dmarc_sp = tags.get("sp").map(|s| s.to_lowercase());
        report.dmarc_adkim = tags.get("adkim").map(|s| s.to_lowercase());
        report.dmarc_aspf = tags.get("aspf").map(|s| s.to_lowercase());
        report.dmarc_pct = tags.get("pct").and_then(|p| p.parse().ok()).unwrap_or(100);

        match policy.as_str() {
            "reject" => checks.push(CheckItem::new(
                "DMARC_POLICY_REJECT",
                "SECURITY",
                Severity::Pass,
                "Strong DMARC Policy (p=reject)",
                "DMARC policy is set to 'reject', providing maximum domain spoofing protection.",
            )),
            "quarantine" => checks.push(CheckItem::new(
                "DMARC_POLICY_QUARANTINE",
                "SECURITY",
                Severity::Pass,
                "DMARC Policy (p=quarantine)",
                "DMARC policy is set to 'quarantine' (suspicious mail sent to spam folder).",
            )),
            "none" => checks.push(
                CheckItem::new(
                    "DMARC_POLICY_NONE",
                    "SECURITY",
                    Severity::Notice,
                    "Passive DMARC Policy (p=none)",
                    "DMARC policy is in 'none' (monitoring-only) mode; forged emails will not be blocked.",
                )
                .fix("After reviewing DMARC reports, upgrade policy from 'p=none' to 'p=quarantine' or 'p=reject'."),
            ),
            _ => checks.push(
                CheckItem::new(
                    "DMARC_POLICY_INVALID",
                    "SECURITY",
                    Severity::Warning,
                    "Invalid DMARC Policy",
                    format!("Unrecognized DMARC policy tag 'p={}'.", policy),
                )
                .fix("Set 'p=reject', 'p=quarantine', or 'p=none'."),
            ),
        }

        if report.dmarc_pct < 100 && policy != "none" {
            checks.push(CheckItem::new("DMARC_PCT_PARTIAL", "SECURITY", Severity::Notice, format!("DMARC Policy Applies to Only {}% of Mail", report.dmarc_pct), format!("pct={} means receivers apply p={} to only part of failing mail; the rest is treated as p=none.", report.dmarc_pct, policy)).fix("Raise pct to 100 once reports look clean."));
        }

        let strength = |p: &str| match p {
            "reject" => 2,
            "quarantine" => 1,
            _ => 0,
        };
        if let Some(sp) = &report.dmarc_sp {
            if strength(sp) < strength(&policy) {
                checks.push(CheckItem::new("DMARC_SP_WEAKER", "SECURITY", Severity::Notice, format!("Subdomain Policy Is Weaker (sp={})", sp), format!("The domain is protected with p={}, but sp={} lets anyone spoof made-up subdomains such as billing.{}.", policy, sp, domain)).fix("Remove sp= (it then inherits p=) or set it to the same strength."));
            }
        }

        let alignment = format!(
            "DKIM alignment: {}, SPF alignment: {}",
            if report.dmarc_adkim.as_deref() == Some("s") {
                "strict"
            } else {
                "relaxed"
            },
            if report.dmarc_aspf.as_deref() == Some("s") {
                "strict"
            } else {
                "relaxed"
            }
        );
        checks.push(CheckItem::new("DMARC_ALIGNMENT", "SECURITY", Severity::Info, "DMARC Alignment Mode", format!("{}. Strict alignment breaks mail sent through subdomains or third parties that sign with a parent domain.", alignment)));

        match &report.dmarc_rua {
            None => checks.push(
                CheckItem::new(
                    "DMARC_NO_RUA",
                    "SECURITY",
                    Severity::Notice,
                    "DMARC Missing Aggregate Reporting (rua)",
                    "DMARC record lacks an aggregate reporting URI ('rua=mailto:...').",
                )
                .fix("Add 'rua=mailto:dmarc-reports@...' to receive daily authentication telemetry."),
            ),
            Some(rua) => self.check_external_report_auth(domain, rua, "rua", checks),
        }
        if let Some(ruf) = report.dmarc_ruf.clone() {
            self.check_external_report_auth(domain, &ruf, "ruf", checks);
        }
    }

    /// RFC 7489 §7.1: a report address in another domain only receives reports if that
    /// domain publishes <domain>._report._dmarc.<its domain>.
    fn check_external_report_auth(&self, domain: &str, uris: &str, tag: &str, checks: &mut Vec<CheckItem>) {
        let mut unauthorized = Vec::new();
        for uri in uris.split(',') {
            let Some(addr) = uri
                .trim()
                .strip_prefix("mailto:")
                .or_else(|| uri.trim().strip_prefix("MAILTO:"))
            else {
                continue;
            };
            let addr = addr.split('!').next().unwrap_or(addr);
            let Some((_, rdomain)) = addr.rsplit_once('@') else {
                continue;
            };
            let rdomain = rdomain.trim().trim_end_matches('.').to_ascii_lowercase();
            if same_organization(domain, &rdomain) {
                continue;
            }
            let auth_name = format!("{}._report._dmarc.{}", domain, rdomain);
            let ok = self
                .query_txt(&auth_name)
                .map(|t| t.iter().any(|r| r.trim().to_ascii_uppercase().starts_with("V=DMARC1")))
                .unwrap_or(false);
            if !ok {
                unauthorized.push(format!("{} (needs TXT at {})", addr, auth_name));
            }
        }
        if !unauthorized.is_empty() {
            checks.push(CheckItem::new(format!("DMARC_{}_UNAUTHORIZED", tag.to_ascii_uppercase()), "SECURITY", Severity::Warning, format!("DMARC {} Address in Another Domain Is Not Authorized", tag), format!("Receivers will not send reports to: {}. RFC 7489 §7.1 requires the receiving domain to opt in.", unauthorized.join("; "))).fix("Ask the report receiver to publish the authorization record (\"v=DMARC1\"), or use an address in your own domain."));
        }
    }

    fn check_dkim(&self, domain: &str, custom: Option<&str>, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        let custom: Vec<&str> = custom
            .map(|c| c.split(',').map(str::trim).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let mut selectors: Vec<&str> = custom.clone();
        selectors.extend(DKIM_SELECTORS.iter().filter(|s| !custom.contains(s)));

        // A few at a time: a burst of ~100 queries makes some resolvers drop answers, and a
        // dropped answer would read as "no key here".
        let mut found: Vec<Option<DkimKey>> = Vec::new();
        for batch in selectors.chunks(DKIM_PARALLEL_LOOKUPS) {
            found.extend(std::thread::scope(|scope| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|sel| {
                        scope.spawn(move || {
                            let txts = self.query_txt(&format!("{}._domainkey.{}", sel, domain)).ok()?;
                            let record = txts.into_iter().find(|t| t.contains("v=DKIM1") || t.contains("p="))?;
                            Some(DkimKey::parse(sel, record))
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().ok().flatten()).collect::<Vec<_>>()
            }));
        }
        report.dkim_keys = found.into_iter().flatten().collect();

        // A wildcard *._domainkey record answers for every selector, so a made-up one
        // tells real keys from the wildcard's copies.
        let probe = format!("mxd-probe-{:x}._domainkey.{}", random_id(), domain);
        if let Some(wild) = self.query_txt(&probe).ok().and_then(|t| t.into_iter().next()) {
            report.dkim_keys.retain(|k| k.record != wild);
            checks.push(CheckItem::new(
                "DKIM_WILDCARD",
                "SECURITY",
                Severity::Info,
                "Wildcard DKIM Record",
                format!("*._domainkey.{} answers for every selector with '{}'.", domain, wild),
            ));
        }

        for sel in custom
            .iter()
            .filter(|c| !report.dkim_keys.iter().any(|k| &k.selector == *c))
        {
            checks.push(
                CheckItem::new(
                    "DKIM_CUSTOM_NOT_FOUND",
                    "SECURITY",
                    Severity::Warning,
                    format!("DKIM Selector '{}' Not Found", sel),
                    format!("No DKIM key found at '{}._domainkey.{}'.", sel, domain),
                )
                .fix("Check the selector spelling (the s= value in a message's DKIM-Signature header)."),
            );
        }

        if report.dkim_keys.is_empty() {
            if custom.is_empty() {
                checks.push(CheckItem::new(
                    "DKIM_NOT_DISCOVERED",
                    "SECURITY",
                    Severity::Info,
                    "No DKIM Key Under Common Selectors",
                    format!("DNS cannot list DKIM selectors, and none of the {} common ones exist here. Pass --dkim-selector with the s= value from a message's DKIM-Signature header to check yours.", DKIM_SELECTORS.len()),
                ));
            }
            return;
        }

        let active: Vec<String> = report
            .dkim_keys
            .iter()
            .filter(|k| !k.revoked)
            .map(|k| format!("{} ({})", k.selector, k.describe()))
            .collect();
        let revoked = report.dkim_keys.len() - active.len();
        if active.is_empty() {
            checks.push(CheckItem::new(
                "DKIM_ONLY_REVOKED",
                "SECURITY",
                Severity::Notice,
                "Only Revoked DKIM Keys Found",
                format!("{} selector(s) exist but all have an empty p= (revoked). The domain has probably rotated to a newer selector that is not on the common list; check the s= value of a recent message's DKIM-Signature header with --dkim-selector.", revoked),
            ));
            return;
        }
        checks.push(CheckItem::new(
            "DKIM_FOUND",
            "SECURITY",
            Severity::Pass,
            format!("{} Active DKIM Key(s) Found", active.len()),
            format!(
                "Selectors: {}.{}",
                active.join(", "),
                if revoked > 0 {
                    format!(" {} older selector(s) are revoked.", revoked)
                } else {
                    String::new()
                }
            ),
        ));
        for k in &report.dkim_keys {
            let (sev, problem, fix) = match (k.revoked, k.key_type.as_str(), k.approx_bits) {
                (true, _, _) => continue, // a revoked old selector is normal key rotation
                (_, "rsa", Some(b)) if b < 1024 => (
                    Severity::Critical,
                    format!(
                        "is a {}-bit RSA key, which can be factored; receivers treat it as unsigned",
                        b
                    ),
                    Some("Generate a 2048-bit key and publish it under a new selector."),
                ),
                (_, "rsa", Some(1024)) => (
                    Severity::Notice,
                    "is a 1024-bit RSA key; 2048 bits is the current recommendation (RFC 8301)".to_string(),
                    Some("Rotate to a 2048-bit key under a new selector."),
                ),
                _ => continue,
            };
            let c = CheckItem::new(
                format!("DKIM_KEY_{}", k.selector),
                "SECURITY",
                sev,
                format!("DKIM Selector '{}' Key Problem", k.selector),
                format!("The key at {}._domainkey.{} {}.", k.selector, domain, problem),
            );
            checks.push(match fix {
                Some(f) => c.fix(f),
                None => c,
            });
        }
    }

    pub fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String> {
        Ok(self.lookup(domain, DNS_TYPE_MX)?.mx())
    }

    pub fn query_a(&self, domain: &str) -> Result<Vec<String>, String> {
        Ok(self.lookup(domain, DNS_TYPE_A)?.ips())
    }

    pub fn query_aaaa(&self, domain: &str) -> Result<Vec<String>, String> {
        Ok(self.lookup(domain, DNS_TYPE_AAAA)?.ips())
    }

    pub fn query_txt(&self, domain: &str) -> Result<Vec<String>, String> {
        Ok(self.lookup(domain, DNS_TYPE_TXT)?.txt())
    }

    pub fn query_ptr(&self, ip: &str) -> Result<Vec<String>, String> {
        let addr: IpAddr = ip.trim().parse().map_err(|_| format!("Invalid IP address '{}'", ip))?;
        Ok(self.lookup(&reverse_name(&addr), DNS_TYPE_PTR)?.ptr())
    }

    /// TLSA records for SMTP on `host`, with whether a validating resolver vouched for them.
    pub fn query_tlsa(&self, host: &str) -> Result<(Vec<TlsaRecord>, Option<bool>), String> {
        let name = format!("_25._tcp.{}", host.trim_end_matches('.'));
        let msg = self.lookup(&name, DNS_TYPE_TLSA)?;
        let records = msg.tlsa();
        if records.is_empty() {
            return Ok((records, None));
        }
        let ad = if msg.authentic_data {
            Some(true)
        } else {
            self.validated(&name, DNS_TYPE_TLSA)
        };
        Ok((records, ad))
    }

    /// Whether `name` is DNSSEC-authenticated, asked of a resolver that has proved it
    /// validates. None when no such resolver is reachable: some networks intercept DNS
    /// to public resolvers and strip the AD flag, which must not read as "unsigned".
    pub fn validated(&self, name: &str, qtype: u16) -> Option<bool> {
        let addr = (*self.validator.get_or_init(|| self.find_validator()))?;
        let r = DnsResolver::with_nameservers(vec![addr], self.timeout);
        // Retry once: a cache-hit answer can briefly come back without AD.
        let ad = |r: &DnsResolver| r.lookup(name, qtype).ok().map(|m| m.authentic_data);
        match ad(&r)? {
            true => Some(true),
            false => ad(&r),
        }
    }

    fn find_validator(&self) -> Option<SocketAddr> {
        let public = VALIDATING_RESOLVERS.iter().filter_map(|s| s.parse::<SocketAddr>().ok());
        self.nameservers.iter().copied().chain(public).find(|ns| {
            let resolver = DnsResolver::with_nameservers(vec![*ns], self.timeout);
            // Twice: one lost packet must not decide that no resolver validates.
            (0..2).any(|_| {
                resolver
                    .lookup(DNSSEC_PROBE_NAME, DNS_TYPE_A)
                    .map(|m| m.authentic_data)
                    .unwrap_or(false)
            })
        })
    }

    /// Sends a query to each nameserver in turn, retrying over TCP when the UDP answer
    /// is truncated. NXDOMAIN is a valid empty answer; SERVFAIL moves to the next server.
    pub fn lookup(&self, name: &str, qtype: u16) -> Result<DnsMessage, String> {
        let id = random_id();
        let packet = Self::build_query(name, qtype, id)?;
        let mut last_err = String::from("No nameservers reachable");

        // Two passes over the servers: a single lost UDP packet should not fail a check.
        for ns in self.nameservers.iter().chain(&self.nameservers) {
            let reply = match self.udp_exchange(&packet, ns, id) {
                Ok(r) => r,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            let mut msg = match Self::parse_message(&reply) {
                Ok(m) => m,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            if msg.truncated {
                match self.tcp_exchange(&packet, ns).and_then(|r| Self::parse_message(&r)) {
                    Ok(m) if m.id == id => msg = m,
                    Ok(_) => {
                        last_err = "TCP answer ID mismatch".to_string();
                        continue;
                    }
                    Err(e) => {
                        last_err = format!("truncated UDP answer and TCP retry failed: {}", e);
                        continue;
                    }
                }
            }
            match msg.rcode {
                RCODE_NOERROR | RCODE_NXDOMAIN => return Ok(msg),
                RCODE_SERVFAIL => last_err = format!("SERVFAIL for {} from {}", name, ns),
                other => last_err = format!("DNS error code {} for {} from {}", other, name, ns),
            }
        }
        Err(last_err)
    }

    fn udp_exchange(&self, packet: &[u8], ns: &SocketAddr, id: u16) -> Result<Vec<u8>, String> {
        let bind = if ns.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        socket.set_read_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;
        socket.connect(ns).map_err(|e| e.to_string())?;
        socket.send(packet).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 4096];
        // Skip stray datagrams with the wrong ID instead of trusting them.
        for _ in 0..4 {
            let len = socket.recv(&mut buf).map_err(|e| e.to_string())?;
            if len >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return Ok(buf[..len].to_vec());
            }
        }
        Err("no answer with a matching ID".to_string())
    }

    fn tcp_exchange(&self, packet: &[u8], ns: &SocketAddr) -> Result<Vec<u8>, String> {
        let mut s = TcpStream::connect_timeout(ns, self.timeout).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(self.timeout)).ok();
        s.set_write_timeout(Some(self.timeout)).ok();
        let mut framed = (packet.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(packet);
        s.write_all(&framed).map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }

    /// Plain RFC 1035 query with a fixed ID, kept for tests and fuzzing.
    pub fn build_dns_query_packet(name: &str, qtype: u16) -> Result<Vec<u8>, String> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        Self::push_question(&mut packet, name, qtype)?;
        Ok(packet)
    }

    /// Query with recursion desired, the AD bit set to ask for validation status
    /// (RFC 6840 §5.7), and an EDNS0 OPT record allowing 1232-byte UDP answers.
    pub fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, String> {
        let mut packet = Vec::with_capacity(64);
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&[0x01, 0x20]); // RD + AD
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // QD=1, AR=1
        Self::push_question(&mut packet, name, qtype)?;
        packet.push(0x00); // OPT owner: root
        packet.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        packet.extend_from_slice(&1232u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // ext rcode, version, flags, rdlen
        Ok(packet)
    }

    fn push_question(packet: &mut Vec<u8>, name: &str, qtype: u16) -> Result<(), String> {
        let trimmed = name.trim_end_matches('.');
        if trimmed.len() > 253 {
            return Err("DNS name longer than 253 characters".to_string());
        }
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("Invalid DNS label: '{}'", label));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        Ok(())
    }

    /// Parses a DNS response. Malformed records end the answer list instead of failing
    /// the whole message, so a partly valid answer still yields what it can.
    pub fn parse_message(buf: &[u8]) -> Result<DnsMessage, String> {
        if buf.len() < 12 {
            return Err("Truncated DNS response header".to_string());
        }
        let mut msg = DnsMessage {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            truncated: buf[2] & 0x02 != 0,
            authentic_data: buf[3] & 0x20 != 0,
            rcode: buf[3] & 0x0F,
            answers: Vec::new(),
        };
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        let mut offset = 12;
        for _ in 0..qdcount {
            if offset >= buf.len() {
                return Err("Truncated Question section".to_string());
            }
            offset = Self::skip_name(buf, offset)?;
            if offset.saturating_add(4) > buf.len() {
                return Err("Truncated Question QTYPE/QCLASS".to_string());
            }
            offset += 4;
        }

        for _ in 0..ancount {
            if offset >= buf.len() {
                break;
            }
            let owner = Self::read_name(buf, offset).map(|(n, _)| n).unwrap_or_default();
            offset = Self::skip_name(buf, offset)?;
            if offset.saturating_add(10) > buf.len() {
                break;
            }
            let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
            offset += 10;
            if offset.saturating_add(rdlength) > buf.len() {
                break;
            }
            let rdata = &buf[offset..offset + rdlength];
            let data = match rtype {
                DNS_TYPE_A if rdlength == 4 => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                DNS_TYPE_AAAA if rdlength == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(rdata);
                    RData::Aaaa(Ipv6Addr::from(o))
                }
                DNS_TYPE_MX if rdlength >= 3 => {
                    let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                    match Self::read_name(buf, offset + 2) {
                        Ok((exchange, _)) => RData::Mx(pref, exchange),
                        Err(_) => RData::Other,
                    }
                }
                DNS_TYPE_PTR => match Self::read_name(buf, offset) {
                    Ok((n, _)) => RData::Ptr(n),
                    Err(_) => RData::Other,
                },
                DNS_TYPE_CNAME => match Self::read_name(buf, offset) {
                    Ok((n, _)) => RData::Cname(n),
                    Err(_) => RData::Other,
                },
                DNS_TYPE_TXT => {
                    let mut i = 0;
                    let mut full = Vec::new();
                    while i < rdata.len() {
                        let len = rdata[i] as usize;
                        i += 1;
                        if i + len > rdata.len() {
                            break;
                        }
                        full.extend_from_slice(&rdata[i..i + len]);
                        i += len;
                    }
                    if full.is_empty() {
                        RData::Other
                    } else {
                        RData::Txt(String::from_utf8_lossy(&full).into_owned())
                    }
                }
                DNS_TYPE_TLSA if rdlength >= 3 => RData::Tlsa(TlsaRecord {
                    usage: rdata[0],
                    selector: rdata[1],
                    matching_type: rdata[2],
                    data_hex: rdata[3..].iter().map(|b| format!("{:02x}", b)).collect(),
                }),
                _ => RData::Other,
            };
            msg.answers.push(ResourceRecord {
                name: owner,
                rtype,
                data,
            });
            offset += rdlength;
        }
        Ok(msg)
    }

    pub fn parse_mx_response(buf: &[u8]) -> Result<Vec<(u16, String)>, String> {
        Ok(Self::parse_message(buf)?.mx())
    }

    pub fn parse_a_response(buf: &[u8]) -> Result<Vec<String>, String> {
        Ok(Self::parse_message(buf)?.ips())
    }

    pub fn parse_txt_response(buf: &[u8]) -> Result<Vec<String>, String> {
        Ok(Self::parse_message(buf)?.txt())
    }

    pub fn parse_ptr_response(buf: &[u8]) -> Result<Vec<String>, String> {
        Ok(Self::parse_message(buf)?.ptr())
    }

    pub fn skip_name(buf: &[u8], mut offset: usize) -> Result<usize, String> {
        let mut steps = 0;
        while offset < buf.len() {
            steps += 1;
            if steps > buf.len() + 1 {
                return Err("Name traversal loop in skip_name".to_string());
            }
            let len = buf[offset] as usize;
            if len == 0 {
                return Ok(offset + 1);
            } else if (len & 0xC0) == 0xC0 {
                if offset + 1 >= buf.len() {
                    return Err("Truncated compression pointer".to_string());
                }
                return Ok(offset + 2);
            } else if (len & 0xC0) != 0 {
                return Err(format!("Unsupported DNS compression marker: 0x{:02X}", len));
            } else {
                if offset + 1 + len > buf.len() {
                    return Err("Truncated DNS label".to_string());
                }
                offset += 1 + len;
            }
        }
        Err("Malformed DNS name offset".to_string())
    }

    pub fn read_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), String> {
        const MAX_POINTER_JUMPS: usize = 16;
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut bytes_read = 0;
        let mut jump_count = 0;
        let initial_offset = offset;

        while offset < buf.len() {
            let len = buf[offset] as usize;
            if len == 0 {
                if !jumped {
                    bytes_read = offset + 1 - initial_offset;
                }
                return Ok((labels.join("."), bytes_read));
            } else if (len & 0xC0) == 0xC0 {
                if offset + 1 >= buf.len() {
                    return Err("Pointer truncated".to_string());
                }
                jump_count += 1;
                if jump_count > MAX_POINTER_JUMPS {
                    return Err("DNS compression pointer loop detected".to_string());
                }
                let ptr_offset = ((len & 0x3F) << 8) | (buf[offset + 1] as usize);
                if ptr_offset >= buf.len() {
                    return Err("Compression pointer target out of bounds".to_string());
                }
                if !jumped {
                    bytes_read = offset + 2 - initial_offset;
                    jumped = true;
                }
                offset = ptr_offset;
            } else if (len & 0xC0) != 0 {
                return Err(format!("Unsupported DNS label type: 0x{:02X}", len));
            } else {
                offset += 1;
                if offset + len > buf.len() {
                    return Err("Label truncated".to_string());
                }
                labels.push(String::from_utf8_lossy(&buf[offset..offset + len]).to_string());
                offset += len;
            }
        }

        Err("Unterminated DNS name reached end of packet".to_string())
    }
}

#[derive(Default)]
struct SpfStats {
    lookups: usize,
    voids: usize,
    has_ptr: bool,
    broken_includes: Vec<String>,
    problems: Vec<String>,
}

fn random_id() -> u16 {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish() as u16
}

/// in-addr.arpa or ip6.arpa name for a PTR lookup.
pub fn reverse_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles: Vec<String> = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0F));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

fn same_ip(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Rough organizational-domain test without a Public Suffix List: one name is the
/// other or ends with "." + the other.
pub fn same_organization(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('.').to_ascii_lowercase();
    let b = b.trim_end_matches('.').to_ascii_lowercase();
    a == b || a.ends_with(&format!(".{}", b)) || b.ends_with(&format!(".{}", a))
}
