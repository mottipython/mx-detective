use std::net::IpAddr;
use std::time::Duration;

use crate::dns::{reverse_name, DnsResolver, DNS_TYPE_MX};
use crate::models::{CheckItem, DnsReport, DnsblResult, MtaStsReport, Severity};
use crate::tls;

/// DNS blocklists that answer free, low-volume queries.
pub const DNSBLS: [&str; 4] = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "psbl.surriel.com",
];

/// Parses a "key: value" MTA-STS policy (RFC 8461 §3.2). Unknown keys are ignored.
pub fn parse_mta_sts_policy(text: &str, report: &mut MtaStsReport) -> Option<String> {
    let mut version = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim().to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "version" => version = Some(v),
            "mode" => report.mode = Some(v.to_ascii_lowercase()),
            "mx" => report.mx_patterns.push(v.to_ascii_lowercase()),
            "max_age" => report.max_age = v.parse().ok(),
            _ => {}
        }
    }
    version
}

pub fn check_mta_sts(
    resolver: &DnsResolver,
    domain: &str,
    timeout: Duration,
    dns: &mut DnsReport,
    checks: &mut Vec<CheckItem>,
) {
    let txt_name = format!("_mta-sts.{}", domain);
    let txts: Vec<String> = resolver
        .query_txt(&txt_name)
        .unwrap_or_default()
        .into_iter()
        .filter(|t| t.trim().to_ascii_lowercase().starts_with("v=stsv1"))
        .collect();

    if txts.is_empty() {
        checks.push(CheckItem::new("MTA_STS_MISSING", "TLS", Severity::Notice, "MTA-STS Not Configured", "Without MTA-STS (or DANE), senders fall back to plaintext if someone strips STARTTLS, and they cannot tell a forged certificate from the real one.").fix("Publish _mta-sts TXT and a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt; start with mode: testing plus TLS-RPT."));
        return;
    }

    let mut sts = MtaStsReport {
        txt_record: Some(txts[0].clone()),
        policy_url: format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain),
        ..Default::default()
    };
    sts.policy_id = DnsResolver::parse_dmarc_tags(&txts[0]).get("id").cloned();

    if txts.len() > 1 {
        checks.push(
            CheckItem::new(
                "MTA_STS_MULTIPLE_TXT",
                "TLS",
                Severity::Warning,
                "Multiple MTA-STS TXT Records",
                "RFC 8461 §3.1: with more than one v=STSv1 record, senders treat the domain as having no policy.",
            )
            .fix("Keep exactly one _mta-sts TXT record."),
        );
    }
    if sts.policy_id.as_deref().map(str::is_empty).unwrap_or(true) {
        checks.push(
            CheckItem::new(
                "MTA_STS_NO_ID",
                "TLS",
                Severity::Warning,
                "MTA-STS TXT Record Has No id=",
                "Senders use id= to notice policy changes; without it the record is invalid.",
            )
            .fix("Add id=<timestamp> and change it whenever the policy file changes."),
        );
    }

    let host = format!("mta-sts.{}", domain);
    match tls::https_get(&host, "/.well-known/mta-sts.txt", timeout) {
        Ok((200, content_type, body)) => {
            sts.policy_fetched = true;
            sts.raw_policy = Some(body.clone());
            if !content_type
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .starts_with("text/plain")
            {
                checks.push(CheckItem::new("MTA_STS_CONTENT_TYPE", "TLS", Severity::Notice, "MTA-STS Policy Not Served as text/plain", format!("Content-Type is '{}'; RFC 8461 §3.2 requires text/plain and strict senders ignore the policy otherwise.", content_type.unwrap_or_else(|| "missing".to_string()))));
            }
            let version = parse_mta_sts_policy(&body, &mut sts);
            if version.as_deref() != Some("STSv1") || sts.mode.is_none() || sts.max_age.is_none() {
                checks.push(CheckItem::new("MTA_STS_POLICY_INVALID", "TLS", Severity::Warning, "MTA-STS Policy File Is Incomplete", "The policy must contain version: STSv1, mode, mx and max_age lines. Senders discard an invalid policy.").fix("Fix the policy file; see RFC 8461 §3.2."));
            }
        }
        Ok((status, _, _)) => {
            sts.fetch_error = Some(format!("HTTP {}", status));
            checks.push(CheckItem::new("MTA_STS_FETCH_FAILED", "TLS", Severity::Warning, format!("MTA-STS Policy Fetch Returned HTTP {}", status), format!("The TXT record announces MTA-STS but {} did not return the policy. Redirects are not followed (RFC 8461 §3.3).", sts.policy_url)).fix("Serve the policy file directly with status 200."));
        }
        Err(e) => {
            sts.fetch_error = Some(e.clone());
            checks.push(CheckItem::new("MTA_STS_FETCH_FAILED", "TLS", Severity::Warning, "MTA-STS Policy Could Not Be Fetched", format!("The TXT record announces MTA-STS but fetching {} failed: {}. Senders need a publicly trusted certificate on mta-sts.{}.", sts.policy_url, e, domain)).fix("Check that mta-sts.<domain> resolves and serves HTTPS with a valid certificate."));
        }
    }

    if sts.policy_fetched {
        let mode = sts.mode.clone().unwrap_or_default();
        match mode.as_str() {
            "enforce" => checks.push(CheckItem::new(
                "MTA_STS_ENFORCE",
                "TLS",
                Severity::Pass,
                "MTA-STS Policy in Enforce Mode",
                format!(
                    "Senders that support MTA-STS will only deliver over verified TLS to: {}.",
                    sts.mx_patterns.join(", ")
                ),
            )),
            "testing" => checks.push(
                CheckItem::new(
                    "MTA_STS_TESTING",
                    "TLS",
                    Severity::Notice,
                    "MTA-STS Policy in Testing Mode",
                    "Senders report TLS failures (via TLS-RPT) but still deliver without verified TLS.",
                )
                .fix("Switch to mode: enforce once TLS-RPT reports are clean."),
            ),
            _ => checks.push(CheckItem::new(
                "MTA_STS_NONE",
                "TLS",
                Severity::Notice,
                format!("MTA-STS Policy Mode '{}'", mode),
                "The policy does not ask senders to enforce TLS.",
            )),
        }
        if let Some(age) = sts.max_age {
            if age < 86_400 {
                checks.push(CheckItem::new("MTA_STS_SHORT_MAX_AGE", "TLS", Severity::Notice, format!("Short MTA-STS max_age ({} s)", age), "A short cache lifetime gives little protection; an attacker only has to block the policy fetch.").fix("Use max_age of at least 604800 (one week); RFC 8461 suggests weeks."));
            }
        }
        let unmatched: Vec<String> = dns
            .mx_hosts
            .iter()
            .filter(|h| !h.is_null_mx)
            .filter(|h| !sts.mx_patterns.iter().any(|p| tls::hostname_matches(p, &h.hostname)))
            .map(|h| h.hostname.clone())
            .collect();
        if !unmatched.is_empty() {
            let enforce = mode == "enforce";
            checks.push(
                CheckItem::new(
                    "MTA_STS_MX_MISMATCH",
                    "TLS",
                    if enforce { Severity::Critical } else { Severity::Warning },
                    "MX Hosts Not Listed in the MTA-STS Policy",
                    format!(
                        "{} not covered by any mx: line ({}).{}",
                        unmatched.join(", "),
                        sts.mx_patterns.join(", "),
                        if enforce {
                            " In enforce mode, MTA-STS senders (Gmail, Outlook) will refuse to deliver to these hosts."
                        } else {
                            ""
                        }
                    ),
                )
                .fix("Add an mx: line for each MX hostname (or a *.domain wildcard) and bump the TXT id."),
            );
        }
    }

    dns.mta_sts = Some(sts);
}

pub fn check_tls_rpt(resolver: &DnsResolver, domain: &str, dns: &mut DnsReport, checks: &mut Vec<CheckItem>) {
    let rec = resolver
        .query_txt(&format!("_smtp._tls.{}", domain))
        .unwrap_or_default()
        .into_iter()
        .find(|t| t.trim().to_ascii_lowercase().starts_with("v=tlsrptv1"));
    let uses_tls_policy = dns.mta_sts.is_some() || dns.mx_hosts.iter().any(|h| !h.tlsa_records.is_empty());
    match &rec {
        Some(r) => checks.push(CheckItem::new(
            "TLS_RPT_OK",
            "TLS",
            Severity::Pass,
            "TLS-RPT Reporting Configured",
            format!("Senders will report TLS delivery failures: {}", r),
        )),
        None => checks.push(
            CheckItem::new(
                "TLS_RPT_MISSING",
                "TLS",
                if uses_tls_policy {
                    Severity::Notice
                } else {
                    Severity::Info
                },
                "No TLS-RPT Record",
                "Without _smtp._tls TXT (RFC 8460), you never hear about senders failing to reach you over TLS.",
            )
            .fix("Publish _smtp._tls.<domain> TXT \"v=TLSRPTv1; rua=mailto:tls-reports@<domain>\"."),
        ),
    }
    dns.tls_rpt_record = rec;
}

pub fn check_bimi(resolver: &DnsResolver, domain: &str, dns: &mut DnsReport, checks: &mut Vec<CheckItem>) {
    let rec = resolver
        .query_txt(&format!("default._bimi.{}", domain))
        .unwrap_or_default()
        .into_iter()
        .find(|t| t.trim().to_ascii_lowercase().starts_with("v=bimi1"));
    if let Some(r) = &rec {
        let enforced =
            matches!(dns.dmarc_policy.as_deref(), Some("quarantine") | Some("reject")) && dns.dmarc_pct == 100;
        let tags = DnsResolver::parse_dmarc_tags(r);
        let logo = tags.get("l").cloned().unwrap_or_default();
        if !enforced {
            checks.push(
                CheckItem::new(
                    "BIMI_NO_ENFORCEMENT",
                    "SECURITY",
                    Severity::Warning,
                    "BIMI Record Ignored: DMARC Not Enforced",
                    "Mailbox providers show a BIMI logo only with DMARC p=quarantine or p=reject at pct=100.",
                )
                .fix("Move DMARC to enforcement first."),
            );
        } else if !logo.to_ascii_lowercase().starts_with("https://") {
            checks.push(CheckItem::new(
                "BIMI_BAD_LOGO",
                "SECURITY",
                Severity::Notice,
                "BIMI Logo URL Missing or Not HTTPS",
                format!("l= is '{}'; it must be an HTTPS URL to an SVG Tiny PS file.", logo),
            ));
        } else {
            checks.push(CheckItem::new(
                "BIMI_OK",
                "SECURITY",
                Severity::Pass,
                "BIMI Record Published",
                format!(
                    "Logo: {}{}",
                    logo,
                    if tags.get("a").map(|a| !a.is_empty()).unwrap_or(false) {
                        " (with a VMC/CMC certificate)"
                    } else {
                        " (no VMC; Gmail and Apple require one)"
                    }
                ),
            ));
        }
    } else {
        checks.push(CheckItem::new(
            "BIMI_MISSING",
            "SECURITY",
            Severity::Info,
            "No BIMI Record",
            "BIMI is optional; it shows your logo next to authenticated mail in supporting inboxes.",
        ));
    }
    dns.bimi_record = rec;
}

pub fn check_dnssec(resolver: &DnsResolver, domain: &str, dns: &mut DnsReport, checks: &mut Vec<CheckItem>) {
    dns.dnssec_signed = resolver.validated(domain, DNS_TYPE_MX);
    match dns.dnssec_signed {
        Some(true) => checks.push(CheckItem::new("DNSSEC_SIGNED", "DNS", Severity::Pass, "Domain Is DNSSEC-Signed", "A validating resolver authenticated the MX answer, so forged DNS replies are detectable and DANE is possible.")),
        Some(false) => checks.push(CheckItem::new("DNSSEC_UNSIGNED", "DNS", Severity::Info, "Domain Is Not DNSSEC-Signed", "MX answers are not authenticated. Common (gmail.com is unsigned), but it rules out DANE.")),
        None => checks.push(CheckItem::new("DNSSEC_UNKNOWN", "DNS", Severity::Info, "DNSSEC Status Unknown", "No reachable resolver validates DNSSEC (the system resolver does not, and queries to 1.1.1.1/8.8.8.8 come back unvalidated, so the network may be intercepting DNS).")),
    }
}

/// Looks up TLSA for each MX host and reports DNS-side DANE problems. Whether the
/// certificate matches is checked later, during the SMTP session.
pub fn check_dane_records(resolver: &DnsResolver, dns: &mut DnsReport, checks: &mut Vec<CheckItem>) {
    let mut any = false;
    for mx in dns
        .mx_hosts
        .iter_mut()
        .filter(|h| !h.is_null_mx && !h.hostname.is_empty())
    {
        if let Ok((recs, ad)) = resolver.query_tlsa(&mx.hostname) {
            mx.tlsa_dnssec_valid = ad;
            if recs.is_empty() {
                continue;
            }
            any = true;
            mx.tlsa_records = recs;
            match ad {
                Some(true) => {}
                Some(false) => checks.push(
                    CheckItem::new(
                        "DANE_NO_DNSSEC",
                        "TLS",
                        Severity::Warning,
                        format!("TLSA Records Without DNSSEC ({})", mx.hostname),
                        format!("_25._tcp.{} has TLSA records but they are not DNSSEC-validated, so senders ignore them (RFC 7672 §2.2).", mx.hostname),
                    )
                    .fix("Sign the MX host's zone with DNSSEC, or remove the TLSA records."),
                ),
                None => checks.push(CheckItem::new(
                    "DANE_DNSSEC_UNKNOWN",
                    "TLS",
                    Severity::Info,
                    format!("TLSA DNSSEC Status Unknown ({})", mx.hostname),
                    "No reachable resolver validates DNSSEC, so it is unknown whether DANE senders will trust these TLSA records.",
                )),
            }
            let bad_usage: Vec<String> = mx
                .tlsa_records
                .iter()
                .filter(|r| r.usage < 2)
                .map(|r| format!("{} {} {}", r.usage, r.selector, r.matching_type))
                .collect();
            if !bad_usage.is_empty() {
                checks.push(
                    CheckItem::new(
                        "DANE_PKIX_USAGE",
                        "TLS",
                        Severity::Notice,
                        format!("TLSA Usage 0/1 Not Used for SMTP ({})", mx.hostname),
                        format!(
                            "RFC 7672 §3.1.3 says SMTP clients treat PKIX-TA/PKIX-EE records as unusable: {}.",
                            bad_usage.join(", ")
                        ),
                    )
                    .fix("Use usage 3 (DANE-EE) or 2 (DANE-TA)."),
                );
            }
        }
    }
    if !any {
        checks.push(CheckItem::new(
            "DANE_NOT_USED",
            "TLS",
            Severity::Info,
            "DANE Not Used",
            "No MX host publishes TLSA records. DANE needs DNSSEC; MTA-STS gives similar protection without it.",
        ));
    }
}

/// Spamhaus return codes. 127.255.255.x means the query itself was refused.
fn spamhaus_meaning(code: &str) -> Option<&'static str> {
    Some(match code {
        "127.0.0.2" => "SBL: known spam source",
        "127.0.0.3" => "CSS: snowshoe spam",
        "127.0.0.4" | "127.0.0.5" | "127.0.0.6" | "127.0.0.7" => "XBL: compromised host or botnet",
        "127.0.0.9" => "DROP: hijacked network",
        "127.0.0.10" | "127.0.0.11" => "PBL: end-user/dynamic IP range (should not send mail directly)",
        _ => return None,
    })
}

pub fn lookup_dnsbl(resolver: &DnsResolver, ip: &str, list: &str) -> DnsblResult {
    let mut res = DnsblResult {
        ip: ip.to_string(),
        list: list.to_string(),
        ..Default::default()
    };
    let Ok(addr) = ip.parse::<IpAddr>() else { return res };
    let rev = reverse_name(&addr);
    let suffix = if addr.is_ipv4() { ".in-addr.arpa" } else { ".ip6.arpa" };
    let query = format!("{}.{}", rev.trim_end_matches(suffix), list);
    match resolver.query_a(&query) {
        Ok(codes) if codes.is_empty() => res.listed = Some(false),
        Ok(codes) => {
            if codes.iter().any(|c| c.starts_with("127.255.255.")) {
                res.meaning =
                    Some("query refused (Spamhaus blocks public/open resolvers and high-volume users)".to_string());
            } else if codes.iter().all(|c| c.starts_with("127.")) {
                res.listed = Some(true);
                res.meaning = if list.contains("spamhaus") {
                    Some(
                        codes
                            .iter()
                            .filter_map(|c| spamhaus_meaning(c))
                            .collect::<Vec<_>>()
                            .join("; "),
                    )
                } else {
                    None
                };
            } else {
                res.meaning = Some("unexpected answer (resolver may be hijacking NXDOMAIN)".to_string());
            }
            res.return_codes = codes;
        }
        Err(e) => res.meaning = Some(format!("lookup failed: {}", e)),
    }
    res
}

pub fn check_dnsbl(resolver: &DnsResolver, dns: &mut DnsReport, checks: &mut Vec<CheckItem>) {
    let ips: Vec<String> = dns
        .mx_hosts
        .iter()
        .flat_map(|h| h.ipv4_addresses.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if ips.is_empty() {
        return;
    }
    let results: Vec<DnsblResult> = std::thread::scope(|s| {
        let handles: Vec<_> = ips
            .iter()
            .flat_map(|ip| DNSBLS.iter().map(move |l| (ip, l)))
            .map(|(ip, l)| s.spawn(move || lookup_dnsbl(resolver, ip, l)))
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let listed: Vec<&DnsblResult> = results.iter().filter(|r| r.listed == Some(true)).collect();
    let refused: Vec<&DnsblResult> = results.iter().filter(|r| r.listed.is_none()).collect();
    let pbl_only = |r: &DnsblResult| {
        r.list.contains("spamhaus") && r.return_codes.iter().all(|c| c == "127.0.0.10" || c == "127.0.0.11")
    };

    for r in &listed {
        checks.push(CheckItem::new(format!("DNSBL_LISTED_{}_{}", r.ip, r.list), "SECURITY", if pbl_only(r) { Severity::Notice } else { Severity::Warning }, format!("MX IP {} Listed on {}", r.ip, r.list), format!(
                "{} returned {}{}. Mail sent from this IP is likely to be rejected or filtered by receivers that use this list.",
                r.list,
                r.return_codes.join(", "),
                r.meaning.as_ref().filter(|m| !m.is_empty()).map(|m| format!(" ({})", m)).unwrap_or_default()
            )).fix("Find the cause (compromised account, open relay, misconfigured forwarding), fix it, then request delisting on the list's website."));
    }
    let checked = results.iter().filter(|r| r.listed.is_some()).count();
    if listed.is_empty() && checked > 0 {
        checks.push(CheckItem::new(
            "DNSBL_CLEAN",
            "SECURITY",
            Severity::Pass,
            "MX IPs Not on Common Blocklists",
            format!(
                "{} lookups across {} IPs and {} lists found no listings.",
                checked,
                ips.len(),
                DNSBLS.len()
            ),
        ));
    }
    if !refused.is_empty() {
        let lists: std::collections::BTreeSet<&str> = refused.iter().map(|r| r.list.as_str()).collect();
        let why = refused
            .iter()
            .filter_map(|r| r.meaning.clone())
            .next()
            .unwrap_or_default();
        checks.push(CheckItem::new(
            "DNSBL_INCONCLUSIVE",
            "SECURITY",
            Severity::Info,
            "Some Blocklists Could Not Be Checked",
            format!("{}: {}", lists.into_iter().collect::<Vec<_>>().join(", "), why),
        ));
    }
    dns.dnsbl = results;
}
