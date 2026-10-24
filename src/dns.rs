use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::models::{CheckItem, DnsReport, MxHost, Severity};

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_TXT: u16 = 16;

pub struct DnsResolver {
    nameservers: Vec<SocketAddr>,
    timeout: Duration,
}

impl DnsResolver {
    pub fn new(timeout: Duration) -> Self {
        let mut servers = Self::parse_resolv_conf();
        if servers.is_empty() {
            // Fallbacks: Cloudflare, Google, Quad9
            if let Ok(addr) = "1.1.1.1:53".parse() {
                servers.push(addr);
            }
            if let Ok(addr) = "8.8.8.8:53".parse() {
                servers.push(addr);
            }
        }
        Self {
            nameservers: servers,
            timeout,
        }
    }

    fn parse_resolv_conf() -> Vec<SocketAddr> {
        let mut servers = Vec::new();
        if let Ok(file) = File::open("/etc/resolv.conf") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip_str = parts[1];
                        let socket_str = if ip_str.contains(':') {
                            format!("[{}]:53", ip_str)
                        } else {
                            format!("{}:53", ip_str)
                        };
                        if let Ok(sa) = socket_str.parse::<SocketAddr>() {
                            servers.push(sa);
                        }
                    }
                }
            }
        }
        servers
    }

    pub fn resolve_all(
        &self,
        domain: &str,
        custom_selector: Option<&str>,
    ) -> (DnsReport, Vec<CheckItem>) {
        let clean_domain = domain.trim().trim_end_matches('.').to_lowercase();
        let mut checks = Vec::new();
        let mut report = DnsReport {
            domain: clean_domain.clone(),
            mx_hosts: Vec::new(),
            has_mx_records: false,
            fallback_to_a: false,
            spf_record: None,
            spf_multiple: false,
            spf_mechanisms: Vec::new(),
            spf_lookup_count: 0,
            spf_qualifier: None,
            dmarc_record: None,
            dmarc_policy: None,
            dmarc_pct: 100,
            dmarc_rua: None,
            dkim_selector: None,
            dkim_record: None,
        };

        // 1. Discover MX records
        self.check_mx_records(&clean_domain, &mut report, &mut checks);

        // 2. Discover IPs and Reverse DNS for each MX host
        self.check_ips_and_rdns(&mut report, &mut checks);

        // 3. SPF record check
        self.check_spf(&clean_domain, &mut report, &mut checks);

        // 4. DMARC record check
        self.check_dmarc(&clean_domain, &mut report, &mut checks);

        // 5. DKIM check
        self.check_dkim(&clean_domain, custom_selector, &mut report, &mut checks);

        (report, checks)
    }

    fn check_mx_records(&self, domain: &str, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        match self.query_mx(domain) {
            Ok(records) if !records.is_empty() => {
                report.has_mx_records = true;
                let mut sorted_records = records;
                sorted_records.sort_by_key(|r| r.0); // Sort by priority

                for (pref, mut host) in sorted_records {
                    host = host.trim_end_matches('.').to_string();
                    let is_null = pref == 0 && (host.is_empty() || host == ".");
                    report.mx_hosts.push(MxHost {
                        hostname: host,
                        priority: pref,
                        ipv4_addresses: Vec::new(),
                        ipv6_addresses: Vec::new(),
                        is_cname: false,
                        is_null_mx: is_null,
                        ptr_records: HashMap::new(),
                        fcrdns_valid: HashMap::new(),
                    });
                }

                if report.mx_hosts.iter().any(|h| h.is_null_mx) {
                    checks.push(CheckItem {
                        check_id: "DNS_NULL_MX".to_string(),
                        category: "DNS".to_string(),
                        title: "RFC 7505 Null MX Record Configured".to_string(),
                        severity: Severity::Notice,
                        message: format!("Domain '{}' publishes a Null MX ('0 .'), explicitly rejecting all email.", domain),
                        recommendation: Some("Remove Null MX and add valid MX records if this domain is intended to receive mail.".to_string()),
                        technical_details: None,
                    });
                    return;
                }

                if report.mx_hosts.len() == 1 {
                    checks.push(CheckItem {
                        check_id: "DNS_MX_SINGLE".to_string(),
                        category: "DNS".to_string(),
                        title: "Single MX Host (No Redundancy)".to_string(),
                        severity: Severity::Notice,
                        message: format!("Domain '{}' has only 1 MX record ({}) configured.", domain, report.mx_hosts[0].hostname),
                        recommendation: Some("Configure at least 2 distinct MX servers for high availability.".to_string()),
                        technical_details: None,
                    });
                } else {
                    checks.push(CheckItem {
                        check_id: "DNS_MX_REDUNDANCY".to_string(),
                        category: "DNS".to_string(),
                        title: "MX Redundancy Present".to_string(),
                        severity: Severity::Pass,
                        message: format!("Found {} MX records configured for redundancy.", report.mx_hosts.len()),
                        recommendation: None,
                        technical_details: None,
                    });
                }
            }
            _ => {
                // Fallback to A record (RFC 5321 §5.1)
                if let Ok(ips) = self.query_a(domain) {
                    if !ips.is_empty() {
                        report.has_mx_records = false;
                        report.fallback_to_a = true;
                        report.mx_hosts.push(MxHost {
                            hostname: domain.to_string(),
                            priority: 0,
                            ipv4_addresses: ips,
                            ipv6_addresses: Vec::new(),
                            is_cname: false,
                            is_null_mx: false,
                            ptr_records: HashMap::new(),
                            fcrdns_valid: HashMap::new(),
                        });

                        checks.push(CheckItem {
                            check_id: "DNS_MX_FALLBACK_A".to_string(),
                            category: "DNS".to_string(),
                            title: "No MX Record (RFC 5321 Fallback to Root A)".to_string(),
                            severity: Severity::Warning,
                            message: format!("No MX records found for '{}'; SMTP relies on root A-record fallback.", domain),
                            recommendation: Some("Publish explicit MX records to guarantee reliable email routing.".to_string()),
                            technical_details: None,
                        });
                        return;
                    }
                }

                checks.push(CheckItem {
                    check_id: "DNS_NO_MX_OR_A".to_string(),
                    category: "DNS".to_string(),
                    title: "No Mail Exchanger Discovered".to_string(),
                    severity: Severity::Critical,
                    message: format!("Domain '{}' has neither MX nor A records. Incoming mail cannot be delivered.", domain),
                    recommendation: Some("Add an MX record pointing to your mail server hostname.".to_string()),
                    technical_details: None,
                });
            }
        }
    }

    fn check_ips_and_rdns(&self, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        for mx in &mut report.mx_hosts {
            if mx.is_null_mx || mx.hostname.is_empty() {
                continue;
            }

            // Resolve IPv4
            if let Ok(ips) = self.query_a(&mx.hostname) {
                mx.ipv4_addresses = ips;
            } else if let Ok(addrs) = format!("{}:25", mx.hostname).to_socket_addrs() {
                for addr in addrs {
                    if let SocketAddr::V4(v4) = addr {
                        let ip_str = v4.ip().to_string();
                        if !mx.ipv4_addresses.contains(&ip_str) {
                            mx.ipv4_addresses.push(ip_str);
                        }
                    }
                }
            }

            if mx.ipv4_addresses.is_empty() {
                checks.push(CheckItem {
                    check_id: format!("DNS_NO_IP_{}", mx.hostname),
                    category: "DNS".to_string(),
                    title: format!("MX Host Has No IPv4 Address ({})", mx.hostname),
                    severity: Severity::Critical,
                    message: format!("Hostname '{}' failed to resolve to an IPv4 address.", mx.hostname),
                    recommendation: Some("Create an A record in DNS for this MX hostname.".to_string()),
                    technical_details: None,
                });
                continue;
            }

            // Check Reverse DNS (PTR) and FCrDNS
            for ip in &mx.ipv4_addresses {
                let ptrs = self.query_ptr(ip).unwrap_or_default();
                mx.ptr_records.insert(ip.clone(), ptrs.clone());

                if ptrs.is_empty() {
                    checks.push(CheckItem {
                        check_id: format!("DNS_NO_PTR_{}", ip),
                        category: "DNS".to_string(),
                        title: format!("Missing Reverse DNS (PTR) for {}", ip),
                        severity: Severity::Warning,
                        message: format!("IP {} ({}) does not have a PTR record configured.", ip, mx.hostname),
                        recommendation: Some("Set up a PTR record with your hosting provider / ISP. Major mail providers (Gmail/Yahoo) reject mail from servers without PTR.".to_string()),
                        technical_details: None,
                    });
                    mx.fcrdns_valid.insert(ip.clone(), false);
                } else {
                    // Forward-Confirmed Reverse DNS (FCrDNS)
                    let mut fcrdns_matched = false;
                    for ptr in &ptrs {
                        if let Ok(fwd_ips) = self.query_a(ptr) {
                            if fwd_ips.contains(ip) {
                                fcrdns_matched = true;
                                break;
                            }
                        }
                    }

                    mx.fcrdns_valid.insert(ip.clone(), fcrdns_matched);
                    if !fcrdns_matched {
                        checks.push(CheckItem {
                            check_id: format!("DNS_FCRDNS_MISMATCH_{}", ip),
                            category: "DNS".to_string(),
                            title: format!("FCrDNS Mismatch for {}", ip),
                            severity: Severity::Warning,
                            message: format!("IP {} resolves to PTR '{}', but that hostname does not resolve back to {}.", ip, ptrs[0], ip),
                            recommendation: Some("Ensure your PTR hostname has a matching forward A record pointing back to the same IP.".to_string()),
                            technical_details: None,
                        });
                    } else {
                        checks.push(CheckItem {
                            check_id: format!("DNS_PTR_VALID_{}", ip),
                            category: "DNS".to_string(),
                            title: format!("Valid Reverse DNS for {}", ip),
                            severity: Severity::Pass,
                            message: format!("IP {} has valid Forward-Confirmed Reverse DNS matching '{}'.", ip, ptrs[0]),
                            recommendation: None,
                            technical_details: None,
                        });
                    }
                }
            }
        }
    }

    pub fn parse_spf_mechanisms(raw_spf: &str) -> Vec<String> {
        raw_spf
            .split_whitespace()
            .skip(1)
            .map(|s| s.to_string())
            .collect()
    }

    fn check_spf(&self, domain: &str, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        if let Ok(txts) = self.query_txt(domain) {
            let spf_records: Vec<String> = txts
                .into_iter()
                .filter(|t| t.trim().to_ascii_lowercase().starts_with("v=spf1"))
                .collect();

            if spf_records.is_empty() {
                checks.push(CheckItem {
                    check_id: "SPF_MISSING".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Missing SPF Record".to_string(),
                    severity: Severity::Warning,
                    message: format!("Domain '{}' lacks an SPF TXT record.", domain),
                    recommendation: Some("Publish a 'v=spf1 ... -all' record to authorize legitimate senders and prevent spoofing.".to_string()),
                    technical_details: None,
                });
                return;
            }

            if spf_records.len() > 1 {
                report.spf_multiple = true;
                checks.push(CheckItem {
                    check_id: "SPF_MULTIPLE_RECORDS".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Multiple SPF Records Detected (RFC 7208 PermError)".to_string(),
                    severity: Severity::Critical,
                    message: format!("Found {} SPF records. RFC 7208 §3.2 strictly prohibits more than one SPF record per domain.", spf_records.len()),
                    recommendation: Some("Merge all SPF rules into a single 'v=spf1' record. Multiple records result in immediate evaluation failure.".to_string()),
                    technical_details: Some(format!("Found: {:?}", spf_records)),
                });
            }

            let raw_spf = &spf_records[0];
            report.spf_record = Some(raw_spf.clone());

            let mechanisms = Self::parse_spf_mechanisms(raw_spf);
            report.spf_mechanisms = mechanisms.clone();

            let mut lookups = 0;
            let mut has_ptr = false;

            for m in &mechanisms {
                let clean = m.trim_start_matches(|c| c == '+' || c == '-' || c == '~' || c == '?');
                if clean.starts_with("include:")
                    || clean.starts_with("a")
                    || clean.starts_with("mx")
                    || clean.starts_with("exists:")
                    || clean.starts_with("redirect=")
                {
                    lookups += 1;
                } else if clean.starts_with("ptr") {
                    has_ptr = true;
                    lookups += 1;
                }
            }

            report.spf_lookup_count = lookups;

            if lookups > 10 {
                checks.push(CheckItem {
                    check_id: "SPF_LOOKUP_LIMIT_EXCEEDED".to_string(),
                    category: "SECURITY".to_string(),
                    title: "SPF Lookup Limit Exceeded (> 10)".to_string(),
                    severity: Severity::Critical,
                    message: format!("SPF record requires {} DNS lookups, exceeding the RFC 7208 maximum of 10.", lookups),
                    recommendation: Some("Flatten includes or remove redundant lookups to stay under the 10 DNS query limit.".to_string()),
                    technical_details: None,
                });
            }

            if has_ptr {
                checks.push(CheckItem {
                    check_id: "SPF_PTR_DEPRECATED".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Deprecated 'ptr' Mechanism Used in SPF".to_string(),
                    severity: Severity::Warning,
                    message: "The 'ptr' mechanism is deprecated per RFC 7208 §5.5 and should not be used in SPF records.".to_string(),
                    recommendation: Some("Replace 'ptr' with explicit 'ip4', 'ip6', or 'include' mechanisms.".to_string()),
                    technical_details: None,
                });
            }

            if let Some(all_mech) = mechanisms.iter().find(|m| m.ends_with("all")) {
                report.spf_qualifier = Some(all_mech.clone());
                match all_mech.as_str() {
                    "-all" => checks.push(CheckItem {
                        check_id: "SPF_STRICT_ALL".to_string(),
                        category: "SECURITY".to_string(),
                        title: "Strict SPF Policy (-all)".to_string(),
                        severity: Severity::Pass,
                        message: "SPF policy specifies strict HardFail enforcement (-all).".to_string(),
                        recommendation: None,
                        technical_details: None,
                    }),
                    "~all" => checks.push(CheckItem {
                        check_id: "SPF_SOFTFAIL".to_string(),
                        category: "SECURITY".to_string(),
                        title: "SPF SoftFail Policy (~all)".to_string(),
                        severity: Severity::Pass,
                        message: "SPF policy specifies SoftFail enforcement (~all).".to_string(),
                        recommendation: None,
                        technical_details: None,
                    }),
                    "?all" => checks.push(CheckItem {
                        check_id: "SPF_NEUTRAL".to_string(),
                        category: "SECURITY".to_string(),
                        title: "Weak SPF Policy (?all)".to_string(),
                        severity: Severity::Warning,
                        message: "SPF policy ends with '?all' (Neutral), offering zero spoofing protection.".to_string(),
                        recommendation: Some("Update '?all' to '~all' or '-all'.".to_string()),
                        technical_details: None,
                    }),
                    "+all" | "all" => checks.push(CheckItem {
                        check_id: "SPF_PASS_ALL".to_string(),
                        category: "SECURITY".to_string(),
                        title: "Dangerous SPF Policy (+all)".to_string(),
                        severity: Severity::Critical,
                        message: "SPF ends with '+all', explicitly authorizing the entire Internet to send as your domain!".to_string(),
                        recommendation: Some("Immediately change '+all' to '-all'.".to_string()),
                        technical_details: None,
                    }),
                    _ => {}
                }
            } else {
                checks.push(CheckItem {
                    check_id: "SPF_NO_ALL".to_string(),
                    category: "SECURITY".to_string(),
                    title: "SPF Missing Terminating 'all' Mechanism".to_string(),
                    severity: Severity::Warning,
                    message: "SPF record lacks a terminating 'all' qualifier (such as -all or ~all).".to_string(),
                    recommendation: Some("Append '-all' or '~all' at the end of the SPF record.".to_string()),
                    technical_details: None,
                });
            }
        }
    }

    pub fn parse_dmarc_tags(raw_dmarc: &str) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        for part in raw_dmarc.split(';') {
            let trimmed = part.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                tags.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        tags
    }

    fn check_dmarc(&self, domain: &str, report: &mut DnsReport, checks: &mut Vec<CheckItem>) {
        let dmarc_host = format!("_dmarc.{}", domain);
        if let Ok(txts) = self.query_txt(&dmarc_host) {
            let dmarc_records: Vec<String> = txts
                .into_iter()
                .filter(|t| t.trim().to_ascii_uppercase().starts_with("V=DMARC1"))
                .collect();

            if dmarc_records.is_empty() {
                checks.push(CheckItem {
                    check_id: "DMARC_MISSING".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Missing DMARC Record".to_string(),
                    severity: Severity::Warning,
                    message: format!("No DMARC record found at '{}'.", dmarc_host),
                    recommendation: Some(format!("Create a TXT record at '_dmarc.{}' (e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{}').", domain, domain)),
                    technical_details: None,
                });
                return;
            }

            let raw_dmarc = &dmarc_records[0];
            report.dmarc_record = Some(raw_dmarc.clone());

            let tags = Self::parse_dmarc_tags(raw_dmarc);

            let policy = tags.get("p").map(|s| s.to_lowercase()).unwrap_or_default();
            report.dmarc_policy = Some(policy.clone());
            report.dmarc_rua = tags.get("rua").cloned();
            report.dmarc_pct = tags.get("pct").and_then(|p| p.parse().ok()).unwrap_or(100);

            match policy.as_str() {
                "reject" => checks.push(CheckItem {
                    check_id: "DMARC_POLICY_REJECT".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Strong DMARC Policy (p=reject)".to_string(),
                    severity: Severity::Pass,
                    message: "DMARC policy is set to 'reject', providing maximum domain spoofing protection.".to_string(),
                    recommendation: None,
                    technical_details: None,
                }),
                "quarantine" => checks.push(CheckItem {
                    check_id: "DMARC_POLICY_QUARANTINE".to_string(),
                    category: "SECURITY".to_string(),
                    title: "DMARC Policy (p=quarantine)".to_string(),
                    severity: Severity::Pass,
                    message: "DMARC policy is set to 'quarantine' (suspicious mail sent to spam folder).".to_string(),
                    recommendation: None,
                    technical_details: None,
                }),
                "none" => checks.push(CheckItem {
                    check_id: "DMARC_POLICY_NONE".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Passive DMARC Policy (p=none)".to_string(),
                    severity: Severity::Notice,
                    message: "DMARC policy is in 'none' (monitoring-only) mode; forged emails will not be blocked.".to_string(),
                    recommendation: Some("After reviewing DMARC reports, upgrade policy from 'p=none' to 'p=quarantine' or 'p=reject'.".to_string()),
                    technical_details: None,
                }),
                _ => checks.push(CheckItem {
                    check_id: "DMARC_POLICY_INVALID".to_string(),
                    category: "SECURITY".to_string(),
                    title: "Invalid DMARC Policy".to_string(),
                    severity: Severity::Warning,
                    message: format!("Unrecognized DMARC policy tag 'p={}'.", policy),
                    recommendation: Some("Set 'p=reject', 'p=quarantine', or 'p=none'.".to_string()),
                    technical_details: None,
                }),
            }

            if report.dmarc_rua.is_none() {
                checks.push(CheckItem {
                    check_id: "DMARC_NO_RUA".to_string(),
                    category: "SECURITY".to_string(),
                    title: "DMARC Missing Aggregate Reporting (rua)".to_string(),
                    severity: Severity::Notice,
                    message: "DMARC record lacks an aggregate reporting URI ('rua=mailto:...').".to_string(),
                    recommendation: Some("Add 'rua=mailto:dmarc-reports@...' to receive daily authentication telemetry.".to_string()),
                    technical_details: None,
                });
            }
        }
    }

    fn check_dkim(
        &self,
        domain: &str,
        custom_selector: Option<&str>,
        report: &mut DnsReport,
        checks: &mut Vec<CheckItem>,
    ) {
        let default_selectors = ["default", "google", "k1", "mail", "selector1", "s1", "smtp"];
        let selectors_to_try: Vec<&str> = if let Some(sel) = custom_selector {
            vec![sel]
        } else {
            default_selectors.to_vec()
        };

        for sel in selectors_to_try {
            let dkim_host = format!("{}._domainkey.{}", sel, domain);
            if let Ok(txts) = self.query_txt(&dkim_host) {
                for t in txts {
                    if t.contains("v=DKIM1") || t.contains("p=") {
                        report.dkim_selector = Some(sel.to_string());
                        report.dkim_record = Some(t);
                        checks.push(CheckItem {
                            check_id: "DKIM_FOUND".to_string(),
                            category: "SECURITY".to_string(),
                            title: format!("DKIM Record Discovered ('{}')", sel),
                            severity: Severity::Pass,
                            message: format!("Active DKIM public key record found under selector '{}'.", sel),
                            recommendation: None,
                            technical_details: None,
                        });
                        return;
                    }
                }
            }
        }

        if let Some(sel) = custom_selector {
            checks.push(CheckItem {
                check_id: "DKIM_CUSTOM_NOT_FOUND".to_string(),
                category: "SECURITY".to_string(),
                title: format!("Custom DKIM Selector '{}' Not Found", sel),
                severity: Severity::Warning,
                message: format!("No DKIM key found at '{}._domainkey.{}'.", sel, domain),
                recommendation: Some("Verify selector spelling in your DNS registrar.".to_string()),
                technical_details: None,
            });
        }
    }

    // --- Low-level UDP DNS queries (RFC 1035) ---

    pub fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String> {
        let response = self.send_dns_query(domain, DNS_TYPE_MX)?;
        Self::parse_mx_response(&response)
    }

    pub fn query_a(&self, domain: &str) -> Result<Vec<String>, String> {
        let response = self.send_dns_query(domain, DNS_TYPE_A)?;
        Self::parse_a_response(&response)
    }

    pub fn query_txt(&self, domain: &str) -> Result<Vec<String>, String> {
        let response = self.send_dns_query(domain, DNS_TYPE_TXT)?;
        Self::parse_txt_response(&response)
    }

    pub fn query_ptr(&self, ip: &str) -> Result<Vec<String>, String> {
        let octets: Vec<&str> = ip.trim().split('.').collect();
        if octets.len() != 4 {
            return Err("Invalid IPv4 address".to_string());
        }
        let reverse_name = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
        let response = self.send_dns_query(&reverse_name, DNS_TYPE_PTR)?;
        Self::parse_ptr_response(&response)
    }

    fn send_dns_query(&self, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
        let packet = Self::build_dns_query_packet(name, qtype)?;
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket.set_read_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;
        socket.set_write_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;

        let last_err = String::from("No nameservers reachable");
        for ns in &self.nameservers {
            if socket.send_to(&packet, ns).is_ok() {
                let mut buf = [0u8; 4096];
                if let Ok((len, _)) = socket.recv_from(&mut buf) {
                    return Ok(buf[..len].to_vec());
                }
            }
        }
        Err(last_err)
    }

    pub fn build_dns_query_packet(name: &str, qtype: u16) -> Result<Vec<u8>, String> {
        let mut packet = Vec::with_capacity(64);
        // Header: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
        packet.extend_from_slice(&[0x12, 0x34]); // Transaction ID
        packet.extend_from_slice(&[0x01, 0x00]); // Standard query with recursion desired
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question: QNAME
        for label in name.trim_end_matches('.').split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("Invalid DNS label: '{}'", label));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // Terminating zero byte

        // QTYPE and QCLASS
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN (Internet)

        Ok(packet)
    }

    pub fn parse_mx_response(buf: &[u8]) -> Result<Vec<(u16, String)>, String> {
        if buf.len() < 12 {
            return Err("Truncated DNS response header".to_string());
        }
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        let mut offset = 12;
        // Skip Question section
        for _ in 0..qdcount {
            if offset >= buf.len() {
                return Err("Truncated Question section".to_string());
            }
            offset = Self::skip_name(buf, offset)?;
            if offset.saturating_add(4) > buf.len() {
                return Err("Truncated Question QTYPE/QCLASS".to_string());
            }
            offset += 4; // QTYPE (2) + QCLASS (2)
        }

        let mut results = Vec::new();
        for _ in 0..ancount {
            if offset >= buf.len() {
                break;
            }
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

            if rtype == DNS_TYPE_MX && rdlength >= 3 {
                let pref = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                if let Ok((exchange, _)) = Self::read_name(buf, offset + 2) {
                    results.push((pref, exchange));
                }
            }
            offset += rdlength;
        }

        Ok(results)
    }

    pub fn parse_a_response(buf: &[u8]) -> Result<Vec<String>, String> {
        if buf.len() < 12 {
            return Err("Truncated DNS response header".to_string());
        }
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

        let mut ips = Vec::new();
        for _ in 0..ancount {
            if offset >= buf.len() {
                break;
            }
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

            if rtype == DNS_TYPE_A && rdlength == 4 {
                let ip = format!("{}.{}.{}.{}", buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
                ips.push(ip);
            }
            offset += rdlength;
        }
        Ok(ips)
    }

    pub fn parse_txt_response(buf: &[u8]) -> Result<Vec<String>, String> {
        if buf.len() < 12 {
            return Err("Truncated DNS response header".to_string());
        }
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

        let mut records = Vec::new();
        for _ in 0..ancount {
            if offset >= buf.len() {
                break;
            }
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

            if rtype == DNS_TYPE_TXT {
                let mut txt_chunk_offset = offset;
                let end = offset + rdlength;
                let mut full_txt = String::new();
                while txt_chunk_offset < end {
                    let len = buf[txt_chunk_offset] as usize;
                    txt_chunk_offset += 1;
                    if txt_chunk_offset + len <= end {
                        let s = String::from_utf8_lossy(&buf[txt_chunk_offset..txt_chunk_offset + len]);
                        full_txt.push_str(&s);
                        txt_chunk_offset += len;
                    } else {
                        break;
                    }
                }
                if !full_txt.is_empty() {
                    records.push(full_txt);
                }
            }
            offset += rdlength;
        }
        Ok(records)
    }

    pub fn parse_ptr_response(buf: &[u8]) -> Result<Vec<String>, String> {
        if buf.len() < 12 {
            return Err("Truncated DNS response header".to_string());
        }
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

        let mut ptrs = Vec::new();
        for _ in 0..ancount {
            if offset >= buf.len() {
                break;
            }
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

            if rtype == DNS_TYPE_PTR {
                if let Ok((name, _)) = Self::read_name(buf, offset) {
                    ptrs.push(name.trim_end_matches('.').to_string());
                }
            }
            offset += rdlength;
        }
        Ok(ptrs)
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
                return Ok(offset + 2); // Pointer compression
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
                let ptr_offset = (((len & 0x3F) << 8) | (buf[offset + 1] as usize)) as usize;
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
                let label = String::from_utf8_lossy(&buf[offset..offset + len]).to_string();
                labels.push(label);
                offset += len;
            }
        }

        Err("Unterminated DNS name reached end of packet".to_string())
    }
}
