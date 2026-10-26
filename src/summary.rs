//! Short answers for scripts: stable `key=value` pairs taken from a finished diagnostic.

use crate::models::{DiagnosticResult, Severity};

/// Every key `--summary` prints and `--get` accepts, with what it means. Values never
/// contain spaces or newlines. An empty value means "not applicable or not measured".
pub const KEYS: &[(&str, &str)] = &[
    ("domain", "the domain that was checked"),
    ("tool_version", "version of mx-detective that produced the result"),
    ("score", "health score, 0-100"),
    ("grade", "letter grade: A+, A, B, C, D or F"),
    ("critical", "number of Critical findings"),
    ("warning", "number of Warning findings"),
    ("notice", "number of Notice findings"),
    ("pass", "number of checks that passed"),
    ("critical_ids", "comma-separated IDs of the Critical findings"),
    ("warning_ids", "comma-separated IDs of the Warning findings"),
    ("mx_hosts", "number of MX hosts the domain publishes"),
    ("servers_tested", "number of server addresses tested"),
    (
        "servers_reachable",
        "number of those that answered with an SMTP greeting",
    ),
    ("starttls_servers", "number of servers that offer STARTTLS"),
    (
        "tls_trusted_servers",
        "number of servers with a publicly trusted certificate for their name",
    ),
    (
        "cert_days_left",
        "days until the soonest certificate expires (negative if expired)",
    ),
    ("open_relay", "true if any server accepted a relay test"),
    ("port25", "open, closed or untested"),
    ("spf", "present or missing"),
    ("spf_lookups", "DNS lookups the SPF record needs, of 10 allowed"),
    ("dmarc_policy", "none, quarantine, reject or missing"),
    ("dkim_keys", "number of active DKIM keys found under common selectors"),
    ("mta_sts", "enforce, testing, none or missing"),
    ("dane", "true if any MX host publishes TLSA records"),
    ("dnssec", "signed, unsigned or unknown"),
    ("blocklisted", "number of blocklist listings for the MX addresses"),
];

fn flag(value: bool) -> String {
    value.to_string()
}

/// The `KEYS` in order, with this result's values.
pub fn pairs(result: &DiagnosticResult) -> Vec<(&'static str, String)> {
    let count = |sev: Severity| result.checks.iter().filter(|c| c.severity == sev).count();
    let ids = |sev: Severity| {
        result
            .checks
            .iter()
            .filter(|c| c.severity == sev)
            .map(|c| c.check_id.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    let servers = &result.servers;
    let tls = || servers.iter().filter_map(|s| s.tls.as_ref());
    let dns = result.dns.as_ref();

    let port25 = match result.port_probes.iter().find(|p| p.port == 25) {
        Some(p) if p.reachable => "open",
        Some(_) => "closed",
        None => "untested",
    };
    let dmarc = dns
        .map(|d| d.dmarc_policy.clone().unwrap_or_default())
        .unwrap_or_default();
    let values = [
        result.domain.clone(),
        result.tool_version.clone(),
        result.score.to_string(),
        result.grade.clone(),
        count(Severity::Critical).to_string(),
        count(Severity::Warning).to_string(),
        count(Severity::Notice).to_string(),
        count(Severity::Pass).to_string(),
        ids(Severity::Critical),
        ids(Severity::Warning),
        dns.map(|d| d.mx_hosts.iter().filter(|h| !h.is_null_mx).count())
            .unwrap_or(0)
            .to_string(),
        servers.len().to_string(),
        servers.iter().filter(|s| s.smtp.connected).count().to_string(),
        servers
            .iter()
            .filter(|s| s.smtp.starttls_advertised)
            .count()
            .to_string(),
        tls().filter(|t| t.chain_verified).count().to_string(),
        tls()
            .filter_map(|t| t.cert_days_left)
            .min()
            .map(|d| d.to_string())
            .unwrap_or_default(),
        flag(servers.iter().any(|s| s.smtp.open_relay_detected)),
        port25.to_string(),
        if dns.is_some_and(|d| d.spf_record.is_some()) {
            "present"
        } else {
            "missing"
        }
        .to_string(),
        dns.map(|d| d.spf_lookup_count).unwrap_or(0).to_string(),
        if dmarc.is_empty() { "missing".to_string() } else { dmarc },
        dns.map(|d| d.dkim_keys.iter().filter(|k| !k.revoked).count())
            .unwrap_or(0)
            .to_string(),
        dns.and_then(|d| d.mta_sts.as_ref())
            .map(|s| s.mode.clone().unwrap_or_else(|| "none".to_string()))
            .unwrap_or_else(|| "missing".to_string()),
        flag(dns.is_some_and(|d| d.mx_hosts.iter().any(|h| !h.tlsa_records.is_empty()))),
        match dns.and_then(|d| d.dnssec_signed) {
            Some(true) => "signed",
            Some(false) => "unsigned",
            None => "unknown",
        }
        .to_string(),
        dns.map(|d| d.dnsbl.iter().filter(|r| r.listed == Some(true)).count())
            .unwrap_or(0)
            .to_string(),
    ];
    KEYS.iter().map(|(k, _)| *k).zip(values).collect()
}

/// One `key=value` line per entry.
pub fn to_text(result: &DiagnosticResult) -> String {
    pairs(result).iter().map(|(k, v)| format!("{}={}\n", k, v)).collect()
}

/// The value of one key.
pub fn get(result: &DiagnosticResult, key: &str) -> Option<String> {
    pairs(result).into_iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}
