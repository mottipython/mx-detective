//! Compares two diagnostics of the same domain and lists what changed.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::models::{DiagnosticResult, Severity};
use crate::summary;

/// Largest baseline file that is read; a real result is well under 1 MB.
const MAX_BASELINE_BYTES: u64 = 16 << 20;

/// Summary keys left out of the comparison: they differ on every run, or only repeat the findings.
const SKIPPED_FACTS: &[&str] = &[
    "tool_version",
    "score",
    "grade",
    "critical",
    "warning",
    "notice",
    "pass",
    "critical_ids",
    "warning_ids",
    "cert_days_left",
];

/// Extra keys for `--summary` and `--get` when a baseline is given.
pub const KEYS: &[(&str, &str)] = &[
    ("changes", "number of differences from the baseline"),
    ("regressions", "number of those that are worse"),
    ("improvements", "number of those that are better"),
    ("regression_ids", "comma-separated IDs of the changes that are worse"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Trend {
    Worse,
    Better,
    Neutral,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub id: String,
    pub kind: Kind,
    pub trend: Trend,
    pub old: String,
    pub new: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diff {
    pub domain: String,
    pub baseline_timestamp: String,
    pub baseline_score: i32,
    pub baseline_grade: String,
    pub score: i32,
    pub grade: String,
    pub changes: Vec<Change>,
}

impl Diff {
    pub fn count(&self, trend: Trend) -> usize {
        self.changes.iter().filter(|c| c.trend == trend).count()
    }

    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let ids = self
            .changes
            .iter()
            .filter(|c| c.trend == Trend::Worse)
            .map(|c| c.id.replace(' ', "_"))
            .collect::<Vec<_>>()
            .join(",");
        let values = [
            self.changes.len().to_string(),
            self.count(Trend::Worse).to_string(),
            self.count(Trend::Better).to_string(),
            ids,
        ];
        KEYS.iter().map(|(k, _)| *k).zip(values).collect()
    }
}

/// Reads a saved `--json` result to compare against.
pub fn load_baseline(path: &str) -> Result<DiagnosticResult, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("cannot read {}: {}", path, e))?
        .len();
    if size > MAX_BASELINE_BYTES {
        return Err(format!("{} is too large to be a result", path));
    }
    let json = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
    parse_baseline(&json).map_err(|e| format!("{} is not a mx-detective --json result: {}", path, e))
}

pub fn parse_baseline(json: &str) -> Result<DiagnosticResult, serde_json::Error> {
    serde_json::from_str(json)
}

/// What changed from `old` to `new`. Changes whose ID starts with an `ignore` entry are dropped.
pub fn compare(old: &DiagnosticResult, new: &DiagnosticResult, ignore: &[String]) -> Result<Diff, String> {
    if !old.domain.eq_ignore_ascii_case(&new.domain) {
        return Err(format!("the baseline is for {}, not {}", old.domain, new.domain));
    }
    let mut changes = finding_changes(old, new);
    let (before, after) = (flatten(old), flatten(new));
    for id in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (before.get(id), after.get(id));
        if a != b {
            changes.push(change(id, a.cloned(), b.cloned(), Trend::Neutral));
        }
    }
    changes.retain(|c| {
        !ignore
            .iter()
            .any(|i| c.id.to_ascii_lowercase().starts_with(&i.to_ascii_lowercase()))
    });
    Ok(Diff {
        domain: new.domain.clone(),
        baseline_timestamp: old.timestamp.clone(),
        baseline_score: old.score,
        baseline_grade: old.grade.clone(),
        score: new.score,
        grade: new.grade.clone(),
        changes,
    })
}

fn change(id: &str, old: Option<String>, new: Option<String>, trend: Trend) -> Change {
    let kind = match (&old, &new) {
        (None, _) => Kind::Added,
        (_, None) => Kind::Removed,
        _ => Kind::Changed,
    };
    Change {
        id: id.to_string(),
        kind,
        trend,
        old: old.unwrap_or_default(),
        new: new.unwrap_or_default(),
    }
}

fn rank(severity: Option<Severity>) -> u8 {
    match severity {
        Some(Severity::Notice) => 1,
        Some(Severity::Warning) => 2,
        Some(Severity::Critical) => 3,
        _ => 0,
    }
}

/// The worst severity per check ID, so a finding merged across servers or split by severity compares as one.
fn worst_by_id(result: &DiagnosticResult) -> BTreeMap<&str, Severity> {
    let mut worst: BTreeMap<&str, Severity> = BTreeMap::new();
    for c in &result.checks {
        let entry = worst.entry(c.check_id.as_str()).or_insert(c.severity);
        if rank(Some(c.severity)) > rank(Some(*entry)) {
            *entry = c.severity;
        }
    }
    worst
}

fn finding_changes(old: &DiagnosticResult, new: &DiagnosticResult) -> Vec<Change> {
    let (before, after) = (worst_by_id(old), worst_by_id(new));
    let mut changes = Vec::new();
    for id in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (before.get(id).copied(), after.get(id).copied());
        let (ra, rb) = (rank(a), rank(b));
        // Pass, Info and absent look the same to someone reading the result.
        if a == b || (ra == 0 && rb == 0) {
            continue;
        }
        let trend = match rb.cmp(&ra) {
            std::cmp::Ordering::Greater => Trend::Worse,
            std::cmp::Ordering::Less => Trend::Better,
            std::cmp::Ordering::Equal => Trend::Neutral,
        };
        changes.push(change(
            id,
            a.map(|s| s.label().into()),
            b.map(|s| s.label().into()),
            trend,
        ));
    }
    changes
}

/// Everything that is compared as plain text: the summary facts, the DNS records and each server.
fn flatten(r: &DiagnosticResult) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut put = |key: String, value: Option<String>| {
        if let Some(v) = value {
            map.insert(key, v);
        }
    };
    for (key, value) in summary::pairs(r) {
        if !SKIPPED_FACTS.contains(&key) {
            put(key.to_string(), Some(value));
        }
    }
    if let Some(dns) = &r.dns {
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v.join(", ")
        };
        put(
            "mx".into(),
            Some(sorted(
                dns.mx_hosts
                    .iter()
                    .map(|h| format!("{} {}", h.priority, h.hostname))
                    .collect(),
            )),
        );
        for h in &dns.mx_hosts {
            let ips = h.ipv4_addresses.iter().chain(&h.ipv6_addresses).cloned().collect();
            put(format!("mx addresses {}", h.hostname), Some(sorted(ips)));
        }
        put("spf record".into(), dns.spf_record.clone());
        put("dmarc record".into(), dns.dmarc_record.clone());
        put("tls-rpt record".into(), dns.tls_rpt_record.clone());
        put("bimi record".into(), dns.bimi_record.clone());
        if let Some(m) = &dns.mta_sts {
            put("mta-sts policy id".into(), m.policy_id.clone());
            put("mta-sts max age".into(), m.max_age.map(|a| a.to_string()));
        }
        for k in &dns.dkim_keys {
            put(format!("dkim {}", k.selector), Some(k.describe()));
        }
        for l in dns.dnsbl.iter().filter(|l| l.listed == Some(true)) {
            put(format!("listed {} {}", l.list, l.ip), Some("listed".into()));
        }
    }
    for s in &r.servers {
        let at = |what: &str| format!("server {} {}", s.ip, what);
        put(at("greeting"), s.smtp.connected.then(|| "answers".to_string()));
        if let Some(t) = &s.tls {
            put(at("tls version"), t.tls_version.clone());
            put(at("cipher"), t.cipher_name.clone());
            put(
                at("certificate"),
                t.cert_subject_cn
                    .as_ref()
                    .map(|cn| format!("{} issued by {}", cn, t.cert_issuer.as_deref().unwrap_or("unknown"))),
            );
            put(
                at("fingerprint"),
                t.cert_sha256.as_ref().map(|f| f.chars().take(16).collect()),
            );
            put(at("trusted"), Some(t.chain_verified.to_string()));
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CheckItem, ServerResult, TlsReport};

    fn result(checks: &[(&str, Severity)]) -> DiagnosticResult {
        let mut r = DiagnosticResult::new("example.com".into(), None);
        r.checks = checks
            .iter()
            .map(|(id, s)| CheckItem::new(*id, "DNS", *s, "t", "m"))
            .collect();
        r.calculate_score();
        r
    }

    fn compare_ok(a: &DiagnosticResult, b: &DiagnosticResult) -> Diff {
        compare(a, b, &[]).unwrap()
    }

    fn ids(diff: &Diff, trend: Trend) -> Vec<&str> {
        diff.changes
            .iter()
            .filter(|c| c.trend == trend)
            .map(|c| c.id.as_str())
            .collect()
    }

    #[test]
    fn identical_results_have_no_changes() {
        let r = result(&[("SPF", Severity::Warning), ("TLS", Severity::Pass)]);
        assert!(compare_ok(&r, &r.clone()).changes.is_empty());
    }

    #[test]
    fn new_resolved_and_changed_findings() {
        let old = result(&[
            ("SPF", Severity::Warning),
            ("DMARC", Severity::Notice),
            ("PTR", Severity::Warning),
        ]);
        let new = result(&[
            ("SPF", Severity::Critical),
            ("DMARC", Severity::Pass),
            ("RELAY", Severity::Critical),
        ]);
        let diff = compare_ok(&old, &new);
        assert_eq!(ids(&diff, Trend::Worse), ["RELAY", "SPF"]);
        assert_eq!(ids(&diff, Trend::Better), ["DMARC", "PTR"]);
        let relay = diff.changes.iter().find(|c| c.id == "RELAY").unwrap();
        assert_eq!(
            (relay.kind, relay.old.as_str(), relay.new.as_str()),
            (Kind::Added, "", "CRITICAL")
        );
    }

    #[test]
    fn pass_and_info_churn_is_not_reported() {
        let old = result(&[("A", Severity::Pass)]);
        let new = result(&[("B", Severity::Info)]);
        assert!(compare_ok(&old, &new).changes.is_empty());
    }

    #[test]
    fn worst_severity_wins_when_one_id_is_split() {
        let old = result(&[("TLS", Severity::Notice), ("TLS", Severity::Warning)]);
        let new = result(&[("TLS", Severity::Warning)]);
        assert!(compare_ok(&old, &new).changes.is_empty());
    }

    #[test]
    fn certificate_renewal_changes_only_the_fingerprint() {
        let server = |sha: &str| ServerResult {
            ip: "192.0.2.1".into(),
            tls: Some(TlsReport {
                cert_subject_cn: Some("mx.example.com".into()),
                cert_issuer: Some("Test CA".into()),
                cert_sha256: Some(sha.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (mut old, mut new) = (result(&[]), result(&[]));
        old.servers = vec![server("aaaaaaaaaaaaaaaaaaaa")];
        new.servers = vec![server("bbbbbbbbbbbbbbbbbbbb")];
        let diff = compare_ok(&old, &new);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].id, "server 192.0.2.1 fingerprint");
        assert_eq!(diff.changes[0].trend, Trend::Neutral);
    }

    #[test]
    fn ignore_matches_by_prefix_without_case() {
        let old = result(&[("SPF", Severity::Warning)]);
        let new = result(&[("SPF", Severity::Critical)]);
        let diff = compare(&old, &new, &["spf".to_string()]).unwrap();
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn a_baseline_for_another_domain_is_refused() {
        let mut other = result(&[]);
        other.domain = "example.org".into();
        assert!(compare(&other, &result(&[]), &[]).is_err());
    }

    #[test]
    fn summary_pairs_list_the_worse_ids_without_spaces() {
        let old = result(&[]);
        let new = result(&[("RELAY", Severity::Critical)]);
        let pairs: BTreeMap<_, _> = compare_ok(&old, &new).pairs().into_iter().collect();
        assert_eq!(pairs["changes"], pairs["regressions"]);
        assert_eq!(pairs["regression_ids"], "RELAY");
        assert!(pairs.values().all(|v| !v.contains(' ')));
    }
}
