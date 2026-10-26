use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Severity {
    Pass,
    Notice,
    Warning,
    Critical,
    #[default]
    Info,
}

impl Severity {
    pub fn badge(&self) -> &'static str {
        match self {
            Severity::Pass => "✓ PASS",
            Severity::Notice => "ℹ NOTICE",
            Severity::Warning => "⚠ WARNING",
            Severity::Critical => "✗ CRITICAL",
            Severity::Info => "ℹ INFO",
        }
    }

    /// The badge without symbols, for output that must survive any console code page.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Notice => "NOTICE",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
            Severity::Info => "INFO",
        }
    }

    pub fn penalty(&self) -> i32 {
        match self {
            Severity::Pass => 0,
            Severity::Notice => 3,
            Severity::Warning => 12,
            Severity::Critical => 28,
            Severity::Info => 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckItem {
    pub check_id: String,
    pub category: String, // DNS, NETWORK, SMTP, BEHAVIOR, TLS, SECURITY
    pub title: String,
    pub severity: Severity,
    pub message: String,
    pub recommendation: Option<String>,
    pub technical_details: Option<String>,
}

impl CheckItem {
    pub fn new(
        check_id: impl Into<String>,
        category: &str,
        severity: Severity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            category: category.to_string(),
            title: title.into(),
            severity,
            message: message.into(),
            recommendation: None,
            technical_details: None,
        }
    }

    pub fn fix(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = Some(recommendation.into());
        self
    }

    pub fn details(mut self, details: impl Into<String>) -> Self {
        self.technical_details = Some(details.into());
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MxHost {
    pub hostname: String,
    pub priority: u16,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub is_cname: bool,
    pub is_null_mx: bool,
    pub ptr_records: HashMap<String, Vec<String>>, // IP -> PTR hostnames
    pub fcrdns_valid: HashMap<String, bool>,       // IP -> matches forward
    pub tlsa_records: Vec<TlsaRecord>,             // _25._tcp.<host>
    pub tlsa_dnssec_valid: Option<bool>,           // AD bit on the TLSA answer
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub data_hex: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtaStsReport {
    pub txt_record: Option<String>,
    pub policy_id: Option<String>,
    pub policy_url: String,
    pub policy_fetched: bool,
    pub fetch_error: Option<String>,
    pub raw_policy: Option<String>,
    pub mode: Option<String>,
    pub mx_patterns: Vec<String>,
    pub max_age: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DkimKey {
    pub selector: String,
    pub record: String,
    pub key_type: String, // k= tag, "rsa" when absent
    pub approx_bits: Option<u32>,
    pub revoked: bool,
}

impl DkimKey {
    pub fn parse(selector: &str, record: String) -> Self {
        let tag = |name: &str| {
            record.split(';').find_map(|part| {
                let (k, v) = part.split_once('=')?;
                (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().to_string())
            })
        };
        let key_type = tag("k").unwrap_or_else(|| "rsa".to_string()).to_ascii_lowercase();
        let p: String = tag("p")
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let revoked = p.is_empty();
        // An RSA public key in SPKI form is about bits/8 + 38 bytes of DER.
        let approx_bits = (key_type == "rsa" && !revoked).then(|| {
            let der_len = p.trim_end_matches('=').len() * 3 / 4;
            let raw = (der_len.saturating_sub(38) * 8) as u32;
            *[512u32, 768, 1024, 2048, 3072, 4096]
                .iter()
                .min_by_key(|b| b.abs_diff(raw))
                .unwrap_or(&2048)
        });
        Self {
            selector: selector.to_string(),
            record,
            key_type,
            approx_bits,
            revoked,
        }
    }

    pub fn describe(&self) -> String {
        match (self.revoked, self.approx_bits) {
            (true, _) => "revoked".to_string(),
            (_, Some(b)) => format!("{} ~{}-bit", self.key_type, b),
            _ => self.key_type.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsblResult {
    pub ip: String,
    pub list: String,
    pub listed: Option<bool>, // None = list refused or did not answer
    pub return_codes: Vec<String>,
    pub meaning: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsReport {
    pub domain: String,
    pub mx_hosts: Vec<MxHost>,
    pub has_mx_records: bool,
    pub fallback_to_a: bool,
    pub spf_record: Option<String>,
    pub spf_multiple: bool,
    pub spf_mechanisms: Vec<String>,
    pub spf_lookup_count: usize, // counted across the whole include/redirect tree
    pub spf_void_lookups: usize,
    pub spf_qualifier: Option<String>,
    pub dmarc_record: Option<String>,
    pub dmarc_policy: Option<String>,
    pub dmarc_pct: u8,
    pub dmarc_rua: Option<String>,
    pub dmarc_ruf: Option<String>,
    pub dmarc_sp: Option<String>,
    pub dmarc_adkim: Option<String>,
    pub dmarc_aspf: Option<String>,
    pub dkim_keys: Vec<DkimKey>,
    pub dnssec_signed: Option<bool>, // None = no validating resolver answered
    pub mta_sts: Option<MtaStsReport>,
    pub tls_rpt_record: Option<String>,
    pub bimi_record: Option<String>,
    pub dnsbl: Vec<DnsblResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub direction: String, // "->" (sent), "<-" (received), "*" (system info)
    pub timestamp: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MisbehaviorAnomaly {
    pub code: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub raw_response: String,
    pub rfc_reference: String,
}

impl MisbehaviorAnomaly {
    pub fn new(
        code: &str,
        severity: Severity,
        rfc_reference: &str,
        title: impl Into<String>,
        description: impl Into<String>,
        raw_response: impl Into<String>,
    ) -> Self {
        Self {
            code: code.to_string(),
            title: title.into(),
            severity,
            description: description.into(),
            raw_response: raw_response.into(),
            rfc_reference: rfc_reference.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmtpReport {
    pub host: String,
    pub ip: Option<String>,
    pub port: u16,
    pub connected: bool,
    pub connect_time_ms: f64,
    pub banner: Option<String>,
    pub banner_time_ms: f64,
    pub is_tarpit: bool,
    pub banner_rfc_compliant: bool,
    pub banner_has_fqdn: bool,
    pub esmtp_supported: bool,
    pub multiline_format_valid: bool,
    pub capabilities: Vec<String>,
    pub max_message_size_bytes: Option<u64>,
    pub auth_mechanisms: Vec<String>,
    pub plaintext_auth_offered: bool,
    pub starttls_advertised: bool,
    pub pipelining_supported: bool,
    pub chunking_supported: bool,
    pub smtputf8_supported: bool,
    pub null_sender_accepted: Option<bool>, // MAIL FROM:<>
    pub open_relay_tested: bool,
    pub open_relay_detected: bool,
    pub open_relay_response: Option<String>,
    pub recipient_tested: Option<String>,
    pub recipient_accepted: Option<bool>,
    pub recipient_response: Option<String>,
    pub postmaster_accepted: Option<bool>,
    pub postmaster_response: Option<String>,
    pub greylisting_suspected: bool,
    pub catch_all_detected: Option<bool>,
    pub vrfy_response: Option<String>,
    pub expn_response: Option<String>,
    pub rset_working: bool,
    pub quit_clean: bool,
    pub error_message: Option<String>,
    pub anomalies: Vec<MisbehaviorAnomaly>,
    pub transcript: Vec<TranscriptEntry>,
}

impl SmtpReport {
    pub fn max_size_mb(&self) -> Option<f64> {
        self.max_message_size_bytes.map(|b| (b as f64) / (1024.0 * 1024.0))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsReport {
    pub host: String,
    pub port: u16,
    pub starttls_attempted: bool,
    pub handshake_success: bool,
    pub tls_version: Option<String>,
    pub cipher_name: Option<String>,
    pub cert_subject_cn: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_sans: Vec<String>,
    pub cert_san_matches_host: bool,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_days_left: Option<i64>,
    pub cert_is_expired: bool,
    pub chain_verified: bool,
    pub verify_error: Option<String>, // why the chain or name did not verify
    pub cert_sha256: Option<String>,
    pub chain_length: usize,
    pub dane_status: Option<String>,
    pub error_message: Option<String>,
}

/// One SMTP session against one address of one MX host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerResult {
    pub hostname: String,
    pub ip: String,
    pub priority: u16,
    pub smtp: SmtpReport,
    pub tls: Option<TlsReport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortProbe {
    pub port: u16,
    pub service: String,
    pub reachable: bool,
    pub latency_ms: f64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiagnosticResult {
    pub tool_version: String,
    pub domain: String,
    pub target_host: Option<String>,
    pub target_ip: Option<String>,
    pub timestamp: String,
    pub port_probes: Vec<PortProbe>,
    pub dns: Option<DnsReport>,
    pub smtp: Option<SmtpReport>,
    pub tls: Option<TlsReport>,
    pub servers: Vec<ServerResult>, // every MX address tested; smtp/tls above are the primary one
    pub checks: Vec<CheckItem>,
    pub score: i32,
    pub grade: String,
    pub port_25_blocked_suspected: bool,
}

impl DiagnosticResult {
    pub fn new(domain: String, target_host: Option<String>) -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            domain,
            target_host,
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            score: 100,
            grade: "A+".to_string(),
            ..Default::default()
        }
    }

    pub fn calculate_score(&mut self) {
        let mut deduction = 0;
        let mut has_critical = false;

        for check in &self.checks {
            deduction += check.severity.penalty();
            if check.severity == Severity::Critical {
                has_critical = true;
            }
        }

        let mut calc = (100 - deduction).max(0);
        if has_critical && calc > 59 {
            calc = 59; // Cap at D if any critical security or behavioral issue exists
        }

        self.score = calc;
        self.grade = if self.score >= 95 {
            "A+".to_string()
        } else if self.score >= 88 {
            "A".to_string()
        } else if self.score >= 78 {
            "B".to_string()
        } else if self.score >= 65 {
            "C".to_string()
        } else if self.score >= 50 {
            "D".to_string()
        } else {
            "F".to_string()
        };
    }
}
