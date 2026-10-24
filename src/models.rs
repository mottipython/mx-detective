use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Pass,
    Notice,
    Warning,
    Critical,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckItem {
    pub check_id: String,
    pub category: String, // DNS, NETWORK, SMTP, BEHAVIOR, TLS, SECURITY
    pub title: String,
    pub severity: Severity,
    pub message: String,
    pub recommendation: Option<String>,
    pub technical_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxHost {
    pub hostname: String,
    pub priority: u16,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub is_cname: bool,
    pub is_null_mx: bool,
    pub ptr_records: HashMap<String, Vec<String>>, // IP -> PTR hostnames
    pub fcrdns_valid: HashMap<String, bool>,        // IP -> matches forward
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsReport {
    pub domain: String,
    pub mx_hosts: Vec<MxHost>,
    pub has_mx_records: bool,
    pub fallback_to_a: bool,
    pub spf_record: Option<String>,
    pub spf_multiple: bool,
    pub spf_mechanisms: Vec<String>,
    pub spf_lookup_count: usize,
    pub spf_qualifier: Option<String>,
    pub dmarc_record: Option<String>,
    pub dmarc_policy: Option<String>,
    pub dmarc_pct: u8,
    pub dmarc_rua: Option<String>,
    pub dkim_selector: Option<String>,
    pub dkim_record: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub direction: String, // "->" (sent), "<-" (received), "*" (system info)
    pub timestamp: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisbehaviorAnomaly {
    pub code: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub raw_response: String,
    pub rfc_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpReport {
    pub host: String,
    pub port: u16,
    pub connected: bool,
    pub connect_time_ms: f64,
    pub banner: Option<String>,
    pub banner_time_ms: f64,
    pub is_tarpit: bool,
    pub banner_rfc_compliant: bool,
    pub banner_has_fqdn: bool,
    pub early_talker_rejected: bool,
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
    pub rset_working: bool,
    pub quit_clean: bool,
    pub error_message: Option<String>,
    pub anomalies: Vec<MisbehaviorAnomaly>,
    pub transcript: Vec<TranscriptEntry>,
}

impl SmtpReport {
    pub fn max_size_mb(&self) -> Option<f64> {
        self.max_message_size_bytes
            .map(|b| (b as f64) / (1024.0 * 1024.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortProbe {
    pub port: u16,
    pub service: String,
    pub reachable: bool,
    pub latency_ms: f64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticResult {
    pub domain: String,
    pub target_host: Option<String>,
    pub target_ip: Option<String>,
    pub timestamp: String,
    pub port_probes: Vec<PortProbe>,
    pub dns: Option<DnsReport>,
    pub smtp: Option<SmtpReport>,
    pub tls: Option<TlsReport>,
    pub checks: Vec<CheckItem>,
    pub score: i32,
    pub grade: String,
    pub port_25_blocked_suspected: bool,
}

impl DiagnosticResult {
    pub fn new(domain: String, target_host: Option<String>) -> Self {
        Self {
            domain,
            target_host,
            target_ip: None,
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            port_probes: Vec::new(),
            dns: None,
            smtp: None,
            tls: None,
            checks: Vec::new(),
            score: 100,
            grade: "A+".to_string(),
            port_25_blocked_suspected: false,
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
