use mx_detective::models::{
    CheckItem, DiagnosticResult, MisbehaviorAnomaly, PortProbe, Severity, SmtpReport,
    TranscriptEntry,
};
use mx_detective::reporter::DiagnosticReporter;

#[test]
fn test_perfect_score_calculation() {
    let mut res = DiagnosticResult::new("example.com".to_string(), None);
    res.checks.push(CheckItem {
        check_id: "DNS_MX_OK".to_string(),
        category: "DNS".to_string(),
        title: "MX Records Valid".to_string(),
        severity: Severity::Pass,
        message: "Found 2 valid MX servers.".to_string(),
        recommendation: None,
        technical_details: None,
    });
    res.calculate_score();

    assert_eq!(res.score, 100);
    assert_eq!(res.grade, "A+");
}

#[test]
fn test_critical_score_capping() {
    let mut res = DiagnosticResult::new("example.com".to_string(), None);
    // A single critical check has 28 penalty, which would leave 72 (Grade B)
    // but critical issues should cap at 69 (Grade D)
    res.checks.push(CheckItem {
        check_id: "SECURITY_OPEN_RELAY".to_string(),
        category: "SECURITY".to_string(),
        title: "Open Relay Detected".to_string(),
        severity: Severity::Critical,
        message: "Server allows unauthenticated relaying.".to_string(),
        recommendation: Some("Disable open relaying immediately.".to_string()),
        technical_details: None,
    });
    res.calculate_score();

    assert!(res.score <= 69, "Score should be capped at 69 when critical issue exists");
    assert_eq!(res.grade, "D");
}

#[test]
fn test_all_report_formats() {
    let mut res = DiagnosticResult::new("testdomain.org".to_string(), Some("mx1.testdomain.org".to_string()));
    res.target_ip = Some("198.51.100.25".to_string());

    res.checks.push(CheckItem {
        check_id: "BEHAVIOR_NULL_SENDER".to_string(),
        category: "BEHAVIOR".to_string(),
        title: "Rejects Null Sender (MAIL FROM:<>)".to_string(),
        severity: Severity::Critical,
        message: "Server rejected MAIL FROM:<> with 550.".to_string(),
        recommendation: Some("Configure MTA to accept null sender.".to_string()),
        technical_details: None,
    });

    res.port_probes.push(PortProbe {
        port: 25,
        service: "SMTP".to_string(),
        reachable: true,
        latency_ms: 32.5,
        error: None,
    });

    let smtp = SmtpReport {
        host: "mx1.testdomain.org".to_string(),
        port: 25,
        connected: true,
        connect_time_ms: 15.0,
        banner: Some("220 mx1.testdomain.org ESMTP".to_string()),
        banner_time_ms: 45.0,
        is_tarpit: false,
        banner_rfc_compliant: true,
        banner_has_fqdn: true,
        early_talker_rejected: false,
        esmtp_supported: true,
        multiline_format_valid: true,
        capabilities: vec!["STARTTLS".to_string(), "SIZE 52428800".to_string()],
        max_message_size_bytes: Some(52428800),
        auth_mechanisms: vec!["PLAIN".to_string()],
        plaintext_auth_offered: true,
        starttls_advertised: true,
        pipelining_supported: true,
        chunking_supported: false,
        smtputf8_supported: true,
        null_sender_accepted: Some(false),
        open_relay_tested: true,
        open_relay_detected: false,
        open_relay_response: Some("550 Relay access denied".to_string()),
        recipient_tested: None,
        recipient_accepted: None,
        recipient_response: None,
        rset_working: true,
        quit_clean: true,
        error_message: None,
        anomalies: vec![MisbehaviorAnomaly {
            code: "REJECTS_NULL_SENDER".to_string(),
            title: "RFC 5321 §3.6 Violation: Rejects Null Sender".to_string(),
            severity: Severity::Critical,
            description: "Server rejects MAIL FROM:<> breaking bounce delivery.".to_string(),
            raw_response: "550 5.1.0 Sender rejected".to_string(),
            rfc_reference: "RFC 5321 §3.6".to_string(),
        }],
        transcript: vec![
            TranscriptEntry {
                direction: "<-".to_string(),
                timestamp: "12:00:00.123".to_string(),
                text: "220 mx1.testdomain.org ESMTP".to_string(),
            },
            TranscriptEntry {
                direction: "->".to_string(),
                timestamp: "12:00:00.124".to_string(),
                text: "EHLO diagnostic.local".to_string(),
            },
        ],
    };

    res.smtp = Some(smtp);
    res.calculate_score();

    // 1. JSON
    let json_output = DiagnosticReporter::to_json(&res);
    assert!(json_output.contains("testdomain.org"));
    assert!(json_output.contains("REJECTS_NULL_SENDER"));

    // 2. HTML
    let html_output = DiagnosticReporter::to_html(&res);
    assert!(html_output.contains("<!DOCTYPE html>"));
    assert!(html_output.contains("testdomain.org"));
    assert!(html_output.contains("RFC 5321 §3.6"));

    // 3. Markdown
    let md_output = DiagnosticReporter::to_markdown(&res);
    assert!(md_output.contains("# 🕵️ MX Detective Diagnostic Report: testdomain.org"));
    assert!(md_output.contains("RFC 5321 §3.6"));
    assert!(md_output.contains("```smtp"));

    // 4. CSV
    let csv_output = DiagnosticReporter::to_csv(&res);
    assert!(csv_output.contains("Type,Category,Severity,Title,Message,Recommendation,Reference"));
    assert!(csv_output.contains("\"Anomaly\",\"SMTP\""));

    // 5. Plain Text
    let txt_output = DiagnosticReporter::to_text(&res);
    assert!(txt_output.contains("MX DETECTIVE REPORT: testdomain.org"));
    assert!(txt_output.contains("DETECTED SMTP PROTOCOL MISBEHAVIORS"));
}
