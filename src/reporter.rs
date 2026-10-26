use crate::models::{DiagnosticResult, DnsReport, MisbehaviorAnomaly, Severity, SmtpReport};

pub struct DiagnosticReporter;

/// Every SMTP session, labelled; falls back to the single primary session.
fn sessions(result: &DiagnosticResult) -> Vec<(String, &SmtpReport)> {
    if result.servers.is_empty() {
        result.smtp.iter().map(|s| (s.host.clone(), s)).collect()
    } else {
        result
            .servers
            .iter()
            .map(|s| (format!("{} ({})", s.hostname, s.ip), &s.smtp))
            .collect()
    }
}

/// The same anomaly on several servers, reported once with where it was seen.
fn grouped_anomalies(result: &DiagnosticResult) -> Vec<(&MisbehaviorAnomaly, String)> {
    let all = sessions(result);
    let mut out: Vec<(&MisbehaviorAnomaly, Vec<String>)> = Vec::new();
    for (label, smtp) in &all {
        for a in &smtp.anomalies {
            match out.iter_mut().find(|(x, _)| x.code == a.code) {
                Some((_, labels)) => labels.push(label.clone()),
                None => out.push((a, vec![label.clone()])),
            }
        }
    }
    out.into_iter()
        .map(|(a, labels)| {
            let seen = match (all.len(), labels.len()) {
                (0..=1, _) => String::new(),
                (t, n) if n == t => format!("all {} servers", t),
                _ => labels.join(", "),
            };
            (a, seen)
        })
        .collect()
}

const SERVER_HEADERS: [&str; 8] = [
    "Host",
    "Address",
    "SMTP",
    "STARTTLS",
    "TLS",
    "Certificate",
    "Expires",
    "DANE",
];

fn server_rows(result: &DiagnosticResult) -> Vec<[String; 8]> {
    result
        .servers
        .iter()
        .map(|s| {
            let smtp = if s.smtp.connected { "OK" } else { "unreachable" };
            let starttls = match (s.smtp.starttls_advertised, s.smtp.connected) {
                (true, _) => "yes",
                (false, true) => "NO",
                _ => "-",
            };
            let dash = || "-".to_string();
            let (tls, cert, exp, dane) = match &s.tls {
                Some(t) if t.handshake_success => (
                    format!(
                        "{} {}",
                        t.tls_version.as_deref().unwrap_or("?"),
                        t.cipher_name.as_deref().unwrap_or("")
                    ),
                    match &t.verify_error {
                        None => format!(
                            "trusted: {} / {}",
                            t.cert_subject_cn.as_deref().unwrap_or("?"),
                            t.cert_issuer.as_deref().unwrap_or("?")
                        ),
                        Some(e) => format!("NOT trusted ({}): {}", e, t.cert_subject_cn.as_deref().unwrap_or("?")),
                    },
                    t.cert_days_left.map(|d| format!("{} days", d)).unwrap_or_else(dash),
                    t.dane_status.clone().unwrap_or_else(dash),
                ),
                Some(t) => (
                    format!("FAILED: {}", t.error_message.as_deref().unwrap_or("?")),
                    dash(),
                    dash(),
                    dash(),
                ),
                None => (dash(), dash(), dash(), dash()),
            };
            [
                s.hostname.clone(),
                s.ip.clone(),
                smtp.into(),
                starttls.into(),
                tls,
                cert,
                exp,
                dane,
            ]
        })
        .collect()
}

/// Mail-authentication and transport-security records as label/value pairs.
fn record_lines(dns: &DnsReport) -> Vec<(&'static str, String)> {
    let or_none = |o: &Option<String>| o.clone().unwrap_or_else(|| "none".to_string());
    let mut v = vec![
        ("SPF", or_none(&dns.spf_record)),
        (
            "SPF lookups",
            format!("{} of 10 (whole include tree)", dns.spf_lookup_count),
        ),
        ("DMARC", or_none(&dns.dmarc_record)),
        (
            "DKIM",
            if dns.dkim_keys.is_empty() {
                "none found".to_string()
            } else {
                dns.dkim_keys
                    .iter()
                    .map(|k| format!("{} ({})", k.selector, k.describe()))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ),
        (
            "DNSSEC",
            match dns.dnssec_signed {
                Some(true) => "signed and validated",
                Some(false) => "not signed",
                None => "unknown",
            }
            .to_string(),
        ),
        (
            "MTA-STS",
            match &dns.mta_sts {
                Some(sts) if sts.policy_fetched => format!(
                    "mode={} max_age={} mx={}",
                    sts.mode.as_deref().unwrap_or("?"),
                    sts.max_age.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
                    sts.mx_patterns.join(", ")
                ),
                Some(sts) => format!(
                    "TXT present, policy fetch failed: {}",
                    sts.fetch_error.as_deref().unwrap_or("?")
                ),
                None => "not configured".to_string(),
            },
        ),
        ("TLS-RPT", or_none(&dns.tls_rpt_record)),
        ("BIMI", or_none(&dns.bimi_record)),
    ];
    for mx in dns.mx_hosts.iter().filter(|h| !h.tlsa_records.is_empty()) {
        let recs: Vec<String> = mx
            .tlsa_records
            .iter()
            .map(|t| format!("{} {} {} {}", t.usage, t.selector, t.matching_type, t.data_hex))
            .collect();
        let dnssec = if mx.tlsa_dnssec_valid == Some(true) {
            "DNSSEC ok"
        } else {
            "not DNSSEC-validated"
        };
        v.push(("TLSA", format!("{}: {} ({})", mx.hostname, recs.join(" | "), dnssec)));
    }
    if !dns.dnsbl.is_empty() {
        let listed: Vec<String> = dns
            .dnsbl
            .iter()
            .filter(|r| r.listed == Some(true))
            .map(|r| format!("{} on {}", r.ip, r.list))
            .collect();
        v.push((
            "Blocklists",
            if listed.is_empty() {
                "no listings".to_string()
            } else {
                listed.join(", ")
            },
        ));
    }
    v
}

fn addresses(mx: &crate::models::MxHost) -> Vec<String> {
    mx.ipv4_addresses.iter().chain(&mx.ipv6_addresses).cloned().collect()
}

fn counts(result: &DiagnosticResult) -> [usize; 4] {
    let n = |s: Severity| result.checks.iter().filter(|c| c.severity == s).count();
    [
        n(Severity::Critical),
        n(Severity::Warning),
        n(Severity::Notice),
        n(Severity::Pass),
    ]
}

impl DiagnosticReporter {
    pub fn to_json(result: &DiagnosticResult) -> String {
        // ASCII only (non-ASCII as \u escapes), so any console code page reads it correctly.
        escape_non_ascii(&serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string()))
    }

    pub fn to_text(result: &DiagnosticResult) -> String {
        let mut out = String::new();
        let border = "=".repeat(78);
        let divider = "-".repeat(78);
        let section = |out: &mut String, title: &str| {
            out.push_str(&format!("{d}\n{t}\n{d}\n", d = divider, t = title));
        };

        out.push_str(&format!("{}\n", border));
        out.push_str(&format!(" MX DETECTIVE REPORT: {}\n", result.domain));
        out.push_str(&format!(
            " Target Host: {} ({})\n",
            result.target_host.as_deref().unwrap_or("N/A"),
            result.target_ip.as_deref().unwrap_or("No IP")
        ));
        out.push_str(&format!(" Timestamp:   {}\n", result.timestamp));
        out.push_str(&format!(
            " Overall Score: {}/100 (Grade: {})\n{}\n\n",
            result.score, result.grade, border
        ));

        if result.port_25_blocked_suspected {
            out.push_str(">>> NOTICE: Outbound Port 25 appears blocked by local ISP or Firewall <<<\n\n");
        }

        let [crits, warns, notices, passes] = counts(result);
        out.push_str(&format!(
            "FINDINGS: {} Critical | {} Warnings | {} Notices | {} Passed\n{}\n",
            crits, warns, notices, passes, divider
        ));
        for c in &result.checks {
            out.push_str(&format!(
                " [{}] [{}] {}\n    {}\n",
                c.severity.label(),
                c.category,
                c.title,
                c.message
            ));
            if let Some(rec) = &c.recommendation {
                out.push_str(&format!("    -> Action: {}\n", rec));
            }
            out.push('\n');
        }

        let anomalies = grouped_anomalies(result);
        if !anomalies.is_empty() {
            section(
                &mut out,
                &format!("DETECTED SMTP PROTOCOL MISBEHAVIORS ({}):", anomalies.len()),
            );
            for (a, seen) in &anomalies {
                out.push_str(&format!(
                    " * [{}] {}: {}\n   Raw Response: {}\n",
                    a.rfc_reference, a.title, a.description, a.raw_response
                ));
                if !seen.is_empty() {
                    out.push_str(&format!("   Seen on: {}\n", seen));
                }
            }
            out.push('\n');
        }

        if !result.servers.is_empty() {
            section(&mut out, &format!("SERVERS TESTED ({}):", result.servers.len()));
            for r in server_rows(result) {
                out.push_str(&format!(
                    " {} [{}]  SMTP {}  STARTTLS {}  {}\n",
                    r[0], r[1], r[2], r[3], r[4]
                ));
                if r[5] != "-" {
                    out.push_str(&format!("    cert: {}  expires in {}  DANE: {}\n", r[5], r[6], r[7]));
                }
            }
            out.push('\n');
        }

        if let Some(dns) = &result.dns {
            section(&mut out, "MX RECORDS & MAIL POLICY RECORDS:");
            for mx in &dns.mx_hosts {
                let ips = addresses(mx).join(", ");
                out.push_str(&format!(
                    " Priority {:<3} {} -> {}\n",
                    mx.priority,
                    mx.hostname,
                    if ips.is_empty() { "No IP" } else { &ips }
                ));
            }
            for (k, v) in record_lines(dns) {
                out.push_str(&format!(" {:<12} {}\n", format!("{}:", k), v));
            }
            out.push('\n');
        }

        section(&mut out, "PORT PROBES:");
        for p in &result.port_probes {
            let st = if p.reachable {
                format!("OPEN ({:.0} ms)", p.latency_ms)
            } else {
                format!("CLOSED / TIMEOUT ({})", p.error.as_deref().unwrap_or("Unreachable"))
            };
            out.push_str(&format!(" Port {:<5} {:<30} : {}\n", p.port, p.service, st));
        }
        out.push_str(&format!("\n{}\n", border));
        ascii_fold(&out)
    }

    pub fn to_markdown(result: &DiagnosticResult) -> String {
        let mut md = String::new();
        md.push_str(&format!("# 🕵️ MX Detective Diagnostic Report: {}\n\n", result.domain));
        md.push_str(&format!(
            "- **Target Host:** `{}` (`{}`)\n",
            result.target_host.as_deref().unwrap_or("N/A"),
            result.target_ip.as_deref().unwrap_or("No IP")
        ));
        md.push_str(&format!("- **Timestamp:** `{}`\n", result.timestamp));
        md.push_str(&format!(
            "- **Overall Health Score:** **{}/100 (Grade: {})**\n\n",
            result.score, result.grade
        ));

        if result.port_25_blocked_suspected {
            md.push_str(
                "> ⚠️ **Notice: Outbound port 25 appears blocked by your local network / ISP / Cloud Provider.**\n",
            );
            md.push_str("> Residential broadband and cloud compute instances (AWS, Azure, GCP) block outbound port 25 by default. Inbound email may still function normally.\n\n");
        }

        let table = |md: &mut String, headers: &[&str], rows: Vec<Vec<String>>| {
            md.push_str(&format!(
                "| {} |\n|{}\n",
                headers.join(" | "),
                "---|".repeat(headers.len())
            ));
            for r in rows {
                md.push_str(&format!(
                    "| {} |\n",
                    r.iter().map(|c| md_cell(c)).collect::<Vec<_>>().join(" | ")
                ));
            }
            md.push('\n');
        };

        let anomalies = grouped_anomalies(result);
        if !anomalies.is_empty() {
            md.push_str("## 🚨 Detected Protocol Misbehaviors & RFC Violations\n\n");
            let rows = anomalies
                .iter()
                .map(|(a, seen)| {
                    vec![
                        format!("`{}`", a.rfc_reference),
                        format!("`{}`", a.severity.badge()),
                        format!("**{}**", a.title),
                        a.description.clone(),
                        format!("`{}`", a.raw_response),
                        seen.clone(),
                    ]
                })
                .collect();
            table(
                &mut md,
                &[
                    "RFC Reference",
                    "Severity",
                    "Issue",
                    "Description",
                    "Raw Response",
                    "Seen On",
                ],
                rows,
            );
        }

        md.push_str("## 📋 Audit Findings & Recommendations\n\n");
        let rows = result
            .checks
            .iter()
            .map(|c| {
                vec![
                    format!("`{}`", c.severity.badge()),
                    format!("**{}**", c.category),
                    c.title.clone(),
                    c.message.clone(),
                    c.recommendation.clone().unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        table(
            &mut md,
            &["Status", "Category", "Title", "Details", "Action Required"],
            rows,
        );

        if !result.servers.is_empty() {
            md.push_str("## 🔒 Servers Tested & TLS\n\n");
            table(
                &mut md,
                &SERVER_HEADERS,
                server_rows(result).into_iter().map(|r| r.to_vec()).collect(),
            );
        }

        if let Some(dns) = &result.dns {
            md.push_str("## 🌐 Mail Exchanger (MX) Records\n\n");
            let rows = dns
                .mx_hosts
                .iter()
                .map(|mx| {
                    let ptrs: Vec<String> = mx.ptr_records.values().flatten().cloned().collect();
                    let ips = addresses(mx);
                    vec![
                        mx.priority.to_string(),
                        format!("`{}`", mx.hostname),
                        if ips.is_empty() {
                            "No IP".into()
                        } else {
                            format!("`{}`", ips.join(", "))
                        },
                        if ptrs.is_empty() {
                            "No PTR".into()
                        } else {
                            format!("`{}`", ptrs.join(", "))
                        },
                    ]
                })
                .collect();
            table(
                &mut md,
                &["Priority", "Hostname", "Resolved IP", "Reverse DNS (PTR)"],
                rows,
            );

            md.push_str("### 🔒 Email Authentication & Transport Security\n\n");
            for (k, v) in record_lines(dns) {
                md.push_str(&format!("- **{}:** `{}`\n", k, v.replace('`', "'")));
            }
            md.push('\n');
        }

        md.push_str("## 🔌 Port Reachability\n\n");
        let rows = result
            .port_probes
            .iter()
            .map(|p| {
                vec![
                    p.port.to_string(),
                    p.service.clone(),
                    if p.reachable { "✅ OPEN" } else { "❌ CLOSED" }.into(),
                    if p.reachable {
                        format!("{:.0} ms", p.latency_ms)
                    } else {
                        "-".into()
                    },
                    p.error.clone().unwrap_or_else(|| "OK".into()),
                ]
            })
            .collect();
        table(&mut md, &["Port", "Service", "Status", "Latency", "Details"], rows);

        let all = sessions(result);
        if !all.is_empty() {
            md.push_str("## 📜 Raw SMTP Transcript\n\n");
            for (label, smtp) in &all {
                if all.len() > 1 {
                    md.push_str(&format!("### {}\n\n", label));
                }
                md.push_str("```smtp\n");
                for t in &smtp.transcript {
                    // A server line containing a fence would end the code block early.
                    md.push_str(&format!(
                        "{} {} {}\n",
                        t.timestamp,
                        t.direction,
                        t.text.replace("```", "` ` `")
                    ));
                }
                md.push_str("```\n\n");
            }
        }
        md
    }

    pub fn to_csv(result: &DiagnosticResult) -> String {
        let mut csv = String::from("Type,Category,Severity,Title,Message,Recommendation,Reference\n");
        let mut row = |cols: [&str; 7]| {
            let quoted: Vec<String> = cols.iter().map(|c| format!("\"{}\"", c.replace('"', "\"\""))).collect();
            csv.push_str(&quoted.join(","));
            csv.push('\n');
        };

        for c in &result.checks {
            let sev = format!("{:?}", c.severity);
            row([
                "Check",
                &c.category,
                &sev,
                &c.title,
                &c.message,
                c.recommendation.as_deref().unwrap_or(""),
                "",
            ]);
        }
        for (a, _) in grouped_anomalies(result) {
            let sev = format!("{:?}", a.severity);
            row(["Anomaly", "SMTP", &sev, &a.title, &a.description, "", &a.rfc_reference]);
        }
        for r in server_rows(result) {
            let title = format!("{} {}", r[0], r[1]);
            let msg = format!("SMTP {}; STARTTLS {}; {}", r[2], r[3], r[4]);
            let cert = format!("{}; expires in {}", r[5], r[6]);
            let dane = format!("DANE: {}", r[7]);
            row(["Server", "TLS", "Info", &title, &msg, &cert, &dane]);
        }
        for p in &result.port_probes {
            let title = format!("Port {}", p.port);
            let lat = format!("Latency {:.0} ms", p.latency_ms);
            row([
                "PortProbe",
                "NETWORK",
                if p.reachable { "Pass" } else { "Critical" },
                &title,
                &lat,
                p.error.as_deref().unwrap_or("Reachable"),
                "",
            ]);
        }
        if let Some(dns) = &result.dns {
            for mx in &dns.mx_hosts {
                let title = format!("Priority {}", mx.priority);
                let host = format!("Hostname: {}", mx.hostname);
                let ips = format!("IPs: {}", addresses(mx).join("; "));
                row(["MXRecord", "DNS", "Info", &title, &host, &ips, ""]);
            }
        }
        csv
    }

    pub fn to_html(result: &DiagnosticResult) -> String {
        let grade_color = match result.grade.as_str() {
            "A+" | "A" => "#10b981",
            "B" => "#2563eb",
            "C" => "#d97706",
            "D" | "F" => "#dc2626",
            _ => "#6b7280",
        };
        let table = |headers: &[&str], rows: Vec<Vec<String>>, empty: &str| {
            let mut t = String::from("<div class=\"scroll-x\"><table><thead><tr>");
            for h in headers {
                t.push_str(&format!("<th>{}</th>", h));
            }
            t.push_str("</tr></thead><tbody>");
            if rows.is_empty() {
                t.push_str(&format!(
                    "<tr><td colspan='{}'><em>{}</em></td></tr>",
                    headers.len(),
                    empty
                ));
            }
            for r in rows {
                t.push_str("<tr>");
                for c in r {
                    t.push_str(&format!("<td>{}</td>", html_escape(&c)));
                }
                t.push_str("</tr>");
            }
            t.push_str("</tbody></table></div>");
            t
        };
        let section = |title: &str, body: &str| {
            format!(
                "<div class=\"section\"><div class=\"section-title\">{}</div>{}</div>",
                title, body
            )
        };

        let mut checks_html = String::new();
        for c in &result.checks {
            let class_name = match c.severity {
                Severity::Pass => "badge-pass",
                Severity::Notice => "badge-notice",
                Severity::Warning => "badge-warning",
                Severity::Critical => "badge-critical",
                Severity::Info => "badge-info",
            };
            let rec = c
                .recommendation
                .as_ref()
                .map(|r| {
                    format!(
                        "<div class='rec'><strong>Recommendation:</strong> {}</div>",
                        html_escape(r)
                    )
                })
                .unwrap_or_default();
            checks_html.push_str(&format!(
                r#"<div class="check-card {cls}"><div class="check-header"><span class="badge {cls}">{badge}</span><span class="category">[{cat}]</span><strong>{title}</strong></div><div class="check-msg">{msg}</div>{rec}</div>"#,
                cls = class_name,
                badge = c.severity.badge(),
                cat = html_escape(&c.category),
                title = html_escape(&c.title),
                msg = html_escape(&c.message),
                rec = rec
            ));
        }

        let mut anomalies_html = String::new();
        for (a, seen) in grouped_anomalies(result) {
            let seen = if seen.is_empty() {
                String::new()
            } else {
                format!("<p class='category'>Seen on: {}</p>", html_escape(&seen))
            };
            anomalies_html.push_str(&format!(
                r#"<div class="anomaly-card"><div class="anomaly-title"><span class="rfc-tag">{rfc}</span> <strong>{title}</strong></div><p>{desc}</p><div class="raw-box"><code>{raw}</code></div>{seen}</div>"#,
                rfc = html_escape(&a.rfc_reference),
                title = html_escape(&a.title),
                desc = html_escape(&a.description),
                raw = html_escape(&a.raw_response),
                seen = seen
            ));
        }
        let anomalies_section = if anomalies_html.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="section" style="border-color: #ef4444;"><div class="section-title" style="color: #f87171;">Detected Protocol Misbehaviors & RFC Violations</div>{}</div>"#,
                anomalies_html
            )
        };

        let servers_section = if result.servers.is_empty() {
            String::new()
        } else {
            section(
                "Servers Tested &amp; TLS",
                &table(
                    &SERVER_HEADERS,
                    server_rows(result).into_iter().map(|r| r.to_vec()).collect(),
                    "",
                ),
            )
        };

        let (mx_table, records_table) = match &result.dns {
            Some(dns) => (
                table(
                    &["Pref", "Hostname", "Addresses"],
                    dns.mx_hosts
                        .iter()
                        .map(|mx| vec![mx.priority.to_string(), mx.hostname.clone(), addresses(mx).join(", ")])
                        .collect(),
                    "None",
                ),
                table(
                    &["Record", "Value"],
                    record_lines(dns)
                        .into_iter()
                        .map(|(k, v)| vec![k.to_string(), v])
                        .collect(),
                    "None",
                ),
            ),
            None => (String::new(), String::new()),
        };

        let port_rows = result
            .port_probes
            .iter()
            .map(|p| {
                vec![
                    p.port.to_string(),
                    p.service.clone(),
                    if p.reachable {
                        format!("OPEN ({:.0} ms)", p.latency_ms)
                    } else {
                        "CLOSED".into()
                    },
                    p.error.clone().unwrap_or_else(|| "Connected".into()),
                ]
            })
            .collect();

        let all = sessions(result);
        let mut transcript_html = String::new();
        for (label, smtp) in &all {
            if all.len() > 1 {
                transcript_html.push_str(&format!("<details><summary>{}</summary>", html_escape(label)));
            }
            for t in &smtp.transcript {
                let cls = match t.direction.as_str() {
                    "->" => "tx-sent",
                    "<-" => "tx-recv",
                    _ => "tx-info",
                };
                transcript_html.push_str(&format!(
                    "<div class='tx-line {}'><span class='tx-time'>{}</span> <span class='tx-dir'>{}</span> {}</div>",
                    cls,
                    html_escape(&t.timestamp),
                    html_escape(&t.direction),
                    html_escape(&t.text)
                ));
            }
            if all.len() > 1 {
                transcript_html.push_str("</details>");
            }
        }
        if transcript_html.is_empty() {
            transcript_html = "<em>No transcript</em>".to_string();
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MX Detective Report - {domain}</title>
<style>
    :root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --pass: #10b981; --warn: #f59e0b; --crit: #ef4444; --code-bg: #0b1120; }}
    @media (prefers-color-scheme: light) {{
        :root {{ --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0; --text: #0f172a; --text-muted: #64748b; --code-bg: #f1f5f9; }}
    }}
    [data-theme="light"] {{ --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0; --text: #0f172a; --text-muted: #64748b; --code-bg: #f1f5f9; }}
    [data-theme="dark"] {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --code-bg: #0b1120; }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem 1rem; line-height: 1.5; transition: background 0.2s, color 0.2s; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; gap: 1rem; background: var(--surface); padding: 1.5rem 2rem; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 1.5rem; }}
    .score-circle {{ width: 90px; height: 90px; border-radius: 50%; background: {grade_color}22; border: 4px solid {grade_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; color: {grade_color}; }}
    .score-num {{ font-size: 1.75rem; font-weight: 800; line-height: 1; }}
    .score-grade {{ font-size: 0.85rem; font-weight: 700; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.75rem; font-weight: 700; }}
    .badge-pass {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); }}
    .badge-notice {{ background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-info {{ background: rgba(148, 163, 184, 0.2); color: var(--text-muted); border: 1px solid rgba(148, 163, 184, 0.4); }}
    .section {{ background: var(--surface); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 1.5rem; }}
    .section-title {{ font-size: 1.2rem; font-weight: 700; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    .check-card {{ background: var(--code-bg); padding: 1rem; border-radius: 8px; border-left: 4px solid #64748b; margin-bottom: 0.75rem; }}
    .check-card.badge-pass {{ border-left-color: var(--pass); }}
    .check-card.badge-warning {{ border-left-color: var(--warn); }}
    .check-card.badge-critical {{ border-left-color: var(--crit); }}
    .check-header {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }}
    .check-msg {{ overflow-wrap: anywhere; }}
    .category {{ color: var(--text-muted); font-size: 0.8rem; font-weight: 600; }}
    .rec {{ background: rgba(245, 158, 11, 0.15); border-left: 3px solid var(--warn); padding: 0.4rem 0.75rem; border-radius: 4px; font-size: 0.85rem; margin-top: 0.4rem; }}
    .anomaly-card {{ background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); padding: 1rem; border-radius: 8px; margin-bottom: 0.75rem; }}
    .rfc-tag {{ background: #ef4444; color: white; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
    .raw-box {{ background: var(--code-bg); padding: 0.4rem 0.75rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; margin-top: 0.4rem; overflow-wrap: anywhere; }}
    .scroll-x {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    th, td {{ padding: 0.65rem 0.85rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
    td {{ overflow-wrap: anywhere; }}
    th {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }}
    code {{ background: var(--code-bg); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
    .transcript {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.85rem; max-height: 500px; overflow-y: auto; }}
    .transcript summary {{ cursor: pointer; font-weight: 600; margin: 0.4rem 0; color: var(--text); }}
    .tx-line {{ padding: 0.15rem 0; word-break: break-all; }}
    .tx-sent {{ color: #3b82f6; font-weight: 600; }}
    .tx-recv {{ color: #10b981; }}
    .tx-info {{ color: var(--text-muted); font-style: italic; }}
    .tx-time {{ color: var(--text-muted); margin-right: 0.5rem; }}
    .tx-dir {{ font-weight: bold; margin-right: 0.25rem; }}
    .theme-btn {{ background: var(--border); color: var(--text); border: none; padding: 0.35rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 600; }}
    @media (max-width: 640px) {{ body {{ padding: 1rem; }} .header {{ flex-direction: column; align-items: flex-start; padding: 1rem; }} }}

    @media print {{
        body {{ background: white; color: black; padding: 0; }}
        .header, .section, .check-card, .anomaly-card {{ background: white; border: 1px solid #ccc; color: black; }}
        .transcript {{ background: white; color: black; max-height: none; }}
        code {{ background: #eee; color: black; }}
        .theme-btn {{ display: none; }}
    }}
</style>
<script>
    function toggleTheme() {{
        const cur = document.documentElement.dataset.theme;
        document.documentElement.dataset.theme = cur === 'light' ? 'dark' : 'light';
    }}
</script>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>MX Detective Diagnostic Report</h1>
            <p>Domain: <strong>{domain}</strong> | Primary Host: <strong>{host}</strong> | Servers tested: <strong>{server_count}</strong></p>
            <p><small>{timestamp}</small></p>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <button class="theme-btn" onclick="toggleTheme()">🌓 Light / Dark</button>
            <div class="score-circle">
                <span class="score-num">{score}</span>
                <span class="score-grade">{grade}</span>
            </div>
        </div>
    </div>

    {anomalies_section}
    {checks_section}
    {servers_section}
    {mx_section}
    {records_section}
    {ports_section}
    {transcript_section}
</div>
</body>
</html>"#,
            domain = html_escape(&result.domain),
            host = html_escape(result.target_host.as_deref().unwrap_or("N/A")),
            server_count = result.servers.len().max(usize::from(result.smtp.is_some())),
            timestamp = html_escape(&result.timestamp),
            score = result.score,
            grade = html_escape(&result.grade),
            grade_color = grade_color,
            anomalies_section = anomalies_section,
            checks_section = section(&format!("Diagnostic Findings ({})", result.checks.len()), &checks_html),
            servers_section = servers_section,
            mx_section = section("Mail Exchangers (MX Records)", &mx_table),
            records_section = section("Mail Authentication &amp; Transport Security", &records_table),
            ports_section = section(
                "Port Reachability",
                &table(&["Port", "Service", "Status", "Details"], port_rows, "Not probed")
            ),
            transcript_section = section(
                "SMTP Packet Transcript",
                &format!("<div class=\"transcript\">{}</div>", transcript_html)
            ),
        )
    }
}

/// Plain ASCII for output that scripts capture, whose console code page may not be UTF-8.
fn ascii_fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            c if c.is_ascii() => out.push(c),
            '\u{a7}' => out.push_str("sec. "),
            '\u{2013}' | '\u{2014}' | '\u{2011}' => out.push('-'),
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '\u{201c}' | '\u{201d}' => out.push('"'),
            '\u{2192}' => out.push_str("->"),
            '\u{2026}' => out.push_str("..."),
            _ => out.push('?'),
        }
    }
    out
}

/// Rewrites every non-ASCII character as a JSON \u escape. Such characters only occur
/// inside string values, so the document stays valid and means the same.
fn escape_non_ascii(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0u16; 2]) {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}
