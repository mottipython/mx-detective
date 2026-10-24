use crate::models::{DiagnosticResult, Severity};

pub struct DiagnosticReporter;

impl DiagnosticReporter {
    pub fn to_json(result: &DiagnosticResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(result: &DiagnosticResult) -> String {
        let mut out = String::new();
        let border = "═".repeat(78);
        let divider = "─".repeat(78);

        out.push_str(&border);
        out.push('\n');
        out.push_str(&format!(" MX DETECTIVE REPORT: {}\n", result.domain));
        out.push_str(&format!(" Target Host: {} ({})\n", result.target_host.as_deref().unwrap_or("N/A"), result.target_ip.as_deref().unwrap_or("No IP")));
        out.push_str(&format!(" Timestamp:   {}\n", result.timestamp));
        out.push_str(&format!(" Overall Score: {}/100 (Grade: {})\n", result.score, result.grade));
        out.push_str(&border);
        out.push_str("\n\n");

        if result.port_25_blocked_suspected {
            out.push_str(">>> NOTICE: Outbound Port 25 appears blocked by local ISP or Firewall <<<\n\n");
        }

        // Summary counts
        let crits = result.checks.iter().filter(|c| c.severity == Severity::Critical).count();
        let warns = result.checks.iter().filter(|c| c.severity == Severity::Warning).count();
        let notices = result.checks.iter().filter(|c| c.severity == Severity::Notice).count();
        let passes = result.checks.iter().filter(|c| c.severity == Severity::Pass).count();

        out.push_str(&format!("FINDINGS: {} Critical | {} Warnings | {} Notices | {} Passed\n", crits, warns, notices, passes));
        out.push_str(&divider);
        out.push('\n');

        for c in &result.checks {
            out.push_str(&format!(" [{}] [{}] {}\n", c.severity.badge(), c.category, c.title));
            out.push_str(&format!("    {}\n", c.message));
            if let Some(rec) = &c.recommendation {
                out.push_str(&format!("    -> Action: {}\n", rec));
            }
            out.push('\n');
        }

        // SMTP Misbehavior Anomalies
        if let Some(smtp) = &result.smtp {
            if !smtp.anomalies.is_empty() {
                out.push_str(&divider);
                out.push('\n');
                out.push_str(&format!("DETECTED SMTP PROTOCOL MISBEHAVIORS ({}):\n", smtp.anomalies.len()));
                out.push_str(&divider);
                out.push('\n');
                for a in &smtp.anomalies {
                    out.push_str(&format!(" * [{}] {}: {}\n", a.rfc_reference, a.title, a.description));
                    out.push_str(&format!("   Raw Response: {}\n", a.raw_response));
                }
                out.push('\n');
            }
        }

        // DNS Records
        if let Some(dns) = &result.dns {
            out.push_str(&divider);
            out.push('\n');
            out.push_str("MX RECORDS & REVERSE DNS:\n");
            out.push_str(&divider);
            out.push('\n');
            for mx in &dns.mx_hosts {
                let ips = mx.ipv4_addresses.join(", ");
                out.push_str(&format!(" Priority {:<3} {} -> {}\n", mx.priority, mx.hostname, if ips.is_empty() { "No IP" } else { &ips }));
            }
            out.push_str(&format!(" SPF:   {}\n", dns.spf_record.as_deref().unwrap_or("None")));
            out.push_str(&format!(" DMARC: {}\n", dns.dmarc_record.as_deref().unwrap_or("None")));
            out.push('\n');
        }

        // Port Probes
        out.push_str(&divider);
        out.push('\n');
        out.push_str("PORT PROBES:\n");
        out.push_str(&divider);
        out.push('\n');
        for p in &result.port_probes {
            let st = if p.reachable {
                format!("OPEN ({:.0} ms)", p.latency_ms)
            } else {
                format!("CLOSED / TIMEOUT ({})", p.error.as_deref().unwrap_or("Unreachable"))
            };
            out.push_str(&format!(" Port {:<5} {:<30} : {}\n", p.port, p.service, st));
        }
        out.push('\n');

        out.push_str(&border);
        out.push('\n');
        out
    }

    pub fn to_markdown(result: &DiagnosticResult) -> String {
        let mut md = String::new();
        md.push_str(&format!("# 🕵️ MX Detective Diagnostic Report: {}\n\n", result.domain));
        md.push_str(&format!("- **Target Host:** `{}` (`{}`)\n", result.target_host.as_deref().unwrap_or("N/A"), result.target_ip.as_deref().unwrap_or("No IP")));
        md.push_str(&format!("- **Timestamp:** `{}`\n", result.timestamp));
        md.push_str(&format!("- **Overall Health Score:** **{}/100 (Grade: {})**\n\n", result.score, result.grade));

        if result.port_25_blocked_suspected {
            md.push_str("> ⚠️ **Notice: Outbound port 25 appears blocked by your local network / ISP / Cloud Provider.**\n");
            md.push_str("> Residential broadband and cloud compute instances (AWS, Azure, GCP) block outbound port 25 by default. Inbound email may still function normally.\n\n");
        }

        // Anomalies Section
        if let Some(smtp) = &result.smtp {
            if !smtp.anomalies.is_empty() {
                md.push_str("## 🚨 Detected Protocol Misbehaviors & RFC Violations\n\n");
                md.push_str("| RFC Reference | Severity | Issue | Description | Raw Response |\n");
                md.push_str("|---|---|---|---|---|\n");
                for a in &smtp.anomalies {
                    md.push_str(&format!(
                        "| `{}` | `{}` | **{}** | {} | `{}` |\n",
                        a.rfc_reference,
                        a.severity.badge(),
                        a.title.replace('|', "\\|"),
                        a.description.replace('|', "\\|"),
                        a.raw_response.replace('|', "\\|")
                    ));
                }
                md.push_str("\n");
            }
        }

        // Audit Findings
        md.push_str("## 📋 Audit Findings & Recommendations\n\n");
        md.push_str("| Status | Category | Title | Details | Action Required |\n");
        md.push_str("|---|---|---|---|---|\n");
        for c in &result.checks {
            let rec_str = c.recommendation.as_deref().unwrap_or("-");
            md.push_str(&format!(
                "| `{}` | **{}** | {} | {} | {} |\n",
                c.severity.badge(),
                c.category,
                c.title.replace('|', "\\|"),
                c.message.replace('|', "\\|"),
                rec_str.replace('|', "\\|")
            ));
        }
        md.push_str("\n");

        // MX Records
        if let Some(dns) = &result.dns {
            md.push_str("## 🌐 Mail Exchanger (MX) Records\n\n");
            md.push_str("| Priority | Hostname | Resolved IP | Reverse DNS (PTR) |\n");
            md.push_str("|---|---|---|---|\n");
            for mx in &dns.mx_hosts {
                let ips = if mx.ipv4_addresses.is_empty() { "No IP".to_string() } else { mx.ipv4_addresses.join(", ") };
                let ptrs: Vec<String> = mx.ptr_records.values().flatten().cloned().collect();
                let ptr_str = if ptrs.is_empty() { "No PTR".to_string() } else { ptrs.join(", ") };
                md.push_str(&format!("| {} | `{}` | `{}` | `{}` |\n", mx.priority, mx.hostname, ips, ptr_str));
            }
            md.push_str("\n");

            md.push_str("### 🔒 Email Authentication Records\n\n");
            md.push_str(&format!("- **SPF:** `{}`\n", dns.spf_record.as_deref().unwrap_or("None published")));
            md.push_str(&format!("- **DMARC:** `{}`\n", dns.dmarc_record.as_deref().unwrap_or("None published")));
            md.push_str(&format!("- **DKIM:** `{}`\n\n", dns.dkim_record.as_deref().unwrap_or("None discovered")));
        }

        // Port Probes
        md.push_str("## 🔌 Port Reachability\n\n");
        md.push_str("| Port | Service | Status | Latency | Details |\n");
        md.push_str("|---|---|---|---|---|\n");
        for p in &result.port_probes {
            let st = if p.reachable { "✅ OPEN" } else { "❌ CLOSED" };
            let lat = if p.reachable { format!("{:.0} ms", p.latency_ms) } else { "-".to_string() };
            md.push_str(&format!("| {} | {} | {} | {} | {} |\n", p.port, p.service, st, lat, p.error.as_deref().unwrap_or("OK")));
        }
        md.push_str("\n");

        // Raw Transcript
        if let Some(smtp) = &result.smtp {
            md.push_str("## 📜 Raw SMTP Transcript\n\n");
            md.push_str("```smtp\n");
            for t in &smtp.transcript {
                md.push_str(&format!("{} {} {}\n", t.timestamp, t.direction, t.text));
            }
            md.push_str("```\n");
        }

        md
    }

    pub fn to_csv(result: &DiagnosticResult) -> String {
        let mut csv = String::new();
        csv.push_str("Type,Category,Severity,Title,Message,Recommendation,Reference\n");

        for c in &result.checks {
            csv.push_str(&format!(
                "\"Check\",\"{}\",\"{:?}\",\"{}\",\"{}\",\"{}\",\"\"\n",
                escape_csv(&c.category),
                c.severity,
                escape_csv(&c.title),
                escape_csv(&c.message),
                escape_csv(c.recommendation.as_deref().unwrap_or(""))
            ));
        }

        if let Some(smtp) = &result.smtp {
            for a in &smtp.anomalies {
                csv.push_str(&format!(
                    "\"Anomaly\",\"SMTP\",\"{:?}\",\"{}\",\"{}\",\"\",\"{}\"\n",
                    a.severity,
                    escape_csv(&a.title),
                    escape_csv(&a.description),
                    escape_csv(&a.rfc_reference)
                ));
            }
        }

        for p in &result.port_probes {
            csv.push_str(&format!(
                "\"PortProbe\",\"NETWORK\",\"{}\",\"Port {}\",\"Latency {:.0} ms\",\"{}\",\"\"\n",
                if p.reachable { "Pass" } else { "Critical" },
                p.port,
                p.latency_ms,
                escape_csv(p.error.as_deref().unwrap_or("Reachable"))
            ));
        }

        if let Some(dns) = &result.dns {
            for mx in &dns.mx_hosts {
                csv.push_str(&format!(
                    "\"MXRecord\",\"DNS\",\"Info\",\"Priority {}\",\"Hostname: {}\",\"IPs: {}\",\"\"\n",
                    mx.priority,
                    escape_csv(&mx.hostname),
                    escape_csv(&mx.ipv4_addresses.join("; "))
                ));
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

        let mut checks_html = String::new();
        for c in &result.checks {
            let class_name = match c.severity {
                Severity::Pass => "badge-pass",
                Severity::Notice => "badge-notice",
                Severity::Warning => "badge-warning",
                Severity::Critical => "badge-critical",
                Severity::Info => "badge-info",
            };

            let rec_html = if let Some(rec) = &c.recommendation {
                format!("<div class='rec'><strong>Recommendation:</strong> {}</div>", html_escape(rec))
            } else {
                String::new()
            };

            checks_html.push_str(&format!(
                r#"<div class="check-card {class_name}">
                    <div class="check-header">
                        <span class="badge {class_name}">{badge}</span>
                        <span class="category">[{cat}]</span>
                        <strong>{title}</strong>
                    </div>
                    <div class="check-msg">{msg}</div>
                    {rec}
                </div>"#,
                class_name = class_name,
                badge = c.severity.badge(),
                cat = html_escape(&c.category),
                title = html_escape(&c.title),
                msg = html_escape(&c.message),
                rec = rec_html
            ));
        }

        let mut anomalies_html = String::new();
        if let Some(smtp) = &result.smtp {
            for a in &smtp.anomalies {
                anomalies_html.push_str(&format!(
                    r#"<div class="anomaly-card">
                        <div class="anomaly-title"><span class="rfc-tag">{rfc}</span> <strong>{title}</strong></div>
                        <p>{desc}</p>
                        <div class="raw-box"><code>{raw}</code></div>
                    </div>"#,
                    rfc = html_escape(&a.rfc_reference),
                    title = html_escape(&a.title),
                    desc = html_escape(&a.description),
                    raw = html_escape(&a.raw_response)
                ));
            }
        }

        let mut mx_rows = String::new();
        if let Some(dns) = &result.dns {
            for mx in &dns.mx_hosts {
                let ips = mx.ipv4_addresses.join("<br>");
                mx_rows.push_str(&format!(
                    "<tr><td><strong>{}</strong></td><td>{}</td><td><code>{}</code></td></tr>",
                    mx.priority,
                    html_escape(&mx.hostname),
                    if ips.is_empty() { "No IP".to_string() } else { ips }
                ));
            }
        }

        let mut port_rows = String::new();
        for p in &result.port_probes {
            let badge = if p.reachable {
                format!("<span class='badge badge-pass'>OPEN ({:.0} ms)</span>", p.latency_ms)
            } else {
                "<span class='badge badge-critical'>CLOSED</span>".to_string()
            };
            port_rows.push_str(&format!(
                "<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td><small>{}</small></td></tr>",
                p.port,
                html_escape(&p.service),
                badge,
                html_escape(p.error.as_deref().unwrap_or("Connected"))
            ));
        }

        let mut transcript_html = String::new();
        if let Some(smtp) = &result.smtp {
            for t in &smtp.transcript {
                let cls = match t.direction.as_str() {
                    "->" => "tx-sent",
                    "<-" => "tx-recv",
                    _ => "tx-info",
                };
                transcript_html.push_str(&format!(
                    "<div class='tx-line {cls}'><span class='tx-time'>{time}</span> <span class='tx-dir'>{dir}</span> {text}</div>",
                    cls = cls,
                    time = html_escape(&t.timestamp),
                    dir = html_escape(&t.direction),
                    text = html_escape(&t.text)
                ));
            }
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
    .container {{ max-width: 960px; margin: 0 auto; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; background: var(--surface); padding: 1.5rem 2rem; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 1.5rem; }}
    .score-circle {{ width: 90px; height: 90px; border-radius: 50%; background: {grade_color}22; border: 4px solid {grade_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; color: {grade_color}; }}
    .score-num {{ font-size: 1.75rem; font-weight: 800; line-height: 1; }}
    .score-grade {{ font-size: 0.85rem; font-weight: 700; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.75rem; font-weight: 700; }}
    .badge-pass {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); }}
    .badge-notice {{ background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .section {{ background: var(--surface); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 1.5rem; }}
    .section-title {{ font-size: 1.2rem; font-weight: 700; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    .check-card {{ background: var(--code-bg); padding: 1rem; border-radius: 8px; border-left: 4px solid #64748b; margin-bottom: 0.75rem; }}
    .check-card.badge-pass {{ border-left-color: var(--pass); }}
    .check-card.badge-warning {{ border-left-color: var(--warn); }}
    .check-card.badge-critical {{ border-left-color: var(--crit); }}
    .check-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }}
    .category {{ color: var(--text-muted); font-size: 0.8rem; font-weight: 600; }}
    .rec {{ background: rgba(245, 158, 11, 0.15); border-left: 3px solid var(--warn); padding: 0.4rem 0.75rem; border-radius: 4px; font-size: 0.85rem; margin-top: 0.4rem; }}
    .anomaly-card {{ background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); padding: 1rem; border-radius: 8px; margin-bottom: 0.75rem; }}
    .rfc-tag {{ background: #ef4444; color: white; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
    .raw-box {{ background: var(--code-bg); padding: 0.4rem 0.75rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; margin-top: 0.4rem; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    th, td {{ padding: 0.65rem 0.85rem; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }}
    code {{ background: var(--code-bg); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
    .transcript {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.85rem; max-height: 400px; overflow-y: auto; }}
    .tx-line {{ padding: 0.15rem 0; word-break: break-all; }}
    .tx-sent {{ color: #3b82f6; font-weight: 600; }}
    .tx-recv {{ color: #10b981; }}
    .tx-info {{ color: var(--text-muted); font-style: italic; }}
    .tx-time {{ color: var(--text-muted); margin-right: 0.5rem; }}
    .tx-dir {{ font-weight: bold; margin-right: 0.25rem; }}
    .theme-btn {{ background: var(--border); color: var(--text); border: none; padding: 0.35rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 600; }}

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
        const next = cur === 'light' ? 'dark' : 'light';
        document.documentElement.dataset.theme = next;
    }}
</script>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>MX Detective Diagnostic Report</h1>
            <p>Domain: <strong>{domain}</strong> | Tested Host: <strong>{host}</strong></p>
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

    <div class="section">
        <div class="section-title">Diagnostic Findings ({checks_count})</div>
        {checks_html}
    </div>

    <div class="section">
        <div class="section-title">Mail Exchangers (MX Records)</div>
        <table>
            <thead><tr><th>Pref</th><th>Hostname</th><th>Resolved IP</th></tr></thead>
            <tbody>{mx_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Port Reachability</div>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>{port_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">SMTP Packet Transcript</div>
        <div class="transcript">{transcript_html}</div>
    </div>
</div>
</body>
</html>"#,
            domain = html_escape(&result.domain),
            host = html_escape(result.target_host.as_deref().unwrap_or("N/A")),
            timestamp = html_escape(&result.timestamp),
            score = result.score,
            grade = html_escape(&result.grade),
            grade_color = grade_color,
            anomalies_section = if !anomalies_html.is_empty() {
                format!(r#"<div class="section" style="border-color: #ef4444;"><div class="section-title" style="color: #f87171;">Detected Protocol Misbehaviors & RFC Violations</div>{}</div>"#, anomalies_html)
            } else {
                String::new()
            },
            checks_count = result.checks.len(),
            checks_html = checks_html,
            mx_rows = if !mx_rows.is_empty() { mx_rows } else { "<tr><td colspan='3'><em>None</em></td></tr>".to_string() },
            port_rows = port_rows,
            transcript_html = if !transcript_html.is_empty() { transcript_html } else { "<em>No transcript</em>".to_string() }
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"")
}
