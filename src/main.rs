mod dns;
mod gui;
mod models;
mod ports;
mod reporter;
mod smtp;

use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

use crate::dns::DnsResolver;
use crate::models::DiagnosticResult;
use crate::ports::PortProber;
use crate::reporter::DiagnosticReporter;
use crate::smtp::SmtpProber;

#[derive(Parser, Debug)]
#[command(
    name = "mx-detective",
    author = "Motti Schleider <motti.schleider@gmail.com>",
    version = "0.1.0",
    about = "MX Detective - Public MX Server, SMTP Handshake & Protocol Behavior Diagnostic Tool",
    after_help = "Examples:
  mx-detective google.com
  mx-detective example.com --host mail.example.com
  mx-detective example.com --recipient admin@example.com --export report.html
  mx-detective example.com --json
  mx-detective --gui
"
)]
struct CliArgs {
    /// Domain to diagnose (e.g. example.com). Required unless --gui is used.
    #[arg(value_name = "DOMAIN")]
    domain: Option<String>,

    /// Override primary MX server host to test a specific mail exchanger
    #[arg(short = 's', long = "host")]
    host_override: Option<String>,

    /// Target SMTP port to test
    #[arg(short = 'p', long = "port", default_value_t = 25)]
    port: u16,

    /// Socket timeout in seconds
    #[arg(short = 't', long = "timeout", default_value_t = 5.0)]
    timeout: f64,

    /// Test whether a specific recipient mailbox is accepted without sending email
    #[arg(long = "recipient")]
    recipient: Option<String>,

    /// Skip Open Relay vulnerability test
    #[arg(long = "no-relay")]
    no_relay: bool,

    /// Output full report as JSON to stdout
    #[arg(long = "json")]
    json: bool,

    /// Export diagnostic report to file (.html, .json, .md, .csv, or .txt)
    #[arg(short = 'o', long = "export")]
    export_path: Option<String>,

    /// Specific export format (html, json, markdown, csv, txt). Defaults to auto-detect from extension.
    #[arg(long = "format")]
    format: Option<String>,

    /// Launch the native graphical desktop interface
    #[arg(long = "gui")]
    gui: bool,
}

fn print_banner() {
    println!("\x1b[1;96m╔════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;96m║                         🕵  MX DETECTIVE (v0.1.0)                          ║\x1b[0m");
    println!("\x1b[1;96m║        Public MX Server, SMTP Handshake & Protocol Behavior Diagnostics    ║\x1b[0m");
    println!("\x1b[1;96m╚════════════════════════════════════════════════════════════════════════════╝\x1b[0m");
}

fn run_cli(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let domain = match args.domain {
        Some(d) => d,
        None => {
            print_banner();
            eprintln!("\n\x1b[1;91mError: Domain name is required in CLI mode.\x1b[0m");
            eprintln!("Usage: mx-detective <domain> or mx-detective --gui\n");
            std::process::exit(1);
        }
    };

    if !args.json {
        print_banner();
        println!("\n \x1b[1mInitiating diagnostic investigation for:\x1b[0m \x1b[1;97m{}\x1b[0m\n", domain);
    }

    let timeout = Duration::from_secs_f64(args.timeout);

    // 1. DNS Resolution
    if !args.json {
        println!(" \x1b[1;94m[DNS]\x1b[0m      Querying DNS MX, A, PTR, SPF, and DMARC records...");
    }
    let dns_resolver = DnsResolver::new(timeout);
    let (dns_report, dns_checks) = dns_resolver.resolve_all(&domain, None);

    let mut result = DiagnosticResult::new(domain.clone(), args.host_override.clone());
    result.dns = Some(dns_report.clone());
    for c in dns_checks {
        result.checks.push(c);
    }

    // Determine target host
    let target_host = if let Some(h) = args.host_override {
        Some(h)
    } else if let Some(first_mx) = dns_report.mx_hosts.first() {
        Some(first_mx.hostname.clone())
    } else if dns_report.fallback_to_a {
        Some(domain.clone())
    } else {
        None
    };

    result.target_host = target_host.clone();

    let target_ip = if let Some(th) = &target_host {
        dns_report
            .mx_hosts
            .iter()
            .find(|h| &h.hostname == th)
            .and_then(|h| h.ipv4_addresses.first().cloned())
    } else {
        None
    };
    result.target_ip = target_ip;

    if let Some(host) = target_host {
        // 2. Port Probing
        if !args.json {
            println!(" \x1b[1;94m[PORTS]\x1b[0m    Probing standard mail ports (25, 587, 465, 2525) on {}...", host);
        }
        let port_prober = PortProber::new(timeout);
        let (probes, port_checks, p25_blocked) = port_prober.probe_mail_ports(&host);
        result.port_probes = probes;
        result.port_25_blocked_suspected = p25_blocked;
        for c in port_checks {
            result.checks.push(c);
        }

        // 3. SMTP Handshake & Behavior Audit
        if !args.json {
            println!(" \x1b[1;94m[SMTP]\x1b[0m     Connecting to {}:{} to inspect banner, tarpit, and response behavior...", host, args.port);
        }
        let smtp_prober = SmtpProber::new(timeout);
        let (smtp_report, tls_report, smtp_checks) = smtp_prober.probe_server(
            &host,
            args.port,
            !args.no_relay,
            args.recipient.as_deref(),
            true,
        );
        result.smtp = Some(smtp_report);
        result.tls = tls_report;
        for c in smtp_checks {
            result.checks.push(c);
        }
    } else if !args.json {
        eprintln!(" \x1b[1;91m[ERROR]\x1b[0m    No MX host could be discovered for testing.");
    }

    result.calculate_score();

    // Output JSON or Text
    if args.json {
        println!("{}", DiagnosticReporter::to_json(&result));
    } else {
        println!("{}", DiagnosticReporter::to_text(&result));
    }

    // Export to file if requested
    if let Some(export_path) = args.export_path {
        let fmt_choice = args
            .format
            .as_deref()
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| {
                if export_path.ends_with(".html") {
                    "html".to_string()
                } else if export_path.ends_with(".json") {
                    "json".to_string()
                } else if export_path.ends_with(".md") || export_path.ends_with(".markdown") {
                    "markdown".to_string()
                } else if export_path.ends_with(".csv") {
                    "csv".to_string()
                } else {
                    "txt".to_string()
                }
            });

        let content = match fmt_choice.as_str() {
            "html" => DiagnosticReporter::to_html(&result),
            "json" => DiagnosticReporter::to_json(&result),
            "md" | "markdown" => DiagnosticReporter::to_markdown(&result),
            "csv" => DiagnosticReporter::to_csv(&result),
            _ => DiagnosticReporter::to_text(&result),
        };

        let mut f = File::create(&export_path)?;
        f.write_all(content.as_bytes())?;
        if !args.json {
            println!(" \x1b[1;92m✓ [{}] Report saved successfully to:\x1b[0m {}\n", fmt_choice.to_uppercase(), export_path);
        }
    }

    Ok(())
}

fn main() {
    let args = CliArgs::parse();

    if args.gui {
        if let Err(e) = gui::launch_gui(args.domain) {
            eprintln!("\x1b[1;91mFailed to start GUI:\x1b[0m {}", e);
            std::process::exit(1);
        }
    } else {
        if let Err(e) = run_cli(args) {
            eprintln!("\x1b[1;91mExecution error:\x1b[0m {}", e);
            std::process::exit(1);
        }
    }
}
