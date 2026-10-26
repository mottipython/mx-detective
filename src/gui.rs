use eframe::egui;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use crate::diagnose::{self, DiagnosticOptions};
use crate::models::{DiagnosticResult, Severity};
use crate::reporter::DiagnosticReporter;

#[derive(PartialEq, Clone, Copy)]
pub enum ThemeMode {
    Dark,
    Light,
    System,
}

#[derive(PartialEq)]
enum AppTab {
    Overview,
    SmtpBehavior,
    Servers,
    DnsRecords,
    Ports,
    Transcript,
}

pub struct MxDetectiveApp {
    domain_input: String,
    host_override: String,
    port_input: String,
    recipient_input: String,
    dkim_selector_input: String,
    test_relay: bool,
    primary_only: bool,
    transcript_server: std::cell::Cell<usize>,
    active_tab: AppTab,
    theme_mode: ThemeMode,
    is_running: bool,
    status_text: String,
    result: Option<DiagnosticResult>,
    rx: Option<Receiver<DiagnosticMessage>>,
    export_message: Option<(bool, String)>,
    last_exported_path: Option<String>,
    tx_export: Sender<Result<String, String>>,
    rx_export: Receiver<Result<String, String>>,
}

enum DiagnosticMessage {
    Status(String),
    Complete(Box<DiagnosticResult>),
}

fn open_in_system(target: &str) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", target])
        .spawn();

    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(target).spawn();

    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(target).spawn();
}

impl MxDetectiveApp {
    pub fn new(initial_domain: Option<String>) -> Self {
        let (tx_export, rx_export) = channel();
        Self {
            domain_input: initial_domain.unwrap_or_else(|| "google.com".to_string()),
            host_override: String::new(),
            port_input: "25".to_string(),
            recipient_input: String::new(),
            dkim_selector_input: String::new(),
            test_relay: true,
            primary_only: false,
            transcript_server: std::cell::Cell::new(0),
            active_tab: AppTab::Overview,
            theme_mode: ThemeMode::Dark,
            is_running: false,
            status_text: "Ready to inspect MX servers.".to_string(),
            result: None,
            rx: None,
            export_message: None,
            last_exported_path: None,
            tx_export,
            rx_export,
        }
    }

    fn export_with_dialog(&self, res: &DiagnosticResult, ext: &'static str, filter_name: &'static str) {
        let domain = res.domain.clone();
        let default_name = format!("{}-report.{}", domain, ext);
        let content = match ext {
            "html" => DiagnosticReporter::to_html(res),
            "md" => DiagnosticReporter::to_markdown(res),
            "csv" => DiagnosticReporter::to_csv(res),
            "json" => DiagnosticReporter::to_json(res),
            "txt" => DiagnosticReporter::to_text(res),
            _ => return,
        };
        let tx = self.tx_export.clone();

        thread::spawn(move || {
            let dialog = rfd::FileDialog::new()
                .set_file_name(&default_name)
                .set_title(format!("Save {} Report", filter_name))
                .add_filter(filter_name, &[ext]);

            if let Some(path_buf) = dialog.save_file() {
                match std::fs::write(&path_buf, content) {
                    Ok(_) => {
                        let path_str = path_buf.to_string_lossy().to_string();
                        let _ = tx.send(Ok(path_str));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("Could not write file: {}", e)));
                    }
                }
            }
        });
    }

    fn quick_export_downloads(&self, res: &DiagnosticResult) {
        let downloads_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(|h| std::path::PathBuf::from(h).join("Downloads"))
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));

        let _ = std::fs::create_dir_all(&downloads_dir);
        let domain = &res.domain;

        let html_path = downloads_dir.join(format!("{}-report.html", domain));
        let md_path = downloads_dir.join(format!("{}-report.md", domain));
        let csv_path = downloads_dir.join(format!("{}-report.csv", domain));
        let json_path = downloads_dir.join(format!("{}-report.json", domain));
        let txt_path = downloads_dir.join(format!("{}-report.txt", domain));

        let _ = std::fs::write(&html_path, DiagnosticReporter::to_html(res));
        let _ = std::fs::write(&md_path, DiagnosticReporter::to_markdown(res));
        let _ = std::fs::write(&csv_path, DiagnosticReporter::to_csv(res));
        let _ = std::fs::write(&json_path, DiagnosticReporter::to_json(res));
        let _ = std::fs::write(&txt_path, DiagnosticReporter::to_text(res));

        let _ = self.tx_export.send(Ok(html_path.to_string_lossy().to_string()));
    }

    fn render_export_menu(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        if ui
            .button("🌐 HTML Report (.html)...")
            .on_hover_text("Open file dialog to save interactive HTML report")
            .clicked()
        {
            self.export_with_dialog(res, "html", "HTML");
            ui.close();
        }
        if ui
            .button("📝 Markdown Report (.md)...")
            .on_hover_text("Open file dialog to save Markdown report")
            .clicked()
        {
            self.export_with_dialog(res, "md", "Markdown");
            ui.close();
        }
        if ui
            .button("📊 CSV Spreadsheet (.csv)...")
            .on_hover_text("Open file dialog to save CSV diagnostic data")
            .clicked()
        {
            self.export_with_dialog(res, "csv", "CSV");
            ui.close();
        }
        if ui
            .button("📋 JSON Data (.json)...")
            .on_hover_text("Open file dialog to save structured JSON")
            .clicked()
        {
            self.export_with_dialog(res, "json", "JSON");
            ui.close();
        }
        if ui
            .button("📄 Plain Text (.txt)...")
            .on_hover_text("Open file dialog to save plain ASCII text report")
            .clicked()
        {
            self.export_with_dialog(res, "txt", "Plain Text");
            ui.close();
        }
        ui.separator();
        if ui
            .button("⚡ Quick Export All to ~/Downloads")
            .on_hover_text("Quickly saves HTML, MD, CSV, JSON, and TXT directly to ~/Downloads")
            .clicked()
        {
            self.quick_export_downloads(res);
            ui.close();
        }
    }

    fn run_diagnostic(&mut self) {
        if self.domain_input.trim().is_empty() {
            self.status_text = "Please enter a valid domain name.".to_string();
            return;
        }

        self.is_running = true;
        self.export_message = None;
        let domain = self.domain_input.trim().to_string();
        let host_override = if self.host_override.trim().is_empty() {
            None
        } else {
            Some(self.host_override.trim().to_string())
        };
        let port = self.port_input.trim().parse::<u16>().unwrap_or(25);
        let recipient = if self.recipient_input.trim().is_empty() {
            None
        } else {
            Some(self.recipient_input.trim().to_string())
        };
        let opts = DiagnosticOptions {
            domain,
            host_override,
            port,
            recipient,
            test_relay: self.test_relay,
            dkim_selector: Some(self.dkim_selector_input.trim().to_string()).filter(|s| !s.is_empty()),
            primary_only: self.primary_only,
            ..Default::default()
        };
        self.transcript_server.set(0);

        let (tx, rx): (Sender<DiagnosticMessage>, Receiver<DiagnosticMessage>) = channel();
        self.rx = Some(rx);

        thread::spawn(move || {
            let status_tx = tx.clone();
            let result = diagnose::run(&opts, &move |msg| {
                let _ = status_tx.send(DiagnosticMessage::Status(msg.to_string()));
            });
            let _ = tx.send(DiagnosticMessage::Complete(Box::new(result)));
        });
    }
}

impl MxDetectiveApp {
    /// Draws one frame.
    fn show(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
        let ctx = &ctx;
        match self.theme_mode {
            ThemeMode::Dark => ctx.set_visuals(egui::Visuals::dark()),
            ThemeMode::Light => ctx.set_visuals(egui::Visuals::light()),
            ThemeMode::System => {}
        }

        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    DiagnosticMessage::Status(s) => {
                        self.status_text = s;
                    }
                    DiagnosticMessage::Complete(res) => {
                        self.status_text = format!("Diagnostic complete. Score: {}/100 ({})", res.score, res.grade);
                        self.result = Some(*res);
                        self.is_running = false;
                    }
                }
            }
        }

        while let Ok(msg) = self.rx_export.try_recv() {
            match msg {
                Ok(path) => {
                    self.export_message = Some((false, format!("Successfully saved report: {}", path)));
                    self.last_exported_path = Some(path);
                }
                Err(err) => {
                    self.export_message = Some((true, format!("Export failed: {}", err)));
                }
            }
        }

        let is_dark = ctx.global_style().visuals.dark_mode;

        egui::Panel::top("top_panel").show_inside(root, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("🕵 MX Detective");
                let subtitle_color = if is_dark {
                    egui::Color32::from_rgb(148, 163, 184)
                } else {
                    egui::Color32::from_rgb(71, 85, 105)
                };
                ui.label(egui::RichText::new("Public MX Server & SMTP Behavior Diagnostic Tool").color(subtitle_color));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (icon, label) = match self.theme_mode {
                        ThemeMode::Dark => ("🌙", "Dark"),
                        ThemeMode::Light => ("☀", "Light"),
                        ThemeMode::System => ("🖥", "System"),
                    };
                    if ui
                        .button(format!("{} {}", icon, label))
                        .on_hover_text("Toggle Theme (Dark / Light / System)")
                        .clicked()
                    {
                        self.theme_mode = match self.theme_mode {
                            ThemeMode::Dark => ThemeMode::Light,
                            ThemeMode::Light => ThemeMode::System,
                            ThemeMode::System => ThemeMode::Dark,
                        };
                    }
                });
            });
            ui.add_space(8.0);

            ui.horizontal_wrapped(|ui| {
                ui.label("Domain:");
                let domain_box = ui.add(
                    egui::TextEdit::singleline(&mut self.domain_input)
                        .hint_text("e.g. google.com")
                        .desired_width(180.0),
                );
                if domain_box.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.run_diagnostic();
                }

                ui.label("Host Override:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.host_override)
                        .hint_text("Optional MX host")
                        .desired_width(160.0),
                );

                ui.label("Port:");
                ui.add(egui::TextEdit::singleline(&mut self.port_input).desired_width(45.0));

                ui.label("Recipient Probe:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.recipient_input)
                        .hint_text("user@domain.com")
                        .desired_width(150.0),
                );

                ui.label("DKIM Selector:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.dkim_selector_input)
                        .hint_text("optional, comma-separated")
                        .desired_width(80.0),
                );

                ui.checkbox(&mut self.test_relay, "Open Relay Test");
                ui.checkbox(&mut self.primary_only, "Primary MX only")
                    .on_hover_text("Test only the most preferred MX host instead of every address of every MX host");

                ui.add_space(10.0);
                if self.is_running {
                    ui.add(egui::Spinner::new());
                    ui.label(egui::RichText::new(&self.status_text).color(egui::Color32::from_rgb(96, 165, 250)));
                } else {
                    if ui
                        .button(
                            egui::RichText::new("🔍 Inspect MX")
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .clicked()
                    {
                        self.run_diagnostic();
                    }

                    let export_enabled = self.result.is_some();
                    ui.add_enabled_ui(export_enabled, |ui| {
                        ui.menu_button(egui::RichText::new("💾 Export Report ▾").strong(), |ui| {
                            if let Some(res) = &self.result {
                                self.render_export_menu(ui, res);
                            }
                        });
                    });
                }
            });

            if !self.is_running {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&self.status_text)
                            .small()
                            .color(egui::Color32::from_rgb(148, 163, 184)),
                    );
                });
            }

            if let Some((is_error, msg)) = &self.export_message {
                ui.add_space(2.0);
                let (bg_color, border_color, text_color) = if *is_error {
                    (
                        egui::Color32::from_rgb(254, 242, 242),
                        egui::Color32::from_rgb(239, 68, 68),
                        egui::Color32::from_rgb(185, 28, 28),
                    )
                } else if is_dark {
                    (
                        egui::Color32::from_rgb(6, 78, 59),
                        egui::Color32::from_rgb(16, 185, 129),
                        egui::Color32::from_rgb(167, 243, 208),
                    )
                } else {
                    (
                        egui::Color32::from_rgb(236, 253, 245),
                        egui::Color32::from_rgb(16, 185, 129),
                        egui::Color32::from_rgb(4, 120, 87),
                    )
                };

                egui::Frame::new()
                    .fill(bg_color)
                    .stroke(egui::Stroke::new(1.0_f32, border_color))
                    .corner_radius(4.0)
                    .inner_margin(egui::Margin::symmetric(8, 4))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let icon = if *is_error { "❌" } else { "✓" };
                            ui.label(
                                egui::RichText::new(format!("{} {}", icon, msg))
                                    .strong()
                                    .color(text_color),
                            );

                            if let Some(path) = &self.last_exported_path {
                                if ui
                                    .button("📂 Open Folder")
                                    .on_hover_text("Open containing folder in file manager")
                                    .clicked()
                                {
                                    if let Some(parent) = std::path::Path::new(path).parent() {
                                        open_in_system(&parent.to_string_lossy());
                                    }
                                }
                                if ui
                                    .button("📄 View File")
                                    .on_hover_text("Open file in default viewer")
                                    .clicked()
                                {
                                    open_in_system(path);
                                }
                            }
                        });
                    });
            }

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, AppTab::Overview, "📋 Overview & Findings");
                ui.selectable_value(
                    &mut self.active_tab,
                    AppTab::SmtpBehavior,
                    "⚡ SMTP Behavior & Anomalies",
                );
                ui.selectable_value(&mut self.active_tab, AppTab::Servers, "🔒 Servers & TLS");
                ui.selectable_value(&mut self.active_tab, AppTab::DnsRecords, "🌐 DNS & Reverse DNS");
                ui.selectable_value(&mut self.active_tab, AppTab::Ports, "🔌 Port Reachability");
                ui.selectable_value(&mut self.active_tab, AppTab::Transcript, "📜 Raw Transcript");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(res) = &self.result {
                        ui.menu_button("💾 Export...", |ui| {
                            self.render_export_menu(ui, res);
                        });
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show_inside(root, |ui| {
            if let Some(res) = &self.result {
                ui.horizontal(|ui| {
                    let score_color = match res.grade.as_str() {
                        "A+" | "A" => egui::Color32::from_rgb(16, 185, 129),
                        "B" => egui::Color32::from_rgb(37, 99, 235),
                        "C" => egui::Color32::from_rgb(217, 119, 6),
                        _ => egui::Color32::from_rgb(220, 38, 38),
                    };

                    ui.label(
                        egui::RichText::new(format!("Health Grade: {} ({}/100)", res.grade, res.score))
                            .heading()
                            .strong()
                            .color(score_color),
                    );

                    let crits = res.checks.iter().filter(|c| c.severity == Severity::Critical).count();
                    let warns = res.checks.iter().filter(|c| c.severity == Severity::Warning).count();
                    let notices = res.checks.iter().filter(|c| c.severity == Severity::Notice).count();
                    let passes = res.checks.iter().filter(|c| c.severity == Severity::Pass).count();

                    ui.label(format!("| {} Critical | {} Warnings | {} Notices | {} Passed", crits, warns, notices, passes));
                });

                if res.port_25_blocked_suspected {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("⚠ Notice: Outbound port 25 appears blocked by your local ISP or Cloud Firewall. Inbound mail for this domain may still be functioning.")
                            .color(egui::Color32::from_rgb(251, 191, 36)),
                    );
                }

                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    match self.active_tab {
                        AppTab::Overview => {
                            self.render_overview_tab(ui, res);
                        }
                        AppTab::SmtpBehavior => {
                            self.render_smtp_behavior_tab(ui, res);
                        }
                        AppTab::Servers => {
                            self.render_servers_tab(ui, res);
                        }
                        AppTab::DnsRecords => {
                            self.render_dns_tab(ui, res);
                        }
                        AppTab::Ports => {
                            self.render_ports_tab(ui, res);
                        }
                        AppTab::Transcript => {
                            self.render_transcript_tab(ui, res);
                        }
                    }
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.heading("Enter a domain above and click 'Inspect MX'");
                    ui.label(egui::RichText::new("Tests every MX server over IPv4 and IPv6: SMTP behavior, real TLS certificates, DANE, MTA-STS, SPF/DMARC/DKIM, blocklists and open relays.").color(egui::Color32::from_rgb(148, 163, 184)));
                });
            }
        });
    }
}

impl MxDetectiveApp {
    fn render_overview_tab(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        let is_dark = ui.visuals().dark_mode;
        let action_color = if is_dark {
            egui::Color32::from_rgb(254, 243, 199)
        } else {
            egui::Color32::from_rgb(146, 64, 14)
        };
        let cat_color = if is_dark {
            egui::Color32::from_rgb(148, 163, 184)
        } else {
            egui::Color32::from_rgb(100, 116, 139)
        };

        ui.heading("Audit Findings & Recommendations");
        ui.add_space(6.0);

        for c in &res.checks {
            let color = match c.severity {
                Severity::Pass => {
                    if is_dark {
                        egui::Color32::from_rgb(52, 211, 153)
                    } else {
                        egui::Color32::from_rgb(5, 150, 105)
                    }
                }
                Severity::Notice => {
                    if is_dark {
                        egui::Color32::from_rgb(96, 165, 250)
                    } else {
                        egui::Color32::from_rgb(29, 78, 216)
                    }
                }
                Severity::Warning => {
                    if is_dark {
                        egui::Color32::from_rgb(251, 191, 36)
                    } else {
                        egui::Color32::from_rgb(217, 119, 6)
                    }
                }
                Severity::Critical => {
                    if is_dark {
                        egui::Color32::from_rgb(248, 113, 113)
                    } else {
                        egui::Color32::from_rgb(220, 38, 38)
                    }
                }
                Severity::Info => cat_color,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(c.severity.badge()).strong().color(color));
                    ui.label(
                        egui::RichText::new(format!("[{}]", c.category))
                            .small()
                            .color(cat_color),
                    );
                    ui.label(egui::RichText::new(&c.title).strong());
                });
                ui.label(&c.message);
                if let Some(rec) = &c.recommendation {
                    ui.label(egui::RichText::new(format!("↳ Action: {}", rec)).color(action_color));
                }
            });
            ui.add_space(4.0);
        }
    }

    fn render_smtp_behavior_tab(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        if let Some(smtp) = &res.smtp {
            ui.heading("SMTP Server Behavior & RFC Compliance Analysis");
            ui.add_space(6.0);

            if !smtp.anomalies.is_empty() {
                ui.label(
                    egui::RichText::new(format!(
                        "⚠ {} Protocol Misbehaviors / RFC Violations Detected:",
                        smtp.anomalies.len()
                    ))
                    .heading()
                    .color(egui::Color32::from_rgb(239, 68, 68)),
                );
                ui.add_space(4.0);
                for a in &smtp.anomalies {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(&a.rfc_reference)
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            );
                            ui.label(
                                egui::RichText::new(&a.title)
                                    .strong()
                                    .color(egui::Color32::from_rgb(248, 113, 113)),
                            );
                        });
                        ui.label(&a.description);
                        ui.label(
                            egui::RichText::new(format!("Raw: {}", a.raw_response))
                                .monospace()
                                .small(),
                        );
                    });
                    ui.add_space(4.0);
                }
                ui.separator();
            }

            ui.horizontal(|ui| {
                ui.label("Banner Response Time:");
                let tarpit_label = if smtp.is_tarpit {
                    " (Tarpit / Delay Detected!)"
                } else {
                    " (Normal)"
                };
                ui.label(egui::RichText::new(format!("{:.0} ms{}", smtp.banner_time_ms, tarpit_label)).strong());
            });

            ui.horizontal(|ui| {
                ui.label("Banner Text:");
                ui.label(egui::RichText::new(smtp.banner.as_deref().unwrap_or("None")).monospace());
            });

            ui.horizontal(|ui| {
                ui.label("Open Relay Status:");
                let relay_text = if smtp.open_relay_detected {
                    egui::RichText::new("Open relay detected")
                        .strong()
                        .color(egui::Color32::from_rgb(239, 68, 68))
                } else {
                    egui::RichText::new("Relay denied").color(egui::Color32::from_rgb(52, 211, 153))
                };
                ui.label(relay_text);
            });

            if let Some(size_mb) = smtp.max_size_mb() {
                ui.horizontal(|ui| {
                    ui.label("Advertised Max Size Limit:");
                    ui.label(egui::RichText::new(format!("{:.1} MB", size_mb)).strong());
                });
            }

            ui.add_space(6.0);
            ui.label(egui::RichText::new("Advertised ESMTP Capabilities:").strong());
            ui.horizontal_wrapped(|ui| {
                for cap in &smtp.capabilities {
                    ui.label(
                        egui::RichText::new(cap)
                            .monospace()
                            .background_color(egui::Color32::from_rgb(30, 41, 59)),
                    );
                }
            });
        } else {
            ui.label("No SMTP data recorded.");
        }
    }

    fn render_dns_tab(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        if let Some(dns) = &res.dns {
            ui.heading("DNS MX & Mail Authentication Records");
            ui.add_space(6.0);

            ui.label(egui::RichText::new("Mail Exchangers (MX Records):").strong());
            egui::Grid::new("mx_grid")
                .striped(true)
                .min_col_width(80.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Priority").strong());
                    ui.label(egui::RichText::new("Hostname").strong());
                    ui.label(egui::RichText::new("Addresses").strong());
                    ui.label(egui::RichText::new("Reverse DNS (PTR)").strong());
                    ui.end_row();

                    for mx in &dns.mx_hosts {
                        ui.label(mx.priority.to_string());
                        ui.label(&mx.hostname);
                        ui.label(
                            mx.ipv4_addresses
                                .iter()
                                .chain(mx.ipv6_addresses.iter())
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        let ptrs: Vec<String> = mx.ptr_records.values().flatten().cloned().collect();
                        ui.label(if ptrs.is_empty() {
                            "No PTR".to_string()
                        } else {
                            ptrs.join(", ")
                        });
                        ui.end_row();
                    }
                });

            ui.add_space(10.0);
            ui.label(egui::RichText::new("Email Authentication:").strong());
            ui.horizontal(|ui| {
                ui.label("SPF Record:");
                ui.label(egui::RichText::new(dns.spf_record.as_deref().unwrap_or("None")).monospace());
            });
            ui.horizontal(|ui| {
                ui.label("DMARC Record:");
                ui.label(egui::RichText::new(dns.dmarc_record.as_deref().unwrap_or("None")).monospace());
            });
            ui.horizontal(|ui| {
                ui.label("DKIM Record:");
                ui.label(
                    egui::RichText::new(if dns.dkim_keys.is_empty() {
                        "None found".to_string()
                    } else {
                        dns.dkim_keys
                            .iter()
                            .map(|k| format!("{} ({})", k.selector, k.describe()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .monospace(),
                );
            });
            ui.horizontal(|ui| {
                ui.label("SPF DNS Lookups:");
                ui.label(
                    egui::RichText::new(format!("{} of 10 (whole include tree)", dns.spf_lookup_count)).monospace(),
                );
            });

            ui.add_space(10.0);
            ui.label(egui::RichText::new("Transport Security:").strong());
            let row = |ui: &mut egui::Ui, k: &str, v: String| {
                ui.horizontal(|ui| {
                    ui.label(k);
                    ui.label(egui::RichText::new(v).monospace());
                });
            };
            row(
                ui,
                "DNSSEC:",
                match dns.dnssec_signed {
                    Some(true) => "Signed and validated",
                    Some(false) => "Not signed",
                    None => "Unknown",
                }
                .to_string(),
            );
            match &dns.mta_sts {
                Some(sts) => {
                    row(ui, "MTA-STS TXT:", sts.txt_record.clone().unwrap_or_default());
                    row(
                        ui,
                        "MTA-STS Policy:",
                        if sts.policy_fetched {
                            format!(
                                "mode={} max_age={} mx={}",
                                sts.mode.as_deref().unwrap_or("?"),
                                sts.max_age.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
                                sts.mx_patterns.join(", ")
                            )
                        } else {
                            format!("fetch failed: {}", sts.fetch_error.as_deref().unwrap_or("?"))
                        },
                    );
                }
                None => row(ui, "MTA-STS:", "Not configured".to_string()),
            }
            row(
                ui,
                "TLS-RPT:",
                dns.tls_rpt_record.clone().unwrap_or_else(|| "None".into()),
            );
            row(ui, "BIMI:", dns.bimi_record.clone().unwrap_or_else(|| "None".into()));
            for mx in dns.mx_hosts.iter().filter(|h| !h.tlsa_records.is_empty()) {
                let recs: Vec<String> = mx
                    .tlsa_records
                    .iter()
                    .map(|t| {
                        format!(
                            "{} {} {} {}…",
                            t.usage,
                            t.selector,
                            t.matching_type,
                            &t.data_hex[..t.data_hex.len().min(16)]
                        )
                    })
                    .collect();
                row(
                    ui,
                    &format!("TLSA {}:", mx.hostname),
                    format!(
                        "{}{}",
                        recs.join(" | "),
                        if mx.tlsa_dnssec_valid == Some(true) {
                            " (DNSSEC ok)"
                        } else {
                            " (NOT DNSSEC-validated)"
                        }
                    ),
                );
            }

            if !dns.dnsbl.is_empty() {
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Blocklists:").strong());
                egui::Grid::new("dnsbl_grid").striped(true).show(ui, |ui| {
                    for r in &dns.dnsbl {
                        ui.label(&r.ip);
                        ui.label(&r.list);
                        ui.label(match r.listed {
                            Some(true) => format!("LISTED {}", r.return_codes.join(",")),
                            Some(false) => "clean".into(),
                            None => r.meaning.clone().unwrap_or_else(|| "unknown".into()),
                        });
                        ui.end_row();
                    }
                });
            }
        }
    }

    fn render_ports_tab(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        ui.heading("Port Connectivity & Handshake Latency");
        ui.add_space(6.0);

        egui::Grid::new("ports_grid")
            .striped(true)
            .min_col_width(100.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Port").strong());
                ui.label(egui::RichText::new("Service").strong());
                ui.label(egui::RichText::new("Status").strong());
                ui.label(egui::RichText::new("Latency").strong());
                ui.label(egui::RichText::new("Details").strong());
                ui.end_row();

                for p in &res.port_probes {
                    ui.label(p.port.to_string());
                    ui.label(&p.service);
                    if p.reachable {
                        ui.label(
                            egui::RichText::new("OPEN")
                                .strong()
                                .color(egui::Color32::from_rgb(52, 211, 153)),
                        );
                        ui.label(format!("{:.0} ms", p.latency_ms));
                        ui.label("Connected successfully");
                    } else {
                        ui.label(
                            egui::RichText::new("CLOSED / TIMEOUT")
                                .strong()
                                .color(egui::Color32::from_rgb(248, 113, 113)),
                        );
                        ui.label("-");
                        ui.label(p.error.as_deref().unwrap_or("Unreachable"));
                    }
                    ui.end_row();
                }
            });
    }

    fn render_servers_tab(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        let is_dark = ui.visuals().dark_mode;
        let good = if is_dark {
            egui::Color32::from_rgb(52, 211, 153)
        } else {
            egui::Color32::from_rgb(5, 150, 105)
        };
        let warn = if is_dark {
            egui::Color32::from_rgb(251, 191, 36)
        } else {
            egui::Color32::from_rgb(217, 119, 6)
        };
        let bad = if is_dark {
            egui::Color32::from_rgb(248, 113, 113)
        } else {
            egui::Color32::from_rgb(220, 38, 38)
        };

        ui.heading("Every MX Address Tested");
        ui.add_space(6.0);
        if res.servers.is_empty() {
            ui.label("No SMTP servers were tested.");
            return;
        }
        egui::Grid::new("servers_grid")
            .striped(true)
            .min_col_width(60.0)
            .show(ui, |ui| {
                for h in [
                    "Pref",
                    "Host",
                    "Address",
                    "SMTP",
                    "STARTTLS",
                    "TLS",
                    "Certificate",
                    "Expires",
                    "DANE",
                ] {
                    ui.label(egui::RichText::new(h).strong());
                }
                ui.end_row();
                for s in &res.servers {
                    ui.label(s.priority.to_string());
                    ui.label(&s.hostname);
                    ui.label(egui::RichText::new(&s.ip).monospace());
                    if s.smtp.connected {
                        ui.label(egui::RichText::new(format!("OK ({:.0} ms)", s.smtp.banner_time_ms)).color(good));
                    } else {
                        ui.label(egui::RichText::new("Unreachable").color(bad))
                            .on_hover_text(s.smtp.error_message.as_deref().unwrap_or(""));
                    }
                    ui.label(if s.smtp.starttls_advertised {
                        egui::RichText::new("Offered").color(good)
                    } else if s.smtp.connected {
                        egui::RichText::new("No").color(warn)
                    } else {
                        egui::RichText::new("-")
                    });
                    match &s.tls {
                        Some(t) if t.handshake_success => {
                            ui.label(t.tls_version.clone().unwrap_or_default())
                                .on_hover_text(t.cipher_name.clone().unwrap_or_default());
                            let cert = if t.chain_verified {
                                egui::RichText::new("Trusted").color(good)
                            } else {
                                egui::RichText::new("Not trusted").color(warn)
                            };
                            ui.label(cert).on_hover_text(format!(
                                "CN: {}\nIssuer: {}\nSANs: {}\nSHA-256: {}{}",
                                t.cert_subject_cn.as_deref().unwrap_or("?"),
                                t.cert_issuer.as_deref().unwrap_or("?"),
                                t.cert_sans.join(", "),
                                t.cert_sha256.as_deref().unwrap_or("?"),
                                t.verify_error
                                    .as_ref()
                                    .map(|e| format!("\nProblem: {}", e))
                                    .unwrap_or_default()
                            ));
                            let days = t.cert_days_left.unwrap_or(0);
                            let color = if days < 14 {
                                bad
                            } else if days < 30 {
                                warn
                            } else {
                                good
                            };
                            ui.label(egui::RichText::new(format!("{} days", days)).color(color))
                                .on_hover_text(t.cert_not_after.clone().unwrap_or_default());
                            ui.label(t.dane_status.clone().unwrap_or_else(|| "-".to_string()));
                        }
                        Some(t) => {
                            ui.label(egui::RichText::new("Failed").color(bad))
                                .on_hover_text(t.error_message.clone().unwrap_or_default());
                            ui.label("-");
                            ui.label("-");
                            ui.label("-");
                        }
                        None => {
                            for _ in 0..4 {
                                ui.label("-");
                            }
                        }
                    }
                    ui.end_row();
                }
            });
    }

    fn render_transcript_tab(&self, ui: &mut egui::Ui, res: &DiagnosticResult) {
        let sessions: Vec<(String, &crate::models::SmtpReport)> = if res.servers.is_empty() {
            res.smtp.iter().map(|s| (s.host.clone(), s)).collect()
        } else {
            res.servers
                .iter()
                .map(|s| (format!("{} ({})", s.hostname, s.ip), &s.smtp))
                .collect()
        };
        let mut idx = self.transcript_server.get().min(sessions.len().saturating_sub(1));

        ui.horizontal(|ui| {
            ui.heading("Raw SMTP Packet Transcript");
            if sessions.len() > 1 {
                egui::ComboBox::from_id_salt("transcript_server")
                    .selected_text(sessions[idx].0.clone())
                    .show_ui(ui, |ui| {
                        for (i, (label, _)) in sessions.iter().enumerate() {
                            ui.selectable_value(&mut idx, i, label);
                        }
                    });
            }
            if let Some((_, smtp)) = sessions.get(idx) {
                if ui.button("📋 Copy to Clipboard").clicked() {
                    let text = smtp
                        .transcript
                        .iter()
                        .map(|t| format!("{} {} {}", t.timestamp, t.direction, t.text))
                        .collect::<Vec<_>>()
                        .join("\n");
                    ui.ctx().copy_text(text);
                }
            }
        });
        self.transcript_server.set(idx);
        ui.add_space(4.0);

        let is_dark = ui.visuals().dark_mode;
        let time_color = if is_dark {
            egui::Color32::from_rgb(100, 116, 139)
        } else {
            egui::Color32::from_rgb(148, 163, 184)
        };

        if let Some((_, smtp)) = sessions.get(idx) {
            for t in &smtp.transcript {
                let color = match t.direction.as_str() {
                    "->" => {
                        if is_dark {
                            egui::Color32::from_rgb(96, 165, 250)
                        } else {
                            egui::Color32::from_rgb(29, 78, 216)
                        }
                    }
                    "<-" => {
                        if is_dark {
                            egui::Color32::from_rgb(52, 211, 153)
                        } else {
                            egui::Color32::from_rgb(5, 150, 105)
                        }
                    }
                    _ => {
                        if is_dark {
                            egui::Color32::from_rgb(148, 163, 184)
                        } else {
                            egui::Color32::from_rgb(100, 116, 139)
                        }
                    }
                };
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&t.timestamp).small().color(time_color));
                    ui.label(egui::RichText::new(&t.direction).strong().color(color));
                    ui.label(egui::RichText::new(&t.text).monospace().color(color));
                });
            }
        } else {
            ui.label("No transcript entries recorded.");
        }
    }
}

#[cfg(not(windows))]
impl egui_backend_selector::App for MxDetectiveApp {
    fn ui(&mut self, ui: &mut egui::Ui, _backend: egui_backend_selector::BackendInterop<'_>) {
        self.show(ui);
    }
}

#[cfg(windows)]
impl egui_software_backend::App for MxDetectiveApp {
    fn ui(&mut self, ui: &mut egui::Ui, _backend: &mut egui_software_backend::SoftwareBackend) {
        self.show(ui);
    }
}

/// Opens the window. It draws on the CPU, so it needs no graphics driver and opens in virtual
/// machines and remote desktop sessions. On Windows that is always; elsewhere OpenGL is used
/// when it works.
pub fn launch_gui(initial_domain: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([980.0, 720.0])
        .with_min_inner_size([720.0, 500.0])
        .with_title("MX Detective")
        .with_app_id("mx-detective");
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png")) {
        viewport = viewport.with_icon(icon);
    }

    // Caching is off because it renders incorrectly in the software backend (upstream issue 11).
    let software = egui_software_backend::SoftwareBackendAppConfiguration {
        caching: false,
        viewport_builder: viewport.clone(),
        ..Default::default()
    };

    #[cfg(windows)]
    {
        let _ = viewport;
        egui_software_backend::run_app_with_software_backend(software, move |_ctx| {
            MxDetectiveApp::new(initial_domain.clone())
        })?;
        Ok(())
    }

    #[cfg(not(windows))]
    {
        use egui_backend_selector::{Backend, BackendConfiguration};
        if std::env::var_os("MX_DETECTIVE_SOFTWARE_RENDER").is_some() {
            egui_backend_selector::overwrite_backend(Backend::SoftwareBackend);
        }
        let config = BackendConfiguration::new(viewport, eframe::NativeOptions::default(), software);
        egui_backend_selector::run_app("mx-detective", config, move |_ctx, _storage| {
            MxDetectiveApp::new(initial_domain.clone())
        })
    }
}
