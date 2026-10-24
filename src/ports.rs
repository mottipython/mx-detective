use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::models::{CheckItem, PortProbe, Severity};

pub struct PortProber {
    timeout: Duration,
}

impl PortProber {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn probe_mail_ports(&self, host: &str) -> (Vec<PortProbe>, Vec<CheckItem>, bool) {
        let ports = [
            (25, "SMTP (MTA-to-MTA Transfer)"),
            (587, "Submission (STARTTLS)"),
            (465, "SMTPS (Implicit TLS)"),
            (2525, "SMTP Alternative"),
        ];

        let mut probes = Vec::new();
        let mut checks = Vec::new();

        for (port, service) in ports {
            let start = Instant::now();
            let addr_str = format!("{}:{}", host, port);

            match addr_str.to_socket_addrs() {
                Ok(addrs) => {
                    let mut connected = false;
                    let mut last_err = None;

                    for addr in addrs {
                        match TcpStream::connect_timeout(&addr, self.timeout) {
                            Ok(stream) => {
                                let latency = (start.elapsed().as_secs_f64() * 1000.0).round();
                                connected = true;
                                drop(stream);
                                probes.push(PortProbe {
                                    port,
                                    service: service.to_string(),
                                    reachable: true,
                                    latency_ms: latency,
                                    error: None,
                                });
                                break;
                            }
                            Err(e) => {
                                last_err = Some(e.to_string());
                            }
                        }
                    }

                    if !connected {
                        let latency = (start.elapsed().as_secs_f64() * 1000.0).round();
                        probes.push(PortProbe {
                            port,
                            service: service.to_string(),
                            reachable: false,
                            latency_ms: latency,
                            error: last_err.or_else(|| Some("Connection failed".to_string())),
                        });
                    }
                }
                Err(e) => {
                    probes.push(PortProbe {
                        port,
                        service: service.to_string(),
                        reachable: false,
                        latency_ms: 0.0,
                        error: Some(format!("DNS lookup failed: {}", e)),
                    });
                }
            }
        }

        // Analyze Port 25 Reachability
        let p25 = probes.iter().find(|p| p.port == 25);
        let mut port_25_blocked_suspected = false;

        if let Some(p) = p25 {
            if p.reachable {
                checks.push(CheckItem {
                    check_id: "PORT_25_OPEN".to_string(),
                    category: "NETWORK".to_string(),
                    title: format!("Port 25 (SMTP) Open ({:.0} ms)", p.latency_ms),
                    severity: Severity::Pass,
                    message: format!("Successfully connected to {}:25 in {:.0} ms.", host, p.latency_ms),
                    recommendation: None,
                    technical_details: None,
                });
            } else {
                port_25_blocked_suspected = true;
                checks.push(CheckItem {
                    check_id: "PORT_25_CLOSED".to_string(),
                    category: "NETWORK".to_string(),
                    title: "Port 25 (SMTP) Unreachable".to_string(),
                    severity: Severity::Critical,
                    message: format!("Could not connect to {}:25 ({})", host, p.error.clone().unwrap_or_default()),
                    recommendation: Some("COMMON IT CAUSE: Outbound port 25 is actively filtered by residential ISPs (Comcast, Charter, AT&T) and cloud providers (AWS, Azure, GCP) to prevent spam bots. If testing from a workstation, public incoming email may still be functioning correctly.".to_string()),
                    technical_details: p.error.clone(),
                });
            }
        }

        (probes, checks, port_25_blocked_suspected)
    }
}
