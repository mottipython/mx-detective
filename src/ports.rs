use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::models::{CheckItem, PortProbe, Severity};

const MAIL_PORTS: [(u16, &str); 4] = [
    (25, "SMTP (MTA-to-MTA Transfer)"),
    (587, "Submission (STARTTLS)"),
    (465, "SMTPS (Implicit TLS)"),
    (2525, "SMTP Alternative"),
];

pub struct PortProber {
    timeout: Duration,
}

impl PortProber {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    fn probe(&self, ip: IpAddr, port: u16, service: &str) -> PortProbe {
        let start = Instant::now();
        let result = TcpStream::connect_timeout(&SocketAddr::new(ip, port), self.timeout);
        PortProbe {
            port,
            service: service.to_string(),
            reachable: result.is_ok(),
            latency_ms: (start.elapsed().as_secs_f64() * 1000.0).round(),
            error: result.err().map(|e| e.to_string()),
        }
    }

    /// Probes all mail ports on one address in parallel, so filtered ports cost one
    /// timeout in total rather than one each.
    pub fn probe_mail_ports(&self, host: &str, ip: IpAddr) -> (Vec<PortProbe>, Vec<CheckItem>, bool) {
        let probes: Vec<PortProbe> = std::thread::scope(|s| {
            let handles: Vec<_> = MAIL_PORTS
                .iter()
                .map(|(port, svc)| s.spawn(move || self.probe(ip, *port, svc)))
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        let mut checks = Vec::new();

        let p25 = probes.iter().find(|p| p.port == 25);
        let mut port_25_blocked_suspected = false;

        if let Some(p) = p25 {
            if p.reachable {
                checks.push(CheckItem::new(
                    "PORT_25_OPEN",
                    "NETWORK",
                    Severity::Pass,
                    format!("Port 25 (SMTP) Open ({:.0} ms)", p.latency_ms),
                    format!("Successfully connected to {}:25 in {:.0} ms.", host, p.latency_ms),
                ));
            } else {
                port_25_blocked_suspected = true;
                checks.push(CheckItem {
                    technical_details: p.error.clone(),
                    ..CheckItem::new(
                        "PORT_25_CLOSED",
                        "NETWORK",
                        Severity::Critical,
                        "Port 25 (SMTP) Unreachable",
                        format!("Could not connect to {}:25 ({})", host, p.error.clone().unwrap_or_default()),
                    )
                    .fix("Many residential ISPs (Comcast, Charter, AT&T) and cloud providers (AWS, Azure, GCP) block outbound port 25. If you are testing from such a network, inbound mail to this domain may still work.")
                });
            }
        }

        (probes, checks, port_25_blocked_suspected)
    }
}
