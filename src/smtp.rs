use chrono::Utc;
use rustls::{ClientConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::models::{CheckItem, MisbehaviorAnomaly, Severity, SmtpReport, TlsReport, TlsaRecord, TranscriptEntry};
use crate::tls;

/// Lines longer than this are cut off; RFC 5321 §4.5.3.1.5 caps replies at 512 octets.
const MAX_LINE: usize = 16 * 1024;
/// A multi-line reply with more lines than this is treated as a broken server.
const MAX_REPLY_LINES: usize = 500;
const GREETING_TIMEOUT: Duration = Duration::from_secs(30);

/// What to test in one SMTP session.
#[derive(Debug, Clone, Default)]
pub struct ProbeOptions {
    /// Domain under test; used for the postmaster and catch-all probes.
    pub domain: Option<String>,
    pub test_relay: bool,
    pub recipient: Option<String>,
    pub audit_tls: bool,
    /// TLSA records for this MX host, to check DANE against the presented chain.
    pub tlsa: Vec<TlsaRecord>,
    /// Postmaster, catch-all and VRFY/EXPN probes.
    pub extended: bool,
}

enum Transport {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Closed,
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
            Transport::Closed => Ok(0),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
            Transport::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "connection closed")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
            Transport::Closed => Ok(()),
        }
    }
}

/// An SMTP connection with its own read buffer, so nothing is lost between replies
/// and leftover plaintext after the STARTTLS reply can be detected.
struct SmtpConn {
    transport: Transport,
    buf: Vec<u8>,
}

impl SmtpConn {
    fn new(sock: TcpStream) -> Self {
        Self {
            transport: Transport::Plain(sock),
            buf: Vec::new(),
        }
    }

    fn is_tls(&self) -> bool {
        matches!(self.transport, Transport::Tls(_))
    }

    fn read_line(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Ok(Some(line));
            }
            if self.buf.len() > MAX_LINE {
                let line = std::mem::take(&mut self.buf);
                return Ok(Some(line));
            }
            let mut chunk = [0u8; 4096];
            match self.transport.read(&mut chunk) {
                Ok(0) => {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(std::mem::take(&mut self.buf)));
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}

type Reply = (u16, Vec<String>, bool);

pub struct SmtpProber {
    timeout: Duration,
    client_fqdn: String,
}

impl SmtpProber {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            client_fqdn: "mail-diagnostic.detective.local".to_string(),
        }
    }

    /// Runs one SMTP session against `addr`, using `host` for TLS name checks.
    pub fn probe(
        &self,
        host: &str,
        addr: SocketAddr,
        opts: &ProbeOptions,
    ) -> (SmtpReport, Option<TlsReport>, Vec<CheckItem>) {
        let mut report = SmtpReport {
            host: host.to_string(),
            ip: Some(addr.ip().to_string()),
            port: addr.port(),
            multiline_format_valid: true,
            recipient_tested: opts.recipient.clone(),
            ..Default::default()
        };
        let mut tls_report: Option<TlsReport> = None;
        let mut checks = Vec::new();

        let mut conn = match self.open_session(addr, &mut report, &mut checks, true) {
            Some(c) => c,
            None => return (report, tls_report, checks),
        };

        if report.starttls_advertised && opts.audit_tls {
            match Self::command(&mut conn, "STARTTLS", &mut report) {
                Ok((220, _, _)) => {
                    if !conn.buf.is_empty() {
                        let extra = String::from_utf8_lossy(&conn.buf).trim().to_string();
                        report.anomalies.push(MisbehaviorAnomaly::new("STARTTLS_PLAINTEXT_AFTER_220", Severity::Warning, "RFC 3207 §5", "Server Sent Plaintext After the STARTTLS 220 Reply", "Data arrived after '220 Ready to start TLS' and before the TLS handshake. A client that kept it would treat unencrypted text as if it came over TLS (the CVE-2011-0411 class of bug).", extra));
                        conn.buf.clear();
                    }
                    match self.upgrade(conn, host, addr.port(), opts, &mut report) {
                        Ok((upgraded, tr)) => {
                            conn = upgraded;
                            Self::push_tls_checks(&tr, &mut checks);
                            tls_report = Some(tr);

                            // RFC 3207 §4.2: the client must discard state and EHLO again.
                            let ehlo = format!("EHLO {}", self.client_fqdn);
                            match Self::command(&mut conn, &ehlo, &mut report) {
                                Ok((250, lines, _)) => {
                                    if lines
                                        .iter()
                                        .skip(1)
                                        .any(|l| Self::extract_ehlo_capability(l).eq_ignore_ascii_case("STARTTLS"))
                                    {
                                        report.anomalies.push(MisbehaviorAnomaly::new("STARTTLS_ADVERTISED_INSIDE_TLS", Severity::Notice, "RFC 3207 §4.2", "STARTTLS Still Advertised Inside the TLS Session", "RFC 3207 §4.2 says a server must not offer STARTTLS again after TLS is negotiated.", lines.join(" | ")));
                                    }
                                    self.parse_ehlo_extensions(&lines, &mut report, &mut checks, true);
                                }
                                _ => {
                                    report.anomalies.push(MisbehaviorAnomaly::new(
                                        "RFC3207_POST_TLS_EHLO_FAIL",
                                        Severity::Critical,
                                        "RFC 3207 §4.2",
                                        "Post-STARTTLS State Reset Failure (RFC 3207 §4.2 Violation)",
                                        "Server failed to accept a clean EHLO command after TLS negotiation.",
                                        "No 250 response to re-EHLO",
                                    ));
                                    return (report, tls_report, checks);
                                }
                            }
                        }
                        Err(err_str) => {
                            tls_report = Some(TlsReport {
                                host: host.to_string(),
                                port: addr.port(),
                                starttls_attempted: true,
                                error_message: Some(err_str.clone()),
                                ..Default::default()
                            });
                            report.anomalies.push(MisbehaviorAnomaly::new(
                                "TLS_HANDSHAKE_DROP",
                                Severity::Critical,
                                "RFC 3207 §4",
                                "TLS Handshake Failed / Rejected",
                                format!(
                                    "Server accepted STARTTLS with 220, but the TLS handshake failed: {}",
                                    err_str
                                ),
                                err_str.clone(),
                            ));
                            let old_tls = err_str.contains("ProtocolVersion") || err_str.contains("protocol version");
                            checks.push(CheckItem::new("TLS_HANDSHAKE_ERROR", "TLS", Severity::Critical, if old_tls { "TLS Handshake Failed (No TLS 1.2 or 1.3)" } else { "TLS Handshake Failed" }.to_string(), format!("STARTTLS was accepted but the handshake failed: {}. Senders that try TLS will retry or give up, delaying mail.", err_str)).fix(if old_tls {
                                    "Enable TLS 1.2 and TLS 1.3 on the MTA; TLS 1.0 and 1.1 are deprecated by RFC 8996."
                                } else {
                                    "Check the MTA's TLS certificate, key and cipher configuration."
                                }.to_string()).details(err_str));
                            // Real MTAs fall back to plaintext; do the same so the rest gets tested.
                            Self::log(
                                &mut report,
                                "*",
                                "Reconnecting without TLS to run the remaining tests...",
                            );
                            conn = match self.open_session(addr, &mut report, &mut Vec::new(), false) {
                                Some(c) => c,
                                None => return (report, tls_report, checks),
                            };
                        }
                    }
                }
                Ok((other_code, other_lines, _)) => {
                    let raw_resp = other_lines.join(" ");
                    report.anomalies.push(MisbehaviorAnomaly::new(
                        "STARTTLS_FALSE_ADVERTISING",
                        Severity::Critical,
                        "RFC 3207 §4.1",
                        format!("STARTTLS Advertised But Rejected (Code {})", other_code),
                        format!(
                            "Server advertised STARTTLS in EHLO capabilities, but returned code {} upon execution.",
                            other_code
                        ),
                        raw_resp.clone(),
                    ));
                    checks.push(
                        CheckItem::new(
                            "BEHAVIOR_STARTTLS_REJECTED",
                            "BEHAVIOR",
                            Severity::Critical,
                            "STARTTLS False Advertisement",
                            format!(
                                "Server advertised STARTTLS in EHLO, but rejected the command with code {}: '{}'",
                                other_code, raw_resp
                            ),
                        )
                        .fix("Fix MTA configuration or certificate bindings causing STARTTLS command failure."),
                    );
                }
                Err(e) => {
                    report.error_message = Some(format!("Network error during STARTTLS: {}", e));
                    return (report, tls_report, checks);
                }
            }
        } else if !report.starttls_advertised {
            checks.push(CheckItem::new("TLS_NOT_SUPPORTED", "SECURITY", Severity::Warning, "STARTTLS Not Advertised (Plaintext Only)", "Server does not advertise STARTTLS encryption. Email will be transmitted in unencrypted cleartext.").fix("Enable STARTTLS on the mail server to prevent eavesdropping and comply with modern security standards."));
        }

        // Envelope tests run the same inside or outside TLS.
        self.probe_null_sender(&mut conn, &mut report, &mut checks);
        if opts.extended {
            if let Some(domain) = &opts.domain {
                self.probe_postmaster_and_catch_all(&mut conn, domain, &mut report, &mut checks);
            }
        }
        if opts.test_relay {
            self.probe_open_relay(&mut conn, &mut report, &mut checks);
        }
        if let Some(rcpt) = &opts.recipient {
            self.probe_recipient(&mut conn, rcpt, &mut report, &mut checks);
        }
        if opts.extended {
            self.probe_vrfy_expn(&mut conn, &mut report, &mut checks);
        }

        match Self::command(&mut conn, "RSET", &mut report) {
            Ok((250, _, _)) => report.rset_working = true,
            Ok((code, lines, _)) => {
                report.anomalies.push(MisbehaviorAnomaly::new(
                    "RSET_STATE_FAILURE",
                    Severity::Warning,
                    "RFC 5321 §4.1.1.5",
                    format!("Non-250 Response to RSET ({})", code),
                    "RFC 5321 §4.1.1.5 specifies that RSET must always reset state and return 250 OK.",
                    lines.join(" "),
                ));
            }
            Err(_) => {}
        }

        match Self::command(&mut conn, "QUIT", &mut report) {
            Ok((221, _, _)) => report.quit_clean = true,
            Ok((code, lines, _)) => {
                report.anomalies.push(MisbehaviorAnomaly::new(
                    "QUIT_NON_221",
                    Severity::Notice,
                    "RFC 5321 §4.1.1.10",
                    format!("Non-221 Response to QUIT ({})", code),
                    "Server responded to QUIT with non-standard status code instead of 221.",
                    lines.join(" "),
                ));
            }
            Err(_) => {
                report.anomalies.push(MisbehaviorAnomaly::new(
                    "PREMATURE_SOCKET_DROP_ON_QUIT",
                    Severity::Notice,
                    "RFC 5321 §4.1.1.10",
                    "Abrupt Disconnect on QUIT (No 221 Greeting)",
                    "Server abruptly dropped the TCP connection upon receiving QUIT without sending a 221 response.",
                    "Connection closed",
                ));
            }
        }

        (report, tls_report, checks)
    }

    /// Connects, reads the banner and sends EHLO (or HELO). With `record` false it only
    /// gets a usable session back, for the plaintext retry after a failed handshake.
    fn open_session(
        &self,
        addr: SocketAddr,
        report: &mut SmtpReport,
        checks: &mut Vec<CheckItem>,
        record: bool,
    ) -> Option<SmtpConn> {
        let start_connect = Instant::now();
        let sock = match TcpStream::connect_timeout(&addr, self.timeout) {
            Ok(s) => s,
            Err(e) => {
                report.error_message = Some(format!("TCP connection to {} failed: {}", addr, e));
                if record {
                    checks.push(CheckItem::new("SMTP_CONN_FAILED", "NETWORK", Severity::Critical, format!("SMTP Connection Failed (port {})", addr.port()), format!("Failed to establish TCP connection to {}: {}", addr, e)).fix("Verify if port 25 is blocked outbound by your ISP or firewall, and verify the MTA daemon is listening.").details(e.to_string()));
                }
                return None;
            }
        };
        let _ = sock.set_read_timeout(Some(self.timeout));
        let _ = sock.set_write_timeout(Some(self.timeout));
        if record {
            report.connect_time_ms = (start_connect.elapsed().as_secs_f64() * 1000.0).round();
            report.connected = true;
        }
        let connect_ms = (start_connect.elapsed().as_secs_f64() * 1000.0).round();
        Self::log(report, "*", &format!("Connected to {} in {:.1} ms", addr, connect_ms));
        let mut conn = SmtpConn::new(sock);

        // Greeting delays are legitimate (postscreen pauses ~6 s on purpose), and RFC 5321
        // §4.5.3.2 gives clients 5 minutes, so allow longer than for other replies.
        let start_banner = Instant::now();
        if let Transport::Plain(sock) = &conn.transport {
            let _ = sock.set_read_timeout(Some(self.timeout.max(GREETING_TIMEOUT)));
        }
        let banner = Self::read_reply(&mut conn, report);
        if let Transport::Plain(sock) = &conn.transport {
            let _ = sock.set_read_timeout(Some(self.timeout));
        }
        let (banner_code, banner_lines, raw_crlf_valid) = match banner {
            Ok(res) => res,
            Err(e) => {
                report.error_message = Some(format!("Failed reading initial banner: {}", e));
                if record {
                    checks.push(
                        CheckItem::new(
                            "SMTP_BANNER_TIMEOUT",
                            "BEHAVIOR",
                            Severity::Critical,
                            "SMTP Banner Timeout / Immediate Disconnect",
                            format!(
                                "Server accepted TCP connection but failed to send 220 banner within {}s: {}",
                                self.timeout.max(GREETING_TIMEOUT).as_secs(),
                                e
                            ),
                        )
                        .fix("Check mail server logs for immediate connection drops or firewall inspection timeouts."),
                    );
                }
                return None;
            }
        };

        if !record {
            if banner_code != 220 {
                return None;
            }
            let ehlo = format!("EHLO {}", self.client_fqdn);
            return match Self::command(&mut conn, &ehlo, report) {
                Ok((250, _, _)) => Some(conn),
                _ => None,
            };
        }

        report.banner_time_ms = (start_banner.elapsed().as_secs_f64() * 1000.0).round();
        report.banner = Some(banner_lines.join(" "));

        if report.banner_time_ms > 3000.0 {
            report.is_tarpit = true;
            checks.push(CheckItem::new("BEHAVIOR_TARPIT", "BEHAVIOR", Severity::Notice, format!("Anti-Spam Tarpit Detected ({:.0} ms greeting delay)", report.banner_time_ms), format!("Server artificially delayed sending its initial 220 banner by {:.0} ms.", report.banner_time_ms)).fix("Ensure greeting delay does not exceed sending MTAs' connect timeouts (standard MTA timeout is typically 300s, but aggressive filters may abort).").details("Tarpitting (greeting pause) is designed to slow down bulk spammers who send data immediately."));
        }

        if banner_code != 220 {
            report.anomalies.push(MisbehaviorAnomaly::new(
                "INVALID_GREETING_CODE",
                Severity::Critical,
                "RFC 5321 §4.2",
                format!("Non-220 Banner Status Code ({})", banner_code),
                format!(
                    "Server greeted with code {} instead of required 220 greeting.",
                    banner_code
                ),
                report.banner.clone().unwrap_or_default(),
            ));
            checks.push(
                CheckItem::new(
                    "BEHAVIOR_INVALID_BANNER_CODE",
                    "BEHAVIOR",
                    Severity::Critical,
                    format!("Unexpected Banner Status Code ({})", banner_code),
                    format!(
                        "Expected 220 greeting banner, but server responded with code {}: '{}'",
                        banner_code,
                        report.banner.clone().unwrap_or_default()
                    ),
                )
                .fix("Check if your IP address is blacklisted or if the server is in maintenance mode."),
            );
            return None;
        }

        report.banner_rfc_compliant = true;
        let full_banner = report.banner.clone().unwrap_or_default();
        let first_word = banner_lines
            .first()
            .map(|l| Self::extract_ehlo_capability(l))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("");
        if first_word.contains('.') {
            report.banner_has_fqdn = true;
        } else {
            report.anomalies.push(MisbehaviorAnomaly::new("BANNER_NO_FQDN", Severity::Notice, "RFC 5321 §4.2", "SMTP Banner Missing Fully Qualified Domain Name (FQDN)", "RFC 5321 §4.2 specifies that the first word of the 220 greeting MUST be the domain name of the SMTP server.", full_banner.clone()));
            checks.push(CheckItem::new("BEHAVIOR_BANNER_NO_FQDN", "BEHAVIOR", Severity::Notice, "Banner Missing Server FQDN", format!("The 220 banner greeting does not contain an FQDN as its first word: '{}'", full_banner)).fix("Configure your MTA hostname setting (e.g. `myhostname` in Postfix) to display a valid FQDN in the banner."));
        }

        if !raw_crlf_valid {
            report.multiline_format_valid = false;
            report.anomalies.push(MisbehaviorAnomaly::new("BARE_LF_LINE_TERMINATOR", Severity::Warning, "RFC 5321 §2.3.8", "Non-compliant Line Terminator (Bare LF detected)", "RFC 5321 §2.3.8 mandates that lines end with CRLF (\\r\\n). Bare LF (\\n) causes protocol desynchronization.", full_banner.clone()));
        }

        checks.push(CheckItem::new(
            "SMTP_BANNER_OK",
            "SMTP",
            Severity::Pass,
            "Valid 220 SMTP Greeting Banner",
            format!(
                "Received compliant 220 greeting in {:.0} ms: '{}'",
                report.banner_time_ms, full_banner
            ),
        ));

        let ehlo_cmd = format!("EHLO {}", self.client_fqdn);
        match Self::command(&mut conn, &ehlo_cmd, report) {
            Ok((250, ehlo_lines, _)) => {
                report.esmtp_supported = true;
                self.parse_ehlo_extensions(&ehlo_lines, report, checks, false);
            }
            Ok((err_code, _, _)) => {
                report.anomalies.push(MisbehaviorAnomaly::new(
                    "EHLO_REJECTED",
                    Severity::Warning,
                    "RFC 5321 §3.2",
                    format!("EHLO Command Rejected with Code {}", err_code),
                    "Server does not support ESMTP (RFC 5321), requiring fallback to legacy 1982 HELO.",
                    format!("Code {}", err_code),
                ));
                let helo_cmd = format!("HELO {}", self.client_fqdn);
                match Self::command(&mut conn, &helo_cmd, report) {
                    Ok((250, _, _)) => {
                        checks.push(CheckItem::new("BEHAVIOR_LEGACY_HELO", "BEHAVIOR", Severity::Warning, "Legacy HELO Only (No ESMTP Support)", "Server rejected EHLO and only supports legacy HELO. Modern extensions like STARTTLS and SIZE are unavailable.").fix("Enable ESMTP support on your mail transfer agent."));
                    }
                    _ => {
                        checks.push(
                            CheckItem::new(
                                "SMTP_HANDSHAKE_REJECTED",
                                "SMTP",
                                Severity::Critical,
                                "Handshake Failed (Both EHLO and HELO Rejected)",
                                "Server rejected both EHLO and HELO commands.",
                            )
                            .fix("Check mail server relay access configuration."),
                        );
                        return None;
                    }
                }
            }
            Err(e) => {
                report.error_message = Some(format!("Error during EHLO handshake: {}", e));
                return None;
            }
        }
        Some(conn)
    }

    /// Upgrades a plaintext session after the server's 220 to STARTTLS.
    fn upgrade(
        &self,
        conn: SmtpConn,
        host: &str,
        port: u16,
        opts: &ProbeOptions,
        report: &mut SmtpReport,
    ) -> Result<(SmtpConn, TlsReport), String> {
        let Transport::Plain(mut sock) = conn.transport else {
            return Err("connection was not plaintext".to_string());
        };
        Self::log(report, "*", "Initiating TLS ClientHello handshake...");
        let started = Instant::now();

        let verifier = tls::RecordingVerifier::new()?;
        let config = tls::recording_config(verifier.clone())?;
        let mut tls_conn = ClientConnection::new(config, tls::server_name(host)?).map_err(|e| e.to_string())?;
        if let Err(e) = tls::complete_handshake(&mut tls_conn, &mut sock) {
            Self::log(report, "*", &format!("TLS handshake failed: {}", e));
            return Err(e);
        }

        let ms = (started.elapsed().as_secs_f64() * 1000.0).round();
        let tr = tls::inspect_session(&tls_conn, host, port, verifier.outcome(), &opts.tlsa);
        Self::log(
            report,
            "*",
            &format!(
                "TLS established in {:.1} ms: {} {} | cert CN={} issuer={} | {}",
                ms,
                tr.tls_version.as_deref().unwrap_or("?"),
                tr.cipher_name.as_deref().unwrap_or("?"),
                tr.cert_subject_cn.as_deref().unwrap_or("?"),
                tr.cert_issuer.as_deref().unwrap_or("?"),
                if tr.chain_verified {
                    "trusted".to_string()
                } else {
                    format!("NOT trusted: {}", tr.verify_error.as_deref().unwrap_or("?"))
                }
            ),
        );

        Ok((
            SmtpConn {
                transport: Transport::Tls(Box::new(StreamOwned::new(tls_conn, sock))),
                buf: Vec::new(),
            },
            tr,
        ))
    }

    fn push_tls_checks(tr: &TlsReport, checks: &mut Vec<CheckItem>) {
        let version = tr.tls_version.clone().unwrap_or_else(|| "unknown".to_string());
        let cipher = tr.cipher_name.clone().unwrap_or_else(|| "unknown".to_string());
        let fingerprint = tr.cert_sha256.as_ref().map(|f| format!("Leaf SHA-256: {}", f));

        if tr.chain_verified {
            checks.push(CheckItem {
                technical_details: fingerprint.clone(),
                ..CheckItem::new(
                    "TLS_STARTTLS_OK",
                    "TLS",
                    Severity::Pass,
                    "STARTTLS With a Trusted Certificate",
                    format!(
                        "{} with {}. Certificate for '{}' issued by {}, valid until {}.",
                        version,
                        cipher,
                        tr.cert_subject_cn.as_deref().unwrap_or("?"),
                        tr.cert_issuer.as_deref().unwrap_or("?"),
                        tr.cert_not_after.as_deref().unwrap_or("?")
                    ),
                )
            });
        } else {
            let reason = tr.verify_error.clone().unwrap_or_else(|| "unknown reason".to_string());
            checks.push(CheckItem::new("TLS_CERT_UNTRUSTED", "TLS", Severity::Warning, "STARTTLS Works, but the Certificate Is Not Trusted", format!(
                    "Encryption works ({} with {}), but the {}. Most senders still deliver with opportunistic TLS, but MTA-STS and DANE senders will refuse it.",
                    version, cipher, reason
                )).fix("Install a certificate from a public CA (e.g. Let's Encrypt) that covers the MX hostname, and serve the full intermediate chain.").details(format!(
                    "Subject CN: {} | Issuer: {} | SANs: {} | SHA-256: {}",
                    tr.cert_subject_cn.as_deref().unwrap_or("?"),
                    tr.cert_issuer.as_deref().unwrap_or("?"),
                    if tr.cert_sans.is_empty() { "none".to_string() } else { tr.cert_sans.join(", ") },
                    tr.cert_sha256.as_deref().unwrap_or("?")
                )));
        }

        if let Some(days) = tr.cert_days_left {
            if tr.cert_is_expired {
                checks.push(CheckItem::new("TLS_CERT_EXPIRED", "TLS", Severity::Critical, "TLS Certificate Has Expired", format!("The certificate expired on {} ({} days ago).", tr.cert_not_after.as_deref().unwrap_or("?"), -days)).fix("Renew the certificate and reload the MTA. Check that automatic renewal also reloads the mail server."));
            } else if days < 14 {
                checks.push(
                    CheckItem::new(
                        "TLS_CERT_EXPIRING",
                        "TLS",
                        Severity::Warning,
                        format!("TLS Certificate Expires in {} Days", days),
                        format!(
                            "The certificate expires on {}.",
                            tr.cert_not_after.as_deref().unwrap_or("?")
                        ),
                    )
                    .fix("Renew now. If renewal is automated, it has probably failed or the MTA was not reloaded."),
                );
            } else if days < 30 {
                checks.push(CheckItem::new(
                    "TLS_CERT_EXPIRING",
                    "TLS",
                    Severity::Notice,
                    format!("TLS Certificate Expires in {} Days", days),
                    format!(
                        "The certificate expires on {}.",
                        tr.cert_not_after.as_deref().unwrap_or("?")
                    ),
                ));
            }
        }

        if let Some(dane) = &tr.dane_status {
            let ok = dane.starts_with("match");
            checks.push(if ok {
                CheckItem {
                    technical_details: fingerprint,
                    ..CheckItem::new("DANE_MATCH", "TLS", Severity::Pass, "DANE TLSA Record Matches the Certificate", format!("The presented certificate chain matches a published TLSA record: {}.", dane))
                }
            } else {
                CheckItem {
                    technical_details: fingerprint,
                    ..CheckItem::new("DANE_MISMATCH", "TLS", Severity::Critical, "DANE TLSA Record Does Not Match the Certificate", "None of the published TLSA records match the certificate this server presented. DANE-enabled senders (Postfix, Exim, Microsoft 365) will defer mail to this server.")
                        .fix("Publish TLSA records for the new key before rotating certificates (keep old and new during the changeover), or update the TLSA record now.")
                }
            });
        }
    }

    pub fn extract_ehlo_capability(line: &str) -> &str {
        let b = line.as_bytes();
        if b.len() >= 4
            && b[0].is_ascii_digit()
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
            && (b[3] == b'-' || b[3] == b' ')
        {
            line[4..].trim()
        } else if b.len() == 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2].is_ascii_digit() {
            ""
        } else {
            line.trim()
        }
    }

    pub fn parse_smtp_status_code(line: &str) -> Option<(u16, bool)> {
        let b = line.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2].is_ascii_digit() {
            let code = ((b[0] - b'0') as u16) * 100 + ((b[1] - b'0') as u16) * 10 + ((b[2] - b'0') as u16);
            let is_final = b.len() == 3 || b[3] == b' ';
            Some((code, is_final))
        } else {
            None
        }
    }

    pub fn parse_ehlo_extensions(
        &self,
        lines: &[String],
        report: &mut SmtpReport,
        checks: &mut Vec<CheckItem>,
        post_tls: bool,
    ) {
        for line in lines.iter().skip(1) {
            let cap_str = Self::extract_ehlo_capability(line);
            let cap = cap_str.to_uppercase();
            if cap.is_empty() {
                continue;
            }

            if !report.capabilities.contains(&cap) {
                report.capabilities.push(cap.clone());
            }

            if cap.starts_with("STARTTLS") && !post_tls {
                report.starttls_advertised = true;
            }

            if cap.starts_with("SIZE") {
                let parts: Vec<&str> = cap.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(bytes) = parts[1].parse::<u64>() {
                        report.max_message_size_bytes = Some(bytes);
                    }
                }
            }

            if cap.starts_with("PIPELINING") {
                report.pipelining_supported = true;
            }

            if cap.starts_with("CHUNKING") || cap.starts_with("BDAT") {
                report.chunking_supported = true;
            }

            if cap.starts_with("SMTPUTF8") {
                report.smtputf8_supported = true;
            }

            if cap.starts_with("AUTH") {
                let parts: Vec<&str> = cap.split_whitespace().skip(1).collect();
                for &p in &parts {
                    let p_str = p.to_string();
                    if !report.auth_mechanisms.contains(&p_str) {
                        report.auth_mechanisms.push(p_str);
                    }
                }

                if !post_tls && !report.plaintext_auth_offered {
                    report.plaintext_auth_offered = true;
                    report.anomalies.push(MisbehaviorAnomaly::new("INSECURE_PLAINTEXT_AUTH", Severity::Warning, "RFC 4954 §4", "Authentication Advertised Over Unencrypted Connection", "Server advertises AUTH mechanisms over cleartext port 25 without TLS. User passwords could be transmitted in plaintext.", cap.clone()));
                    checks.push(CheckItem::new("SECURITY_PLAINTEXT_AUTH", "SECURITY", Severity::Warning, "Insecure Plaintext AUTH Advertised", format!("Server advertises AUTH ({:?}) over unencrypted plaintext.", report.auth_mechanisms)).fix("Configure the MTA to only offer authentication mechanisms after STARTTLS encryption has been established."));
                }
            }
        }

        if !post_tls {
            if let Some(size_mb) = report.max_size_mb() {
                if size_mb < 5.0 {
                    report.anomalies.push(MisbehaviorAnomaly::new(
                        "ABNORMALLY_LOW_SIZE_LIMIT",
                        Severity::Warning,
                        "RFC 1870",
                        format!("Abnormally Low Message Size Limit ({:.1} MB)", size_mb),
                        "Most modern email messages with attachments require at least 10-25 MB size limits.",
                        format!("{:.1} MB", size_mb),
                    ));
                }

                checks.push(CheckItem::new(
                    "SMTP_MAX_SIZE",
                    "SMTP",
                    if size_mb >= 10.0 {
                        Severity::Pass
                    } else {
                        Severity::Notice
                    },
                    format!("Advertised Max Message Size: {:.1} MB", size_mb),
                    format!("Server advertises SIZE limit of {:.1} MB.", size_mb),
                ));
            }

            if report.pipelining_supported {
                checks.push(CheckItem::new(
                    "SMTP_PIPELINING_OK",
                    "SMTP",
                    Severity::Pass,
                    "RFC 2920 Command Pipelining Supported",
                    "Server supports PIPELINING for fast parallel command execution.",
                ));
            }
        }
    }

    fn probe_null_sender(&self, conn: &mut SmtpConn, report: &mut SmtpReport, checks: &mut Vec<CheckItem>) {
        let Ok((code, lines, _)) = Self::command(conn, "MAIL FROM:<>", report) else {
            return;
        };
        if code == 250 || code == 251 {
            report.null_sender_accepted = Some(true);
            checks.push(CheckItem::new(
                "BEHAVIOR_NULL_SENDER_OK",
                "BEHAVIOR",
                Severity::Pass,
                "RFC 5321 Null Reverse-Path (<>) Accepted",
                "Server correctly accepts 'MAIL FROM:<>' for bounce and Delivery Status Notifications.",
            ));
        } else if (500..600).contains(&code) {
            report.null_sender_accepted = Some(false);
            report.anomalies.push(MisbehaviorAnomaly::new("REJECTS_NULL_SENDER", Severity::Critical, "RFC 5321 §3.6", "RFC 5321 §3.6 Violation: Rejects Null Reverse-Path (MAIL FROM:<>)", "Compliant SMTP servers MUST accept MAIL FROM:<>. Rejecting null senders breaks standard NDR delivery bounces and causes delivery loops.", lines.join(" ")));
            checks.push(
                CheckItem::new(
                    "BEHAVIOR_NULL_SENDER_REJECTED",
                    "BEHAVIOR",
                    Severity::Critical,
                    "Rejects Null Sender (MAIL FROM:<>)",
                    format!(
                        "Server rejected 'MAIL FROM:<>' with code {}: '{}'. This breaks RFC 5321 bounce handling.",
                        code,
                        lines.join(" ")
                    ),
                )
                .fix("Configure your MTA to accept null senders (<>) as required by RFC 5321 §3.6."),
            );
        }
        let _ = Self::command(conn, "RSET", report);
    }

    /// RFC 5321 §4.5.1 requires postmaster@ to exist. A temporary failure here on first
    /// contact is the usual sign of greylisting. A random address being accepted too
    /// means the server takes mail for any address.
    fn probe_postmaster_and_catch_all(
        &self,
        conn: &mut SmtpConn,
        domain: &str,
        report: &mut SmtpReport,
        checks: &mut Vec<CheckItem>,
    ) {
        let from = if report.null_sender_accepted == Some(true) {
            "MAIL FROM:<>".to_string()
        } else {
            format!("MAIL FROM:<probe@{}>", self.client_fqdn)
        };
        match Self::command(conn, &from, report) {
            Ok((250, _, _)) => {}
            _ => {
                let _ = Self::command(conn, "RSET", report);
                return;
            }
        }

        let Ok((code, lines, _)) = Self::command(conn, &format!("RCPT TO:<postmaster@{}>", domain), report) else {
            return;
        };
        let resp = lines.join(" ");
        report.postmaster_response = Some(resp.clone());
        match code {
            250 | 251 => {
                report.postmaster_accepted = Some(true);
                checks.push(CheckItem::new(
                    "SMTP_POSTMASTER_OK",
                    "SMTP",
                    Severity::Pass,
                    "postmaster@ Mailbox Accepted",
                    format!(
                        "Server accepts mail for postmaster@{} as RFC 5321 §4.5.1 requires.",
                        domain
                    ),
                ));
            }
            421 | 450 | 451 | 452 => {
                report.greylisting_suspected = true;
                checks.push(CheckItem::new("SMTP_GREYLISTING", "BEHAVIOR", Severity::Notice, "Greylisting Suspected (Temporary Rejection on First Contact)", format!("A recipient that must exist was deferred with {}: '{}'. Legitimate senders retry, but first-time mail from a new sender is delayed (often 5-15 minutes); one-time codes and password resets may arrive late.", code, resp)).fix("If delays are a problem, whitelist large senders (Google, Microsoft, Amazon SES) or shorten the greylist delay."));
            }
            _ => {
                report.postmaster_accepted = Some(false);
                checks.push(CheckItem::new("SMTP_POSTMASTER_REJECTED", "SMTP", Severity::Warning, "postmaster@ Mailbox Rejected", format!("Server rejected postmaster@{} with {}: '{}'. RFC 5321 §4.5.1 requires every mail domain to accept mail for postmaster, and abuse reports and blocklist delisting requests go there.", domain, code, resp)).fix("Create a postmaster alias pointing at a monitored mailbox."));
            }
        }

        if report.postmaster_accepted == Some(true) {
            let random_local = format!(
                "mxd-nonexistent-{:x}",
                Utc::now().timestamp_subsec_nanos() ^ 0x5eed_c0de
            );
            if let Ok((code, lines, _)) = Self::command(conn, &format!("RCPT TO:<{}@{}>", random_local, domain), report)
            {
                let accepted = code == 250 || code == 251;
                report.catch_all_detected = Some(accepted);
                if accepted {
                    checks.push(CheckItem::new("SMTP_CATCH_ALL", "BEHAVIOR", Severity::Notice, "Accepts Mail for Non-existent Addresses (Catch-all)", format!("A made-up address ({}@{}) was accepted: '{}'. Either the domain has a catch-all, or the server checks recipients only after accepting the message, which produces backscatter bounces to forged senders.", random_local, domain, lines.join(" "))).fix("Reject unknown recipients at RCPT time (recipient verification / directory-based edge blocking)."));
                } else if (500..600).contains(&code) {
                    checks.push(CheckItem::new("SMTP_UNKNOWN_RCPT_REJECTED", "BEHAVIOR", Severity::Pass, "Unknown Recipients Rejected at RCPT Time", "A made-up address was rejected during the SMTP dialogue, so no backscatter bounces are generated."));
                }
            }
        }
        let _ = Self::command(conn, "RSET", report);
    }

    fn probe_open_relay(&self, conn: &mut SmtpConn, report: &mut SmtpReport, checks: &mut Vec<CheckItem>) {
        let from_ok = matches!(
            Self::command(conn, "MAIL FROM:<probe@diagnostic-probe.invalid>", report),
            Ok((250, _, _))
        ) || {
            let _ = Self::command(conn, "RSET", report);
            matches!(Self::command(conn, "MAIL FROM:<>", report), Ok((250, _, _)))
        };
        if !from_ok {
            let _ = Self::command(conn, "RSET", report);
            return;
        }
        report.open_relay_tested = true;
        let Ok((code, lines, _)) = Self::command(conn, "RCPT TO:<relay-test@example.net>", report) else {
            return;
        };
        let resp_str = lines.join(" ");
        report.open_relay_response = Some(resp_str.clone());

        if code == 250 || code == 251 {
            report.open_relay_detected = true;
            report.anomalies.push(MisbehaviorAnomaly::new("OPEN_RELAY_VULNERABILITY", Severity::Critical, "RFC 5321 §3.9", "Open Mail Relay", "Server accepted a non-local recipient without authentication. Spammers will find and abuse it, and its IP will land on blocklists.", resp_str.clone()));
            checks.push(
                CheckItem::new(
                    "SECURITY_OPEN_RELAY",
                    "SECURITY",
                    Severity::Critical,
                    "Open Mail Relay",
                    format!(
                        "Server accepted an external recipient without authentication. Response: '{}'",
                        resp_str
                    ),
                )
                .fix("Restrict relaying to authenticated users and trusted internal networks."),
            );
        } else if (400..600).contains(&code) {
            checks.push(CheckItem::new(
                "SECURITY_RELAY_DENIED",
                "SECURITY",
                Severity::Pass,
                "Relay Access Denied",
                format!(
                    "Server rejected unauthenticated relaying to an external domain (code {}).",
                    code
                ),
            ));
        }
        let _ = Self::command(conn, "RSET", report);
    }

    fn probe_recipient(
        &self,
        conn: &mut SmtpConn,
        recipient: &str,
        report: &mut SmtpReport,
        checks: &mut Vec<CheckItem>,
    ) {
        let domain = recipient.split('@').nth(1).unwrap_or("example.com");
        let _ = Self::command(conn, &format!("MAIL FROM:<probe@{}>", domain), report);
        let Ok((code, lines, _)) = Self::command(conn, &format!("RCPT TO:<{}>", recipient), report) else {
            return;
        };
        let resp = lines.join(" ");
        report.recipient_response = Some(resp.clone());

        if code == 250 || code == 251 {
            report.recipient_accepted = Some(true);
            checks.push(CheckItem::new(
                "RECIPIENT_ACCEPTED",
                "SMTP",
                Severity::Pass,
                format!("Recipient Mailbox Accepted ({})", recipient),
                format!("Server accepted recipient <{}>: '{}'", recipient, resp),
            ));
        } else if code == 450 || code == 451 || code == 452 {
            report.recipient_accepted = None;
            checks.push(CheckItem::new(
                "RECIPIENT_GREYLISTED",
                "SMTP",
                Severity::Notice,
                format!("Recipient Deferred / Greylisted ({})", recipient),
                format!(
                    "Server deferred recipient <{}> with temporary code {}: '{}'",
                    recipient, code, resp
                ),
            ));
        } else {
            report.recipient_accepted = Some(false);
            checks.push(CheckItem::new(
                "RECIPIENT_REJECTED",
                "SMTP",
                Severity::Warning,
                format!("Recipient Rejected ({})", recipient),
                format!(
                    "Server rejected recipient <{}> with code {}: '{}'",
                    recipient, code, resp
                ),
            ));
        }
        let _ = Self::command(conn, "RSET", report);
    }

    /// VRFY and EXPN let anyone confirm addresses or read mailing-list members.
    /// 252 ("cannot verify, will accept") is the safe answer RFC 5321 §3.5.3 suggests.
    fn probe_vrfy_expn(&self, conn: &mut SmtpConn, report: &mut SmtpReport, checks: &mut Vec<CheckItem>) {
        for verb in ["VRFY", "EXPN"] {
            let Ok((code, lines, _)) = Self::command(conn, &format!("{} postmaster", verb), report) else {
                return;
            };
            let resp = lines.join(" ");
            if verb == "VRFY" {
                report.vrfy_response = Some(resp.clone());
            } else {
                report.expn_response = Some(resp.clone());
            }
            if code == 250 || code == 251 {
                checks.push(
                    CheckItem::new(
                        format!("SECURITY_{}_ENABLED", verb),
                        "SECURITY",
                        Severity::Notice,
                        format!("{} Reveals Mailbox Information", verb),
                        format!(
                            "'{} postmaster' returned {}: '{}'. Spammers use this to harvest valid addresses{}.",
                            verb,
                            code,
                            resp,
                            if verb == "EXPN" { " and list members" } else { "" }
                        ),
                    )
                    .fix(format!(
                        "Disable {} (Postfix: disable_vrfy_command = yes) or answer 252.",
                        verb
                    )),
                );
            }
        }
    }

    fn command(conn: &mut SmtpConn, cmd: &str, report: &mut SmtpReport) -> Result<Reply, String> {
        Self::log(report, "->", cmd);
        if let Err(e) = conn
            .transport
            .write_all(format!("{}\r\n", cmd).as_bytes())
            .and_then(|_| conn.transport.flush())
        {
            conn.transport = Transport::Closed;
            return Err(e.to_string());
        }
        let r = Self::read_reply(conn, report);
        if r.is_err() {
            conn.transport = Transport::Closed;
        }
        r
    }

    fn read_reply(conn: &mut SmtpConn, report: &mut SmtpReport) -> Result<Reply, String> {
        let mut lines = Vec::new();
        let mut all_crlf_valid = true;
        let secure = conn.is_tls();
        loop {
            let raw = match conn.read_line()? {
                Some(l) => l,
                None => {
                    return Err(if secure {
                        "TLS stream closed unexpectedly"
                    } else {
                        "Connection closed unexpectedly by server"
                    }
                    .to_string());
                }
            };
            if !raw.ends_with(b"\r\n") {
                all_crlf_valid = false;
            }
            let text = String::from_utf8_lossy(&raw);
            let trimmed = text.trim_end_matches(['\r', '\n']).to_string();
            Self::log(report, "<-", &trimmed);
            lines.push(trimmed.clone());

            match Self::parse_smtp_status_code(&trimmed) {
                Some((code, true)) => return Ok((code, lines, all_crlf_valid)),
                Some((_, false)) => {}
                None => {
                    report.multiline_format_valid = false;
                }
            }
            if lines.len() > MAX_REPLY_LINES {
                return Err(format!("reply exceeded {} lines without a final line", MAX_REPLY_LINES));
            }
        }
    }

    fn log(report: &mut SmtpReport, direction: &str, text: &str) {
        report.transcript.push(TranscriptEntry {
            direction: direction.to_string(),
            timestamp: Utc::now().format("%H:%M:%S%.3f").to_string(),
            text: text.to_string(),
        });
    }
}
