use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256, Sha512};

use crate::models::{TlsReport, TlsaRecord};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn root_store() -> Arc<RootCertStore> {
    Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

/// Runs normal WebPKI verification and remembers the outcome, but lets the handshake
/// finish either way. MX servers are reached with opportunistic TLS, so an untrusted
/// certificate is a finding to report, not a reason to stop looking at the server.
#[derive(Debug)]
pub struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    outcome: Mutex<Option<Result<(), String>>>,
}

impl RecordingVerifier {
    pub fn new() -> Result<Arc<Self>, String> {
        let inner = WebPkiServerVerifier::builder_with_provider(root_store(), provider())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            inner,
            outcome: Mutex::new(None),
        }))
    }

    pub fn outcome(&self) -> Option<Result<(), String>> {
        self.outcome.lock().ok().and_then(|o| o.clone())
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map(|_| ())
            .map_err(|e| describe_verify_error(&e));
        if let Ok(mut slot) = self.outcome.lock() {
            *slot = Some(result);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn describe_verify_error(e: &rustls::Error) -> String {
    const PLAIN: [(&str, &str); 9] = [
        ("Expired", "certificate has expired"),
        ("NotValidYet", "certificate is not valid yet"),
        ("CaUsedAsEndEntity", "certificate is self-signed"),
        (
            "UnknownIssuer",
            "certificate is self-signed or from an untrusted CA (or the intermediate chain is missing)",
        ),
        ("NotValidForName", "certificate does not cover this hostname"),
        ("Revoked", "certificate has been revoked"),
        (
            "InvalidPurpose",
            "certificate is not valid for TLS server authentication",
        ),
        ("BadSignature", "certificate signature is invalid"),
        ("BadEncoding", "certificate is malformed"),
    ];
    let rustls::Error::InvalidCertificate(ce) = e else {
        return e.to_string();
    };
    let dbg = format!("{:?}", ce);
    PLAIN
        .iter()
        .find(|(key, _)| dbg.contains(key))
        .map(|(_, plain)| plain.to_string())
        .unwrap_or_else(|| format!("certificate rejected: {}", dbg))
}

/// Config for probing MX servers: records trust instead of enforcing it.
pub fn recording_config(verifier: Arc<RecordingVerifier>) -> Result<Arc<ClientConfig>, String> {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Config that enforces trust, as a real MTA-STS sender would when fetching the policy.
pub fn strict_config() -> Result<Arc<ClientConfig>, String> {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(root_store())
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.trim_end_matches('.').to_string())
        .map_err(|e| format!("invalid TLS server name '{}': {}", host, e))
}

/// Drives a handshake to completion on a blocking socket.
pub fn complete_handshake(conn: &mut ClientConnection, sock: &mut TcpStream) -> Result<(), String> {
    while conn.is_handshaking() {
        conn.complete_io(sock).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Builds a report from the negotiated session and the certificate actually presented.
pub fn inspect_session(
    conn: &ClientConnection,
    host: &str,
    port: u16,
    verify: Option<Result<(), String>>,
    tlsa: &[TlsaRecord],
) -> TlsReport {
    let mut report = TlsReport {
        host: host.to_string(),
        port,
        starttls_attempted: true,
        handshake_success: true,
        ..Default::default()
    };

    report.tls_version = conn.protocol_version().map(|v| match format!("{:?}", v).as_str() {
        "TLSv1_3" => "TLS 1.3".to_string(),
        "TLSv1_2" => "TLS 1.2".to_string(),
        other => other.replace('_', "."),
    });
    report.cipher_name = conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite()));

    let chain: Vec<Vec<u8>> = conn
        .peer_certificates()
        .map(|c| c.iter().map(|d| d.as_ref().to_vec()).collect())
        .unwrap_or_default();
    report.chain_length = chain.len();

    match verify {
        Some(Ok(())) => report.chain_verified = true,
        Some(Err(e)) => report.verify_error = Some(e),
        None => report.verify_error = Some("certificate was not verified".to_string()),
    }

    if let Some(leaf) = chain.first() {
        report.cert_sha256 = Some(hex(&Sha256::digest(leaf)));
        fill_cert_fields(&mut report, leaf, host);
    }

    if !tlsa.is_empty() {
        report.dane_status = Some(match dane_match(tlsa, &chain) {
            Some(rec) => format!("match (TLSA {} {} {})", rec.usage, rec.selector, rec.matching_type),
            None => "no TLSA record matches the presented certificate chain".to_string(),
        });
    }

    report
}

fn fill_cert_fields(report: &mut TlsReport, der: &[u8], host: &str) {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        report.error_message = Some("could not parse the server certificate".to_string());
        return;
    };

    report.cert_subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let issuer = cert.issuer();
    report.cert_issuer = issuer
        .iter_organization()
        .next()
        .and_then(|o| o.as_str().ok())
        .map(|o| {
            let cn = issuer.iter_common_name().next().and_then(|c| c.as_str().ok());
            match cn {
                Some(cn) if cn != o => format!("{} ({})", o, cn),
                _ => o.to_string(),
            }
        })
        .or_else(|| Some(issuer.to_string()));

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = name {
                report.cert_sans.push(d.to_string());
            }
        }
    }
    let names: Vec<&str> = if report.cert_sans.is_empty() {
        report.cert_subject_cn.iter().map(|s| s.as_str()).collect()
    } else {
        report.cert_sans.iter().map(|s| s.as_str()).collect()
    };
    report.cert_san_matches_host = names.iter().any(|n| hostname_matches(n, host));

    let validity = cert.validity();
    report.cert_not_before = Some(validity.not_before.to_string());
    report.cert_not_after = Some(validity.not_after.to_string());
    let now = chrono::Utc::now().timestamp();
    let left = (validity.not_after.timestamp() - now).div_euclid(86_400);
    report.cert_days_left = Some(left);
    report.cert_is_expired = validity.not_after.timestamp() < now;
}

/// Matches a certificate or MTA-STS name pattern against a hostname. A leading
/// "*." matches exactly one label, as RFC 6125 and RFC 8461 §4.1 require.
pub fn hostname_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        match h.split_once('.') {
            Some((first, rest)) => !first.is_empty() && rest == suffix,
            None => false,
        }
    } else {
        p == h
    }
}

/// RFC 6698 / RFC 7672 matching. Usages 1 and 3 (end-entity) are checked against the
/// leaf; usages 0 and 2 (trust anchor) against any certificate the server sent.
pub fn dane_match<'a>(records: &'a [TlsaRecord], chain: &[Vec<u8>]) -> Option<&'a TlsaRecord> {
    records.iter().find(|rec| {
        let candidates: Vec<&Vec<u8>> = match rec.usage {
            1 | 3 => chain.first().into_iter().collect(),
            0 | 2 => chain.iter().collect(),
            _ => Vec::new(),
        };
        candidates.iter().any(|der| {
            let material: Vec<u8> = match rec.selector {
                0 => der.to_vec(),
                1 => match x509_parser::parse_x509_certificate(der) {
                    Ok((_, c)) => c.public_key().raw.to_vec(),
                    Err(_) => return false,
                },
                _ => return false,
            };
            let digest = match rec.matching_type {
                0 => material,
                1 => Sha256::digest(&material).to_vec(),
                2 => Sha512::digest(&material).to_vec(),
                _ => return false,
            };
            hex(&digest).eq_ignore_ascii_case(&rec.data_hex)
        })
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

const MAX_HTTP_BODY: usize = 64 * 1024;

/// Minimal HTTPS GET with full certificate checks and no redirects (RFC 8461 §3.3
/// forbids following them). Returns status, Content-Type and body.
pub fn https_get(host: &str, path: &str, timeout: Duration) -> Result<(u16, Option<String>, String), String> {
    let addr: SocketAddr = format!("{}:443", host)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {}", host, e))?
        .next()
        .ok_or_else(|| format!("{} has no address", host))?;
    let mut sock =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("cannot connect to {}:443: {}", host, e))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let mut conn = ClientConnection::new(strict_config()?, server_name(host)?).map_err(|e| e.to_string())?;
    complete_handshake(&mut conn, &mut sock).map_err(|e| format!("TLS to {} failed: {}", host, e))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mx-detective/{}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
        path,
        host,
        env!("CARGO_PKG_VERSION")
    );
    tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_HTTP_BODY + 16 * 1024 {
                    return Err("response too large".to_string());
                }
            }
            // Many servers close without close_notify; keep what arrived.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    parse_http_response(&raw)
}

pub fn parse_http_response(raw: &[u8]) -> Result<(u16, Option<String>, String), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("malformed HTTP response (no header end)")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];

    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or("malformed HTTP status line")?;

    let mut content_type = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            if k == "content-type" {
                content_type = Some(v.trim().to_string());
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }

    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    let body = &body[..body.len().min(MAX_HTTP_BODY)];
    Ok((status, content_type, String::from_utf8_lossy(body).into_owned()))
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated chunk header")?;
        let size_str = String::from_utf8_lossy(&data[..eol]);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| "bad chunk size")?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > data.len() || out.len() + size > MAX_HTTP_BODY {
            return Err("chunk exceeds response".to_string());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        data = data.strip_prefix(b"\r\n").unwrap_or(data);
    }
}
