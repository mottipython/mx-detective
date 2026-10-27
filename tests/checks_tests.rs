use mx_detective::diagnose::merge_checks;
use mx_detective::dns::{
    reverse_name, same_organization, DnsResolver, RData, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_TLSA,
};
use mx_detective::models::{CheckItem, MtaStsReport, Severity, TlsaRecord};
use mx_detective::policy::parse_mta_sts_policy;
use mx_detective::tls::{dane_match, hex, hostname_matches, parse_http_response};
use sha2::{Digest, Sha256};

#[test]
fn wildcard_matches_exactly_one_label() {
    assert!(hostname_matches("*.example.com", "mx1.example.com"));
    assert!(hostname_matches("MX.Example.COM.", "mx.example.com"));
    assert!(!hostname_matches("*.example.com", "example.com"));
    assert!(!hostname_matches("*.example.com", "a.b.example.com"));
    assert!(!hostname_matches("*.example.com", "mx1.example.org"));
}

#[test]
fn dane_matches_full_certificate_digest() {
    let leaf = b"leaf certificate bytes".to_vec();
    let ca = b"issuer certificate bytes".to_vec();
    let rec = |usage, data: &[u8]| TlsaRecord {
        usage,
        selector: 0,
        matching_type: 1,
        data_hex: hex(&Sha256::digest(data)),
    };
    let chain = vec![leaf.clone(), ca.clone()];

    assert!(dane_match(&[rec(3, &leaf)], &chain).is_some());
    assert!(
        dane_match(&[rec(2, &ca)], &chain).is_some(),
        "DANE-TA matches any cert in the chain"
    );
    assert!(
        dane_match(&[rec(3, &ca)], &chain).is_none(),
        "DANE-EE only matches the leaf"
    );
    assert!(dane_match(&[rec(3, b"other")], &chain).is_none());

    let exact = TlsaRecord {
        usage: 3,
        selector: 0,
        matching_type: 0,
        data_hex: hex(&leaf).to_uppercase(),
    };
    assert!(dane_match(&[exact], &chain).is_some(), "hex comparison ignores case");
}

#[test]
fn http_response_plain_and_chunked() {
    let plain = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nversion: STSv1\r\n";
    let (status, ct, body) = parse_http_response(plain).unwrap();
    assert_eq!((status, ct.as_deref()), (200, Some("text/plain")));
    assert_eq!(body, "version: STSv1\r\n");

    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nmode\r\n7\r\n: test\n\r\n0\r\n\r\n";
    assert_eq!(parse_http_response(chunked).unwrap().2, "mode: test\n");

    assert!(parse_http_response(b"garbage").is_err());
    assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err());
    assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffff\r\nab").is_err());
}

#[test]
fn mta_sts_policy_parsing() {
    let mut sts = MtaStsReport::default();
    let v = parse_mta_sts_policy(
        "version: STSv1\nmode: Enforce\nmx: mx1.example.com\nmx: *.example.net\nmax_age: 604800\n",
        &mut sts,
    );
    assert_eq!(v.as_deref(), Some("STSv1"));
    assert_eq!(sts.mode.as_deref(), Some("enforce"));
    assert_eq!(sts.mx_patterns, vec!["mx1.example.com", "*.example.net"]);
    assert_eq!(sts.max_age, Some(604800));
}

#[test]
fn spf_terms() {
    // "-all" must not be mistaken for the "a" mechanism (it used to be counted as a lookup).
    assert_eq!(DnsResolver::spf_term("-all"), ("all".into(), None));
    assert_eq!(DnsResolver::spf_term("a"), ("a".into(), None));
    assert_eq!(
        DnsResolver::spf_term("a:mail.example.com/24"),
        ("a".into(), Some("mail.example.com/24".into()))
    );
    assert_eq!(DnsResolver::spf_term("mx/24"), ("mx".into(), None));
    assert_eq!(
        DnsResolver::spf_term("~include:_spf.google.com"),
        ("include".into(), Some("_spf.google.com".into()))
    );
    assert_eq!(
        DnsResolver::spf_term("redirect=_spf.example.com"),
        ("redirect".into(), Some("_spf.example.com".into()))
    );
    assert_eq!(DnsResolver::spf_term("ip4:192.0.2.0/24").0, "ip4");
}

#[test]
fn reverse_names() {
    assert_eq!(reverse_name(&"192.0.2.10".parse().unwrap()), "10.2.0.192.in-addr.arpa");
    let v6 = reverse_name(&"2001:db8::1".parse().unwrap());
    assert!(v6.starts_with("1.0.0.0.0.0.0.0"));
    assert!(v6.ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    assert_eq!(v6.split('.').count(), 34);
}

#[test]
fn organization_comparison() {
    assert!(same_organization("example.com", "example.com"));
    assert!(same_organization("example.com", "reports.example.com"));
    assert!(!same_organization("example.com", "dmarc-vendor.net"));
    assert!(!same_organization("example.com", "badexample.com"));
}

/// Builds a response to `query` carrying one answer with a pointer to the question name.
fn answer(query: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut msg = query.to_vec();
    msg[2] |= 0x80; // QR
    msg[3] |= 0x20; // AD
    msg[7] = 1; // ANCOUNT
    msg[11] = 0; // drop the OPT record count
    let q_end = 12 + DnsResolver::skip_name(query, 12).unwrap() - 12 + 4;
    msg.truncate(q_end);
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x0E, 0x10]);
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(rdata);
    msg
}

#[test]
fn parses_tlsa_aaaa_and_cname_answers() {
    let q = DnsResolver::build_query("_25._tcp.mx.example.com", DNS_TYPE_TLSA, 0xBEEF).unwrap();
    let msg = DnsResolver::parse_message(&q).unwrap();
    assert_eq!(msg.id, 0xBEEF);

    let msg = DnsResolver::parse_message(&answer(&q, DNS_TYPE_TLSA, &[3, 1, 1, 0xAB, 0xCD])).unwrap();
    assert!(msg.authentic_data);
    assert_eq!(
        msg.answers[0].data,
        RData::Tlsa(TlsaRecord {
            usage: 3,
            selector: 1,
            matching_type: 1,
            data_hex: "abcd".into()
        })
    );
    assert_eq!(msg.answers[0].name, "_25._tcp.mx.example.com");

    let ip: std::net::Ipv6Addr = "2001:db8::25".parse().unwrap();
    let msg = DnsResolver::parse_message(&answer(&q, DNS_TYPE_AAAA, &ip.octets())).unwrap();
    assert_eq!(msg.answers[0].data, RData::Aaaa(ip));

    let msg = DnsResolver::parse_message(&answer(&q, DNS_TYPE_CNAME, &[0xC0, 0x0C])).unwrap();
    assert_eq!(msg.answers[0].data, RData::Cname("_25._tcp.mx.example.com".into()));
}

#[test]
fn merging_collapses_repeated_findings() {
    let c = |id: &str, sev| CheckItem::new(id, "TLS", sev, "t", "m");
    let merged = merge_checks(vec![
        ("a (1)".into(), vec![c("X", Severity::Warning), c("Y", Severity::Pass)]),
        ("b (2)".into(), vec![c("X", Severity::Warning)]),
    ]);
    assert_eq!(merged.len(), 2);
    assert!(merged[0].message.ends_with("[all 2 servers tested]"));
    assert!(merged[1].message.contains("1 of 2 servers: a (1)"));

    let single = merge_checks(vec![("a".into(), vec![c("X", Severity::Pass)])]);
    assert_eq!(single[0].message, "m", "a single server adds no suffix");
}

#[test]
fn dkim_key_strength() {
    use mx_detective::models::DkimKey;
    // Lengths of real base64 SPKI keys: 1024-bit ≈ 216 chars, 2048-bit ≈ 392.
    let key = |chars: usize| format!("v=DKIM1; k=rsa; p={}", "A".repeat(chars));
    assert_eq!(DkimKey::parse("s", key(216)).approx_bits, Some(1024));
    assert_eq!(DkimKey::parse("s", key(392)).approx_bits, Some(2048));
    assert_eq!(DkimKey::parse("s", key(120)).approx_bits, Some(512));
    assert!(DkimKey::parse("s", "v=DKIM1; p=".into()).revoked);
    let ed = DkimKey::parse(
        "s",
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
    );
    assert_eq!((ed.key_type.as_str(), ed.approx_bits), ("ed25519", None));
}

fn sample_result() -> mx_detective::models::DiagnosticResult {
    use mx_detective::models::{DiagnosticResult, ServerResult};
    let mut r = DiagnosticResult::new("example.com".into(), None);
    r.checks.push(CheckItem::new(
        "TLS_X",
        "TLS",
        Severity::Critical,
        "T\u{2014}itle \u{1f575}",
        "RFC 5321 \u{a7}4.2 \u{4e2d}",
    ));
    r.checks
        .push(CheckItem::new("DNS_Y", "DNS", Severity::Warning, "t", "m"));
    r.checks.push(CheckItem::new("OK", "DNS", Severity::Pass, "t", "m"));
    let mut server = ServerResult::default();
    server.smtp.connected = true;
    server.smtp.banner = Some("220 m\u{e9}l.example caf\u{e9} \u{1f600}".into());
    r.servers.push(server);
    r.calculate_score();
    r
}

#[test]
fn summary_keys_match_their_documentation() {
    use mx_detective::summary::{get, pairs, to_text, KEYS};
    let r = sample_result();
    let p = pairs(&r);
    assert_eq!(p.len(), KEYS.len(), "every documented key needs a value");
    for ((key, value), (doc_key, _)) in p.iter().zip(KEYS) {
        assert_eq!(key, doc_key);
        assert!(
            !value.contains(char::is_whitespace),
            "{key} has whitespace in {value:?}"
        );
    }
    assert_eq!(get(&r, "critical").as_deref(), Some("1"));
    assert_eq!(get(&r, "warning").as_deref(), Some("1"));
    assert_eq!(get(&r, "critical_ids").as_deref(), Some("TLS_X"));
    assert_eq!(get(&r, "servers_reachable").as_deref(), Some("1"));
    assert_eq!(
        get(&r, "mta_sts").as_deref(),
        Some("missing"),
        "no DNS data means missing, not a crash"
    );
    assert_eq!(get(&r, "nonsense"), None);
    assert!(to_text(&r).starts_with("domain=example.com\ntool_version="));
}

#[test]
fn text_report_and_json_are_pure_ascii() {
    use mx_detective::reporter::DiagnosticReporter;
    let r = sample_result();
    let text = DiagnosticReporter::to_text(&r);
    assert!(text.is_ascii(), "text report must survive any console code page");
    assert!(text.contains("RFC 5321 sec. 4.2"));
    assert!(text.contains("[CRITICAL]"));

    let json = DiagnosticReporter::to_json(&r);
    assert!(json.is_ascii());
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        parsed["checks"][0]["title"], "T\u{2014}itle \u{1f575}",
        "escapes decode back to the original text"
    );
    assert_eq!(
        parsed["servers"][0]["smtp"]["banner"],
        "220 m\u{e9}l.example caf\u{e9} \u{1f600}"
    );
}

#[test]
fn a_saved_json_result_loads_as_a_baseline() {
    use mx_detective::diff::{compare, parse_baseline};
    use mx_detective::models::DiagnosticResult;
    use mx_detective::reporter::DiagnosticReporter;

    let mut old = DiagnosticResult::new("example.com".into(), None);
    old.checks = vec![CheckItem::new("SPF", "DNS", Severity::Notice, "t", "m")];
    let mut new = old.clone();
    new.checks[0].severity = Severity::Critical;

    let loaded = parse_baseline(&DiagnosticReporter::to_json(&old)).unwrap();
    let diff = compare(&loaded, &new, &[]).unwrap();
    assert_eq!(diff.changes.len(), 1);
    assert!(DiagnosticReporter::to_json_with_diff(&new, &diff).contains("\"diff\""));
    assert!(parse_baseline("{\"not\": \"a result\"}").is_err());
}
