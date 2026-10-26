use mx_detective::dns::DnsResolver;
use mx_detective::models::{
    CheckItem, DiagnosticResult, DnsReport, MisbehaviorAnomaly, MxHost, PortProbe, Severity, SmtpReport,
    TranscriptEntry,
};
use mx_detective::reporter::DiagnosticReporter;
use mx_detective::smtp::SmtpProber;
use std::time::Duration;

/// Simple fast reproducible 64-bit XorShift PRNG for zero-dependency fuzzing
struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdeadbeefcafebabe } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u64() as usize) % max
        }
    }

    fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (self.next_u32() & 0xFF) as u8;
        }
        buf
    }

    fn random_string_up_to(&mut self, max: usize) -> String {
        let len = self.next_usize(max);
        let chars =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.;= <>/\"'\\!@#$%^&*()[]{}:,?\r\n\0\t";
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = self.next_usize(chars.len());
            s.push(chars[idx] as char);
        }
        s
    }

    fn random_unicode_string_up_to(&mut self, max_chars: usize) -> String {
        let char_count = self.next_usize(max_chars);
        let sample = [
            "a",
            "B",
            "1",
            "-",
            "_",
            ".",
            ";",
            "=",
            " ",
            "\t",
            "\r",
            "\n",
            "\0",
            "é",
            "ñ",
            "ü",
            "ø",
            "ß",
            "ç",
            "å", // 2-byte UTF-8
            "€",
            "漢",
            "字",
            "안",
            "녕",
            "하",
            "세",
            "요", // 3-byte UTF-8
            "🚀",
            "🔥",
            "✨",
            "🎉",
            "💀",
            "👾",
            "🛡️", // 4-byte UTF-8
            "<script>",
            "\"quotes\"",
            "'single'",
            "\\backslash",
            "&amp;",
            "|pipe|",
        ];
        let mut s = String::new();
        for _ in 0..char_count {
            let idx = self.next_usize(sample.len());
            s.push_str(sample[idx]);
        }
        s
    }
}

// =========================================================================
// 1. DNS Parser Fuzzing
// =========================================================================

#[test]
fn test_fuzz_dns_random_bytes() {
    let mut rng = FuzzRng::new(0x12345678_ABCDEF01);
    const ITERATIONS: usize = 100_000;

    for _ in 0..ITERATIONS {
        let len = rng.next_usize(1024);
        let buf = rng.random_bytes(len);

        let _ = DnsResolver::parse_mx_response(&buf);
        let _ = DnsResolver::parse_a_response(&buf);
        let _ = DnsResolver::parse_txt_response(&buf);
        let _ = DnsResolver::parse_ptr_response(&buf);

        if !buf.is_empty() {
            let offset = rng.next_usize(buf.len() + 5);
            let _ = DnsResolver::skip_name(&buf, offset);
            let _ = DnsResolver::read_name(&buf, offset);
        }
    }
}

#[test]
fn test_fuzz_dns_compression_pointer_loops() {
    // 1. Direct self-referencing pointer (offset 12 -> 12)
    let mut self_loop = vec![0u8; 16];
    self_loop[4] = 0;
    self_loop[5] = 0; // qdcount = 0
    self_loop[6] = 0;
    self_loop[7] = 1; // ancount = 1
    self_loop[12] = 0xC0;
    self_loop[13] = 0x0C; // Points to offset 12!

    assert!(DnsResolver::read_name(&self_loop, 12).is_err());
    assert!(DnsResolver::parse_mx_response(&self_loop).is_ok() || DnsResolver::parse_mx_response(&self_loop).is_err());

    // 2. Mutual 2-pointer loop (offset 12 -> 14, offset 14 -> 12)
    let mut mutual_loop = vec![0u8; 18];
    mutual_loop[12] = 0xC0;
    mutual_loop[13] = 0x0E; // points to 14
    mutual_loop[14] = 0xC0;
    mutual_loop[15] = 0x0C; // points to 12

    let res = DnsResolver::read_name(&mutual_loop, 12);
    assert!(res.is_err(), "Should detect circular pointer loop");

    // 3. Pointer jumping out of buffer bounds
    let mut oob_pointer = vec![0u8; 16];
    oob_pointer[12] = 0xC0;
    oob_pointer[13] = 0x80; // offset 128 in a 16-byte buffer

    assert!(DnsResolver::read_name(&oob_pointer, 12).is_err());

    // 4. Truncated pointer at very end of buffer
    let truncated_ptr = vec![0x03, b'f', b'o', b'o', 0xC0]; // missing 2nd byte
    assert!(DnsResolver::read_name(&truncated_ptr, 0).is_err());
    assert!(DnsResolver::skip_name(&truncated_ptr, 4).is_err());

    // 5. Reserved compression bits 0x40 and 0x80
    let reserved_bits = vec![0x40, 0x05];
    assert!(DnsResolver::read_name(&reserved_bits, 0).is_err());
    assert!(DnsResolver::skip_name(&reserved_bits, 0).is_err());

    // 6. Deep chain of 50 pointers
    let mut chain = vec![0u8; 120];
    for i in 0..50 {
        let off = i * 2;
        chain[off] = 0xC0;
        chain[off + 1] = (off + 2) as u8;
    }
    chain[100] = 0x00;
    assert!(DnsResolver::read_name(&chain, 0).is_err());
}

#[test]
fn test_fuzz_dns_mutated_packets() {
    let mut rng = FuzzRng::new(0xCAFEBABE_98765432);

    let base_packet = DnsResolver::build_dns_query_packet("mail.example.com", 15).unwrap();

    for _ in 0..50_000 {
        let mut mutated = base_packet.clone();

        let mutation_type = rng.next_usize(5);
        match mutation_type {
            0 => {
                let trunc_len = rng.next_usize(mutated.len());
                mutated.truncate(trunc_len);
            }
            1 => {
                if !mutated.is_empty() {
                    let pos = rng.next_usize(mutated.len());
                    let bit = 1 << rng.next_usize(8);
                    mutated[pos] ^= bit;
                }
            }
            2 => {
                if !mutated.is_empty() {
                    let pos = rng.next_usize(mutated.len());
                    let val = match rng.next_usize(4) {
                        0 => 0x00,
                        1 => 0xC0,
                        2 => 0xFF,
                        _ => (rng.next_u32() & 0xFF) as u8,
                    };
                    mutated[pos] = val;
                }
            }
            3 => {
                let extra_len = rng.next_usize(128);
                mutated.extend(rng.random_bytes(extra_len));
            }
            _ => {
                let pos = rng.next_usize(mutated.len() + 1);
                mutated.insert(pos, (rng.next_u32() & 0xFF) as u8);
            }
        }

        let _ = DnsResolver::parse_mx_response(&mutated);
        let _ = DnsResolver::parse_a_response(&mutated);
        let _ = DnsResolver::parse_txt_response(&mutated);
        let _ = DnsResolver::parse_ptr_response(&mutated);
    }
}

#[test]
fn test_fuzz_dns_record_parsers() {
    let mut rng = FuzzRng::new(0x456789AB_CDEF0123);

    for _ in 0..50_000 {
        let s = rng.random_unicode_string_up_to(20);
        let tags = DnsResolver::parse_dmarc_tags(&s);
        let _ = tags.get("p");
        let _ = tags.get("rua");
        let _ = tags.get("pct");
    }

    for _ in 0..50_000 {
        let s = rng.random_unicode_string_up_to(20);
        let mechs = DnsResolver::parse_spf_mechanisms(&s);
        for m in &mechs {
            let _ = m.ends_with("all");
            let _ = m.starts_with("include:");
        }
    }

    for _ in 0..5_000 {
        let domain = rng.random_unicode_string_up_to(30);
        let qtype = rng.next_u32() as u16;
        let _ = DnsResolver::build_dns_query_packet(&domain, qtype);
    }
}

// =========================================================================
// 2. SMTP Protocol & Status Code Fuzzing
// =========================================================================

#[test]
fn test_fuzz_smtp_status_code_parser() {
    let mut rng = FuzzRng::new(0x98765432_10FEDCBA);

    assert_eq!(SmtpProber::parse_smtp_status_code("250 OK"), Some((250, true)));
    assert_eq!(SmtpProber::parse_smtp_status_code("250-STARTTLS"), Some((250, false)));
    assert_eq!(SmtpProber::parse_smtp_status_code("250"), Some((250, true)));
    assert_eq!(
        SmtpProber::parse_smtp_status_code("550 User not found"),
        Some((550, true))
    );
    assert_eq!(
        SmtpProber::parse_smtp_status_code("220 mx.example.com ESMTP"),
        Some((220, true))
    );

    assert_eq!(SmtpProber::parse_smtp_status_code(""), None);
    assert_eq!(SmtpProber::parse_smtp_status_code("2"), None);
    assert_eq!(SmtpProber::parse_smtp_status_code("25"), None);
    assert_eq!(SmtpProber::parse_smtp_status_code("ABC OK"), None);
    assert_eq!(SmtpProber::parse_smtp_status_code("25A OK"), None);

    let tricky_inputs = [
        "€50", "🚀50", "漢50", "é50", "2€0", "25€", "🚀 250", "   250", "\t250", "\r\n250", "250\0OK", "250\r\n",
        "250-", "250 ",
    ];
    for input in &tricky_inputs {
        let _ = SmtpProber::parse_smtp_status_code(input);
    }

    for _ in 0..50_000 {
        let s = rng.random_unicode_string_up_to(25);
        let _ = SmtpProber::parse_smtp_status_code(&s);
    }
}

#[test]
fn test_fuzz_smtp_capability_extractor() {
    let mut rng = FuzzRng::new(0x55AA55AA_33CC33CC);

    assert_eq!(SmtpProber::extract_ehlo_capability("250-STARTTLS"), "STARTTLS");
    assert_eq!(SmtpProber::extract_ehlo_capability("250 STARTTLS"), "STARTTLS");
    assert_eq!(
        SmtpProber::extract_ehlo_capability("250-SIZE 52428800"),
        "SIZE 52428800"
    );
    assert_eq!(SmtpProber::extract_ehlo_capability("250-PIPELINING"), "PIPELINING");
    assert_eq!(SmtpProber::extract_ehlo_capability("STARTTLS"), "STARTTLS");
    assert_eq!(SmtpProber::extract_ehlo_capability("250"), "");

    for _ in 0..50_000 {
        let s = rng.random_unicode_string_up_to(30);
        let extracted = SmtpProber::extract_ehlo_capability(&s);
        let _ = extracted.to_uppercase();
    }
}

#[test]
fn test_fuzz_smtp_ehlo_extensions_parser() {
    let mut rng = FuzzRng::new(0xFEEDFACE_11223344);
    let prober = SmtpProber::new(Duration::from_secs(5));

    for _ in 0..50_000 {
        let line_count = rng.next_usize(15);
        let mut lines = Vec::new();

        lines.push(rng.random_unicode_string_up_to(20));

        for _ in 0..line_count {
            let choice = rng.next_usize(8);
            let line = match choice {
                0 => format!("250-STARTTLS {}", rng.random_string_up_to(5)),
                1 => format!(
                    "250-SIZE {}",
                    if rng.next_usize(2) == 0 {
                        rng.next_u64().to_string()
                    } else {
                        "invalid_number".to_string()
                    }
                ),
                2 => format!("250-AUTH {}", rng.random_string_up_to(20)),
                3 => "250-PIPELINING".to_string(),
                4 => "250-CHUNKING".to_string(),
                5 => "250-SMTPUTF8".to_string(),
                6 => rng.random_unicode_string_up_to(25),
                _ => format!("250 {}", rng.random_string_up_to(10)),
            };
            lines.push(line);
        }

        let mut report = SmtpReport {
            host: "mx.test".to_string(),
            port: 25,
            connected: true,
            connect_time_ms: 10.0,
            banner_time_ms: 20.0,
            banner_rfc_compliant: true,
            banner_has_fqdn: true,
            esmtp_supported: true,
            multiline_format_valid: true,
            ..Default::default()
        };

        let mut checks = Vec::new();
        prober.parse_ehlo_extensions(&lines, &mut report, &mut checks, false);
        prober.parse_ehlo_extensions(&lines, &mut report, &mut checks, true);
    }
}

// =========================================================================
// 3. Reporter & Format Serialization Fuzzing
// =========================================================================

#[test]
fn test_fuzz_reporter_all_formats() {
    let mut rng = FuzzRng::new(0x778899AA_BBCCDDEE);

    for _ in 0..1_000 {
        let domain = rng.random_unicode_string_up_to(25);
        let target = if rng.next_usize(2) == 0 {
            Some(rng.random_unicode_string_up_to(20))
        } else {
            None
        };

        let mut res = DiagnosticResult::new(domain, target);

        res.score = match rng.next_usize(6) {
            0 => 0,
            1 => 100,
            2 => 101,
            3 => -50,
            4 => rng.next_usize(101) as i32,
            _ => 69,
        };
        res.grade = rng.random_unicode_string_up_to(5);
        res.target_ip = if rng.next_usize(2) == 0 {
            Some(format!(
                "{}.{}.{}.{}",
                rng.next_usize(256),
                rng.next_usize(256),
                rng.next_usize(256),
                rng.next_usize(256)
            ))
        } else {
            None
        };

        let check_count = rng.next_usize(10);
        for _ in 0..check_count {
            let sev = match rng.next_usize(4) {
                0 => Severity::Pass,
                1 => Severity::Notice,
                2 => Severity::Warning,
                _ => Severity::Critical,
            };
            res.checks.push(CheckItem {
                check_id: rng.random_string_up_to(10),
                category: rng.random_unicode_string_up_to(8),
                title: rng.random_unicode_string_up_to(15),
                severity: sev,
                message: rng.random_unicode_string_up_to(30),
                recommendation: if rng.next_usize(2) == 0 {
                    Some(rng.random_unicode_string_up_to(25))
                } else {
                    None
                },
                technical_details: if rng.next_usize(2) == 0 {
                    Some(rng.random_unicode_string_up_to(25))
                } else {
                    None
                },
            });
        }

        let port_count = rng.next_usize(5);
        for _ in 0..port_count {
            let lat = match rng.next_usize(6) {
                0 => f64::NAN,
                1 => f64::INFINITY,
                2 => f64::NEG_INFINITY,
                3 => -12.5,
                4 => 0.0,
                _ => (rng.next_usize(5000) as f64) / 10.0,
            };
            res.port_probes.push(PortProbe {
                port: rng.next_u32() as u16,
                service: rng.random_unicode_string_up_to(8),
                reachable: rng.next_usize(2) == 0,
                latency_ms: lat,
                error: if rng.next_usize(2) == 0 {
                    Some(rng.random_unicode_string_up_to(15))
                } else {
                    None
                },
            });
        }

        if rng.next_usize(2) == 0 {
            let mut dns = DnsReport {
                domain: rng.random_unicode_string_up_to(15),
                has_mx_records: rng.next_usize(2) == 0,
                spf_record: if rng.next_usize(2) == 0 {
                    Some(rng.random_unicode_string_up_to(30))
                } else {
                    None
                },
                spf_lookup_count: rng.next_usize(20),
                dmarc_record: if rng.next_usize(2) == 0 {
                    Some(rng.random_unicode_string_up_to(30))
                } else {
                    None
                },
                dmarc_pct: 100,
                ..Default::default()
            };

            let mx_count = rng.next_usize(4);
            for _ in 0..mx_count {
                dns.mx_hosts.push(MxHost {
                    hostname: rng.random_unicode_string_up_to(15),
                    priority: rng.next_u32() as u16,
                    ipv4_addresses: vec!["1.2.3.4".to_string()],
                    ..Default::default()
                });
            }
            res.dns = Some(dns);
        }

        if rng.next_usize(2) == 0 {
            let mut smtp = SmtpReport {
                host: rng.random_unicode_string_up_to(15),
                port: 25,
                connected: true,
                connect_time_ms: 12.0,
                banner: Some(rng.random_unicode_string_up_to(25)),
                banner_time_ms: 40.0,
                banner_rfc_compliant: true,
                banner_has_fqdn: true,
                esmtp_supported: true,
                multiline_format_valid: true,
                capabilities: vec!["STARTTLS".to_string()],
                max_message_size_bytes: Some(10485760),
                starttls_advertised: true,
                pipelining_supported: true,
                smtputf8_supported: true,
                null_sender_accepted: Some(true),
                open_relay_tested: true,
                rset_working: true,
                quit_clean: true,
                ..Default::default()
            };

            let anom_count = rng.next_usize(4);
            for _ in 0..anom_count {
                smtp.anomalies.push(MisbehaviorAnomaly {
                    code: rng.random_string_up_to(10),
                    title: rng.random_unicode_string_up_to(15),
                    severity: Severity::Critical,
                    description: rng.random_unicode_string_up_to(30),
                    raw_response: rng.random_unicode_string_up_to(20),
                    rfc_reference: "RFC 5321 §4.2".to_string(),
                });
            }

            let tr_count = rng.next_usize(5);
            for _ in 0..tr_count {
                smtp.transcript.push(TranscriptEntry {
                    direction: if rng.next_usize(2) == 0 {
                        "->".to_string()
                    } else {
                        "<-".to_string()
                    },
                    timestamp: "12:34:56.789".to_string(),
                    text: rng.random_unicode_string_up_to(25),
                });
            }

            res.smtp = Some(smtp);
        }

        let json = DiagnosticReporter::to_json(&res);
        assert!(!json.is_empty());
        let _: serde_json::Value = serde_json::from_str(&json).expect("Fuzzed JSON must be valid JSON");

        let text = DiagnosticReporter::to_text(&res);
        assert!(!text.is_empty());

        let md = DiagnosticReporter::to_markdown(&res);
        assert!(!md.is_empty());

        let csv = DiagnosticReporter::to_csv(&res);
        assert!(!csv.is_empty());

        let html = DiagnosticReporter::to_html(&res);
        assert!(!html.is_empty());
    }
}

#[test]
fn test_fuzz_score_calculation() {
    let mut rng = FuzzRng::new(0x13579BDF_2468ACE0);

    for _ in 0..20_000 {
        let mut res = DiagnosticResult::new("example.org".to_string(), None);
        let check_count = rng.next_usize(20);
        let mut has_critical = false;

        for _ in 0..check_count {
            let sev = match rng.next_usize(5) {
                0 => Severity::Pass,
                1 => Severity::Notice,
                2 => Severity::Warning,
                3 => {
                    has_critical = true;
                    Severity::Critical
                }
                _ => Severity::Info,
            };
            res.checks.push(CheckItem {
                check_id: format!("CHK_{}", rng.next_u32()),
                category: "SECURITY".to_string(),
                title: "Test Check".to_string(),
                severity: sev,
                message: "Test Message".to_string(),
                recommendation: None,
                technical_details: None,
            });
        }

        res.calculate_score();

        assert!(
            res.score >= 0 && res.score <= 100,
            "Score {} must be within [0, 100]",
            res.score
        );
        assert!(!res.grade.is_empty(), "Grade must not be empty");

        if has_critical {
            assert!(
                res.score <= 69,
                "Critical findings must cap the score at 69, but got {}",
                res.score
            );
            assert!(
                res.grade == "D" || res.grade == "F",
                "Critical findings must result in D or F grade, but got {}",
                res.grade
            );
        }

        if check_count == 0
            || res
                .checks
                .iter()
                .all(|c| c.severity == Severity::Pass || c.severity == Severity::Info)
        {
            assert_eq!(res.score, 100);
            assert_eq!(res.grade, "A+");
        }
    }
}
