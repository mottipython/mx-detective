#![no_main]
use libfuzzer_sys::fuzz_target;
use mx_detective::models::TlsaRecord;
use mx_detective::tls::{dane_match, hostname_matches};

// Certificates and TLSA records are attacker-supplied: DER that is not a certificate
// must not panic the selector 1 (public key) path.
fuzz_target!(|data: &[u8]| {
    let split = data.first().copied().unwrap_or(0) as usize % (data.len().max(1));
    let (cert, rest) = data.split_at(split.min(data.len()));
    let chain = vec![cert.to_vec(), rest.to_vec()];
    for usage in 0..4u8 {
        for selector in 0..2u8 {
            for matching_type in 0..3u8 {
                let rec = TlsaRecord {
                    usage,
                    selector,
                    matching_type,
                    data_hex: String::from_utf8_lossy(rest).into_owned(),
                };
                let _ = dane_match(&[rec], &chain);
            }
        }
    }
    let text = String::from_utf8_lossy(data);
    let (a, b) = text.split_at(text.len() / 2);
    let _ = hostname_matches(a, b);
});
