#![no_main]
use libfuzzer_sys::fuzz_target;
use mx_detective::dns::{same_organization, DnsResolver};
use mx_detective::models::DkimKey;

// SPF, DMARC and DKIM records are free text published in DNS.
fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data).into_owned();
    let _ = DnsResolver::parse_dmarc_tags(&s);
    for term in DnsResolver::parse_spf_mechanisms(&s) {
        let _ = DnsResolver::spf_term(&term);
    }
    let _ = DkimKey::parse("selector", s.clone()).describe();
    let (a, b) = s.split_at(s.len() / 2);
    let _ = same_organization(a, b);
});
