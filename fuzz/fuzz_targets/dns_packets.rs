#![no_main]
use libfuzzer_sys::fuzz_target;
use mx_detective::dns::DnsResolver;

// Whatever a nameserver sends back must parse or fail cleanly, never panic or loop.
fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = DnsResolver::parse_message(data) {
        let _ = (msg.mx(), msg.ips(), msg.txt(), msg.ptr(), msg.tlsa());
    }
    for offset in [0, 12, data.len() / 2, data.len()] {
        let _ = DnsResolver::read_name(data, offset);
        let _ = DnsResolver::skip_name(data, offset);
    }
    let name = String::from_utf8_lossy(data);
    let _ = DnsResolver::build_query(&name, 16, 1);
});
