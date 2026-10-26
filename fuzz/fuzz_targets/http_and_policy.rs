#![no_main]
use libfuzzer_sys::fuzz_target;
use mx_detective::models::MtaStsReport;
use mx_detective::policy::parse_mta_sts_policy;
use mx_detective::tls::parse_http_response;

// The MTA-STS policy is fetched from a host the domain owner controls.
fuzz_target!(|data: &[u8]| {
    if let Ok((_, _, body)) = parse_http_response(data) {
        let _ = parse_mta_sts_policy(&body, &mut MtaStsReport::default());
    }
    let _ = parse_mta_sts_policy(&String::from_utf8_lossy(data), &mut MtaStsReport::default());
});
