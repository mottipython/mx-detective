#![no_main]
use libfuzzer_sys::fuzz_target;
use mx_detective::models::SmtpReport;
use mx_detective::smtp::SmtpProber;
use std::time::Duration;

// Reply lines come straight from the server under test.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    for line in &lines {
        let _ = SmtpProber::parse_smtp_status_code(line);
        let _ = SmtpProber::extract_ehlo_capability(line);
    }
    let prober = SmtpProber::new(Duration::from_secs(1));
    let mut report = SmtpReport::default();
    let mut checks = Vec::new();
    prober.parse_ehlo_extensions(&lines, &mut report, &mut checks, false);
    prober.parse_ehlo_extensions(&lines, &mut report, &mut checks, true);
});
