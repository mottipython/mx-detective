#![no_main]
use libfuzzer_sys::fuzz_target;
use mx_detective::diff::{compare, parse_baseline};

// A baseline is a file someone hands to --baseline or --diff.
fuzz_target!(|data: &[u8]| {
    if let Ok(result) = parse_baseline(&String::from_utf8_lossy(data)) {
        let _ = compare(&result, &result, &[]);
    }
});
