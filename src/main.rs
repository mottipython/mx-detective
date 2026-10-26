use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{ArgGroup, CommandFactory, FromArgMatches, Parser, ValueEnum};

use mx_detective::diagnose::{self, DiagnosticOptions};
use mx_detective::models::{DiagnosticResult, Severity};
use mx_detective::reporter::DiagnosticReporter;
use mx_detective::{gui, platform, summary};

/// Finished, and a finding at or above `--fail-on` was found.
const EXIT_FINDINGS: u8 = 1;
/// Command line error (the code clap uses for bad arguments).
const EXIT_USAGE: u8 = 2;
/// Could not finish: timed out, or the report file could not be written.
const EXIT_FAILED: u8 = 3;

const LONG_ABOUT: &str = "\
Check a domain's mail setup from the outside.

mx-detective looks up the domain's MX servers, connects to every address of every \
server over IPv4 and IPv6, and checks what a sending server would run into: the real \
TLS certificate, DANE and MTA-STS, SPF, DMARC and DKIM, reverse DNS, DNS blocklists, \
open relay, and protocol behavior. It speaks ordinary SMTP and never sends a message.

The answer is a score (0-100), a grade (A+ to F) and a list of findings. Each finding \
is Critical, Warning, Notice, Info or Pass.";

const SHORT_HELP_FOOTER: &str = "Run with --help for the exit codes, the keys for --get and --summary, and examples.";

const HELP_BODY: &str = "\
GETTING AN ANSWER
  (default)     full text report on stdout
  --summary     one key=value line per fact (keys are listed below)
  --get KEY     only the value of one key, for example: --get grade
  --json        the complete result as JSON
  -o FILE       also save a report; the format follows the extension
                (.html .md .json .csv .txt), or choose it with --format

  Only one of --summary, --get and --json can be used at a time. Everything on
  stdout is plain ASCII, whatever the console code page. Progress and messages go
  to stderr, and only when stderr is a terminal (--quiet hides them there too),
  so output captured from a script contains the answer and nothing else.

EXIT CODES
  0   finished, and nothing is at or above --fail-on (always 0 without --fail-on)
  1   finished, and at least one finding is at or above --fail-on
  2   command line error
  3   could not finish: --max-time ran out, or a report file could not be written

  A domain that cannot receive mail is an answer, not an error: it is reported as a
  Critical finding, so combine --fail-on critical with the exit code.

KEYS FOR --summary AND --get
";

const HELP_EXAMPLES: &str = "
EXAMPLES
  mx-detective example.com
  mx-detective example.com --summary
  mx-detective example.com --get grade
  mx-detective example.com --fail-on critical --quiet || echo \"mail problem\"
  mx-detective example.com --json > result.json
  mx-detective example.com -o report.html
  mx-detective example.com --host mx1.example.com --recipient user@example.com
  mx-detective example.com --primary-only --no-dnsbl --timeout 3

  PowerShell:
    $grade = mx-detective.exe example.com --get grade
    $r = mx-detective.exe example.com --json | ConvertFrom-Json
    \"$($r.domain): $($r.grade), $($r.score)/100\"
    mx-detective.exe example.com --fail-on warning --quiet; if ($LASTEXITCODE -eq 1) { ... }

NOTES
  - Outbound port 25 is blocked on many home, hotel and cloud networks. When it is,
    the result says so (port25=closed) and the SMTP checks cannot run from there.
  - DNS blocklists such as Spamhaus refuse queries from busy public resolvers; those
    lists are then skipped rather than reported as clean.
  - DNSSEC needs a validating resolver; without one, dnssec=unknown.
  - Only test servers you are responsible for, or have permission to test.
  - Colors appear only on a terminal. Set NO_COLOR to turn them off.
  - The window needs no graphics driver: on Windows it always draws on the CPU; on Linux and
    macOS it uses OpenGL when that works. MX_DETECTIVE_SOFTWARE_RENDER=1 forces the CPU
    renderer there.
  - With no domain, a double-click on Windows opens the window. Use --gui to open the
    window anywhere.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FailOn {
    Critical,
    Warning,
    Notice,
}

impl FailOn {
    fn rank(self) -> u8 {
        match self {
            FailOn::Notice => 1,
            FailOn::Warning => 2,
            FailOn::Critical => 3,
        }
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Pass | Severity::Info => 0,
        Severity::Notice => 1,
        Severity::Warning => 2,
        Severity::Critical => 3,
    }
}

fn exceeds(result: &DiagnosticResult, level: FailOn) -> bool {
    result.checks.iter().any(|c| severity_rank(c.severity) >= level.rank())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Html,
    Json,
    #[value(alias = "markdown")]
    Md,
    Csv,
    Txt,
}

impl Format {
    fn from_path(path: &str) -> Self {
        match path.rsplit('.').next().map(str::to_ascii_lowercase).as_deref() {
            Some("html" | "htm") => Format::Html,
            Some("json") => Format::Json,
            Some("md" | "markdown") => Format::Md,
            Some("csv") => Format::Csv,
            _ => Format::Txt,
        }
    }

    fn render(self, result: &DiagnosticResult) -> String {
        match self {
            Format::Html => DiagnosticReporter::to_html(result),
            Format::Json => DiagnosticReporter::to_json(result),
            Format::Md => DiagnosticReporter::to_markdown(result),
            Format::Csv => DiagnosticReporter::to_csv(result),
            Format::Txt => DiagnosticReporter::to_text(result),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "mx-detective",
    version,
    about = "Check a domain's mail servers from the outside",
    long_about = LONG_ABOUT,
    after_help = SHORT_HELP_FOOTER,
    group(ArgGroup::new("stdout").args(["json", "summary", "get"])),
)]
struct Cli {
    /// Domain to check, for example example.com
    #[arg(value_name = "DOMAIN")]
    domain: Option<String>,

    /// Test only this server instead of the domain's MX servers
    #[arg(short = 's', long, value_name = "HOST", help_heading = "What to test")]
    host: Option<String>,

    /// SMTP port to test
    #[arg(short = 'p', long, default_value_t = 25, help_heading = "What to test")]
    port: u16,

    /// Also check whether this mailbox is accepted (nothing is sent)
    #[arg(long, value_name = "ADDRESS", help_heading = "What to test")]
    recipient: Option<String>,

    /// Extra DKIM selectors to look for, comma-separated; about 95 common ones are always tried
    #[arg(long, value_name = "LIST", help_heading = "What to test")]
    dkim_selector: Option<String>,

    /// Test only the most preferred MX host, not every address of every host
    #[arg(long, help_heading = "What to test")]
    primary_only: bool,

    /// Do not test over IPv6
    #[arg(long, help_heading = "What to test")]
    no_ipv6: bool,

    /// Skip DNS blocklist lookups
    #[arg(long, help_heading = "What to test")]
    no_dnsbl: bool,

    /// Skip the open relay test
    #[arg(long, help_heading = "What to test")]
    no_relay: bool,

    /// Skip the postmaster, catch-all and VRFY/EXPN probes
    #[arg(long, help_heading = "What to test")]
    no_extended: bool,

    /// Seconds to wait for each network operation, 0.5 to 120
    #[arg(
        short = 't',
        long,
        default_value_t = 5.0,
        value_name = "SECONDS",
        help_heading = "Timing"
    )]
    timeout: f64,

    /// Give up after this many seconds in total and exit with code 3; 0 means no limit
    #[arg(long, default_value_t = 300, value_name = "SECONDS", help_heading = "Timing")]
    max_time: u64,

    /// Print one key=value line per fact
    #[arg(long, help_heading = "Output")]
    summary: bool,

    /// Print only the value of one summary key
    #[arg(long, value_name = "KEY", value_parser = PossibleValuesParser::new(summary::KEYS.iter().map(|(k, _)| *k)), help_heading = "Output")]
    get: Option<String>,

    /// Print the complete result as JSON
    #[arg(long, help_heading = "Output")]
    json: bool,

    /// Also save a report to this file
    #[arg(
        short = 'o',
        long = "output",
        visible_alias = "export",
        value_name = "FILE",
        help_heading = "Output"
    )]
    output: Option<String>,

    /// Format of the saved report; by default taken from the file extension
    #[arg(long, value_enum, value_name = "FORMAT", help_heading = "Output")]
    format: Option<Format>,

    /// Exit with code 1 if any finding is at or above this level
    #[arg(long, value_enum, value_name = "LEVEL", help_heading = "Output")]
    fail_on: Option<FailOn>,

    /// Hide progress and messages on stderr
    #[arg(short = 'q', long, help_heading = "Output")]
    quiet: bool,

    /// Open the window instead of running on the command line
    #[arg(long)]
    gui: bool,
}

fn command() -> clap::Command {
    let keys: String = summary::KEYS
        .iter()
        .map(|(k, d)| format!("  {:<20}{}\n", k, d))
        .collect();
    Cli::command().after_long_help(format!("{}{}{}", HELP_BODY, keys, HELP_EXAMPLES))
}

/// Progress and messages on stderr. Only for people at a terminal: a script that
/// captures stderr should get nothing it has to filter out.
struct Term {
    progress: bool,
    color: bool,
}

impl Term {
    fn new(quiet: bool) -> Self {
        let tty = io::stderr().is_terminal();
        Self {
            progress: tty && !quiet,
            color: tty && std::env::var_os("NO_COLOR").is_none() && platform::enable_ansi(),
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }

    fn header(&self, domain: &str) {
        if self.progress {
            let title = format!("MX Detective {} - {}", env!("CARGO_PKG_VERSION"), domain);
            eprintln!("{}", self.paint("1", &title));
        }
    }

    fn step(&self, message: &str) {
        if self.progress {
            eprintln!("  {} {}", self.paint("2", "..."), message);
        }
    }

    fn note(&self, message: &str) {
        if self.progress {
            eprintln!("{}", message);
        }
    }
}

/// Writes to stdout and ignores a closed pipe (`mx-detective ... | head`).
fn write_stdout(text: &str) {
    let mut out = io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|_| out.flush());
}

fn run(cli: Cli, domain: String) -> ExitCode {
    if cli.max_time > 0 {
        let limit = cli.max_time;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(limit));
            eprintln!("mx-detective: gave up after {} seconds (--max-time)", limit);
            std::process::exit(EXIT_FAILED.into());
        });
    }

    let term = Term::new(cli.quiet);
    term.header(&domain);

    let opts = DiagnosticOptions {
        domain,
        host_override: cli.host.clone(),
        port: cli.port,
        timeout: Duration::from_secs_f64(cli.timeout.clamp(0.5, 120.0)),
        recipient: cli.recipient.clone(),
        test_relay: !cli.no_relay,
        dkim_selector: cli.dkim_selector.clone(),
        primary_only: cli.primary_only,
        ipv6: !cli.no_ipv6,
        dnsbl: !cli.no_dnsbl,
        extended: !cli.no_extended,
    };
    let result = diagnose::run(&opts, &|message| term.step(message));

    if let Some(key) = &cli.get {
        write_stdout(&format!("{}\n", summary::get(&result, key).unwrap_or_default()));
    } else if cli.summary {
        write_stdout(&summary::to_text(&result));
    } else if cli.json {
        write_stdout(&format!("{}\n", DiagnosticReporter::to_json(&result)));
    } else {
        write_stdout(&DiagnosticReporter::to_text(&result));
    }

    if let Some(path) = &cli.output {
        let format = cli.format.unwrap_or_else(|| Format::from_path(path));
        if let Err(e) = std::fs::write(path, format.render(&result)) {
            eprintln!("mx-detective: cannot write {}: {}", path, e);
            return ExitCode::from(EXIT_FAILED);
        }
        term.note(&format!("Report saved to {}", path));
    }

    match cli.fail_on {
        Some(level) if exceeds(&result, level) => ExitCode::from(EXIT_FINDINGS),
        _ => ExitCode::SUCCESS,
    }
}

fn open_window(domain: Option<String>) -> ExitCode {
    // A double-clicked executable gets a console of its own that the window does not need.
    let detached = platform::console_owned_alone();
    if detached {
        platform::detach_console();
    }
    match gui::launch_gui(domain) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let message = format!(
                "Could not open the window: {}\n\nThe command line works everywhere: run mx-detective with a domain, or with --help.",
                e
            );
            if detached {
                platform::error_dialog(&message);
            } else {
                eprintln!("mx-detective: {}", message);
            }
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// True when someone double-clicked the executable: a console of its own, and a person on it.
fn launched_by_double_click() -> bool {
    platform::console_owned_alone() && io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn main() -> ExitCode {
    let matches = command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };

    match cli.domain.clone() {
        Some(domain) if !cli.gui => run(cli, domain),
        domain if cli.gui || launched_by_double_click() => open_window(domain),
        _ => {
            eprintln!("{}", command().render_help());
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_detective::models::CheckItem;

    fn result_with(severities: &[Severity]) -> DiagnosticResult {
        let mut r = DiagnosticResult::new("example.com".into(), None);
        r.checks = severities
            .iter()
            .map(|s| CheckItem::new("X", "DNS", *s, "t", "m"))
            .collect();
        r
    }

    #[test]
    fn fail_on_levels() {
        let notice = result_with(&[Severity::Pass, Severity::Info, Severity::Notice]);
        assert!(exceeds(&notice, FailOn::Notice));
        assert!(!exceeds(&notice, FailOn::Warning));

        let warning = result_with(&[Severity::Warning]);
        assert!(exceeds(&warning, FailOn::Warning));
        assert!(!exceeds(&warning, FailOn::Critical));

        let critical = result_with(&[Severity::Critical]);
        assert!(exceeds(&critical, FailOn::Critical));

        let clean = result_with(&[Severity::Pass, Severity::Info]);
        assert!(!exceeds(&clean, FailOn::Notice), "Info and Pass never fail a run");
        assert!(!exceeds(&result_with(&[]), FailOn::Notice));
    }

    #[test]
    fn report_format_follows_the_extension() {
        assert_eq!(Format::from_path("out.HTML"), Format::Html);
        assert_eq!(Format::from_path("dir.d/out.json"), Format::Json);
        assert_eq!(Format::from_path("a.md"), Format::Md);
        assert_eq!(Format::from_path("a.markdown"), Format::Md);
        assert_eq!(Format::from_path("a.csv"), Format::Csv);
        assert_eq!(Format::from_path("a.log"), Format::Txt);
        assert_eq!(Format::from_path("noextension"), Format::Txt);
    }

    #[test]
    fn help_text_is_ascii_and_lists_every_key() {
        let help = command().render_long_help().to_string();
        assert!(help.is_ascii(), "help must survive any console code page");
        for (key, _) in summary::KEYS {
            assert!(help.contains(key), "help does not mention {}", key);
        }
        assert!(help.contains("EXIT CODES"));
    }
}
