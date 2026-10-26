# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security tab → Report a vulnerability** (private vulnerability reporting is
enabled). Please do not open a public issue for something exploitable.

You can expect an acknowledgement within a week.

## Supported versions

Only the latest release receives fixes.

## How the project is checked

MX Detective reads data from servers and DNS zones it does not control, so
everything it parses is treated as untrusted input. These checks run
automatically on GitHub (see the badges in the README):

| Check | When | Workflow |
| --- | --- | --- |
| Build, tests, `clippy -D warnings`, `rustfmt` | every push and pull request | [CI](.github/workflows/ci.yml) |
| `cargo audit` against the RustSec advisory database | every push, every pull request, and weekly | [Security](.github/workflows/security.yml) |
| Snyk Code static analysis | every push and pull request, and weekly | [Security](.github/workflows/security.yml) |
| Fuzzing with AddressSanitizer: DNS packets, SMTP replies, HTTP and MTA-STS policy, SPF/DMARC/DKIM records, certificate and DANE matching | weekly and on demand | [Security](.github/workflows/security.yml) |
| Dependency update pull requests | weekly | [Dependabot](.github/dependabot.yml) |
| Secret scanning with push protection | always on | GitHub |

Snyk's dependency scan does not support Cargo, so dependencies are covered by
`cargo audit` and Dependabot instead. The in-tree randomized tests in
`tests/fuzz_tests.rs` also run on every CI build.

## Design notes

- The tool only sends what a normal sending server sends: `EHLO`, `STARTTLS`,
  `MAIL FROM`, `RCPT TO`, `VRFY`, `EXPN`, `RSET` and `QUIT`. It never sends the
  `DATA` command, so no message is ever delivered.
- The open-relay and catch-all probes use reserved or made-up addresses
  (`example.net`, `.invalid`) and are always followed by `RSET`.
- DNS replies are accepted only with the query's random ID, answers are bounded,
  and name compression loops are cut off.
- TLS is provided by `rustls`. Certificate problems on MX servers are recorded
  as findings rather than refused, because MX delivery uses opportunistic TLS;
  the MTA-STS policy fetch, in contrast, verifies the certificate strictly and
  does not follow redirects, as RFC 8461 requires.
- Responses read over the network are size-limited (64 KiB for HTTP, 500 lines
  for an SMTP reply).
