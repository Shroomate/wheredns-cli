# Native core implementation and validation

## Product and architecture

Standalone stable Rust CLI for local single-target diagnosis. clap parses target,
category and bounded options; Tokio schedules at most 4 operations by default
(configurable 1–16), with per-operation timeout and aggregate deadline. DNS uses
hickory wire messages over UDP with TCP fallback, typed records, response matching;
HTTP uses reqwest/rustls, pinned checked destinations, six-hop redirect cap, 1 MiB
RDAP body cap. Ctrl-C cancels async work and OS ping is killed on drop. Results
use a versioned serde envelope; protocol evidence is nested JSON. No persistence.
This project is separate from the hosted website. Read-only behavior references
were consulted; hosted schemas are not a compatibility promise.

## Coverage

- Summary: DNS, public domain RDAP and reverse IP evidence. No provider attribution heuristics.
- DNS: selected positional types or --type; TTL, owner, type, values, response code;
  NODATA distinct from NXDOMAIN and transport timeout; UDP with TCP fallback.
- Email: MX and TXT, SPF evidence, DMARC, selected DKIM owners, MTA-STS DNS,
  TLS-RPT, BIMI DNS evidence. No policy evaluator, MTA-STS HTTPS policy fetch,
  signature validation or delivery test.
- RDAP: domain/IP JSON through rdap.org redirect routing; no local IANA bootstrap.
- IP: addresses and PTR. ASN, prefix and forward-confirmed reverse lookup remain gaps.
- HTTP: HEAD, checked redirects, status, headers, per-response elapsed time,
  rustls certificate validation. Certificate metadata and split TCP/TLS timings remain gaps.
- TCP: up to ten supplied ports, default 443, bounded connect timing, first resolved IP.
- ICMP: actual OS ping, three requests, deadline, raw OS latency/loss summary.
  Structured sample parsing and locale-independent permission classification remain gaps.
- Propagation: up to six authoritative servers, A and SOA evidence. Automatic agreement
  classification remains a gap; compare returned records/serials.
- Subdomains: 20 common names, A records and randomized wildcard control evidence.
  Automatic wildcard labeling and AAAA controls remain gaps.
- Headers: explicit stdin command, 64 KiB bound, unfolding, duplicate fields,
  malformed count; authentication evidence marked untrusted. Routing analysis remains a gap.
- Blocklists: unimplemented; no deliverability claims.

## Actual Linux validation (2026-11-19)

cargo test --locked: 4 unit tests passed, 1 integration test passed, 0 failed.
cargo fmt --check: exit 0.
cargo clippy --locked -- -D warnings: exit 0.
cargo build --locked: exit 0.
Binary --version: wheredns 0.1.0. Integration test executes help/version, missing
input exit 2, piped folded/duplicate header JSON and no ANSI.

Two sequential live checks in this native pass, no sweeps:
example.com dns A --json: exit 0, 14 ms; 104.20.23.154 and 172.66.147.243,
TTL 115, resolver 1.1.1.1:53, status No Error.
https://example.com web --json: exit 0, 85 ms total; HTTP 200, 56 ms response.
DNS request fanout: one query; HTTPS fanout: A + AAAA and one HEAD.
Earlier foundation pass performed two utility probes; no live all/ports/subdomain tests.

macOS ARM/Intel and Windows execution is untested locally. CI matrix builds/tests
and uploads native binaries; no release/deployment steps. Homebrew and Scoop
are explicit unrendered templates requiring verified archives and SHA-256 hashes.
Windows ZIP/WinGet preparation is documented. No release/package is published.
