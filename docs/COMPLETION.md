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

## Independent review correctness fixes

B1–B4 addressed directly in the parent thread, with one writer and no external
diagnostic requests. The checked-in tests/review_regressions.py reproduces the
review's packet and stdin fixtures without writing to the review artifact directory.
RED on d152b5f: assertions failed for SERVFAIL, truncated TCP, malformed PTR,
unrelated-owner HTTP connection, failed ping, invalid UTF-8, initial separator,
and oversized whitespace. GREEN after fixes: 10 offline review regressions passed.

Typed Result propagation now determines verdicts for DNS/email/subdomains, PTR
and authoritative operations; failed subchecks fail the category (partial evidence
is not retained). SERVFAIL/REFUSED and other resolver errors fail; NXDOMAIN/NODATA
remain successful negative evidence. Failed ping reports bounded stdout/stderr in
its error. TCP closed remains diagnostic evidence. HTTP non-success status fails.
UDP envelope ID/question/QR/opcode is checked before TC fallback; final TCP TC is
an incomplete-response error. IDs use the OS-seeded rand generator. A mismatched
packet fails the query rather than being retried. Address records must match the
queried family and owner, or an unambiguous bounded CNAME chain rooted there.
Loops and overlong chains fail. Only those addresses enter destination policy and
HTTP pinning. Header bytes are bounded before decoding, read/UTF-8 errors fail,
and initial header/body separators are preserved.

Additional offline tests cover happy TCP fallback, TCP TC, ID/question/opcode/QR
mismatch, malformed/short frames, rejected UDP TC without TCP connection, negative
RCODE controls, unrelated owner/type, CNAME positive/loop and mixed families,
header read errors/leading continuation, address policy and macOS IPv6 ping6.
The destination policy conservatively denies private, local, shared, documentation,
benchmark and selected special/transition ranges; it is not an automatically
updated IANA registry. Private opt-in applies to resolver and destination sockets.

Final local verification: cargo test --locked --offline: 9 unit + 1 integration
passed, 0 failed; Python: 10 offline review regressions passed; cargo build
--locked --offline, cargo fmt --check and cargo clippy --locked --offline -- -D
warnings all exit 0. Python fixture suite is configured in Linux CI; Rust fixtures
run across the matrix. Native macOS/Windows runtime behavior remains unverified
until their checks finish. No live diagnostics in this correction pass.

## Re-review DNS eligibility corrections

R1/R2: connector resolution now requires typed Outcome::NoError and IN (class 1)
address records and CNAME links. RR class remains visible in DNS evidence;
NXDOMAIN remains successful negative diagnostic evidence, but none of its records
can supply connection addresses. Non-IN records are ignored for connector use.
Conflicting IN CNAME/address evidence at one owner is rejected. Authoritative NS
selection also requires NOERROR and matching owner/IN class.

RED: new checked-in tests/dns_eligibility.py failed against 56791e4 for both A and
AAAA NXDOMAIN-with-address, negative alias, CH/HS addresses, CH/HS aliases, and
CH/HS terminal records (16 failing transport assertions). GREEN: 30 eligibility
regressions passed: positive exact owner/CNAME, mixed IN/non-IN positives,
NXDOMAIN addresses/aliases, SERVFAIL/REFUSED, CH/HS address and chain rejection,
conflicting positive CNAME/address evidence, and legitimate empty NXDOMAIN/NODATA.
Rejected evidence produced no HTTP connection. Fixtures use ephemeral loopback
UDP/HTTP ports, including IPv6; no privileged port 53 or live service calls.
The new suite runs in Linux CI alongside the original 10 regression cases.

Final local validation: 9 Rust unit tests and 1 executable integration test passed;
30 eligibility regressions and 10 original review regressions passed; fmt --check,
clippy --locked --offline -- -D warnings, build --locked --offline and diff --check
passed. No external diagnostics performed. No other feature scope added.
