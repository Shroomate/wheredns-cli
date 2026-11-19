# Initial implementation: incomplete coverage

Goal: standalone stable Rust CLI, local probes, no hosted WhereDNS dependency.
Architecture: clap arguments, versioned serde JSON envelope, sequential bounded subprocesses for dig/curl/ping; native TCP connect timeout. Output captures at most 256 KiB per stream. Child processes are killed on deadline. OS cancellation uses default process behavior; process-group cancellation is not implemented.

Implemented: generic DNS ANY evidence, MX evidence, reverse lookup evidence, HTTPS HEAD, domain RDAP fetch, literal-IP TCP connect, OS ping. JSON is a typed envelope around raw utility evidence, not typed protocol records. Hostname networking requires explicit --allow-private because utility resolution is not pinned. Redirects are not followed. No shell interpolation. No hosted WhereDNS calls.

Missing: authoritative propagation, subdomains, header parsing, full email policy suite, DNS wire parser and selected types, IP ASN/BGP enrichment, bootstrap RDAP routing, blacklist checks, bounded parallel scheduling, robust cancellation, full reserved-address policy, native dependency-free DNS/HTTP, structured protocol output and fixtures. This is an initial foundation, not completion of the requested full product. System utilities must be installed separately; Windows DNS requires dig.

Actual Linux validation: cargo test: 1 passed; cargo fmt; cargo clippy -- -D warnings; cargo build. Binary --version: `wheredns 0.1.0`. Help lists target/check, JSON, private permission, timeout and port. JSON fixture output:

```json
{"schema_version":1,"target":"127.0.0.1","check":"tcp","ok":false,"evidence":"private target requires --allow-private"}
```

stdin fixture output: `dns 127.0.0.1: private target requires --allow-private` (exit 1).
Two live probes only: `1.1.1.1 dns` returned DNS NXDOMAIN evidence (utility exit success is not DNS answer success); `example.com web --allow-private` returned HTTP/2 200. No live sweeps. macOS and Windows execution untested locally; CI configured, not claimed passing.

Packaging: build with `cargo build --locked --release`; distribute the resulting wheredns executable with system utility requirements documented. No release, installer, Homebrew publication, checksum or download URL exists. Before distribution, build natively on each CI OS, archive binary with README, compute SHA-256 from that archive, and verify extracted --version. Packaging automation remains incomplete.
