# WhereDNS CLI

Initial local Rust diagnostic CLI. See [coverage and validation](docs/COMPLETION.md) for substantial outstanding requirements.

Build: `cargo build --locked --release` (stable Rust).
Run: `wheredns --help`, `wheredns 8.8.8.8 tcp --port 443 --json`.
Hostname probes require `--allow-private` because external utility DNS resolution cannot be pinned safely. `dig`, `curl`, and OS `ping` are runtime dependencies for their respective checks. No WhereDNS hosted service is used.
