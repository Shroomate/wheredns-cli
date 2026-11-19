# WhereDNS CLI

Standalone Rust local diagnostics. Build with stable Rust: `cargo build --locked`.

Examples:

    wheredns example.com
    wheredns example.com dns A MX --json
    wheredns example.com email --selectors google
    wheredns https://example.com/path web
    wheredns example.com propagation
    wheredns example.com subdomains
    wheredns 1.1.1.1 ping
    wheredns 127.0.0.1 tcp --ports 80,443 --allow-private
    cat message.eml | wheredns headers --json

DNS, HTTP and RDAP are native Rust. ICMP requires OS ping. No hosted WhereDNS
service, account, CAPTCHA or remote auth dependency. External DNS/RDAP/target
servers receive diagnostic requests. No telemetry or result persistence.
Private destinations and private resolvers require --allow-private. No subnet
scanning. HTTP destinations are checked and pinned at each redirect; proxies
are disabled. DNS defaults to 1.1.1.1:53; override with --resolver.

Exit codes: 0 completed checks, 1 diagnostic error, 2 invalid input, 130 cancellation
or aggregate deadline. DNS negatives remain evidence. Plain output is formatted
evidence with labels; JSON is versioned. Neither emits ANSI.
See docs/COMPLETION.md for exact coverage and packaging/README.md for release steps.
