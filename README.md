# WhereDNS CLI

WhereDNS is a standalone Rust CLI for local DNS, email, registration, and
network diagnostics.

## Install on macOS

Build WhereDNS from source with a current stable Rust toolchain and Apple's
command-line developer tools. If you already have Xcode or its command-line
tools, skip `xcode-select --install`. If you already have Cargo, skip the Rust
installation step. Rust is needed to build WhereDNS. The installed executable
runs without a Rust toolchain.

1. Install [Apple's Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools/).

   ```sh
   xcode-select --install
   ```

2. Install Rust using [rustup](https://rustup.rs/), or run the following if you
   already use Homebrew.

   ```sh
   brew install rust
   ```

3. Clone the repository and install with the checked-in dependency lockfile.
   If you already have a checkout, run the install command from its root.

   ```sh
   git clone https://github.com/Shroomate/wheredns-cli.git
   cd wheredns-cli
   cargo install --path . --locked
   ```

4. Verify the installation. These commands work offline.

   ```sh
   wheredns --version
   wheredns --help
   ```

   If your shell reports `command not found`, add Cargo's default binary
   directory to your PATH. Run this in your current shell and add the same
   line to `~/.zshrc` to use it in new Terminal sessions.

   ```sh
   export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
   ```

Run `cargo uninstall wheredns` to remove the installed binary.

## Usage

WhereDNS shows a themed report in Terminal. Use `--theme` with `purple` (the
default), `tty`, `btop`, `phosphor`, or `amber`. Set `NO_COLOR=1` for
monochrome panels. Add `--json` for scripts and other tools.

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
or aggregate deadline. DNS negatives remain evidence. Redirected output uses
plain text by default. JSON is versioned and contains no ANSI escape sequences.
See docs/COMPLETION.md for exact coverage and packaging/README.md for release steps.

Resolver failures (including SERVFAIL/REFUSED), failed PTR/authoritative subchecks
and nonzero OS ping exits fail the category with exit 1. NXDOMAIN and NODATA remain
negative evidence with exit 0. Headers require valid UTF-8 within 64 KiB of raw
input; read/encoding/size errors exit 2. An initial blank line ends the headers.
Destination policy conservatively denies selected special/transition ranges as
well as private/local addresses; it is not an automatically updated registry.
macOS IPv6 ICMP selects ping6. Run the offline review suite after cargo build:
`python3 tests/review_regressions.py` (loopback fixtures, no external diagnostics).
