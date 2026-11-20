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

Give WhereDNS a domain, IP address or URL, then any checks you want. With no
checks, a domain runs `where email ping whois web` (the same default as the
WhereDNS website) and an IP runs `ping whois web ip`. Checks run concurrently
and each panel prints as soon as it is ready.

    wheredns github.com
    wheredns google.com email dkim:20230601
    wheredns example.com dns A MX TXT propagation
    wheredns 8.8.8.8 blacklist ip
    wheredns cloudflare.com web ports 22 443 8443
    wheredns example.com all
    pbpaste | wheredns headers

| Check | Evidence |
|---|---|
| `where` | DNS hosting provider, domain registrar, IP network owner |
| `email` | MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI with lint notes |
| `ping` | Ten ICMP echoes with a latency chart, loss and min/avg/max |
| `whois` | RDAP registration: registrar, dates, status, nameservers, DNSSEC |
| `web` | Status, redirects, DNS/TCP/TLS/response timing, certificate, HSTS, HTTP→HTTPS |
| `dns [TYPES]` | 14 record types plus SRV/TLSA presets, or the types you name; DNSSEC AD flag |
| `blacklist` | The IP (or the domain's mail servers) on 14 public DNS blocklists |
| `ip` | Reverse DNS with forward confirmation, ASN, BGP prefix, network owner |
| `ports [N…]` | Common TCP ports, or up to ten you name |
| `propagation` | Each authoritative nameserver queried directly; answers and SOA serials compared |
| `subdomains` | Twenty common names with randomized wildcard controls |
| `dkim:SEL` | Email check using that DKIM selector |
| `headers` | Email header from stdin: hop trace with delays and authentication results |

On a terminal the report is live, like the website: each check gets a panel
while it runs, ping replies, port probes and blocklist answers stream in, and
finished panels slide in with bars that grow to their measured size. Panels
fill the terminal width and re-lay out if you resize the window during a run.

Themes match the website: `btop` (default), `tty`, `purple`, `phosphor` and
`amber`. Save your preferences once with `wheredns config`:

```sh
wheredns config                          # show settings and the file path
wheredns config set theme tty
wheredns config set checks where web dns # default checks for a domain
wheredns config set animate minimal      # full (default), minimal or off
wheredns config set background false     # keep the terminal's own background
wheredns config unset theme
```

Settings live in `~/.config/wheredns/config` (`$XDG_CONFIG_HOME` is honored).
`--theme`/`--animate` beat `WHEREDNS_THEME`/`WHEREDNS_ANIMATE`, which beat the
file. `NO_COLOR=1` turns colors off. Add `--json` for scripts; output that is
not a terminal is plain text with no escape sequences or animation.

Everything runs from your machine. DNS, HTTP, TLS and RDAP are native Rust; ICMP
uses the OS `ping`. There is no hosted WhereDNS service, account or telemetry,
and nothing is stored. External DNS, RDAP and target servers receive the
diagnostic requests. Private destinations and resolvers require
`--allow-private`. HTTP destinations are resolved, checked and pinned at every
redirect, and proxies are disabled. DNS defaults to 1.1.1.1:53; override with
`--resolver`.

Exit codes: 0 every check completed, 1 a check failed, 2 invalid input, 130
cancellation or aggregate deadline. JSON output is versioned (`schema_version`
2) and contains no ANSI escape sequences.
See docs/COMPLETION.md for exact coverage and packaging/README.md for release steps.

Resolver failures (including SERVFAIL/REFUSED), failed PTR/authoritative subchecks
and nonzero OS ping exits fail the category with exit 1. NXDOMAIN and NODATA remain
negative evidence with exit 0. Headers require valid UTF-8 within 64 KiB of raw
input; read/encoding/size errors exit 2. An initial blank line ends the headers.
Destination policy conservatively denies selected special/transition ranges as
well as private/local addresses; it is not an automatically updated registry.
macOS IPv6 ICMP selects ping6. Run the offline review suite after cargo build:
`python3 tests/review_regressions.py` (loopback fixtures, no external diagnostics).
