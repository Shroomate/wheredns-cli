# wheredns

DNS, email, registration, web and network diagnostics for a domain, IP address
or URL. All checks run from the local machine.

```sh
wheredns github.com
```

## Install

Homebrew (macOS and Linux):

```sh
brew install shroomate/tap/wheredns
```

Prebuilt archives for macOS, Linux and Windows are attached to each
[release](https://github.com/Shroomate/wheredns-cli/releases).

From source, with a stable Rust toolchain:

```sh
cargo install --git https://github.com/Shroomate/wheredns-cli --locked
```

Cargo installs to `~/.cargo/bin`. Add it to `PATH` if `wheredns` is not found.

## Usage

```
wheredns TARGET [CHECK ...] [OPTIONS]
```

With no checks, a domain runs `where email ping whois web` and an IP address
runs `ping whois web ip`. Checks run concurrently.

```sh
wheredns google.com email dkim:20230601
wheredns example.com dns A MX TXT propagation
wheredns 8.8.8.8 blacklist ip
wheredns cloudflare.com web ports 22 443 8443
wheredns example.com all
pbpaste | wheredns headers
```

| Check | Output |
|---|---|
| `where` | DNS hosting provider, registrar, IP network owner |
| `email` | MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI, with lint notes |
| `ping` | 10 ICMP echoes: latency chart, loss, min/avg/max |
| `whois` | RDAP registration: registrar, dates, status, nameservers, DNSSEC |
| `web` | Status, redirects, DNS/TCP/TLS/response timing, certificate, HSTS, HTTP to HTTPS |
| `dns [TYPES]` | 14 record types plus SRV/TLSA presets, or the given types; DNSSEC AD flag |
| `blacklist` | The IP, or the domain's mail servers, on 14 DNS blocklists |
| `ip` | Reverse DNS with forward confirmation, ASN, BGP prefix, network owner |
| `ports [N ...]` | Common TCP ports, or up to 10 given ports |
| `propagation` | Each authoritative nameserver queried directly; answers and SOA serials compared |
| `subdomains` | 20 common names, with randomized wildcard controls |
| `dkim:SEL` | Email check using the given DKIM selector |
| `headers` | Email header read from stdin: hop trace, delays, authentication results |
| `all` | Every check except `headers` |

### Options

| Option | Default | |
|---|---|---|
| `--json` | | JSON output (`schema_version` 2) |
| `--theme NAME` | `btop` | `btop`, `tty`, `purple`, `phosphor`, `amber` |
| `--animate MODE` | `full` | `full` (live panels), `minimal` (progress line), `off` |
| `--resolver IP:PORT` | `1.1.1.1:53` | Recursive resolver |
| `--timeout SECS` | 5 | Per-operation timeout |
| `--deadline SECS` | 60 | Whole-run deadline |
| `--allow-private` | off | Allow private, loopback and other non-public destinations and resolvers |

Run `wheredns --help` for the full list.

Output that is not a terminal is plain text with no escape sequences.
`NO_COLOR=1` disables colors.

### Settings

```sh
wheredns config                           # show settings and the file path
wheredns config set theme tty
wheredns config set checks where web dns  # default checks for a domain
wheredns config set animate off
wheredns config set background false      # use the terminal's background
wheredns config unset theme
```

Settings are stored in `~/.config/wheredns/config` (or
`$XDG_CONFIG_HOME/wheredns/config`). Command-line flags override
`WHEREDNS_THEME` and `WHEREDNS_ANIMATE`, which override the file.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks completed |
| 1 | A check failed |
| 2 | Invalid input |
| 130 | Cancelled, or the deadline was reached |

NXDOMAIN and NODATA are results, not failures. SERVFAIL, REFUSED, failed
subqueries and a nonzero `ping` exit fail the check.

## Network behavior

- DNS, HTTP, TLS and RDAP are implemented in Rust. ICMP uses the system `ping`
  (`ping6` for IPv6 on macOS).
- Requests go to the configured resolver, the target, the 14 blocklist zones
  and rdap.org (which redirects to the registry). There is no wheredns service,
  account or telemetry.
- HTTP requests are `HEAD` with the user agent
  `wheredns/VERSION (+https://github.com/Shroomate/wheredns-cli)`. Each redirect
  hop is resolved, checked against the destination policy and pinned. Proxies
  are not used.
- Private, loopback, link-local, shared, documentation and benchmark ranges are
  refused unless `--allow-private` is given.
- `headers` reads at most 64 KiB of UTF-8 from stdin and makes no network
  requests.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build && python3 tests/loopback_regressions.py && python3 tests/dns_eligibility.py
```

The Python suites run the debug binary against loopback DNS and HTTP fixtures.
Release steps are in [packaging/README.md](packaging/README.md).

## License

MIT
