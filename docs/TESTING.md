# Testing

Every suite runs offline. Network behavior is tested against loopback
fixtures: a scripted DNS resolver, local HTTP servers, a saved email header
and a scratch config directory. No test depends on the public internet, so
results don't change with DNS or registry data.

CI runs all of it on Linux, Windows, macOS ARM64 and macOS Intel for every
push and pull request.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked                      # unit, CLI contract and scenario tests
cargo build --locked
python3 tests/loopback_regressions.py    # loopback DNS/HTTP edge cases
python3 tests/dns_eligibility.py         # which DNS answers count as evidence
```

## Cases

| Suite | Cases | What it covers |
|---|---:|---|
| Unit (`src/`) | 15 | DNS wire parsing and hostile replies, header parsing, URL normalization, address policy, ping output on each platform, provider attribution, TLS error text, settings validation |
| CLI contract (`tests/cli.rs`) | 7 | `--help`/`--version`, usage errors, JSON schema, redirect evidence on HTTP failure, NXDOMAIN parent-zone lookup, NODATA labelling, terminal DNS layout |
| Scenarios (`tests/scenarios.rs`) | 14 | End-to-end runs of the binary, listed below |
| Loopback regressions (`tests/loopback_regressions.py`) | 12 | REFUSED, SERVFAIL, truncated TCP, malformed PTR, unrelated owners, nonzero ping, invalid and oversized headers |
| DNS eligibility (`tests/dns_eligibility.py`) | 30 | Which answers (by rcode, class and owner) count as evidence for each check |
| **Total** | **78** | |

### Scenarios

| Test | Checks that |
|---|---|
| `headers_trace_hops_oldest_first_with_delays` | `Received:` hops are ordered oldest first, with per-hop and total delays |
| `headers_report_authentication_results_as_untrusted_claims` | DKIM, SPF and DMARC results are parsed and flagged as untrusted claims |
| `headers_terminal_report_is_offline_and_plain_when_piped` | The header report is labelled offline and has no escape sequences in a pipe |
| `headers_reject_oversized_and_non_utf8_input` | Input over 64 KiB or not UTF-8 exits 2 |
| `nxdomain_is_evidence_not_a_failure` | NXDOMAIN is a result (exit 0), not an error |
| `servfail_fails_the_check` | SERVFAIL fails the check (exit 1) |
| `null_mx_is_labelled_in_the_terminal_report` | An RFC 7505 null MX is shown as "accepts no mail" |
| `email_check_reads_spf_and_dmarc_records` | MX, SPF and DMARC findings come from the resolver's answers |
| `deadline_cancels_a_hung_run_with_exit_130` | `--deadline` stops a run against a resolver that never replies |
| `invalid_targets_are_usage_errors` | Malformed targets exit 2 with nothing on stdout |
| `private_destinations_require_allow_private` | Loopback and RFC 1918 targets are refused without `--allow-private` |
| `private_resolver_requires_allow_private` | A private `--resolver` is refused without `--allow-private` |
| `config_set_show_and_unset_round_trip` | `wheredns config set/unset` writes the file, rejects bad values and resets |
| `json_output_is_versioned_and_free_of_escape_sequences` | `--json` carries `schema_version` 2 and no escape sequences |

## Screenshots

The images in `docs/images` are real runs, rendered by
`scripts/screenshots/generate.sh`: it runs the release binary in a
pseudo-terminal, converts the colored output to HTML, and screenshots it with
headless Chrome. It needs python3, Google Chrome and ImageMagick 7. Live checks
reflect the network at capture time, so regenerated images will differ.
