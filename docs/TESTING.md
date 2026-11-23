# Testing

Every suite runs offline. Network behavior is tested against loopback
fixtures: a scripted DNS resolver, local HTTP servers, a saved email header
and a scratch config directory. No test depends on the public internet, so
results don't change with DNS or registry data.

CI runs the Rust suites (unit, CLI contract, scenarios, regressions) on Linux,
Windows, macOS ARM64 and macOS Intel for every push and pull request. The two
Python suites run on Linux only: their fixtures assume a Unix binary path and a
shell-script `ping`. `ping_nonzero_exit_fails_even_with_a_reply` is Unix-only
for the same reason.

The counts below are what `cargo test -- --list` and the Python scripts report;
update them when you add or remove a case.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked                      # unit, CLI contract, scenario and regression tests
cargo build --locked
python3 tests/loopback_regressions.py    # loopback DNS/HTTP edge cases
python3 tests/dns_eligibility.py         # which DNS answers count as evidence
```

## Cases

| Suite | Cases | What it covers |
|---|---:|---|
| Unit (`src/`) | 32 | DNS wire parsing and hostile replies, owner-bound evidence, header parsing, hostile dates, URL normalization, address policy, ping output on each platform, provider attribution at label boundaries, UTF-8-safe policy prefixes, DKIM key structure, propagation agreement rules, RDAP candidates and referral identity, HTTP header blocks, TLS error text, settings validation and config paths, theme escape output, panel width and layout |
| CLI contract (`tests/cli.rs`) | 7 | `--help`/`--version`, usage errors, JSON schema, redirect evidence on HTTP failure, NXDOMAIN parent-zone lookup, NODATA labelling, terminal DNS layout |
| Scenarios (`tests/scenarios.rs`) | 14 | End-to-end runs of the binary, listed below |
| Regressions (`tests/regressions.rs`) | 15 | End-to-end runs for the 2026-11-22 review findings, listed below |
| Loopback regressions (`tests/loopback_regressions.py`) | 10 | REFUSED, SERVFAIL, truncated TCP, malformed PTR, unrelated owners, nonzero ping, invalid and oversized headers |
| DNS eligibility (`tests/dns_eligibility.py`) | 30 | Which answers (by rcode, class and owner) count as evidence for each check |
| **Total** | **108** | |

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

### Regressions

| Test | Checks that |
|---|---|
| `non_ascii_txt_never_crashes_the_email_check` | Non-ASCII TXT data is compared safely and never panics |
| `records_at_unrelated_owners_are_not_evidence` | A TXT record at another owner is not this domain's SPF |
| `policy_version_impostors_and_keyless_dkim_are_not_positives` | `v=DMARC10`, `v=STSv10`, keyless or malformed DKIM records are not reported as published; real and revoked keys still are |
| `email_nxdomain_is_a_result` | NXDOMAIN in the email check exits 0 |
| `one_failed_dkim_selector_fails_the_email_check` | One SERVFAIL selector fails the check |
| `servfail_fails_blacklist_and_subdomains_but_keeps_rows` | Failed list and name lookups fail the check and keep their rows |
| `null_mx_skips_the_domain_blacklist` | A null MX sends no blocklist or website-address queries |
| `ping_nonzero_exit_fails_even_with_a_reply` | A nonzero `ping` exit fails the check and keeps the samples (Unix) |
| `overlapping_checks_never_ask_the_same_question_twice` | `all` sends each DNS question once, even while the first answer is in flight |
| `concurrency_bounds_in_flight_operations_per_check` | `--concurrency N` means at most N outstanding queries per check |
| `cancelled_blacklist_keeps_answered_lists` | A deadline keeps answered lists and marks the rest pending |
| `headers_honor_the_deadline_on_stalled_input` | `headers --deadline` stops on stdin that never closes (exit 130) |
| `http_interim_incomplete_and_oversized_responses` | 103 is skipped for the final 200; unfinished or over-64-KiB headers fail |
| `five_redirects_are_followed_and_a_sixth_is_refused` | Exactly five redirects are followed |
| `config_path_works_without_home` | `config path` resolves from `%APPDATA%` when `HOME` is unset |

## Screenshots

The images in `docs/images` are real runs, rendered by
`scripts/screenshots/generate.sh`: it runs the release binary in a
pseudo-terminal, converts the colored output to HTML, and screenshots it with
headless Chrome. It needs python3, Google Chrome and ImageMagick 7. Live checks
reflect the network at capture time, so regenerated images will differ.
