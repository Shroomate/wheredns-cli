# Releasing

1. Set `version` in `Cargo.toml`, run `cargo build` to update `Cargo.lock`, and
   merge to `main`.
2. Tag and push:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. `.github/workflows/release.yml` builds these archives, checks that the tag
   matches `Cargo.toml`, and publishes a GitHub release with `SHA256SUMS`,
   `wheredns.rb` and `wheredns.json`:

   | Target | Archive |
   |---|---|
   | `aarch64-apple-darwin` | `.tar.gz` |
   | `x86_64-apple-darwin` | `.tar.gz` |
   | `x86_64-unknown-linux-gnu` | `.tar.gz` |
   | `x86_64-pc-windows-msvc` | `.zip` |

   Each archive contains `wheredns` (or `wheredns.exe`), `README.md` and `LICENSE`.

4. Copy the release's `wheredns.rb` to `Formula/wheredns.rb` in
   [Shroomate/homebrew-tap](https://github.com/Shroomate/homebrew-tap) and push.
   Check it with:

   ```sh
   brew update
   brew install shroomate/tap/wheredns
   brew test wheredns
   brew audit --strict --online shroomate/tap/wheredns
   ```

`wheredns.json` is a Scoop manifest for a Scoop bucket.

To render a template by hand from a downloaded `SHA256SUMS`:

```sh
packaging/render.sh 0.1.0 SHA256SUMS packaging/wheredns.rb.in > wheredns.rb
```
