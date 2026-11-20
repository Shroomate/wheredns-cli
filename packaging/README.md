# Release preparation (no release published)

CI builds native Linux x86_64, macOS ARM64/Intel and Windows x86_64 binaries.
For an explicitly approved version, download successful CI artifacts, extract and
run --version on each platform, archive binary with README and license, compute
SHA-256 for each archive, and attach those exact archives to a versioned release.
Do not advertise installation until all artifacts and hashes are verified.

Homebrew: render wheredns.rb.in with the version, actual release archive URLs and
SHA-256 values. Test locally with brew install --build-from-source or the verified
bottle archive before committing the formula to a separate tap.
Windows: distribute a ZIP containing wheredns.exe and README; Scoop manifest uses
that verified ZIP URL/hash, bin wheredns.exe and version. Submit WinGet only after
a published immutable version exists. No registry or tap is published by CI.
