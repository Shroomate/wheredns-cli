# WhereDNS for PowerShell

A thin wrapper around the bundled Rust CLI. No separate Rust installation,
Homebrew, Scoop, or executable on PATH is required.

Once the module is published to the PowerShell Gallery:

```powershell
Install-Module WhereDNS -Scope CurrentUser
Invoke-WhereDns example.com dns A MX
Invoke-WhereDns example.com email --json | ConvertFrom-Json
Get-Content -Raw message.eml | Invoke-WhereDns headers --json
Invoke-WhereDns --help
$LASTEXITCODE
```

`Invoke-WhereDns` forwards CLI arguments. Quote arguments containing spaces and
URLs containing PowerShell metacharacters. Output remains CLI text (including
JSON when requested); stderr stays on the native error stream. Exit codes are
available through `$LASTEXITCODE`: 0 success, 1 failed check, 2 invalid input,
130 cancellation/deadline. A failed diagnostic does not throw a PowerShell
terminating error. Missing binaries and unsupported platforms do throw.
Pipeline input feeds stdin, primarily for `headers`; it does not run checks
for each domain in a pipeline. There is no global PATH modification or alias
that could shadow an existing `wheredns` installation.

Supported binary targets: Windows x64, Linux x64 (glibc), macOS Intel and Apple
silicon. Use 64-bit Windows PowerShell 5.1 or PowerShell 7.2+ on a supported OS.
Unix executable permissions are restored on first invocation because Gallery
package extraction may discard them. The `ping` check still needs the OS ping
utility. Other native runtime requirements are the same as the standalone CLI.

## Build and test

From the repository root, using the release archives and their SHA256SUMS:

```sh
python3 powershell/build-module.py --artifacts dist --output target/powershell --version 0.3.0
pwsh -NoProfile -File powershell/test-module.ps1 -ModulePath ./target/powershell/WhereDNS
pwsh -NoProfile -File powershell/package-module.ps1 -ModulePath ./target/powershell/WhereDNS -OutputPath ./target/nupkg
pwsh -NoProfile -File powershell/test-package.ps1 -PackageDirectory ./target/nupkg
```

The output directory must not already contain `WhereDNS`. The builder verifies
all four archives before creating the module; it never downloads or executes
remote installation code. Module versions follow stable three-part CLI release
versions. Binaries are build artifacts and are not committed to the repository.

For a native development smoke test (only this machine's binary is staged):

```powershell
./powershell/test-module.ps1 -BinaryPath ./target/release/wheredns
```

On Windows use `wheredns.exe`. CI runs this test on every supported runner and
also under Windows PowerShell 5.1. This partial test staging is not a distributable
Gallery package.

## Publish

The release workflow attaches `WhereDNS.VERSION.nupkg` to the GitHub release,
assembled from the same binaries as the standalone archives. It does not
publish to the Gallery automatically.

To publish the staged module, with an API key scoped to the package name:

```powershell
Test-ModuleManifest ./target/powershell/WhereDNS/WhereDNS.psd1
Publish-PSResource -Path ./target/powershell/WhereDNS -Repository PSGallery -ApiKey $env:PSGALLERY_API_KEY
```

Use Microsoft.PowerShell.PSResourceGet for publication. A Gallery account,
available/owned `WhereDNS` package name and API key are required. Keep keys out
of source control. Do not republish an existing module version; publish a new
CLI/module version instead. Installation examples above become usable after
the first successful Gallery publication.
