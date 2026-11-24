param(
    [string] $ModulePath,
    [string] $BinaryPath
)
$ErrorActionPreference = 'Stop'
$work = Join-Path ([IO.Path]::GetTempPath()) ('WhereDNS module test ' + [Guid]::NewGuid())
$oldModulePath = $env:PSModulePath
$oldConfig = $env:XDG_CONFIG_HOME
$oldTheme = $env:WHEREDNS_THEME
$oldAnimate = $env:WHEREDNS_ANIMATE
function Assert($condition, $message) {
    if (-not $condition) { throw $message }
}
try {
    $stage = Join-Path $work 'WhereDNS'
    New-Item $stage -ItemType Directory -Force | Out-Null
    if ($ModulePath) {
        Copy-Item (Join-Path $ModulePath '*') $stage -Recurse
    } elseif ($BinaryPath) {
        Copy-Item (Join-Path $PSScriptRoot 'WhereDNS/*') $stage
        if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
            $target = 'x86_64-pc-windows-msvc'; $name = 'wheredns.exe'
        } elseif ($IsMacOS) {
            $target = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -eq 'Arm64') { 'aarch64-apple-darwin' } else { 'x86_64-apple-darwin' }
            $name = 'wheredns'
        } else {
            $target = 'x86_64-unknown-linux-gnu'; $name = 'wheredns'
        }
        $bin = Join-Path $stage "bin/$target"
        New-Item $bin -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $BinaryPath -Destination (Join-Path $bin $name)
    } else { throw 'Provide ModulePath or BinaryPath.' }

    # Simulate a Gallery installation in a path with spaces and lost Unix modes.
    if ($PSVersionTable.PSEdition -ne 'Desktop' -and -not $IsWindows) {
        Get-ChildItem (Join-Path $stage 'bin') -Recurse -File | ForEach-Object {
            & /bin/chmod a-x $_.FullName
            Assert ($LASTEXITCODE -eq 0) 'Could not prepare mode restoration test'
        }
    }
    $manifest = Test-ModuleManifest (Join-Path $stage 'WhereDNS.psd1')
    Assert ($manifest.ExportedFunctions.Keys -contains 'Invoke-WhereDns') 'Missing exported function'
    $env:PSModulePath = $work + [IO.Path]::PathSeparator + $oldModulePath
    $env:XDG_CONFIG_HOME = Join-Path $work 'config'
    $env:WHEREDNS_THEME = 'none'
    $env:WHEREDNS_ANIMATE = 'off'
    Remove-Module WhereDNS -ErrorAction SilentlyContinue
    # Invoke by exported name: exercise module auto-loading through PSModulePath.
    $version = Invoke-WhereDns --version
    Assert ($version -match '^wheredns \d+\.\d+\.\d+') 'Version argument was not forwarded'
    Assert ($LASTEXITCODE -eq 0) 'Success exit code not preserved'
    Assert (@((Get-Module WhereDNS).ExportedCommands.Keys).Count -eq 1) 'Private helper was exported'
    $help = Invoke-WhereDns --help
    Assert (($help -join "`n") -match '--json') 'Help argument was not forwarded'

    $subject = 'cafe ' + [char]0x00e9 + ' "quoted"; $literal'
    $json = "Subject: $subject`r`nX-Test: first`r`nX-Test: second`r`n`r`n" | Invoke-WhereDns headers --json
    Assert ($LASTEXITCODE -eq 0) 'Header pipeline failed'
    $parsed = $json | ConvertFrom-Json
    if ($parsed.analysis.subject -ne $subject) {
        # Show code points so an encoding fault is diagnosable from CI logs.
        $codes = { param($s) (([int[]][char[]][string]$s) | ForEach-Object { '{0:X4}' -f $_ }) -join ' ' }
        Write-Host ('expected: ' + (& $codes $subject))
        Write-Host ('actual:   ' + (& $codes $parsed.analysis.subject))
        Write-Host ('console out: ' + [Console]::OutputEncoding.CodePage + ', OutputEncoding: ' + $OutputEncoding.CodePage)
    }
    Assert ($parsed.analysis.subject -eq $subject) 'UTF-8/quoted pipeline input changed'
    Assert ($parsed.fields.Count -eq 3) 'Pipeline input was not forwarded intact'

    # Both a single argument containing spaces and multiple flags must survive.
    $null = Invoke-WhereDns config set checks 'where web dns'
    Assert ($LASTEXITCODE -eq 0) 'Argument containing spaces was split incorrectly'
    $configText = Get-Content (Join-Path $env:XDG_CONFIG_HOME 'wheredns/config') -Raw
    Assert ($configText -match 'where web dns') 'Config argument changed'
    $null = Invoke-WhereDns example.test dns --resolver 127.0.0.1:53 --json
    Assert ($LASTEXITCODE -eq 1) 'Failed check exit code not preserved'
    # Invalid option is handled by the native CLI, not PowerShell parameter binding.
    $null = Invoke-WhereDns --not-a-real-option 2>$null
    Assert ($LASTEXITCODE -eq 2) 'Invalid option exit code not preserved'

    $socket = New-Object System.Net.Sockets.UdpClient(0)
    try {
        $resolver = '127.0.0.1:' + $socket.Client.LocalEndPoint.Port
        $json = Invoke-WhereDns example.test dns A --resolver $resolver --allow-private --timeout 30 --deadline 1 --json
        Assert ($LASTEXITCODE -eq 130) 'Deadline exit code not preserved'
        Assert (-not ($json | ConvertFrom-Json).complete) 'Incomplete JSON lost'
    } finally { $socket.Dispose() }
    Write-Host 'PowerShell module smoke tests passed.'
} finally {
    Remove-Module WhereDNS -ErrorAction SilentlyContinue
    $env:PSModulePath = $oldModulePath
    $env:XDG_CONFIG_HOME = $oldConfig
    $env:WHEREDNS_THEME = $oldTheme
    $env:WHEREDNS_ANIMATE = $oldAnimate
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
$global:LASTEXITCODE = 0
