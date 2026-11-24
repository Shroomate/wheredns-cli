# Resolve lazily so Get-Help and Import-Module also work on unsupported hosts.
$script:Executable = $null
function Get-WhereDnsExecutable {
    if ($script:Executable) { return $script:Executable }

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        # Windows PowerShell 5.1 runs only on Windows. A 32-bit process cannot
        # use our x64 package; avoid depending on RuntimeInformation in .NET Framework.
        if (-not [Environment]::Is64BitProcess) {
            throw 'WhereDNS requires a 64-bit PowerShell process.'
        }
        $target = 'x86_64-pc-windows-msvc'
    } else {
        if ($PSVersionTable.PSVersion -lt [version]'7.2') {
            throw 'WhereDNS requires PowerShell 7.2 or later on PowerShell Core.'
        }
        $architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        if ($IsWindows -and $architecture -eq 'X64') {
            $target = 'x86_64-pc-windows-msvc'
        } elseif ($IsMacOS -and $architecture -eq 'Arm64') {
            $target = 'aarch64-apple-darwin'
        } elseif ($IsMacOS -and $architecture -eq 'X64') {
            $target = 'x86_64-apple-darwin'
        } elseif ($IsLinux -and $architecture -eq 'X64') {
            $target = 'x86_64-unknown-linux-gnu'
        } else {
            throw "WhereDNS does not bundle a binary for this OS/architecture ($architecture)."
        }
    }
    $name = if ($target -eq 'x86_64-pc-windows-msvc') { 'wheredns.exe' } else { 'wheredns' }
    $executable = Join-Path $PSScriptRoot "bin/$target/$name"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Bundled WhereDNS executable is missing: $executable. Reinstall the module."
    }
    if ($target -ne 'x86_64-pc-windows-msvc') {
        # NuGet extraction can drop Unix executable bits. Repair only our binary.
        & /bin/chmod u+x $executable
        if ($LASTEXITCODE -ne 0) { throw "Cannot make the bundled executable runnable: $executable" }
    }
    $script:Executable = $executable
    return $executable
}

function Invoke-WhereDns {
    <#
    .SYNOPSIS
    Runs the bundled WhereDNS diagnostic CLI.
    .DESCRIPTION
    Forwards arguments unchanged to WhereDNS. Use --help for CLI options and
    --json for JSON text, which can be piped to ConvertFrom-Json. Native exit
    codes are preserved in $LASTEXITCODE. Pipeline input is sent to stdin for
    the headers command; it does not iterate over domain names.
    .EXAMPLE
    Invoke-WhereDns example.com dns A MX
    .EXAMPLE
    Invoke-WhereDns example.com email --json | ConvertFrom-Json
    .EXAMPLE
    Get-Content -Raw message.eml | Invoke-WhereDns headers --json
    #>
    # Deliberately a simple function: advanced parameter binding would consume
    # CLI flags such as --verbose instead of forwarding the original arguments.
    $executable = Get-WhereDnsExecutable
    # Windows PowerShell turns redirected native stderr into error records.
    # Keep those non-terminating so native exit codes remain the contract.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    # The CLI writes UTF-8. Windows PowerShell 5.1 decodes native output with
    # the console code page (often 437), so switch to UTF-8 for this call only.
    # Hosts without a console can refuse the change; output then stays as-is.
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    # Windows PowerShell 5.1 encodes stdin for native commands with the global
    # $OutputEncoding (ASCII by default) and ignores a module-local one, so set
    # the global for this call only and restore it afterwards.
    $previousInputEncoding = $global:OutputEncoding
    $global:OutputEncoding = $utf8
    $previousEncoding = $null
    try {
        if ([Console]::OutputEncoding.CodePage -ne 65001) {
            $previousEncoding = [Console]::OutputEncoding
            [Console]::OutputEncoding = $utf8
        }
    } catch { $previousEncoding = $null }
    try {
        if ($MyInvocation.ExpectingInput) {
            $input | & $executable @args
        } else {
            & $executable @args
        }
        $global:LASTEXITCODE = $LASTEXITCODE
    } finally {
        $global:OutputEncoding = $previousInputEncoding
        if ($previousEncoding) {
            try { [Console]::OutputEncoding = $previousEncoding } catch { }
        }
    }
}

Export-ModuleMember -Function Invoke-WhereDns
