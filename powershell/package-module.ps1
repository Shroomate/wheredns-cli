param(
    [Parameter(Mandatory = $true)][string] $ModulePath,
    [Parameter(Mandatory = $true)][string] $OutputPath
)
$ErrorActionPreference = 'Stop'
$null = Test-ModuleManifest (Join-Path $ModulePath 'WhereDNS.psd1')
New-Item $OutputPath -ItemType Directory -Force | Out-Null
if (Get-Command Compress-PSResource -ErrorAction SilentlyContinue) {
    Compress-PSResource -Path $ModulePath -DestinationPath $OutputPath
} else {
    # Older PSResourceGet releases create packages by publishing to a local feed.
    # Always name that feed explicitly; never select a configured remote default.
    $repository = 'WhereDNS-build-' + [Guid]::NewGuid()
    Register-PSResourceRepository -Name $repository -Uri (Resolve-Path $OutputPath).Path -Trusted
    try {
        Publish-PSResource -Path $ModulePath -Repository $repository
    } finally {
        Unregister-PSResourceRepository -Name $repository
    }
}
