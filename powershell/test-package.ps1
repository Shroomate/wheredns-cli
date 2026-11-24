param([Parameter(Mandatory = $true)][string] $PackageDirectory)
$ErrorActionPreference = 'Stop'
$repository = 'WhereDNS-test-' + [Guid]::NewGuid()
$work = Join-Path ([IO.Path]::GetTempPath()) $repository
New-Item $work -ItemType Directory | Out-Null
Register-PSResourceRepository -Name $repository -Uri (Resolve-Path $PackageDirectory).Path -Trusted
try {
    # Exercise actual NuGet extraction through PSResourceGet without installing
    # into the user's permanent module directories or contacting the Gallery.
    Save-PSResource -Name WhereDNS -Repository $repository -Path $work -TrustRepository
    $manifest = @(Get-ChildItem $work -Filter WhereDNS.psd1 -Recurse)
    if ($manifest.Count -ne 1) { throw 'Expected one extracted module manifest' }
    & (Join-Path $PSScriptRoot 'test-module.ps1') -ModulePath $manifest[0].DirectoryName
} finally {
    Unregister-PSResourceRepository -Name $repository
    Remove-Item $work -Recurse -Force
}
$global:LASTEXITCODE = 0
