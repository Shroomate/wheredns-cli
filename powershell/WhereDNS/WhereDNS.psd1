@{
    RootModule = 'WhereDNS.psm1'
    ModuleVersion = '0.0.0' # Replaced by the package builder.
    GUID = '853d120d-6559-473b-a139-a4db44586130'
    Author = 'Shroomate'
    Description = 'DNS, email, web and network diagnostics using the bundled WhereDNS CLI.'
    Copyright = 'Copyright Shroomate. MIT license.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Invoke-WhereDns')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('DNS', 'Network', 'Diagnostics', 'Windows', 'Linux', 'macOS')
            LicenseUri = 'https://github.com/Shroomate/wheredns-cli/blob/main/LICENSE'
            ProjectUri = 'https://github.com/Shroomate/wheredns-cli'
        }
    }
}
