#Requires -Version 5.1
[CmdletBinding()]
param([string] $InstallDirectory = $PSScriptRoot)

. (Join-Path $PSScriptRoot 'package-common.ps1')
Assert-WindowsHost
$destination = Get-PlainPath $InstallDirectory
if (-not (Test-Path -LiteralPath $destination)) {
    Write-Host 'Agents Vault CLI is already absent.'
    return
}
$null = Read-Package $destination -Installed
# Rename first so a failure to move an in-use installation leaves it intact.
$removed = Join-Path ([IO.Path]::GetDirectoryName($destination)) ('.agents-vault-removed-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::Move($destination, $removed)
try {
    Remove-Item -LiteralPath $removed -Recurse -Force
} catch {
    Write-Warning "The CLI was removed from its installation path; close av and remove the remaining files at $removed."
    throw
}
Write-Host 'Agents Vault CLI removed. Vaults, recovery files, project files, and user PATH were preserved.'
