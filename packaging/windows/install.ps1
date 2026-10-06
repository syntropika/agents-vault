#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $InstallDirectory = (Join-Path $env:LOCALAPPDATA 'Programs\AgentsVault\cli')
)

. (Join-Path $PSScriptRoot 'package-common.ps1')
Assert-WindowsHost
$source = Get-PlainPath $PSScriptRoot
$destination = Get-PlainPath $InstallDirectory
Assert-SeparatePaths $source $destination
$package = Read-Package $source
$existing = Test-Path -LiteralPath $destination
if ($existing) {
    $previous = Read-Package $destination -Installed
    if ([version] $package.version -lt [version] $previous.version) {
        throw 'Downgrade refused.'
    }
}

$parent = [IO.Path]::GetDirectoryName($destination)
$null = [IO.Directory]::CreateDirectory($parent)
$stage = Join-Path $parent ('.agents-vault-stage-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $parent ('.agents-vault-previous-' + [guid]::NewGuid().ToString('N'))
$published = $false
try {
    $null = [IO.Directory]::CreateDirectory($stage)
    foreach ($name in ($PackageFiles + 'package.json')) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $stage $name)
    }
    $null = Read-Package $stage
    Write-PackageJson @{ format = 'agents-vault.windows-direct.install.v1' } (Join-Path $stage 'installed.json')
    if ($existing) { [IO.Directory]::Move($destination, $backup) }
    try {
        [IO.Directory]::Move($stage, $destination)
        $published = $true
    } catch {
        if ($existing -and -not (Test-Path -LiteralPath $destination)) {
            [IO.Directory]::Move($backup, $destination)
        }
        throw
    }
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
if ($published -and (Test-Path -LiteralPath $backup)) {
    try { Remove-Item -LiteralPath $backup -Recurse -Force } catch {
        Write-Warning "Installed successfully; an old copy remains at $backup. Close running av processes before removing it."
    }
}
Write-Host "Installed Agents Vault CLI $($package.version) at $destination"
Write-Host "Run: & '$(Join-Path $destination 'av.exe')' --help"
Write-Host 'To use av by name, add the installation directory to your user PATH in Windows Settings, then open a new terminal.'
