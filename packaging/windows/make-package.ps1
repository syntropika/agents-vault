#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Binary,
    [Parameter(Mandatory = $true)] [ValidatePattern('^\d+\.\d+\.\d+$')] [string] $Version,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory
)

. (Join-Path $PSScriptRoot 'package-common.ps1')
$null = [version] $Version
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
Assert-X64ConsoleExecutable $binaryPath
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $reportedVersion = @(& $binaryPath --version)
    if ($LASTEXITCODE -ne 0 -or $reportedVersion.Count -ne 1 -or
        $reportedVersion[0] -cne "av $Version") {
        throw "The executable must report 'av $Version' from --version."
    }
}

$output = [IO.Path]::GetFullPath($OutputDirectory)
$null = [IO.Directory]::CreateDirectory($output)
$archive = Join-Path $output "agents-vault-$Version-windows-x64.zip"
if ((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath ($archive + '.sha256'))) {
    throw 'The output archive or checksum already exists.'
}
$stage = Join-Path $output ('.agents-vault-package-' + [guid]::NewGuid().ToString('N'))
try {
    $null = [IO.Directory]::CreateDirectory($stage)
    Copy-Item -LiteralPath $binaryPath -Destination (Join-Path $stage 'av.exe')
    foreach ($name in ($PackageFiles | Where-Object { $_ -ne 'av.exe' })) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage $name)
    }
    $hashes = [ordered] @{}
    foreach ($name in $PackageFiles) {
        $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Write-PackageJson ([ordered] @{
        format = 'agents-vault.windows-direct.v1'
        target = 'windows-x64'
        version = $Version
        files = $hashes
    }) (Join-Path $stage 'package.json')
    $null = Read-Package $stage
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($archive + '.sha256', "$hash  $([IO.Path]::GetFileName($archive))`n", (New-Object Text.UTF8Encoding($false)))
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
Write-Host $archive
