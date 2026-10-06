#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Binary,
    [switch] $PortableValidationOnly
)

. (Join-Path $PSScriptRoot 'package-common.ps1')
if (-not $PortableValidationOnly) { Assert-WindowsHost }
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('Agents Vault package test ' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$priorPackagePublic = [Environment]::GetEnvironmentVariable('AV_PACKAGE_TEST', 'Process')
$priorImportedPublic = [Environment]::GetEnvironmentVariable('AV_IMPORTED_PUBLIC', 'Process')

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Rejected([scriptblock] $Action, [string] $Message) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-True $rejected $Message
}

function Assert-InvalidPeVariant([string] $Name, [scriptblock] $Mutate) {
    $variant = Join-Path $root "$Name.exe"
    [IO.File]::Copy($binaryPath, $variant)
    $writer = New-Object IO.BinaryWriter([IO.File]::OpenWrite($variant))
    try { & $Mutate $writer $peOffset } finally { $writer.Dispose() }
    Assert-Rejected { Assert-X64ConsoleExecutable $variant } "Invalid PE variant was accepted: $Name"
    return $variant
}

try {
    # Require av run to supply both values rather than inheriting them.
    [Environment]::SetEnvironmentVariable('AV_PACKAGE_TEST', $null, 'Process')
    [Environment]::SetEnvironmentVariable('AV_IMPORTED_PUBLIC', $null, 'Process')
    $output = Join-Path $root 'archives'
    $packages = @{}
    # Portable mode cannot run the Windows binary; its version is synthetic.
    $binaryVersion = if ($PortableValidationOnly) { '0.1.0' } else {
        $reportedVersion = @(& $binaryPath --version)
        Assert-True ($LASTEXITCODE -eq 0 -and $reportedVersion.Count -eq 1 -and
            $reportedVersion[0] -match '^av (\d+\.\d+\.\d+)$') 'The CLI did not report a semantic version.'
        $Matches[1]
    }
    & (Join-Path $PSScriptRoot 'make-package.ps1') -Binary $binaryPath -Version $binaryVersion -OutputDirectory $output
    $archive = Join-Path $output "agents-vault-$binaryVersion-windows-x64.zip"
    $expected = (Get-Content -LiteralPath ($archive + '.sha256') -Raw).Split(' ')[0]
    Assert-True ((Get-FileHash -LiteralPath $archive).Hash -ieq $expected) 'Archive checksum mismatch.'
    $packages['base'] = Join-Path $root 'base'
    Expand-Archive -LiteralPath $archive -DestinationPath $packages['base']
    $null = Read-Package $packages['base']
    $packages['higher'] = Join-Path $root 'higher'
    Copy-Item -LiteralPath $packages['base'] -Destination $packages['higher'] -Recurse
    $higherVersion = ([version] $binaryVersion).Build + 1
    $higherVersion = "$(([version] $binaryVersion).Major).$(([version] $binaryVersion).Minor).$higherVersion"
    $higherManifest = Get-Content -LiteralPath (Join-Path $packages['higher'] 'package.json') -Raw | ConvertFrom-Json
    $higherManifest.version = $higherVersion
    Write-PackageJson $higherManifest (Join-Path $packages['higher'] 'package.json')
    $null = Read-Package $packages['higher']
    Assert-Rejected {
        & (Join-Path $PSScriptRoot 'make-package.ps1') -Binary $binaryPath -Version $binaryVersion -OutputDirectory $output
    } 'Building a package must not overwrite an existing archive.'
    if (-not $PortableValidationOnly) {
        Assert-Rejected {
            & (Join-Path $PSScriptRoot 'make-package.ps1') -Binary $binaryPath -Version $higherVersion -OutputDirectory $output
        } 'A package with a version different from its executable was accepted.'
    }
    $reader = New-Object IO.BinaryReader([IO.File]::OpenRead($binaryPath))
    try {
        $reader.BaseStream.Position = 0x3c
        $peOffset = [long] $reader.ReadUInt32()
    } finally { $reader.Dispose() }
    $gui = Assert-InvalidPeVariant 'gui' {
        param($writer, $offset)
        $writer.BaseStream.Position = $offset + 24 + 68
        $writer.Write([byte] 2)
    }
    $null = Assert-InvalidPeVariant 'dll' {
        param($writer, $offset)
        $writer.BaseStream.Position = $offset + 23
        $writer.Write([byte] 0x20)
    }
    $null = Assert-InvalidPeVariant 'wrong-machine' {
        param($writer, $offset)
        $writer.BaseStream.Position = $offset + 4
        $writer.Write([byte] 0x4c)
    }
    $null = Assert-InvalidPeVariant 'wrong-optional-format' {
        param($writer, $offset)
        $writer.BaseStream.Position = $offset + 25
        $writer.Write([byte] 1)
    }
    $null = Assert-InvalidPeVariant 'too-many-sections' {
        param($writer, $offset)
        $writer.BaseStream.Position = $offset + 6
        $writer.Write([byte] 0xff)
        $writer.Write([byte] 0xff)
    }
    $null = Assert-InvalidPeVariant 'truncated' {
        param($writer, $offset)
        $writer.BaseStream.SetLength($offset + 24)
    }
    $null = Assert-InvalidPeVariant 'bad-header-offset' {
        param($writer, $offset)
        $writer.BaseStream.Position = 0x3f
        $writer.Write([byte] 0x7f)
    }
    Assert-Rejected {
        & (Join-Path $PSScriptRoot 'make-package.ps1') -Binary $gui -Version $binaryVersion -OutputDirectory (Join-Path $root 'reject-gui')
    } 'The package builder accepted a GUI executable.'
    $rehashed = Join-Path $root 'rehashed-gui'
    Copy-Item -LiteralPath $packages['base'] -Destination $rehashed -Recurse
    Copy-Item -LiteralPath $gui -Destination (Join-Path $rehashed 'av.exe') -Force
    $rehashedManifest = Get-Content -LiteralPath (Join-Path $rehashed 'package.json') -Raw | ConvertFrom-Json
    $rehashedManifest.files.'av.exe' = (Get-FileHash -LiteralPath (Join-Path $rehashed 'av.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-PackageJson $rehashedManifest (Join-Path $rehashed 'package.json')
    Assert-Rejected { Read-Package $rehashed } 'A rehashed GUI executable was accepted.'
    $damaged = Join-Path $root 'damaged'
    Copy-Item -LiteralPath $packages['higher'] -Destination $damaged -Recurse
    [IO.File]::AppendAllText((Join-Path $damaged 'av.exe'), 'synthetic corruption')
    Assert-Rejected { Read-Package $damaged } 'A damaged executable was accepted.'
    $extra = Join-Path $packages['base'] 'unexpected.txt'
    [IO.File]::WriteAllText($extra, 'synthetic extra file')
    Assert-Rejected { Read-Package $packages['base'] } 'Unexpected package files were accepted.'
    Remove-Item -LiteralPath $extra
    if ($PortableValidationOnly) {
        Write-Host 'Portable archive and PE validation passed. Binary version matching and native installation/CLI execution were not tested.'
        return
    }

    $install = Join-Path $root 'Programs\AgentsVault CLI'
    $retained = Join-Path $root 'synthetic-vault-marker.txt'
    [IO.File]::WriteAllText($retained, 'retain this synthetic user data')
    $before = (Get-FileHash -LiteralPath $retained).Hash
    Assert-Rejected {
        & (Join-Path $packages['base'] 'install.ps1') -InstallDirectory $packages['base']
    } 'Installation accepted an overlapping source and destination.'
    $occupied = Join-Path $root 'occupied directory'
    $null = [IO.Directory]::CreateDirectory($occupied)
    $userFile = Join-Path $occupied 'user-file.txt'
    [IO.File]::WriteAllText($userFile, 'preserve me')
    Assert-Rejected {
        & (Join-Path $packages['base'] 'install.ps1') -InstallDirectory $occupied
    } 'Installation accepted an unrelated occupied directory.'
    Assert-True (Test-Path -LiteralPath $userFile) 'Installation removed an unrelated file.'
    & (Join-Path $packages['base'] 'install.ps1') -InstallDirectory $install
    $exe = Join-Path $install 'av.exe'
    & $exe --help
    Assert-True ($LASTEXITCODE -eq 0) 'The installed CLI did not start.'
    & $exe run --help
    Assert-True ($LASTEXITCODE -eq 0) 'The direct run entry point failed.'
    $config = Join-Path $root 'av.toml'
    [IO.File]::WriteAllText($config, @'
schema = 2
[project]
id = "windows-package-smoke"
[values.AV_PACKAGE_TEST]
type = "string"
value = "offline package value"
'@)
    & $exe --config $config check
    Assert-True ($LASTEXITCODE -eq 0) 'The installed CLI could not validate public configuration.'
    $delivered = & $exe --config $config run -- $env:ComSpec /d /c set AV_PACKAGE_TEST
    Assert-True ($LASTEXITCODE -eq 0 -and $delivered -contains 'AV_PACKAGE_TEST=offline package value') 'Direct environment delivery failed.'
    $dotenv = Join-Path $root 'public.env'
    $importConfig = Join-Path $root 'imported.toml'
    $importVault = Join-Path $root 'import-should-not-create-vault.db'
    [IO.File]::WriteAllText($dotenv, "AV_IMPORTED_PUBLIC=imported offline value`n")
    & $exe --config $importConfig --vault $importVault import-env $dotenv --project windows-package-import --public AV_IMPORTED_PUBLIC
    Assert-True ($LASTEXITCODE -eq 0) 'Public-only .env import failed.'
    Assert-True (-not (Test-Path -LiteralPath $importVault)) 'Public-only import created a vault.'
    & $exe --config $importConfig --vault $importVault check
    Assert-True ($LASTEXITCODE -eq 0) 'Imported public configuration failed validation.'
    $imported = & $exe --config $importConfig --vault $importVault run -- $env:ComSpec /d /c set AV_IMPORTED_PUBLIC
    Assert-True ($LASTEXITCODE -eq 0 -and $imported -contains 'AV_IMPORTED_PUBLIC=imported offline value') 'Imported public value was not delivered.'
    $secretConfig = Join-Path $root 'secret-template.toml'
    $secretTemplate = Join-Path $root 'secret-placeholder.env'
    $unusedVault = Join-Path $root 'template-should-not-create-vault.db'
    [IO.File]::WriteAllText($secretConfig, @'
schema = 2
[project]
id = "windows-package-smoke"
[values.AV_TEMPLATE_SECRET]
type = "string"
secret = "secret://windows-package-smoke/token"
'@)
    & $exe --config $secretConfig --vault $unusedVault placeholders --output $secretTemplate
    Assert-True ($LASTEXITCODE -eq 0) 'Secret placeholder generation failed.'
    Assert-True ((Get-Content -LiteralPath $secretTemplate -Raw).Contains('<AV_SECRET:windows-package-smoke/token>')) 'The secret reference was not rendered as a placeholder.'
    Assert-True (-not (Test-Path -LiteralPath $unusedVault)) 'Placeholder generation created a vault.'
    & $exe --config $config run -- $env:ComSpec /d /c exit 23
    Assert-True ($LASTEXITCODE -eq 23) 'Direct child exit status failed.'
    & (Join-Path $packages['base'] 'install.ps1') -InstallDirectory $install
    & (Join-Path $packages['higher'] 'install.ps1') -InstallDirectory $install
    Assert-True ((Read-Package $install -Installed).version -eq $higherVersion) 'Synthetic upgrade manifest version mismatch.'
    Assert-True ((Get-FileHash -LiteralPath $exe).Hash -eq
        (Get-FileHash -LiteralPath (Join-Path $packages['higher'] 'av.exe')).Hash) 'Synthetic update did not install its package binary.'
    $installedHash = (Get-FileHash -LiteralPath $exe).Hash
    Assert-Rejected {
        & (Join-Path $packages['base'] 'install.ps1') -InstallDirectory $install
    } 'An unapproved downgrade succeeded.'
    Assert-Rejected {
        & (Join-Path $damaged 'install.ps1') -InstallDirectory $install
    } 'A damaged update succeeded.'
    Assert-True ((Get-FileHash -LiteralPath $exe).Hash -eq $installedHash) 'A rejected update changed the installed binary.'
    $junction = Join-Path $root 'installation junction'
    $null = New-Item -ItemType Junction -Path $junction -Target $install
    try {
        Assert-Rejected {
            & (Join-Path $packages['higher'] 'install.ps1') -InstallDirectory $junction
        } 'Installation accepted a junction.'
        Assert-Rejected {
            & (Join-Path $packages['higher'] 'uninstall.ps1') -InstallDirectory $junction
        } 'Uninstall accepted a junction.'
    } finally { [IO.Directory]::Delete($junction) }
    Assert-True (Test-Path -LiteralPath $exe) 'A rejected junction operation changed the installation.'
    $extra = Join-Path $install 'user-file.txt'
    [IO.File]::WriteAllText($extra, 'preserve me')
    Assert-Rejected {
        & (Join-Path $install 'uninstall.ps1')
    } 'Uninstall accepted an unexpected user file.'
    Assert-True (Test-Path -LiteralPath $extra) 'Uninstall removed unexpected data.'
    Remove-Item -LiteralPath $extra
    & (Join-Path $install 'uninstall.ps1')
    Assert-True (-not (Test-Path -LiteralPath $install)) 'Uninstall left the installation directory.'
    & (Join-Path $packages['higher'] 'uninstall.ps1') -InstallDirectory $install
    Assert-True ((Get-FileHash -LiteralPath $retained).Hash -eq $before) 'Install/update/uninstall changed unrelated user data.'
    $global:LASTEXITCODE = 0
    Write-Host 'Native Windows package lifecycle and public direct CLI smoke passed. The higher-version install used synthetic manifest metadata with the same binary; a distinct binary upgrade was not tested. Interactive secret release requires test-direct-console.ps1 in a native console.'
} finally {
    [Environment]::SetEnvironmentVariable('AV_PACKAGE_TEST', $priorPackagePublic, 'Process')
    [Environment]::SetEnvironmentVariable('AV_IMPORTED_PUBLIC', $priorImportedPublic, 'Process')
    Remove-Item -LiteralPath $root -Recurse -Force
}
