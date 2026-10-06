# Shared offline package validation. Compatible with Windows PowerShell 5.1.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PackageFiles = @('av.exe', 'install.ps1', 'uninstall.ps1', 'package-common.ps1', 'README.md')

function Assert-WindowsHost {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Installation and removal require Windows.'
    }
    $architecture = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
    if ($architecture -ne 'AMD64') { throw 'This package supports x64 Windows only.' }
}

function Get-PlainPath([string] $Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'Use an absolute filesystem path.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($full -eq [IO.Path]::GetPathRoot($full).TrimEnd([IO.Path]::DirectorySeparatorChar)) {
        throw 'The filesystem root is not an installation directory.'
    }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Links and reparse points are not supported: $current"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $full
}

function Assert-SeparatePaths([string] $First, [string] $Second) {
    $a = $First.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $b = $Second.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($a.StartsWith($b, [StringComparison]::OrdinalIgnoreCase) -or
        $b.StartsWith($a, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The source package and installation directory must not overlap.'
    }
}

function Assert-X64ConsoleExecutable([string] $Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        $length = $stream.Length
        if ($length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw 'The input must be an x64 Windows console executable.'
        }
        $stream.Position = 0x3c
        $peOffset = [long] $reader.ReadUInt32()
        if ($peOffset -lt 64 -or $peOffset -gt $length - 24) {
            throw 'Invalid Windows PE header offset.'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'The input must be an x64 Windows PE executable.'
        }
        $sections = $reader.ReadUInt16()
        $stream.Position = $peOffset + 20
        $optionalSize = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        if ($sections -eq 0 -or $sections -gt 96 -or ($characteristics -band 0x0002) -eq 0 -or
            ($characteristics -band 0x2000) -ne 0) {
            throw 'The input must be an executable, not a DLL.'
        }
        $optionalOffset = $peOffset + 24
        $sectionOffset = $optionalOffset + $optionalSize
        $sectionEnd = $sectionOffset + [long] $sections * 40
        if ($optionalSize -lt 112 -or $sectionEnd -gt $length) {
            throw 'Truncated Windows PE headers.'
        }
        $stream.Position = $optionalOffset
        if ($reader.ReadUInt16() -ne 0x020b) { throw 'The input must use the PE32+ format.' }
        $stream.Position = $optionalOffset + 16
        $entry = [long] $reader.ReadUInt32()
        $stream.Position = $optionalOffset + 56
        $imageSize = [long] $reader.ReadUInt32()
        $headerSize = [long] $reader.ReadUInt32()
        $stream.Position = $optionalOffset + 68
        $subsystem = $reader.ReadUInt16()
        if ($entry -eq 0 -or $subsystem -ne 3 -or $headerSize -lt $sectionEnd -or
            $headerSize -gt $length -or $imageSize -lt $headerSize -or $entry -ge $imageSize) {
            throw 'Invalid Windows console executable header.'
        }
        $entryInFile = $false
        for ($i = 0; $i -lt $sections; $i++) {
            $stream.Position = $sectionOffset + [long] $i * 40 + 8
            $virtualSize = [long] $reader.ReadUInt32()
            $virtualAddress = [long] $reader.ReadUInt32()
            $rawSize = [long] $reader.ReadUInt32()
            $rawOffset = [long] $reader.ReadUInt32()
            if ($virtualAddress + $virtualSize -gt $imageSize -or
                ($rawSize -ne 0 -and ($rawOffset -lt $headerSize -or $rawOffset -gt $length - $rawSize))) {
                throw 'Invalid Windows PE section bounds.'
            }
            if ($rawSize -ne 0 -and $entry -ge $virtualAddress -and
                $entry -lt $virtualAddress + $rawSize) { $entryInFile = $true }
        }
        if (-not $entryInFile) { throw 'The Windows PE entry point has no file-backed section.' }
    } finally {
        $reader.Dispose()
    }
}

function Read-Package([string] $Directory, [switch] $Installed) {
    $null = Get-PlainPath $Directory
    $allowed = $PackageFiles + 'package.json'
    if ($Installed) { $allowed += 'installed.json' }
    $actual = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($actual.Count -ne $allowed.Count) { throw "Unexpected package contents: $Directory" }
    foreach ($item in $actual) {
        if ($item.PSIsContainer -or $item.Name -cnotin $allowed -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected package entry: $($item.Name)"
        }
    }
    $manifest = Get-Content -LiteralPath (Join-Path $Directory 'package.json') -Raw | ConvertFrom-Json
    if ($manifest.format -cne 'agents-vault.windows-direct.v1' -or
        $manifest.target -cne 'windows-x64' -or
        $manifest.version -notmatch '^\d+\.\d+\.\d+$') {
        throw 'Unsupported Windows package manifest.'
    }
    $null = [version] $manifest.version
    if (@($manifest.files.PSObject.Properties).Count -ne $PackageFiles.Count) {
        throw 'The package manifest must list exactly the expected files.'
    }
    foreach ($name in $PackageFiles) {
        $expected = $manifest.files.$name
        if ($expected -notmatch '^[0-9a-f]{64}$') { throw "Invalid package hash: $name" }
        $hash = (Get-FileHash -LiteralPath (Join-Path $Directory $name) -Algorithm SHA256).Hash
        if ($hash -ine $expected) { throw "Package hash mismatch: $name" }
    }
    Assert-X64ConsoleExecutable (Join-Path $Directory 'av.exe')
    if ($Installed) {
        $marker = Get-Content -LiteralPath (Join-Path $Directory 'installed.json') -Raw | ConvertFrom-Json
        if ($marker.format -cne 'agents-vault.windows-direct.install.v1') {
            throw 'This directory is not an Agents Vault CLI installation.'
        }
    }
    return $manifest
}

function Write-PackageJson($Value, [string] $Path) {
    $json = $Value | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}
