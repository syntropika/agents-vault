#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Binary,
    [switch] $Interactive
)

# rpassword opens CONIN$/CONOUT$ on Windows. This test intentionally requires
# a real native console; redirected stdin cannot exercise secret entry.
. (Join-Path $PSScriptRoot 'package-common.ps1')
Assert-WindowsHost
if (-not $Interactive) {
    throw 'Run this test with -Interactive from a native Windows console. It will wait for hidden av prompts.'
}

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('Agents Vault direct console ' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$config = Join-Path $root 'av.toml'
$vault = Join-Path $root 'vault.db'
$restoredVault = Join-Path $root 'restored.db'
$recovery = Join-Path $root 'recovery.txt'
$newRecovery = Join-Path $root 'new-recovery.txt'
$backup = Join-Path $root 'vault.backup'
$marker = Join-Path $root 'started.txt'
$nativeCommand = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
$priorSecret = [Environment]::GetEnvironmentVariable('AV_TEST_SECRET', 'Process')
$priorPublic = [Environment]::GetEnvironmentVariable('AV_PUBLIC_LABEL', 'Process')

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Succeeded([int] $Code, [string] $Stage) {
    Assert-True ($Code -eq 0) "$Stage failed with exit code $Code."
}

function Assert-Failed([int] $Code, [string] $Stage) {
    Assert-True ($Code -ne 0) "$Stage unexpectedly succeeded."
}

function Invoke-Av([string] $VaultPath, [string[]] $CliArguments) {
    # Only fixed command names, paths, and variable names enter argv. The av
    # process reads passphrases, the synthetic value, and approval from CONIN$.
    & $binaryPath --config $config --vault $VaultPath @CliArguments | Out-Host
    return [int] $LASTEXITCODE
}

$locationPushed = $false
try {
    # Prevent inherited values from making the child-delivery check pass.
    [Environment]::SetEnvironmentVariable('AV_TEST_SECRET', $null, 'Process')
    [Environment]::SetEnvironmentVariable('AV_PUBLIC_LABEL', $null, 'Process')
    [IO.File]::WriteAllText($config, @'
schema = 2
[project]
id = "windows-direct-console"
[values.AV_TEST_SECRET]
type = "string"
secret = "secret://windows-direct-console/AV_TEST_SECRET"
[values.AV_PUBLIC_LABEL]
type = "string"
value = "public-ok"
'@)
    Push-Location $root
    $locationPushed = $true
    # The child writes a marker only after it receives the secret and the
    # expected public project value. The secret is never printed or in argv.
    $task = @($nativeCommand, '/d', '/c', 'if defined AV_TEST_SECRET (if "%AV_PUBLIC_LABEL%"=="public-ok" (echo started>started.txt) else (exit /b 43)) else (exit /b 42)')

    Write-Host 'Use only an invented temporary passphrase and secret. Enter them at the hidden av prompts.'
    Write-Host 'Remember the first passphrase through backup/restore. The recovery step asks for a different new passphrase.'
    Assert-Succeeded (Invoke-Av $vault @('status')) 'Initial status'
    Assert-Succeeded (Invoke-Av $vault @('setup', '--direct', '--recovery-file', $recovery)) 'Direct setup'
    Assert-True ((Test-Path -LiteralPath $recovery) -and (Test-Path -LiteralPath $vault)) 'Setup did not create the encrypted vault and recovery output.'
    Assert-Succeeded (Invoke-Av $vault @('unlock', '--direct')) 'Explicit unlock check'

    Write-Host 'Enter an invented secret at the av prompt. Do not enter a live credential.'
    Assert-Succeeded (Invoke-Av $vault @('secret', 'add', 'AV_TEST_SECRET')) 'Secret add'
    Assert-Succeeded (Invoke-Av $vault @('check')) 'Secret-backed project check'
    Assert-Succeeded (Invoke-Av $vault @('secret', 'list')) 'Secret metadata listing'

    Assert-Failed (Invoke-Av $vault (@('run', '--') + $task)) 'Default-denied run'
    Assert-True (-not (Test-Path -LiteralPath $marker)) 'The denied command started its child.'
    Assert-Succeeded (Invoke-Av $vault (@('secret', 'grant', 'AV_TEST_SECRET', '--') + $task)) 'Pinned direct grant'

    Write-Host 'At the next approval prompt, enter anything except approve.'
    Assert-Failed (Invoke-Av $vault (@('run', '--') + $task)) 'Rejected approval'
    Assert-True (-not (Test-Path -LiteralPath $marker)) 'The rejected approval started its child.'

    Write-Host 'At the next approval prompt, type approve.'
    Assert-Succeeded (Invoke-Av $vault (@('run', '--') + $task)) 'Approved direct run'
    Assert-True ((Test-Path -LiteralPath $marker) -and
        @(Get-Content -LiteralPath $marker).Count -eq 1) 'Approved run did not deliver the secret to its child exactly once.'

    Assert-Succeeded (Invoke-Av $vault @('secret', 'backup', $backup)) 'Encrypted backup'
    Assert-True ((Test-Path -LiteralPath $backup) -and
        (Get-Item -LiteralPath $backup).Length -gt 0) 'Backup was not created.'
    Assert-Succeeded (Invoke-Av $restoredVault @('secret', 'restore', $backup)) 'Restore into a new vault'
    Assert-Succeeded (Invoke-Av $restoredVault @('unlock', '--direct')) 'Restored vault unlock'
    Remove-Item -LiteralPath $marker
    Write-Host 'Type approve again to verify the restored grant and secret.'
    Assert-Succeeded (Invoke-Av $restoredVault (@('run', '--') + $task)) 'Restored vault release'
    Assert-True (Test-Path -LiteralPath $marker) 'Restored vault did not deliver its secret.'

    Write-Host 'Recovery will replace the original vault passphrase. Enter a new temporary passphrase twice.'
    Assert-Succeeded (Invoke-Av $vault @('secret', 'recover', '--recovery-file', $recovery,
        '--new-recovery-file', $newRecovery)) 'Offline-key recovery'
    Assert-True (Test-Path -LiteralPath $newRecovery) 'Recovery did not create a new recovery output.'
    Assert-Succeeded (Invoke-Av $vault @('unlock', '--direct')) 'Recovered vault unlock'
    Remove-Item -LiteralPath $marker
    Write-Host 'Type approve once more to verify the recovered grant and secret.'
    Assert-Succeeded (Invoke-Av $vault (@('run', '--') + $task)) 'Recovered vault release'
    Assert-True (Test-Path -LiteralPath $marker) 'Recovered vault did not deliver its secret.'
    Write-Host 'Native Windows direct console journey passed: setup, unlock, mixed public/secret values, default denial, approval, backup/restore, and recovery.'
} finally {
    if ($locationPushed) { Pop-Location }
    [Environment]::SetEnvironmentVariable('AV_TEST_SECRET', $priorSecret, 'Process')
    [Environment]::SetEnvironmentVariable('AV_PUBLIC_LABEL', $priorPublic, 'Process')
    Remove-Item -LiteralPath $root -Recurse -Force
}
