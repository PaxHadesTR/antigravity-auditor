[CmdletBinding()]
param(
    [switch]$SkipGlobalSkillInstall,
    [switch]$GenerateVerifierSidecars,
    [string]$InstallRootOverride = '',
    [string]$HomeGeminiOverride = '',
    [string]$SimulateFailureStep = ''
)
$ErrorActionPreference = 'Stop'
$packageRoot = $PSScriptRoot
$homeGemini = if ($HomeGeminiOverride) { $HomeGeminiOverride } elseif ($env:ANTIGRAVITY_GEMINI_HOME) { $env:ANTIGRAVITY_GEMINI_HOME } else { Join-Path $HOME '.gemini' }
$globalSkills = Join-Path $homeGemini 'config/skills'
$globalRules = Join-Path $homeGemini 'config/rules'
$installRoot = if ($InstallRootOverride) { $InstallRootOverride } elseif ($env:ANTIGRAVITY_AUDITOR_HOME) { $env:ANTIGRAVITY_AUDITOR_HOME } else { Join-Path $env:LOCALAPPDATA 'AntigravityAuditor' }

$env:ANTIGRAVITY_AUDITOR_HOME = $installRoot
$env:ANTIGRAVITY_GEMINI_HOME = $homeGemini
$env:PYTHONDONTWRITEBYTECODE = '1'

<#
.SYNOPSIS
    Preflight process and database lock check before installer modifies any runtime files.

.DESCRIPTION
    Inspects running system processes and SQLite database files prior to modifying runtime files,
    cleaning backups, running database migrations, or installing skills.

    LIMITATIONS & CONCURRENCY GUARANTEES:
    1. FileShare.None checks incompatible open file handles at preflight time:
       Attempts to open auditor.db, auditor.db-wal, and auditor.db-shm with FileShare.None. If an
       exclusive or conflicting file handle is held by another process, preflight detects it and aborts.
    2. Does not directly inspect every SQLite byte-range lock:
       SQLite uses Win32 byte-range locking (LockFileEx) for shared reader locks in WAL mode. FileShare.None
       will catch unshared OS handles, but does not query internal SQLite VFS lock tables directly.
    3. Point-in-time check:
       The preflight check is performed once before runtime modification begins. It cannot prevent a new
       process from being launched concurrently after the preflight check finishes.
    4. Operational requirement:
       Relevant Auditor processes (workers, MCP servers, Sidecars) must remain stopped throughout installation.
    5. No termination of unrelated processes:
       Preflight never automatically terminates running processes. When an Auditor process or database
       lock is detected, it reports the PID, process name, and command line, then safely aborts without modifying
       any runtime files.
#>
function Test-AuditorProcessPreflight {
    param(
        [Parameter(Mandatory = $true)][string]$TargetInstallRoot,
        [Parameter(Mandatory = $false)][string]$TargetDbFile = ''
    )

    $conflicts = @()
    $normTarget = try { [System.IO.Path]::GetFullPath($TargetInstallRoot).TrimEnd('\', '/') } catch { $TargetInstallRoot }
    $normTargetEsc = [Regex]::Escape($normTarget)
    $forwardTargetEsc = [Regex]::Escape($normTarget.Replace('\', '/'))

    # Exact boundary regex matching to prevent prefix collisions (e.g. C:\Target vs C:\Target_Extra)
    $targetBoundaryPattern = "(?:$normTargetEsc|$forwardTargetEsc)(?=[\\/]|\s|""|'|$)"

    $defaultInstallRoot = try { [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'AntigravityAuditor')).TrimEnd('\', '/') } catch { '' }
    $isDefaultTarget = ($normTarget -eq $defaultInstallRoot)

    $currentPid = $PID
    $procs = try {
        Get-CimInstance Win32_Process -ErrorAction Stop
    } catch {
        Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    }

    if ($procs) {
        foreach ($proc in $procs) {
            $procId = [int]$proc.ProcessId
            if ($procId -eq $currentPid) { continue }
            $procName = [string]$proc.Name
            $cmdLine = [string]$proc.CommandLine
            $exePath = [string]$proc.ExecutablePath

            if ([string]::IsNullOrWhiteSpace($cmdLine) -and [string]::IsNullOrWhiteSpace($exePath)) {
                continue
            }

            # Check if process relates to TargetInstallRoot using path boundary match
            $matchesInstallRoot = ($cmdLine -match $targetBoundaryPattern) -or
                                  ($exePath -match $targetBoundaryPattern)

            # Check for Auditor-specific component markers
            $isWorker = ($cmdLine -match '\bverifier[-_]worker\b')
            $isSidecar = ($cmdLine -match '\bauditor[-_]sidecar\b') -or ($cmdLine -match '\bverifier[-_]sidecar\b')
            $isMcp = ($cmdLine -match '\bmcp[-_](serve|server)\b') -or ($cmdLine -match '\bmcp_server(\.py)?\b')
            $isAuditorCore = ($cmdLine -match '\bcore[\\/](cli|mcp_server|verification)\.py\b')

            # Auditor identity markers: do not rely on generic filenames (e.g. core/mcp_server.py) alone
            $hasAuditorToken = ($cmdLine -match '\bantigravity[-_]?auditor\b') -or
                               ($cmdLine -match '\bAntigravityAuditor\b') -or
                               ($cmdLine -match '\bANTIGRAVITY_AUDITOR\b') -or
                               ($exePath -match '\bantigravity[-_]?auditor\b|\bAntigravityAuditor\b')

            $isAuditorConflict = $false
            $role = ''

            if ($matchesInstallRoot) {
                # Process explicitly references this installation root within directory boundaries
                if ($isWorker) { $role = 'Auditor verifier-worker' }
                elseif ($isMcp) { $role = 'Auditor MCP server' }
                elseif ($isSidecar) { $role = 'Auditor Sidecar' }
                elseif ($isAuditorCore) { $role = 'Auditor core process' }
                else { $role = 'Auditor runtime process' }
                $isAuditorConflict = $true
            } else {
                # Process does not explicitly reference this installation root in its command line.
                # Must carry explicit Auditor identity tokens — generic filenames alone never qualify.
                if ($hasAuditorToken) {
                    $targetsDifferentRoot = $false
                    if ($cmdLine -match '[-_]InstallRootOverride\s+(?:["'']([^"'']+)["'']|(\S+))') {
                        $specifiedRoot = $(if ($matches[1]) { $matches[1] } else { $matches[2] }).Trim()
                        $normSpecified = try { [System.IO.Path]::GetFullPath($specifiedRoot).TrimEnd('\', '/') } catch { $specifiedRoot }
                        if ($normSpecified -ne $normTarget) {
                            $targetsDifferentRoot = $true
                        }
                    }
                    if ($cmdLine -match 'ANTIGRAVITY_AUDITOR_HOME[=:]\s*(?:["'']([^"'']+)["'']|(\S+))') {
                        $specifiedRoot = $(if ($matches[1]) { $matches[1] } else { $matches[2] }).Trim()
                        $normSpecified = try { [System.IO.Path]::GetFullPath($specifiedRoot).TrimEnd('\', '/') } catch { $specifiedRoot }
                        if ($normSpecified -ne $normTarget) {
                            $targetsDifferentRoot = $true
                        }
                    }

                    if (-not $targetsDifferentRoot -and $isDefaultTarget) {
                        if ($isWorker) {
                            $role = 'Auditor verifier-worker'
                            $isAuditorConflict = $true
                        } elseif ($isMcp) {
                            $role = 'Auditor MCP server'
                            $isAuditorConflict = $true
                        } elseif ($isSidecar) {
                            $role = 'Auditor Sidecar'
                            $isAuditorConflict = $true
                        } elseif ($isAuditorCore) {
                            $role = 'Auditor core process'
                            $isAuditorConflict = $true
                        }
                    } elseif (-not $targetsDifferentRoot -and -not $isDefaultTarget -and ($isWorker -or $isMcp -or $isSidecar -or $isAuditorCore)) {
                        # Its root is not visible on the command line (e.g. set through ANTIGRAVITY_AUDITOR_HOME in its
                        # environment). Blocking would stop every custom-root install while the default install runs,
                        # so warn instead of silently ignoring it.
                        Write-Warning ("PREFLIGHT WARNING: Auditor process PID $($proc.ProcessId) ($procName) does not show its install root on the command line; " +
                            "make sure it is not using '$TargetInstallRoot' before continuing.")
                    }
                }
            }

            if ($isAuditorConflict) {
                $conflicts += [PSCustomObject]@{
                    Type        = 'ActiveProcess'
                    Role        = $role
                    ProcessName = $procName
                    PID         = $procId
                    CommandLine = $cmdLine
                }
            }
        }
    }

    # Open Auditor database/WAL/SHM file handles check
    if ($TargetDbFile) {
        $dbCandidates = @(
            $TargetDbFile,
            ($TargetDbFile + '-wal'),
            ($TargetDbFile + '-shm')
        )
        foreach ($dbCand in $dbCandidates) {
            if (Test-Path $dbCand) {
                $fileLocked = $false
                $lockErr = ''
                try {
                    $stream = [System.IO.File]::Open($dbCand, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                    if ($stream) {
                        $stream.Close()
                        $stream.Dispose()
                    }
                } catch [System.IO.IOException] {
                    $fileLocked = $true
                    $lockErr = $_.Exception.Message
                } catch {
                    $fileLocked = $true
                    $lockErr = $_.Exception.Message
                }

                if ($fileLocked) {
                    $conflicts += [PSCustomObject]@{
                        Type        = 'DatabaseLock'
                        Role        = 'Auditor database file locked by open handle'
                        ProcessName = [System.IO.Path]::GetFileName($dbCand)
                        PID         = -1
                        CommandLine = "File handle lock on '$dbCand': $lockErr"
                    }
                }
            }
        }
    }

    if ($conflicts.Count -gt 0) {
        Write-Host "=================================================================" -ForegroundColor Red
        Write-Host "PREFLIGHT ERROR: Active Auditor processes or database locks detected!" -ForegroundColor Red
        Write-Host "Cannot proceed with installation while Auditor processes are running." -ForegroundColor Red
        Write-Host "Please terminate running workers, MCP servers, and Sidecars before installing." -ForegroundColor Red
        Write-Host "=================================================================" -ForegroundColor Red

        $reportLines = @()
        foreach ($c in $conflicts) {
            $msg = "[$($c.Role)] PID: $($c.PID), Process: '$($c.ProcessName)', CommandLine: '$($c.CommandLine)'"
            Write-Host $msg -ForegroundColor Yellow
            $reportLines += $msg
        }
        $summary = $reportLines -join "`n"
        throw "Active Antigravity Auditor process(es) or database lock(s) detected. Aborting installation before modifying runtime:`n$summary"
    }
}

if ($SimulateFailureStep -eq 'preflight') {
    throw 'Simulated failure during preflight.'
}

$targetDbFilePreflight = Join-Path $installRoot 'database/auditor.db'
Test-AuditorProcessPreflight -TargetInstallRoot $installRoot -TargetDbFile $targetDbFilePreflight

# Must be measured before the directories are created below, or a rollback could never remove them.
$targetSkillsExistedBeforeInstall = Test-Path $globalSkills
New-Item -ItemType Directory -Force -Path $installRoot, $globalSkills, $globalRules | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) { throw 'Python 3 was not found. Install Python 3.11+ and re-run this installer.' }

function Invoke-AuditorPython {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$PyArgs)
    if ($python.Name -eq 'py') {
        & py -3 -B @PyArgs
    } else {
        & python -B @PyArgs
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed (exit code $LASTEXITCODE): $($PyArgs -join ' ')"
    }
}

function Copy-CleanTree {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (Test-Path $Destination) {
        Remove-Item -Path $Destination -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -Path $Source -Force | ForEach-Object {
        if ($_.Name -in @('__pycache__', '.pytest_cache')) { return }
        if (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo')) { return }
        $childDest = Join-Path $Destination $_.Name
        if ($_.PSIsContainer) {
            Copy-CleanTree -Source $_.FullName -Destination $childDest
        } else {
            Copy-Item -Path $_.FullName -Destination $childDest -Force
        }
    }
}

function Restore-DirectorySnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][bool]$ExistedBefore,
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [ref]$RestoredList,
        [ref]$ErrorList
    )
    try {
        if ($ExistedBefore) {
            if (-not (Test-Path $BackupPath)) {
                throw "Pre-replace backup missing for '$Label' at '$BackupPath'."
            }
            Copy-CleanTree -Source $BackupPath -Destination $TargetPath
            $RestoredList.Value += $Label
        } else {
            if (Test-Path $TargetPath) {
                Remove-Item -Path $TargetPath -Recurse -Force
            }
            $RestoredList.Value += "$Label (removed newly created directory)"
        }
    } catch {
        $ErrorList.Value += "Failed to restore '$Label' -> $($_.Exception.Message)"
    }
}

# 1. Stage/back up existing installed core, integrations, global-skills, target global skills, and SQLite database before replacing anything.
$rollbackRoot = Join-Path $installRoot ('backups/install-stage-' + $timestamp)
New-Item -ItemType Directory -Force -Path $rollbackRoot | Out-Null

$coreSource = Join-Path $packageRoot 'core'
$coreTarget = Join-Path $installRoot 'core'
$coreExisted = Test-Path $coreTarget
$coreBackup = Join-Path $rollbackRoot 'core'
if ($coreExisted) {
    Copy-CleanTree -Source $coreTarget -Destination $coreBackup
    $legacyCoreBackup = Join-Path $installRoot ('backups/core-' + $timestamp)
    Copy-CleanTree -Source $coreTarget -Destination $legacyCoreBackup
}

$integrationsSource = Join-Path $packageRoot 'integrations'
$integrationsTarget = Join-Path $installRoot 'integrations'
$integrationsExisted = Test-Path $integrationsTarget
$integrationsBackup = Join-Path $rollbackRoot 'integrations'
if ($integrationsExisted) {
    Copy-CleanTree -Source $integrationsTarget -Destination $integrationsBackup
}

$globalSkillsSource = Join-Path $packageRoot 'global-skills'
$globalSkillsTarget = Join-Path $installRoot 'global-skills'
$globalSkillsExisted = Test-Path $globalSkillsTarget
$globalSkillsBackup = Join-Path $rollbackRoot 'global-skills'
if ($globalSkillsExisted) {
    Copy-CleanTree -Source $globalSkillsTarget -Destination $globalSkillsBackup
}

$targetSkillsExisted = $targetSkillsExistedBeforeInstall
$targetSkillsBackup = Join-Path $rollbackRoot 'target-config-skills'
if ($targetSkillsExisted) {
    Copy-CleanTree -Source $globalSkills -Destination $targetSkillsBackup
}

$dbFile = Join-Path $installRoot 'database/auditor.db'
$dbExistedBefore = Test-Path $dbFile
$dbBackupFile = ''
if ($dbExistedBefore) {
    $dbBackupDir = Join-Path $installRoot ('backups/pre-migration-' + $timestamp)
    New-Item -ItemType Directory -Force -Path $dbBackupDir | Out-Null
    $dbBackupFile = Join-Path $dbBackupDir 'auditor-pre-migration.db'
    $backupScript = @'
import sqlite3
import sys
from pathlib import Path

src_db = Path(sys.argv[1])
dst_db = Path(sys.argv[2])
dst_db.parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(str(src_db), timeout=30.0) as src_conn:
    with sqlite3.connect(str(dst_db), timeout=30.0) as dst_conn:
        src_conn.backup(dst_conn)
with sqlite3.connect(str(dst_db), timeout=30.0) as verify_conn:
    integrity = verify_conn.execute("PRAGMA integrity_check").fetchone()[0]
    if str(integrity).lower() != "ok":
        raise RuntimeError(f"Pre-migration backup failed integrity_check: {integrity}")
'@
    if ($python.Name -eq 'py') {
        $backupScript | & py -3 -B - $dbFile $dbBackupFile
    } else {
        $backupScript | & python -B - $dbFile $dbBackupFile
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dbBackupFile)) {
        throw "Pre-migration SQLite Online Backup failed for '$dbFile'. Aborting installation before schema migration."
    }
}

# register-mcp and generate-verifier-sidecars change Antigravity's own configuration; snapshot it as well.
$geminiConfigDir = Join-Path $homeGemini 'config'
$mcpConfigFile = if ($env:ANTIGRAVITY_MCP_CONFIG_PATH) { $env:ANTIGRAVITY_MCP_CONFIG_PATH } else { Join-Path $geminiConfigDir 'mcp_config.json' }
$appConfigFile = if ($env:ANTIGRAVITY_CONFIG_PATH) { $env:ANTIGRAVITY_CONFIG_PATH } else { Join-Path $geminiConfigDir 'config.json' }
$sidecarRootDir = if ($env:ANTIGRAVITY_SIDECAR_ROOT) { $env:ANTIGRAVITY_SIDECAR_ROOT } else { Join-Path $geminiConfigDir 'sidecars' }
$configFileSnapshots = @()
foreach ($cfgFile in @($mcpConfigFile, $appConfigFile)) {
    $cfgExisted = Test-Path $cfgFile
    $cfgBackup = Join-Path $rollbackRoot ('antigravity-config/' + [System.IO.Path]::GetFileName($cfgFile))
    if ($cfgExisted) {
        New-Item -ItemType Directory -Force -Path (Split-Path $cfgBackup -Parent) | Out-Null
        Copy-Item -Path $cfgFile -Destination $cfgBackup -Force
    }
    $configFileSnapshots += [PSCustomObject]@{ Path = $cfgFile; Existed = $cfgExisted; Backup = $cfgBackup }
}
$sidecarRootExisted = Test-Path $sidecarRootDir
$sidecarRootBackup = Join-Path $rollbackRoot 'antigravity-sidecars'
if ($sidecarRootExisted) {
    Copy-CleanTree -Source $sidecarRootDir -Destination $sidecarRootBackup
}

$skillsInstallAttempted = $false
$migrationAttempted = $false
$antigravityConfigAttempted = $false

try {
    # 2. Copy updated application payload (core, integrations, global-skills) excluding __pycache__ and *.pyc.
    Copy-CleanTree -Source $coreSource -Destination $coreTarget
    Copy-CleanTree -Source $integrationsSource -Destination $integrationsTarget
    Copy-CleanTree -Source $globalSkillsSource -Destination $globalSkillsTarget

    $cli = Join-Path $installRoot 'core/cli.py'

    # 3. Import bundle skills conflict-safely.
    if (-not $SkipGlobalSkillInstall) {
        $skillsInstallAttempted = $true
        if ($SimulateFailureStep -eq 'install-global-skills') {
            throw 'Simulated failure during install-global-skills.'
        }
        $skillBackupRoot = Join-Path $installRoot ('backups/skills-' + $timestamp)
        Invoke-AuditorPython $cli 'install-global-skills' '--target-root' $globalSkills '--backup-root' $skillBackupRoot '--include-omniapex'
    }

    # 4. Apply versioned SQLite migration safely (v1/v2 -> v3) and register MCP server.
    $migrationAttempted = $true
    if ($SimulateFailureStep -eq 'init') {
        throw 'Simulated failure during init (database migration).'
    }
    Invoke-AuditorPython $cli 'init'

    if ($SimulateFailureStep -eq 'integrity-check') {
        throw 'Simulated failure during integrity-check.'
    }
    Invoke-AuditorPython $cli 'integrity-check'

    $antigravityConfigAttempted = $true
    if ($SimulateFailureStep -eq 'register-mcp') {
        throw 'Simulated failure during register-mcp.'
    }
    Invoke-AuditorPython $cli 'register-mcp'

    # 5. Optionally generate verifier Sidecar files while leaving Sidecar activation disabled in config.json.
    if ($GenerateVerifierSidecars) {
        if ($SimulateFailureStep -eq 'generate-verifier-sidecars') {
            throw 'Simulated failure during generate-verifier-sidecars.'
        }
        Invoke-AuditorPython $cli 'generate-verifier-sidecars'
    }
} catch {
    $originalError = $_
    $restoredItems = @()
    $rollbackErrors = @()

    Restore-DirectorySnapshot -Label 'core' -ExistedBefore $coreExisted -BackupPath $coreBackup -TargetPath $coreTarget -RestoredList ([ref]$restoredItems) -ErrorList ([ref]$rollbackErrors)
    Restore-DirectorySnapshot -Label 'integrations' -ExistedBefore $integrationsExisted -BackupPath $integrationsBackup -TargetPath $integrationsTarget -RestoredList ([ref]$restoredItems) -ErrorList ([ref]$rollbackErrors)
    Restore-DirectorySnapshot -Label 'global-skills' -ExistedBefore $globalSkillsExisted -BackupPath $globalSkillsBackup -TargetPath $globalSkillsTarget -RestoredList ([ref]$restoredItems) -ErrorList ([ref]$rollbackErrors)

    if ($skillsInstallAttempted) {
        Restore-DirectorySnapshot -Label 'config/skills' -ExistedBefore $targetSkillsExisted -BackupPath $targetSkillsBackup -TargetPath $globalSkills -RestoredList ([ref]$restoredItems) -ErrorList ([ref]$rollbackErrors)
    }

    if ($antigravityConfigAttempted) {
        foreach ($snap in $configFileSnapshots) {
            try {
                if ($snap.Existed) {
                    Copy-Item -Path $snap.Backup -Destination $snap.Path -Force
                    $restoredItems += [System.IO.Path]::GetFileName($snap.Path)
                } elseif (Test-Path $snap.Path) {
                    Remove-Item -Path $snap.Path -Force
                    $restoredItems += "$([System.IO.Path]::GetFileName($snap.Path)) (removed newly created file)"
                }
            } catch {
                $rollbackErrors += "Failed to restore '$($snap.Path)' -> $($_.Exception.Message)"
            }
        }
        Restore-DirectorySnapshot -Label 'config/sidecars' -ExistedBefore $sidecarRootExisted -BackupPath $sidecarRootBackup -TargetPath $sidecarRootDir -RestoredList ([ref]$restoredItems) -ErrorList ([ref]$rollbackErrors)
    }

    if ($migrationAttempted) {
        try {
            if ($dbExistedBefore) {
                if (-not $dbBackupFile -or -not (Test-Path $dbBackupFile)) {
                    throw "Pre-migration database backup missing at '$dbBackupFile'."
                }
                foreach ($walSuffix in @('-wal', '-shm')) {
                    $sidecar = $dbFile + $walSuffix
                    if (Test-Path $sidecar) { Remove-Item -Path $sidecar -Force }
                }
                $restoreDbScript = @'
import sqlite3
import sys
from pathlib import Path

backup_db = Path(sys.argv[1])
target_db = Path(sys.argv[2])
target_db.parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(str(backup_db), timeout=30.0) as src_conn:
    with sqlite3.connect(str(target_db), timeout=30.0) as dst_conn:
        src_conn.backup(dst_conn)
with sqlite3.connect(str(target_db), timeout=30.0) as verify_conn:
    integrity = verify_conn.execute("PRAGMA integrity_check").fetchone()[0]
    if str(integrity).lower() != "ok":
        raise RuntimeError(f"Restored database failed integrity_check: {integrity}")
'@
                if ($python.Name -eq 'py') {
                    $restoreDbScript | & py -3 -B - $dbBackupFile $dbFile
                } else {
                    $restoreDbScript | & python -B - $dbBackupFile $dbFile
                }
                if ($LASTEXITCODE -ne 0) {
                    throw "Database restore script exited with code $LASTEXITCODE."
                }
                $restoredItems += 'auditor.db'
            } else {
                foreach ($dbPathToClean in @($dbFile, ($dbFile + '-wal'), ($dbFile + '-shm'))) {
                    if (Test-Path $dbPathToClean) { Remove-Item -Path $dbPathToClean -Force }
                }
                $restoredItems += 'auditor.db (removed newly created DB)'
            }
        } catch {
            $rollbackErrors += "Failed to restore 'auditor.db' -> $($_.Exception.Message)"
        }
    } else {
        $restoredItems += 'auditor.db (untouched; migration had not started)'
    }

    if ($rollbackErrors.Count -gt 0) {
        $errSummary = $rollbackErrors -join '; '
        Write-Host "INSTALLER ROLLBACK INCOMPLETE after error ($($originalError.Exception.Message)). Restored: [$($restoredItems -join ', ')]. Rollback failures: $errSummary" -ForegroundColor Red
        throw "Installation failed: $($originalError.Exception.Message). Rollback ALSO encountered errors: $errSummary"
    } else {
        Write-Host "INSTALLER ROLLBACK COMPLETED cleanly after error ($($originalError.Exception.Message)). Restored: [$($restoredItems -join ', ')]." -ForegroundColor Yellow
        throw "Installation failed and was cleanly rolled back ($($restoredItems -join ', ')): $($originalError.Exception.Message)"
    }
}

Write-Host "Antigravity Auditor installed at: $installRoot" -ForegroundColor Green
Write-Host 'Global skills (including independent-audit-verifier), DB schema v3, and MCP server were configured conflict-safely.' -ForegroundColor Cyan
Write-Host 'Verifier Sidecar activation remains disabled by default until explicitly enabled via enable-verifier-sidecar.' -ForegroundColor Yellow
