# Isolated PowerShell test harness for Install-AntigravityAuditor.ps1 process preflight
# Verifies process preflight, unrelated MCP server isolation, and SQLite file lock detection.

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot
$installerScript = Join-Path (Split-Path $scriptRoot -Parent) 'Install-AntigravityAuditor.ps1'

if (-not (Test-Path $installerScript)) {
    throw "Installer script not found at '$installerScript'."
}

$testBase = Join-Path ([System.IO.Path]::GetTempPath()) ("auditor-preflight-test-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $testBase | Out-Null

$results = [ordered]@{}

try {
    # -------------------------------------------------------------------------
    # Test 1: No active process - installation may proceed to the next stage
    # -------------------------------------------------------------------------
    Write-Host "[1/18] Testing: No active process allows installation to proceed..." -ForegroundColor Cyan
    $test1Root = Join-Path $testBase 'test1_root'
    $test1Gemini = Join-Path $testBase 'test1_gemini'
    New-Item -ItemType Directory -Force -Path $test1Root, $test1Gemini | Out-Null

    $outputFile1 = Join-Path $testBase 'out1.txt'
    $stdoutFile1 = Join-Path $testBase 'stdout1.txt'
    $proc1 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test1Root,
        '-HomeGeminiOverride', $test1Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile1 -RedirectStandardOutput $stdoutFile1

    $err1 = if (Test-Path $outputFile1) { Get-Content $outputFile1 -Raw } else { '' }
    $out1 = if (Test-Path $stdoutFile1) { Get-Content $stdoutFile1 -Raw } else { '' }
    $allOut1 = "$out1`n$err1"

    if ($allOut1 -match 'PREFLIGHT ERROR') {
        throw "Test 1 failed: preflight unexpectedly aborted: $allOut1"
    }
    if ($allOut1 -notmatch 'Simulated failure during init') {
        throw "Test 1 failed: installer did not reach simulated init step: $allOut1"
    }
    $results['Test1_NoActiveProcess'] = 'PASSED'
    Write-Host "  -> PASSED: Preflight permitted installer to proceed." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 2: Active Auditor worker - installer aborts
    # -------------------------------------------------------------------------
    Write-Host "[2/18] Testing: Active Auditor worker aborts installation..." -ForegroundColor Cyan
    $test2Root = Join-Path $testBase 'test2_root'
    $test2Gemini = Join-Path $testBase 'test2_gemini'
    New-Item -ItemType Directory -Force -Path $test2Root, $test2Gemini | Out-Null

    $mockWorker = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`" verifier-worker $test2Root" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile2 = Join-Path $testBase 'out2.txt'
    $proc2 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test2Root,
        '-HomeGeminiOverride', $test2Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile2 -RedirectStandardOutput (Join-Path $testBase 'stdout2.txt')

    if (-not $mockWorker.HasExited) { Stop-Process -Id $mockWorker.Id -Force }

    $err2 = if (Test-Path $outputFile2) { Get-Content $outputFile2 -Raw } else { '' }
    $out2 = if (Test-Path (Join-Path $testBase 'stdout2.txt')) { Get-Content (Join-Path $testBase 'stdout2.txt') -Raw } else { '' }
    $allOut2 = "$out2`n$err2"

    if ($proc2.ExitCode -eq 0) {
        throw "Test 2 failed: Installer succeeded despite active Auditor worker."
    }
    if ($allOut2 -notmatch 'Active Antigravity Auditor process' -and $allOut2 -notmatch 'verifier-worker') {
        throw "Test 2 failed: Abort error message did not report active process: $allOut2"
    }
    $results['Test2_ActiveWorkerAborts'] = 'PASSED'
    Write-Host "  -> PASSED: Active worker caused preflight abort with PID reporting." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 3: Active Auditor MCP server - installer aborts
    # -------------------------------------------------------------------------
    Write-Host "[3/18] Testing: Active Auditor MCP server aborts installation..." -ForegroundColor Cyan
    $test3Root = Join-Path $testBase 'test3_root'
    $test3Gemini = Join-Path $testBase 'test3_gemini'
    New-Item -ItemType Directory -Force -Path $test3Root, $test3Gemini | Out-Null

    $mockMcp = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`" mcp-serve $test3Root" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile3 = Join-Path $testBase 'out3.txt'
    $proc3 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test3Root,
        '-HomeGeminiOverride', $test3Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile3 -RedirectStandardOutput (Join-Path $testBase 'stdout3.txt')

    if (-not $mockMcp.HasExited) { Stop-Process -Id $mockMcp.Id -Force }

    $err3 = if (Test-Path $outputFile3) { Get-Content $outputFile3 -Raw } else { '' }
    $out3 = if (Test-Path (Join-Path $testBase 'stdout3.txt')) { Get-Content (Join-Path $testBase 'stdout3.txt') -Raw } else { '' }
    $allOut3 = "$out3`n$err3"

    if ($proc3.ExitCode -eq 0) {
        throw "Test 3 failed: Installer succeeded despite active Auditor MCP server."
    }
    if ($allOut3 -notmatch 'Active Antigravity Auditor process' -and $allOut3 -notmatch 'Auditor MCP server') {
        throw "Test 3 failed: Abort error message did not report MCP server process: $allOut3"
    }
    $results['Test3_ActiveMcpAborts'] = 'PASSED'
    Write-Host "  -> PASSED: Active MCP server caused preflight abort with PID reporting." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 4: Abort causes no runtime file modification
    # -------------------------------------------------------------------------
    Write-Host "[4/18] Testing: Preflight abort causes zero runtime file modifications..." -ForegroundColor Cyan
    $test4Root = Join-Path $testBase 'test4_root'
    $test4Gemini = Join-Path $testBase 'test4_gemini'
    New-Item -ItemType Directory -Force -Path $test4Root, $test4Gemini | Out-Null

    $canaryPath = Join-Path $test4Root 'canary.txt'
    Set-Content -Path $canaryPath -Value 'CANARY_CONTENT_UNTOUCHED' -Encoding utf8
    $beforeListing = Get-ChildItem -Path $test4Root -Recurse | Select-Object -ExpandProperty FullName

    $mockConflict = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`" verifier-worker $test4Root" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile4 = Join-Path $testBase 'out4.txt'
    $proc4 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test4Root,
        '-HomeGeminiOverride', $test4Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile4 -RedirectStandardOutput (Join-Path $testBase 'stdout4.txt')

    if (-not $mockConflict.HasExited) { Stop-Process -Id $mockConflict.Id -Force }

    if ($proc4.ExitCode -eq 0) {
        throw "Test 4 failed: Installer unexpectedly succeeded."
    }

    $afterListing = Get-ChildItem -Path $test4Root -Recurse | Select-Object -ExpandProperty FullName
    if ($beforeListing.Count -ne $afterListing.Count) {
        throw "Test 4 failed: Filesystem changed after preflight abort. Before: [$($beforeListing -join ', ')], After: [$($afterListing -join ', ')]"
    }
    $afterCanary = Get-Content $canaryPath -Raw
    if ($afterCanary.Trim() -ne 'CANARY_CONTENT_UNTOUCHED') {
        throw "Test 4 failed: Canary content modified after abort!"
    }
    foreach ($unexpected in @('core', 'database', 'integrations', 'backups', 'global-skills')) {
        if (Test-Path (Join-Path $test4Root $unexpected)) {
            throw "Test 4 failed: Unexpected directory '$unexpected' was created despite preflight abort!"
        }
    }
    $results['Test4_ZeroModificationsOnAbort'] = 'PASSED'
    Write-Host "  -> PASSED: Runtime directory was completely untouched on preflight abort." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 5: Unrelated Python process does not cause a false positive
    # -------------------------------------------------------------------------
    Write-Host "[5/18] Testing: Unrelated Python process does not cause a false positive..." -ForegroundColor Cyan
    $test5Root = Join-Path $testBase 'test5_root'
    $test5Gemini = Join-Path $testBase 'test5_gemini'
    New-Item -ItemType Directory -Force -Path $test5Root, $test5Gemini | Out-Null

    $unrelatedPy = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile5 = Join-Path $testBase 'out5.txt'
    $proc5 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test5Root,
        '-HomeGeminiOverride', $test5Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile5 -RedirectStandardOutput (Join-Path $testBase 'stdout5.txt')

    if (-not $unrelatedPy.HasExited) { Stop-Process -Id $unrelatedPy.Id -Force }

    $out5 = if (Test-Path (Join-Path $testBase 'stdout5.txt')) { Get-Content (Join-Path $testBase 'stdout5.txt') -Raw } else { '' }
    $err5 = if (Test-Path $outputFile5) { Get-Content $outputFile5 -Raw } else { '' }
    $allOut5 = "$out5`n$err5"

    if ($allOut5 -match 'PREFLIGHT ERROR') {
        throw "Test 5 failed: Unrelated Python process triggered a false positive in preflight: $allOut5"
    }
    if ($allOut5 -notmatch 'Simulated failure during init') {
        throw "Test 5 failed: Installation did not proceed past preflight: $allOut5"
    }
    $results['Test5_UnrelatedPythonNoFalsePositive'] = 'PASSED'
    Write-Host "  -> PASSED: Unrelated Python process was ignored; installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 6: Unrelated mcp-server process does not block installation
    # -------------------------------------------------------------------------
    Write-Host "[6/18] Testing: Unrelated mcp-server process does not block installation..." -ForegroundColor Cyan
    $test6Root = Join-Path $testBase 'test6_root'
    $test6Gemini = Join-Path $testBase 'test6_gemini'
    $unrelatedProj6 = Join-Path $testBase 'unrelated_tool_6'
    New-Item -ItemType Directory -Force -Path $test6Root, $test6Gemini, $unrelatedProj6 | Out-Null

    $unrelatedMcpServer = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`" mcp-server $unrelatedProj6" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile6 = Join-Path $testBase 'out6.txt'
    $proc6 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test6Root,
        '-HomeGeminiOverride', $test6Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile6 -RedirectStandardOutput (Join-Path $testBase 'stdout6.txt')

    if (-not $unrelatedMcpServer.HasExited) { Stop-Process -Id $unrelatedMcpServer.Id -Force }

    $out6 = if (Test-Path (Join-Path $testBase 'stdout6.txt')) { Get-Content (Join-Path $testBase 'stdout6.txt') -Raw } else { '' }
    $err6 = if (Test-Path $outputFile6) { Get-Content $outputFile6 -Raw } else { '' }
    $allOut6 = "$out6`n$err6"

    if ($allOut6 -match 'PREFLIGHT ERROR') {
        throw "Test 6 failed: Unrelated mcp-server process triggered false positive: $allOut6"
    }
    if ($allOut6 -notmatch 'Simulated failure during init') {
        throw "Test 6 failed: Installation did not proceed past preflight: $allOut6"
    }
    $results['Test6_UnrelatedMcpServerNoFalsePositive'] = 'PASSED'
    Write-Host "  -> PASSED: Unrelated mcp-server process was ignored; installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 7: Unrelated mcp_serve process does not block installation
    # -------------------------------------------------------------------------
    Write-Host "[7/18] Testing: Unrelated mcp_serve process does not block installation..." -ForegroundColor Cyan
    $test7Root = Join-Path $testBase 'test7_root'
    $test7Gemini = Join-Path $testBase 'test7_gemini'
    $unrelatedProj7 = Join-Path $testBase 'unrelated_tool_7'
    New-Item -ItemType Directory -Force -Path $test7Root, $test7Gemini, $unrelatedProj7 | Out-Null

    $unrelatedMcpServe = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`" mcp_serve $unrelatedProj7" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile7 = Join-Path $testBase 'out7.txt'
    $proc7 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test7Root,
        '-HomeGeminiOverride', $test7Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile7 -RedirectStandardOutput (Join-Path $testBase 'stdout7.txt')

    if (-not $unrelatedMcpServe.HasExited) { Stop-Process -Id $unrelatedMcpServe.Id -Force }

    $out7 = if (Test-Path (Join-Path $testBase 'stdout7.txt')) { Get-Content (Join-Path $testBase 'stdout7.txt') -Raw } else { '' }
    $err7 = if (Test-Path $outputFile7) { Get-Content $outputFile7 -Raw } else { '' }
    $allOut7 = "$out7`n$err7"

    if ($allOut7 -match 'PREFLIGHT ERROR') {
        throw "Test 7 failed: Unrelated mcp_serve process triggered false positive: $allOut7"
    }
    if ($allOut7 -notmatch 'Simulated failure during init') {
        throw "Test 7 failed: Installation did not proceed past preflight: $allOut7"
    }
    $results['Test7_UnrelatedMcpServeNoFalsePositive'] = 'PASSED'
    Write-Host "  -> PASSED: Unrelated mcp_serve process was ignored; installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 8: SQLite lock on auditor.db causes safe abort without terminating process
    # -------------------------------------------------------------------------
    Write-Host "[8/18] Testing: SQLite lock on auditor.db causes safe abort..." -ForegroundColor Cyan
    $test8Root = Join-Path $testBase 'test8_root'
    $test8Gemini = Join-Path $testBase 'test8_gemini'
    $dbDir8 = Join-Path $test8Root 'database'
    New-Item -ItemType Directory -Force -Path $dbDir8, $test8Gemini | Out-Null
    $dbFile8 = Join-Path $dbDir8 'auditor.db'
    Set-Content -Path $dbFile8 -Value 'MOCK_SQLITE_HEADER' -Encoding utf8

    $canary8 = Join-Path $test8Root 'canary.txt'
    Set-Content -Path $canary8 -Value 'CANARY_UNTOUCHED_DB' -Encoding utf8
    $beforeList8 = Get-ChildItem -Path $test8Root -Recurse | Select-Object -ExpandProperty FullName

    # Hold auditor.db open in background python process
    $lockDbProc = Start-Process python -ArgumentList "-B -c `"import time, sys; fh = open(sys.argv[1], 'r+b'); time.sleep(30)`" `"$dbFile8`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile8 = Join-Path $testBase 'out8.txt'
    $proc8 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test8Root,
        '-HomeGeminiOverride', $test8Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile8 -RedirectStandardOutput (Join-Path $testBase 'stdout8.txt')

    # Verify locking process was NOT terminated by preflight
    $lockStillRunning8 = (-not $lockDbProc.HasExited)
    if ($lockDbProc -and -not $lockDbProc.HasExited) { Stop-Process -Id $lockDbProc.Id -Force }

    $out8 = if (Test-Path (Join-Path $testBase 'stdout8.txt')) { Get-Content (Join-Path $testBase 'stdout8.txt') -Raw } else { '' }
    $err8 = if (Test-Path $outputFile8) { Get-Content $outputFile8 -Raw } else { '' }
    $allOut8 = "$out8`n$err8"

    if ($proc8.ExitCode -eq 0) {
        throw "Test 8 failed: Installer succeeded despite locked auditor.db."
    }
    if (-not $lockStillRunning8) {
        throw "Test 8 failed: Installer terminated the locking process!"
    }
    if ($allOut8 -notmatch 'auditor\.db' -or $allOut8 -notmatch 'database lock') {
        throw "Test 8 failed: Abort message did not report database lock on auditor.db: $allOut8"
    }

    # Verify zero file modification
    $afterList8 = Get-ChildItem -Path $test8Root -Recurse | Select-Object -ExpandProperty FullName
    if ($beforeList8.Count -ne $afterList8.Count) {
        throw "Test 8 failed: Filesystem changed after db lock abort!"
    }
    if ((Get-Content $canary8 -Raw).Trim() -ne 'CANARY_UNTOUCHED_DB') {
        throw "Test 8 failed: Canary content modified after db lock abort!"
    }
    $results['Test8_DbLockSafeAbort'] = 'PASSED'
    Write-Host "  -> PASSED: Lock on auditor.db caused safe abort without terminating process." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 9: SQLite lock on auditor.db-wal causes safe abort without terminating process
    # -------------------------------------------------------------------------
    Write-Host "[9/18] Testing: SQLite lock on auditor.db-wal causes safe abort..." -ForegroundColor Cyan
    $test9Root = Join-Path $testBase 'test9_root'
    $test9Gemini = Join-Path $testBase 'test9_gemini'
    $dbDir9 = Join-Path $test9Root 'database'
    New-Item -ItemType Directory -Force -Path $dbDir9, $test9Gemini | Out-Null
    $walFile9 = Join-Path $dbDir9 'auditor.db-wal'
    Set-Content -Path $walFile9 -Value 'MOCK_WAL_HEADER' -Encoding utf8

    $canary9 = Join-Path $test9Root 'canary.txt'
    Set-Content -Path $canary9 -Value 'CANARY_UNTOUCHED_WAL' -Encoding utf8
    $beforeList9 = Get-ChildItem -Path $test9Root -Recurse | Select-Object -ExpandProperty FullName

    # Hold auditor.db-wal open in background python process
    $lockWalProc = Start-Process python -ArgumentList "-B -c `"import time, sys; fh = open(sys.argv[1], 'r+b'); time.sleep(30)`" `"$walFile9`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile9 = Join-Path $testBase 'out9.txt'
    $proc9 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test9Root,
        '-HomeGeminiOverride', $test9Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile9 -RedirectStandardOutput (Join-Path $testBase 'stdout9.txt')

    $lockStillRunning9 = (-not $lockWalProc.HasExited)
    if ($lockWalProc -and -not $lockWalProc.HasExited) { Stop-Process -Id $lockWalProc.Id -Force }

    $out9 = if (Test-Path (Join-Path $testBase 'stdout9.txt')) { Get-Content (Join-Path $testBase 'stdout9.txt') -Raw } else { '' }
    $err9 = if (Test-Path $outputFile9) { Get-Content $outputFile9 -Raw } else { '' }
    $allOut9 = "$out9`n$err9"

    if ($proc9.ExitCode -eq 0) {
        throw "Test 9 failed: Installer succeeded despite locked auditor.db-wal."
    }
    if (-not $lockStillRunning9) {
        throw "Test 9 failed: Installer terminated the locking process!"
    }
    if ($allOut9 -notmatch 'auditor\.db-wal' -or $allOut9 -notmatch 'database lock') {
        throw "Test 9 failed: Abort message did not report database lock on auditor.db-wal: $allOut9"
    }

    $afterList9 = Get-ChildItem -Path $test9Root -Recurse | Select-Object -ExpandProperty FullName
    if ($beforeList9.Count -ne $afterList9.Count) {
        throw "Test 9 failed: Filesystem changed after wal lock abort!"
    }
    if ((Get-Content $canary9 -Raw).Trim() -ne 'CANARY_UNTOUCHED_WAL') {
        throw "Test 9 failed: Canary content modified after wal lock abort!"
    }
    $results['Test9_WalLockSafeAbort'] = 'PASSED'
    Write-Host "  -> PASSED: Lock on auditor.db-wal caused safe abort without terminating process." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 10: SQLite lock on auditor.db-shm causes safe abort without terminating process
    # -------------------------------------------------------------------------
    Write-Host "[10/18] Testing: SQLite lock on auditor.db-shm causes safe abort..." -ForegroundColor Cyan
    $test10Root = Join-Path $testBase 'test10_root'
    $test10Gemini = Join-Path $testBase 'test10_gemini'
    $dbDir10 = Join-Path $test10Root 'database'
    New-Item -ItemType Directory -Force -Path $dbDir10, $test10Gemini | Out-Null
    $shmFile10 = Join-Path $dbDir10 'auditor.db-shm'
    Set-Content -Path $shmFile10 -Value 'MOCK_SHM_HEADER' -Encoding utf8

    $canary10 = Join-Path $test10Root 'canary.txt'
    Set-Content -Path $canary10 -Value 'CANARY_UNTOUCHED_SHM' -Encoding utf8
    $beforeList10 = Get-ChildItem -Path $test10Root -Recurse | Select-Object -ExpandProperty FullName

    # Hold auditor.db-shm open in background python process
    $lockShmProc = Start-Process python -ArgumentList "-B -c `"import time, sys; fh = open(sys.argv[1], 'r+b'); time.sleep(30)`" `"$shmFile10`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile10 = Join-Path $testBase 'out10.txt'
    $proc10 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test10Root,
        '-HomeGeminiOverride', $test10Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile10 -RedirectStandardOutput (Join-Path $testBase 'stdout10.txt')

    $lockStillRunning10 = (-not $lockShmProc.HasExited)
    if ($lockShmProc -and -not $lockShmProc.HasExited) { Stop-Process -Id $lockShmProc.Id -Force }

    $out10 = if (Test-Path (Join-Path $testBase 'stdout10.txt')) { Get-Content (Join-Path $testBase 'stdout10.txt') -Raw } else { '' }
    $err10 = if (Test-Path $outputFile10) { Get-Content $outputFile10 -Raw } else { '' }
    $allOut10 = "$out10`n$err10"

    if ($proc10.ExitCode -eq 0) {
        throw "Test 10 failed: Installer succeeded despite locked auditor.db-shm."
    }
    if (-not $lockStillRunning10) {
        throw "Test 10 failed: Installer terminated the locking process!"
    }
    if ($allOut10 -notmatch 'auditor\.db-shm' -or $allOut10 -notmatch 'database lock') {
        throw "Test 10 failed: Abort message did not report database lock on auditor.db-shm: $allOut10"
    }

    $afterList10 = Get-ChildItem -Path $test10Root -Recurse | Select-Object -ExpandProperty FullName
    if ($beforeList10.Count -ne $afterList10.Count) {
        throw "Test 10 failed: Filesystem changed after shm lock abort!"
    }
    if ((Get-Content $canary10 -Raw).Trim() -ne 'CANARY_UNTOUCHED_SHM') {
        throw "Test 10 failed: Canary content modified after shm lock abort!"
    }
    $results['Test10_ShmLockSafeAbort'] = 'PASSED'
    Write-Host "  -> PASSED: Lock on auditor.db-shm caused safe abort without terminating process." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 11: No lock on any database files allows installation to proceed
    # -------------------------------------------------------------------------
    Write-Host "[11/18] Testing: Unlocked database files allow installation to proceed..." -ForegroundColor Cyan
    $test11Root = Join-Path $testBase 'test11_root'
    $test11Gemini = Join-Path $testBase 'test11_gemini'
    $dbDir11 = Join-Path $test11Root 'database'
    New-Item -ItemType Directory -Force -Path $dbDir11, $test11Gemini | Out-Null
    $dbFile11 = Join-Path $dbDir11 'auditor.db'
    & python -B -c "import sqlite3, sys; conn = sqlite3.connect(sys.argv[1]); conn.execute('CREATE TABLE t(id INT)'); conn.commit()" $dbFile11
    Set-Content -Path (Join-Path $dbDir11 'auditor.db-wal') -Value 'UNLOCKED_WAL' -Encoding utf8
    Set-Content -Path (Join-Path $dbDir11 'auditor.db-shm') -Value 'UNLOCKED_SHM' -Encoding utf8

    $outputFile11 = Join-Path $testBase 'out11.txt'
    $proc11 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test11Root,
        '-HomeGeminiOverride', $test11Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile11 -RedirectStandardOutput (Join-Path $testBase 'stdout11.txt')

    $out11 = if (Test-Path (Join-Path $testBase 'stdout11.txt')) { Get-Content (Join-Path $testBase 'stdout11.txt') -Raw } else { '' }
    $err11 = if (Test-Path $outputFile11) { Get-Content $outputFile11 -Raw } else { '' }
    $allOut11 = "$out11`n$err11"

    if ($allOut11 -match 'PREFLIGHT ERROR') {
        throw "Test 11 failed: Preflight unexpectedly failed on unlocked DB files: $allOut11"
    }
    if ($allOut11 -notmatch 'Simulated failure during init') {
        throw "Test 11 failed: Installation did not proceed past preflight: $allOut11"
    }
    $results['Test11_NoLockProceedsCleanly'] = 'PASSED'
    Write-Host "  -> PASSED: Unlocked database files permitted installation to proceed." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 12: Case A - Unrelated python C:\OtherProject\core\mcp_server.py does not block installation
    # -------------------------------------------------------------------------
    Write-Host "[12/18] Testing: Case A - Unrelated core\mcp_server.py does not block installation..." -ForegroundColor Cyan
    $test12Root = Join-Path $testBase 'test12_root'
    $test12Gemini = Join-Path $testBase 'test12_gemini'
    $otherProjA = Join-Path $testBase 'OtherProjectA'
    $otherCoreA = Join-Path $otherProjA 'core'
    New-Item -ItemType Directory -Force -Path $test12Root, $test12Gemini, $otherCoreA | Out-Null
    $mcpPyA = Join-Path $otherCoreA 'mcp_server.py'
    Set-Content -Path $mcpPyA -Value "import time; time.sleep(30)" -Encoding utf8

    $mockProcA = Start-Process python -ArgumentList "`"$mcpPyA`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile12 = Join-Path $testBase 'out12.txt'
    $proc12 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test12Root,
        '-HomeGeminiOverride', $test12Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile12 -RedirectStandardOutput (Join-Path $testBase 'stdout12.txt')

    if (-not $mockProcA.HasExited) { Stop-Process -Id $mockProcA.Id -Force }

    $out12 = if (Test-Path (Join-Path $testBase 'stdout12.txt')) { Get-Content (Join-Path $testBase 'stdout12.txt') -Raw } else { '' }
    $err12 = if (Test-Path $outputFile12) { Get-Content $outputFile12 -Raw } else { '' }
    $allOut12 = "$out12`n$err12"

    if ($allOut12 -match 'PREFLIGHT ERROR') {
        throw "Test 12 failed: Unrelated core\mcp_server.py triggered preflight false positive: $allOut12"
    }
    if ($allOut12 -notmatch 'Simulated failure during init') {
        throw "Test 12 failed: Installation did not proceed past preflight: $allOut12"
    }
    $results['Test12_CaseA_UnrelatedMcpServerFile'] = 'PASSED'
    Write-Host "  -> PASSED: Unrelated core\mcp_server.py was ignored; installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 13: Case B - Unrelated python C:\OtherProject\core\cli.py mcp-serve does not block installation
    # -------------------------------------------------------------------------
    Write-Host "[13/18] Testing: Case B - Unrelated core\cli.py mcp-serve does not block installation..." -ForegroundColor Cyan
    $test13Root = Join-Path $testBase 'test13_root'
    $test13Gemini = Join-Path $testBase 'test13_gemini'
    $otherProjB = Join-Path $testBase 'OtherProjectB'
    $otherCoreB = Join-Path $otherProjB 'core'
    New-Item -ItemType Directory -Force -Path $test13Root, $test13Gemini, $otherCoreB | Out-Null
    $cliPyB = Join-Path $otherCoreB 'cli.py'
    Set-Content -Path $cliPyB -Value "import time; time.sleep(30)" -Encoding utf8

    $mockProcB = Start-Process python -ArgumentList "`"$cliPyB`" mcp-serve" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile13 = Join-Path $testBase 'out13.txt'
    $proc13 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test13Root,
        '-HomeGeminiOverride', $test13Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile13 -RedirectStandardOutput (Join-Path $testBase 'stdout13.txt')

    if (-not $mockProcB.HasExited) { Stop-Process -Id $mockProcB.Id -Force }

    $out13 = if (Test-Path (Join-Path $testBase 'stdout13.txt')) { Get-Content (Join-Path $testBase 'stdout13.txt') -Raw } else { '' }
    $err13 = if (Test-Path $outputFile13) { Get-Content $outputFile13 -Raw } else { '' }
    $allOut13 = "$out13`n$err13"

    if ($allOut13 -match 'PREFLIGHT ERROR') {
        throw "Test 13 failed: Unrelated core\cli.py mcp-serve triggered preflight false positive: $allOut13"
    }
    if ($allOut13 -notmatch 'Simulated failure during init') {
        throw "Test 13 failed: Installation did not proceed past preflight: $allOut13"
    }
    $results['Test13_CaseB_UnrelatedCliMcpServe'] = 'PASSED'
    Write-Host "  -> PASSED: Unrelated core\cli.py mcp-serve was ignored; installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 14: Genuine Auditor core/mcp_server.py is detected and blocks installation
    # -------------------------------------------------------------------------
    Write-Host "[14/18] Testing: Genuine Auditor core\mcp_server.py is detected and aborts..." -ForegroundColor Cyan
    $test14Root = Join-Path $testBase 'test14_root'
    $test14Gemini = Join-Path $testBase 'test14_gemini'
    $auditorCore14 = Join-Path $test14Root 'core'
    New-Item -ItemType Directory -Force -Path $test14Root, $test14Gemini, $auditorCore14 | Out-Null
    $auditorMcpPy14 = Join-Path $auditorCore14 'mcp_server.py'
    Set-Content -Path $auditorMcpPy14 -Value "import time; time.sleep(30)" -Encoding utf8

    $mockGenuineMcp = Start-Process python -ArgumentList "`"$auditorMcpPy14`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile14 = Join-Path $testBase 'out14.txt'
    $proc14 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test14Root,
        '-HomeGeminiOverride', $test14Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile14 -RedirectStandardOutput (Join-Path $testBase 'stdout14.txt')

    if (-not $mockGenuineMcp.HasExited) { Stop-Process -Id $mockGenuineMcp.Id -Force }

    $out14 = if (Test-Path (Join-Path $testBase 'stdout14.txt')) { Get-Content (Join-Path $testBase 'stdout14.txt') -Raw } else { '' }
    $err14 = if (Test-Path $outputFile14) { Get-Content $outputFile14 -Raw } else { '' }
    $allOut14 = "$out14`n$err14"

    if ($proc14.ExitCode -eq 0) {
        throw "Test 14 failed: Installer succeeded despite running genuine Auditor core\mcp_server.py."
    }
    if ($allOut14 -notmatch 'Auditor MCP server' -and $allOut14 -notmatch 'Active Antigravity Auditor process') {
        throw "Test 14 failed: Error did not report Auditor MCP server: $allOut14"
    }
    $results['Test14_GenuineAuditorMcpDetected'] = 'PASSED'
    Write-Host "  -> PASSED: Genuine Auditor core\mcp_server.py was detected and caused preflight abort." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 15: Genuine Auditor core/cli.py mcp-serve is detected and blocks installation
    # -------------------------------------------------------------------------
    Write-Host "[15/18] Testing: Genuine Auditor core\cli.py mcp-serve is detected and aborts..." -ForegroundColor Cyan
    $test15Root = Join-Path $testBase 'test15_root'
    $test15Gemini = Join-Path $testBase 'test15_gemini'
    $auditorCore15 = Join-Path $test15Root 'core'
    New-Item -ItemType Directory -Force -Path $test15Root, $test15Gemini, $auditorCore15 | Out-Null
    $auditorCliPy15 = Join-Path $auditorCore15 'cli.py'
    Set-Content -Path $auditorCliPy15 -Value "import time; time.sleep(30)" -Encoding utf8

    $mockGenuineCli = Start-Process python -ArgumentList "`"$auditorCliPy15`" mcp-serve" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile15 = Join-Path $testBase 'out15.txt'
    $proc15 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test15Root,
        '-HomeGeminiOverride', $test15Gemini
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile15 -RedirectStandardOutput (Join-Path $testBase 'stdout15.txt')

    if (-not $mockGenuineCli.HasExited) { Stop-Process -Id $mockGenuineCli.Id -Force }

    $out15 = if (Test-Path (Join-Path $testBase 'stdout15.txt')) { Get-Content (Join-Path $testBase 'stdout15.txt') -Raw } else { '' }
    $err15 = if (Test-Path $outputFile15) { Get-Content $outputFile15 -Raw } else { '' }
    $allOut15 = "$out15`n$err15"

    if ($proc15.ExitCode -eq 0) {
        throw "Test 15 failed: Installer succeeded despite running genuine Auditor core\cli.py mcp-serve."
    }
    if ($allOut15 -notmatch 'Auditor MCP server' -and $allOut15 -notmatch 'Active Antigravity Auditor process') {
        throw "Test 15 failed: Error did not report Auditor MCP server: $allOut15"
    }
    $results['Test15_GenuineAuditorCliMcpServeDetected'] = 'PASSED'
    Write-Host "  -> PASSED: Genuine Auditor core\cli.py mcp-serve was detected and caused preflight abort." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 16: Explicit -InstallRootOverride pointing to another installation is respected
    # -------------------------------------------------------------------------
    Write-Host "[16/18] Testing: Explicit -InstallRootOverride to another path does not block current target..." -ForegroundColor Cyan
    $test16Root = Join-Path $testBase 'test16_target_root'
    $test16Gemini = Join-Path $testBase 'test16_gemini'
    $otherAuditorRoot = Join-Path $testBase 'other_auditor_root'
    New-Item -ItemType Directory -Force -Path $test16Root, $test16Gemini, $otherAuditorRoot | Out-Null

    # Process running for a different auditor install root
    $mockOtherAuditor = Start-Process python -ArgumentList "-B -c `"import time; time.sleep(30)`" antigravity-auditor verifier-worker -InstallRootOverride `"$otherAuditorRoot`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile16 = Join-Path $testBase 'out16.txt'
    $proc16 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test16Root,
        '-HomeGeminiOverride', $test16Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile16 -RedirectStandardOutput (Join-Path $testBase 'stdout16.txt')

    if (-not $mockOtherAuditor.HasExited) { Stop-Process -Id $mockOtherAuditor.Id -Force }

    $out16 = if (Test-Path (Join-Path $testBase 'stdout16.txt')) { Get-Content (Join-Path $testBase 'stdout16.txt') -Raw } else { '' }
    $err16 = if (Test-Path $outputFile16) { Get-Content $outputFile16 -Raw } else { '' }
    $allOut16 = "$out16`n$err16"

    if ($allOut16 -match 'PREFLIGHT ERROR') {
        throw "Test 16 failed: Process targeting different install root triggered false positive: $allOut16"
    }
    if ($allOut16 -notmatch 'Simulated failure during init') {
        throw "Test 16 failed: Installation did not proceed past preflight: $allOut16"
    }
    $results['Test16_OtherInstallRootOverrideRespected'] = 'PASSED'
    Write-Host "  -> PASSED: Process targeting another installation root was respected; current installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 17: Path sharing textual prefix with TargetInstallRoot does not qualify as Auditor process
    # -------------------------------------------------------------------------
    Write-Host "[17/18] Testing: Path prefix collision is not mistaken for TargetInstallRoot..." -ForegroundColor Cyan
    $test17Root = Join-Path $testBase 'test17_root'
    $test17Gemini = Join-Path $testBase 'test17_gemini'
    $prefixCollisionRoot = $test17Root + '_PrefixCollision'
    $prefixCore = Join-Path $prefixCollisionRoot 'core'
    New-Item -ItemType Directory -Force -Path $test17Root, $test17Gemini, $prefixCore | Out-Null
    $prefixPy = Join-Path $prefixCore 'mcp_server.py'
    Set-Content -Path $prefixPy -Value "import time; time.sleep(30)" -Encoding utf8

    $mockPrefixProc = Start-Process python -ArgumentList "`"$prefixPy`"" -PassThru
    Start-Sleep -Milliseconds 600

    $outputFile17 = Join-Path $testBase 'out17.txt'
    $proc17 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test17Root,
        '-HomeGeminiOverride', $test17Gemini,
        '-SimulateFailureStep', 'init'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile17 -RedirectStandardOutput (Join-Path $testBase 'stdout17.txt')

    if (-not $mockPrefixProc.HasExited) { Stop-Process -Id $mockPrefixProc.Id -Force }

    $out17 = if (Test-Path (Join-Path $testBase 'stdout17.txt')) { Get-Content (Join-Path $testBase 'stdout17.txt') -Raw } else { '' }
    $err17 = if (Test-Path $outputFile17) { Get-Content $outputFile17 -Raw } else { '' }
    $allOut17 = "$out17`n$err17"

    if ($allOut17 -match 'PREFLIGHT ERROR') {
        throw "Test 17 failed: Path prefix collision ($prefixCollisionRoot) was mistakenly matched as TargetInstallRoot ($test17Root): $allOut17"
    }
    if ($allOut17 -notmatch 'Simulated failure during init') {
        throw "Test 17 failed: Installation did not proceed past preflight: $allOut17"
    }
    $results['Test17_PrefixCollisionNotMatched'] = 'PASSED'
    Write-Host "  -> PASSED: Path prefix collision was correctly rejected; installation proceeded." -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Test 18: A failure in register-mcp restores Antigravity's mcp_config.json and sidecars
    # -------------------------------------------------------------------------
    Write-Host "[18/18] Testing: failure after register-mcp restores mcp_config.json and sidecars..." -ForegroundColor Cyan
    $test18Root = Join-Path $testBase 'test18_root'
    $test18Gemini = Join-Path $testBase 'test18_gemini'
    $test18Config = Join-Path $test18Gemini 'config'
    $test18Sidecars = Join-Path $test18Config 'sidecars/existing-sidecar'
    New-Item -ItemType Directory -Force -Path $test18Root, $test18Sidecars | Out-Null
    $mcpCfg18 = Join-Path $test18Config 'mcp_config.json'
    $originalMcp18 = '{"mcpServers": {"other-server": {"command": "other.exe"}}}'
    Set-Content -Path $mcpCfg18 -Value $originalMcp18 -Encoding utf8 -NoNewline
    Set-Content -Path (Join-Path $test18Sidecars 'sidecar.json') -Value '{"builtin": "schedule"}' -Encoding utf8 -NoNewline

    $outputFile18 = Join-Path $testBase 'out18.txt'
    $proc18 = Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $installerScript,
        '-InstallRootOverride', $test18Root,
        '-HomeGeminiOverride', $test18Gemini,
        '-SkipGlobalSkillInstall',
        '-GenerateVerifierSidecars',
        '-SimulateFailureStep', 'generate-verifier-sidecars'
    ) -PassThru -NoNewWindow -Wait -RedirectStandardError $outputFile18 -RedirectStandardOutput (Join-Path $testBase 'stdout18.txt')

    $out18 = if (Test-Path (Join-Path $testBase 'stdout18.txt')) { Get-Content (Join-Path $testBase 'stdout18.txt') -Raw } else { '' }
    $err18 = if (Test-Path $outputFile18) { Get-Content $outputFile18 -Raw } else { '' }
    $allOut18 = "$out18`n$err18"

    if ($allOut18 -notmatch 'Simulated failure during generate-verifier-sidecars') {
        throw "Test 18 failed: installer did not get past register-mcp: $allOut18"
    }
    if ($allOut18 -notmatch 'ROLLBACK COMPLETED') {
        throw "Test 18 failed: rollback did not complete cleanly: $allOut18"
    }
    $restoredMcp18 = Get-Content -Path $mcpCfg18 -Raw
    if ($restoredMcp18 -ne $originalMcp18) {
        throw "Test 18 failed: mcp_config.json was not restored. Got: $restoredMcp18"
    }
    if (-not (Test-Path (Join-Path $test18Sidecars 'sidecar.json'))) {
        throw "Test 18 failed: existing sidecar was lost during rollback."
    }
    $results['Test18_RegisterMcpRollbackRestoresConfig'] = 'PASSED'
    Write-Host "  -> PASSED: register-mcp failure restored mcp_config.json and existing sidecars." -ForegroundColor Green

    Write-Host "`nAll 18 installer preflight and SQLite lock tests passed cleanly!" -ForegroundColor Green
    $results.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray }
} finally {
    if (Test-Path $testBase) {
        Remove-Item -Path $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
