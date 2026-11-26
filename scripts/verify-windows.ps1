# Full local verification for Windows.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-windows.ps1
#
# Non-interactive. Runs the protected-input check, formatting, the build, the
# three strict Clippy graphs and the three test graphs (default workspace,
# engine test-support, platform native-test-hooks). Every step runs even after
# a failure; a short summary follows and the exit status is non-zero if any
# step failed. Prerequisites are the README's: the pinned Rust toolchain, MSVC
# Build Tools with the Windows SDK, and Python 3.
#
# The detached engine needs Job Object breakaway, which a launcher Job Object
# (Cargo's included) prevents. So this script refuses to run inside a Job
# Object, compiles tests with Cargo, and runs each reported test binary
# directly (one harness thread, from its package directory). Engine lifetime
# and Job Object behavior are never relaxed to make a test pass.
#
# Each test graph runs with TMP/TEMP set to its own fresh directory. Afterwards
# any process whose command line names that directory (a detached engine or
# test host a failed test did not stop) is reported, stopped and counted as a
# failure.
param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
Set-Location $root

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class VerifyHost {
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool inJob);
}
'@
$inJob = $false
if (-not [VerifyHost]::IsProcessInJob([VerifyHost]::GetCurrentProcess(), [IntPtr]::Zero, [ref]$inJob)) {
    Write-Output 'Cannot establish Job Object membership of this host'
    exit 2
}
if ($inJob) {
    Write-Output 'Run this script from an independent terminal outside a launcher Job Object'
    exit 2
}

# Native stderr is progress output here, not a PowerShell error.
$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.Generic.List[object]
function Record([string]$name, [bool]$ok) {
    $results.Add([PSCustomObject]@{ Step = $name; Status = $(if ($ok) { 'PASS' } else { 'FAIL' }) })
}
function Step([string]$name, [scriptblock]$command) {
    Write-Output "==> $name"
    & $command
    Record $name ($LASTEXITCODE -eq 0)
}

function Sweep([string]$name, [string]$directory) {
    # Windows paths are case-insensitive and may appear in 8.3 short form.
    $forms = @($directory)
    try { $forms += (New-Object -ComObject Scripting.FileSystemObject).GetFolder($directory).ShortPath } catch { }
    $leaked = @(Get-CimInstance Win32_Process | Where-Object {
        $line = $_.CommandLine
        $line -and @($forms | Where-Object { $line.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -gt 0
    })
    if ($leaked.Count -gt 0) {
        $leaked | ForEach-Object { Write-Output "leaked after ${name}: $($_.ProcessId) $($_.CommandLine)" }
        $leaked | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Record "${name}: no leaked processes" $false
    } else {
        Record "${name}: no leaked processes" $true
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $directory
}

function TestGraph([string]$name, [string[]]$cargoArgs) {
    Write-Output "==> $name (compile)"
    # Compiler diagnostics stay on the console; only JSON is collected.
    $json = & cargo test @cargoArgs --locked --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { Record "$name (compile)" $false; return }
    $artifacts = @($json | ForEach-Object { try { ConvertFrom-Json $_ } catch { $null } } |
        Where-Object { $_ -and $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.executable })
    if ($artifacts.Count -eq 0) { Record "$name (no test binaries)" $false; return }
    # Kept short so deep test-created paths stay well within MAX_PATH.
    $directory = Join-Path ([IO.Path]::GetTempPath()) ("d3d-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force $directory | Out-Null
    $savedTmp = $env:TMP; $savedTemp = $env:TEMP
    $env:TMP = $directory; $env:TEMP = $directory
    $failed = @()
    foreach ($artifact in $artifacts) {
        $package = Split-Path -Parent $artifact.manifest_path
        $label = "$($artifact.target.kind -join ','):$($artifact.target.name)"
        Push-Location $package
        $env:CARGO_MANIFEST_DIR = $package
        & $artifact.executable --test-threads=1
        if ($LASTEXITCODE -ne 0) { $failed += $label }
        Pop-Location
    }
    $env:TMP = $savedTmp; $env:TEMP = $savedTemp
    Remove-Item Env:CARGO_MANIFEST_DIR -ErrorAction SilentlyContinue
    foreach ($label in $failed) { Write-Output "failed test binary in ${name}: $label" }
    Record "$name ($($artifacts.Count) binaries)" ($failed.Count -eq 0)
    Sweep $name $directory
}

$metadata = & cargo metadata --format-version 1 --no-deps --locked | ConvertFrom-Json
$target = $metadata.target_directory
if ($LASTEXITCODE -ne 0 -or -not $target) {
    Write-Output 'Cannot resolve the Cargo target directory (cargo metadata)'
    exit 2
}

Step 'protected inputs' { & $Python -B scripts/verify_protected_inputs.py }
Step 'fmt' { & cargo fmt --all -- --check }
Step 'build workspace' { & cargo build --workspace --locked }
Step 'build test-support examples' { & cargo build -p dissect3d-engine --features test-support --examples --locked }
Step 'clippy default' { & cargo clippy --workspace --all-targets --locked -- -D warnings }
Step 'clippy engine test-support' { & cargo clippy -p dissect3d-engine --all-targets --features test-support --locked -- -D warnings }
Step 'clippy platform native-test-hooks' { & cargo clippy -p dissect3d-platform --all-targets --features native-test-hooks --locked -- -D warnings }

$env:DISSECT3D_TEST_ENGINE = Join-Path $target 'debug/dissect3d-engine.exe'
$env:DISSECT3D_TEST_CLI = Join-Path $target 'debug/dissect3d.exe'
$env:DISSECT3D_TEST_DISCOVERY_ENGINE = Join-Path $target 'debug/examples/discovery_test_host.exe'
$env:DISSECT3D_TEST_SUBMISSION_ENGINE = Join-Path $target 'debug/examples/submission_test_host.exe'
$env:DISSECT3D_TEST_SUBMISSION_TOOL = Join-Path $target 'debug/examples/submission_fixture_tool.exe'

TestGraph 'tests default workspace' @('--workspace', '--all-targets')
TestGraph 'tests engine test-support' @('-p', 'dissect3d-engine', '--features', 'test-support', '--lib', '--tests')
TestGraph 'tests platform native-test-hooks' @('-p', 'dissect3d-platform', '--features', 'native-test-hooks', '--lib', '--tests')

Write-Output ''
Write-Output "Summary (Windows $([Environment]::OSVersion.Version) $env:PROCESSOR_ARCHITECTURE):"
$results | ForEach-Object { Write-Output ('{0,-6} {1}' -f $_.Status, $_.Step) }
$failedSteps = @($results | Where-Object { $_.Status -ne 'PASS' }).Count
if ($failedSteps -gt 0) { Write-Output "FAILED: $failedSteps step(s)"; exit 1 }
Write-Output 'ALL PASSED'
exit 0
