# validate_liberty_core.ps1
# Full quality gate for liberty-controlled-chaos crate.
# Usage: .\validate_liberty_core.ps1  (run from repo root)
# Exit code: 0 = all gates passed, 1 = one or more gates failed.

$crate = "liberty-controlled-chaos"
$passed = 0
$failed = 0
$results = @()

function Run-Gate([string]$name, [scriptblock]$block) {
    Write-Host "[RUN ] $name" -ForegroundColor Cyan
    $output = & $block 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[PASS] $name" -ForegroundColor Green
        $script:passed++
        $script:results += [pscustomobject]@{ Gate = $name; Status = "PASS" }
    } else {
        $detail = ($output | Select-Object -Last 5) -join "`n"
        Write-Host "[FAIL] $name" -ForegroundColor Red
        Write-Host $detail -ForegroundColor Yellow
        $script:failed++
        $script:results += [pscustomobject]@{ Gate = $name; Status = "FAIL" }
    }
}

Write-Host ""
Write-Host "======================================================"
Write-Host "  Liberty Core Validation -- $crate"
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "======================================================"
Write-Host ""

Run-Gate "cargo build (debug)" {
    cargo build -p liberty-controlled-chaos
}

Run-Gate "cargo fmt --check" {
    cargo fmt -p liberty-controlled-chaos -- --check
}

Run-Gate "cargo clippy -D warnings" {
    cargo clippy -p liberty-controlled-chaos -- -D warnings
}

Run-Gate "cargo test (all)" {
    cargo test -p liberty-controlled-chaos
}

Write-Host ""
Write-Host "======================================================"
Write-Host "  Results"
Write-Host "======================================================"
$results | Format-Table -AutoSize

$total = $passed + $failed
if ($failed -eq 0) {
    Write-Host "Passed: $passed / $total"
    Write-Host "VALIDATION PASSED -- all gates green." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Passed: $passed / $total  Failed: $failed"
    Write-Host "VALIDATION FAILED -- $failed gate(s) did not pass." -ForegroundColor Red
    exit 1
}
