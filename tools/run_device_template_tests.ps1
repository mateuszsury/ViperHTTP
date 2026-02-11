param(
    [string]$Port = "COM14"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Step {
    param(
        [string]$Name,
        [string]$ScriptPath
    )
    Write-Host ""
    Write-Host "== $Name =="
    $output = python -m mpremote connect $Port run $ScriptPath 2>&1
    $output | ForEach-Object { Write-Host $_ }
    $outputText = ($output | Out-String)
    if ($outputText -match "FAIL:") {
        Write-Host "FAILED: $Name (output contains FAIL)" -ForegroundColor Red
        exit 1
    }
    if ($outputText -notmatch "PASS") {
        Write-Host "FAILED: $Name (missing PASS marker)" -ForegroundColor Red
        exit 1
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "OK: $Name" -ForegroundColor Green
}

Invoke-Step "Template parse error test" "$repoRoot\tools\device_template_parse_error_test.py"
Invoke-Step "Template debug mode test" "$repoRoot\tools\device_template_debug_test.py"
Invoke-Step "Template parser vectors test" "$repoRoot\tools\device_template_parser_vectors_test.py"
Invoke-Step "Template include test" "$repoRoot\tools\device_template_include_test.py"
Invoke-Step "Template runtime matrix test" "$repoRoot\tools\device_template_runtime_matrix_test.py"
Invoke-Step "Template Jinja compatibility test" "$repoRoot\tools\device_template_jinja_compat_test.py"
Invoke-Step "Template warmup test" "$repoRoot\tools\device_template_warmup_test.py"
Invoke-Step "Template cache regression test" "$repoRoot\tools\device_template_cache_regression_test.py"

Write-Host ""
Write-Host "ALL TEMPLATE TESTS PASSED" -ForegroundColor Green
