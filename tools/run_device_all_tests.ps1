param(
    [Parameter(Mandatory = $true)]
    [string]$Ip,
    [int]$Port = 8080,
    [switch]$SkipManualCurl
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Host ""
    Write-Host "== $Name =="
    & $Action | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red
        return $false
    }
    Write-Host "OK: $Name" -ForegroundColor Green
    return $true
}

$ok = $true

$stepOk = Invoke-Step "Host full HTTP test" {
    python "$repoRoot\tools\host_full_test.py" $Ip
}
if (-not $stepOk) { $ok = $false }

$stepOk = Invoke-Step "WebSocket test" {
    python "$repoRoot\tools\ws_test.py" $Ip
}
if (-not $stepOk) { $ok = $false }

if (-not $SkipManualCurl) {
    $stepOk = Invoke-Step "Manual curl sweep" {
        powershell -ExecutionPolicy Bypass -File "$repoRoot\tools\manual_curl_test.ps1" -Ip $Ip -Port $Port
    }
    if (-not $stepOk) { $ok = $false }
}

Write-Host ""
if ($ok) {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}

Write-Host "TESTS FAILED" -ForegroundColor Red
exit 1
