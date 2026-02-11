param(
    [string]$Port = "COM14"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$serverOut = Join-Path $repoRoot "tools/server.out.log"
$serverErr = Join-Path $repoRoot "tools/server.err.log"
$pidFile = Join-Path $repoRoot "tools/esp_server.pid"

if (Test-Path $pidFile) {
    $procId = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($procId) {
        Get-Process -Id $procId -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match '^python(\.exe)?$' -and
        $_.CommandLine -match 'mpremote' -and
        $_.CommandLine -match [regex]::Escape($Port)
    } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

if (Test-Path $serverOut) { Remove-Item $serverOut -Force -ErrorAction SilentlyContinue }
if (Test-Path $serverErr) { Remove-Item $serverErr -Force -ErrorAction SilentlyContinue }

$p = Start-Process -FilePath "python" -ArgumentList "-m","mpremote","connect",$Port,"run","tools/run_server_wifi.py" -NoNewWindow -PassThru -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr
$p.Id | Set-Content $pidFile

Start-Sleep -Seconds 5
if (Test-Path $serverOut) {
    Get-Content $serverOut -Tail 40
}
