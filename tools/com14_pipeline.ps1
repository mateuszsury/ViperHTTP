param(
    [string]$Port = "COM14",
    [string]$BuildDir = "vendor/micropython/ports/esp32/build-ESP32S3_N16R8",
    [switch]$SkipBuild,
    [switch]$SkipFlash,
    [switch]$SkipSyncVfs,
    [switch]$SkipStartServer,
    [switch]$SkipTests,
    [switch]$SkipBench,
    [int]$BenchDuration = 10,
    [int]$BenchWorkers = 4,
    [string]$Ip = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildAbs = Join-Path $repoRoot $BuildDir
$serverOut = Join-Path $repoRoot "tools/server.out.log"
$serverErr = Join-Path $repoRoot "tools/server.err.log"
$pidFile = Join-Path $repoRoot "tools/esp_server.pid"

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Host ""
    Write-Host "== $Name =="
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Name (exit $LASTEXITCODE)"
    }
}

function Stop-DeviceServer {
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
}

function Resolve-DeviceIp {
    param([int]$TimeoutSec = 25)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $serverOut) {
            $tail = Get-Content $serverOut -Tail 50 -ErrorAction SilentlyContinue
            foreach ($line in $tail) {
                $m = [regex]::Match($line, "(\d+\.\d+\.\d+\.\d+)")
                if ($m.Success -and $m.Groups[1].Value -ne "0.0.0.0") {
                    return $m.Groups[1].Value
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    return ""
}

Push-Location $repoRoot
try {
    Stop-DeviceServer

    if (-not $SkipBuild) {
        Invoke-Step "WSL build firmware" {
            wsl bash -lc "cd /mnt/c/Users/thete/OneDrive/Dokumenty/PyCharm/ViperHTTP && ./tools/build_firmware.sh"
        }
    }

    if (-not $SkipFlash) {
        Invoke-Step "Flash firmware ($Port)" {
            Push-Location $buildAbs
            try {
                python -m esptool --chip esp32s3 -p $Port -b 460800 --before default_reset --after hard_reset write_flash "@flash_args"
            } finally {
                Pop-Location
            }
        }
    }

    if (-not $SkipSyncVfs) {
        Invoke-Step "Sync VFS + gzip" {
            powershell -ExecutionPolicy Bypass -File "$repoRoot/tools/sync_vfs.ps1" -Port $Port -Source "$repoRoot/tools/www" -Target "/www" -GzipMinSize 0 -GzipLevel 6
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_bridge.py" :/viperhttp_bridge.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_app.py" :/viperhttp_app.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_auth.py" :/viperhttp_auth.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_session.py" :/viperhttp_session.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_responses.py" :/viperhttp_responses.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_lifespan.py" :/viperhttp_lifespan.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_ws.py" :/viperhttp_ws.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_autodocs.py" :/viperhttp_autodocs.py
            python -m mpremote connect $Port fs cp "$repoRoot/viperhttp_ota.py" :/viperhttp_ota.py
        }
    }

    if (-not $SkipStartServer) {
        Invoke-Step "Start server on device" {
            if (Test-Path $serverOut) { Remove-Item $serverOut -Force -ErrorAction SilentlyContinue }
            if (Test-Path $serverErr) { Remove-Item $serverErr -Force -ErrorAction SilentlyContinue }
            $p = Start-Process -FilePath "python" -ArgumentList "-m","mpremote","connect",$Port,"run","tools/run_server_wifi.py" -NoNewWindow -PassThru -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr
            $p.Id | Set-Content $pidFile
            Start-Sleep -Seconds 3
        }
    }

    if (-not $Ip) {
        $Ip = Resolve-DeviceIp
    }
    if (-not $Ip) {
        throw "Could not resolve device IP from logs. Check tools/server.out.log"
    }
    Write-Host "Device IP: $Ip"

    if (-not $SkipTests) {
        Invoke-Step "Host full HTTP test" {
            python "$repoRoot/tools/host_full_test.py" $Ip
        }
        Invoke-Step "WebSocket test" {
            python "$repoRoot/tools/ws_test.py" $Ip
        }
        Invoke-Step "Full script sweep" {
            powershell -ExecutionPolicy Bypass -File "$repoRoot/tools/run_device_all_tests.ps1" -Ip $Ip -Port 8080
        }
    }

    if (-not $SkipBench) {
        Invoke-Step "HTTP benchmark" {
            python "$repoRoot/tools/http_bench.py" $Ip --duration $BenchDuration --workers $BenchWorkers
        }
    }

    Write-Host ""
    Write-Host "PIPELINE OK" -ForegroundColor Green
} finally {
    Pop-Location
}
