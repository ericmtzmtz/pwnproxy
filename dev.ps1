#!/usr/bin/env pwsh
# dev.ps1 — Start all pwnproxy services for local development
# Requires: PowerShell 7+, poetry, node, pwnproxy on PATH
#   dev.ps1              — start dev environment
#   dev.ps1 -KillPort    — free all pwnproxy ports (proxy, API, callback)

param(
    [switch]$KillPort,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# -- Ports --
$ProxyPort   = if ($env:PWNPROXY_PROXY_PORT) { $env:PWNPROXY_PROXY_PORT } else { 8080 }
$ApiPort     = if ($env:PWNPROXY_API_PORT)   { $env:PWNPROXY_API_PORT   } else { 8000 }
$CallbackPort = 18081

function Clear-Port($portNum, $label, [switch]$Prompt) {
    Write-Host "[dev] Finding process(es) on port $portNum ($label)..." -ForegroundColor Yellow
    $conn = Get-NetTCPConnection -LocalPort $portNum -ErrorAction SilentlyContinue
    if (-not $conn) {
        Write-Host "[dev]   Port $portNum is free" -ForegroundColor Green
        return
    }
    $procs = $conn | ForEach-Object { $_.OwningProcess } | Sort-Object -Unique
    $procNames = $procs | ForEach-Object { (Get-Process -Id $_ -ErrorAction SilentlyContinue).ProcessName }
    Write-Host "[dev]   Stale process(es) on port $portNum : $($procNames -join ', ')" -ForegroundColor Yellow

    if ($Prompt) {
        $choice = Read-Host "  Kill them? [Y/n]"
        if ($choice -ne "" -and $choice -notmatch "^(y|yes)$") {
            Write-Host "[dev]   Skipped" -ForegroundColor Gray
            return
        }
    }

    foreach ($procId in $procs) {
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "  Killing PID $procId ($($proc.ProcessName))..." -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
    $remaining = Get-NetTCPConnection -LocalPort $portNum -ErrorAction SilentlyContinue
    if ($remaining) {
        Write-Host "[dev]   WARNING: Port $portNum still in use. Retrying..." -ForegroundColor Red
        $remaining | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 1
    } else {
        Write-Host "[dev]   Port $portNum freed" -ForegroundColor Green
    }
}

if ($KillPort) {
    Clear-Port $ProxyPort "proxy"
    Clear-Port $ApiPort "API"
    Clear-Port $CallbackPort "SSRF callback"
    exit 0
}

# -- Clear stale ports before starting (prompts user) --
Clear-Port $ProxyPort "proxy (stale)" -Prompt
Clear-Port $ApiPort "API (stale)" -Prompt
Clear-Port $CallbackPort "SSRF callback (stale)" -Prompt

$ApiHost   = if ($env:PWNPROXY_API_HOST)   { $env:PWNPROXY_API_HOST   } else { "127.0.0.1" }
$WebPort   = 4321
$HealthUrl = "http://127.0.0.1:${ApiPort}/api/v1/health"
$SSRFUrl   = "http://127.0.0.1:${CallbackPort}/"

# -- Prerequisites --
function Check-Command($cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "[ERROR] '$cmd' not found on PATH. Install it first." -ForegroundColor Red
        exit 1
    }
}

Check-Command "poetry"
Check-Command "node"

# Try to find pwnproxy, fall back to poetry run
$PwnCmd = "pwnproxy"
if (-not (Get-Command "pwnproxy" -ErrorAction SilentlyContinue)) {
    Write-Host "[dev] pwnproxy not on PATH, trying 'poetry run pwnproxy'..." -ForegroundColor Yellow
    $PwnCmd = "poetry"
    # Verify we can find it via poetry
    $test = & poetry run pwnproxy --help 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Could not find pwnproxy via PATH or poetry." -ForegroundColor Red
        Write-Host "  Run 'poetry shell' or 'pip install -e .' first." -ForegroundColor Yellow
        exit 1
    }
}

# -- Web UI needs a reachable API host (0.0.0.0 is not valid in browser) --
$WebApiHost = if ($ApiHost -eq "0.0.0.0") { "127.0.0.1" } else { $ApiHost }
$env:PUBLIC_API_BASE = "http://${WebApiHost}:${ApiPort}/api/v1"

Write-Host "`n[dev] Starting pwnproxy dev environment..." -ForegroundColor Cyan

# -- 1. Start pwnproxy in background --
$pwnArgs = @{ PassThru = $true }
if ($Verbose) {
    $pwnArgs["NoNewWindow"] = $true
    Write-Host "[dev] Starting proxy on port ${ProxyPort} (API: ${ApiHost}:${ApiPort})... (verbose)" -ForegroundColor Yellow
    Write-Host "[dev]   pwnproxy logs will appear below" -ForegroundColor Gray
} else {
    $pwnArgs["WindowStyle"] = "Hidden"
    Write-Host "[dev] Starting proxy on port ${ProxyPort} (API: ${ApiHost}:${ApiPort})..." -ForegroundColor Yellow
}
if ($PwnCmd -eq "poetry") {
    $proxyJob = Start-Process @pwnArgs -FilePath "poetry" -ArgumentList @(
        "run", "pwnproxy", "start", "--host", "$ApiHost", "--proxy-port", "$ProxyPort", "--api-port", "$ApiPort", "--callback-port", "18081", "--no-restore-session"
    )
} else {
    $proxyJob = Start-Process @pwnArgs -FilePath "pwnproxy" -ArgumentList @(
        "start", "--host", "$ApiHost", "--proxy-port", "$ProxyPort", "--api-port", "$ApiPort", "--callback-port", "18081", "--no-restore-session"
    )
}

# -- 2. Poll API health endpoint --
Write-Host "[dev] Waiting for API to be ready..." -ForegroundColor Yellow
$ready = $false
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 1
    if ($proxyJob.HasExited) {
        Write-Host "[ERROR] pwnproxy exited prematurely (port $ProxyPort may be in use)." -ForegroundColor Red
        Write-Host "  Try: `$env:PWNPROXY_PROXY_PORT=9090" -ForegroundColor Yellow
        exit 1
    }
    try {
        $code = curl.exe -s -o nul -w "%{http_code}" $HealthUrl 2>$null
        if ($code -eq "200") {
            $ready = $true
            break
        }
    } catch { }
    Write-Host "[dev]   Attempt $i/15 - not ready yet..." -ForegroundColor Gray
}

if (-not $ready) {
    Write-Host "[ERROR] API did not start within 15 seconds." -ForegroundColor Red
    taskkill /T /F /PID $proxyJob.Id 2>&1 | Out-Null
    exit 1
}
Write-Host "[dev] API is ready!" -ForegroundColor Green

# -- 3. Verify SSRF callback is listening --
Write-Host "[dev] Verifying SSRF callback server..." -ForegroundColor Yellow
Start-Sleep -Seconds 1
try {
    $cbCode = curl.exe -s -o nul -w "%{http_code}" $SSRFUrl 2>$null
    if ($cbCode -ne "") { Write-Host "[dev]   SSRF callback OK" -ForegroundColor Green }
    else                { throw }
} catch {
    Write-Host "[dev]   (SSRF callback not reachable yet - will check later)" -ForegroundColor Gray
}

# -- 4. Print URLs --
Write-Host ""
Write-Host "--- pwnproxy Dev Environment ---" -ForegroundColor Cyan
Write-Host "  API   -> http://${ApiHost}:$ApiPort" -ForegroundColor Green
Write-Host "  Proxy -> http://${ApiHost}:$ProxyPort" -ForegroundColor Green
Write-Host "  Docs  -> http://${ApiHost}:${ApiPort}/docs" -ForegroundColor Green
Write-Host "  Web UI -> http://127.0.0.1:$WebPort" -ForegroundColor Green
Write-Host "---------------------------------" -ForegroundColor Cyan
if ($ApiHost -eq "0.0.0.0") {
    Write-Host "Remote access: http://<this-machine-ip>:$ApiPort" -ForegroundColor Yellow
}
Write-Host "Press Ctrl+C to stop" -ForegroundColor DarkGray
Write-Host ""

# -- 5. Start Web UI in foreground (blocks until Ctrl+C) --
$webDir = Join-Path $PSScriptRoot "apps/web"
Push-Location $webDir
try {
    npm run dev -- --host 
} finally {
    Pop-Location
    Write-Host "`n[dev] Shutting down..." -ForegroundColor Yellow

    # Kill pwnproxy (background)
    if ($proxyJob -and -not $proxyJob.HasExited) {
        taskkill /T /F /PID $proxyJob.Id 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
    }

    # Fallback: kill anything still holding pwnproxy ports
    foreach ($port in @($ProxyPort, $ApiPort, $CallbackPort)) {
        $stale = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        if ($stale) {
            Write-Host "[dev] Cleaning up process(es) on port $port..." -ForegroundColor Yellow
            $stale | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 500
            $still = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
            if ($still) {
                Write-Host "[WARN] Port $port still in use - run 'dev.ps1 -KillPort' to retry" -ForegroundColor Red
            } else {
                Write-Host "[dev] Port $port freed" -ForegroundColor Green
            }
        }
    }
}
