#!/usr/bin/env pwsh
# dev.ps1 — Start all pwnproxy services for local development
# Requires: PowerShell 7+, poetry, node, pwnproxy on PATH
#   dev.ps1              — start dev environment
#   dev.ps1 -KillPort    — kill process(es) holding port 8080

param([switch]$KillPort)

$ErrorActionPreference = "Stop"

if ($KillPort) {
    $portNum = if ($env:PWNPROXY_PROXY_PORT) { $env:PWNPROXY_PROXY_PORT } else { 8080 }
    Write-Host "[dev] Finding process(es) on port $portNum..." -ForegroundColor Yellow
    $conn = Get-NetTCPConnection -LocalPort $portNum -ErrorAction SilentlyContinue
    if (-not $conn) {
        Write-Host "[dev] No process found on port $portNum" -ForegroundColor Green
        exit 0
    }
    $procs = $conn | ForEach-Object { $_.OwningProcess } | Sort-Object -Unique
    foreach ($procId in $procs) {
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "  Killing PID $procId ($($proc.ProcessName))..." -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 1
    $remaining = Get-NetTCPConnection -LocalPort $portNum -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Write-Host "[dev] Port $portNum is now free" -ForegroundColor Green
    } else {
        Write-Host "[dev] WARNING: Port $portNum still in use. Retrying..." -ForegroundColor Red
        $remaining | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 1
    }
    exit 0
}

$ProxyPort = if ($env:PWNPROXY_PROXY_PORT) { $env:PWNPROXY_PROXY_PORT } else { 8080 }
$ApiPort   = if ($env:PWNPROXY_API_PORT)   { $env:PWNPROXY_API_PORT   } else { 8000 }
$ApiHost   = if ($env:PWNPROXY_API_HOST)   { $env:PWNPROXY_API_HOST   } else { "127.0.0.1" }
$WebPort   = 4321
$HealthUrl = "http://127.0.0.1:${ApiPort}/api/v1/health"

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

Write-Host "`n[dev] Starting pwnproxy dev environment..." -ForegroundColor Cyan

# -- Start Proxy --
Write-Host "[dev] Starting proxy on port ${ProxyPort} (API: ${ApiHost}:${ApiPort})..." -ForegroundColor Yellow
if ($PwnCmd -eq "poetry") {
    $proxyJob = Start-Process -NoNewWindow -PassThru -FilePath "poetry" -ArgumentList @(
        "run", "pwnproxy", "start", "--host", "$ApiHost", "--proxy-port", "$ProxyPort", "--api-port", "$ApiPort", "--no-restore-session"
    )
} else {
    $proxyJob = Start-Process -NoNewWindow -PassThru -FilePath "pwnproxy" -ArgumentList @(
        "start", "--host", "$ApiHost", "--proxy-port", "$ProxyPort", "--api-port", "$ApiPort", "--no-restore-session"
    )
}

# -- Poll health endpoint --
Write-Host "[dev] Waiting for API to be ready..." -ForegroundColor Yellow
$ready = $false
for ($i = 1; $i -le 5; $i++) {
    Start-Sleep -Seconds 1

    # Check if proxy process died
    if ($proxyJob.HasExited) {
        Write-Host "[ERROR] Proxy process exited prematurely (port $ProxyPort may be in use)." -ForegroundColor Red
        Write-Host "  Try a different port: `$env:PWNPROXY_PROXY_PORT=9090" -ForegroundColor Yellow
        Write-Host "  Or check what's using the port: netstat -ano | findstr :$ProxyPort" -ForegroundColor Yellow
        exit 1
    }

    try {
        $res = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2
        if ($res.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        # Not ready yet
    }
    Write-Host "[dev]   Attempt $i/5 - not ready yet..." -ForegroundColor Gray
}

if (-not $ready) {
    Write-Host "[ERROR] API did not start within 5 seconds. The proxy process may still be running." -ForegroundColor Red
    Write-Host "  Check if the proxy logged errors above." -ForegroundColor Yellow
    Stop-Process -Id $proxyJob.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "[dev] API is ready!" -ForegroundColor Green

# -- Set env for Web UI --
$env:PUBLIC_API_BASE = "http://${ApiHost}:${ApiPort}/api/v1"

# -- Print URLs --
Write-Host ""
Write-Host "--- pwnproxy Dev Environment ---" -ForegroundColor Cyan
Write-Host "  Proxy -> http://${ApiHost}:$ProxyPort" -ForegroundColor Green
Write-Host "  API   -> http://${ApiHost}:$ApiPort" -ForegroundColor Green
Write-Host "  Docs  -> http://${ApiHost}:${ApiPort}/docs" -ForegroundColor Green
Write-Host "  Web UI -> http://127.0.0.1:$WebPort" -ForegroundColor Green
Write-Host "---------------------------------" -ForegroundColor Cyan
if ($ApiHost -eq "0.0.0.0") {
    Write-Host "Remote access: http://<this-machine-ip>:$ApiPort" -ForegroundColor Yellow
}
Write-Host "Press Ctrl+C to stop all services" -ForegroundColor DarkGray
Write-Host ""

# Start Web UI in foreground (blocks until Ctrl+C)
$webDir = Join-Path $PSScriptRoot "web-ui"
Push-Location $webDir
try {
    npm run dev
} finally {
    Pop-Location
    # Clean up proxy when Web UI exits
    if ($proxyJob -and -not $proxyJob.HasExited) {
        Write-Host "`n[dev] Shutting down..." -ForegroundColor Yellow
        # Kill the entire process tree (poetry + python + mitmproxy)
        taskkill /T /F /PID $proxyJob.Id 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
    }

    # Fallback: kill anything still holding the proxy port
    $stale = Get-NetTCPConnection -LocalPort $ProxyPort -ErrorAction SilentlyContinue
    if ($stale) {
        Write-Host "[dev] Cleaning up process(es) on port $ProxyPort..." -ForegroundColor Yellow
        $stale | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        $still = Get-NetTCPConnection -LocalPort $ProxyPort -ErrorAction SilentlyContinue
        if ($still) {
            Write-Host "[WARN] Port $ProxyPort still in use - run 'dev.ps1 -KillPort' to retry" -ForegroundColor Red
        } else {
            Write-Host "[dev] Port $ProxyPort freed" -ForegroundColor Green
        }
    }
}
