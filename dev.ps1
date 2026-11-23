#!/usr/bin/env pwsh
# dev.ps1 — Start all pwnproxy services for local development
# Requires: PowerShell 7+, node, and either poetry (repo virtualenv, preferred)
#           or a pwnproxy executable on PATH (fallback only)
#   dev.ps1              — start dev environment
#   dev.ps1 -Verbose     — same, but pwnproxy output stays in this console
#   dev.ps1 -KillPort    — free all pwnproxy ports (proxy, API, callback)
#
# pwnproxy always runs from the repo virtualenv when poetry + pyproject.toml are
# present. A global `pwnproxy` executable is only used as a fallback and is
# announced: a stale `pip install -e .` outside poetry has no dependencies
# (aiosqlite & co.), so it dies at import time.

param(
    [switch]$KillPort,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# -- Ports --
# Defaults live in pwnproxy/shared/ports.py (tests/architecture/test_ports.py
# fails if a stale literal comes back). All of them are overridable.
$ProxyPort   = if ($env:PWNPROXY_PROXY_PORT) { $env:PWNPROXY_PROXY_PORT } else { 17170 }
$ApiPort     = if ($env:PWNPROXY_API_PORT)   { $env:PWNPROXY_API_PORT   } else { 17171 }
$CallbackPort = if ($env:CALLBACK_PORT)      { $env:CALLBACK_PORT      } else { 17173 }

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
$WebPort   = if ($env:WEB_PORT)            { $env:WEB_PORT            } else { 17172 }
$HealthUrl = "http://127.0.0.1:${ApiPort}/api/v1/health"
$SSRFUrl   = "http://127.0.0.1:${CallbackPort}/"

# -- Prerequisites --
function Check-Command($cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "[ERROR] '$cmd' not found on PATH. Install it first." -ForegroundColor Red
        exit 1
    }
}

Check-Command "node"

# -- pwnproxy log files (relative to the repo, never inside the working dir) --
$RepoRoot   = $PSScriptRoot
$LogDir     = Join-Path $RepoRoot ".dev-logs"
$LogFile    = Join-Path $LogDir "pwnproxy.log"
$ErrLogFile = Join-Path $LogDir "pwnproxy.err.log"

# Repo virtualenv first, global executable only as a fallback.
function Get-PwnCommand {
    param([string]$RepoRoot)

    $hasPyproject = Test-Path -LiteralPath (Join-Path $RepoRoot "pyproject.toml")
    $poetry = Get-Command "poetry" -ErrorAction SilentlyContinue
    if ($hasPyproject -and $poetry) {
        return [pscustomobject]@{
            Kind     = "poetry"
            FilePath = $poetry.Source
            Prefix   = @("run", "pwnproxy")
            Label    = "poetry run pwnproxy ($($poetry.Source))"
            Warning  = $null
        }
    }

    $global = Get-Command "pwnproxy.exe", "pwnproxy" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -in @("Application", "ExternalScript") } |
        Select-Object -First 1
    if ($global) {
        $why = if (-not $hasPyproject) { "no pyproject.toml next to this script" } else { "poetry not on PATH" }
        return [pscustomobject]@{
            Kind     = "global"
            FilePath = $global.Source
            Prefix   = @()
            Label    = "$($global.Source) [global executable]"
            Warning  = "using a GLOBAL pwnproxy executable ($($global.Source)) because $why. Its dependencies may not match pyproject.toml (missing aiosqlite etc.)."
        }
    }

    return $null
}

function Get-LogTail {
    param([string]$Path, [int]$Lines = 25)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Get-Content -LiteralPath $Path -Tail $Lines -ErrorAction SilentlyContinue)
}

function Test-PortBusyError {
    param([string[]]$Lines)
    if (-not $Lines -or $Lines.Count -eq 0) { return $false }
    return (($Lines -join "`n") -match 'Errno 10048|WinError 10048|address already in use|only one usage of each socket address|EADDRINUSE')
}

# Real diagnostics for a pwnproxy that died: exit code, log tail, log paths.
function Show-PwnExitDiagnostics {
    param($Job, [string]$LogFile, [string]$ErrLogFile, [int]$ProxyPort)

    $exitCode = "unknown"
    try { $exitCode = $Job.ExitCode } catch { }
    Write-Host "[ERROR] pwnproxy exited prematurely (exit code $exitCode)." -ForegroundColor Red

    $tail = @(Get-LogTail -Path $ErrLogFile -Lines 25)
    if ($tail.Count -eq 0) { $tail = @(Get-LogTail -Path $LogFile -Lines 25) }

    if ($tail.Count -gt 0) {
        Write-Host "[dev] Last $($tail.Count) line(s) of the log:" -ForegroundColor Yellow
        $tail | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "[dev] (no log output captured - rerun as 'dev.ps1 -Verbose' to see pwnproxy output live)" -ForegroundColor Yellow
    }

    if (Test-PortBusyError $tail) {
        Write-Host "  The log says the port is in use. Try: `$env:PWNPROXY_PROXY_PORT=9090" -ForegroundColor Yellow
    }

    if ($LogFile -and (Test-Path -LiteralPath $LogFile)) {
        Write-Host "[dev]   stdout log: $LogFile" -ForegroundColor DarkGray
    }
    if ($ErrLogFile -and (Test-Path -LiteralPath $ErrLogFile)) {
        Write-Host "[dev]   stderr log: $ErrLogFile" -ForegroundColor DarkGray
    }
}

# Web UI URL with the API token in the fragment, read from the CLI itself.
# `pwnproxy api token` also prints the token and the file; only the URL is
# returned here, so no other line of this script can leak the secret. Without a
# token (older CLI, command failed) the bare URL is returned and the UI asks for
# the token by hand.
function Get-WebUiUrl {
    param($Pwn, [int]$WebPort)

    $fallback = "http://127.0.0.1:${WebPort}/"
    try {
        $lines = & $Pwn.FilePath ($Pwn.Prefix + @("api", "token")) 2>$null
        $tokenLine = $lines | Where-Object { $_ -match '^Token:\s' } | Select-Object -First 1
        if (-not $tokenLine) { return $fallback }
        $token = ($tokenLine -replace '^Token:\s+', '').Trim()
        if (-not $token) { return $fallback }
        return "http://127.0.0.1:${WebPort}/#token=${token}"
    } catch {
        Write-Host "[dev] WARNING: could not read the API token ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "[dev]   Get it with: $($Pwn.Label) api token" -ForegroundColor DarkGray
        return $fallback
    }
}

$Pwn = Get-PwnCommand -RepoRoot $RepoRoot
if (-not $Pwn) {
    Write-Host "[ERROR] Could not find pwnproxy: poetry is not on PATH and no pwnproxy executable is available." -ForegroundColor Red
    Write-Host "  Recommended: run 'poetry install' in $RepoRoot, then retry." -ForegroundColor Yellow
    exit 1
}
if ($Pwn.Warning) {
    Write-Host "[dev] WARNING: $($Pwn.Warning)" -ForegroundColor Yellow
}
Write-Host "[dev] Using $($Pwn.Label)" -ForegroundColor DarkGray

# -- Web UI needs a reachable API host (0.0.0.0 is not valid in browser) --
$WebApiHost = if ($ApiHost -eq "0.0.0.0") { "127.0.0.1" } else { $ApiHost }
$env:PUBLIC_API_BASE = "http://${WebApiHost}:${ApiPort}/api/v1"

Write-Host "`n[dev] Starting pwnproxy dev environment..." -ForegroundColor Cyan

# -- 1. Start pwnproxy in background --
$pwnCommandArgs = @(
    "start", "--host", "$ApiHost", "--proxy-port", "$ProxyPort", "--api-port", "$ApiPort", "--callback-port", "$CallbackPort", "--no-restore-session"
)
$pwnArgs = @{ PassThru = $true }
if ($Verbose) {
    $pwnArgs["NoNewWindow"] = $true
    Write-Host "[dev] Starting proxy on port ${ProxyPort} (API: ${ApiHost}:${ApiPort})... (verbose)" -ForegroundColor Yellow
    Write-Host "[dev]   pwnproxy logs will appear below" -ForegroundColor Gray
} else {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    Remove-Item -LiteralPath $LogFile, $ErrLogFile -Force -ErrorAction SilentlyContinue
    $pwnArgs["WindowStyle"] = "Hidden"
    $pwnArgs["RedirectStandardOutput"] = $LogFile
    $pwnArgs["RedirectStandardError"] = $ErrLogFile
    Write-Host "[dev] Starting proxy on port ${ProxyPort} (API: ${ApiHost}:${ApiPort})..." -ForegroundColor Yellow
    Write-Host "[dev]   log: $LogFile" -ForegroundColor Gray
}
$proxyJob = Start-Process @pwnArgs -FilePath $Pwn.FilePath -ArgumentList ($Pwn.Prefix + $pwnCommandArgs)

# -- 2. Poll API health endpoint --
Write-Host "[dev] Waiting for API to be ready..." -ForegroundColor Yellow
$ready = $false
$exitedEarly = $false
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 1
    if ($proxyJob.HasExited) {
        $exitedEarly = $true
        break
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

if ($exitedEarly) {
    if ($Verbose) {
        Write-Host "[ERROR] pwnproxy exited prematurely (exit code $($proxyJob.ExitCode))." -ForegroundColor Red
        Write-Host "[dev]   Its output was printed above (verbose mode)." -ForegroundColor DarkGray
    } else {
        Show-PwnExitDiagnostics -Job $proxyJob -LogFile $LogFile -ErrLogFile $ErrLogFile -ProxyPort $ProxyPort
    }
    exit 1
}

if (-not $ready) {
    Write-Host "[ERROR] API did not start within 15 seconds." -ForegroundColor Red
    if (-not $Verbose) {
        $tail = @(Get-LogTail -Path $ErrLogFile -Lines 25)
        if ($tail.Count -eq 0) { $tail = @(Get-LogTail -Path $LogFile -Lines 25) }
        if ($tail.Count -gt 0) {
            Write-Host "[dev] Last $($tail.Count) line(s) of the log:" -ForegroundColor Yellow
            $tail | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
        }
        Write-Host "[dev]   log: $LogFile" -ForegroundColor DarkGray
    }
    taskkill /T /F /PID $proxyJob.Id 2>&1 | Out-Null
    exit 1
}
Write-Host "[dev] API is ready!" -ForegroundColor Green
if (-not $Verbose) {
    Write-Host "[dev]   log: $LogFile" -ForegroundColor DarkGray
    Write-Host "[dev]   errors: $ErrLogFile" -ForegroundColor DarkGray
}

# -- 2b. Read the API token (the Web UI needs it in the URL fragment) --
# The API requires Authorization: Bearer <token>; the Web UI takes it from
# #token=... . Only the URL is printed: the token must not appear on any other
# line of this output (it would end up in a log or in a pasted issue).
$WebUiUrl = Get-WebUiUrl -Pwn $Pwn -WebPort $WebPort

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
Write-Host "  Web UI -> $WebUiUrl" -ForegroundColor Cyan
Write-Host "            (open this URL: the token travels in the fragment, never to a server)" -ForegroundColor DarkGray
if (-not $Verbose) {
    Write-Host "  Log    -> $LogFile" -ForegroundColor Green
}
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
    npm run dev -- --host --port $WebPort
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
