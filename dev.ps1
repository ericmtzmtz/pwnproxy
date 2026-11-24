#!/usr/bin/env pwsh
# dev.ps1 — Start all pwnproxy services for local development
# Requires: PowerShell 7+, node, and either poetry (repo virtualenv, preferred)
#           or a pwnproxy executable on PATH (fallback only)
#   dev.ps1              — start dev environment
#   dev.ps1 -Verbose     — same, but pwnproxy output stays in this console
#   dev.ps1 -KillPort    — free all pwnproxy ports (proxy, API, callback, Web UI)
#
# The Web UI runs in the background and the box with the URL is printed only
# after it answers on its own port, so the printed link works on the first
# click instead of showing a connection error for ~15 s. PWNPROXY_WEBUI_TIMEOUT
# overrides the 60 s wait.
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
$WebPort     = if ($env:WEB_PORT)            { $env:WEB_PORT            } else { 17172 }
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
    Clear-Port $WebPort "Web UI"
    Clear-Port $CallbackPort "SSRF callback"
    exit 0
}

# -- Clear stale ports before starting (prompts user) --
Clear-Port $ProxyPort "proxy (stale)" -Prompt
Clear-Port $ApiPort "API (stale)" -Prompt
Clear-Port $WebPort "Web UI (stale)" -Prompt
Clear-Port $CallbackPort "SSRF callback (stale)" -Prompt

$ApiHost   = if ($env:PWNPROXY_API_HOST)   { $env:PWNPROXY_API_HOST   } else { "127.0.0.1" }
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
$WebLog     = Join-Path $LogDir "webui.log"
$WebErrLog  = Join-Path $LogDir "webui.err.log"

# How long to wait for the Web UI port to answer before giving up (seconds).
$WebWaitSeconds = 60
if ($env:PWNPROXY_WEBUI_TIMEOUT) {
    $parsed = 0
    if ([int]::TryParse($env:PWNPROXY_WEBUI_TIMEOUT, [ref]$parsed) -and $parsed -gt 0) {
        $WebWaitSeconds = $parsed
    } else {
        Write-Host "[dev] WARNING: PWNPROXY_WEBUI_TIMEOUT='$($env:PWNPROXY_WEBUI_TIMEOUT)' is not a positive number; using 60." -ForegroundColor Yellow
    }
}

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
            Display  = "poetry run pwnproxy"
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
            Display  = $global.Source
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
# the token by hand. The returned object carries HasToken so the caller can say
# plainly whether a token was read; `Detail` explains a failed read without ever
# quoting a secret.
function Get-WebUiUrl {
    param($Pwn, [int]$WebPort)

    $fallback = "http://127.0.0.1:${WebPort}/"
    try {
        $lines = & $Pwn.FilePath ($Pwn.Prefix + @("api", "token")) 2>$null
        $tokenLine = $lines | Where-Object { $_ -match '^Token:\s' } | Select-Object -First 1
        if (-not $tokenLine) {
            return [pscustomobject]@{ Url = $fallback; HasToken = $false; Detail = "the CLI printed no 'Token:' line" }
        }
        $token = ($tokenLine -replace '^Token:\s+', '').Trim()
        if (-not $token) {
            return [pscustomobject]@{ Url = $fallback; HasToken = $false; Detail = "the CLI printed an empty token" }
        }
        return [pscustomobject]@{ Url = "http://127.0.0.1:${WebPort}/#token=${token}"; HasToken = $true; Detail = $null }
    } catch {
        return [pscustomobject]@{ Url = $fallback; HasToken = $false; Detail = $_.Exception.Message }
    }
}

# Real diagnostics for a Web UI that died or never answered: exit code, log tails.
function Show-WebUiDiagnostics {
    param($Job, [string]$StdLog, [string]$ErrLog, [string]$ProbeUrl)

    if ($Job -and $Job.HasExited) {
        $exitCode = "unknown"
        try { $exitCode = $Job.ExitCode } catch { }
        Write-Host "[ERROR] The Web UI exited prematurely (exit code $exitCode)." -ForegroundColor Red
    } elseif ($ProbeUrl) {
        Write-Host "[ERROR] The Web UI did not answer on $ProbeUrl within ${WebWaitSeconds} seconds." -ForegroundColor Red
        Write-Host "[dev]   Raise the limit with: `$env:PWNPROXY_WEBUI_TIMEOUT=120" -ForegroundColor Gray
    }

    $tail = @(Get-LogTail -Path $ErrLog -Lines 25)
    if ($tail.Count -eq 0) { $tail = @(Get-LogTail -Path $StdLog -Lines 25) }

    if ($tail.Count -gt 0) {
        Write-Host "[dev] Last $($tail.Count) line(s) of the Web UI log:" -ForegroundColor Yellow
        $tail | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "[dev] (no Web UI output captured)" -ForegroundColor Yellow
    }

    if ($StdLog -and (Test-Path -LiteralPath $StdLog)) {
        Write-Host "[dev]   stdout log: $StdLog" -ForegroundColor DarkGray
    }
    if ($ErrLog -and (Test-Path -LiteralPath $ErrLog)) {
        Write-Host "[dev]   stderr log: $ErrLog" -ForegroundColor DarkGray
    }
}

# Streams new complete lines of one Web UI log to this console. Byte offsets in
# $State keep it cheap; a half-written line waits for its newline instead of
# being printed twice.
function Watch-WebLogFile {
    param([hashtable]$State, [string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $start = if ($State.ContainsKey($Path)) { [long]$State[$Path] } else { [long]0 }
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    } catch { return }

    try {
        $length = $stream.Length
        if ($length -lt $start) { $start = 0 }      # log was truncated
        if ($length -eq $start) { $State[$Path] = $start; return }

        [void]$stream.Seek($start, [System.IO.SeekOrigin]::Begin)
        $count = [int]($length - $start)
        $buffer = New-Object byte[] $count
        [void]$stream.Read($buffer, 0, $count)

        $lastNewline = -1
        for ($i = $buffer.Length - 1; $i -ge 0; $i--) {
            if ($buffer[$i] -eq 10) { $lastNewline = $i; break }
        }
        if ($lastNewline -lt 0) { $State[$Path] = $start; return }

        $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $lastNewline)
        foreach ($line in ($text -split "`n")) {
            Write-Host ($line.TrimEnd("`r"))
        }
        $State[$Path] = $start + $lastNewline + 1
    } finally {
        $stream.Dispose()
    }
}

# Stops both background services (process tree) and frees their ports. Used on
# every exit path, so Ctrl+C and startup failures leave nothing listening.
function Stop-DevProcesses {
    param($ProxyJob, $WebJob)

    Write-Host "`n[dev] Shutting down..." -ForegroundColor Yellow

    foreach ($job in @($ProxyJob, $WebJob)) {
        if ($job -and -not $job.HasExited) {
            taskkill /T /F /PID $job.Id 2>&1 | Out-Null
            Start-Sleep -Milliseconds 500
        }
    }

    # Fallback: kill anything still holding pwnproxy ports
    foreach ($port in @($ProxyPort, $ApiPort, $CallbackPort, $WebPort)) {
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
    Stop-DevProcesses -ProxyJob $proxyJob
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
    Stop-DevProcesses -ProxyJob $proxyJob
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
# line of this output (it would end up in a log or in a pasted issue). That is
# why the status line says OK/NOT FOUND instead of echoing the value.
$WebUi = Get-WebUiUrl -Pwn $Pwn -WebPort $WebPort
$WebUiUrl = $WebUi.Url
if ($WebUi.HasToken) {
    Write-Host "[dev] API token: OK" -ForegroundColor Green
} else {
    Write-Host "[dev] API token: NOT FOUND - the Web UI will ask for it (get it with: $($Pwn.Display) api token)" -ForegroundColor Yellow
    if ($WebUi.Detail) {
        Write-Host "[dev]   reason: $($WebUi.Detail)" -ForegroundColor DarkGray
    }
}

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

# -- 4. Start the Web UI in the background --
# A background Process cannot share this console, so its output goes to a log
# (that log is also what the failure path tails) and step 7 streams it live.
# It needs ~15 s to answer, therefore the URL box waits for the port: opening
# the link the second it is printed has to work.
$WebProbeUrl = "http://127.0.0.1:${WebPort}/"
$webDir = Join-Path $RepoRoot "apps/web"
$npm = Get-Command "npm.cmd", "npm" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $npm) {
    Write-Host "[ERROR] 'npm' not found on PATH. Install Node.js first." -ForegroundColor Red
    Stop-DevProcesses -ProxyJob $proxyJob
    exit 1
}

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
Remove-Item -LiteralPath $WebLog, $WebErrLog -Force -ErrorAction SilentlyContinue
Write-Host "[dev] Starting the Web UI on port ${WebPort}..." -ForegroundColor Yellow
Write-Host "[dev]   log: $WebLog" -ForegroundColor Gray
$webJob = Start-Process -FilePath $npm.Source `
    -ArgumentList @("run", "dev", "--", "--host", "--port", "$WebPort") `
    -WorkingDirectory $webDir -WindowStyle Hidden `
    -RedirectStandardOutput $WebLog -RedirectStandardError $WebErrLog -PassThru

# -- 5. Wait for the Web UI port to answer (anything under 500 counts) --
Write-Host "[dev] Waiting for the Web UI..." -ForegroundColor Yellow
$webReady = $false
$webExited = $false
for ($i = 1; $i -le $WebWaitSeconds; $i++) {
    Start-Sleep -Seconds 1
    if ($webJob.HasExited) {
        $webExited = $true
        break
    }
    $code = ""
    try { $code = curl.exe -s -o nul -w "%{http_code}" $WebProbeUrl 2>$null } catch { }
    if ($code -match '^\d{3}$') {
        $codeNum = [int]$code
        if ($codeNum -ge 200 -and $codeNum -lt 500) {
            $webReady = $true
            break
        }
    }
    Write-Host "[dev]   Attempt $i/$WebWaitSeconds - not ready yet..." -ForegroundColor Gray
}

if ($webExited) {
    Show-WebUiDiagnostics -Job $webJob -StdLog $WebLog -ErrLog $WebErrLog
    Stop-DevProcesses -ProxyJob $proxyJob -WebJob $webJob
    exit 1
}

if (-not $webReady) {
    Show-WebUiDiagnostics -Job $webJob -StdLog $WebLog -ErrLog $WebErrLog -ProbeUrl $WebProbeUrl
    Stop-DevProcesses -ProxyJob $proxyJob -WebJob $webJob
    exit 1
}
Write-Host "[dev] Web UI is ready!" -ForegroundColor Green

# -- 6. Print URLs (only now, so the link works on the first click) --
Write-Host ""
Write-Host "--- pwnproxy Dev Environment ---" -ForegroundColor Cyan
Write-Host "  API   -> http://${ApiHost}:$ApiPort" -ForegroundColor Green
Write-Host "  Proxy -> http://${ApiHost}:$ProxyPort" -ForegroundColor Green
Write-Host "  Docs  -> http://${ApiHost}:${ApiPort}/docs" -ForegroundColor Green
Write-Host "  Web UI -> $WebUiUrl" -ForegroundColor Cyan
if ($WebUi.HasToken) {
    Write-Host "            (open this URL: the token travels in the fragment, never to a server)" -ForegroundColor DarkGray
} else {
    Write-Host "            (open this URL and paste the token the UI asks for)" -ForegroundColor DarkGray
}
if (-not $Verbose) {
    Write-Host "  Log    -> $LogFile" -ForegroundColor Green
}
Write-Host "  Astro  -> $WebLog" -ForegroundColor Green
Write-Host "---------------------------------" -ForegroundColor Cyan
if ($ApiHost -eq "0.0.0.0") {
    Write-Host "Remote access: http://<this-machine-ip>:$ApiPort" -ForegroundColor Yellow
}
Write-Host "Press Ctrl+C to stop" -ForegroundColor DarkGray
Write-Host ""

# -- 7. Follow the Web UI output until Ctrl+C (or until it dies) --
Write-Host "[dev] Web UI output follows (Ctrl+C stops everything)" -ForegroundColor Gray
$followState = @{ $WebLog = [long]0; $WebErrLog = [long]0 }
try {
    while (-not $webJob.HasExited) {
        foreach ($path in @($WebLog, $WebErrLog)) {
            Watch-WebLogFile -State $followState -Path $path
        }
    }
    # Flush whatever the Web UI wrote on its way out.
    foreach ($path in @($WebLog, $WebErrLog)) {
        Watch-WebLogFile -State $followState -Path $path
    }
    $webExit = $webJob.ExitCode
    if ($webExit -eq 0) {
        Write-Host "`n[dev] The Web UI exited." -ForegroundColor Gray
    } else {
        Write-Host "`n[ERROR] The Web UI stopped (exit code $webExit)." -ForegroundColor Red
        $tail = @(Get-LogTail -Path $WebErrLog -Lines 15)
        if ($tail.Count -eq 0) { $tail = @(Get-LogTail -Path $WebLog -Lines 15) }
        $tail | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    }
} finally {
    Stop-DevProcesses -ProxyJob $proxyJob -WebJob $webJob
}

