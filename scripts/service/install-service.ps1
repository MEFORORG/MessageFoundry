<#
.SYNOPSIS
    Install MessageFoundry as a Windows background service using NSSM.

.DESCRIPTION
    Registers the MessageFoundry engine ("messagefoundry serve") as a Windows service
    via NSSM (https://nssm.cc). The service starts on boot, restarts on crash, captures
    stdout/stderr to rotating log files, and is stopped with Ctrl+C so the engine drains
    connections cleanly (the ASGI lifespan calls engine.stop()).

    Run from an elevated (Administrator) PowerShell prompt.

.EXAMPLE
    .\install-service.ps1
    .\install-service.ps1 -Port 9000 -LogLevel DEBUG -DataDir D:\MEFOR
#>
[CmdletBinding()]
param(
    [string]$NssmPath,
    [string]$ServiceName = "MessageFoundry",
    [string]$AppExe,
    [string]$Config,
    [string]$DbPath,
    [string]$DataDir = "C:\ProgramData\MessageFoundry",
    [string]$ListenHost = "127.0.0.1",
    [int]$Port = 8765,
    # Least-privilege service account (DEPLOY-1). Recommended: a dedicated low-privilege account or
    # a virtual service account, e.g. -ServiceAccount "NT SERVICE\MessageFoundry" (no password). It
    # needs only read on -Config and read/write on -DataDir. When omitted, the service runs as
    # LocalSystem (NSSM default) and a warning is printed. See docs/SERVICE.md.
    [string]$ServiceAccount,
    [SecureString]$ServiceAccountPassword,
    [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
    [string]$LogLevel = "INFO"
)

$ErrorActionPreference = "Stop"

# Pinned NSSM release, auto-downloaded if not already present (so end users need no manual setup).
$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$NssmSha256 = "727D1E42275C605E0F04ABA98095C38A8E1E46DEF453CDFFCE42869428AA6743"

function Resolve-Nssm {
    param([string]$Provided, [string]$DataDir)

    if ($Provided) {
        if (-not (Test-Path $Provided)) { throw "NSSM not found at: $Provided" }
        return (Resolve-Path $Provided).Path
    }
    $onPath = Get-Command nssm -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    $binDir = Join-Path $DataDir "bin"
    $cached = Join-Path $binDir "nssm.exe"
    if (Test-Path $cached) { return $cached }

    Write-Host "NSSM not found - downloading $NssmUrl ..."
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $zip = Join-Path $env:TEMP "nssm-mefor-download.zip"
    $extract = Join-Path $env:TEMP "nssm-mefor-extract"
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $NssmUrl -OutFile $zip -UseBasicParsing
    $hash = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash
    if ($hash -ne $NssmSha256) {
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        throw "NSSM download failed integrity check (got $hash, expected $NssmSha256)."
    }
    Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $zip -DestinationPath $extract -Force
    $exe = Get-ChildItem -Path $extract -Recurse -Filter nssm.exe |
        Where-Object { $_.Directory.Name -eq "win64" } | Select-Object -First 1
    if (-not $exe) { throw "win64\nssm.exe not found in the downloaded NSSM archive." }
    Copy-Item $exe.FullName $cached -Force
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "NSSM installed to $cached"
    return $cached
}

function Set-SecureDataDirAcl {
    <#
      Lock the data/log directory down to SYSTEM + Administrators (+ the service account), removing
      ProgramData's inherited BUILTIN\Users:(RX). NSSM captures the engine's stdout/stderr under here,
      and those logs are a PHI sink (parallel to the DB), so they must not be world-readable - this
      mirrors the runtime DB lockdown (_secure_file / STORE-2). Review finding H-13. Best-effort: a
      failure warns but never aborts the install. Well-known SIDs so it works on non-English Windows.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$Account)
    # *S-1-5-18 = NT AUTHORITY\SYSTEM, *S-1-5-32-544 = BUILTIN\Administrators. (OI)(CI)F is inherited
    # by the files/dirs beneath $Path (the logs, db, and bin).
    $grants = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
    if ($Account) { $grants += "${Account}:(OI)(CI)M" }  # service account: read/write its data + logs
    & icacls $Path /inheritance:r /grant:r @grants | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Could not restrict ACLs on '$Path' (icacls exit $LASTEXITCODE); ensure it is " +
            "not world-readable - the captured logs can contain operational/PHI detail (docs/PHI.md).")
    }
}

function Set-ConfigReadAcl {
    <#
      Grant the least-privilege service account READ+EXECUTE on the config directory so it can load the
      Connection/Router/Handler modules and any DPAPI-protected key file under it (WP-11d, ASVS 13.2.2/
      16.4.2). Additive (no /inheritance:r): the config dir usually lives in the repo, so we don't strip
      the developer's own access - we only add the account's read. Without this grant a non-LocalSystem
      account often can't read -Config and the service fails to start. Best-effort: warns, never aborts.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Account)
    & icacls $Path /grant:r "${Account}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Could not grant '$Account' read on the config dir '$Path' (icacls exit " +
            "$LASTEXITCODE); grant it manually so the service can load config (docs/SERVICE.md).")
    }
}

# --- preflight ---------------------------------------------------------------

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Installing a Windows service requires an elevated (Administrator) PowerShell."
}

$NssmPath = Resolve-Nssm -Provided $NssmPath -DataDir $DataDir

# Repo root is two levels up from this script (scripts\service\).
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if (-not $AppExe) { $AppExe = Join-Path $RepoRoot ".venv\Scripts\messagefoundry.exe" }
if (-not $Config) { $Config = Join-Path $RepoRoot "samples\config" }
if (-not $DbPath) { $DbPath = Join-Path $DataDir "messagefoundry.db" }

if (-not (Test-Path $AppExe)) {
    throw "Engine executable not found at: $AppExe`nRun 'pip install -e .' in the project venv, or pass -AppExe."
}
if (-not (Test-Path $Config)) { throw "Config directory not found at: $Config" }

# Absolute paths only: a service's relative paths resolve to the system directory.
$Config   = (Resolve-Path $Config).Path
$LogDir   = Join-Path $DataDir "logs"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir  | Out-Null
# Harden the PHI sink (review H-13): NSSM writes the engine's stdout/stderr under $LogDir, so lock
# the data dir (logs inherit) down to SYSTEM/Administrators/(service account) - not world-readable.
Set-SecureDataDirAcl -Path $DataDir -Account $ServiceAccount
# Least-privilege (WP-11d): when running under a dedicated account, grant it read on the config dir so
# it can actually load the config modules / DPAPI key file (LocalSystem already has access).
if ($ServiceAccount) { Set-ConfigReadAcl -Path $Config -Account $ServiceAccount }

$StdoutLog = Join-Path $LogDir "service.out.log"
$StderrLog = Join-Path $LogDir "service.err.log"
$AppParams = "serve --config `"$Config`" --db `"$DbPath`" --host $ListenHost --port $Port --log-level $LogLevel"

# --- install -----------------------------------------------------------------

function Invoke-Nssm {
    param([Parameter(ValueFromRemainingArguments = $true)]$NssmArgs)
    & $NssmPath @NssmArgs
    if ($LASTEXITCODE -ne 0) { throw "nssm $($NssmArgs -join ' ') failed (exit $LASTEXITCODE)" }
}

# If the service already exists, reconfigure it in place (idempotent install).
# Detect via Get-Service rather than `nssm status` (which errors to stderr on a missing
# service and would abort under ErrorActionPreference=Stop).
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service '$ServiceName' exists - stopping and reconfiguring..."
    try { & $NssmPath stop $ServiceName 2>&1 | Out-Null } catch { }  # best-effort
} else {
    Write-Host "Installing service '$ServiceName'..."
    Invoke-Nssm install $ServiceName $AppExe
}

Invoke-Nssm set $ServiceName Application $AppExe
Invoke-Nssm set $ServiceName AppParameters $AppParams
Invoke-Nssm set $ServiceName AppDirectory $RepoRoot
Invoke-Nssm set $ServiceName DisplayName "MessageFoundry Engine"
Invoke-Nssm set $ServiceName Description "MessageFoundry HL7 v2 integration engine."
Invoke-Nssm set $ServiceName Start SERVICE_AUTO_START

# Logging: NSSM captures stdout/stderr to rotating files (we don't add file handlers
# in Python). Rotate when a stream passes ~10 MB.
Invoke-Nssm set $ServiceName AppStdout $StdoutLog
Invoke-Nssm set $ServiceName AppStderr $StderrLog
Invoke-Nssm set $ServiceName AppRotateFiles 1
Invoke-Nssm set $ServiceName AppRotateOnline 1
Invoke-Nssm set $ServiceName AppRotateBytes 10485760

# Graceful shutdown: send Ctrl+C and give uvicorn up to 15s to drain connections before
# NSSM escalates. Restart on unexpected exit, throttled to avoid crash-loops.
Invoke-Nssm set $ServiceName AppStopMethodConsole 15000
Invoke-Nssm set $ServiceName AppExit Default Restart
Invoke-Nssm set $ServiceName AppThrottle 5000

# Service logon account (DEPLOY-1). Prefer a least-privilege account: the engine only needs to
# read -Config and read/write -DataDir, so running as LocalSystem (NSSM's default) grants far more
# than required and widens the blast radius of any compromise (e.g. a malicious config module).
if ($ServiceAccount) {
    if ($ServiceAccountPassword) {
        # Convert the SecureString to plaintext only here - NSSM's ObjectName takes a plain password.
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            Invoke-Nssm set $ServiceName ObjectName $ServiceAccount $plain
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    } else {
        # Virtual / managed accounts (e.g. "NT SERVICE\MessageFoundry", a gMSA) take no password.
        Invoke-Nssm set $ServiceName ObjectName $ServiceAccount
    }
    Write-Host "  Account: $ServiceAccount" -ForegroundColor Green
    Write-Host "  ACLs   : granted read on '$Config'; read/write on '$DataDir' (docs/SERVICE.md)."
} else {
    Write-Warning ("Service will run as LocalSystem (most-privileged). For least privilege, re-run " +
        "with -ServiceAccount 'NT SERVICE\$ServiceName' (a virtual account, no password; this script " +
        "auto-grants it the config + data-dir ACLs) or a gMSA; see docs/SERVICE.md.")
}

Write-Host ""
Write-Host "Installed '$ServiceName'." -ForegroundColor Green
Write-Host "  Engine : $AppExe $AppParams"
Write-Host "  Logs   : $StdoutLog"
Write-Host "           $StderrLog"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  $NssmPath start $ServiceName"
Write-Host "  curl http://${ListenHost}:${Port}/health"
Write-Host "  Stop:      $NssmPath stop $ServiceName"
Write-Host "  Uninstall: .\uninstall-service.ps1"
