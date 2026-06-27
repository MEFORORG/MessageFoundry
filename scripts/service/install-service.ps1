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
    .\install-service.ps1 -Environment prod
    .\install-service.ps1 -Environment prod -Port 9000 -LogLevel INFO -DataDir D:\MEFOR
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
    # Opt-in: strip inherited ACEs from the config dir and lock it to SYSTEM + Administrators + the
    # service account (RX). The in-process source-trust guard (SEC-003) refuses to load config from a
    # dir/module a low-privileged principal can write, so this one flag satisfies that requirement.
    # Default OFF because the config dir often lives inside a developer's repo, where stripping
    # inheritance is surprising; for production point -Config at a dedicated admin-owned dir and pass
    # this switch (see docs/SERVICE.md "Restrict the config directory").
    [switch]$LockConfigDir,
    [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
    [string]$LogLevel = "INFO",
    # Active environment NAME (ADR 0017): selects environments/<name>.toml + the instance's PHI
    # posture. REQUIRED -- `serve` refuses to start without it (no silent default), so this script
    # validates it up front rather than installing a service that immediately exits. Built-in names
    # dev/staging/prod carry a default posture; a custom name also needs [ai].data_class +
    # [ai].production set in the service config. (Named -Environment, not -Env, to avoid colliding
    # with PowerShell's $env: automatic variable used below.)
    [string]$Environment
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

function Set-SecureConfigAcl {
    <#
      Lock the config directory down to SYSTEM + Administrators (+ the service account, RX), STRIPPING
      inherited ACEs (/inheritance:r). The in-process source-trust guard (SEC-003) refuses to load any
      config dir/module a broad/low-privilege principal can write, so this brings the on-disk ACL into
      line with what the runtime enforces - inherited write/modify ACEs (e.g. from a parent profile or
      ProgramData) are removed. Opt-in via -LockConfigDir because the config dir often lives in a repo
      where stripping inheritance is surprising. Mirrors Set-SecureDataDirAcl: well-known SIDs (non-
      English Windows), best-effort (warn, never abort).
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$Account)
    # *S-1-5-18 = SYSTEM, *S-1-5-32-544 = Administrators. Full control, inherited (OI)(CI) by children.
    $grants = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
    # Service account: read+execute only (it loads, never writes, config) - matches the runtime guard,
    # which treats a non-owner/non-admin WRITE grant as a refusal but allows read/execute.
    if ($Account) { $grants += "${Account}:(OI)(CI)RX" }
    & icacls $Path /inheritance:r /grant:r @grants | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Could not lock down the config dir '$Path' (icacls exit $LASTEXITCODE); a " +
            "low-privileged principal with write would cause the engine to REFUSE to load it (SEC-003, " +
            "docs/SERVICE.md). Lock it manually or re-run elevated.")
    }
}

# --- preflight ---------------------------------------------------------------

# Active environment is REQUIRED (ADR 0017): `serve` won't start without it, so refuse early with a
# clear message rather than registering a service that immediately exits. The name becomes a filename
# segment (environments/<name>.toml) and a CLI argument, so keep it a simple token.
if (-not $Environment) {
    throw ("specify the active environment with -Environment <name> (e.g. -Environment prod). It " +
        "selects environments/<name>.toml and the instance's PHI posture (ADR 0017).")
}
if ($Environment -notmatch '^[A-Za-z0-9._-]+$') {
    throw ("invalid -Environment '$Environment': use letters, digits, '.', '_' or '-' (it selects " +
        "environments/<name>.toml).")
}

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
# Config-source trust (SEC-003): -LockConfigDir strips inherited ACEs and locks the dir to SYSTEM/
# Administrators (+ the account, RX), satisfying the in-process guard that refuses a config dir/module
# any low-privilege principal can write. Without the switch we stay additive and WARN that the guard
# will refuse to load if an inherited write ACE survives.
if ($LockConfigDir) {
    Set-SecureConfigAcl -Path $Config -Account $ServiceAccount
    $cfgGrantees = if ($ServiceAccount) { "SYSTEM/Administrators (F) + $ServiceAccount (RX)" }
                   else { "SYSTEM/Administrators (F)" }
    Write-Host "  Config : locked to $cfgGrantees; inheritance disabled (SEC-003)."
} else {
    if ($ServiceAccount) { Set-ConfigReadAcl -Path $Config -Account $ServiceAccount }
    Write-Warning ("The config dir '$Config' still inherits its parent's ACL. The engine's in-process " +
        "source-trust guard (SEC-003) will REFUSE to load if a low-privileged principal (Everyone, " +
        "Authenticated Users, Users, or any non-admin) has write/modify on the dir or any *.py in it. " +
        "Re-run with -LockConfigDir, or point -Config at a dedicated admin-owned dir; see docs/SERVICE.md " +
        "'Restrict the config directory'.")
}

$StdoutLog = Join-Path $LogDir "service.out.log"
$StderrLog = Join-Path $LogDir "service.err.log"
$AppParams = "serve --config `"$Config`" --db `"$DbPath`" --host $ListenHost --port $Port --log-level $LogLevel --env $Environment"

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
