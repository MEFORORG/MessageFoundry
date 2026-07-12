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
    # Least-privilege service account (DEPLOY-1). Override the default run-as with a specific account -
    # a dedicated low-privilege user, a gMSA, or a different virtual account, e.g.
    # -ServiceAccount "NT SERVICE\MessageFoundry" (no password). It needs only read on -Config and
    # read/write on -DataDir. When omitted, the service now DEFAULTS to the per-service virtual account
    # NT SERVICE\<ServiceName> (least-privilege, no password) unless -AllowLocalSystem is passed. See
    # docs/SERVICE.md.
    [string]$ServiceAccount,
    [SecureString]$ServiceAccountPassword,
    # Least-privilege posture (#224, built on #99): the service now DEFAULTS to a least-privilege virtual
    # account (NT SERVICE\<ServiceName>) instead of LocalSystem. Pass -AllowLocalSystem to opt OUT and run
    # as LocalSystem (the most-privileged local account) intentionally - it is required to get LocalSystem
    # now that the default is flipped. An explicit -ServiceAccount always wins over both. See docs/SERVICE.md
    # "Least-privilege service account".
    [switch]$AllowLocalSystem,
    # gMSA preflight (#99): when -ServiceAccount names a group Managed Service Account (a name ending in
    # '$', e.g. DOMAIN\svc$), the installer runs Test-ADServiceAccount and grants SeServiceLogonRight
    # before registering the service. Pass -SkipGmsaPreflight to skip it (e.g. when the account is
    # pre-provisioned by a separate runbook). On a non-domain / RSAT-less box the preflight degrades
    # gracefully (skips with a message), never hard-fails. See docs/DEPLOY-SERVER-DB.md.
    [switch]$SkipGmsaPreflight,
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

function Test-LooksLikeGmsa {
    <#
      A group Managed Service Account (gMSA / sMSA) logs on with a name ending in '$' and NO password
      (the domain rotates its secret). We treat a -ServiceAccount ending in '$' as a (g)MSA candidate for
      the AD preflight, EXCEPT the built-in NT AUTHORITY / NT SERVICE virtual accounts (which also take
      no password but are not domain-managed and have no Test-ADServiceAccount story).
    #>
    param([string]$Account)
    if (-not $Account) { return $false }
    if ($Account -notmatch '\$\s*$') { return $false }
    if ($Account -match '^(NT AUTHORITY|NT SERVICE)\\') { return $false }
    return $true
}

function Test-GmsaInstalled {
    <#
      OPTIONAL gMSA preflight (#99): verify the gMSA is installed + usable on THIS host via
      Test-ADServiceAccount (RSAT ActiveDirectory module). DEGRADES GRACEFULLY: on a non-domain / RSAT-
      less box the cmdlet is absent, so we skip with a clear message rather than hard-failing (dev boxes,
      CI). A reachable-but-not-installed gMSA warns and points at Install-ADServiceAccount. Best-effort:
      it never aborts the install (the service registration below is the source of truth).
    #>
    param([Parameter(Mandatory)][string]$Account)
    $cmd = Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host ("  gMSA   : skipping preflight for '$Account' - the RSAT ActiveDirectory module " +
            "(Test-ADServiceAccount) is not available on this host (non-domain / dev box). Ensure the " +
            "gMSA is installed on the target server with Install-ADServiceAccount before starting.")
        return
    }
    # Test-ADServiceAccount takes the SAM account name WITHOUT the domain prefix or trailing '$'.
    $sam = ($Account -replace '^.*\\', '') -replace '\$\s*$', ''
    try {
        if (Test-ADServiceAccount -Identity $sam) {
            Write-Host "  gMSA   : Test-ADServiceAccount '$sam' -> OK (installed + usable on this host)." -ForegroundColor Green
        } else {
            Write-Warning ("gMSA '$sam' is NOT usable on this host (Test-ADServiceAccount returned " +
                "false). Install it first:  Install-ADServiceAccount -Identity $sam  (the host's " +
                "computer account must be a member of the gMSA's PrincipalsAllowedToRetrieveManagedPassword " +
                "group). See docs/DEPLOY-SERVER-DB.md.")
        }
    } catch {
        Write-Warning ("gMSA preflight for '$sam' could not run ($($_.Exception.Message)); verify with " +
            "Test-ADServiceAccount / Install-ADServiceAccount manually. Continuing.")
    }
}

function Set-ServiceLogonRight {
    <#
      Grant the SeServiceLogonRight ("Log on as a service") user right to $Account via the LOCAL security
      policy (#99). NSSM's ObjectName assigns the account but does NOT grant this right the way the SCM UI
      does, so a gMSA / dedicated account otherwise fails to start with error 1069. Implemented with the
      built-in secedit (no extra module): export USER_RIGHTS, append the account SID to
      SeServiceLogonRight if missing, re-import. Best-effort: resolves the SID, warns and returns on any
      failure, never aborts the install (an operator can grant it via secpol.msc / Group Policy instead).
    #>
    param([Parameter(Mandatory)][string]$Account)
    try {
        $sid = ([Security.Principal.NTAccount]$Account).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Warning ("Could not resolve '$Account' to a SID to grant 'Log on as a service' " +
            "($($_.Exception.Message)); grant SeServiceLogonRight manually (secpol.msc -> Local " +
            "Policies -> User Rights Assignment) or the service will fail to start with error 1069.")
        return
    }
    $inf = Join-Path $env:TEMP "mefor-secedit-$PID.inf"
    $sdb = Join-Path $env:TEMP "mefor-secedit-$PID.sdb"
    try {
        & secedit /export /areas USER_RIGHTS /cfg $inf | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $inf)) {
            Write-Warning "secedit export failed (exit $LASTEXITCODE); grant 'Log on as a service' to '$Account' manually."
            return
        }
        $lines = Get-Content $inf
        $row = $lines | Where-Object { $_ -match '^\s*SeServiceLogonRight\s*=' }
        if ($row) {
            # Compare against exact SID tokens, not a raw substring: a SID that is a string prefix of an
            # already-granted SID (RID 110 vs 1100) would false-positive under -match and skip the grant,
            # so the service could fail to start (error 1069). Split the value on ',' and match each
            # trimmed entry exactly (secedit writes SIDs in the leading-'*' form).
            $value = ($row -replace '^\s*SeServiceLogonRight\s*=', '')
            $held = $value -split ',' | ForEach-Object { $_.Trim() } | Where-Object {
                $_ -eq ("*" + $sid) -or $_ -eq $sid
            }
            if ($held) {
                Write-Host "  Right  : '$Account' already holds SeServiceLogonRight (Log on as a service)."
                return
            }
        }
        if ($row) {
            $new = $lines -replace '^\s*SeServiceLogonRight\s*=(.*)$', "SeServiceLogonRight =`$1,*$sid"
        } else {
            # No existing row: inject one under [Privilege Rights].
            $new = $lines -replace '(\[Privilege Rights\])', "`$1`r`nSeServiceLogonRight = *$sid"
        }
        Set-Content -Path $inf -Value $new -Encoding Unicode
        & secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "secedit configure failed (exit $LASTEXITCODE); grant 'Log on as a service' to '$Account' manually."
            return
        }
        Write-Host "  Right  : granted SeServiceLogonRight (Log on as a service) to '$Account'." -ForegroundColor Green
    } finally {
        Remove-Item $inf, $sdb -Force -ErrorAction SilentlyContinue
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
# NB the data-dir + config-dir ACL lockdown is applied LATER, AFTER the service is registered and its
# ObjectName (run-as account) is set - see "ACLs" below. The default run-as is now a per-service VIRTUAL
# account (NT SERVICE\<ServiceName>, #224), whose SID does NOT resolve for icacls until the service
# exists, so the grants cannot run here in preflight (S4 ordering). The dirs are created now so NSSM has
# somewhere to write logs; they are locked down before the operator starts the service.

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

# Service logon account (DEPLOY-1, #224). The engine only needs to read -Config and read/write
# -DataDir, so LocalSystem grants far more than required and widens the blast radius of any compromise
# (e.g. a malicious config module). DEFAULT to a least-privilege per-service VIRTUAL account
# (NT SERVICE\<ServiceName>, no password) rather than LocalSystem; pass -AllowLocalSystem to run as
# LocalSystem intentionally. An explicit -ServiceAccount (a gMSA / dedicated user / a different virtual
# account) always wins over the default.
if (-not $ServiceAccount -and -not $AllowLocalSystem) {
    $ServiceAccount = "NT SERVICE\$ServiceName"
    Write-Host ("  Account: defaulting to the least-privilege virtual account '$ServiceAccount' (no " +
        "password). Pass -AllowLocalSystem to run as LocalSystem, or -ServiceAccount for a gMSA / " +
        "dedicated account instead (docs/SERVICE.md 'Least-privilege service account').")
}
if ($ServiceAccount) {
    # gMSA preflight (#99): verify the account is installed + usable on this host, then grant it the
    # "Log on as a service" right BEFORE registering (NSSM's ObjectName does not grant it). Both steps
    # degrade gracefully on a non-domain box and never abort the install.
    if ((Test-LooksLikeGmsa -Account $ServiceAccount) -and -not $SkipGmsaPreflight) {
        Test-GmsaInstalled -Account $ServiceAccount
    }
    if (-not $ServiceAccountPassword) {
        # A password-less account (gMSA / virtual / managed) still needs SeServiceLogonRight granted (a
        # password account is granted it implicitly by the SCM when NSSM sets the password). Best-effort.
        Set-ServiceLogonRight -Account $ServiceAccount
    }
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
        # Virtual / managed accounts (e.g. "NT SERVICE\MessageFoundry", a gMSA) take no password. NSSM
        # wants a gMSA's ObjectName with a trailing '$' and no password.
        Invoke-Nssm set $ServiceName ObjectName $ServiceAccount
    }
    Write-Host "  Account: $ServiceAccount" -ForegroundColor Green
} else {
    # $ServiceAccount is empty only when -AllowLocalSystem was passed (the default above otherwise fills
    # it with the virtual account), so this branch is now the explicit LocalSystem opt-out (#224). Leave
    # ObjectName unset -> NSSM runs the service as LocalSystem (most-privileged); warn that it is the
    # acknowledged, non-default choice.
    Write-Warning ("Service will run as LocalSystem (most-privileged) - acknowledged via " +
        "-AllowLocalSystem. The default is now the least-privilege virtual account " +
        "'NT SERVICE\$ServiceName' (no password); prefer it or a gMSA for production. See docs/SERVICE.md " +
        "'Least-privilege service account'.")
}

# --- ACLs: applied AFTER the service exists + ObjectName is set (S4 ordering, #224) ------------------
# A per-service virtual-account SID (NT SERVICE\<ServiceName>) does not resolve for icacls until the
# service has been created and its ObjectName assigned, so the data-dir + config-dir grants run HERE,
# not in preflight. This also keeps the DPAPI machine-key path startable: the run-as account must retain
# read on the data dir (+ key file) it needs at startup (#44 / WIN2025 S2.2) - a grant that can only name
# the account once its SID resolves. For a LocalSystem opt-out ($ServiceAccount empty) the grants lock
# the dirs to SYSTEM/Administrators only, which LocalSystem (= SYSTEM) can read/write.
#
# Harden the PHI sink (review H-13): NSSM writes the engine's stdout/stderr under $LogDir, so lock the
# data dir (logs inherit) down to SYSTEM/Administrators/(service account) - not world-readable.
Set-SecureDataDirAcl -Path $DataDir -Account $ServiceAccount
# Least-privilege (WP-11d): grant the run-as account read on the config dir so it can load the config
# modules / DPAPI key file (LocalSystem already has access). Config-source trust (SEC-003):
# -LockConfigDir strips inherited ACEs and locks the dir to SYSTEM/Administrators (+ the account, RX),
# satisfying the in-process guard that refuses a config dir/module any low-privilege principal can write.
# Without the switch we stay additive and WARN that the guard will refuse to load if an inherited write
# ACE survives.
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
if ($ServiceAccount) {
    Write-Host "  ACLs   : granted read on '$Config'; read/write on '$DataDir' (docs/SERVICE.md)."
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
