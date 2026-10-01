# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
    # Where the nssm.exe the service runs is kept (BACKLOG #2364). It must be a folder only
    # administrators can write, and the script refuses one that is not: this script runs that file as
    # administrator, and the SCM starts it as the service account. Not under -DataDir, where the
    # engine's own account has modify rights.
    [string]$NssmDir = "$env:ProgramFiles\MessageFoundry\nssm",
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
    # Opt-in: suppress Windows Error Reporting crash dumps for the engine image MACHINE-WIDE (ADR 0152
    # Phase 0). A WER dump of a running engine writes in-flight HL7 bodies, decrypted plaintext and the
    # unwrapped DEK to a file outside the store's encryption, ACLs and retention sweep. The engine
    # already applies the process-local half of this at every `serve` (SetErrorMode + WerSetFlags, see
    # messagefoundry/crashdump.py), but HKLM LocalDumps and the WER exclusion list are MACHINE POLICY -
    # Microsoft documents local dump collection as controlled independently of the rest of WER, so it
    # fires even for a process that set every flag it can. Only this switch closes that half. Default
    # OFF because it writes HKLM keys by IMAGE NAME (which affects every process of that name on the
    # box, not just this service) - an explicit operator decision, not a side effect of installing.
    [switch]$SuppressCrashDumps,
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
# $NssmSha256 is the hash of the ARCHIVE, so it can check a download and nothing else. The hash of the
# nssm.exe inside it is $NssmExeSha256, in the pinned-hash block below, and that is the one every
# copy is checked against before it runs.
$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$NssmSha256 = "727D1E42275C605E0F04ABA98095C38A8E1E46DEF453CDFFCE42869428AA6743"
# Tried in order when $NssmUrl fails, so an nssm.cc outage does not stop an install (BACKLOG #2504).
# A mirror is as safe as the primary only because every download is checked against $NssmSha256
# before it is opened. Add only a copy whose bytes you have hashed against that pin.
#
# The Internet Archive's raw capture (the id_ suffix) of $NssmUrl. Measured 2026-10-01: the archive
# hashes to $NssmSha256 and its win64 nssm.exe to $NssmExeSha256. The Archive recorded one payload
# digest for this URL in every capture from 2015 to 2025.
$NssmMirrorUrls = @(
    "https://web.archive.org/web/20250427013751id_/https://nssm.cc/release/nssm-2.24.zip"
)

# BEGIN pinned-hash check (kept byte-identical in install-service.ps1 and install-net-helper.ps1;
# guarded by tests/test_nssm_pin.py, which fails if the two copies drift)
#
# The SHA-256 of nssm.exe itself: the win64 binary in the NSSM 2.24 archive that install-service.ps1
# pins as $NssmSha256. Both installers check every nssm.exe they copy or run against this value,
# whichever source it came from - -NssmPath, PATH, an installed copy, or a download (BACKLOG #2364).
# Only the download used to be checked. The two uninstallers do not run nssm at all. The block also
# carries the folder check and the registration read-back, which both installers need.
$NssmExeSha256 = "F689EE9AF94B00E9E3F0BB072B34CAAF207F32DCB4F5782FC9CA351DF9A06C97"

function Get-FilePinProblem {
    <#
      Why the file at $Path does not match the pinned SHA-256 $Expected, or "" when it does.

      RETURNED, NOT THROWN, so each caller decides what a mismatch means: refuse to go on, or skip to
      another source. The message names both hashes, so an operator can compare them against the
      channel the pin came from. A file that cannot be hashed is a mismatch, never a pass.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Expected)
    try {
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
    } catch {
        return ("'$Path' could not be hashed ($($_.Exception.Message)), so nothing checked it " +
            "against the pinned SHA-256 $Expected")
    }
    if ($actual -ne $Expected) { return "'$Path' has SHA-256 $actual, not the pinned $Expected" }
    return ""
}


function Get-BroadWriteHolders {
    <#
      Principals who can write $Path, or can make themselves able to, beyond the five that always
      may. Two arms: the OWNER, and Allow-write entries on the DACL.

      Returns an empty array when the directory is administrator-only, which is what makes "the
      folder is safe" a reading rather than an assumption.

      NOT install-service.ps1's Get-BroadAclResidue, and deliberately not a copy of it. That one
      allows the engine's service account, because the engine has to write its data directory; it
      takes any Allow entry rather than write-class ones, and it has no owner arm. Here nothing
      outside the five may write at all - whoever can write this folder can replace a binary that
      an administrator runs, or that later runs as SYSTEM. Same shape, different question; naming them apart keeps a reader from
      assuming one answers the other's.
    #>
    param([Parameter(Mandatory)][string]$Path)
    # The same four principals messagefoundry/config/wiring.py's _WIN_TRUSTED_SIDS trusts for the
    # same reason, plus OWNER RIGHTS: that module's comment records that S-1-3-0 and S-1-3-4 both
    # appear on ordinary inherited ACLs and must not be refused. Omitting S-1-3-4 would be a false
    # REFUSAL, and in install-net-helper.ps1 its only escape is -AllowBroadAcl, which downgrades the
    # whole check to a warning -- so one false positive would disable the gate.
    $allowed = @(
        "S-1-5-18",                                                                # SYSTEM
        "S-1-5-32-544",                                                            # Administrators
        "S-1-3-0",                                                                 # CREATOR OWNER
        "S-1-3-4",                                                                 # OWNER RIGHTS
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"           # TrustedInstaller
    )
    $rights = [Security.AccessControl.FileSystemRights]
    # THE TWO GENERIC BITS ARE IN THE MASK ON PURPOSE, and leaving them out is why a first version of
    # this was quietly weaker than it looked. FileSystemRights names no GENERIC_ALL or GENERIC_WRITE,
    # and a real Program Files ACL is full of them: measured on Windows 11 26200, five of its
    # fourteen entries render as the bare numbers 268435456 (GENERIC_ALL) and -1610612736
    # (GENERIC_READ|GENERIC_EXECUTE). Those are the inherit-only templates that decide what a file
    # CREATED in the folder gets - which is exactly the binary this install is about to write - and
    # none of the named bits below intersects them. So a GENERIC_ALL for Users would have passed a
    # mask built only from the named rights.
    $genericAll = 0x10000000
    $genericWrite = 0x40000000
    $writeMask = [int]($rights::WriteData -bor $rights::AppendData -bor $rights::WriteAttributes -bor
        $rights::WriteExtendedAttributes -bor $rights::Delete -bor $rights::DeleteSubdirectoriesAndFiles -bor
        $rights::ChangePermissions -bor $rights::TakeOwnership) -bor $genericAll -bor $genericWrite
    $found = @()
    # RETURNED AS A RESIDUE, NOT THROWN. An unreadable DACL is not "the folder is fine", so it has to
    # reach the caller - but throwing from here made install-net-helper.ps1's refusal message name
    # -AllowBroadAcl as the escape when that switch is not consulted until AFTER this call. An operator following
    # that instruction got the identical refusal: a dead end, and exactly the false-premise defect
    # the rest of this script is written against. Returned as a finding instead, so the one decision
    # about -AllowBroadAcl covers all three ways this can come back non-empty.
    #
    # -LiteralPath, NOT -Path. Measured: for a directory whose name holds '[' or ']', `Get-Acl -Path`
    # returns $null WITHOUT raising, even under -ErrorAction Stop - so the catch never fires and the
    # arms below read a null object.
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch {
        return @("the permissions of '$Path' could not be read ($($_.Exception.Message)), so " +
            "nothing established who can write there")
    }
    if ($null -eq $acl) {
        return @("the permissions of '$Path' could not be read (Get-Acl returned nothing), so " +
            "nothing established who can write there")
    }

    # THE OWNER ARM, and the DACL alone is not the question. An owner holds WRITE_DAC implicitly, so
    # a low-privilege owner can rewrite the DACL whatever it says today and then replace a binary
    # this install is about to have the SCM start as SYSTEM. messagefoundry/config/wiring.py's
    # _evaluate_config_dacl carries the same arm for the same reason (SEC-003, CWE-732); a check
    # without it reports a clean folder for exactly that case.
    #
    # AND IT TAKES THE WELL-KNOWN ADMIN RIDs TOO, which the literal list cannot cover: that module's
    # _WIN_ADMIN_RIDS records that the built-in Administrator (500), Domain Admins (512), Schema
    # Admins (518) and Enterprise Admins (519) vary per domain. Without them a folder an admin ran
    # `takeown` on, or one restored from a backup, is refused for being owned by an administrator.
    $ownerSid = $null
    try {
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    } catch { $ownerSid = "$($acl.Owner)" }
    # COMPARED AS TEXT, NOT CAST. A RID is a 32-bit UNSIGNED value and [int] is signed, so casting
    # overflows on a real SID: measured, TrustedInstaller's last group is 2271478464 and
    # `[int]"2271478464"` throws "Value was either too large or too small for an Int32" -- which
    # under $ErrorActionPreference = "Stop" aborted this whole check on an ordinary Program Files
    # folder. A string compare answers the only question being asked and cannot overflow.
    $ownerRid = if ($ownerSid -match '-(\d+)$') { $Matches[1] } else { "" }
    if (($allowed -notcontains $ownerSid) -and ($ownerRid -notin @("500", "512", "518", "519"))) {
        $found += "$($acl.Owner) (owner, so implicitly WRITE_DAC)"
    }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (([int]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
        $name = "$($rule.IdentityReference)"
        # $allowed holds SIDs only, so an untranslatable identity falls back to its own text and is
        # REPORTED rather than skipped: a SID nobody can translate is still a grant, and dropping it
        # would turn a residue into a clean result.
        $sid = $name
        try {
            $sid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { }
        if ($allowed -notcontains $sid) { $found += "$name ($($rule.FileSystemRights))" }
    }
    return ($found | Select-Object -Unique)
}
function Get-ServiceImageProblem {
    <#
      Why the service's registration does not start "$Path", quoted, or "" when it does.

      QUOTED OR NOTHING. An unquoted path with a space in it is CWE-428: the SCM tries each prefix
      that ends at a space, so C:\Program Files\... is first tried as C:\Program.exe. NSSM 2.24
      registers its own path unquoted, so Set-ServiceImage quotes it, and this accepts only that.
      Arguments after the quoted path are allowed. Read from the service's registry key with
      -LiteralPath, so the service name is never parsed as a wildcard or a query.
    #>
    param([Parameter(Mandatory)][string]$ServiceName, [Parameter(Mandatory)][string]$Path)
    $line = ""
    try {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $line = "$((Get-ItemProperty -LiteralPath $key -Name ImagePath -ErrorAction Stop).ImagePath)".Trim()
    } catch { }
    $quoted = "`"$Path`""
    if (($line -eq $quoted) -or $line.StartsWith("$quoted ", [StringComparison]::OrdinalIgnoreCase)) {
        return ""
    }
    return "'$ServiceName' is registered to start '$line', not the checked copy $quoted"
}

function Set-ServiceImage {
    <#
      Point the service's registration at "$Path", quoted, and read it back. Throws when it cannot.

      This is what makes the checked copy the one the SCM starts. `nssm set` never changes the
      image path, `nssm install` writes it unquoted, and a registration from an earlier install can
      name any nssm.exe at all. Win32_Service.Change calls ChangeServiceConfig, which the SCM
      applies at once; editing ImagePath in the registry would wait for a reboot. It is not passed
      through sc.exe because Windows PowerShell 5.1 does not escape the quotes inside a native
      argument.
    #>
    param([Parameter(Mandatory)][string]$ServiceName, [Parameter(Mandatory)][string]$Path)
    if (-not (Get-ServiceImageProblem -ServiceName $ServiceName -Path $Path)) { return }
    $svc = Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
    if (-not $svc) { throw "'$ServiceName' is not registered, so its image path cannot be set." }
    $result = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ PathName = "`"$Path`"" }
    if ($result.ReturnValue -ne 0) {
        throw ("Could not point '$ServiceName' at `"$Path`": Win32_Service.Change returned " +
            "$($result.ReturnValue).")
    }
    $problem = Get-ServiceImageProblem -ServiceName $ServiceName -Path $Path
    if ($problem) { throw "$problem, although Win32_Service.Change reported success." }
}
function Set-ServiceAccount {
    <#
      Set the account a service runs as through the SCM, and read it back. Throws when it cannot.

      NOT `nssm set ObjectName`. NSSM 2.24, the build this repository pins, refuses a virtual account.
      Measured on both hosted Windows runners in CI run 36590581708 (2026-09-29): "Invalid account
      name!" and "Setting ObjectName requires both a username and password", exit 6. Win32_Service.
      Change calls ChangeServiceConfig, which takes all three forms the installers use.

      THE PASSWORD ARGUMENT DEPENDS ON THE ACCOUNT. ChangeServiceConfig wants lpPassword NULL for a
      virtual or managed account, so StartPassword is left out of the call for those rather than sent
      as "". LocalSystem and the two NT AUTHORITY service accounts take an empty string. Any other
      account takes the -Password it was given.

      THE PASSWORD NEVER REACHES A MESSAGE (BACKLOG #1573). It arrives as a SecureString and becomes
      plaintext only inside the argument table of the one call, which is emptied in `finally`. Every
      message here is built from the account name and a return code. When a password was passed, a
      failed call's own exception text is left out too, because nothing guarantees it does not echo
      its arguments.

      THE NAME IS CANONICALISED FIRST, as `nssm set ObjectName` did: a bare user name or a UPN is
      translated to its SID and back, to the DOMAIN\user form ChangeServiceConfig wants and stores.
      A name that does not translate yet, such as a virtual account before its service exists, is
      sent as given.

      A FAILURE DISABLES THE SERVICE before the throw. The script stops there, before the data
      directory is locked down, and a fresh registration would otherwise start at the next boot as
      NSSM's default, LocalSystem.
    #>
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$Account,
        [SecureString]$Password
    )
    $fail = {
        param([string]$Why)
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        throw "$Why '$ServiceName' was set to Disabled so it cannot start as the wrong account."
    }
    $svc = Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
    if (-not $svc) { throw "'$ServiceName' is not registered, so its run-as account cannot be set." }
    $builtin = $Account -match '^(\.\\)?LocalSystem$|^NT AUTHORITY\\(LocalService|NetworkService|SYSTEM)$'
    if (-not $builtin) {
        try {
            $Account = ([Security.Principal.NTAccount]$Account).Translate(
                [Security.Principal.SecurityIdentifier]).Translate([Security.Principal.NTAccount]).Value
        } catch { }
    }
    $arguments = @{ StartName = $Account }
    if ($builtin) { $arguments['StartPassword'] = "" }
    $bstr = [IntPtr]::Zero
    $result = $null
    $failure = $null
    try {
        if ($Password) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $arguments['StartPassword'] = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        $result = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments $arguments -ErrorAction Stop
    } catch {
        $failure = if ($Password) { "the call failed" } else { $_.Exception.Message }
    } finally {
        $arguments.Remove('StartPassword')
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    if ($failure) {
        & $fail "Could not set '$ServiceName' to run as '$Account' (Win32_Service.Change: $failure)."
    }
    if ($result.ReturnValue -ne 0) {
        & $fail ("Could not set '$ServiceName' to run as '$Account': Win32_Service.Change returned " +
            "$($result.ReturnValue).")
    }
    # Read back from the service's own key. The SCM keeps a ".\" prefix when it was given one, so the
    # two sides are compared without it.
    $stored = ""
    try {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $stored = "$((Get-ItemProperty -LiteralPath $key -Name ObjectName -ErrorAction Stop).ObjectName)"
    } catch { }
    if (($stored -replace '^\.\\', '') -ne ($Account -replace '^\.\\', '')) {
        & $fail ("'$ServiceName' runs as '$stored', not '$Account', although Win32_Service.Change " +
            "reported success.")
    }
}
# END pinned-hash check

function Set-AdminOnlyAcl {
    <#
      Make a folder or file this script created administrator-only: inheritance off, SYSTEM and
      Administrators full control, Users and Authenticated Users read and execute, and Administrators
      as the owner.

      A NEW FOLDER IS NOT ADMINISTRATOR-ONLY BY DEFAULT on every host. Under the "Object creator"
      default-owner policy its owner is the individual operator, and Program Files' inheritable
      CREATOR OWNER entry gives that operator full control of it. Measured by the 2026-09-29 review
      of this change: a child of a folder carrying CREATOR OWNER:(OI)(CI)(IO)F gets
      '<creator>:(I)(F)'. Either one is a write path Get-BroadWriteHolders refuses. So the ACL is set
      rather than inherited. Best-effort: the check that follows reads the result either way.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $grants = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX",
        "*S-1-5-11:(OI)(CI)RX")
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $grants = @("*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-5-32-545:RX", "*S-1-5-11:RX")
    }
    & icacls $Path /inheritance:r /grant:r @grants | Out-Null
    & icacls $Path /setowner "*S-1-5-32-544" | Out-Null
}

function Get-NssmHomeProblem {
    <#
      Who, other than administrators, could replace $File: through the file itself, its folder, or
      any folder above that up to, not including, the drive root. "" when nobody.

      THE PARENTS COUNT. Whoever can delete or rename a folder's child can move the checked folder
      aside and put their own in its place. The drive root is left out because Windows lets
      Authenticated Users create folders there by default, which moves nothing that already exists.
    #>
    param([Parameter(Mandatory)][string]$File)
    $found = @()
    if (Test-Path -LiteralPath $File) { $found += @(Get-BroadWriteHolders -Path $File) }
    $dir = Split-Path -Parent $File
    while ($dir -and (Split-Path -Parent $dir)) {
        $found += @(Get-BroadWriteHolders -Path $dir | ForEach-Object { "$_ on '$dir'" })
        $dir = Split-Path -Parent $dir
    }
    return ($found -join "; ")
}

function Resolve-Nssm {
    <#
      The nssm.exe this install runs, and registers the service with: the copy in -NssmDir, a folder
      only administrators can write (BACKLOG #2364).

      WHY A FOLDER OF ITS OWN. The registration names an nssm.exe by path, and this script runs that
      file as administrator. It used to be cached in <DataDir>\bin, where the engine's own account
      has modify rights. From there, code running as the engine could replace the file, plant a DLL
      beside it, or turn the folder into a junction, for the next install to run as administrator. A
      hash check sees only the first of those three. So the copy lives where only administrators can
      write, and Get-NssmHomeProblem reads that from the file, its folder and the folders above,
      rather than assuming it. With nobody else able to write there, nothing can change the copy
      between this check and its use.

      Every source is checked against $NssmExeSha256 before it is copied in:
        installed  the copy already in -NssmDir. Used as it is when it passes, and REFUSED when it
                   does not, because only an administrator can have changed it.
        -NssmPath  refused on a mismatch. The operator named that file.
        PATH       skipped with a warning on a mismatch. A package manager's nssm may be another
                   build, which is ordinary and not an attack.
        download   the archive is checked against $NssmSha256, then its nssm.exe against the pin.

      TWO COPIES THAT PASS THE PIN ARE THE SAME BYTES, so a passing installed copy is never
      overwritten. That also means a reinstall never copies over the image a running service holds
      open.
    #>
    param([string]$Provided, [Parameter(Mandatory)][string]$NssmDir)

    # Every folder this call creates gets an administrator-only ACL. A folder that already existed is
    # left as it is: its permissions are the operator's choice, and the check below reads them.
    $missing = @()
    $probe = $NssmDir
    while ($probe -and -not (Test-Path -LiteralPath $probe)) {
        $missing = @($probe) + $missing
        $probe = Split-Path -Parent $probe
    }
    New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
    foreach ($dir in $missing) { Set-AdminOnlyAcl -Path $dir }
    $target = Join-Path $NssmDir "nssm.exe"
    $refuse = {
        param($holders)
        throw ("'$target' is not administrator-only: $holders. Whoever can write there can replace " +
            "the nssm.exe this script runs as administrator, or plant a DLL beside it. Pass " +
            "-NssmDir with a folder under Program Files, or fix its permissions, and re-run.")
    }
    $holders = Get-NssmHomeProblem -File $target
    if ($holders) { & $refuse $holders }

    $source = $null
    if ($Provided) {
        if (-not (Test-Path -LiteralPath $Provided)) { throw "NSSM not found at: $Provided" }
        $source = (Resolve-Path -LiteralPath $Provided).Path
        $problem = Get-FilePinProblem -Path $source -Expected $NssmExeSha256
        if ($problem) {
            throw ("Refusing -NssmPath: $problem. Pass the win64 nssm.exe from the NSSM 2.24 " +
                "release, or leave -NssmPath out and this script downloads and checks it.")
        }
    }
    if (Test-Path -LiteralPath $target) {
        $problem = Get-FilePinProblem -Path $target -Expected $NssmExeSha256
        if ($problem) {
            throw ("Refusing the installed NSSM: $problem. Only an administrator can write " +
                "'$NssmDir', so find out what changed it. Then delete it and re-run.")
        }
        return $target
    }
    if (-not $source) {
        $onPath = Get-Command nssm -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($onPath) {
            $problem = Get-FilePinProblem -Path $onPath.Source -Expected $NssmExeSha256
            if (-not $problem) { $source = $onPath.Source }
            else {
                Write-Warning ("Not using the nssm on PATH: $problem. Downloading the pinned release " +
                    "instead. With no internet access, pass -NssmPath with the win64 nssm.exe from " +
                    "nssm-2.24.zip.")
            }
        }
    }
    if ($source) {
        Copy-Item -LiteralPath $source -Destination $target -Force
    } else {
        Save-PinnedNssm -Destination $target
    }
    # The new file's owner follows the same default-owner policy as a new folder, so it is set too.
    Set-AdminOnlyAcl -Path $target
    # The COPY is what runs, so the copy is what gets checked. With the download, a mismatch here
    # means the two pins disagree: a binary pin that does not match the pinned archive is wrong.
    $problem = Get-FilePinProblem -Path $target -Expected $NssmExeSha256
    $holders = Get-NssmHomeProblem -File $target
    if ($problem -or $holders) {
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
        if ($holders) { & $refuse $holders }
        throw "The nssm.exe copied into '$NssmDir' failed its check: $problem."
    }
    Write-Host "NSSM installed to $target"
    return $target
}

function Save-PinnedNssm {
    <#
      Download the pinned NSSM archive, check it against $NssmSha256, and write its win64 nssm.exe to
      $Destination. The caller checks the written file against $NssmExeSha256.

      $NssmUrl first, then each of $NssmMirrorUrls. The first download that matches $NssmSha256 is
      the one used. A source that fails, or serves other bytes, is skipped with a warning; nothing
      from it is opened. When no source matches, this throws and writes nothing.
    #>
    param([Parameter(Mandatory)][string]$Destination)
    Write-Host "NSSM not found - downloading the pinned release ..."
    # GetTempPath, not $env:TEMP. The variable is unset on Linux pwsh, where the tests lift this
    # function, and Join-Path refuses a null. On Windows GetTempPath reads TMP, then TEMP, then falls
    # back to the profile, so it names the same folder.
    #
    # A NEW FOLDER OF ITS OWN FOR EVERY RUN, created without -Force so an existing one is an error. The
    # fixed names this used before could be pre-created by another user wherever the temp folder is
    # shared - C:\Windows\Temp when this runs as SYSTEM - and a recursive delete of a planted junction
    # there would follow it. The pins still check what comes out; this keeps the cleanup to our own
    # files.
    $temp = [IO.Path]::GetTempPath()
    $work = Join-Path $temp ("nssm-mefor-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $zip = Join-Path $work "nssm-2.24.zip"
        $extract = Join-Path $work "extract"
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $failures = @()
        $verified = $false
        foreach ($url in @(@($NssmUrl) + @($NssmMirrorUrls) | Where-Object { $_ })) {
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            Write-Host "  trying $url"
            try {
                Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
                $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
            } catch {
                $failures += "$url : $($_.Exception.Message)"
                Write-Warning "NSSM download failed from $url : $($_.Exception.Message)"
                continue
            }
            if ($hash -ne $NssmSha256) {
                Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
                $failures += "$url : failed integrity check (got $hash, expected $NssmSha256)"
                Write-Warning ("NSSM download from $url failed integrity check (got $hash, " +
                    "expected $NssmSha256). Not using it.")
                continue
            }
            $verified = $true
            break
        }
        if (-not $verified) {
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            throw ("NSSM download failed from every source, so nothing was installed. With no " +
                "internet access, pass -NssmPath with the win64 nssm.exe from nssm-2.24.zip. " +
                "Sources: " + ($failures -join " | "))
        }
        Expand-Archive -LiteralPath $zip -DestinationPath $extract
        $exe = Get-ChildItem -Path $extract -Recurse -Filter nssm.exe |
            Where-Object { $_.Directory.Name -eq "win64" } | Select-Object -First 1
        if (-not $exe) { throw "win64\nssm.exe not found in the downloaded NSSM archive." }
        Copy-Item -LiteralPath $exe.FullName -Destination $Destination -Force
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function Set-SecureDataDirAcl {
    <#
      Lock the data/log directory down to SYSTEM + Administrators (+ the service account). NSSM
      captures the engine's stdout/stderr under here, and those logs are a PHI sink (parallel to the
      DB), so they must not be world-readable - this mirrors the runtime DB lockdown (_secure_file /
      STORE-2). Review finding H-13. Best-effort: a failure warns but never aborts the install.
      Well-known SIDs so it works on non-English Windows.

      `/inheritance:r /grant:r` IS NOT A LOCKDOWN ON ITS OWN, and that was the shape here until
      BACKLOG #1699 built the first test that read the DACL back. /inheritance:r removes INHERITED
      ACEs; /grant:r replaces the permissions of the principals it NAMES. An EXPLICIT ACE for any
      other principal survives both. Measured: an explicit BUILTIN\Users:(OI)(CI)RX on the data dir
      came through the old call untouched, propagated to the logs directory beneath it, and icacls
      exited 0 - so the installer reported a hardened PHI sink over a world-readable one.

      ProgramData's own BUILTIN\Users ACE is inherited, which is why the default path looked correct
      and the gap stayed invisible. It bites wherever the data dir is NOT freshly created under
      ProgramData: an operator pointing -DataDir at an existing directory or share, a dir made by
      another tool, or a reinstall after somebody granted access by hand.

      So the explicit broad ACEs are removed as well, and then the resulting DACL is READ BACK. The
      named removals cover AT LEAST the well-known broad principals listed below - not all of them,
      and the list is not a closed set: Power Users (S-1-5-32-547) and Remote Desktop Users
      (S-1-5-32-555) are two it does not name. That is what the read-back is for. It catches
      whatever the list missed and NAMES it, rather than leaving the caller to believe a lockdown
      that did not happen, so an omission degrades to a warning the operator must act on rather than
      to a silent exposure.
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
        return
    }
    # Drop any EXPLICIT broad ACE the grant above left standing. Removing a SID that is not present
    # is a no-op and still exits 0, so the whole set goes in one call. Well-known SIDs, so this works
    # on non-English Windows (an English host prints "BUILTIN\Users"; a German one does not).
    #
    # OWNER RIGHTS (S-1-3-4) is in the set and CREATOR OWNER (S-1-3-0) does not cover it. CREATOR
    # OWNER materializes into an ACE for the creating principal at creation time; OWNER RIGHTS stays
    # S-1-3-4 in the DACL and is evaluated against whoever owns the object AT ACCESS TIME. The owner
    # is not a fixed principal - any Administrator can take ownership, and the service account owns
    # every log file it creates - so it is a standing grant to a moving target over a PHI sink.
    # Measured 2026-09-18 on the CI windows-2022 and windows-2025 runners, and reproduced locally: an
    # EXPLICIT OWNER RIGHTS ACE on the data dir came through `/inheritance:r /grant:r` untouched with
    # icacls exiting 0, propagated to the logs directory beneath it, and only the read-back saw it.
    # Removing the ACE does not lock the owner out: with no S-1-3-4 ACE constraining them, Windows
    # falls back to the owner's implicit READ_CONTROL + WRITE_DAC.
    $broad = @(
        "*S-1-1-0",       # Everyone
        "*S-1-5-32-545",  # BUILTIN\Users
        "*S-1-5-11",      # Authenticated Users
        "*S-1-5-4",       # INTERACTIVE
        "*S-1-3-0",       # CREATOR OWNER
        "*S-1-3-4",       # OWNER RIGHTS
        "*S-1-5-32-546",  # Guests
        "*S-1-5-7"        # ANONYMOUS LOGON
    )
    & icacls $Path /remove:g @broad | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Could not remove broad-principal ACEs from '$Path' (icacls exit " +
            "$LASTEXITCODE); check it by hand with 'icacls $Path' - the captured logs are a PHI sink " +
            "(docs/PHI.md).")
        return
    }
    $residue = Get-BroadAclResidue -Path $Path -Account $Account
    if ($residue) {
        Write-Warning ("'$Path' still grants access to: $($residue -join ', '). The engine's logs " +
            "under it can contain operational/PHI detail (docs/PHI.md); remove those grants by hand " +
            "or point -DataDir at a directory only SYSTEM and Administrators can reach.")
    }
}

function Set-DataDirOwner {
    <#
      Make BUILTIN\Administrators the OWNER of the data directory (ADR 0183 Wave 0b). The engine gives
      the store trio the directory's principals only when the directory's owner is SYSTEM,
      Administrators or the service account, because an owner keeps WRITE_DAC whatever the DACL says.
      New-Item leaves the owner to the host's default-owner policy: Administrators for an elevated
      member under the default, but the creating USER under "Object creator", and the hosted CI
      runners' built-in Administrator (RID 500) was measured owning the objects it creates (CI run
      36039014999). Without this step the store there falls back to owner-only and the service and
      the operator's provision-admin lock each other out. Mirrors Set-SecureConfigAcl's owner step.
      Separate from Set-SecureDataDirAcl so that function's own tests, which run unelevated, are not
      asked to change an owner they cannot. Best-effort: warns, never aborts.
    #>
    param([Parameter(Mandatory)][string]$Path)
    & icacls $Path /setowner "*S-1-5-32-544" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Could not set Administrators as the owner of the data dir '$Path' (icacls " +
            "exit $LASTEXITCODE). The engine then restricts its SQLite store owner-only, and the " +
            "service and provision-admin cannot both open it. Run " +
            "'icacls ""$Path"" /setowner ""*S-1-5-32-544""' elevated.")
    }
}

function Get-BroadAclResidue {
    <#
      READ THE DACL BACK and return the names of any principals holding Allow access beyond SYSTEM,
      Administrators and the service account. Returns an empty array when the directory is locked
      down, which is what makes "the lockdown worked" a reading rather than an assumption.

      An unresolvable identity is reported rather than skipped: a SID nobody can translate is still
      a grant, and dropping it here would turn a residue into a clean result.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$Account)
    $allowed = @("S-1-5-18", "S-1-5-32-544")
    if ($Account) {
        try {
            $allowed += ([Security.Principal.NTAccount]$Account).Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch {
            # A virtual account's SID may not resolve before the service exists; fall back to the name.
            $allowed += $Account
        }
    }
    $found = @()
    try { $acl = Get-Acl -Path $Path } catch {
        Write-Warning "Could not read the ACL of '$Path' ($($_.Exception.Message))."
        return @()
    }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $name = "$($rule.IdentityReference)"
        $sid = $name
        try {
            $sid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { }
        if (($allowed -notcontains $sid) -and ($allowed -notcontains $name)) { $found += $name }
    }
    return ($found | Select-Object -Unique)
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
      inherited ACEs (/inheritance:r), and set its OWNER to Administrators. The in-process source-trust
      guard (SEC-003) refuses to load any config dir/module a broad/low-privilege principal can write,
      so this brings the on-disk ACL into line with what the runtime enforces - inherited write/modify
      ACEs (e.g. from a parent profile or ProgramData) are removed. Opt-in via -LockConfigDir because
      the config dir often lives in a repo where stripping inheritance is surprising. Mirrors
      Set-SecureDataDirAcl: well-known SIDs (non-English Windows), best-effort (warn, never abort).

      THE OWNER STEP IS NOT COSMETIC (ADR 0036 Amendment A, BACKLOG #1647). The guard vets the OWNER
      as well as the DACL, because an owner holds WRITE_DAC implicitly and can rewrite the executed
      .py whatever the ACEs say. A DACL-only lockdown therefore does NOT clear the guard: the dir
      keeps the owner it was created with - typically the individual operator who made it - and the
      runtime membership lookup is local-only and sees DIRECT members, so an operator whose admin
      rights arrive through a nested domain group is refused. Without this step the shipped installer
      could not produce a config dir that loads, and the only remaining cure would be
      MEFOR_ALLOW_INSECURE_CONFIG_SOURCE, which disables the whole control.
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
    # /T so the *.py files the guard also vets carry the same owner, not just the directory. /C so one
    # unsettable file (an open editor, an AV scan) does not abort the walk and leave the rest of the
    # tree on the old owner - the guard evaluates each *.py individually, so a partial pass refuses on
    # whichever module was missed, and the directory itself would already look correct.
    & icacls $Path /setowner "*S-1-5-32-544" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Could not set Administrators as the owner of the config dir '$Path' (icacls " +
            "exit $LASTEXITCODE); the engine vets the OWNER as well as the ACL and would REFUSE to " +
            "load a dir owned by a non-administrator (SEC-003, docs/SERVICE.md). With /C some files " +
            "may have been skipped - check which, then run " +
            "'icacls ""$Path"" /setowner ""*S-1-5-32-544"" /T /C' elevated.")
    }
}

function Get-CrashDumpImageName {
    <#
      The image names whose WER behaviour must be suppressed (ADR 0152 Phase 0). Returns BOTH the
      launcher ($AppExe, e.g. messagefoundry.exe) and the venv interpreter, because a pip console-script
      launcher on Windows starts the interpreter as a CHILD process - so the process that actually holds
      the PHI heap, and therefore the one WER would dump, is python.exe, not messagefoundry.exe. Naming
      only the launcher would produce a policy that looks applied and protects nothing.
    #>
    param([Parameter(Mandatory)][string]$AppExe)
    $names = @([IO.Path]::GetFileName($AppExe))
    $interpreter = Join-Path (Split-Path -Parent $AppExe) "python.exe"
    if (Test-Path $interpreter) { $names += [IO.Path]::GetFileName($interpreter) }
    return ($names | Select-Object -Unique)
}

function Set-CrashDumpSuppression {
    <#
      Reduce Windows Error Reporting crash-dump exposure for the given image names, machine-wide
      (ADR 0152 Phase 0). Two INDEPENDENT registry surfaces, because neither one alone is sufficient:

        1. ExcludedApplications\<image> = 1  - keeps WER from reporting/queueing faults for the image.
        2. LocalDumps\<image>               - LocalDumps is evaluated SEPARATELY from the exclusion list
                                              and from every process-local WerSetFlags flag, so an
                                              excluded image still gets a local dump if LocalDumps is
                                              configured.

      LOCALDUMPS IS ONLY EVER *NARROWED*, NEVER TURNED ON. WER local dump collection is OPT-IN: if the
      LocalDumps key does not exist, no local dumps are collected for anything on this host. Creating
      LocalDumps\<image> where the parent key was absent would therefore CONFIGURE per-image dump
      collection where none existed - a switch called -SuppressCrashDumps that plausibly ENABLES PHI
      dumps is worse than shipping nothing. So the per-image override is written ONLY when a LocalDumps
      configuration already exists; otherwise the host is already in the state we want and we say so.

      When it IS written, the override is DumpType=0 + CustomDumpFlags=0 (MiniDumpNormal - no heap,
      which is the PHI-relevant part) so a host configured for full dumps stops writing the engine's
      heap. DumpCount=0 is set as well, but note Microsoft documents DumpCount as "the maximum number
      of dump files in the folder", NOT as a disable switch - 0 is not a documented "off", and this
      has NOT been verified on a real box. Treat the whole per-image override as a REDUCTION (no heap),
      never as an elimination: a MiniDumpNormal still carries thread stacks. To eliminate local dumps,
      remove the host's LocalDumps configuration.

      RESIDUAL we cannot close here: a postmortem debugger registered under AeDebug attaches ahead of
      WER entirely. If this host has one, dumps remain possible regardless of these keys.

      Best-effort: warns and continues on failure, never aborts the install.
    #>
    param([Parameter(Mandatory)][string[]]$ImageNames)
    $werRoot = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    $localDumpsRoot = Join-Path $werRoot "LocalDumps"
    # Probed ONCE, before any write, so our own per-image key can never be mistaken for pre-existing
    # host configuration on the second image in the loop.
    $localDumpsConfigured = Test-Path $localDumpsRoot
    foreach ($image in $ImageNames) {
        try {
            $excluded = Join-Path $werRoot "ExcludedApplications"
            if (-not (Test-Path $excluded)) { New-Item -Path $excluded -Force | Out-Null }
            New-ItemProperty -Path $excluded -Name $image -Value 1 -PropertyType DWord -Force | Out-Null

            if ($localDumpsConfigured) {
                $localDumps = Join-Path $localDumpsRoot $image
                if (-not (Test-Path $localDumps)) { New-Item -Path $localDumps -Force | Out-Null }
                New-ItemProperty -Path $localDumps -Name "DumpCount" -Value 0 -PropertyType DWord -Force | Out-Null
                New-ItemProperty -Path $localDumps -Name "DumpType" -Value 0 -PropertyType DWord -Force | Out-Null
                New-ItemProperty -Path $localDumps -Name "CustomDumpFlags" -Value 0 -PropertyType DWord -Force | Out-Null
                Write-Host ("  Dumps  : WER reporting excluded for image '$image'; this host HAS " +
                    "LocalDumps configured, so its per-image dump was narrowed to a heap-free " +
                    "MiniDumpNormal (a reduction, not an elimination).")
            }
            else {
                Write-Host ("  Dumps  : WER reporting excluded for image '$image'; LocalDumps is not " +
                    "configured on this host, so no local dumps are collected and NOTHING was written " +
                    "under LocalDumps (creating it would have switched collection ON).")
            }
        } catch {
            Write-Warning ("Could not suppress WER crash dumps for image '$image' " +
                "($($_.Exception.Message)). A crash dump of the engine would contain plaintext PHI " +
                "(docs/PHI.md); configure it manually under '$werRoot' or accept the exposure.")
        }
    }
    Write-Warning ("WER crash-dump suppression is set by IMAGE NAME and is machine-wide: it affects " +
        "every process of these names on this host, a postmortem debugger registered under AeDebug " +
        "still bypasses it, and these keys PERSIST after uninstall-service.ps1 (deliberately - " +
        "silently re-enabling PHI dumps on uninstall would be the more surprising default). Remove " +
        "them by hand under '$werRoot' if you want the host's original WER behaviour back. This is " +
        "memory HYGIENE and moves ASVS 11.7.1 by ZERO - it keeps plaintext PHI out of a fault report " +
        "on disk, it does not encrypt memory in use. See " +
        "docs/adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-" +
        "asvs-11-7-1.md.")
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
      policy (#99). Setting the account (Set-ServiceAccount) does NOT grant this right the way the SCM UI
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

# Repo root is two levels up from this script (scripts\service\). Computed FIRST: -AppExe and
# -Config default from it, and the normalization below has to run before anything CONSUMES a path.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# --- absolute paths, before anything consumes one (BACKLOG #1554) -----------------------------------
# A service resolves a relative path against its own working directory, so every path baked into the
# registration must be absolute. Only -Config was normalized, and it was normalized LATE - after
# Resolve-Nssm had already joined a possibly-relative -DataDir, and after Test-Path had validated a
# relative -DbPath against a DIFFERENT directory from the one the service would resolve it against.
# That is the whole defect: one path, validated here against the operator's shell location, resolved
# there against AppDirectory ($RepoRoot).
#
# NOT Resolve-Path: it THROWS on a path that does not exist, and a first install legitimately has no
# database file yet. GetUnresolvedProviderPathFromPSPath normalizes without requiring existence.
#
# THE ANCHOR IS $PWD, THE DIRECTORY THE OPERATOR RAN THIS FROM - not $PSScriptRoot and not $RepoRoot.
# A relative path an operator types means "from where I am standing"; anchoring it to the script's own
# location would silently relocate it, which is a quieter version of the same bug.
function Resolve-AbsolutePath {
    param([Parameter(Mandatory)][string]$Path)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

$DataDir = Resolve-AbsolutePath $DataDir
if (-not $AppExe) { $AppExe = Join-Path $RepoRoot ".venv\Scripts\messagefoundry.exe" }
else { $AppExe = Resolve-AbsolutePath $AppExe }
if (-not $Config) { $Config = Join-Path $RepoRoot "samples\config" }
else { $Config = Resolve-AbsolutePath $Config }
# Derived from the ALREADY-absolute $DataDir, so the default is absolute without a second pass.
if (-not $DbPath) { $DbPath = Join-Path $DataDir "messagefoundry.db" }
else { $DbPath = Resolve-AbsolutePath $DbPath }

$NssmDir = Resolve-AbsolutePath $NssmDir

# AFTER the normalization: Resolve-Nssm copies nssm.exe into -NssmDir, and the service is registered
# with that path, so a relative one would be resolved against a different directory later.
$NssmPath = Resolve-Nssm -Provided $NssmPath -NssmDir $NssmDir

if (-not (Test-Path $AppExe)) {
    throw "Engine executable not found at: $AppExe`nRun 'pip install -e .' in the project venv, or pass -AppExe."
}
if (-not (Test-Path $Config)) { throw "Config directory not found at: $Config" }

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
    <#
      Run nssm and FAIL CLOSED on a non-zero exit, naming the subcommand that failed.

      The failure message joins the arguments because for its ordinary call sites that is exactly what
      an operator needs ("nssm set MessageFoundry AppStdout ... failed (exit 3)"). One call used to pass
      the service-account password as a positional argument, and a joined message there put a
      cleartext password into the thrown message, the console, and the $Error record it leaves behind
      (BACKLOG #1573).

      NO CALL SITE PASSES -Secret NOW. The password call was `nssm set ObjectName`, which NSSM 2.24
      refuses for a virtual account, so the run-as account moved to Set-ServiceAccount, which carries
      its own #1573 guard (BACKLOG #2364). The parameter stays, with its tests, so that a future nssm
      call carrying a secret has a redacting form to use rather than a joined one.

      So the secret is a SEPARATE, NAME-ONLY parameter and the message is built from $NssmArgs, which
      never holds it. The redaction is therefore a property of how the message is CONSTRUCTED - there
      is no code path anywhere that assembles a string containing the password and filters it after the
      fact, which is the version that leaks the first time somebody adds a second message.

      -Secret is name-only because $NssmArgs declares Position = 0: with an explicit position on the
      remaining-arguments parameter, PowerShell stops binding the unpositioned ones positionally, so
      `Invoke-Nssm set $ServiceName ...` still binds every token to $NssmArgs. Measured on Windows
      PowerShell 5.1.26100 (the host CI runs these scripts on) and on PowerShell 7.

      $LASTEXITCODE IS CLEARED FIRST, AND A MISSING ONE IS A FAILURE. It is a session-wide variable
      that a failed LAUNCH never writes, so a check written after one reads whatever the PREVIOUS
      native command left. Whether that is reachable depends on the host, and on Windows it is not:
      measured 2026-09-18 on PowerShell 7.6.6 and Windows PowerShell 5.1.26100, a present-but-
      unrunnable nssm.exe raises a TERMINATING ApplicationFailedException and this line is never
      reached. On Linux it IS reachable - observed on this branch's ubuntu CI leg, where PowerShell
      resolved a non-executable file, failed to start it, wrote a NON-terminating error, and ran
      straight on to the check with $LASTEXITCODE never set.

      So the clear buys two things on every host: the code reported is unambiguously the one THIS
      call produced, and an absent one is named rather than printed as `failed (exit )`.
    #>
    param(
        # A trailing argument that must never reach a message, a transcript, or an $Error record.
        # Appended to the nssm command line as the LAST argument; the failure message shows a
        # placeholder in its place.
        [string]$Secret,
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]$NssmArgs
    )
    $hasSecret = $PSBoundParameters.ContainsKey('Secret')
    # Built BEFORE the call, from the non-secret arguments only.
    $shown = @($NssmArgs)
    if ($hasSecret) { $shown += '<redacted>' }
    $global:LASTEXITCODE = $null
    if ($hasSecret) { & $NssmPath @NssmArgs $Secret } else { & $NssmPath @NssmArgs }
    $exit = $LASTEXITCODE
    if ($null -eq $exit) {
        throw ("nssm $($shown -join ' ') failed (no exit code: '$NssmPath' did not run)")
    }
    if ($exit -ne 0) { throw "nssm $($shown -join ' ') failed (exit $exit)" }
}

# BEGIN Stop-ServiceAndConfirm (kept byte-identical with uninstall-service.ps1; guarded by
# tests/test_service_install_manifest.py, which fails if the two copies drift)
function Stop-ServiceAndConfirm {
    <#
      Stop the service and CONFIRM from the SCM that it actually stopped. Returns $true when the
      service is Stopped (or gone); $false when it is still running.

      Neither half of this existed before (BACKLOG #1558), and neither half is enough on its own.

      THE EXIT CODE, AND WHY THE OLD try/catch WAS NOT THE GUARD IT LOOKED LIKE. The previous call
      was `try { & $NssmPath stop $ServiceName 2>&1 | Out-Null } catch { }`. Measured on both hosts:
      under PowerShell 7.6.6 a non-zero native exit raises nothing, so the catch never fired and the
      failure was simply unnoticed; under Windows PowerShell 5.1.26100 - the host CI runs these
      scripts on - the `2>&1` MERGE turned nssm's stderr into a terminating RemoteException, which
      the empty catch then swallowed, AND left $LASTEXITCODE at -1 because the pipeline aborted
      before nssm's real exit code was recorded. So an exit-code check written after a merged
      capture would have been unreachable on the very host that matters. This calls nssm BARE: its
      output goes to the operator instead of Out-Null, no redirection wraps the error stream, and
      $LASTEXITCODE is the true exit code on both hosts.

      AND A MISSING EXIT CODE IS NOT A ZERO. $LASTEXITCODE is session-wide and a failed LAUNCH never
      writes it, so a check written after one reads whatever the PREVIOUS native command left. The
      catch above covers the hosts where such a failure is TERMINATING - measured 2026-09-18 on
      PowerShell 7.6.6 and Windows PowerShell 5.1.26100, a present-but-unrunnable nssm.exe raises
      ApplicationFailedException and lands there. It does NOT cover the hosts where the failure is
      non-terminating: observed on this branch's ubuntu CI leg, where execution ran straight past the
      catch with $LASTEXITCODE never set and the warning printed `exited ` with nothing after it. So
      the variable is cleared first and a $null afterwards is treated as the catch treats a throw:
      nssm did not run, say so, and stop through the SCM instead.

      THE RE-READ. An exit code is still not enough. `nssm stop` can exit 0 while the process is
      still shutting down - the engine drains connections for up to AppStopMethodConsole ms - and
      the caller's next step (rewriting the configuration, or removing the registration) then runs
      against a service that is still running. So the status is polled back from the SCM and the
      caller is told what it is, rather than assuming.

      NSSM'S STDOUT GOES TO THE HOST, NOT INTO THE RETURN VALUE. This function's contract is a single
      boolean, and a bare call puts everything nssm prints on stdout into the function's output
      stream ahead of it. The caller then holds an ARRAY, and `if (-not $stopped)` on a multi-element
      array is $false however the stop actually went - so the "still running" warning the whole
      function exists to raise is skipped exactly when nssm had something to say. Measured
      2026-09-18 on PowerShell 7.6.6 and Windows PowerShell 5.1.26100 against a stub that prints one
      stdout line: bare returns 2 objects, `| Out-Host` returns 1. Out-Host and not Out-Null because
      the operator still needs to read it, and not a redirection, which is what broke the old form.
      $LASTEXITCODE survives the pipe on both hosts (measured, same run).
    #>
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        # Empty when nssm is unavailable; the stop then goes through the SCM instead.
        [string]$NssmPath,
        [int]$TimeoutSeconds = 30
    )
    if ($NssmPath) {
        $launched = $true
        $global:LASTEXITCODE = $null
        try { & $NssmPath stop $ServiceName | Out-Host } catch {
            $launched = $false
            Write-Warning ("Could not run '$NssmPath' to stop '$ServiceName' " +
                "($($_.Exception.Message)). Falling back to the SCM.")
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        $exit = $LASTEXITCODE
        if ($launched -and $null -eq $exit) {
            $launched = $false
            Write-Warning ("'$NssmPath' left no exit code, so nssm never ran and '$ServiceName' was " +
                "not stopped by it. Falling back to the SCM.")
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        } elseif ($launched -and $exit -ne 0) {
            Write-Warning ("nssm stop '$ServiceName' exited $exit (its message is above). " +
                "The service may still be running; the status is checked below.")
        }
    } else {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) { return $true }
        if ($svc.Status -eq "Stopped") { return $true }
        if ((Get-Date) -ge $deadline) {
            Write-Warning ("Service '$ServiceName' is still '$($svc.Status)' $TimeoutSeconds " +
                "seconds after the stop was issued.")
            return $false
        }
        Start-Sleep -Milliseconds 500
    }
}
# END Stop-ServiceAndConfirm

# If the service already exists, reconfigure it in place (idempotent install).
# Detect via Get-Service rather than `nssm status` (which errors to stderr on a missing
# service and would abort under ErrorActionPreference=Stop).
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service '$ServiceName' exists - stopping and reconfiguring..."
    if (-not (Stop-ServiceAndConfirm -ServiceName $ServiceName -NssmPath $NssmPath)) {
        Write-Warning ("Reconfiguring '$ServiceName' while it is still running. NSSM writes the new " +
            "settings, but the RUNNING process keeps the old ones until it is restarted - so this " +
            "install can report success over a service that is still on the previous configuration, " +
            "including the previous run-as account and the previous paths. Stop it by hand and " +
            "re-run, or restart it once this finishes, and confirm with 'Get-Service $ServiceName'.")
    }
} else {
    Write-Host "Installing service '$ServiceName'..."
    Invoke-Nssm install $ServiceName $AppExe
}

# THE REGISTRATION IS POINTED AT THE CHECKED COPY, QUOTED, AND READ BACK (BACKLOG #2364). `nssm set`
# never changes which nssm.exe the SCM starts: a fresh `nssm install` writes its own path unquoted,
# and a service from an earlier install may name any nssm.exe at all, where anyone could have
# changed it. Nothing here runs that earlier binary; the stop above went through the checked copy.
# On failure the service is set to Disabled before the throw, so a registration this script could
# not make safe does not start at the next boot.
try {
    Set-ServiceImage -ServiceName $ServiceName -Path $NssmPath
} catch {
    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
    throw ("$($_.Exception.Message) '$ServiceName' was set to Disabled so it cannot start from an " +
        "unchecked image. Remove it with .\uninstall-service.ps1 and re-run.")
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
# TWO VALUES, NEVER ONE (BACKLOG #1553). $RunAsObjectName is what the SCM is told to run the service as;
# $ServiceAccount stays "the account that needs an EXPLICIT ACL grant", and is EMPTY for LocalSystem.
# They must not be collapsed: Set-SecureDataDirAcl already grants *S-1-5-18, which IS LocalSystem, so
# adding a named "LocalSystem" grant is redundant and can make icacls exit non-zero.
$RunAsObjectName = if ($ServiceAccount) { $ServiceAccount } else { "LocalSystem" }

if ($ServiceAccount) {
    # gMSA preflight (#99): verify the account is installed + usable on this host, then grant it the
    # "Log on as a service" right BEFORE registering (setting the account does not grant it). Both steps
    # degrade gracefully on a non-domain box and never abort the install.
    if ((Test-LooksLikeGmsa -Account $ServiceAccount) -and -not $SkipGmsaPreflight) {
        Test-GmsaInstalled -Account $ServiceAccount
    }
    # EVERY named account needs SeServiceLogonRight, a password account too. This skipped password
    # accounts while `nssm set ObjectName` granted the right to them itself. Set-ServiceAccount goes
    # through the SCM, which grants nothing (BACKLOG #2364). Best-effort, and idempotent.
    Set-ServiceLogonRight -Account $ServiceAccount
    if ($ServiceAccountPassword) {
        # The SecureString goes to Set-ServiceAccount as it is. It becomes plaintext only inside that
        # function's one call to the SCM, and no message it builds can carry it (BACKLOG #1573).
        Set-ServiceAccount -ServiceName $ServiceName -Account $RunAsObjectName -Password $ServiceAccountPassword
    } else {
        # Virtual / managed accounts (e.g. "NT SERVICE\MessageFoundry", a gMSA) take no password, and
        # a gMSA keeps its trailing '$'. Through the SCM, because NSSM 2.24 refuses these outright.
        Set-ServiceAccount -ServiceName $ServiceName -Account $RunAsObjectName
    }
    Write-Host "  Account: $RunAsObjectName" -ForegroundColor Green
} else {
    # $ServiceAccount is empty only when -AllowLocalSystem was passed (the default above otherwise fills
    # it with the virtual account), so this branch is the explicit LocalSystem opt-out (#224).
    #
    # OBJECTNAME IS SET EXPLICITLY HERE, AND IT USED TO BE LEFT ALONE (BACKLOG #1553). The comment that
    # stood here said "leave ObjectName unset -> NSSM runs the service as LocalSystem", and that is
    # true only of a FRESH install. On a RERUN over a service already registered with another account,
    # not writing ObjectName leaves THAT account configured - and the ACL block below then locks the
    # data and config dirs to SYSTEM/Administrators, stripping the account the service is still
    # running as. The service loses write on its data dir and read on its config dir, and SEC-003
    # source-trust then refuses to load config at all. Writing it every time makes the run-as account
    # and the ACLs agree on every path.
    #
    # It also makes NSSM's create-time default irrelevant. Whether that default really is LocalSystem
    # was never measured; setting the value explicitly removes the need to know.
    Set-ServiceAccount -ServiceName $ServiceName -Account $RunAsObjectName
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
# THESE GRANTS ARE ONLY CORRECT BECAUSE OBJECTNAME IS NOW WRITTEN ON EVERY PATH (BACKLOG #1553). They
# name $ServiceAccount, so "the account the ACLs are built for" and "the account the service actually
# runs as" have to be the same thing. That held on a fresh install and NOT on a rerun: a rerun with
# -AllowLocalSystem left the previous account configured while these three calls stripped its access -
# the data dir here, and the config dir below, where losing READ makes SEC-003 source-trust refuse to
# load config at all. $ServiceAccount stays EMPTY for LocalSystem on purpose; the LocalSystem grant is
# the *S-1-5-18 ACE Set-SecureDataDirAcl already writes, and naming "LocalSystem" as well is redundant
# and can make icacls exit non-zero.
#
# Harden the PHI sink (review H-13): NSSM writes the engine's stdout/stderr under $LogDir, so lock the
# data dir (logs inherit) down to SYSTEM/Administrators/(service account) - not world-readable.
Set-SecureDataDirAcl -Path $DataDir -Account $ServiceAccount
# The owner too, not only the DACL: the engine's store rule reads it (ADR 0183 Wave 0b).
Set-DataDirOwner -Path $DataDir
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
    # Name BOTH refusal criteria. The owner arm (ADR 0036 Amendment A) is independent of the DACL, so
    # an operator who audits the ACL, finds no low-privilege write grant and starts the service can
    # still be refused - and this warning would have told them the ACL was the whole story.
    Write-Warning ("The config dir '$Config' still inherits its parent's ACL, and its OWNER has not " +
        "been set. The engine's in-process source-trust guard (SEC-003) will REFUSE to load if a " +
        "low-privileged principal (Everyone, Authenticated Users, Users, or any non-admin) has " +
        "write/modify on the dir or any *.py in it, AND separately if the dir's owner is neither the " +
        "run-as account nor an administrator it can resolve. Re-run with -LockConfigDir (which sets " +
        "both), or point -Config at a dedicated admin-owned dir; see docs/SERVICE.md " +
        "'Restrict the config directory'.")
}
if ($ServiceAccount) {
    Write-Host "  ACLs   : granted read on '$Config'; read/write on '$DataDir' (docs/SERVICE.md)."
}

# --- WER crash-dump suppression (ADR 0152 Phase 0, opt-in) -------------------------------------------
# The engine applies the PROCESS-LOCAL half at every `serve` unconditionally. This is the MACHINE-POLICY
# half, which no process can set for itself; without it a LocalDumps-configured host can still write a
# full-memory dump of the engine - plaintext PHI, on disk, outside the store's encryption and retention.
if ($SuppressCrashDumps) {
    Set-CrashDumpSuppression -ImageNames (Get-CrashDumpImageName -AppExe $AppExe)
} else {
    Write-Host ("  Dumps  : WER crash-dump suppression NOT applied (pass -SuppressCrashDumps). The " +
        "engine suppresses what a process can suppress on its own, but if this host has WER LocalDumps " +
        "configured, a crash dump of the engine would contain plaintext PHI (docs/PHI.md).")
}

Write-Host ""
Write-Host "Installed '$ServiceName'." -ForegroundColor Green
Write-Host "  Engine : $AppExe $AppParams"
Write-Host "  Logs   : $StdoutLog"
Write-Host "           $StderrLog"
Write-Host ""
Write-Host "Next steps:"
# Start-Service needs no nssm.exe, so an operator following this never runs a copy nobody checked
# (BACKLOG #2364).
Write-Host "  Start-Service '$ServiceName'"
# The engine ALWAYS serves TLS (BACKLOG #1276 part A, ADR 0172): with no [api].tls_cert_file
# configured it mints a self-signed pair beside the store database on first start. So the health
# probe is https, and it must trust that certificate - printing the old plaintext `curl http://...`
# line told an operator to do the exact thing that no longer answers.
$GeneratedCert = Join-Path (Split-Path -Parent $DbPath) "api-generated-cert.pem"
Write-Host "  curl.exe --cacert `"$GeneratedCert`" https://${ListenHost}:${Port}/health"
Write-Host ("           (that PEM is the placeholder pair the engine mints on first start. With your " +
    "own [api].tls_cert_file configured, verify against THAT chain instead - the generated pair is " +
    "never created.)")
Write-Host "  Stop:      Stop-Service '$ServiceName'"
Write-Host "  Uninstall: .\uninstall-service.ps1"
