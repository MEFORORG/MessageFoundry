# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Install mefor-net-helper, the ADR 0056 VIP helper, as a Windows service on this node.

.DESCRIPTION
    Runs net-helper/README.md's "Install it" steps: copy the published helper and an nssm.exe into
    an administrator-only folder, write mefor-net-helper.conf from the engine's own [cluster.vip]
    settings, register the helper as a LocalSystem service, and check the things a wrong install
    gets wrong silently.

    THE CONFIGURATION IS WRITTEN FROM THE ENGINE, NOT TYPED TWICE. The helper refuses every request
    naming an address, interface or mask other than the ones in its .conf, so those three values and
    the engine's [cluster.vip] values must be the same three values. This script reads them by
    running `messagefoundry cluster-vip --json`, which projects what the engine's own loader
    resolved. It does NOT parse messagefoundry.toml: a TOML parser here would be a second definition
    of that block rather than a second reader of it (BACKLOG #1523).

    IT DOES NOT DOWNLOAD NSSM, and that is deliberate. install-service.ps1 pins the archive URL and
    its SHA-256 in $NssmUrl / $NssmSha256, and this script does not repeat them. So pass -NssmPath,
    or have nssm on PATH; net-helper/README.md "Prepare the files once" is the download-and-check
    procedure, and it names that same pin.

    IT DOES CHECK BOTH BINARIES IT STARTS, because both run as SYSTEM (BACKLOG #2364). nssm.exe must
    hash to $NssmExeSha256, the pin of the binary inside that archive, which this script carries in
    a block tests/test_nssm_pin.py keeps identical to install-service.ps1's. mefor-net-helper.exe must hash
    to -HelperSha256. That value has no pin in this repository: the helper is built per release and
    per machine, so the hash comes from the build that made the binary - the net-helper workflow's
    job summary, or Get-FileHash over your own `dotnet publish` output before it leaves your hands.

    Run from an elevated (Administrator) PowerShell prompt, on each cluster node, AFTER the engine's
    own service exists (its account is what the helper's pipe ACL is built from).

.EXAMPLE
    .\install-net-helper.ps1 -HelperSource ..\..\net-helper\out -HelperSha256 <SHA-256> -NssmPath C:\tools\nssm.exe

.EXAMPLE
    .\install-net-helper.ps1 -HelperSource D:\build\net-helper -HelperSha256 <SHA-256> -ServiceConfig C:\ProgramData\MessageFoundry\messagefoundry.toml
#>
[CmdletBinding()]
param(
    # The `dotnet publish` output folder holding mefor-net-helper.exe. See net-helper/README.md
    # "Build it" - `dotnet build` output is NOT installable, it needs the .NET runtime.
    [Parameter(Mandatory)][string]$HelperSource,
    # The SHA-256 of that mefor-net-helper.exe, from the build that produced it (BACKLOG #2364). The
    # script refuses a binary that does not match, before it stops a running helper and again after
    # the copy, because it starts that binary as LocalSystem. REQUIRED, with no default: this
    # repository cannot pin a binary that each release and each machine builds for itself.
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$HelperSha256,
    # Administrator-only by default, and the README explains why it is not under ProgramData: the
    # engine's account has modify rights there, so it could replace the binary that runs as SYSTEM.
    [string]$InstallDir = "C:\Program Files\MessageFoundry\net-helper",
    # BOTH SERVICE NAMES ARE PATTERN-VALIDATED because both are interpolated into a WQL filter
    # (`Get-CimInstance Win32_Service -Filter "Name='$x'"`). A single quote in the value would end the
    # WQL literal, so the query either errors or matches a DIFFERENT service - and this script reads
    # the engine's run-as account out of that result and writes it into the helper's pipe ACL.
    #
    # THE CHARACTER SET IS messagefoundry/service.py's `_SAFE_SERVICE_NAME`, SPACE INCLUDED, and the
    # space is the part to leave alone. -EngineServiceName names the service the ENGINE's installer
    # created, install-service.ps1 puts no validation on its own -ServiceName, and a space is legal
    # there -- `_elevated_cmd_params` uses "My Engine" as its worked example. A tighter pattern here
    # would make an engine installed as "MessageFoundry Prod" unnameable to this script, failing at
    # parameter binding before anything ran. A space cannot end a WQL literal, so it costs nothing.
    [ValidatePattern('^[A-Za-z0-9 ._-]+$')][string]$ServiceName = "MessageFoundryNetHelper",
    # The engine's service, read for its run-as account (the pipe's only non-administrator caller).
    [ValidatePattern('^[A-Za-z0-9 ._-]+$')][string]$EngineServiceName = "MessageFoundry",
    # The engine executable, used only to read [cluster.vip]. Defaults to the repo venv, as
    # install-service.ps1's -AppExe does.
    [string]$AppExe,
    # The engine's service settings TOML. Omitted, `cluster-vip` falls back to ./messagefoundry.toml
    # if one is there - which depends on where you are standing, so pass it on a real install.
    [string]$ServiceConfig,
    # THERE IS NO -Interface OVERRIDE, and that is a decision rather than an omission. [cluster.vip]
    # is file-only with no MEFOR_CLUSTER_VIP_* env layer (docs/CONFIGURATION.md), so each node's
    # settings file already carries THAT node's adapter, which is what ADR 0056 D2 means by "this
    # node's NIC". An override would write a name the engine will never send: the controller sends
    # [cluster.vip].interface and the helper compares it with StringComparison.Ordinal, so every
    # bind on that node would be refused. It would also be the one value in the .conf that never
    # passed _vip_interface_problems. If shared, templated configs are a real deployment shape, that
    # is a question for the config layer, not a flag here.
    #
    # The account that may call the pipe, overriding the engine service's own run-as account. A name
    # or a SID; a name is resolved to a SID before it is written (see Resolve-ClientAccountSid).
    [string]$ClientAccount,
    [string]$NssmPath,
    # Install the files and the registration but leave the service stopped.
    [switch]$NoStart,
    # Install even though the folder check came back with something: a principal outside SYSTEM,
    # Administrators, TrustedInstaller, CREATOR OWNER and OWNER RIGHTS can write to -InstallDir, it
    # is OWNED by one, or its permissions could not be read at all. Whoever can write there can
    # replace a binary that runs as SYSTEM, so all three are refused by default.
    [switch]$AllowBroadAcl
)

$ErrorActionPreference = "Stop"

# Every native call below checks $LASTEXITCODE itself and decides what the code means. Turning a
# non-zero native exit into a terminating error instead would cut those decisions out, part-way
# through an install. uninstall-service.ps1's own assignment of this variable is the source of record
# for the measurements behind it; set explicitly rather than relied on.
$PSNativeCommandUseErrorActionPreference = $false

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
# END pinned-hash check

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Installing a Windows service requires an elevated (Administrator) PowerShell."
}

# --- paths, resolved before anything consumes one --------------------------------------------------
# A service resolves a relative path against its own working directory, so every path that ends up in
# the registration or the .conf must be absolute. The anchor is $PWD, the directory the operator ran
# this from - install-service.ps1's Resolve-AbsolutePath states why that and not $PSScriptRoot.
function Resolve-AbsolutePath {
    param([Parameter(Mandatory)][string]$Path)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$HelperSource = Resolve-AbsolutePath $HelperSource
$InstallDir = Resolve-AbsolutePath $InstallDir
if (-not $AppExe) { $AppExe = Join-Path $RepoRoot ".venv\Scripts\messagefoundry.exe" }
else { $AppExe = Resolve-AbsolutePath $AppExe }
if ($ServiceConfig) { $ServiceConfig = Resolve-AbsolutePath $ServiceConfig }

$SourceExe = Join-Path $HelperSource "mefor-net-helper.exe"
if (-not (Test-Path $SourceExe)) {
    throw ("mefor-net-helper.exe not found in -HelperSource '$HelperSource'. Build it with: " +
        "dotnet publish net-helper\MeforNetHelper.csproj --configuration Release --output " +
        "net-helper\out  (net-helper/README.md 'Build it').")
}
# CHECKED HERE, BEFORE ANYTHING IS STOPPED OR COPIED, so a wrong binary costs the operator a message and
# not a stopped helper. The installed copy is checked again after the copy, because that is the file
# the service starts as LocalSystem.
$helperProblem = Get-FilePinProblem -Path $SourceExe -Expected $HelperSha256
if ($helperProblem) {
    throw ("Refusing mefor-net-helper.exe: $helperProblem (-HelperSha256). Take the hash from the " +
        "build that produced this binary, and do not install one you cannot match to it.")
}
if (-not (Test-Path $AppExe)) {
    throw ("Engine executable not found at: $AppExe`nPass -AppExe. It is run once, read-only, to " +
        "resolve [cluster.vip]; it does not have to be the copy the service runs.")
}

function Resolve-HelperNssm {
    <#
      The nssm.exe this service will be registered with, COPIED into $InstallDir.

      The copy is the point, not a convenience. The registration names an nssm.exe by path, and that
      binary starts a process running as SYSTEM - so it has to live somewhere only administrators can
      write, beside the helper. net-helper/README.md is explicit that ProgramData is NOT such a
      place: the engine's own account has modify rights there.

      Nothing is downloaded here; see this script's header. What is found is checked against
      $NssmExeSha256 and REFUSED on a mismatch, from either source (BACKLOG #2364). There is no
      next source to fall back to, unlike install-service.ps1's search, so a PATH copy that fails
      is a refusal too rather than a skip. This is the copy's first check; the installed copy gets
      its own after the copy, because that one is what the service runs.
    #>
    param([string]$Provided)
    if ($Provided) {
        $found = Resolve-AbsolutePath $Provided
        if (-not (Test-Path -LiteralPath $found)) { throw "NSSM not found at: $found" }
        $where = "-NssmPath"
    } else {
        $onPath = Get-Command nssm -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $onPath) {
            throw ("nssm.exe not found. Pass -NssmPath, or put nssm on PATH. net-helper/README.md " +
                "'Prepare the files once' has the download and the hash check; the pinned archive " +
                "and its SHA-256 are `$NssmUrl and `$NssmSha256 in install-service.ps1.")
        }
        $found = $onPath.Source
        $where = "the nssm on PATH"
    }
    $problem = Get-FilePinProblem -Path $found -Expected $NssmExeSha256
    if ($problem) {
        throw ("Refusing $($where): $problem. Use the win64 nssm.exe from the archive " +
            "install-service.ps1 pins; net-helper/README.md 'Prepare the files once' has the steps.")
    }
    return $found
}

function Get-VipSettings {
    <#
      The engine's resolved [cluster.vip] block, as an object.

      ONE PARSER, ONE DEFINITION. `messagefoundry cluster-vip --json` projects what the engine's own
      loader resolved: `mask` is already the dotted-decimal netmask whichever of `prefix` and
      `netmask` was written, and a switched-on block that the loader refuses comes back as an error
      here rather than as three fields this script would write into a .conf.

      STDERR IS NOT MERGED IN. The engine logs a WARNING on a switched-on VIP (this build has no
      controller yet), and that goes to stderr, where the operator should see it. A `2>&1` merge
      would put it in front of the JSON on stdout AND, on Windows PowerShell 5.1, can turn it into a
      terminating error - the trap uninstall-service.ps1's Stop-ServiceAndConfirm records in full.
    #>
    param([Parameter(Mandatory)][string]$AppExe, [string]$ServiceConfig)
    $cliArgs = @("cluster-vip", "--json")
    if ($ServiceConfig) { $cliArgs += @("--service-config", $ServiceConfig) }
    $global:LASTEXITCODE = $null
    $out = & $AppExe @cliArgs
    $exit = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    if ($null -eq $exit) {
        throw "'$AppExe cluster-vip' did not run (it left no exit code)."
    }
    if (-not $text) {
        throw "'$AppExe cluster-vip' printed nothing (exit $exit); cannot read [cluster.vip]."
    }
    try { $parsed = $text | ConvertFrom-Json } catch {
        throw ("'$AppExe cluster-vip' did not print JSON (exit $exit): $text")
    }
    # The subcommand reports a config it could not load as {"error": ...} and exit 2, so the reason
    # reaches the operator instead of a blank read.
    if ($parsed.PSObject.Properties['error']) {
        throw "Could not read [cluster.vip]: $($parsed.error)"
    }
    if ($exit -ne 0) {
        throw "'$AppExe cluster-vip' failed (exit $exit): $text"
    }
    return $parsed
}

function Resolve-ClientAccountSid {
    <#
      The SID to write as `client_account`, from an account name or a SID.

      WRITE THE SID, NEVER THE NAME. HelperConfig.ParseClient takes the SID branch for any value
      starting "S-1-", and only its other branch calls NTAccount.Translate - which throws on exactly
      the spelling the SCM returns for a LocalSystem service ("LocalSystem" is an SCM alias, not an
      NTAccount name). A SID also survives a rename and is unambiguous across domains, and it is the
      spelling the helper's own log prints when it refuses a caller.

      The three SCM aliases are mapped here rather than handed to Translate for the same reason.
    #>
    param([Parameter(Mandatory)][string]$Account)
    if ($Account -like 'S-1-*') { return $Account }
    switch -Regex ($Account) {
        '^(\.\\)?LocalSystem$' { return "S-1-5-18" }
        '^(NT AUTHORITY\\)?LocalService$' { return "S-1-5-19" }
        '^(NT AUTHORITY\\)?NetworkService$' { return "S-1-5-20" }
    }
    try {
        return ([Security.Principal.NTAccount]$Account).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw ("'$Account' does not resolve to a SID on this node ($($_.Exception.Message)). A " +
            "per-service virtual account only resolves while its service is registered, so " +
            "install the engine's service first, or pass -ClientAccount with the SID.")
    }
}

function Invoke-HelperNssm {
    <#
      Run nssm and FAIL CLOSED on a non-zero exit, naming the subcommand that failed.

      No -Secret parameter, unlike install-service.ps1's Invoke-Nssm: this service runs as
      LocalSystem and is never given a password, so there is no argument here that must be kept out
      of a message. A redaction parameter nothing passes is a claim a reader would have to check.

      $LASTEXITCODE IS CLEARED FIRST AND AN ABSENT ONE IS A FAILURE. It is session-wide and a failed
      LAUNCH never writes it, so a check written after one otherwise reads the PREVIOUS command's
      code. install-service.ps1's Invoke-Nssm records the per-host measurements behind that rule.
    #>
    param([Parameter(Position = 0, ValueFromRemainingArguments = $true)]$NssmArgs)
    $global:LASTEXITCODE = $null
    & $NssmPath @NssmArgs
    $exit = $LASTEXITCODE
    if ($null -eq $exit) {
        throw "nssm $($NssmArgs -join ' ') failed (no exit code: '$NssmPath' did not run)"
    }
    if ($exit -ne 0) { throw "nssm $($NssmArgs -join ' ') failed (exit $exit)" }
}

# --- what goes in the .conf ------------------------------------------------------------------------

$NssmPath = Resolve-HelperNssm -Provided $NssmPath
$vip = Get-VipSettings -AppExe $AppExe -ServiceConfig $ServiceConfig

if (-not $vip.enabled) {
    $which = if ($vip.cluster_enabled) { "[cluster.vip].enabled is false" }
             else { "[cluster].enabled and [cluster.vip].enabled are both false" }
    # WHICH FILE WAS READ IS PART OF THE MESSAGE. With no -ServiceConfig the engine reads
    # ./messagefoundry.toml ONLY IF IT EXISTS, and otherwise every field comes back at its default -
    # which is indistinguishable here from a file that really does say "off". Telling an operator to
    # go set two switches that are already set in a file nothing opened is the worse of the two
    # wrong answers, so the message names the possibility instead of picking one.
    $where = if ($ServiceConfig) { "'$ServiceConfig'" }
             else { "./messagefoundry.toml, if there is one in '$PWD' -- pass -ServiceConfig if " +
                    "the engine's settings live elsewhere, because with no file the engine reports " +
                    "defaults and defaults look exactly like this" }
    throw ("$which in $where, so there is no address to install a helper for. Set both, with " +
        "address, interface and one of prefix/netmask, then re-run. Read what the engine " +
        "currently has with: & `"$AppExe`" cluster-vip" +
        $(if ($ServiceConfig) { " --service-config `"$ServiceConfig`"" } else { "" }))
}
# An enabled block cannot reach here with any of these empty: the engine refuses to LOAD one that
# does (ADR 0056 AC-8), and Get-VipSettings turns that refusal into a throw. Checked anyway, because
# the cost of being wrong is a .conf the helper rejects at start with a less specific message.
foreach ($field in @("address", "interface", "mask")) {
    if (-not $vip.$field) { throw "[cluster.vip].$field resolved to nothing; cannot write the .conf." }
}

$confInterface = $vip.interface
# The helper looks for the adapter only when asked to ACT, so a wrong name here is silent until the
# first failover. Warned and not thrown: an adapter can legitimately be added after the install, and
# Get-NetAdapter is absent on some SKUs.
#
# COMPARED WITH -ceq, NOT LEFT TO Get-NetAdapter -Name. That parameter is case-INSENSITIVE and
# wildcard-aware, so it resolves 'ethernet0' to an adapter named 'Ethernet0' and the check passes for
# exactly the mismatch the warning text names -- NetOps compares with StringComparison.Ordinal. A
# warning whose instrument cannot see the case it warns about is a control resting on a false
# premise (CLAUDE.md section 11, SDS-3.7), so the names are fetched and compared here instead.
try {
    $adapters = @(Get-NetAdapter -ErrorAction Stop | ForEach-Object { $_.Name })
    if ($adapters -cnotcontains $confInterface) {
        $near = @($adapters | Where-Object { $_ -ieq $confInterface })
        $detail = if ($near.Count) { "This node has '$($near[0])', which differs only in case, and " +
                                     "the helper matches exactly." }
                  else { "List them with: Get-NetAdapter | Select-Object Name" }
        Write-Warning ("No adapter on this node is named '$confInterface'. $detail")
    }
} catch {
    Write-Warning ("Could not list adapters to check '$confInterface' ($($_.Exception.Message)).")
}

if ($ClientAccount) {
    $clientSource = "-ClientAccount"
    $clientName = $ClientAccount
} else {
    $engineSvc = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'" -ErrorAction SilentlyContinue
    if (-not $engineSvc) {
        throw ("The engine service '$EngineServiceName' is not installed on this node, so its " +
            "run-as account cannot be read. Install it first (scripts\service\install-service.ps1), " +
            "or pass -ClientAccount. The helper's pipe admits that account and nobody else, so a " +
            "guess here would lock the engine out of its own helper.")
    }
    $clientSource = "the '$EngineServiceName' service"
    $clientName = $engineSvc.StartName
}
if (-not $clientName) { throw "Could not read a run-as account from $clientSource." }

# Resolved ONCE. The translation is an LSA lookup and a domain round trip for a domain account, and
# a second call would be a second place the same "does not resolve" failure is thrown from.
$clientSid = Resolve-ClientAccountSid -Account $clientName

# REFUSED, NOT WARNED, for the two SHARED built-in accounts. Every service on the box running as
# LocalService or NetworkService shares that SID, so writing one here would hand the helper's
# administrator rights to all of them. HelperConfig's own broad-group check does not cover these two
# (its list is the Everyone, Users and Interactive family), so nothing downstream would stop it.
#
# THIS REFUSAL COVERS THIS SCRIPT ONLY, AND SAYING SO IS THE POINT. A .conf written by hand, by a
# future MSI, or by a configuration-management tool bypasses it entirely and the helper accepts it.
# Closing that properly means adding LocalServiceSid and NetworkServiceSid to HelperConfig's
# BroadGroups, which is a change to the helper binary and its ADR 0056 contract, not to an installer.
# An operator who really means it can still pass the name or the SID to -ClientAccount.
if ((-not $ClientAccount) -and ($clientSid -in @("S-1-5-19", "S-1-5-20"))) {
    throw ("The engine service runs as '$clientName', which every service on this host running " +
        "under the same built-in account shares. Admitting it to the helper's pipe would give " +
        "all of them the helper's rights. Move the engine to its own account (the installer " +
        "defaults to NT SERVICE\$EngineServiceName), or pass -ClientAccount '$clientName' to " +
        "say you mean it.")
}
if ($clientSid -eq "S-1-5-18") {
    Write-Warning ("The engine service runs as LocalSystem, which already has the rights this " +
        "helper exists to hold on its behalf. The install will work, and it buys nothing: move the " +
        "engine to a least-privilege account (docs/SERVICE.md) for the helper to be worth running.")
}

# --- files ------------------------------------------------------------------------------------------

Write-Host "Installing the helper into '$InstallDir'..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$broad = @(Get-BroadWriteHolders -Path $InstallDir)
if ($broad.Count -gt 0) {
    $message = ("'$InstallDir' did not come back administrator-only: $($broad -join '; '). Whoever " +
        "can write there can replace mefor-net-helper.exe, its .conf or nssm.exe - each of which " +
        "then runs as SYSTEM. Use a folder under Program Files, or fix the permissions, and " +
        "re-run. Pass -AllowBroadAcl to install anyway.")
    if (-not $AllowBroadAcl) { throw $message }
    Write-Warning $message
}

$TargetExe = Join-Path $InstallDir "mefor-net-helper.exe"
$TargetNssm = Join-Path $InstallDir "nssm.exe"
$ConfPath = Join-Path $InstallDir "mefor-net-helper.conf"
$LogPath = Join-Path $InstallDir "net-helper.log"

# Stopped BEFORE the copy. Windows holds a running image open, so copying over it fails - and a
# reinstall onto a node that already has the helper is the ordinary case, not the exception.
#
# NOT Stop-ServiceAndConfirm. That function is shared byte-identically between install-service.ps1
# and uninstall-service.ps1 with a drift test pinning the pair, and it takes an empty -NssmPath to
# mean "stop through the SCM" -- so it WOULD work here. A third and fourth copy of a byte-pinned
# function is the cost this avoids; what it must not cost is the property, so this loop does the
# same two things that function exists to do: it issues the stop and then CONFIRMS from the SCM
# rather than assuming (BACKLOG #1558).
$serviceExists = [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
if ($serviceExists) {
    Write-Host "  Service '$ServiceName' exists - stopping it before the files are replaced."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(30)
    while ($true) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq "Stopped") { break }
        if ((Get-Date) -ge $deadline) {
            throw ("'$ServiceName' is still '$($svc.Status)' 30 seconds after the stop. Its image " +
                "is open, so the copy below would fail or half-succeed. Stop it by hand and re-run.")
        }
        Start-Sleep -Milliseconds 500
    }
}

Copy-Item $SourceExe $TargetExe -Force
# SKIPPED WHEN THEY ARE THE SAME FILE. Re-running with -NssmPath pointed at the already-installed
# copy is the ordinary reinstall, and Copy-Item raises "cannot be copied onto itself" there -- which
# under $ErrorActionPreference = "Stop" aborts AFTER the service has been stopped, leaving the node
# with a stopped helper and no completed install.
#
# A STRING COMPARE IS NOT ENOUGH, so the throw is caught as well. `-ne` on strings is
# case-insensitive, which covers NSSM.EXE against nssm.exe, and Get-Item resolves a junction or an
# 8.3 spelling to the same FullName - but neither closes every way one file has two names, and the
# cost of missing one is an abort at the worst moment. Measured: the same-file copy raises
# IOException, so the catch is the backstop that keeps this path from ending the install.
$sameFile = $NssmPath -eq $TargetNssm
if (-not $sameFile -and (Test-Path -LiteralPath $TargetNssm)) {
    $sameFile = (Get-Item -LiteralPath $NssmPath).FullName -eq
                (Get-Item -LiteralPath $TargetNssm).FullName
}
if (-not $sameFile) {
    try { Copy-Item -LiteralPath $NssmPath -Destination $TargetNssm -Force } catch [IO.IOException] {
        Write-Host "  NSSM   : '$NssmPath' is already the installed copy; left as it is."
    }
}

# EVERY nssm CALL BELOW RUNS THE INSTALLED COPY, and this line is what makes that true. NSSM writes
# the path of the nssm.exe that ran `install` into the service's own ImagePath, so registering with
# the source binary would point the SCM at a SYSTEM-launched executable outside the folder whose
# permissions were just checked -- and the read-back guard further down would then refuse the
# install it had already performed. net-helper/README.md registers with "$dir\nssm.exe" for the same
# reason and makes confirming it its own numbered step.
$NssmPath = $TargetNssm

# THE INSTALLED COPIES ARE CHECKED, NOT ONLY THEIR SOURCES (BACKLOG #2364). They are what the SCM
# starts as SYSTEM, and a source can change between its check and the copy. The folder check above is
# what keeps them from changing after this. With -AllowBroadAcl that check is only a warning, and then
# nothing does: whoever can write the folder can still swap a binary, plant a DLL beside it or edit
# the .conf before the start below.
#
# A COPY THAT FAILS IS DELETED BEFORE THE THROW, both binaries, and the deletion is read back. On a
# reinstall the helper was stopped and its files copied over, and the registration still starts them
# at boot. So when a file cannot be deleted, the registration is set to Disabled instead, and the
# message says which of the two happened.
$problem = (@(
    (Get-FilePinProblem -Path $TargetExe -Expected $HelperSha256),
    (Get-FilePinProblem -Path $TargetNssm -Expected $NssmExeSha256)
) -ne "") -join "; "
if ($problem) {
    Remove-Item -LiteralPath $TargetExe, $TargetNssm -Force -ErrorAction SilentlyContinue
    $left = @(@($TargetExe, $TargetNssm) | Where-Object { Test-Path -LiteralPath $_ })
    $outcome = "Both binaries were deleted from '$InstallDir'."
    if ($left.Count -gt 0) {
        $outcome = "Could not delete $($left -join ' and ')."
        if ($serviceExists) {
            Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
            $outcome += " '$ServiceName' was set to Disabled so the registration cannot start them."
        }
    }
    throw ("An installed copy failed its check: $problem. $outcome Nothing was started. Re-run from " +
        "files you can match to their hashes.")
}

# The helper reads this with a strict UTF-8 decoder. Written with an explicit BOM-less UTF-8 encoder
# rather than Set-Content, whose default encoding differs between PowerShell 7 and Windows
# PowerShell 5.1 - and this script is reachable from both.
#
# FOUR BARE KEY = VALUE LINES. The helper's parser takes everything after the first '=' as the value,
# so a trailing comment would become part of it. Comments go on their own lines.
$confLines = @(
    "# Written by scripts\service\install-net-helper.ps1 on $(Get-Date -Format 's').",
    "# address, interface and mask come from the engine's [cluster.vip]; read them back with:",
    "#   messagefoundry cluster-vip --json",
    "# The helper reads this file once, at start. Restart it after every edit.",
    "address = $($vip.address)",
    "interface = $confInterface",
    "mask = $($vip.mask)",
    "# The engine service's account, as a SID so the helper never has to translate a name.",
    "client_account = $clientSid"
)
[IO.File]::WriteAllLines($ConfPath, $confLines, [Text.UTF8Encoding]::new($false))

# --- registration -------------------------------------------------------------------------------

if ($serviceExists) {
    Write-Host "Reconfiguring '$ServiceName'..."
} else {
    Write-Host "Registering '$ServiceName'..."
    Invoke-HelperNssm install $ServiceName $TargetExe
}
Invoke-HelperNssm set $ServiceName Application $TargetExe
Invoke-HelperNssm set $ServiceName AppDirectory $InstallDir
Invoke-HelperNssm set $ServiceName DisplayName "MessageFoundry Net Helper"
Invoke-HelperNssm set $ServiceName Description "Binds and releases the MessageFoundry cluster VIP (ADR 0056)."
Invoke-HelperNssm set $ServiceName Start SERVICE_AUTO_START
Invoke-HelperNssm set $ServiceName AppStdout $LogPath
Invoke-HelperNssm set $ServiceName AppStderr $LogPath

# ROTATION AND A RESTART THROTTLE ARE NOT OPTIONAL HERE, and the helper needs them more than the
# engine does. It refuses to start on a bad .conf (exit 2) or a pipe name another process holds
# (exit 3), and it does so IMMEDIATELY. NSSM's default action on exit is Restart with a sub-second
# throttle, so an unthrottled, unrotated helper answers a one-character typo with a tight restart
# loop appending "startup refused" to a file on the system volume -- under Program Files, where a
# full disk is not a local problem. The values match install-service.ps1's: 5s throttle, 10 MB
# rotation. The engine's AppStopMethodConsole is deliberately NOT copied: that exists to give uvicorn
# time to drain connections, and the helper serves one caller at a time and holds no state.
Invoke-HelperNssm set $ServiceName AppExit Default Restart
Invoke-HelperNssm set $ServiceName AppThrottle 5000
Invoke-HelperNssm set $ServiceName AppRotateFiles 1
Invoke-HelperNssm set $ServiceName AppRotateOnline 1
Invoke-HelperNssm set $ServiceName AppRotateBytes 10485760
# LocalSystem is not a choice here the way it is for the engine. The helper's whole job is the
# administrator-rights work the engine's least-privilege account cannot do (ADR 0056), and its
# app.manifest already requires elevation - started by an unprivileged account it fails at once with
# ERROR_ELEVATION_REQUIRED (740).
Invoke-HelperNssm set $ServiceName ObjectName LocalSystem

# THE REGISTRATION IS POINTED AT THE CHECKED COPY, QUOTED, AND READ BACK (BACKLOG #2364). The exit
# codes above say nssm accepted the settings, not that the SCM will start the copy of nssm.exe in this
# folder - which is the property the folder's permissions protect. net-helper/README.md makes this its
# own numbered step for that reason. `nssm install` writes its path unquoted, and the default folder
# has a space in it (CWE-428), so Set-ServiceImage quotes it. It compares the whole registered line,
# not a substring, so a longer path that merely contains this one does not pass. On failure the
# service is set to Disabled before the throw, so it does not start at the next boot.
try {
    Set-ServiceImage -ServiceName $ServiceName -Path $TargetNssm
} catch {
    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
    throw ("$($_.Exception.Message) '$ServiceName' was set to Disabled. Remove it with " +
        ".\uninstall-net-helper.ps1 and re-run.")
}

# --- report -------------------------------------------------------------------------------------

# REPORTED, NOT REQUIRED. No code-signing certificate exists for this project yet, so every build is
# NotSigned and a gate here would fail every honest install. net-helper/README.md "Signing" has what
# changes when one does.
$signature = "unknown"
try { $signature = (Get-AuthenticodeSignature $TargetExe).Status } catch {
    Write-Warning "Could not read the Authenticode status of '$TargetExe' ($($_.Exception.Message))."
}

if (-not $NoStart) {
    Write-Host "Starting '$ServiceName'..."
    Invoke-HelperNssm start $ServiceName
}

Write-Host ""
Write-Host "Installed '$ServiceName'." -ForegroundColor Green
Write-Host "  Helper   : $TargetExe ($signature)"
Write-Host "             SHA-256 $($HelperSha256.ToUpperInvariant()), checked against -HelperSha256"
Write-Host "  NSSM     : $TargetNssm"
Write-Host "             SHA-256 $NssmExeSha256, checked against the pin"
Write-Host "  Config   : $ConfPath"
Write-Host "  Log      : $LogPath"
Write-Host "  Address  : $($vip.address)/$($vip.mask) on '$confInterface'"
Write-Host "  Caller   : $clientSid (from $clientSource, '$clientName')"
Write-Host ""
Write-Host "Next steps:"
if ($NoStart) { Write-Host "  Start it:  & `"$TargetNssm`" start $ServiceName" }
Write-Host ("  Read the log. A good start shows 'listening on \\.\pipe\mefor-net-helper'; a line " +
    "with 'startup refused' names what to fix:")
Write-Host "    Get-Content `"$LogPath`" -Tail 20"
Write-Host ("  Then run the ping check in net-helper/README.md 'A ping proves the helper is up'. It " +
    "does NOT prove the engine's account can connect, nor that the adapter name is right.")
Write-Host "  Uninstall: .\uninstall-net-helper.ps1"
