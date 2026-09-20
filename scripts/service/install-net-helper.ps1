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
    its SHA-256 in $NssmUrl / $NssmSha256, and tests/test_service_install_manifest.py guards that
    pin. A second pin here would be a second thing to keep current, and it would go stale quietly.
    So pass -NssmPath, or have nssm on PATH; net-helper/README.md "Prepare the files once" is the
    download-and-check procedure, and it names that same pin.

    Run from an elevated (Administrator) PowerShell prompt, on each cluster node, AFTER the engine's
    own service exists (its account is what the helper's pipe ACL is built from).

.EXAMPLE
    .\install-net-helper.ps1 -HelperSource ..\..\net-helper\out -NssmPath C:\tools\nssm.exe

.EXAMPLE
    .\install-net-helper.ps1 -HelperSource D:\build\net-helper -ServiceConfig C:\ProgramData\MessageFoundry\messagefoundry.toml
#>
[CmdletBinding()]
param(
    # The `dotnet publish` output folder holding mefor-net-helper.exe. See net-helper/README.md
    # "Build it" - `dotnet build` output is NOT installable, it needs the .NET runtime.
    [Parameter(Mandatory)][string]$HelperSource,
    # Administrator-only by default, and the README explains why it is not under ProgramData: the
    # engine's account has modify rights there, so it could replace the binary that runs as SYSTEM.
    [string]$InstallDir = "C:\Program Files\MessageFoundry\net-helper",
    # BOTH SERVICE NAMES ARE PATTERN-VALIDATED because both are interpolated into a WQL filter
    # (`Get-CimInstance Win32_Service -Filter "Name='$x'"`). A single quote in the value would end the
    # WQL literal, so the query either errors or matches a DIFFERENT service - and this script reads
    # the engine's run-as account out of that result and writes it into the helper's pipe ACL.
    # messagefoundry/service.py's `_SAFE_SERVICE_NAME` gates the same class; this is the same idea in
    # the same character set, minus the space Windows allows but neither script needs.
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$ServiceName = "MessageFoundryNetHelper",
    # The engine's service, read for its run-as account (the pipe's only non-administrator caller).
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$EngineServiceName = "MessageFoundry",
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
    # Install even though a principal other than SYSTEM, Administrators, TrustedInstaller or CREATOR
    # OWNER can write to -InstallDir. Whoever can write there can replace a binary that runs as
    # SYSTEM, so this is refused by default.
    [switch]$AllowBroadAcl
)

$ErrorActionPreference = "Stop"

# Every native call below checks $LASTEXITCODE itself and decides what the code means. Turning a
# non-zero native exit into a terminating error instead would cut those decisions out, part-way
# through an install. uninstall-service.ps1's own assignment of this variable is the source of record
# for the measurements behind it; set explicitly rather than relied on.
$PSNativeCommandUseErrorActionPreference = $false

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
if (-not (Test-Path $AppExe)) {
    throw ("Engine executable not found at: $AppExe`nPass -AppExe. It is run once, read-only, to " +
        "resolve [cluster.vip]; it does not have to be the copy the service runs.")
}

function Resolve-HelperNssm {
    <#
      The nssm.exe this service will be registered with, COPIED into $InstallDir.

      The copy is the point, not a convenience. The registration names an nssm.exe by path, and that
      binary starts a process running as SYSTEM - so it has to live somewhere only administrators can
      write, beside the helper. net-helper/README.md is explicit that the engine's cached copy under
      ProgramData is NOT such a place: the engine's own account has modify rights there.

      Nothing is downloaded and nothing is hash-checked here; see this script's header.
    #>
    param([string]$Provided)
    if ($Provided) {
        $resolved = Resolve-AbsolutePath $Provided
        if (-not (Test-Path $resolved)) { throw "NSSM not found at: $resolved" }
        return $resolved
    }
    $onPath = Get-Command nssm -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw ("nssm.exe not found. Pass -NssmPath, or put nssm on PATH. net-helper/README.md " +
        "'Prepare the files once' has the download and the hash check; the pinned archive and its " +
        "SHA-256 are `$NssmUrl and `$NssmSha256 in install-service.ps1, which is the only place " +
        "this repository states them.")
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
      later runs as SYSTEM. Same shape, different question; naming them apart keeps a reader from
      assuming one answers the other's.
    #>
    param([Parameter(Mandatory)][string]$Path)
    # The same four principals messagefoundry/config/wiring.py's _WIN_TRUSTED_SIDS trusts for the
    # same reason, plus OWNER RIGHTS: that module's comment records that S-1-3-0 and S-1-3-4 both
    # appear on ordinary inherited ACLs and must not be refused. Omitting S-1-3-4 would be a false
    # REFUSAL whose only escape is -AllowBroadAcl, which downgrades the whole check to a warning --
    # so one false positive would disable the gate.
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
    try { $acl = Get-Acl -Path $Path -ErrorAction Stop } catch {
        # THROWN, NOT WARNED. install-service.ps1's sibling warns and returns empty, because there it
        # reports on a lockdown that already happened. Here the empty result IS the verdict that lets
        # a SYSTEM-launched binary be written, and "could not read the permissions" must not render
        # as "the permissions are fine".
        throw ("Could not read the permissions of '$Path' ($($_.Exception.Message)), so nothing " +
            "established that only administrators can write there. Fix the path or pass " +
            "-AllowBroadAcl to install without the check.")
    }

    # THE OWNER ARM, and the DACL alone is not the question. An owner holds WRITE_DAC implicitly, so
    # a low-privilege owner can rewrite the DACL whatever it says today and then replace a binary
    # this install is about to have the SCM start as SYSTEM. messagefoundry/config/wiring.py's
    # _evaluate_config_dacl carries the same arm for the same reason (SEC-003, CWE-732); a check
    # without it reports a clean folder for exactly that case.
    $ownerSid = $null
    try {
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    } catch { $ownerSid = "$($acl.Owner)" }
    if ($allowed -notcontains $ownerSid) {
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

$broad = Get-BroadWriteHolders -Path $InstallDir
if ($broad.Count -gt 0) {
    $message = ("'$InstallDir' can be written by: $($broad -join '; '). Whoever can write there can " +
        "replace mefor-net-helper.exe, its .conf or nssm.exe - each of which then runs as SYSTEM. " +
        "Use a folder under Program Files, or fix the permissions, and re-run. Pass -AllowBroadAcl " +
        "to install anyway.")
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
if ($NssmPath -ne $TargetNssm) { Copy-Item $NssmPath $TargetNssm -Force }

# EVERY nssm CALL BELOW RUNS THE INSTALLED COPY, and this line is what makes that true. NSSM writes
# the path of the nssm.exe that ran `install` into the service's own ImagePath, so registering with
# the source binary would point the SCM at a SYSTEM-launched executable outside the folder whose
# permissions were just checked -- and the read-back guard further down would then refuse the
# install it had already performed. net-helper/README.md registers with "$dir\nssm.exe" for the same
# reason and makes confirming it its own numbered step.
$NssmPath = $TargetNssm

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

# READ THE REGISTRATION BACK. The exit code above says nssm accepted the setting, not that the SCM
# will start the copy of nssm.exe in this folder - which is the property the folder's permissions are
# protecting. net-helper/README.md makes this its own numbered step for that reason.
$registered = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue).PathName
if (-not $registered) {
    throw "'$ServiceName' has no registered image path after the install; nothing to start."
}
# IndexOf and not -like: a path is not a wildcard pattern, and '[' or ']' anywhere in $TargetNssm
# would make -like compare a character class instead of the text.
if ($registered.IndexOf($TargetNssm, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw ("'$ServiceName' would start '$registered', not '$TargetNssm'. Remove the service and " +
        "re-run: a registration pointing at another copy of nssm.exe is a binary outside the folder " +
        "whose permissions this install just checked.")
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
Write-Host "  NSSM     : $TargetNssm"
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
