# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Stop and remove the mefor-net-helper Windows service (ADR 0056).

.DESCRIPTION
    Stops the helper and removes its NSSM registration.

    Removing the registration does NOT return the node to its pre-install state. The installer put
    a binary, an nssm.exe and a configuration file in a folder, and the helper may have added the
    VIP to an adapter. None of that is undone here by default, so this script reads the node before
    it removes the registration and prints an inventory of what it found still in place, with the
    command to clear each one.

    THE ADDRESS IS NOT RELEASED BY DEFAULT, and that is the decision this script turns on. On the
    node that currently holds the VIP, releasing it during an uninstall drops a live address -
    clients talking to it lose the connection at that moment, and nothing takes the address over,
    because the helper that would have re-bound it elsewhere is what you are removing. So a release
    has to be asked for: -ReleaseAddress does it, while the helper is still running and can still
    answer. Without it, the inventory names the address as still bound and gives the command.

    Run from an elevated (Administrator) PowerShell prompt.

.EXAMPLE
    .\uninstall-net-helper.ps1

.EXAMPLE
    .\uninstall-net-helper.ps1 -ReleaseAddress
#>
[CmdletBinding()]
param(
    # PATTERN-VALIDATED because the name is interpolated into a WQL filter below
    # (`Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"`). A single quote would end the
    # WQL literal and the query would error or match a different service, whose image path this
    # script then reports as the helper's.
    #
    # THE CHARACTER SET IS messagefoundry/service.py's `_SAFE_SERVICE_NAME`, SPACE INCLUDED, which is
    # install-net-helper.ps1's set exactly. It has to be: whatever the installer accepts as a name,
    # this has to accept back, or a helper installed as "MessageFoundry Prod" is unremovable through
    # this script - refused at parameter binding, before it can say why. This read "^[A-Za-z0-9._-]+$"
    # until BACKLOG #1523's third review round, and that was the defect.
    #
    # The two literals cannot be collapsed into one: a PowerShell attribute argument must be a
    # compile-time constant, so `[ValidatePattern($pattern)]` is a parse error. They are pinned to
    # the Python definition by tests/test_net_helper_install_scripts.py instead.
    [ValidatePattern('^[A-Za-z0-9 ._-]+$')][string]$ServiceName = "MessageFoundryNetHelper",
    # Where install-net-helper.ps1 put the files. Read for mefor-net-helper.conf, which is the only
    # record on the node of which address the helper was scoped to.
    [string]$InstallDir = "C:\Program Files\MessageFoundry\net-helper",
    # Opt-in: ask the helper to remove the VIP from this node's adapter before it is stopped. Default
    # OFF - see the description. Safe on a node that does not hold the address: the helper's release
    # succeeds and changes nothing when the address is already gone.
    [switch]$ReleaseAddress
)

$ErrorActionPreference = "Stop"

# Every native call below checks $LASTEXITCODE itself. Turning a non-zero native exit into a
# terminating error instead would kill this script part-way through, after the registration was gone
# and before the inventory printed. uninstall-service.ps1's own assignment is the source of record
# for the measurements; set explicitly rather than relied on.
$PSNativeCommandUseErrorActionPreference = $false

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Removing a Windows service requires an elevated (Administrator) PowerShell."
}

if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Host "Service '$ServiceName' is not installed - nothing to do."
    return
}

$InstallDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
$unreadable = @()

function Get-HelperConf {
    <#
      The helper's own scope, read from its own file in its own format.

      A SECOND READER OF THE .conf, and there is no way around that. HelperConfig.Load is the
      definition of the format; this reads the same lines the same way, taking everything after the
      first '=' as the value, because the address the helper was scoped to is recorded nowhere else
      on the node and this script has to work with the service already stopped. The helper's `ping`
      answer carries only ok and version, so there is no request that would return the scope instead.

      Returns $null when the file is missing or holds no address - the caller then reports that it
      could not read the scope, rather than reporting a clean node. `Interface` may still be empty
      even when an address is present (a truncated or hand-edited file), so the release path checks
      it before it binds it to a mandatory parameter.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $values = @{}
    foreach ($line in (Get-Content -Path $Path -Encoding UTF8)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $equals = $trimmed.IndexOf("=")
        if ($equals -le 0) { continue }
        # Everything after the first '=' is the value, which is how the helper reads it too.
        $values[$trimmed.Substring(0, $equals).Trim()] = $trimmed.Substring($equals + 1).Trim()
    }
    if (-not $values["address"]) { return $null }
    return [pscustomobject]@{
        Address   = $values["address"]
        Interface = $values["interface"]
        Mask      = $values["mask"]
    }
}

function Test-AddressBound {
    <#
      Whether $Address is on an adapter on this node right now.

      MEASURED, NOT INFERRED FROM THE SWITCH. The inventory has to say what the node IS, and a node
      that never won leadership never held the address - reporting "still bound" there would send an
      operator after a residue that is not there. $null means the question could not be answered,
      which the caller reports as unreadable rather than as a clean result.
    #>
    param([Parameter(Mandatory)][string]$Address)
    try {
        $found = Get-NetIPAddress -IPAddress $Address -AddressFamily IPv4 -ErrorAction SilentlyContinue
        return [bool]$found
    } catch {
        return $null
    }
}

function Invoke-HelperRelease {
    <#
      Ask the running helper to remove the VIP from this node's adapter.

      One connection, one line of UTF-8 JSON, one line back - net-helper/README.md states the wire
      contract. The caller is elevated, which is one of the two identities the helper's pipe admits,
      so this works whatever client_account names.

      IT MUST RUN BEFORE THE STOP. Once the service is stopped there is nobody on the pipe, and the
      only way left to remove the address is Remove-NetIPAddress by hand - which the inventory then
      prints.

      Returns $true only on an answer of {"ok":true}. A refusal is reported and NOT retried: the
      helper refuses a request naming an address other than its own, and re-sending the same one
      would get the same answer.
    #>
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][string]$Interface)
    $pipe = $null
    try {
        $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'mefor-net-helper',
            [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None,
            [Security.Principal.TokenImpersonationLevel]::Identification)
        $pipe.Connect(5000)
        $body = @{ op = "release"; address = $Address; interface = $Interface } |
            ConvertTo-Json -Compress
        $request = [Text.Encoding]::UTF8.GetBytes($body + "`n")
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()
        $answer = [IO.StreamReader]::new($pipe).ReadLine()
        if (-not $answer) {
            Write-Warning "The helper closed the pipe without answering the release request."
            return $false
        }
        $parsed = $answer | ConvertFrom-Json
        if ($parsed.ok) {
            Write-Host "  Address: released $Address from '$Interface'." -ForegroundColor Green
            return $true
        }
        Write-Warning ("The helper refused the release request: $($parsed.error). The address is " +
            "left as it is.")
        return $false
    } catch {
        Write-Warning ("Could not ask the helper to release $Address ($($_.Exception.Message)). " +
            "The address is left as it is.")
        return $false
    } finally {
        if ($pipe) { $pipe.Dispose() }
    }
}

# --- read the node BEFORE anything is removed ------------------------------------------------------

$registered = $null
try {
    $registered = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop).PathName
} catch {
    $unreadable += ("the registered image path of '$ServiceName' ($($_.Exception.Message)) - the " +
        "inventory below cannot name the nssm.exe the service was started with")
}

$confPath = Join-Path $InstallDir "mefor-net-helper.conf"
$conf = Get-HelperConf -Path $confPath
if (-not $conf) {
    $unreadable += ("the helper's scope: '$confPath' is missing or names no address, so nothing " +
        "checked whether a VIP is still bound to an adapter on this node")
}

$boundBefore = $null
if ($conf) { $boundBefore = Test-AddressBound -Address $conf.Address }
if ($conf -and $null -eq $boundBefore) {
    $unreadable += ("whether $($conf.Address) is bound to an adapter (Get-NetIPAddress failed) - " +
        "check with: Get-NetIPAddress -IPAddress $($conf.Address)")
}

$released = $false
if ($ReleaseAddress) {
    if (-not $conf) {
        Write-Warning ("-ReleaseAddress was passed but the helper's scope could not be read from " +
            "'$confPath', so there is no address to release.")
    } elseif ($boundBefore -eq $false) {
        Write-Host "  Address: $($conf.Address) is not bound on this node; nothing to release."
    } elseif (-not $conf.Interface) {
        # CHECKED BEFORE IT IS BOUND to a [Parameter(Mandatory)][string]. An empty value there is a
        # terminating binding error under $ErrorActionPreference = "Stop", and it would land here --
        # after the node was read and before anything was removed or reported. The whole
        # read-then-remove-then-inventory ordering exists to stop exactly that, so a .conf with an
        # address and no interface warns and falls through to the inventory instead.
        Write-Warning ("-ReleaseAddress was passed, but '$confPath' names no interface, so the " +
            "release request cannot be built. The inventory below has the manual command.")
    } else {
        $released = Invoke-HelperRelease -Address $conf.Address -Interface $conf.Interface
    }
}

# --- stop and remove --------------------------------------------------------------------------------

# THE SCM, NOT NSSM, AND NOT A THIRD COPY OF Stop-ServiceAndConfirm. That function takes an empty
# -NssmPath to mean "stop through the SCM" -- uninstall-service.ps1 calls it that way when nssm is
# absent -- so it WOULD work here, and an earlier version of this comment wrongly said it required
# nssm. The real reason is the copies: it is shared byte-identically between the two engine scripts
# with a drift test pinning the pair, and a third and fourth copy is a cost this script does not need
# to pay for a helper that drains nothing. What it must not cost is the PROPERTY, so this does the
# two things that function exists to do -- issue the stop, then confirm the status back from the SCM
# rather than assuming it (BACKLOG #1558).
Write-Host "Stopping '$ServiceName'..."
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
$stopped = $false
$deadline = (Get-Date).AddSeconds(30)
while ($true) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq "Stopped") { $stopped = $true; break }
    if ((Get-Date) -ge $deadline) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $stopped) {
    Write-Warning ("'$ServiceName' is still running 30 seconds after the stop. Windows marks a " +
        "service removed below for deletion, but the PROCESS keeps running until it exits or the " +
        "host reboots - and it keeps the named pipe open, so a reinstall refuses to start (exit 3, " +
        "'another process holds the pipe name'). Stop it by hand and confirm before reinstalling.")
}

Write-Host "Removing '$ServiceName'..."
# $LASTEXITCODE IS CLEARED FIRST. A failed LAUNCH never writes it, so a check written after one reads
# whatever the previous native command left - and this exit code is the ONLY evidence the removal
# happened, because nothing below re-reads it. uninstall-service.ps1's removal records the full
# reasoning and the per-host measurements.
$nssmForRemoval = Join-Path $InstallDir "nssm.exe"
$global:LASTEXITCODE = $null
if (Test-Path $nssmForRemoval) {
    & $nssmForRemoval remove $ServiceName confirm
    if ($null -eq $LASTEXITCODE) { throw "nssm remove did not run ('$nssmForRemoval' left no exit code)" }
    if ($LASTEXITCODE -ne 0) { throw "nssm remove failed (exit $LASTEXITCODE)" }
} else {
    & sc.exe delete $ServiceName | Out-Null
    if ($null -eq $LASTEXITCODE) { throw "sc.exe delete did not run (it left no exit code)" }
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed (exit $LASTEXITCODE)" }
}
Write-Host "Removed '$ServiceName'." -ForegroundColor Green

# --- what is still here -----------------------------------------------------------------------------

$lines = @("", "Still on this node after removing '$ServiceName':")

if (Test-Path $InstallDir) {
    $lines += "  Helper files     $InstallDir"
    $lines += "                   mefor-net-helper.exe, mefor-net-helper.conf, the nssm.exe the"
    $lines += "                   service was started with, and net-helper.log. Left in place: the"
    $lines += "                   log records which caller asked for which bind, and the .conf is"
    $lines += "                   the only record of the address this node was scoped to. Delete"
    $lines += "                   them once you are sure you are not reinstalling:"
    $lines += "                     Remove-Item -Recurse `"$InstallDir`""
} else {
    $lines += "  Helper files     $InstallDir is gone; nothing to remove."
}

# IndexOf and not -like: a path is not a wildcard pattern, and a '[' or ']' anywhere in $InstallDir
# would make -like compare a character class instead of the text, reporting an nssm.exe that is in
# the folder as living outside it.
if ($registered -and
    ($registered.IndexOf($InstallDir, [StringComparison]::OrdinalIgnoreCase) -lt 0)) {
    # The service was started from an nssm.exe outside the folder this script just reported on, so
    # saying "delete the folder" alone would leave a binary behind and nothing would say so.
    $lines += "  NSSM binary      The service was registered as: $registered"
    $lines += "                   That is outside $InstallDir, so removing the folder above leaves"
    $lines += "                   it. Delete it by hand if nothing else uses it."
}

if ($conf) {
    $boundAfter = Test-AddressBound -Address $conf.Address
    if ($released) {
        $lines += "  VIP address      RELEASED - $($conf.Address) was removed from '$($conf.Interface)'."
    }
    if ($boundAfter -eq $true) {
        $lines += "  VIP address      $($conf.Address) is STILL bound to an adapter on this node."
        $lines += "                   Nothing can move it now: the helper that would have released"
        $lines += "                   it is gone. Traffic for that address still arrives here, and"
        $lines += "                   another node binding it would be two nodes on one address."
        $lines += "                   Remove it when you are ready for the address to go dark:"
        $lines += "                     Remove-NetIPAddress -IPAddress $($conf.Address) -Confirm:`$false"
        $lines += "                   Next time, pass -ReleaseAddress to this script on the"
        $lines += "                   uninstall run - it cannot do it afterwards."
    } elseif ($boundAfter -eq $false -and -not $released) {
        $lines += "  VIP address      $($conf.Address) is not bound on this node; nothing to remove."
    }
}

$lines += "  Engine settings  [cluster.vip] in the engine's service settings is unchanged. The"
$lines += "                   engine does not call the helper in this build, so nothing there"
$lines += "                   breaks - but leave it switched on and the next node to install a"
$lines += "                   helper will be scoped to the same address."

if ($unreadable.Count -gt 0) {
    $lines += ""
    $lines += "  This list covers what this script could read on this node. It could NOT read:"
    foreach ($u in $unreadable) { $lines += "    - $u" }
    $lines += "  Check those by hand before you call the node clean."
}

$lines | ForEach-Object { Write-Host $_ }
