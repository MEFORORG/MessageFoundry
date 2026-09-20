# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Stop and remove the MessageFoundry Windows service (NSSM).

.DESCRIPTION
    Stops the service (Ctrl+C, letting the engine drain connections) and removes its NSSM
    registration.

    Removing the registration does NOT return the host to its pre-install state. The installer
    also grants a user right, writes access-control entries naming the run-as account, turns
    inheritance off on the data directory, caches an NSSM binary, and (with -SuppressCrashDumps)
    writes machine-wide Windows Error Reporting keys. None of that is undone here by default, so
    this script reads the host before it removes the registration and prints an inventory of what
    it found still in place, with the command to clear each one.

    Two of them can be taken back on request, because both need elevation an operator may not have
    later: -RemoveLogonRight drops the "Log on as a service" right, and -RemoveAccountAces drops
    the run-as account's entry from the data and config directories.

    Run from an elevated (Administrator) PowerShell prompt.

.EXAMPLE
    .\uninstall-service.ps1

.EXAMPLE
    .\uninstall-service.ps1 -RemoveLogonRight -RemoveAccountAces
#>
[CmdletBinding()]
param(
    [string]$NssmPath,
    [string]$ServiceName = "MessageFoundry",
    [string]$DataDir = "C:\ProgramData\MessageFoundry",
    # Opt-in: take the "Log on as a service" right back off the run-as account. Default OFF because
    # a SHARED account (a gMSA running several services, a dedicated user reused elsewhere) needs
    # the right for those too, and removing it stops them starting with error 1069. Safe for the
    # installer's default per-service virtual account, whose SID belongs to this service alone.
    [switch]$RemoveLogonRight,
    # Opt-in: remove the run-as account's access-control entry from the data directory and the
    # config directory. The account is gone once the registration is, so the entry is orphaned -
    # but removing it is still a permission change on directories that may outlive this service.
    [switch]$RemoveAccountAces
)

$ErrorActionPreference = "Stop"

# EVERY native call in this script checks $LASTEXITCODE itself and decides what the code means - some
# throw, the two removals below warn and carry on. $PSNativeCommandUseErrorActionPreference turns a
# non-zero native exit into a TERMINATING error instead, which would make those warn-and-carry-on
# branches unreachable: the script would die part-way through the cleanup, after the registration was
# already gone and before the inventory printed. Measured on PowerShell 7.6.6: it defaults to $false,
# so the exposure is an operator whose profile sets it, or a future default flip. Set explicitly
# rather than relied on. Windows PowerShell 5.1 has no such variable; assigning it there is inert.
$PSNativeCommandUseErrorActionPreference = $false

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Removing a Windows service requires an elevated (Administrator) PowerShell."
}

# Detect via Get-Service (no stderr/Stop pitfalls like `nssm status` on a missing service).
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Host "Service '$ServiceName' is not installed - nothing to do."
    return
}

# BEGIN Stop-ServiceAndConfirm (kept byte-identical with install-service.ps1; guarded by
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

function Get-ConfigDirFromAppParameters {
    <#
      Pull the --config value out of the command line NSSM stores as AppParameters.

      The uninstaller takes no -Config, so the config directory is only knowable by reading it back
      off the registration - and only BEFORE the registration is removed. Without it the notice can
      say an orphaned entry exists but not where, which is the half of an inventory an operator
      cannot act on.

      The installer quotes the path (it can contain spaces), so the quoted form is tried first; the
      bare form covers a registration written by hand. Returns an empty string when there is no
      --config, which is the honest answer - a guessed default would name a directory that may have
      nothing to do with this install.
    #>
    param([string]$AppParameters)
    if (-not $AppParameters) { return "" }
    $m = [regex]::Match($AppParameters, '--config\s+"([^"]*)"')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($AppParameters, '--config\s+(\S+)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ""
}

function Get-AccountResidueSpec {
    <#
      ONE RULE, TWO CALLERS: the notice that PRINTS a removal command and the switch that RUNS one.

      Written twice, they drift, and the script then tells an operator a command different from the
      one it ran itself - with nothing comparing the two. Returns both answers together:

        HasAccount  - whether the installer wrote named grants for this run-as account at all. It
                      writes them for everything except LocalSystem, which it covers with the
                      well-known SYSTEM SID instead. Decided on the SID, not the spelling: a
                      registration reading "NT AUTHORITY\SYSTEM" is the same account, and a name test
                      would let the removal strip *S-1-5-18 off the directory holding the logs and
                      the store. An unresolved SID counts as an account - over-reporting costs one
                      icacls read, under-reporting is the defect this file exists to fix.
        Principal   - how to spell that account for icacls. The SID form whenever one resolved,
                      because a deleted service's virtual account name no longer translates.
    #>
    param([string]$ServiceAccount, [string]$ServiceAccountSid)
    $has = [bool]$ServiceAccount -and
        ($ServiceAccount -ne "LocalSystem") -and
        ($ServiceAccountSid -ne "S-1-5-18")
    $principal = if ($ServiceAccountSid) { "*$ServiceAccountSid" } else { $ServiceAccount }
    return @{ HasAccount = $has; Principal = $principal }
}

function Get-UninstallResidueNotice {
    <#
      Build the inventory of what this uninstall leaves on the host (BACKLOG #1704).

      WHAT THIS REPLACES: one line reading "Logs and the message store were left in place." That is
      a COMPLETENESS CLAIM, and it was wrong in at least six ways - the installer also grants
      SeServiceLogonRight, writes an access-control entry for the run-as account on the data dir AND
      on the config dir, turns inheritance off on the data dir (and, with -LockConfigDir, on the
      config dir plus its owner), caches nssm.exe under the data dir, and with -SuppressCrashDumps
      writes machine-wide WER keys. An operator reading the old line would believe the host was back
      to where it started.

      EVERY LINE IS DRIVEN BY A FACT THE CALLER MEASURED, never by a default. A fact that could not
      be read produces no line and is named in -Unreadable instead, so the notice never asserts
      something nobody checked. The one bias is deliberate and stated: an account is treated as
      carrying access-control entries whenever the run-as account is not LocalSystem, because that
      is exactly when install-service.ps1 writes them. Over-reporting costs an operator one icacls
      read; under-reporting is the defect this function exists to fix.

      IT RETURNS LINES RATHER THAN PRINTING THEM so the content can be read back and tested. A
      function that writes to the host can only be checked by scanning the script's own text, and
      the text of an explanation is indistinguishable from the text of a message.
    #>
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$DataDir,
        # The run-as account read off the registration. "LocalSystem" (or empty) means the installer
        # wrote no named grant, so there is no orphaned entry and no user right to report.
        [string]$ServiceAccount,
        # Resolved BEFORE the removal. Once the service is gone a per-service virtual account no
        # longer translates, so the SID is the spelling of the account that still works in icacls.
        [string]$ServiceAccountSid,
        [string]$ConfigDir,
        # Measured from the config dir's own ACL, not assumed from a switch this script never saw.
        [switch]$ConfigInheritanceStripped,
        # Path of the cached NSSM binary, only when it is actually on disk.
        [string]$CachedNssm,
        # Image names found under the WER ExcludedApplications key.
        [string[]]$WerImages,
        # Image names with their own key under WER LocalDumps. A SEPARATE surface: Windows evaluates
        # it independently of the exclusion list, so clearing one leaves the other in force.
        [string[]]$WerLocalDumps,
        # What -RemoveLogonRight / -RemoveAccountAces already took back, so the notice reports the
        # host as it now IS rather than listing a residue this run just cleared.
        [switch]$LogonRightRemoved,
        [switch]$DataAceRemoved,
        [switch]$ConfigAceRemoved,
        # Named where a read failed, so a thin notice is never mistaken for a clean host.
        [string[]]$Unreadable
    )

    # ONE rule for both, shared with the removal switches below. NOT named $principal: the script
    # scope already holds the WindowsPrincipal used by the elevation check, and shadowing that inside
    # a function is a trap for whoever edits next.
    $spec = Get-AccountResidueSpec -ServiceAccount $ServiceAccount -ServiceAccountSid $ServiceAccountSid
    $hasAccount = $spec.HasAccount
    $acePrincipal = $spec.Principal

    $lines = @("", "Still on this host after removing '$ServiceName':")

    # SAYS WHAT THE INSTALLER DID, NOT WHAT THE ACL NOW IS. Nothing here read that ACL, and the
    # installer's lockdown is best-effort - it warns and returns when icacls fails, and it can report
    # principals it could not strip. Asserting "access is SYSTEM and Administrators only" would put
    # the reader off a check they may still need, which is the same false-premise defect this whole
    # inventory exists to remove.
    $lines += "  Data directory   $DataDir"
    $lines += "                   Holds the log files and the message store. The installer turns"
    $lines += "                   inheritance off here and locks the directory to SYSTEM and"
    $lines += "                   Administrators; this script does not put that back, because"
    $lines += "                   turning inheritance back on would hand the parent directory's"
    $lines += "                   users read access to logs that can carry patient data. Read the"
    $lines += "                   permissions yourself before you rely on them: icacls `"$DataDir`""

    if ($CachedNssm) {
        $lines += "  NSSM binary      $CachedNssm"
        $lines += "                   The copy the installer downloaded. Delete it by hand once you"
        $lines += "                   are sure you are not reinstalling."
    }

    if ($hasAccount) {
        if ($DataAceRemoved) {
            $lines += "  Data dir entry   REMOVED - '$ServiceAccount' no longer has an entry on $DataDir."
        } else {
            $lines += "  Data dir entry   '$ServiceAccount' still has read/write on $DataDir."
            $lines += "                   Remove it with:"
            $lines += "                     icacls `"$DataDir`" /remove:g `"$acePrincipal`""
        }

        if ($ConfigDir) {
            if ($ConfigAceRemoved) {
                $lines += "  Config dir entry REMOVED - '$ServiceAccount' no longer has an entry on $ConfigDir."
            } else {
                $lines += "  Config dir entry '$ServiceAccount' still has read on $ConfigDir."
                $lines += "                   Remove it with:"
                $lines += "                     icacls `"$ConfigDir`" /remove:g `"$acePrincipal`""
            }
        }

        if ($LogonRightRemoved) {
            $lines += "  Logon right      REMOVED - '$ServiceAccount' no longer holds 'Log on as a service'."
        } else {
            # NOT "re-run this script". The registration is gone by the time these lines print, and a
            # second run exits at the "is not installed - nothing to do" guard, so the switch has to
            # be passed on the uninstall run itself. Sending an operator back to a command that does
            # nothing is the same defect as the sentence this notice replaced.
            $lines += "  Logon right      '$ServiceAccount' still holds the 'Log on as a service' right"
            $lines += "                   (SeServiceLogonRight). Clear it in secpol.msc under Local"
            $lines += "                   Policies, User Rights Assignment. Next time, pass"
            $lines += "                   -RemoveLogonRight to this script on the uninstall run - it"
            $lines += "                   cannot clear it afterwards, because the account it names is"
            $lines += "                   only readable while the service is registered."
        }
    }

    if ($ConfigDir -and $ConfigInheritanceStripped) {
        # Inheritance is the only half that was MEASURED. Whether -LockConfigDir turned it off, and
        # who owns the directory, were not read - and a directory an operator hardened themselves
        # looks identical here. So this names the state and not its cause.
        $lines += "  Config dir ACL   $ConfigDir has inheritance turned off. install-service.ps1"
        $lines += "                   -LockConfigDir does that, and also sets the owner to"
        $lines += "                   Administrators; this script checked neither the cause nor the"
        $lines += "                   owner, and does not put either back, because nothing recorded"
        $lines += "                   what they were before. Read them yourself, and turn"
        $lines += "                   inheritance back on only if that was the state you started in:"
        $lines += "                     icacls `"$ConfigDir`" /inheritance:e"
    }

    $werAll = @(@($WerImages) + @($WerLocalDumps) | Where-Object { $_ } | Select-Object -Unique)
    if ($werAll.Count -gt 0) {
        $lines += "  Crash-dump keys  Windows Error Reporting keys for $($werAll -join ', ') under"
        $lines += "                   HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting."
        if ($WerImages) {
            $lines += "                     ExcludedApplications: $($WerImages -join ', ')"
        }
        if ($WerLocalDumps) {
            # Named separately because Windows evaluates the two independently: clearing the
            # exclusion list alone leaves the per-image dump overrides in force.
            $lines += "                     LocalDumps:           $($WerLocalDumps -join ', ')"
        }
        $lines += "                   install-service.ps1 -SuppressCrashDumps writes these, they"
        $lines += "                   apply to every process of those names on this host, and they"
        $lines += "                   are left on purpose: deleting them would switch crash dumps"
        $lines += "                   that can carry patient data back on. Remove them by hand if"
        $lines += "                   you want the host's original behaviour back."
    }

    if ($Unreadable -and $Unreadable.Count -gt 0) {
        $lines += ""
        $lines += "  This list covers what this script could read on this host. It could NOT read:"
        foreach ($u in $Unreadable) { $lines += "    - $u" }
        $lines += "  Check those by hand before you call the host clean."
    }

    return $lines
}

function Remove-ServiceLogonRight {
    <#
      Take SeServiceLogonRight back off $Sid, mirroring install-service.ps1's Set-ServiceLogonRight
      in reverse: export USER_RIGHTS, drop the SID from the row, re-import.

      IT TAKES A SID, NOT A NAME, and the caller resolves it BEFORE the registration is removed. A
      per-service virtual account is named by the service; with the service gone the name no longer
      translates, and a resolve attempted here would fail on exactly the default install.

      EXACT TOKEN MATCHING, for the reason the installer's grant states: a SID that is a string
      prefix of another (RID 110 against 1100) would make a substring test drop the wrong account's
      right.

      IT REFUSES TO EMPTY THE ROW. If this SID is the only holder, writing back an empty
      SeServiceLogonRight takes the right away from every account the row covers, which on a real
      host includes the ones other services log on with. That is a far larger change than the one
      asked for, so it stops and says so instead.

      Returns $true only when secedit reported the re-import succeeded.
    #>
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$Sid
    )
    $inf = Join-Path $env:TEMP "mefor-secedit-remove-$PID.inf"
    $sdb = Join-Path $env:TEMP "mefor-secedit-remove-$PID.sdb"
    try {
        # $LASTEXITCODE is session-wide and a failed LAUNCH never writes it, so it is cleared before
        # each call and a $null afterwards is treated as "secedit did not run" - the rule the nssm
        # calls in both scripts follow. NOTE: install-service.ps1's Set-ServiceLogonRight runs the
        # same two secedit calls WITHOUT this clear, so it can read the previous native command's
        # code. That is a pre-existing gap in the grant path, not fixed here; filing it is the
        # maintainer's, and this comment exists so the asymmetry is not read as parity.
        $global:LASTEXITCODE = $null
        & secedit /export /areas USER_RIGHTS /cfg $inf | Out-Null
        if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -ne 0 -or -not (Test-Path $inf)) {
            Write-Warning ("secedit export failed (exit $LASTEXITCODE), so the 'Log on as a " +
                "service' right for '$Account' was NOT removed. Clear it in secpol.msc under " +
                "Local Policies, User Rights Assignment.")
            return $false
        }
        $lines = Get-Content $inf
        $row = $lines | Where-Object { $_ -match '^\s*SeServiceLogonRight\s*=' } | Select-Object -First 1
        if (-not $row) {
            Write-Host "  Right  : no account holds SeServiceLogonRight; nothing to remove."
            return $false
        }
        $value = ($row -replace '^\s*SeServiceLogonRight\s*=', '')
        $held = @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $kept = @($held | Where-Object { $_ -ne ("*" + $Sid) -and $_ -ne $Sid })
        if ($kept.Count -eq $held.Count) {
            Write-Host "  Right  : '$Account' does not hold SeServiceLogonRight; nothing to remove."
            return $false
        }
        if ($kept.Count -eq 0) {
            Write-Warning ("'$Account' is the ONLY account holding 'Log on as a service' on this " +
                "host, so removing it would take the right from every service that logs on with " +
                "it. Left in place - clear it by hand in secpol.msc if that is really what you want.")
            return $false
        }
        # REBUILT LINE BY LINE, NOT WITH -replace. The replacement operand of -replace is .NET
        # substitution syntax, where '$' is a metacharacter: a holder token containing one - secedit
        # can export a gMSA or computer account by NAME, and those end in '$' - would be re-read as
        # $&, $+ or $$ and silently mangle a machine-wide user-right row on its way into
        # `secedit /configure`. A foreach carries the text through untouched.
        $new = foreach ($line in $lines) {
            if ($line -match '^\s*SeServiceLogonRight\s*=') {
                "SeServiceLogonRight = " + ($kept -join ',')
            } else { $line }
        }
        Set-Content -Path $inf -Value $new -Encoding Unicode
        $global:LASTEXITCODE = $null
        & secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS | Out-Null
        if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -ne 0) {
            Write-Warning ("secedit configure failed (exit $LASTEXITCODE), so the 'Log on as a " +
                "service' right for '$Account' was NOT removed. Clear it in secpol.msc under " +
                "Local Policies, User Rights Assignment.")
            return $false
        }
        Write-Host "  Right  : removed SeServiceLogonRight from '$Account'." -ForegroundColor Green
        return $true
    } finally {
        Remove-Item $inf, $sdb -Force -ErrorAction SilentlyContinue
    }
}

function Remove-AccountAce {
    <#
      Drop one principal's access-control entry from $Path - the reverse of the installer's grant.

      $Principal is the SID spelling ("*S-1-...") whenever the caller resolved one, because a
      deleted service's account name no longer translates and icacls would refuse it.

      /remove:g removes ALLOW entries only, so this can never widen access: the worst outcome is
      that nothing matched, which icacls reports as success. Returns $true only on a real exit 0.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][string]$What
    )
    if (-not (Test-Path $Path)) {
        Write-Host "  ACEs   : $What '$Path' is gone; nothing to remove."
        return $false
    }
    $global:LASTEXITCODE = $null
    & icacls $Path /remove:g $Principal | Out-Null
    if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -ne 0) {
        Write-Warning ("Could not remove '$Principal' from the $What '$Path' (icacls exit " +
            "$LASTEXITCODE). Remove it by hand: icacls `"$Path`" /remove:g `"$Principal`"")
        return $false
    }
    Write-Host "  ACEs   : removed '$Principal' from the $What '$Path'." -ForegroundColor Green
    return $true
}

# --- read the host BEFORE the registration goes (BACKLOG #1704) -------------------------------------
# EVERY fact here stops being readable the moment the service is removed. The run-as account and the
# registered command line live in the service's own registry key, which `nssm remove` deletes; and a
# per-service virtual account (NT SERVICE\<ServiceName>, the installer's default) stops translating to
# a SID once the service it is named for is gone. Reading afterwards would produce an empty inventory
# that looks exactly like a clean host, which is the failure this whole change is about.
#
# IT RUNS ABOVE THE NSSM RESOLUTION because -DataDir is corrected from the registration below, and
# Resolve-Nssm's fallback joins "bin" onto whatever -DataDir holds at that moment.
#
# Nothing here throws. A read that fails is recorded in $unreadable and named in the notice, so a
# thinner list is never mistaken for a shorter one.
$unreadable = @()
$objectName = ""
$appParameters = ""
$appExe = ""
$appStdout = ""
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
try {
    $objectName = [string](Get-ItemProperty -Path $svcKey -Name ObjectName -ErrorAction Stop).ObjectName
} catch {
    $unreadable += ("the run-as account of '$ServiceName' ($($_.Exception.Message)) - check " +
        "'$DataDir' and your config directory for an orphaned entry, and secpol.msc for a stray " +
        "'Log on as a service' grant")
}
try {
    $params = Get-ItemProperty -Path (Join-Path $svcKey "Parameters") -ErrorAction Stop
    $appParameters = [string]$params.AppParameters
    $appExe = [string]$params.Application
    $appStdout = [string]$params.AppStdout
} catch {
    $unreadable += ("the registered command line of '$ServiceName' ($($_.Exception.Message)) - so " +
        "the config directory and the data directory below could not be checked against it")
}
$configDir = Get-ConfigDirFromAppParameters -AppParameters $appParameters
# A read that SUCCEEDS and yields nothing is not a clean result. Without this the config-dir lines are
# simply dropped and the notice looks complete, which is the defect this whole change is about.
if ($appParameters -and -not $configDir) {
    $unreadable += ("the config directory of '$ServiceName' - its registered command line carries no " +
        "--config, so the directory holding an entry for the run-as account cannot be named here")
}

# -DataDir IS A PARAMETER WITH A DEFAULT, AND A DEFAULT IS A GUESS. An install that used
# `-DataDir D:\mefor` leaves everything there, and an uninstall run without the same argument would
# name C:\ProgramData\MessageFoundry throughout - the wrong directory in the one report written to
# stop exactly that. The installer registers AppStdout as <DataDir>\logs\service.out.log, so the real
# directory is two parents up. An explicit -DataDir always wins: the operator who passed it knows.
if (-not $PSBoundParameters.ContainsKey('DataDir')) {
    if ($appStdout) {
        $derivedDataDir = Split-Path -Parent (Split-Path -Parent $appStdout)
        if ($derivedDataDir) { $DataDir = $derivedDataDir }
    } else {
        $unreadable += ("the data directory of '$ServiceName' - the inventory below names the " +
            "default '$DataDir', which is the wrong directory if the install used -DataDir")
    }
}

# Find nssm: explicit path, PATH, or the auto-provisioned cache. Fall back to sc.exe if absent.
$cachedNssm = Join-Path $DataDir "bin\nssm.exe"
if (-not $NssmPath) {
    $cmd = Get-Command nssm -ErrorAction SilentlyContinue
    $NssmPath = if ($cmd) { $cmd.Source } else { $cachedNssm }
}
$haveNssm = Test-Path $NssmPath
if (-not (Test-Path $cachedNssm)) { $cachedNssm = "" }

# WHICH ACCOUNTS CARRY A RESIDUE, DECIDED BY SID RATHER THAN BY SPELLING. The installer writes named
# grants for any run-as account except LocalSystem, which it covers with the well-known SYSTEM SID
# instead. "LocalSystem" is only ONE spelling of that account though - a registration written by hand
# or by another tool can read "NT AUTHORITY\SYSTEM" - and a name test would then let
# -RemoveAccountAces issue `/remove:g *S-1-5-18`, stripping the SYSTEM entry that Set-SecureDataDirAcl
# writes on EVERY install off the directory holding the logs and the store.
#
# A SID THAT DOES NOT RESOLVE IS TREATED AS AN ACCOUNT, deliberately. Over-reporting costs an operator
# one icacls read; under-reporting is the defect this function exists to fix.
$accountSid = ""
$hasAccount = $false
if ($objectName -and $objectName -ne "LocalSystem") {
    try {
        $accountSid = ([Security.Principal.NTAccount]$objectName).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        $unreadable += ("the SID of '$objectName' ($($_.Exception.Message)) - the commands below " +
            "name the account instead, and icacls may refuse that name once the service is gone")
    }
}
# ONE rule, the same call Get-UninstallResidueNotice makes. Both the command the notice PRINTS and the
# command -RemoveAccountAces RUNS come from this, so they cannot disagree.
$accountSpec = Get-AccountResidueSpec -ServiceAccount $objectName -ServiceAccountSid $accountSid
$hasAccount = $accountSpec.HasAccount
$acePrincipal = $accountSpec.Principal

# Measured from the directory's own ACL, not inferred from a -LockConfigDir switch this script never
# saw. AreAccessRulesProtected is true exactly when inheritance has been turned off.
$configProtected = $false
if ($configDir) {
    try {
        $configProtected = [bool](Get-Acl -Path $configDir -ErrorAction Stop).AreAccessRulesProtected
    } catch {
        $unreadable += ("the permissions of the config directory '$configDir' " +
            "($($_.Exception.Message))")
    }
}

# WER suppression is by IMAGE NAME and covers BOTH images the installer names: the launcher, and the
# interpreter a pip console script starts as a child - which is the process that actually holds the
# PHI heap. Only images actually present in the registry are reported, so a host that never ran
# -SuppressCrashDumps gets no line.
#
# THE CANDIDATE NAMES ARE NOT PROBED ON DISK. An earlier version took python.exe only when it still
# existed beside the launcher, which made the inventory depend on whether the venv had already been
# deleted - and an operator decommissioning a box deletes it first. The registry is the thing that
# survives, so the registry is what is read.
#
# BOTH SURFACES, because Set-CrashDumpSuppression writes two and they are evaluated independently: an
# operator who clears ExcludedApplications alone still has per-image LocalDumps overrides in place.
$werRoot = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
$werImages = @()
$werLocalDumps = @()
if ($appExe) {
    try {
        $imageNames = @([IO.Path]::GetFileName($appExe), "python.exe") | Select-Object -Unique
        $excludedKey = Join-Path $werRoot "ExcludedApplications"
        if (Test-Path $excludedKey) {
            $excludedProps = Get-ItemProperty -Path $excludedKey -ErrorAction Stop
            foreach ($image in $imageNames) {
                if ($null -ne $excludedProps.PSObject.Properties[$image]) { $werImages += $image }
            }
        }
        foreach ($image in $imageNames) {
            if (Test-Path (Join-Path $werRoot "LocalDumps\$image")) { $werLocalDumps += $image }
        }
    } catch {
        $unreadable += ("the Windows Error Reporting keys ($($_.Exception.Message)) - check them by " +
            "hand under '$werRoot' if you installed with -SuppressCrashDumps")
    }
} else {
    $unreadable += ("the Windows Error Reporting keys - the registered image path could not be read, " +
        "so nothing checked whether -SuppressCrashDumps left machine-wide keys under '$werRoot'")
}

Write-Host "Stopping '$ServiceName'..."
# BOTH stop paths - nssm and the SCM fallback - ran without checking anything and without reading the
# status back, so the removal below proceeded over a service that might still be running (BACKLOG
# #1558). Stop-ServiceAndConfirm covers both: it takes an empty -NssmPath as "use the SCM".
$stopped = Stop-ServiceAndConfirm -ServiceName $ServiceName -NssmPath $(if ($haveNssm) { $NssmPath } else { "" })
if (-not $stopped) {
    Write-Warning ("Removing the registration for '$ServiceName' while it is still running. Windows " +
        "marks the service for deletion but the PROCESS keeps running until it exits or the host " +
        "reboots, and it holds the message store and the log files open - so a reinstall can fail to " +
        "bind, and the store can be written by a service that no longer has a registration. Stop it " +
        "by hand (Stop-Service -Force, or taskkill) and confirm it is gone before reinstalling.")
}

Write-Host "Removing '$ServiceName'..."
# $LASTEXITCODE IS CLEARED FIRST HERE TOO, and this is the site where a stale read costs most. A
# failed LAUNCH never writes the variable, so it keeps the 0 the stop above just left behind, and the
# check then passes and the script prints "Removed" over a registration that is still there. Unlike
# the lockdown, where Get-BroadAclResidue reads the result back, nothing here re-reads: this exit
# code is the ONLY evidence the removal happened, so it has to be this call's own.
$global:LASTEXITCODE = $null
if ($haveNssm) {
    & $NssmPath remove $ServiceName confirm
    if ($null -eq $LASTEXITCODE) { throw "nssm remove did not run ('$NssmPath' left no exit code)" }
    if ($LASTEXITCODE -ne 0) { throw "nssm remove failed (exit $LASTEXITCODE)" }
} else {
    & sc.exe delete $ServiceName | Out-Null
    if ($null -eq $LASTEXITCODE) { throw "sc.exe delete did not run (it left no exit code)" }
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed (exit $LASTEXITCODE)" }
}

Write-Host "Removed '$ServiceName'." -ForegroundColor Green

# --- the two residues an operator can hand back to this script (BACKLOG #1704) ----------------------
# Both run AFTER the registration is gone, against facts read BEFORE it: the service must not lose the
# right or the entry while it is still registered to use them.
#
# NOTHING ELSE IS TAKEN BACK, AND THAT IS A DECISION RATHER THAN AN OMISSION. Turning inheritance back
# on would hand the parent directory's principals read access to logs and a message store that can
# carry patient data, and nothing recorded what the permissions were before the installer changed
# them - so a "restore" would be inventing a state, not returning to one. The notice names those and
# gives the command, which leaves the choice with the operator who knows the host.
$logonRightRemoved = $false
$dataAceRemoved = $false
$configAceRemoved = $false

if ($RemoveLogonRight) {
    if (-not $hasAccount) {
        Write-Host "  Right  : the service ran as LocalSystem, which was never granted the right."
    } elseif (-not $accountSid) {
        Write-Warning ("Cannot remove the 'Log on as a service' right: '$objectName' did not " +
            "resolve to a SID before the registration was removed. Clear it in secpol.msc under " +
            "Local Policies, User Rights Assignment.")
    } else {
        if ($objectName -ne "NT SERVICE\$ServiceName") {
            Write-Warning ("'$objectName' is not this service's own virtual account, so it may log " +
                "other services on as well. Removing the right stops those starting (error 1069). " +
                "Check what else uses it before you rely on this.")
        }
        $logonRightRemoved = Remove-ServiceLogonRight -Account $objectName -Sid $accountSid
    }
}

if ($RemoveAccountAces) {
    if (-not $hasAccount) {
        Write-Host "  ACEs   : the service ran as LocalSystem, so no named entry was ever written."
    } else {
        # $acePrincipal is the value the notice PRINTS, derived once above. Recomputing it here is
        # how a script comes to tell an operator a command different from the one it just ran.
        $dataAceRemoved = Remove-AccountAce -Path $DataDir -Principal $acePrincipal -What "data directory"
        if ($configDir) {
            $configAceRemoved = Remove-AccountAce -Path $configDir -Principal $acePrincipal -What "config directory"
        } else {
            Write-Warning ("The config directory could not be read off the registration, so its " +
                "entry for '$objectName' was left. Remove it with: icacls `"<config dir>`" " +
                "/remove:g `"$acePrincipal`"")
        }
    }
}

Get-UninstallResidueNotice `
    -ServiceName $ServiceName `
    -DataDir $DataDir `
    -ServiceAccount $objectName `
    -ServiceAccountSid $accountSid `
    -ConfigDir $configDir `
    -ConfigInheritanceStripped:$configProtected `
    -CachedNssm $cachedNssm `
    -WerImages $werImages `
    -WerLocalDumps $werLocalDumps `
    -LogonRightRemoved:$logonRightRemoved `
    -DataAceRemoved:$dataAceRemoved `
    -ConfigAceRemoved:$configAceRemoved `
    -Unreadable $unreadable |
    ForEach-Object { Write-Host $_ }
