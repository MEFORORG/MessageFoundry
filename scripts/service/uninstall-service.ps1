# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Stop and remove the MessageFoundry Windows service (NSSM).

.DESCRIPTION
    Stops the service (Ctrl+C, letting the engine drain connections) and removes its NSSM
    registration. Log files and the message store under -DataDir are left in place.

    Run from an elevated (Administrator) PowerShell prompt.

.EXAMPLE
    .\uninstall-service.ps1
#>
[CmdletBinding()]
param(
    [string]$NssmPath,
    [string]$ServiceName = "MessageFoundry",
    [string]$DataDir = "C:\ProgramData\MessageFoundry"
)

$ErrorActionPreference = "Stop"

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

# Find nssm: explicit path, PATH, or the auto-provisioned cache. Fall back to sc.exe if absent.
if (-not $NssmPath) {
    $cmd = Get-Command nssm -ErrorAction SilentlyContinue
    $NssmPath = if ($cmd) { $cmd.Source } else { Join-Path $DataDir "bin\nssm.exe" }
}
$haveNssm = Test-Path $NssmPath

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

Write-Host "Removed '$ServiceName'. Logs and the message store were left in place." -ForegroundColor Green
