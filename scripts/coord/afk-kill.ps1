# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Read the AFK-autonomy kill switch (ADR 0211; docs/AUTONOMY-PLAN.md section 4.3).

.DESCRIPTION
    The switch is the repository Actions variable MEFOR_AFK_KILL on MEFORORG/MessageFoundry, read
    over REST. When it is ON, every decision class reverts to ask-mode.

    THE OWNER SETS IT, AND NOTHING ENFORCES THAT. Every seat acts as the one shared GitHub identity,
    which can write repository variables, so a session could turn it off. The tripwire hook records
    a `gh variable set|delete` or a non-GET `gh api` call on it (ADR 0211); that is a record, not a
    block, and a write by any other route leaves none.

    IT FAILS SAFE: ONLY A READ THAT RETURNS EXACTLY `off` (case and surrounding space ignored) IS
    OFF. A missing variable, any other value, a gh error, no gh at all, or a read that does not
    finish inside -TimeoutSeconds is ON. An unread switch must never read as permission.

    -Status prints `ON` or `OFF` as its only stdout line, and the reason on stderr. It exits 0
    either way, so a caller reads the word rather than an exit code.

    -Banner is the SessionStart hook's mode: when the switch is ON it prints a hook JSON object
    whose systemMessage the owner sees and whose additionalContext the session reads; when OFF it
    prints nothing. A fault anywhere in the script prints the ON banner, so only a real `off` read
    is silent, and it exits 0, so a broken read can never block a session from starting. A hook
    that cannot start at all (a cloud VM before cloud-setup.sh installs pwsh) prints nothing; that
    gap is outside this script.

    It reads no local coordination state and writes nothing, so it runs in a cloud session too,
    where the kill switch must hold as well.
#>
param(
    [switch]$Status,
    [switch]$Banner,
    [string]$Repo = 'MEFORORG/MessageFoundry',
    [string]$Name = 'MEFOR_AFK_KILL',
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-KillSwitch {
    # The read runs in its own runspace so a hung gh cannot outlast the hook's timeout: the
    # SessionStart hook would then be killed and print no banner, which fails OPEN.
    # The runspace gets the decision log's one gh wrapper by its text, because a script block
    # stays bound to the runspace that made it. A hung gh child is left to finish on its own.
    $ps = [powershell]::Create()
    try {
        $null = $ps.AddScript('param($Path, $Fn) Set-Item function:Invoke-DecisionGh ([scriptblock]::Create($Fn)); Invoke-DecisionGh @(''api'', $Path)').
            AddArgument("repos/$Repo/actions/variables/$Name").AddArgument(${function:Invoke-DecisionGh}.ToString())
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $null = $ps.BeginStop($null, $null)
            return [pscustomobject]@{ On = $true; Reason = "the read did not finish within $TimeoutSeconds s" }
        }
        $r = @($ps.EndInvoke($async)) | Select-Object -Last 1
    } catch {
        return [pscustomobject]@{ On = $true; Reason = "the read failed: $($_.Exception.Message)" }
    }
    if ($null -eq $r) { return [pscustomobject]@{ On = $true; Reason = 'the read returned nothing' } }
    if ($r.Code -ne 0) {
        $why = if ($r.Err) { $r.Err } else { "gh exited $($r.Code)" }
        return [pscustomobject]@{ On = $true; Reason = "unreadable ($why)" }
    }
    try {
        $value = [string]($r.Out | ConvertFrom-Json -ErrorAction Stop).value
    } catch {
        return [pscustomobject]@{ On = $true; Reason = 'the read returned no variable value' }
    }
    if ($value.Trim() -eq 'off') { return [pscustomobject]@{ On = $false; Reason = "$Name is 'off'" } }
    return [pscustomobject]@{ On = $true; Reason = "$Name is '$($value.Trim())', and only 'off' is OFF" }
}

if (@($Status, $Banner | Where-Object { $_ }).Count -ne 1) {
    [Console]::Error.WriteLine('afk-kill.ps1: give exactly one of -Status or -Banner.')
    exit 2
}

try {
    # Functions only; it reads no coordination state on load, so this still runs in a cloud session.
    . (Join-Path $PSScriptRoot '_decisionlog.ps1')
    $sw = Read-KillSwitch
} catch {
    # A fault is ON, never a silent OFF.
    $sw = [pscustomobject]@{ On = $true; Reason = "the read failed: $($_.Exception.Message)" }
}
if ($Status) {
    [Console]::Error.WriteLine("afk-kill.ps1: $($sw.Reason)")
    Write-Output $(if ($sw.On) { 'ON' } else { 'OFF' })
    exit 0
}

if (-not $sw.On) { exit 0 }
$text = "AFK KILL SWITCH IS ON. $Name on $Repo reads ON: $($sw.Reason). Every decision class is in " +
    'ask-mode: act on no Class B judgment without the owner, and bring every decision to the owner ' +
    'as you would have before the AFK-autonomy plan. Only the owner turns it off, by setting the ' +
    "variable to 'off'. ADR 0211; docs/AUTONOMY-PLAN.md section 4.3."
# Built by hand rather than with ConvertTo-Json, so nothing on this path can throw.
$json = ($text -replace '[\x00-\x1f]', ' ').Replace('\', '\\').Replace('"', '\"')
Write-Output ('{"systemMessage":"=== ' + $json + ' ===","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"' + $json + '"}}')
exit 0
