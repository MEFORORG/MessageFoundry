# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Record that a config root's account has no subscription, so the usage tracking stops reading it as
    headroom. Also clears that record, and reports it.

.DESCRIPTION
    THE ONE FAILURE THE USAGE READER COULD NOT SEE. `usage.ps1` has four honesty rules about not being
    confidently wrong, and every one of them is about a reading that is stale, thin, or from the wrong
    account. None of them catches a CANCELLED account, and that case fails in the worst direction: a
    dead account stops burning quota, so its last percentage freezes low and its publish directory goes
    quiet -- which is byte-identical to an IDLE account with a full pool. A seat comparing roots to find
    "the one with headroom" is steered straight at the account that has none, and the reader's own
    remedy for a quiet root ("start a NEW session pinned to this root") points it at a subscription that
    no longer exists.

    WHY A FILE ON THE BOX AND NOT A LIST IN THE REPOSITORY. This repository is public, and everything in
    `config-roots.ps1` is built on DISCOVERING config roots by name shape rather than listing them --
    deliberately, because a root is one person's credential set. A checked-in "account 3 is cancelled"
    would put an operator's private account state in an open repository and would be wrong for every
    other box that runs this. So the repository carries the MECHANISM and the operator's filesystem
    carries the FACT.

    WHERE IT LIVES. `<config root>\mefor-usage\unavailable.json` -- the publish directory, which is
    already the per-account partition key (`Get-UsageStateDir`). A marker cannot then describe a
    different account than the numbers beside it, and a reader pointed at an explicit `-StateDir` finds
    the marker belonging to the numbers it is about to read.

    IT DOES NOT TOUCH THE STATUSLINE, THE CREDENTIALS, OR THE SESSIONS. Marking an account changes what
    the usage tracking REPORTS and nothing else. Nothing here logs anybody out, unwires a root, or stops
    a session starting; the account is still launchable and this script does not pretend otherwise.

    CANCELLING NORMALLY HAS A DATE, so `-EffectiveFrom` is first-class rather than an afterthought. A
    subscription usually runs to the end of its billing period, and until that moment the pool is real
    and worth spending. A marker with a future date reports PENDING: `usage.ps1` keeps publishing and
    reading the numbers, and prints the end date beside them. Omit it and the marker is live now.

.EXAMPLE
    Mark an account dead now:
        pwsh -NoProfile -File scripts\coord\account-availability.ps1 -Mark `
            -ConfigDir "$HOME\.claude-account-3" -Reason "subscription cancelled"

    Mark one that runs to the end of the period:
        pwsh -NoProfile -File scripts\coord\account-availability.ps1 -Mark `
            -ConfigDir "$HOME\.claude-account-3" -Reason "subscription cancelled" -EffectiveFrom 2026-10-01

    Read every root on this box:
        pwsh -NoProfile -File scripts\coord\account-availability.ps1 -Status -AllRoots

    Undo it:
        pwsh -NoProfile -File scripts\coord\account-availability.ps1 -Clear -ConfigDir "$HOME\.claude-account-3"
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Mark', Mandatory)][switch]$Mark,
    [Parameter(ParameterSetName = 'Clear', Mandatory)][switch]$Clear,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    # The config root to act on. Defaults in the body to THIS session's root, for the same reason
    # usage.ps1 resolves its own there: a param-block default cannot call a dot-sourced function.
    [string]$ConfigDir,
    # Required to mark. A marker with no reason is a refusal nobody can audit six weeks later, and the
    # reader prints this string as the whole explanation for why an account is being skipped.
    [Parameter(ParameterSetName = 'Mark')][string]$Reason,
    # When the cancellation bites. Omit for "now".
    [Parameter(ParameterSetName = 'Mark')][string]$EffectiveFrom,
    [Parameter(ParameterSetName = 'Mark')][string]$By = 'owner',
    # Survey every launchable root rather than one. Status only.
    [Parameter(ParameterSetName = 'Status')][switch]$AllRoots,
    # A parameter for the test-safety reason config-roots.ps1 states.
    [string]$HomeDir = $(if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') })
)

$ErrorActionPreference = 'Stop'

# NOT GUARDED THE WAY THE STATUSLINE GUARDS IT. This is an operator command run from a terminal, not a
# decoration on a live session, so a missing library must be a loud refusal rather than a fallback --
# the alternative is writing a marker to a path derived by a second, unverified rule.
. (Join-Path $PSScriptRoot 'config-roots.ps1')

if (-not $ConfigDir) { $ConfigDir = (Resolve-CurrentConfigRoot -HomeDir $HomeDir).Path }
$ConfigDir = ConvertTo-NormalRootPath $ConfigDir

function Show-One([string]$Root) {
    $sd = Get-UsageStateDir $Root
    $a = Get-RootUnavailability -StateDir $sd
    $colour = switch ($a.state) {
        'UNAVAILABLE' { 'Magenta' }
        'MALFORMED' { 'Red' }
        'PENDING' { 'Yellow' }
        default { 'Green' }
    }
    Write-Host ("  {0,-46} {1}" -f $Root, $a.state) -ForegroundColor $colour
    if ($a.state -ne 'AVAILABLE') {
        if ($a.reason) { Write-Host ("  {0,-46} {1}" -f "", $a.reason) -ForegroundColor DarkGray }
        if ($a.effective_from) { Write-Host ("  {0,-46} effective from {1}" -f "", $a.effective_from) -ForegroundColor DarkGray }
        if ($a.marked_at) { Write-Host ("  {0,-46} marked {1}{2}" -f "", $a.marked_at, $(if ($a.marked_by) { " by $($a.marked_by)" })) -ForegroundColor DarkGray }
        Write-Host ("  {0,-46} {1}" -f "", $a.marker_path) -ForegroundColor DarkGray
    }
}

switch ($PSCmdlet.ParameterSetName) {

    'Mark' {
        if ([string]::IsNullOrWhiteSpace($Reason)) {
            Write-Host "REFUSED -- -Reason is required." -ForegroundColor Red
            Write-Host "  The reader prints it as the entire explanation for skipping an account, and a" -ForegroundColor DarkGray
            Write-Host "  marker nobody can account for six weeks later is how a root goes quiet for no" -ForegroundColor DarkGray
            Write-Host "  recorded cause. One short phrase is enough: 'subscription cancelled'." -ForegroundColor DarkGray
            exit 1
        }
        # THE INSTALLER'S RULE, RESTATED HERE BECAUSE THIS SCRIPT ALSO WRITES INTO A ROOT. New-Item
        # -Force builds every missing ancestor, so a typo'd -ConfigDir would have this command
        # MANUFACTURE a config root nothing can launch from and then declare it cancelled -- a wholly
        # fictional account, recorded as fact, with nothing anywhere reporting a problem.
        if (-not (Test-Path -LiteralPath $ConfigDir -PathType Container)) {
            Write-Host "REFUSED -- no such config root: $ConfigDir" -ForegroundColor Red
            Write-Host "  This script will not create one. Check the path." -ForegroundColor DarkGray
            exit 1
        }

        $eff = $null
        if ($EffectiveFrom) {
            $eff = ConvertTo-UtcDateTime $EffectiveFrom
            if ($null -eq $eff) {
                Write-Host "REFUSED -- -EffectiveFrom is not a date I can read: $EffectiveFrom" -ForegroundColor Red
                Write-Host "  Use an ISO-8601 date, for example 2026-10-01 or 2026-10-01T00:00:00Z." -ForegroundColor DarkGray
                # WHY THIS IS A REFUSAL AND NOT A FALLBACK TO 'NOW'. Silently treating an unparseable
                # date as immediate would mark a still-live account dead, which is the opposite of
                # what the operator asked for and is indistinguishable from it having worked.
                exit 1
            }
        }
        $now = (Get-Date).ToUniversalTime()
        $doc = [ordered]@{
            unavailable    = $true
            reason         = $Reason
            marked_at      = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
            marked_by      = $By
            effective_from = $(if ($eff) { $eff.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $now.ToString('yyyy-MM-ddTHH:mm:ssZ') })
        }

        $sd = Get-UsageStateDir $ConfigDir
        New-Item -ItemType Directory -Force -Path $sd | Out-Null
        $path = Join-Path $sd $script:UsageUnavailableMarker
        # Temp-then-rename, the same discipline the collector uses: a reader must never observe a
        # half-written marker, and a half-written marker reads as MALFORMED, which fails closed on a
        # live account.
        $tmp = "$path.$PID.tmp"
        [System.IO.File]::WriteAllText($tmp, ($doc | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
        [System.IO.File]::Move($tmp, $path, $true)

        $pending = $eff -and $eff -gt $now
        Write-Host ""
        if ($pending) {
            Write-Host "MARKED PENDING -- $ConfigDir" -ForegroundColor Yellow
            Write-Host "  The pool stays live and readable until $($doc.effective_from), then reports UNAVAILABLE."
        }
        else {
            Write-Host "MARKED UNAVAILABLE -- $ConfigDir" -ForegroundColor Magenta
            Write-Host "  usage.ps1 now reports UNAVAILABLE (exit 21) for this root and never a percentage."
        }
        Write-Host "  reason: $Reason"
        Write-Host "  marker: $path" -ForegroundColor DarkGray
        Write-Host ""
        # SAY WHAT WAS NOT DONE. The account is still launchable, still credentialled, still wired --
        # and an operator who reads "MARKED UNAVAILABLE" and assumes otherwise has been misled by this
        # script rather than by the situation.
        Write-Host "  This changes what the usage tracking REPORTS. It does not log the account out, unwire" -ForegroundColor DarkGray
        Write-Host "  its statusLine, or stop a session launching from it." -ForegroundColor DarkGray
        Write-Host ""
    }

    'Clear' {
        $sd = Get-UsageStateDir $ConfigDir
        $path = Join-Path $sd $script:UsageUnavailableMarker
        Write-Host ""
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force
            Write-Host "CLEARED -- $ConfigDir" -ForegroundColor Green
            Write-Host "  removed: $path" -ForegroundColor DarkGray
            Write-Host "  This root is read as a normal account again."
        }
        else {
            # NOT AN ERROR, AND SAYING SO MATTERS. The desired end state is "no marker here", and it
            # already holds. Exiting non-zero would make a correct no-op look like a failure to a
            # caller that branches on the code.
            Write-Host "NOTHING TO CLEAR -- $ConfigDir carries no availability marker." -ForegroundColor DarkGray
            Write-Host "  looked at: $path" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    default {
        Write-Host ""
        if ($AllRoots) {
            $roots = @(Get-LaunchableConfigRoots -HomeDir $HomeDir)
            if (-not $roots.Count) {
                Write-Host "  No launcher-shaped config roots under $HomeDir." -ForegroundColor Yellow
            }
            else {
                Write-Host "  Account availability, one line per config root under $HomeDir :"
                Write-Host ""
                foreach ($r in $roots) { Show-One $r }
                # ENUMERATED BY A DIFFERENT RULE, exactly as usage.ps1's survey is, so this pass cannot
                # confirm its own predicate. A root spelled outside the anchored name shape and carrying
                # a cancelled account would otherwise be absent from a list an operator reads as whole.
                foreach ($c in @(Get-ClaudeConfigCandidates -HomeDir $HomeDir)) {
                    if ($roots | Where-Object { Test-SameRoot $_ $c.FullName }) { continue }
                    Write-Host ("  {0,-46} not surveyed -- carries a settings.json but is not a launcher-shaped root name" -f $c.Name) -ForegroundColor Yellow
                }
            }
        }
        else {
            Show-One $ConfigDir
        }
        Write-Host ""
    }
}
