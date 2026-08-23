# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Is anything still working in this seat box? Answered from signals with DIFFERENT WRITERS, so a
    caller can tell "quiet" from "unobserved". Dot-sourced library: defines functions, does nothing.

.DESCRIPTION
    THE CORRECTION THIS FILE EXISTS FOR. Readers across this repo treat `seats/.writer-alive/<box>.txt`
    and the seat record's `asOf` as two independent staleness signals. THEY ARE ONE SIGNAL READ TWICE.
    Both are written by `seat.ps1` inside a single `-Record` invocation -- the heartbeat at its rule 3
    touch and `asOf` in the record body. Measured 2026-08-22 across every box on disk: the two agree TO
    THE SECOND in 42 of 42. A reader that counts them as two believes it has corroboration and has a
    copy.

    That matters because of the failure `seat.ps1`'s own rule 3 names: hooks are disabled silently by
    disableAllHooks, by org policy and by workspace trust, and all three produce exactly the observable
    of a quiet, healthy fleet. When the writer is not running, BOTH of those signals go stale together,
    and a sweep reading them concludes the seat is dead while somebody is still typing in it.

    SO THIS FILE ADDS A SIGNAL seat.ps1 DOES NOT WRITE: the mtime of the newest transcript under
    `<config-root>/projects/<slug>/`, which Claude Code itself writes on every turn. It survives the
    hooks-disabled case by construction. It is not hypothetical -- measured the same day,
    `messagefoundry-096b5d29` had a transcript 31.50h old against a `.writer-alive` 0.14h old, the two
    disagreeing by 31.4 hours.

    THE RULES, STATED HERE ONCE so no caller can restate them differently:

    1. A FRESH TRANSCRIPT VETOES, whatever `.writer-alive` says. Absence of a heartbeat is not
       evidence of absence when the thing that writes the heartbeat can be switched off.
    2. `WriterAliveAgeH` AND SEAT `asOf` ARE THE SAME CLOCK. This function returns only the former,
       on purpose, so the count in `Signals` cannot be inflated by reading one clock twice.
    3. FEWER THAN TWO EVALUABLE SIGNALS MEANS REFUSE. `Signals` reports the count and `Evaluable` is
       false below two. An unevaluated fence is not a passed fence -- the rule
       session-registry.ps1:241 states for its own UNREADABLE ranking, applied here.
    4. NEVER RE-DERIVE THE VETO STATE LIST. `Test-OccupancyVeto` in occupancy.ps1 owns it. A second
       copy of a safety list is the drift CLAUDE.md section 11 forbids, and the copy nobody tests is
       the one that breaks.

    WHAT THIS FILE DOES NOT OWN. The box key is mail-key.ps1's. The liveness fence is
    session-registry.ps1's. The veto state list is occupancy.ps1's. All three are dot-sourced.
#>

# NO Set-StrictMode AND NO $ErrorActionPreference HERE, deliberately. Both are SCOPE settings, and a
# dot-sourced file sets them in its CALLER. Neither session-registry.ps1, occupancy.ps1 nor
# mail-key.ps1 sets either, and a library that quietly re-strictens every script that loads it is not
# the "defines functions, does nothing" this file's synopsis promises. Caught by breaking a caller.
. "$PSScriptRoot\session-registry.ps1"
. "$PSScriptRoot\occupancy.ps1"

function ConvertTo-TranscriptSlug {
    <#
    .SYNOPSIS
        A worktree path as Claude Code names its transcript directory under <config-root>/projects/.

    .DESCRIPTION
        Every ':', '\', '/' and '.' becomes '-'. Nothing else changes, and the result is NOT reversible
        -- four characters collapse onto one, so two paths could in principle collide. They do not here:
        verified 2026-08-22 against all 72 worktrees sharing this .git, the 72 slugs were distinct.

        Worked, because the doubled separators look like a bug and are not:
            D:\proj\App\.claude\worktrees\demo-1234
            D--proj-App--claude-worktrees-demo-1234
        `D:` and `\` both map, giving `D--`; `\.claude` is a separator followed by a dot, giving
        `--claude`.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if (-not $Path) { return "" }
    return ($Path -replace '[:\\/.]', '-')
}

function Get-TranscriptAgeHours {
    <#
    .SYNOPSIS
        Hours since the newest transcript for this worktree, or $null if no root held one.

    .DESCRIPTION
        $null means UNEVALUABLE, never "old". The two are opposite instructions to a caller deciding
        whether to disturb something, and collapsing them is how a sweep reads an unobserved seat as a
        dead one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$WorktreePath,
        [string[]]$ConfigRoot,
        [datetime]$Now = [datetime]::UtcNow
    )
    $slug = ConvertTo-TranscriptSlug -Path $WorktreePath
    if (-not $slug) { return $null }
    $newest = $null
    # NOT Get-ClaudeConfigRoots: that one filters to roots holding a sessions/ directory, which is the
    # right question for the liveness fence and the wrong one here. A root can hold transcripts and no
    # session registry, and dropping it would turn an evaluable signal into a missing one.
    $roots = if ($ConfigRoot) { @($ConfigRoot | Where-Object { Test-Path -LiteralPath $_ }) }
             else {
                 @(Get-ChildItem -Path $env:USERPROFILE -Directory -Filter '.claude*' -Force -EA SilentlyContinue |
                       ForEach-Object { $_.FullName })
             }
    foreach ($r in $roots) {
        $dir = Join-Path (Join-Path $r 'projects') $slug
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter *.jsonl -File -EA SilentlyContinue)) {
            if ($null -eq $newest -or $f.LastWriteTimeUtc -gt $newest) { $newest = $f.LastWriteTimeUtc }
        }
    }
    if ($null -eq $newest) { return $null }
    return [math]::Round(($Now - $newest).TotalHours, 2)
}

function Get-WriterAliveAgeHours {
    <#
    .SYNOPSIS
        Hours since seat.ps1 last touched this box's heartbeat, or $null if it never has.

    .DESCRIPTION
        ONE SIGNAL, NOT TWO. The seat record's `asOf` is written by the same script in the same
        invocation and agrees to the second in 42 of 42 boxes measured. Callers get this value and no
        `asOf` accessor, so the temptation to count both does not arise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BoxKey,
        [Parameter(Mandatory)][string]$SeatsDir,
        [datetime]$Now = [datetime]::UtcNow
    )
    $f = Join-Path (Join-Path $SeatsDir '.writer-alive') "$BoxKey.txt"
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { return $null }
    try { return [math]::Round(($Now - (Get-Item -LiteralPath $f -EA Stop).LastWriteTimeUtc).TotalHours, 2) }
    catch { return $null }
}

function Get-BoxActivity {
    <#
    .SYNOPSIS
        Every activity signal for one seat box, with a count of how many could actually be evaluated.

    .OUTPUTS
        BoxKey, WorktreePath, FenceState, FenceVeto, WriterAliveAgeH, TranscriptAgeH, WorktreeExists,
        Signals, Evaluable, Veto, Why.

        Veto = true means DO NOT DISTURB. Veto = false does NOT mean safe -- check Evaluable, which is
        false when fewer than two signals could be read. Three outcomes, not two, and a caller that
        treats this as a boolean has re-created the failure the file is here to prevent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BoxKey,
        [Parameter(Mandatory)][AllowEmptyString()][string]$WorktreePath,
        [Parameter(Mandatory)][string]$SeatsDir,
        [string]$SessionId,
        [string[]]$ConfigRoot,
        [string]$RepoHint,
        # Hours. A signal newer than this vetoes. Deliberately generous: the cost of waiting a day
        # before retiring a file is nothing, and the cost of moving a live seat's handoff is the harm
        # this whole mechanism exists to avoid.
        [double]$FreshHours = 24,
        [datetime]$Now = [datetime]::UtcNow
    )

    $why = @()
    $signals = 0

    $fenceState = ''
    $fenceVeto = $false
    if ($SessionId) {
        try {
            $l = Get-SessionLiveness -SessionId $SessionId -ConfigRoot $ConfigRoot
            $fenceState = [string]$l.State
            # UNKNOWN counts as EVALUATED and as NOT a veto: the fence looked and found no record.
            # It is still not permission -- see the Signals contract. Measured 2026-08-22: 18 registry
            # records against 265 seat records, so UNKNOWN is the normal case for a historical seat,
            # not an edge one.
            $signals++
            $fenceVeto = Test-OccupancyVeto -State $fenceState
            if ($fenceVeto) { $why += "fence=$fenceState" }
        } catch {
            $fenceState = 'UNREADABLE'
            $fenceVeto = $true
            $why += 'fence=UNREADABLE (an unevaluated fence is not a passed fence)'
        }
    }

    $writerH = Get-WriterAliveAgeHours -BoxKey $BoxKey -SeatsDir $SeatsDir -Now $Now
    if ($null -ne $writerH) {
        $signals++
        if ($writerH -lt $FreshHours) { $why += "writer-alive ${writerH}h" }
    }

    $transcriptH = Get-TranscriptAgeHours -WorktreePath $WorktreePath -ConfigRoot $ConfigRoot -Now $Now
    if ($null -ne $transcriptH) {
        $signals++
        # RULE 1. Stated as its own branch rather than folded in with the heartbeat, because the whole
        # reason this signal was added is that it must win when the two disagree.
        if ($transcriptH -lt $FreshHours) { $why += "transcript ${transcriptH}h (independent of seat.ps1)" }
    }

    $exists = $false
    if ($WorktreePath) {
        $norm = ConvertTo-Norm $WorktreePath
        $wts = @(Get-RepoWorktrees -RepoHint $RepoHint)
        if ($wts.Count -gt 0) {
            $signals++
            # COUNTS AS A SIGNAL, IS NOT A VETO, AND SO DOES NOT GO IN `Why`. A checkout existing is
            # evidence the box is real; it is no evidence at all that anyone is in it -- 29 of 42
            # boxes had a present worktree on 2026-08-22 and only 11 had ticked in the last 15
            # minutes. `Why` lists the reasons a caller must not proceed, and a line in it that
            # vetoes nothing makes the field unreadable at exactly the moment it is being read to
            # justify leaving something alone. WorktreeExists carries the fact.
            $exists = [bool](@($wts | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }).Count)
        }
    }

    $veto = $fenceVeto -or
            ($null -ne $transcriptH -and $transcriptH -lt $FreshHours) -or
            ($null -ne $writerH -and $writerH -lt $FreshHours)

    return [pscustomobject]@{
        BoxKey          = $BoxKey
        WorktreePath    = $WorktreePath
        FenceState      = $fenceState
        FenceVeto       = $fenceVeto
        WriterAliveAgeH = $writerH
        TranscriptAgeH  = $transcriptH
        WorktreeExists  = $exists
        Signals         = $signals
        Evaluable       = ($signals -ge 2)
        Veto            = $veto
        Why             = @($why)
    }
}
