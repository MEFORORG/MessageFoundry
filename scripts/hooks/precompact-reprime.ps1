# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# SessionStart hook, scoped to the `compact` source: put back the facts a compaction destroys.
#
# WHAT A COMPACTION TAKES. The seat, the goal, the brief, which ledger numbers this worktree holds,
# and whether the work is pushed. All of that lives in the conversation, and a compaction summarises
# the conversation. seat-declare-prompt.ps1 asks for a declaration once, at a cold start, and never
# fires again -- so after a compaction the seat is undeclared IN CONTEXT even though it declared
# perfectly well an hour ago, and it has no idea it is holding an unfiled allocation that burns if
# the worktree is removed.
#
# WHY IT READS RATHER THAN ASKS. At a cold start the right move is to ask, because nothing is known
# yet and a machine that invents a goal writes a record that looks declared and says nothing. After
# a compaction the declaration usually ALREADY EXISTS on disk; the compaction dropped it from
# context, not from the record. So this hook reads the record back. That is a restatement of a
# stated intent, not an invented one, and the distinction is the same one seat-declare-prompt.ps1
# draws in its own header. Adopted from gastown, which registers its `prime --hook` primer for this
# reason (BACKLOG #1453).
#
# ---------------------------------------------------------------------------------------------
# THIS HOOK RAN ON THE WRONG EVENT FOR ITS WHOLE LIFE AND PUT NOTHING BACK. Recorded here because
# the failure was silent from both ends and the next author will reach for the same wiring.
#
# It was registered on PreCompact and emitted
#     {"hookSpecificOutput":{"hookEventName":"PreCompact","additionalContext":"..."}}
# The harness REJECTED that on every fire. Measured live 2026-09-15:
#     Hook JSON output validation failed - hookSpecificOutput.hookEventName:
#     expected one of "PreToolUse" | "UserPromptSubmit" | "UserPromptExpansion" |
#     "SessionStart" | "Setup" | "PreModelSwitch" | ...
# PreCompact is a real EVENT. It is not an accepted hookSpecificOutput.hookEventName. So the reprime
# text never reached context once, and it surfaced only because the rejection notice happened to
# echo the payload into a transcript somebody was reading.
#
# THE EVENT WAS THE DEEPER HALF, so repairing the payload alone would have shipped a second dud.
# PreCompact fires BEFORE the summary is written, which makes anything it adds to context exactly
# what the compaction then summarises away -- self-defeating by construction. The vendor
# documentation agrees from the other side: exit-0 stdout is added to context for UserPromptSubmit,
# UserPromptExpansion, SessionStart and PostModelSwitch, PreCompact is in none of those lists, and
# no context-injection schema is documented for it at all. That documentation names this very
# repair: use a SessionStart hook on the `compact` source to re-inject context after a compaction.
#
# SO THE OUTPUT IS NOW PLAIN TEXT ON STDOUT, exit 0 -- the form seat-declare-prompt.ps1 has always
# used at SessionStart, and the form measured landing in context on the same day.
#
# WHY THE SOURCE GUARD IS IN THIS SCRIPT RATHER THAN IN A MATCHER. The documented alternative is a
# `"matcher": "compact"` on the settings row. No SessionStart matcher has ever been used in this
# repository and whether this harness honours one is UNMEASURED, while the no-matcher row is
# measured to fire on a compaction. Picking the unmeasured spelling would risk re-shipping the very
# defect above: a hook that reads as wired and never runs. So the row stays match-all and the
# scoping lives here, where a test can drive it. Adding the matcher later stays safe -- this guard
# holds either way, and the two agreeing is the belt-and-braces shape usage-headroom-inject.ps1
# already uses with its own $SPAWN_TOOLS guard.
#
# THE GUARD FAILS OPEN, ON PURPOSE. It goes quiet only when it can POSITIVELY read a payload saying
# this is not a compaction restart. An absent or unparseable payload speaks anyway, because a hook
# that says something unnecessary is a nuisance somebody notices, and a hook that silently says
# nothing is the defect this file exists to record.
#
# LEGIBLE SILENCE. If no declaration is found, this hook says so rather than saying nothing, and
# repeats the declare command. "Never declared" and "declared, then compacted away" have opposite
# fixes and must not both render as blank.
#
# THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 on every path.
#
# WIRING IS ASSERTED, in tests/test_precompact_reprime_hook.py, against .claude/settings.json. This
# header used to say wiring was left unasserted on purpose, because the matcher is settings.json's
# property and not this file's. That much is true, and it is why the check lives in a test rather
# than in this script -- but "not asserted here" got read as "not asserted", and nothing anywhere
# checked the event or the payload. That is how a hook ships dead.
# See docs/WORKTREES.md.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Format-Age {
    # A negative age is not a small age. It means this session's clock and the record's disagree, and
    # rounding it to "0.0 days" would hide the one fault in this line worth reporting.
    param([timespan]$Span)
    if ($Span.TotalSeconds -lt 0) {
        return 'declared in the FUTURE -- this session and the record disagree on the clock'
    }
    if ($Span.TotalHours -lt 1) { return "$([math]::Round($Span.TotalMinutes)) minutes old" }
    if ($Span.TotalDays -lt 1) { return "$([math]::Round($Span.TotalHours, 1)) hours old" }
    return "$([math]::Round($Span.TotalDays, 1)) days old"
}

# ---- scope: a compaction restart, and nothing else --------------------------------------------
# Read before any other work, so the common case (a cold start) costs one JSON parse and exits.
$hookSource = ''
$hookEvent = ''
try {
    if ([Console]::IsInputRedirected) {
        $raw = [Console]::In.ReadToEnd()
        if ($raw) {
            $payload = $raw | ConvertFrom-Json -ErrorAction Stop
            $names = $payload.PSObject.Properties.Name
            if ($names -contains 'source' -and $payload.source) {
                $hookSource = [string]$payload.source
            }
            if ($names -contains 'hook_event_name' -and $payload.hook_event_name) {
                $hookEvent = [string]$payload.hook_event_name
            }
        }
    }
} catch {
    # An unreadable payload is the fail-open case: both discriminators stay empty and the hook speaks.
}

# THE PROPERTY IS "NOT A COMPACTION", NOT A LIST OF THE STARTS THAT ARE NOT ONE. The harness ships at
# least `startup`, `resume`, `clear`, `compact` and `fork`, and an equality test against `compact`
# covers every one of them plus whatever is added next; enumerating the others would be a list that
# is one short the day it grows. Those other starts are seat-declare-prompt.ps1's, and a reprime
# during one would report a seat the session has not chosen yet.
#
# A payload naming any event other than SessionStart is a leftover registration somewhere else, and
# it must stay quiet: its stdout does not reach context, so the work is wasted either way.
if ($hookSource -and $hookSource -ne 'compact') { exit 0 }
if ($hookEvent -and $hookEvent -ne 'SessionStart') { exit 0 }

# Dot-sourced AFTER the guard, so a cold start never pays for it. config-roots.ps1 is a
# definitions-only library with no load-time I/O, which is what makes that safe inside a hook.
# DO NOT restate its rule here. The age line below was briefly a THIRD copy of ConvertTo-UtcDateTime,
# and the copy was the weakest of the three -- it dropped the [datetimeoffset] arm and the
# DateTimeOffset parse. That function's own docstring says why one place to change it is the
# difference between a fix and a hunt, and fleet.ps1's Get-AgeHours records the same measurement.
$rootsLib = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\config-roots.ps1'
if (Test-Path -LiteralPath $rootsLib) { . $rootsLib }

try {
    $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { exit 0 }
    $common = $common.Trim()
    $coord = Join-Path $common 'mefor-coord'
    if (-not (Test-Path -LiteralPath $coord)) { exit 0 }

    $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $top) { exit 0 }
    $top = $top.Trim()
    $topNorm = ($top -replace '/', '\').TrimEnd('\')

    $lines = @()

    # Read the branch BEFORE the declaration block: it is the discriminator that decides whether a
    # record found by path actually belongs to this session, not just a fact reported at the end.
    $branchNow = (& git rev-parse --abbrev-ref HEAD 2>$null)
    if ($branchNow) { $branchNow = $branchNow.Trim() }

    # ---- the declaration -------------------------------------------------------------------
    # Newest record for THIS worktree that actually carries a goal. Records are per-episode, so a
    # box can hold many and only some are declared; taking the newest DECLARED one is what restores
    # intent rather than the most recent heartbeat.
    $seatsDir = Join-Path $coord 'seats'
    if ($env:KORUS_AGENT -eq 'codex') { $seatsDir = Join-Path $coord 'codex-seats' }
    $declared = $null
    if (Test-Path -LiteralPath $seatsDir) {
        $cands = Get-ChildItem -LiteralPath $seatsDir -Recurse -Filter '*.json' -File -EA SilentlyContinue |
                 Sort-Object LastWriteTimeUtc -Descending
        foreach ($f in $cands) {
            try { $j = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
            $wt = [string]$j.worktree
            if (-not $wt) { continue }
            if (($wt -replace '/', '\').TrimEnd('\') -ne $topNorm) { continue }
            # A Codex restart may not inherit the goal of a Claude session in this tree.
            if ($env:KORUS_AGENT -eq 'codex') {
                if (-not $env:KORUS_SESSION_ID) { continue }
                if (-not $j.PSObject.Properties['sessionId'] -or
                    $j.sessionId -ne "codex-$env:KORUS_SESSION_ID") { continue }
            }
            if ($j.PSObject.Properties['goal'] -and $j.goal) { $declared = $j; break }
        }
    }

    if ($declared) {
        # A worktree OUTLIVES the session that declared in it -- directories here get re-used, and a
        # record matched on path alone can be a previous occupant's intent wearing this tree's name.
        # Restoring that as if it were current is worse than restoring nothing, because a stale goal
        # is actionable and reads as authoritative. The branch is the discriminator the fleet already
        # uses for exactly this ("the directory was re-used"), so check it before trusting the goal.
        $declBranch = if ($declared.PSObject.Properties['branch']) { [string]$declared.branch } else { '' }
        $stale = $declBranch -and $branchNow -and ($declBranch -ne $branchNow)

        $age = ''
        $declaredDisplay = ''
        if ($declared.PSObject.Properties['declaredAt'] -and $declared.declaredAt) {
            # SCOPED so the AGE degrades alone. If config-roots.ps1 is missing from a checkout, the
            # call below is an unrecognised command, and without this catch the outer handler would
            # swallow it and drop the WHOLE reprime -- seat, goal and held ledger numbers with it.
            # That is the fail-silent direction this file exists to argue against, and it is not
            # hypothetical: it happened here mid-change, and only driving the script revealed it.
            try {
                $declaredUtc = ConvertTo-UtcDateTime $declared.declaredAt
            } catch {
                $declaredUtc = $null
            }
            if ($null -ne $declaredUtc) {
                $age = ' (' + (Format-Age ((Get-Date).ToUniversalTime() - $declaredUtc)) + ')'
                # Rendered in local time WITH its offset, so it cannot be read as the other zone. The
                # stored field is a UTC instant, and printing its bare wall clock is what made an
                # already-confusing line look local.
                $declaredDisplay = $declaredUtc.ToLocalTime().ToString('yyyy-MM-ddTHH:mm:ssK')
            }
        }

        if ($stale) {
            $lines += "SEAT: a declaration exists for this DIRECTORY but it is probably NOT YOURS."
            $lines += "It was declared on branch '$declBranch'$age; this session is on '$branchNow'."
            $lines += "Worktrees get re-used, so treat the following as a previous occupant's intent"
            $lines += "and re-declare rather than adopting it:"
            $lines += "    seat: $($declared.seat)"
            $lines += "    goal: $($declared.goal)"
            $lines += '    pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <role> -Goal "<one line>"'
        } else {
            $lines += "SEAT: $($declared.seat)"
            $lines += "GOAL: $($declared.goal)"
            if ($declared.PSObject.Properties['done'] -and $declared.done) { $lines += "DONE WHEN: $($declared.done)" }
            if ($declared.PSObject.Properties['outOfScope'] -and $declared.outOfScope) { $lines += "OUT OF SCOPE: $($declared.outOfScope)" }
            if ($declaredDisplay) { $lines += "declared at $declaredDisplay$age" }
        }
    } else {
        $lines += "SEAT: not declared. Nothing on disk carries a goal for this worktree, so this is the"
        $lines += "'never asked or never answered' case, NOT a goal lost to compaction. Declare one:"
        $lines += '    pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <role> -Goal "<one line>"'
    }

    # ---- ledger numbers this worktree holds ------------------------------------------------
    # This is the fact with a permanent cost attached. An allocated-but-unfiled number burns if the
    # worktree is removed, and after a compaction nobody in the session remembers holding one.
    $allocDir = Join-Path $coord 'alloc'
    $held = @()
    if (Test-Path -LiteralPath $allocDir) {
        foreach ($f in (Get-ChildItem -LiteralPath $allocDir -Recurse -Filter '*.json' -File -EA SilentlyContinue)) {
            try { $a = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
            $aw = [string]$a.worktree
            if (-not $aw) { continue }
            # EXACT match, never a prefix. Sibling worktrees in this repo are named as extensions of
            # each other (...-cfbf59 and ...-cfbf59-connscale-ci-claim), so a prefix test claims another
            # tree's numbers as your own.
            if (($aw -replace '/', '\').TrimEnd('\') -ne $topNorm) { continue }
            $held += "#$($a.number) ($($a.kind)) $($a.title)"
        }
    }
    if ($held.Count -gt 0) {
        $lines += ''
        $lines += "LEDGER NUMBERS THIS WORKTREE HOLDS -- these burn permanently if the tree is removed"
        $lines += "with raw git rather than scripts/worktree/remove.ps1:"
        foreach ($h in $held) { $lines += "    $h" }
    }

    # ---- is the work safe ------------------------------------------------------------------
    $dirty = @(& git status --porcelain 2>$null | Where-Object { $_ }).Count
    $unpushed = (& git rev-list --count HEAD --not --remotes --tags 2>$null)
    $lines += ''
    $lines += "BRANCH: $($branchNow) -- $dirty uncommitted file(s), $unpushed commit(s) on no remote or tag."
    if ([int]($unpushed | ForEach-Object { $_ }) -gt 0 -or $dirty -gt 0) {
        $lines += "Commit and push before the context gets any tighter. An unpushed branch is lost work."
    }

    # PLAIN TEXT ON STDOUT, which is what SessionStart adds to context. See the header for the
    # envelope that used to be here and why the harness threw all of it away. [Console]::Out.Write
    # rather than Write-Output, so nothing reformats or wraps the lines on the way out.
    [Console]::Out.Write(
        "[precompact] Restoring what this compaction is about to drop.`n" + ($lines -join "`n")
    )
    exit 0
} catch {
    # Deliberately swallowed. This hook never fails a turn.
    exit 0
}
