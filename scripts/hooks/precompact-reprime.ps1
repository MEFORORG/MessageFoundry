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

function ConvertTo-OneLine {
    # Record text goes into model context, so a line break inside a field could forge a SEAT or GOAL
    # line of its own. alloc.ps1 folds titles for the same reason (BACKLOG #1040).
    param([string]$Text)
    return $Text -replace '[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+', ' '
}

function Get-RecordWorktree {
    # The worktree field exactly as stored, '' unless it is a string. It is an IDENTITY, so it is never
    # folded: folding would let a record naming a different path match this tree.
    param($Record)
    if ($null -eq $Record) { return '' }
    $property = $Record.PSObject.Properties['worktree']
    if ($property -and $property.Value -is [string]) { return $property.Value }
    return ''
}

function Get-RecordText {
    # One field of a parsed record as one line of text, '' when the record has no such field or is
    # not an object. A plain `$record.field` THROWS under strict mode on a missing field or a null
    # record, and one empty file among the seats or allocations would then cost this session its
    # whole restore (BACKLOG #5865).
    param($Record, [string]$Name)
    if ($null -eq $Record) { return '' }
    $property = $Record.PSObject.Properties[$Name]
    if (-not $property) { return '' }
    return ConvertTo-OneLine ([string]$property.Value)
}

function Test-SameWorktree {
    # ORDINAL, because a culture-sensitive compare ignores zero-width and some control characters and
    # would call a different path this tree. Case and separators still fold, as they always have.
    param([string]$Left, [string]$Right)
    return [string]::Equals(($Left -replace '/', '\').TrimEnd('\'), ($Right -replace '/', '\').TrimEnd('\'),
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-GoalText {
    # The goal as one line, '' when it is absent, blank or not text. ConvertFrom-Json turns a goal that
    # looks like a date into a [datetime], and that is still the goal somebody stated, so the original
    # text is read back. -DateKind needs PowerShell 7.5; without it the instant is kept in ISO form.
    param($Record, [string]$Path)
    $property = $Record.PSObject.Properties['goal']
    if (-not $property) { return '' }
    $value = $property.Value
    if ($value -is [datetime] -or $value -is [datetimeoffset]) {
        $reread = $null
        try { $reread = (Read-CoordText $Path | ConvertFrom-Json -DateKind String -EA Stop).goal } catch { }
        $value = if ($reread -is [string]) { $reread } else { $value.ToString('o', [cultureinfo]::InvariantCulture) }
    }
    if ($value -isnot [string]) { return '' }
    $text = ConvertTo-OneLine $value
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }
    return $text
}

function Test-AllocTombstone {
    # EXACTLY the ownerless record the retired allocator left (BACKLOG #1829), the same test
    # remove.ps1's Read-RecordFile applies. Any near miss stays a record nobody can attribute.
    param($Record)
    if ($Record -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $t = $Record.PSObject.Properties['tombstone']
    $w = $Record.PSObject.Properties['worktree']
    $b = $Record.PSObject.Properties['branch']
    if (-not ($t -and $w -and $b)) { return $false }
    return ($t.Value -is [bool]) -and $t.Value -and
        ($w.Value -is [string]) -and ($w.Value -eq '') -and
        ($b.Value -is [string]) -and ($b.Value -eq '')
}

function Get-LedgerLines {
    # The held-number block, built in one place so the normal path and the catch print the same text.
    param([string[]]$Held, [string[]]$Unreadable, [int]$Unattributed, [string]$AllocDir)
    if ($Held.Count -gt 0) {
        ''
        'LEDGER NUMBERS THIS WORKTREE HOLDS -- these burn permanently if the tree is removed'
        'with raw git rather than scripts/worktree/remove.ps1:'
        foreach ($h in $Held) { "    $h" }
    }
    if ($Unreadable.Count -gt 0) {
        ''
        'UNREADABLE LEDGER RECORD -- names this worktree but its filename is no number, so it may'
        'be a held allocation. Read it before removing this tree:'
        foreach ($u in $Unreadable) { "    $u" }
    }
    if ($Unattributed -gt 0) {
        ''
        "LEDGER RECORDS NOT ATTRIBUTED: $Unattributed under $(ConvertTo-OneLine $AllocDir) cannot be read"
        'or name no worktree, so any of them could be this tree''s. Check before removing it.'
    }
}

function Get-WorkLines {
    # Whether the work is safe. Its own function so a throw earlier in the restore still reports it.
    param([string]$Branch)
    if (-not $Branch) { $Branch = (& git rev-parse --abbrev-ref HEAD 2>$null) }
    $dirty = @(& git status --porcelain 2>$null | Where-Object { $_ }).Count
    $unpushed = (& git rev-list --count HEAD --not --remotes --tags 2>$null)
    ''
    "BRANCH: $Branch -- $dirty uncommitted file(s), $unpushed commit(s) on no remote or tag."
    if ([int]($unpushed | ForEach-Object { $_ }) -gt 0 -or $dirty -gt 0) {
        'Commit and push before the context gets any tighter. An unpushed branch is lost work.'
    }
}

# ---- scope: a compaction restart, and nothing else --------------------------------------------
# Read before any other work, so the common case (a cold start) costs one JSON parse and exits.
$hookSource = ''
$hookEvent = ''
$hookCwd = ''
try {
    if ([Console]::IsInputRedirected) {
        # UTF-8 bytes, not the console code page, so a non-ASCII `cwd` survives the read.
        $raw = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false)).ReadToEnd()
        if ($raw) {
            $payload = $raw | ConvertFrom-Json -ErrorAction Stop
            $names = $payload.PSObject.Properties.Name
            if ($names -contains 'source' -and $payload.source) {
                $hookSource = [string]$payload.source
            }
            if ($names -contains 'hook_event_name' -and $payload.hook_event_name) {
                $hookEvent = [string]$payload.hook_event_name
            }
            if ($names -contains 'cwd' -and $payload.cwd) { $hookCwd = [string]$payload.cwd }
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

# EVERY GIT READ BELOW RESOLVES FROM THE SESSION'S OWN DIRECTORY, which is the payload `cwd`. Under
# the desktop app this process starts in the PRIMARY checkout: measured 2026-10-12, the app passes
# `--project-config-root <primary>`, and a hook's working directory followed it. This hook then
# restored the primary's seat and goal into a worktree session's context, beside that worktree's
# own role card.
if ($hookCwd -and (Test-Path -LiteralPath $hookCwd -PathType Container)) {
    try { Set-Location -LiteralPath $hookCwd } catch { }
}

# Dot-sourced AFTER the guard, so a cold start never pays for it. config-roots.ps1 is a
# definitions-only library with no load-time I/O, which is what makes that safe inside a hook.
# DO NOT restate its rule here. The age line below was briefly a THIRD copy of ConvertTo-UtcDateTime,
# and the copy was the weakest of the three -- it dropped the [datetimeoffset] arm and the
# DateTimeOffset parse. That function's own docstring says why one place to change it is the
# difference between a fix and a hunt, and fleet.ps1's Get-AgeHours records the same measurement.
$rootsLib = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\config-roots.ps1'
if (Test-Path -LiteralPath $rootsLib) { . $rootsLib }
# Same contract: definitions only. seats/ and alloc/ are SHARED kinds and come from it.
$coordRootLib = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\coord-root.ps1'
if (Test-Path -LiteralPath $coordRootLib) { . $coordRootLib }
# codex-seats/ is read even with no resolver, so the record reader needs a plain stand-in there.
if (-not (Get-Command Read-CoordText -ErrorAction SilentlyContinue)) {
    function Read-CoordText([string]$Path) { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop }
}

# Outside the try, so the catch below can still print what was gathered before a throw.
$lines = @()
$held = @()
$unreadable = @()
$unattributed = 0
$ledgerScanned = $false
$allocDir = ''
$branchNow = ''
$banner = "[precompact] Restoring what this compaction is about to drop.`n"
$declareCmd = '    pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <role> -Goal "<one line>"'
try {
    $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { exit 0 }
    $common = $common.Trim()
    $coord = Join-Path $common 'mefor-coord'

    $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $top) { exit 0 }
    $top = $top.Trim()

    # seats/ and alloc/ live on the SHARED root (docs/COORD-SHARED-ROOT.md). One probe answers both,
    # since the resolver puts every shared kind on one root. A root that does not answer drops only
    # those two blocks, with a line saying so; the branch and dirty-tree lines below still print,
    # because a reprime that vanished whole would read as "nothing to restore".
    # A missing resolver is a skip with a note, never a read of the local root: that local read would
    # be a second definition of "where" (coord-root.ps1's header), and wrong once a root is configured.
    $sharedRoot = $null
    $sharedError = "$coordRootLib is missing, so the coordination root could not be resolved"
    $haveResolver = [bool](Get-Command Resolve-CoordSharedRoot -ErrorAction SilentlyContinue)
    if ($haveResolver) {
        $sr = Resolve-CoordSharedRoot -From $top -LocalRoot $coord
        if ($sr.Error) { $sharedError = ConvertTo-OneLine ([string]$sr.Error) }
        else { $sharedError = ''; $sharedRoot = $sr.Path }
    }
    # Nothing to restore when neither root holds any state. Checked AFTER the shared root is known,
    # because on a shared root the local one may never have been created. A root that did not answer
    # is not "nothing": that case goes on to say so below.
    if (-not $sharedError -and -not (Test-Path -LiteralPath $coord) -and
        -not ($sharedRoot -and (Test-Path -LiteralPath $sharedRoot))) { exit 0 }

    # Read the branch BEFORE the declaration block: it is the discriminator that decides whether a
    # record found by path actually belongs to this session, not just a fact reported at the end.
    $branchNow = (& git rev-parse --abbrev-ref HEAD 2>$null)
    if ($branchNow) { $branchNow = $branchNow.Trim() }

    # ---- the declaration -------------------------------------------------------------------
    # Newest record for THIS worktree that actually carries a goal. Records are per-episode, so a
    # box can hold many and only some are declared; taking the newest DECLARED one is what restores
    # intent rather than the most recent heartbeat.
    $seatsDir = if ($sharedRoot) { Join-Path $sharedRoot 'seats' } else { $null }
    # codex-seats/ is not a shared kind; it stays on the local root.
    if ($env:KORUS_AGENT -eq 'codex') { $seatsDir = Join-Path $coord 'codex-seats' }
    $declared = $null
    $declaredGoal = ''
    # Records for this tree that were rejected as damaged, so that "none usable" is not reported as
    # "never declared". The newest goal among them is still shown, labelled as unverified.
    $damagedCount = 0
    $damagedFile = ''
    $damagedGoal = ''
    $damagedBranch = ''
    $seatUnattributed = 0
    if ($seatsDir -and (Test-Path -LiteralPath $seatsDir)) {
        $cands = Get-ChildItem -LiteralPath $seatsDir -Recurse -Filter '*.json' -File -EA SilentlyContinue |
                 Sort-Object LastWriteTimeUtc -Descending
        foreach ($f in $cands) {
            # A record that does not parse or names no worktree could be this tree's, so it is counted.
            try { $j = Read-CoordText $f.FullName | ConvertFrom-Json -EA Stop } catch { $seatUnattributed++; continue }
            $wt = Get-RecordWorktree $j
            if (-not $wt) { $seatUnattributed++; continue }
            if (-not (Test-SameWorktree $wt $top)) { continue }
            # Another PC can hold a worktree at the same path. Its record is that PC's seat, not this
            # one's. A record with no host predates the field and is this PC's.
            # Only codex-seats/ is read with no resolver loaded, and that registry is local by kind.
            if ($haveResolver -and -not (Test-CoordRecordIsHere $j)) { continue }
            # A Codex restart may not inherit the goal of a Claude session in this tree.
            if ($env:KORUS_AGENT -eq 'codex') {
                if (-not $env:KORUS_SESSION_ID) { continue }
                if (-not $j.PSObject.Properties['sessionId'] -or
                    $j.sessionId -ne "codex-$env:KORUS_SESSION_ID") { continue }
            }
            # seat.ps1 always writes the `seat` key, so a record without it is damaged and must not
            # displace a good declaration. A PRESENT null is real: `-Declare -Goal` with no -Seat.
            $hasSeat = [bool]$j.PSObject.Properties['seat']
            # seat.ps1 writes a goal as text, so a blank or non-string one is damage too.
            $goalText = Get-GoalText $j $f.FullName
            if ($hasSeat -and $goalText) { $declared = $j; $declaredGoal = $goalText; break }
            # A seat key with a null or absent goal is what seat.ps1 writes before any declaration.
            $goalField = $j.PSObject.Properties['goal']
            if ($hasSeat -and (-not $goalField -or $null -eq $goalField.Value)) { continue }
            $damagedCount++
            if (-not $damagedFile) { $damagedFile = ConvertTo-OneLine $f.FullName }
            if (-not $damagedGoal) {
                $damagedGoal = if ($goalText) { $goalText } else { (Get-RecordText $j 'goal').Trim() }
                if ($damagedGoal) { $damagedBranch = Get-RecordText $j 'branch' }
            }
        }
    }

    $damagedGoalLine = ''
    if ($damagedGoal) {
        $onBranch = if ($damagedBranch) { " (recorded on branch '$damagedBranch')" } else { '' }
        $damagedGoalLine = "    goal in a damaged record, UNVERIFIED$onBranch`: $damagedGoal"
    }

    if ($declared) {
        $declSeat = Get-RecordText $declared 'seat'
        if (-not $declSeat) { $declSeat = '(none recorded)' }
        # A worktree OUTLIVES the session that declared in it -- directories here get re-used, and a
        # record matched on path alone can be a previous occupant's intent wearing this tree's name.
        # Restoring that as if it were current is worse than restoring nothing, because a stale goal
        # is actionable and reads as authoritative. The branch is the discriminator the fleet already
        # uses for exactly this ("the directory was re-used"), so check it before trusting the goal.
        $declBranch = Get-RecordText $declared 'branch'
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
            $lines += "    seat: $declSeat"
            $lines += "    goal: $declaredGoal"
            $lines += $declareCmd
        } else {
            $lines += "SEAT: $declSeat"
            $lines += "GOAL: $declaredGoal"
            if ($declared.PSObject.Properties['done'] -and $declared.done) { $lines += "DONE WHEN: $(Get-RecordText $declared 'done')" }
            if ($declared.PSObject.Properties['outOfScope'] -and $declared.outOfScope) { $lines += "OUT OF SCOPE: $(Get-RecordText $declared 'outOfScope')" }
            if ($declaredDisplay) { $lines += "declared at $declaredDisplay$age" }
        }
        # Every damaged record seen here is NEWER than the declaration, so its goal may supersede it.
        if ($damagedGoalLine) {
            $lines += "A NEWER record naming this worktree is DAMAGED and may supersede this: $damagedFile"
            $lines += $damagedGoalLine
        }
    } elseif ($damagedCount -gt 0) {
        $lines += "SEAT: not restored. $damagedCount DAMAGED record(s) name this worktree, so a declaration may"
        $lines += "have been lost. This is not known to be the never-declared case. Newest: $damagedFile"
        if ($damagedGoalLine) { $lines += $damagedGoalLine }
        $lines += 'Check it, then declare again:'
        $lines += $declareCmd
    } elseif ($sharedError -and -not $seatsDir) {
        $lines += "SEAT: not restored. The shared seat registry did not answer ($sharedError)."
    } else {
        if ($seatUnattributed -gt 0) {
            $lines += "SEAT: not declared by any readable record, but $seatUnattributed seat record(s) cannot be read or"
            $lines += "name no worktree, and any of them could be this tree's. A goal may be lost. Declare one:"
        } else {
            $lines += "SEAT: not declared. Nothing on disk carries a goal for this worktree, so this is the"
            $lines += "'never asked or never answered' case, NOT a goal lost to compaction. Declare one:"
        }
        $lines += $declareCmd
    }

    # ---- ledger numbers this worktree holds ------------------------------------------------
    # This is the fact with a permanent cost attached. An allocated-but-unfiled number burns if the
    # worktree is removed, and after a compaction nobody in the session remembers holding one.
    $allocDir = if ($sharedRoot) { Join-Path $sharedRoot 'alloc' } else { '' }
    if ($sharedError) { $lines += ''; $lines += "LEDGER NUMBERS: not checked, the shared root did not answer." }
    if ($allocDir -and (Test-Path -LiteralPath $allocDir)) {
        foreach ($f in (Get-ChildItem -LiteralPath $allocDir -Recurse -Filter '*.json' -File -EA SilentlyContinue)) {
            # A record that does not parse or names no worktree could be this tree's. They are counted
            # rather than listed, because the registry is shared and this text costs context.
            # -NoEnumerate and the object test are how remove.ps1 reads this record: without them a
            # one-element array unwraps and reads as a normal held number.
            try { $a = Read-CoordText $f.FullName | ConvertFrom-Json -NoEnumerate -EA Stop } catch { $unattributed++; continue }
            if ($a -isnot [System.Management.Automation.PSCustomObject]) { $unattributed++; continue }
            # Another machine's allocation names a path on that machine's disk, so the same path here
            # is a different tree and the number is not this one's to lose. No `host` is this machine.
            if (-not (Test-CoordRecordIsHere $a)) { continue }
            $aw = Get-RecordWorktree $a
            if ([string]::IsNullOrWhiteSpace($aw)) {
                if (-not (Test-AllocTombstone $a)) { $unattributed++ }
                continue
            }
            # EXACT match, never a prefix. Sibling worktrees in this repo are named as extensions of
            # each other (...-cfbf59 and ...-cfbf59-connscale-ci-claim), so a prefix test claims another
            # tree's numbers as your own.
            if (-not (Test-SameWorktree $aw $top)) { continue }
            # THE FILENAME IS THE NUMBER, as alloc.ps1 records, and the body's `number` field is not, so
            # a body that lost the field still names its number. A file naming this tree with no
            # number in its name may still be a held allocation, so it is reported, never skipped.
            # ASCII digits only: `\d` also matches other scripts' digits, as alloc.ps1 warns.
            if ($f.BaseName -notmatch '\A[0-9]+\z') { $unreadable += ConvertTo-OneLine $f.FullName; continue }
            $held += "#$($f.BaseName) ($(ConvertTo-OneLine $f.Directory.Name)) $(Get-RecordText $a 'title')"
        }
    }
    $lines += @(Get-LedgerLines $held $unreadable $unattributed $allocDir)
    # Set only once the block is in $lines: a renderer throw must still earn the catch's caveat.
    $ledgerScanned = $true
    # Emptied once printed, so the catch below cannot print them a second time.
    $held = @()
    $unreadable = @()
    $unattributed = 0

    # ---- is the work safe ------------------------------------------------------------------
    $lines += @(Get-WorkLines $branchNow)

    # PLAIN TEXT ON STDOUT, which is what SessionStart adds to context. See the header for the
    # envelope that used to be here and why the harness threw all of it away. [Console]::Out.Write
    # rather than Write-Output, so nothing reformats or wraps the lines on the way out.
    [Console]::Out.Write($banner + ($lines -join "`n"))
    exit 0
} catch {
    # This hook never fails a turn, but a throw must not discard what was already gathered: that
    # total loss is BACKLOG #5865. The inner try keeps a failed write from failing the turn.
    try {
        # Each step is guarded alone, so a helper that threw on the main path cannot empty this one.
        $why = [string]$_.Exception.Message
        try { $why = ConvertTo-OneLine $why } catch { $why = 'unreadable error' }
        try {
            $lines += @(Get-LedgerLines $held $unreadable $unattributed $allocDir)
        } catch {
            # The renderer is what threw, so the gathered facts go out plain. They are already one line.
            $lines += ''
            $lines += 'LEDGER RECORDS GATHERED BEFORE THE STOP -- held numbers, then unreadable files:'
            foreach ($entry in @($held) + @($unreadable)) { $lines += "    $entry" }
            if ($unattributed -gt 0) { $lines += "LEDGER RECORDS NOT ATTRIBUTED: $unattributed could be this tree's." }
        }
        # A missing ledger block must not read as "this tree holds no numbers".
        if (-not $ledgerScanned) { $lines += ''; $lines += 'LEDGER NUMBERS: not fully checked, so this tree may hold some.' }
        try { $lines += @(Get-WorkLines $branchNow) } catch { }
        $lines += ''
        $lines += "RESTORE INCOMPLETE: this hook stopped early ($why)."
        [Console]::Out.Write($banner + ($lines -join "`n"))
    } catch { }
    exit 0
}
