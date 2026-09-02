# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    PreToolUse gate: refuse to edit a file another LIVE session is already changing.

.DESCRIPTION
    Worktrees stop two sessions from overwriting each other's bytes. They do NOT stop two sessions
    from editing the same file in parallel and discovering it at merge -- by which point both have
    built on divergent assumptions and someone's work is thrown away. This gate turns that from a
    merge-time surprise into an edit-time refusal, which is the only point where it is still cheap.

    NOTHING TO OPT INTO. It reads git state and the session registry, both by-products of working
    normally. That is the whole design: `claim.ps1` has existed for some time and has been used
    exactly ZERO times, because a coordination step you must remember is one you will skip. A guard
    that needs cooperation to work does not work.

    ONLY LIVE SESSIONS BLOCK. A dormant worktree with changes cannot be racing you -- its owner is not
    typing -- so it is reported and allowed. Blocking on dormant worktrees would deny edits to every
    file any abandoned branch ever touched, and a gate that cries wolf gets uninstalled.

    FAILS OPEN, DELIBERATELY. Any error -- unparseable payload, no git, no registry, a broken overlap
    script -- exits 0 and allows the edit. This gate prevents rework; it must never be the reason a
    session cannot work. That is the opposite of the worktree gate's posture (which protects the
    shared tree and should fail closed), and the difference is intentional.

    FAILS OPEN, BUT NOT SILENTLY. Every one of those error paths used to `exit 0` with no output, which
    on stdout is byte-for-byte what "checked, nobody else is touching this file" looks like. So a gate
    that had checked NOTHING was indistinguishable from a gate reporting all-clear, and a session could
    read the absence of a warning as evidence -- while the guard was inert. An unresolved run now says
    so via additionalContext. It still allows: the posture is unchanged, only the silence is.

    Rate-limited per reason (`-NoticeCooldownMinutes`), because a persistently broken overlap script
    would otherwise inject a notice into EVERY Edit and Write. If the throttle state cannot be read or
    written the notice is emitted anyway -- silence is the defect being fixed, so the fallback is noise.

    Wired on Edit|Write|MultiEdit|NotebookEdit. The overlap map is cached, so the common case is a
    cache read, not a git walk across every worktree.
#>
[CmdletBinding()]
param(
    # Overlap script to consult. Parameterised so tests drive the REAL gate against a fixture rather
    # than re-implementing its rule -- a test that asserts a copy of the rule proves nothing.
    [string]$OverlapScript = (Join-Path $PSScriptRoot "..\coord\overlap.ps1"),
    # Emit the decision and skip reading stdin (tests).
    [string]$PathOverride,
    # Where the per-reason "already told them" stamps live. Defaults to the repo's coordination dir.
    # Parameterised so tests are isolated from the real repo AND from each other -- a throttle sharing
    # one directory with the suite would make the first test's notice suppress the second's.
    [string]$StateDir,
    # How long one unresolved reason stays quiet after being reported.
    [int]$NoticeCooldownMinutes = 30,
    # Handed to overlap.ps1 as its walk budget. It must sit UNDER the harness timeout wired for this
    # hook (`Timeout = 20` in install-coordination.ps1), with room for two pwsh startups and the notice
    # write, because the point is to still be running when the budget is hit. Tests drive it low.
    [int]$OverlapTimeBudgetSeconds = 16
)

# No $ErrorActionPreference = Stop: this gate fails OPEN, and a throw would be a deny-by-crash.
$ErrorActionPreference = "SilentlyContinue"

# Fold a CALLER-SUPPLIED value before it goes into a deny reason or an additionalContext notice.
#
# BACKLOG #1040 was filed against the worktree gate, and its closing sentence is the reason this exists
# here too: "every hook in scripts/hooks/ that emits a remediation an agent is told to run has this
# shape -- the gate is where it was noticed, not where it is confined." Measured on THIS gate: a
# PreToolUse payload whose file_path carried embedded newlines produced a notice with TWO
# "Before overriding:" blocks, the FORGED one FIRST, replacing the real `overlap.ps1` line with a
# command of the attacker's choosing. A model reading top-down reaches the forged one first. Nothing
# has to exist on disk -- only the JSON field -- so no other gate sees it either.
#
# THE VALUES ARE NOT ONLY THE PATH. The rows come from overlap.ps1, so Branch is a git refname and
# Worktree a directory name, and a refname is attacker-choosable from a public fork (`gh pr checkout`
# and `git fetch origin <ref>:<ref>` both create refs/heads/<their-name>). Work is free text from the
# session registry. All of them are folded, because deciding value by value is what left the last one
# bare.
#
# THIS FOLD IS FOR PROSE, AND PROSE ONLY. It neutralises LINE STRUCTURE, which is the whole exposure a
# value has inside a sentence; it leaves '$', a backtick, ';' and '&' alone, because those do nothing in
# a sentence. The committed-and-clean notice below now emits a runnable `git log` naming the peer's
# branch, so this file DOES have a command-bound value, and folding is not its treatment -- see
# Get-SafeForCommand directly beneath, and keep the two named apart.
#
# A LOCAL COPY, deliberately, and the alternative is worse. worktree_gate.ps1 is installed OUTSIDE
# every working tree by install-gate.ps1, so it can dot-source nothing from a checkout; a shared module
# would therefore be importable by this hook and not by that one, which is two definitions of one rule
# that drift invisibly. A few lines duplicated, with the divergence visible to grep, beats that.
function Get-SafeForMessage([string]$Value) {
    $t = ("$Value" -replace '[\r\n\t]', ' ')
    if ($t.Length -gt 400) { return $t.Substring(0, 400) + '...' }
    return $t
}

# COMMAND-BOUND values -- the other half of the pair, and QUOTING is its fix rather than folding. The
# rule, the measurements behind it, why the quotes are single and why $Prefix/$Suffix live INSIDE the
# span are recorded once at worktree_gate.ps1's Get-SafeForCommand. This is that function, byte for
# byte, for the reason the fold above is.
#
# WHY IT ARRIVED HERE. Until 2026-08-22 this gate's remediations were literals with placeholders, and
# `git log --oneline origin/main..<that branch> -- <this file>` looked like one. It is not: the branch it
# asks for is printed two clauses earlier, so the reader performs the interpolation the script declined
# to. `git check-ref-format --branch 'evil;whoami'` exits 0, so that is a legal refname, and a public
# fork can create it (`gh pr checkout`, `git fetch origin <ref>:<ref>`). Relocating an interpolation into
# the reader does not remove it, and the reader has no fold and no quoting helper.
function Get-SafeForCommand([string]$Value, [string]$Prefix = "", [string]$Suffix = "") {
    $body = "$Prefix" + (Get-SafeForMessage $Value) + "$Suffix"
    return "'" + ($body -replace "'", "''") + "'"
}

function Deny([string]$Reason) {
    # The hookSpecificOutput wrapper is MANDATORY -- a bare permissionDecision is silently ignored,
    # which would leave this looking installed while permitting everything.
    $payload = @{
        hookSpecificOutput = @{
            hookEventName            = "PreToolUse"
            permissionDecision       = "deny"
            permissionDecisionReason = $Reason
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

function Write-Unresolved([string]$Slug, [string]$Detail) {
    # THE GATE DID NOT CHECK. Say so, and allow anyway.
    #
    # It must be a JSON hookSpecificOutput.additionalContext payload and never a bare line: this is a
    # PreToolUse hook whose stdout is PARSED AS A DECISION, so a stray line risks a misparse on every
    # single Edit and Write -- turning a diagnostic into a worse fault than the one it reports.
    #
    # No permissionDecision key: adding one here would convert a broken guard into a blocked session,
    # which is the fail-open posture inverted.
    $emit = $true
    try {
        $dir = $StateDir
        if (-not $dir) {
            $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
            if ($LASTEXITCODE -eq 0 -and $common) { $dir = Join-Path ([string]$common).Trim() "mefor-coord" }
        }
        if ($dir) {
            # PER WORKTREE, not per repo. The stamp lives in the SHARED git-common-dir, so a single
            # repo-wide stamp would mean the first session to hit a broken gate silences it for every
            # other session for the whole cooldown -- and those sessions would read that silence as
            # "checked, nobody is here", which is precisely the defect this notice exists to remove.
            # One session's diagnostic must never become another session's false all-clear.
            $who = "shared"
            $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
            if ($LASTEXITCODE -eq 0 -and $top) {
                $who = (Split-Path ([string]$top).Trim() -Leaf) -replace '[^A-Za-z0-9._-]+', '-'
                if (-not $who) { $who = "shared" }
            }
            $stamp = Join-Path $dir "gate-unresolved/$who.$Slug.stamp"
            $prev = Get-Item -LiteralPath $stamp -ErrorAction SilentlyContinue
            if ($prev) {
                $mins = ((Get-Date) - $prev.LastWriteTime).TotalMinutes
                # Bound BOTH ways. A stamp dated in the future (clock skew, a copied tree) would read as
                # eternally fresh and suppress this notice forever -- the same silence, now self-inflicted.
                if ($mins -ge 0 -and $mins -lt $NoticeCooldownMinutes) { $emit = $false }
            }
            if ($emit) {
                New-Item -ItemType Directory -Force -Path (Split-Path $stamp) | Out-Null
                Set-Content -LiteralPath $stamp -Value ((Get-Date).ToString("o")) -Encoding UTF8
            }
        }
    } catch {
        # Cannot throttle -> report. Silence is the defect being fixed, so the failure mode of the
        # noise-suppressor must be noise, never quiet.
        $emit = $true
    }
    if ($emit) {
        $payload = @{
            hookSpecificOutput = @{
                hookEventName     = "PreToolUse"
                additionalContext = "[collision] The collision gate could NOT check this edit ($(Get-SafeForMessage $Slug)): $(Get-SafeForMessage $Detail). It allowed the edit without consulting any peer worktree, so an absent collision warning means UNKNOWN here, not clear. Check by hand before assuming nobody else is in this file:  pwsh -NoProfile -File scripts\coord\overlap.ps1"
            }
        }
        [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    }
    exit 0
}

$target = $PathOverride
if (-not $target) {
    if (-not [Console]::IsInputRedirected) { exit 0 }
    try { $hook = [Console]::In.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop } catch {
        Write-Unresolved "payload-unreadable" `
            "the PreToolUse payload on stdin was not readable JSON, so the gate never learned which file this edit targets"
    }
    # Parsed, but to nothing. An empty payload or a literal `null` on stdin does not throw, so this
    # used to be the one unreadable-input path that still exited silently -- the gate had learned no
    # more than in the case above, and said no more than an all-clear.
    if (-not $hook) {
        Write-Unresolved "payload-empty" `
            "stdin carried no PreToolUse payload, so the gate never learned which file this edit targets"
    }
    $target = [string]$hook.tool_input.file_path
    # NotebookEdit and some variants name the path differently; absence just means nothing to check.
    if (-not $target) { $target = [string]$hook.tool_input.notebook_path }
}
if (-not $target) { exit 0 }

if (-not (Test-Path -LiteralPath $OverlapScript)) {
    Write-Unresolved "overlap-missing" "no overlap script at $OverlapScript"
}

$raw = $null
$code = 0
# -TimeBudgetSeconds is passed unconditionally rather than probed for. The installed shim resolves BOTH
# this gate and its callee from the same checkout (docs/WORKTREES.md, "which copy runs"), so they move
# together; a copy that predates the parameter fails the invocation, which lands on the unresolved
# notice below -- loud and allowing, which is this gate's posture for everything it cannot check.
try {
    $raw = & pwsh -NoProfile -NonInteractive -File $OverlapScript `
        -File $target -Json -TimeBudgetSeconds $OverlapTimeBudgetSeconds 2>$null
    $code = $LASTEXITCODE
} catch {
    Write-Unresolved "overlap-threw" "invoking the overlap script raised: $($_.Exception.Message)"
}
# EXIT 3 IS THE BUDGET. Measured 2026-08-22: the walk cost ~12 s across 73 worktrees, under a harness
# timeout of 20 s that kills THIS process when it fires -- and a killed PreToolUse hook writes nothing,
# which on stdout is byte-identical to "checked, nobody else is touching this file". overlap.ps1 bailing
# out under its own budget converts that silence into an exit code. If the budget is hit routinely the
# answer is to make the walk cheaper, not to raise the number past the harness's.
#
# A PARTIAL MAP IS NOW USED, NOT DISCARDED, and the rule governing it is one sentence: it may only ADD
# a deny, never remove one. Measured 2026-08-30 at 162 worktrees, the walk took 26.1 s and bailed on
# five runs of five -- so this gate spent that period allowing every edit against a map it threw away,
# including the peers overlap.ps1 had already found. Reading the walked half costs nothing and can only
# catch collisions that were previously dropped; every path below that would ALLOW on a partial map
# still goes through the unresolved notice, so a short walk can never render as an all-clear.
$partial = ($code -eq 3)
if ($code -ne 0 -and -not $partial) {
    Write-Unresolved "overlap-failed" "the overlap script exited $code"
}

# EMPTY OUTPUT IS NOT AN ANSWER. Under -Json a resolved "nobody else is in this file" is the two bytes
# `[]`; nothing at all is a script that never produced a verdict. Folding those together is precisely
# how this gate came to report all-clear while checking nothing.
$slowDetail = "the overlap walk did not finish within its ${OverlapTimeBudgetSeconds}s budget, so the map below covers only the worktrees it reached and the rest were never looked at"

$text = (@($raw) -join "`n").Trim()
if (-not $text) {
    # A PARTIAL WALK THAT REACHED NOTHING prints nothing rather than "[]" -- overlap.ps1 reserves "[]"
    # for a COMPLETE walk that found nobody, so the two cannot be confused here. Order matters: test
    # the budget first, or a short walk gets reported as a broken script.
    if ($partial) { Write-Unresolved "overlap-slow" $slowDetail }
    Write-Unresolved "overlap-empty" "the overlap script produced no output at all (a resolved 'nobody else' is '[]', not nothing)"
}

$rows = @()
try { $rows = @($text | ConvertFrom-Json -ErrorAction Stop) } catch {
    Write-Unresolved "overlap-unparseable" "the overlap script's output was not JSON"
}

# COVERAGE, IF THE MAP CARRIES IT. Every row of a partial map is stamped with the same Walked/Total, so
# any one of them answers "how much of the map is this". Naming the numbers matters more than naming the
# condition: "covering 26 of 163" tells a reader how much is unknown, where a bare "partial" invites
# them to assume it was nearly done -- and on the measured runs it was not.
if ($partial -and $rows.Count -gt 0 -and $null -ne $rows[0].PSObject.Properties['Total']) {
    $slowDetail = "the overlap walk did not finish within its ${OverlapTimeBudgetSeconds}s budget, " +
        "covering $(Get-SafeForMessage $rows[0].Walked) of $(Get-SafeForMessage $rows[0].Total) worktrees. " +
        "Those were checked; the rest were never looked at"
}

$live = @($rows | Where-Object { $_.Live })

# DENY ONLY ON AN UNCOMMITTED EDIT IN A LIVE WORKTREE. `Files` is the union of what a branch COMMITTED
# and what is dirty in its tree, so a session that committed a file, went clean and finished still
# appears here -- and a committed file stays until the branch LANDS. Reported 2026-08-01 with a repro:
# a session committed a file, confirmed in writing it was done, and the peer it handed off to was still
# refused. While PRs cannot merge, "until it lands" is indefinite, so the blocked set only ever grows.
# That is this gate's own stated failure mode -- "a gate that cries wolf gets uninstalled".
#
# MatchedDirty is the narrower predicate and it is exactly the question being asked: is someone editing
# this file NOW. A row lacking the property (a stale overlap cache written before this change) is
# treated as dirty, so the gate degrades to its previous over-blocking behaviour rather than silently
# permitting a real collision -- over-block is safe, under-block is a silent collision.
$editing = @($live | Where-Object { $null -eq $_.PSObject.Properties['MatchedDirty'] -or $_.MatchedDirty })
if ($editing.Count -eq 0) {
    # EVERY OUTCOME BELOW THIS POINT ALLOWS THE EDIT, which is exactly the set of outcomes a partial map
    # is not entitled to reach quietly. The deny above stands on the walked half alone -- a collision
    # found is a collision, however little else was checked -- but "nobody is in this file" is a claim
    # about the WHOLE map, and a short walk has not earned it. So say so instead of exiting silently.
    if ($partial) { Write-Unresolved "overlap-slow" $slowDetail }
    # Nobody live at all, or the only rows are dormant worktrees: worth knowing, not worth blocking.
    if ($live.Count -eq 0) { exit 0 }

    # Committed-and-clean in every live worktree: report it, do not block. The peer may well have
    # already done what you are about to do, which is worth knowing and not worth refusing over.
    #
    # LABEL THE ID, AND HAND OVER THE BRANCH (BACKLOG #1310). Measured 2026-08-22: this sentence named
    # a peer as "80c88a83 [claude/<peer-branch>]" and its reader took the leading token for an
    # abbreviated commit hash. Reasonably so -- the verb is "CHANGED AND COMMITTED", the noun beside it
    # is "branch", the remediation said "check its commits", and this repo prints REAL short hashes in
    # exactly this `<hex> [<branch>]` shape elsewhere (prune-merged.ps1, rescue.ps1). They searched
    # three separate object stores, found it in none of them, and concluded the gate had invented a
    # revision. It had not, and it could not have: `Short` is the first eight characters of a registry
    # session UUID (overlap.ps1), so it is hex by construction. No git revision is read in this code
    # path at all.
    #
    # #1310 asks for `session=<id>` and this prints `session <id>`, which is the idiom already shipped
    # at overlap.ps1's single-file printer and session-context.ps1's roster and reads better inside a
    # sentence. The divergence lands on the ITEM, not on the code: #1310's stated check is a grep for
    # `session=`, and that grep asks about this FILE, not about what the gate PRINTS. Every hit it
    # returns is a COMMENT line, the ones you are reading among them -- which is how the sentence that
    # used to stand here, "still returns 0 against this file", was falsified by the paragraph written
    # to explain it. Nothing this gate emits contains `session=` anywhere, so that count moves when
    # this prose is re-worded and never when the printed text changes. DO NOT RESTATE THE COUNT HERE:
    # the first correction to this paragraph quoted its own fresh number and was wrong by one on the
    # line that quoted it. tests/test_collision_gate.py checks the PROPERTY instead -- no hex-shaped
    # token in the emitted text without the word in front of it -- and is the check to run in its
    # place.
    #
    # The word goes on the ROW rather than into a legend -- these rows are not uniform, so a legend
    # could not govern every one of them.
    #
    # VERIFYING THE VALUE AS A REVISION IS NOT THE FIX. `git cat-file -e` answers "is this string a git
    # object" when the question is "what KIND of identifier is this", and it answers NO for every real
    # session id -- so guarding on it would suppress the peer's identity and restore the silence. A
    # prefix that happened to collide with one of this repo's objects would then be printed as a
    # VALIDATED revision, which is worse than the ambiguity it replaced. That collision is also why the
    # notice claims the id IS a session id rather than claiming it RESOLVES to nothing: the first is
    # unconditionally true, and the second is the sentence a curious reader can catch out by running
    # `git show` and finding an unrelated object. A control disbelieved on a detail is disbelieved.
    #
    # THE BRANCH IS THE ACTIONABLE HALF. `git log` takes a branch and takes no session id, which is
    # exactly why "check its commits" pointed that reader at the one identifier they could not use. It
    # is emitted through Get-SafeForCommand, quoted, and NOT as a `<that branch>` placeholder the reader
    # fills in from the clause above -- see the note on that helper for why a placeholder next to a
    # printed refname is an interpolation with an extra step.
    #
    # A GLOB PATHSPEC, not the bare leaf. `git log -- overlap.ps1` matches nothing: pathspecs are
    # anchored at the repo root, so the leaf this notice prints resolves to zero commits -- and an empty
    # `git log` reads as "the peer has no commits here", which is the exact false conclusion this notice
    # exists to prevent, reached through a command the gate supplied. Verified in this repo: the leaf
    # returns 0 lines and '*<leaf>' returns the real commits.
    $names = (@($live | ForEach-Object {
                "session $(Get-SafeForMessage $_.Short) on branch $(Get-SafeForMessage $_.Branch)" }) -join '; ')
    $leafQ = Get-SafeForCommand (Split-Path $target -Leaf) -Prefix '*'
    $cmds = (@($live | ForEach-Object {
                "  git log --oneline $(Get-SafeForCommand $_.Branch -Prefix 'origin/main..') -- $leafQ" }) -join "`n")
    [Console]::Out.Write((@{
                hookSpecificOutput = @{
                    hookEventName     = "PreToolUse"
                    additionalContext = "[collision] $(Get-SafeForMessage (Split-Path $target -Leaf)) was already CHANGED AND COMMITTED in another LIVE session's worktree ($names), whose tree is now clean. Not blocking -- but that work may overlap yours. Each id above is a coordination-registry session id and NOT a commit -- do not look one up as a revision. Read the BRANCH beside it instead, before you duplicate or revert what is on it:`n$cmds"
                }
            } | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

$leaf = Get-SafeForMessage (Split-Path $target -Leaf)
$lines = @("$leaf has UNCOMMITTED changes in another LIVE session's worktree -- editing it now means one of you loses work at merge.", "")
foreach ($r in $editing) {
    # "session" for the same reason as the notice above (BACKLOG #1310): unlabelled, this row leads
    # with an 8-hex token immediately before a bracketed branch, the shape of an abbreviated hash.
    $lines += "  session $(Get-SafeForMessage $r.Short) ($(Get-SafeForMessage $r.Surface)) in " +
              "$(Get-SafeForMessage $r.Worktree) [$(Get-SafeForMessage $r.Branch)]"
    foreach ($w in @($r.Work | Select-Object -First 2)) {
        $lines += "      building: $(Get-SafeForMessage $w)"
    }
}
$lines += ""
# A DENY OFF A PARTIAL WALK IS STILL A DENY, and the reader is told which kind they are holding. It
# cuts one way only: what was found is real, and the unwalked worktrees may hold more of the same.
if ($partial) {
    $lines += "This was found in a PARTIAL check -- $(Get-SafeForMessage $slowDetail). More peers may be in this file."
    $lines += ""
}
$lines += "Before overriding: that session may already be doing what you are about to do."
$lines += "  see everything in flight :  pwsh -NoProfile -File scripts\coord\overlap.ps1"
$lines += "  who is live              :  pwsh -NoProfile -File scripts\coord\presence.ps1"
$lines += "If you genuinely need this file, coordinate first -- or edit a different one."

Deny ($lines -join "`n")
