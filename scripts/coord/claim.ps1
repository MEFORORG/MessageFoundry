# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Claim a piece of WORK, atomically, so two concurrent sessions cannot build the same thing twice.

.DESCRIPTION
    `alloc.ps1` stops two sessions taking the same ADR/BACKLOG *number*. This stops them doing the same
    *work* -- a different failure, and one that has cost real rework here. On 2026-07-24 three sessions
    independently fixed the same npm advisory; two of the three PRs were closed as duplicates, and the one
    that merged had NOT tested the failure mode the others found, so it put a latent break on main.

    A claim is a free-text KEY, deliberately not just a backlog number:

        claim.ps1 -Take 105                          # a numbered backlog item
        claim.ps1 -Take npm-audit-brace-expansion    # ad-hoc work that has no number

    The number form is what the commit-msg gate enforces (see scripts/hooks/claim_check.py). The free-text
    form is what catches the case that actually bit us -- unnumbered work nobody thought to coordinate.

    Same test-and-set as alloc.ps1, for the same reason: it claims by EXCLUSIVELY CREATING
    <git-common-dir>/mefor-coord/claims/<key>.json, an atomic NTFS operation. A read-modify-write on a
    shared list is not an option (PowerShell was measured silently losing 4 of 8 concurrent writes).

    Claims are ADVISORY for free-text keys and ENFORCED for numbered ones. Neither can stop a session that
    refuses to look; what they buy is that the collision becomes visible BEFORE the work, not after.

    Releasing is manual and claims do NOT expire: an abandoned claim is a stale note, whereas an
    auto-expiring one silently re-opens the race it exists to prevent. `-List` reports each holder's
    LIVENESS -- worktree gone, or hours since its last commit -- not the claim's age. Age was the
    original signal and it was actively misleading: a 21h claim whose holder had committed two minutes
    earlier was labelled STALE and recommended for release.

    EVERY RELEASE IS RECORDED, `-Force` included, as one JSON line appended to
    <git-common-dir>/mefor-coord/claims/.history: at least the key, the releasing worktree and branch,
    the tree the command was actually invoked FROM (`invoked_from`, BACKLOG #1358), the prior holder,
    its branch and note, when the claim was taken, and whether -Force was used. The record is written
    BEFORE the claim file is removed and the release is refused if it cannot be written -- a release
    nobody can trace is the outcome this will not produce (BACKLOG #1068).

    `released_by` and `invoked_from` answer different questions and routinely differ: the first is the
    tree the claim is held in the name of, the second is where the operator's shell was. Read them as a
    PAIR -- a release where they diverge was performed on another tree's behalf.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\claim.ps1 -Take 105 -Note "corepoint xml importer"
    pwsh -NoProfile -File scripts\coord\claim.ps1 -List
    pwsh -NoProfile -File scripts\coord\claim.ps1 -Release 105
#>
[CmdletBinding()]
param(
    # Claim this key for THIS worktree. Idempotent: re-taking a key you already hold refreshes its note
    # and branch in place (never dropping the claim), rather than failing.
    [string]$Take,
    # Release a claim this worktree holds.
    [string]$Release,
    # Show every active claim (default when no other switch is given).
    [switch]$List,
    # What the work is -- recorded so a sibling session sees WHY the key is taken.
    [string]$Note,
    # Release a claim held by ANOTHER worktree (for a session that died without releasing).
    [switch]$Force,
    # Hold the claim in the name of THIS tree instead of the one this script lives in (BACKLOG #1346).
    #
    # ONE VALUE USED TO ANSWER TWO QUESTIONS -- *where the registry is* and *who holds the claim* -- and
    # inside a single repository those are always the same tree, so the conflation was invisible. Across
    # two repositories that share a registry they diverge, and there was no way to say "the tool lives
    # over there, the committing tree is here". `scripts/hooks/claim_check.py` compares the record's
    # worktree against the tree being committed, so without this the gate in a second repository refused
    # a claim that had just been taken for it.
    #
    # THIS IS NOT A RETREAT FROM THE $PSScriptRoot ANCHORING (BACKLOG #1060). That defect was a SILENT
    # read of the caller's cwd; this is an explicit argument, recorded in the claim, printed back on
    # every surface that shows a holder. Nothing changes unless someone asks for it.
    [string]$AsWorktree,
    # Also ask the NETWORK for merged-work evidence on a directory-only claim (BACKLOG #1466): whether
    # the holder's branch is on origin right now (`git ls-remote`) and whether it has a pull request
    # (`gh`, when installed and signed in). Off by default, so `-List` stays offline. Each lookup is
    # time-boxed, and a failure or timeout prints "unknown", never a guess.
    [switch]$Online
)

$ErrorActionPreference = "Stop"

# Anchored on the SCRIPT, not the current directory -- the reasoning is written out once, at the head of
# alloc.ps1 (BACKLOG #1060). It applies here identically and was found here by inspection rather than by
# a second reproduction: this file recorded `worktree = $repo` from the same unanchored call, so an
# absolute `-File` invocation from another worktree took the claim in the caller's name. A claim is
# advisory for free-text keys and ENFORCED for numbered ones by scripts/hooks/claim_check.py, which reads
# the repo from cwd correctly because it runs as a commit hook -- cwd IS the committing worktree there.
# Hook right, tool wrong, and only the tool can be invoked from somewhere else.
$repo = (& git -C $PSScriptRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
if (-not $repo) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }

# Occupancy is what lets a holder that is a DIRECTORY be told apart from one that is a SESSION
# (BACKLOG #1348). Loaded best-effort and NEVER fatal: if this fails, Get-HolderLiveness keeps its
# older, stricter meaning and refuses, which is the safe direction. Dot-sourced at script scope
# because functions sourced inside a function do not survive it.
try { . "$PSScriptRoot/occupancy.ps1" } catch { }
$repo = $repo.Trim()

# WHO HOLDS THE CLAIM, which is a different question from where this script lives (BACKLOG #1346).
# Defaults to $repo, so every existing invocation behaves exactly as it always has.
$holder = $repo
if ($AsWorktree) {
    $holderTop = (& git -C $AsWorktree rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $holderTop) { throw "-AsWorktree '$AsWorktree' is not inside a git repository." }
    # Its TOPLEVEL, not the string as typed: a subdirectory, a trailing slash or a relative path would
    # otherwise be recorded verbatim, and the gate compares this field against `git rev-parse
    # --show-toplevel` in the committing tree. A record that cannot match is a claim nothing honours.
    $holder = $holderTop.Trim()
}

# WHERE THE SHELL IS STANDING -- a THIRD question, and the one nothing recorded (BACKLOG #1358).
#
# $repo answers *where this copy of the script lives*; $holder answers *who the claim is for*. Neither
# answers *who ran this*, and inside a single checkout all three are the same directory, which is why
# the gap stayed invisible for as long as it did.
#
# Returns $null rather than a guess when the shell is not inside a repository at all. An empty string
# would land in the release record looking like a tree whose path is "", and a record that invents a
# value is the failure this whole item is about.
#
# THIS IS NOT A RE-ANCHORING (BACKLOG #1060). Nothing here decides where the registry lives, who owns a
# claim, or which tree a release is judged against -- every one of those still comes from $PSScriptRoot
# by way of $repo/$holder. This value is written down and never acted on.
function Get-CallerTree {
    $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $top) { return $null }
    return $top.Trim()
}

# ONE divergence test, three call sites (BACKLOG #1358). The note used to be written inline at the very
# end of the script, which put it after the `-Take` success block and therefore made it UNREACHABLE from
# `-Release` -- the script stated the release rule at claim time and went silent at the moment the
# operator applied it. `$Subject` is the only part that varies, because the true sentence differs: a take
# is recorded to $repo, whereas a release is BOTH recorded to it and adjudicated against it.
#
# Deliberately reads $holder at CALL time from script scope rather than taking it as a parameter: a
# second copy of "which tree is this" is exactly the drift this note exists to report.
#
# Compares against $holder, not $repo. The note exists to warn that the claim is being recorded against a
# tree the operator is not standing in -- so once `-AsWorktree` names the tree they ARE standing in, there
# is no divergence left to warn about and firing anyway would be a false alarm on the correct usage.
function Write-DivergenceNote([Parameter(Mandatory)][string]$Subject) {
    # Get-CallerTree, not a second copy of the same read: the note and the release record must agree
    # about where the shell was, and two spellings of one question is how they stop agreeing.
    $cwdTop = Get-CallerTree
    if (-not $cwdTop) { return }
    $a = ($cwdTop -replace '\\', '/').TrimEnd('/')
    $b = ($holder -replace '\\', '/').TrimEnd('/')
    if ($a -ieq $b) { return }
    Write-Host "  NOTE: your shell is in $a, but this claim is recorded against $b," -ForegroundColor Yellow
    Write-Host "        so the $Subject" -ForegroundColor Yellow
}

# WHERE THE REGISTRY LIVES, resolved from the repository the claim is FOR (BACKLOG #1346).
#
# Anchored on $holder rather than $repo so that the tool and `scripts/hooks/claim_check.py` resolve from
# the SAME tree. The gate reads this key in the repository being committed; if the tool read it anywhere
# else the two could disagree, and a claim written where the gate never looks is the unpassable state this
# fixes. `mefor.claimsRoot` is unset in this repository, so the ordinary path is unchanged: $holder's own
# common dir, exactly as before.
#
# ONE HOP. If the host repository sets the key too, its own gate follows the same single hop, so both
# sides still land together and a chain cannot split them.
$registryRepo = $holder
$claimsRoot = $null
try { $claimsRoot = (& git -C $holder config --get mefor.claimsRoot 2>$null) } catch { $claimsRoot = $null }
if ($claimsRoot) {
    $claimsRoot = $claimsRoot.Trim()
    $rootTop = (& git -C $claimsRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
    # THROW rather than fall back. A silent fallback would write this claim into a registry the gate does
    # not read, which looks like success and refuses at commit time with no way to see why -- the exact
    # shape of #1346.
    if (-not $rootTop) {
        throw "mefor.claimsRoot in $holder names '$claimsRoot', which is not a git repository. Fix it with: git -C $holder config mefor.claimsRoot <path>"
    }
    $registryRepo = $rootTop.Trim()
}

$common = (& git -C $registryRepo rev-parse --path-format=absolute --git-common-dir).Trim()
$claims = Join-Path $common "mefor-coord/claims"
New-Item -ItemType Directory -Force -Path $claims | Out-Null

# THE RELEASE LEDGER (BACKLOG #1068). A release used to be `Remove-Item` and nothing else, so a
# `-Force` takeover -- one session releasing a claim held by another -- left no record of who released
# whose claim, when, or why. `-Force` has a real job and stays: a claim whose holder's worktree is
# gone would otherwise be stuck forever, and hand-deleting the file leaves even less evidence. The
# answer is a RECORD, not a refusal.
#
# Measured 2026-08-10. A coordinator force-released a claim after establishing on evidence that the
# holder's worktree was gone and that the work its note guarded had already merged, while the note
# still read "UNPUSHED, NO PR, GitHub finds NOTHING". That release was CORRECT and it left nothing
# behind to find, which is the whole gap: the registry is a shared coordination artifact, and a stale
# note in it has already blocked a lane from claiming an item.
#
# JSON Lines, LF-terminated, one object per release. It sits INSIDE the claims directory, which is
# safe because every reader of that directory keys on a file NAME -- `-List` and prune-merged.ps1 glob
# `*.json`, scripts/hooks/claim_check.py opens `<item>.json` -- and ConvertTo-KeyFile always appends
# ".json", so no key can ever fold onto this name.
$history = Join-Path $claims ".history"

# A key is free text but becomes a FILENAME, so fold it to a safe, case-insensitive form. The original is
# kept inside the json so `-List` can show what the human actually typed.
function ConvertTo-KeyFile([string]$Key) {
    $safe = ($Key.Trim().ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim('-')
    if (-not $safe) { throw "Key '$Key' reduces to nothing usable -- pick something with letters or digits." }
    $safe
}

# ConvertFrom-Json SILENTLY COERCES an ISO-8601 string into a [datetime], so `[string]$c.claimed` does
# not give you back what was written -- it gives the local short form ("08/01/2026 23:17:46"), losing
# the sub-second precision and the UTC offset. Writing that back would quietly downgrade the stamp on
# every refresh, and it would still parse, so nothing would ever complain. Round-trip it instead.
function ConvertTo-Stamp($Value) {
    if ($Value -is [datetime]) { return $Value.ToString("o") }
    if ($Value -is [datetimeoffset]) { return $Value.ToString("o") }
    return [string]$Value
}

function Get-Mine([string]$Path) {
    $c = Get-Content $Path -Raw | ConvertFrom-Json
    $held = ($c.worktree -replace '\\', '/').TrimEnd('/')
    $me = ($holder -replace '\\', '/').TrimEnd('/')
    [pscustomobject]@{ Claim = $c; IsMine = ($held -ieq $me) }
}

# ONE record, appended exclusively, retried. FileMode::Append + FileShare::Read excludes a second
# WRITER -- two worktrees can release in the same instant -- while leaving readers alone, and the whole
# line goes out in a SINGLE Write to a handle already positioned at end-of-file, so a concurrent
# release cannot interleave half a record into another's.
#
# LF, not the platform newline: this is a machine-readable ledger read from PowerShell, python and
# git-bash on the same clone, and a mixed-newline JSONL file is one of those things nothing complains
# about until a parser splits differently from the writer.
#
# The catch is deliberately UNTYPED, for the reason written out at the claim-refresh Move below:
# PowerShell wraps an exception thrown by a .NET METHOD in a MethodInvocationException, so a typed
# `catch [System.IO.IOException]` here would never match and the failure would escape to
# $ErrorActionPreference = "Stop" instead of being retried.
function Add-HistoryLine([string]$Line) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Line + "`n")
    foreach ($attempt in 1..5) {
        try {
            $fs = [System.IO.File]::Open($history, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            return $true
        }
        catch { Start-Sleep -Milliseconds (20 * $attempt) }
    }
    return $false
}

# ONE liveness rule, three call sites (BACKLOG #345 Half B).
#
# `-List` learned this first, and that was the wrong half to fix alone: -List is where you BROWSE, and
# `-Take`/`-Release` are where you are STOPPED. Both blocking paths printed the same "held by another
# worktree" block whether the holder had been deleted, had died, or was committing that minute -- and
# `-Release` went further and RECOMMENDED `-Force` ("If that session is gone...") on a holder it had
# never looked at. Advice that cannot distinguish the two cases is advice to guess, and the guess that
# frees a live session's key causes the duplicate build this whole registry exists to prevent.
#
# Reports only what it can PROVE. A vanished directory is a fact and the one state safe to act on
# unasked. Everything else is 'unknown' or a quiet-hours count -- never "probably fine": a session can
# be alive and simply not committing, so silence is not evidence of death.
# A DIRECTORY IS NOT A PERSON, AND THIS FUNCTION USED TO CONFLATE THEM (BACKLOG #1348).
#
# `present` meant "the path exists". It never asked whether a SESSION was in it, so a worktree that
# outlived its session -- the directory still on disk, nobody in it -- rendered identically to a
# lane that is actively building. That is a THIRD state the tool could not represent, and it is the
# one that produces work that is done, correct, and held by nobody: the sanctioned verbs refuse, and
# the holder is not present to release it.
#
# THAT SENTENCE USED TO END "`-Force` is forbidden by CLAUDE.md, and the claim cannot be regularised
# by anything." BOTH HALVES WERE FALSE, and the first was falsifiable in one grep. CLAUDE.md contains
# no prohibition on this or any `-Force` switch: its only force-related rules are about `git push
# --force` and `reset --hard` (section 5, "Ask before irreversible or outward-facing actions").
# Measured with `no-verify` as a positive control so a broken search could not read as a clean one.
#
# The second half was refuted by THIS FILE, 100 lines down: the `gone` branch prints
# "[HOLDER GONE -- worktree no longer exists; release with -Force]", and the header at the top states
# that every release is recorded, `-Force` included, with whether it was used. `docs/WORKTREES.md`
# describes `-Release <key> -Force` as the ordinary by-hand remedy for exactly this stranded claim.
#
# WHY A WRONG COMMENT HERE COSTS MORE THAN A WRONG COMMENT USUALLY DOES. It does not merely misinform;
# it tells a reader that the documented remedy for the state they are standing in is BANNED, and it
# cites the project's own conventions file as the authority. A session that believes it will not run
# the verb, will not look for the rule, and will leave real work stranded -- which is the exact
# outcome this block was written to prevent.
#
# WHAT IS ACTUALLY TRUE: `-Force` is available, audited, and sometimes correct. That is all this
# paragraph is entitled to say.
#
# NO RULE ANYWHERE PROHIBITS `-Force` ON A JUDGEMENT THIS FILE HAS NOT MADE, and the first draft of
# this replacement quietly invented one. It asserted that "what is forbidden is reaching for it
# without the evidence" and grounded that in `occupancy.ps1`. Read what occupancy.ps1 actually says:
# "Occupancy may therefore only ever VETO an action; a DEAD/STALE/absent verdict must never by itself
# authorise one." That governs what an OCCUPANCY VERDICT may authorise. It says nothing about this
# verb. Treating it as a prohibition on `-Force` is a defensible ANALOGY and it is not a stated rule,
# so the honest form is: this file extends that reasoning by analogy, and the extension is this
# comment's, not occupancy.ps1's. Caught in review. It is the SAME DEFECT CLASS the paragraph above
# is fixing -- asserting a prohibition and citing a source that does not contain it -- in a milder
# form, written by the change that was fixing it. That is how durable this failure mode is.
#
# AND THIS BLOCK STILL DOES NOT ANSWER THE QUESTION A READER IN THIS STATE IS ASKING. `unoccupied`
# is precisely NOT `gone`: that distinction is the whole reason the third state exists. The `gone`
# branch can recommend `-Force` because the worktree is provably absent. `unoccupied` means the
# directory is there and nobody is in it, which this host cannot distinguish from a session that is
# merely quiet -- so the evidence that would justify a release is exactly what is missing. A reader
# standing in `unoccupied` gets an accurate description here and no remedy, and that gap is REAL and
# currently unresolved rather than an oversight in the wording. Do not read this block as resolving
# it. If you are stuck there, the question is a live one and belongs in the ledger, not in a guess.
#
# ***THE NEW STATE REPORTS. IT DOES NOT PERMIT.*** `unoccupied` still REFUSES, exactly as `present`
# does, and this is not timidity -- `occupancy.ps1` states the rule it inherits: "there is no
# heartbeat on this host, so nothing here can prove a session is GONE. Occupancy may therefore only
# ever VETO an action; a DEAD/STALE/absent verdict must never by itself authorise one." What the
# item asked for is that the two be DISTINGUISHABLE, not that the second become releasable.
#
# POLARITY, and it is the same rule the blanket-stage guard carries (#1341, #1229): recognition may
# only ever SUPPRESS. Downgrading to `unoccupied` requires a POSITIVE determination -- the occupancy
# probe loaded, reported itself Available, and returned zero vetoing sessions for that exact path.
# Every other outcome, including the probe failing to load at all, stays `present`. A missing
# answer must cost a refusal, never a licence.
$script:OccupancyProbe = $null   # $null = not yet tried; $false = unavailable; else the object

function Get-OccupancyOnce {
    if ($null -ne $script:OccupancyProbe) { return $script:OccupancyProbe }
    try {
        if (-not (Get-Command Get-WorktreeOccupancy -EA SilentlyContinue)) {
            $script:OccupancyProbe = $false
            return $false
        }
        $occ = Get-WorktreeOccupancy -Repo $repo
        # `Available` false means the fence could not be built -- an unplaceable record, no repo.
        # Treat that exactly like a failed probe.
        $script:OccupancyProbe = if ($occ -and $occ.Available) { $occ } else { $false }
    }
    catch { $script:OccupancyProbe = $false }
    return $script:OccupancyProbe
}

function Get-HolderLiveness([string]$HeldPath) {
    try {
        if (-not (Test-Path -LiteralPath $HeldPath)) {
            return [pscustomobject]@{ State = 'gone'; QuietHours = $null; Occupants = $null }
        }
        $ct = & git -C $HeldPath log -1 --format=%ct 2>$null
        if ($ct) {
            $quiet = [int]((Get-Date) - [System.DateTimeOffset]::FromUnixTimeSeconds([long]$ct).LocalDateTime).TotalHours
            $occ = Get-OccupancyOnce
            if ($occ) {
                $who = @(Get-WorktreeOccupants -Occupancy $occ -Path $HeldPath)
                if ($who.Count -eq 0) {
                    return [pscustomobject]@{ State = 'unoccupied'; QuietHours = $quiet; Occupants = 0 }
                }
                return [pscustomobject]@{ State = 'occupied'; QuietHours = $quiet; Occupants = $who.Count }
            }
            # PROBE UNAVAILABLE -> `present`, which keeps its PRE-#1348 meaning exactly: the path is
            # there and that is all this function knows. It still refuses.
            #
            # THIS SPLIT IS A BUG FIX, NOT A TIDY-UP. The first version of #1348 returned `present`
            # for BOTH "the probe looked and found an occupant" and "the probe could not look", and
            # then labelled `present` "LIVE SESSION in the holder". On a machine with no Claude
            # config root -- every CI runner -- the probe reports Available=false, so the fallback
            # fired and the tool ASSERTED A LIVE SESSION IT HAD NEVER OBSERVED. Caught by the
            # required windows-2025 leg on PR 585, three tests, deterministic rather than flaky.
            #
            # One state cannot mean both "I measured this" and "I could not measure this", and the
            # deny text is where that conflation becomes a false statement to an operator. `occupied`
            # is now the only state that claims a session, and it is reachable only through a probe
            # that returned Available with a vetoing occupant for this exact path.
            return [pscustomobject]@{ State = 'present'; QuietHours = $quiet; Occupants = $null }
        }
        # Present on disk but no commit to date it by -- a brand-new worktree looks exactly like this.
        return [pscustomobject]@{ State = 'unknown'; QuietHours = $null; Occupants = $null }
    }
    catch {
        # Say so rather than returning 'gone'. A failed probe that reported death would turn an
        # unreadable path into a licence to release someone's live claim.
        return [pscustomobject]@{ State = 'failed'; QuietHours = $null; Occupants = $null }
    }
}

# MERGED-WORK EVIDENCE FOR A DIRECTORY-ONLY HOLDER (BACKLOG #1466).
#
# `unoccupied` is the state with no remedy on this host: the directory is there, nobody is placed in
# it, and nothing can prove the session gone. What a reader there lacked was not a verb -- `-Force`
# exists -- but any FACT to ground a decision on. The cheapest fact available offline is whether the
# holder's branch still carries committed work that origin/main lacks -- the work a release could
# leave with nobody claiming it.
#
# ***EVIDENCE, NOT AUTHORITY.*** Nothing below changes a refusal or recommends `-Force`. Landed work
# does not prove the session gone either -- a live session can still be building on a merged branch --
# so it is printed for the owner, whose call a directory-only claim remains. Treating it as a third
# thing that settles the claim would be the automatic release this item declined.
#
# WHAT IT CAN SAY, AND WHAT IT CANNOT. It answers "does the branch carry work origin/main lacks?".
# It does NOT answer "did THIS claim's work land": a branch that pulled main, or a reused branch whose
# earlier work was squash-merged, also carries nothing main lacks, so no verdict below says "landed".
# Pull requests here are SQUASH-merged, so a branch whose content is on main is usually NOT an
# ancestor of it; `git merge-tree` catches that shape by asking whether merging the branch would
# change origin/main at all. Whether anything was committed after the claim is folded in, because a
# branch with nothing built on it carries nothing main lacks, trivially.
#
# BATCHED, BECAUSE A GIT CALL IS THE COST. Measured 2026-09-26 under fleet load: one `git rev-parse`
# took over a second and one `merge-tree` five, while `-List` already spends a git call per claim. So
# this makes a fixed handful of calls per REPOSITORY, never one per claim: `worktree list` for every
# holder's HEAD and branch, one `for-each-ref` with `ahead-behind` for every branch, and one
# `merge-tree --stdin` for every branch that is ahead. A holder can sit in another repository when
# mefor.claimsRoot shares the registry, so origin/main is always the HOLDER's repository's own.
# `merge-tree --write-tree` does write the merged trees into the object store as unreferenced loose
# objects, which `git gc` prunes; it moves no ref and touches no claim.
#
# Offline by default. `-Online` adds `git ls-remote` (once per repository) and `gh` (once per branch),
# each time-boxed, and the first TIMEOUT of either stops that tool for the rest of the run, so a dead
# network costs one timeout rather than one per claim. A plain failure is that one lookup's UNKNOWN.
$script:NetDown = @{}
$EvidenceTimeoutMs = 8000

function ConvertTo-PathKey([string]$Path) { ($Path -replace '\\', '/').TrimEnd('/').ToLowerInvariant() }

# Runs one network command with a hard deadline. $null means "no answer" -- missing tool, non-zero
# exit, timeout, anything -- and callers print that as unknown. An empty string is a real answer.
function Invoke-Bounded([string]$Exe, [string[]]$ArgList, [string]$Cwd) {
    if ($script:NetDown[$Exe]) { return $null }
    try {
        $cmd = Get-Command $Exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cmd) { $script:NetDown[$Exe] = $true; return $null }
        $psi = [System.Diagnostics.ProcessStartInfo]::new($cmd.Source)
        foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
        $psi.WorkingDirectory = $Cwd
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        # Nobody is there to answer a credential prompt, and one would hold the call to its deadline.
        $psi.Environment['GIT_TERMINAL_PROMPT'] = '0'
        $psi.Environment['GCM_INTERACTIVE'] = 'never'
        $psi.Environment['GH_PROMPT_DISABLED'] = '1'
        $psi.Environment['GIT_SSH_COMMAND'] = 'ssh -o BatchMode=yes'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $out = $p.StandardOutput.ReadToEndAsync()
        $null = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($EvidenceTimeoutMs)) {
            try { $p.Kill($true) } catch { }
            $script:NetDown[$Exe] = $true
            return $null
        }
        if ($p.ExitCode -ne 0) { return $null }
        # A grandchild can hold the pipe open after the process exits, so the read has a deadline too.
        $left = [Math]::Max(1000, $EvidenceTimeoutMs - [int]$sw.ElapsedMilliseconds)
        if (-not $out.Wait($left)) { $script:NetDown[$Exe] = $true; return $null }
        return $out.Result
    }
    catch { $script:NetDown[$Exe] = $true; return $null }
}

# origin's owner/name when origin is on GitHub, else $null -- the parse in
# scripts/worktree/prune-merged.ps1, with the https host anchored so a look-alike host cannot match. `gh` is always given `--repo` from this: this clone has more than
# one GitHub remote, and gh's own pick of a default is not guaranteed to be origin.
function Get-OriginSlug([string]$Repo) {
    $url = & git -C $Repo remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $url) { return $null }
    if ("$url".Trim() -match '^(?:https?://(?:[^/@]*@)?github\.com/|git@github\.com:|ssh://git@github\.com/)(?<o>[^/]+)/(?<r>[^/]+?)(?:\.git)?/?$') {
        return "$($Matches['o'])/$($Matches['r'])"
    }
    return $null
}

# One `git worktree list` per repository: every worktree it carries, with its HEAD and branch.
function Add-WorktreeIndex([string]$From, [hashtable]$Index) {
    $wt = $null
    foreach ($line in @(& git -C $From worktree list --porcelain 2>$null)) {
        if ($line -like 'worktree *') {
            $wt = [pscustomobject]@{ Repo = $From; Head = $null; Branch = $null }
            $Index[(ConvertTo-PathKey $line.Substring(9))] = $wt
        }
        elseif ($wt -and $line -like 'HEAD *') { $wt.Head = $line.Substring(5).Trim() }
        elseif ($wt -and $line -like 'branch refs/heads/*') { $wt.Branch = $line.Substring(18).Trim() }
    }
}

# The one-line verdict for a claim, from facts already gathered. $Ahead is commits on the branch that
# origin/main lacks ($null when git could not count them); $Merged is the tree merging them would
# produce, 'CONFLICT', or $null when merge-tree gave no answer for this head.
# $NonMerge is how many of those commits are not merges ($null when not counted).
function Format-LandedLine($Ahead, $HeadTime, $Claimed, $Merged, $Base, [string]$Short, $NonMerge = $null) {
    $at = "origin/main @$($Base.Short)"
    if ($null -eq $Ahead) { return "evidence: UNKNOWN -- git could not count branch head $Short against $at" }
    # Whole seconds on both sides, and a TIE COUNTS AS BEFORE: %ct has no fraction, and for a commit in
    # the claim's own second the safe reading is "nothing built", not "moved on".
    $claimedAt = [System.DateTimeOffset]::new(([datetime]$Claimed).ToUniversalTime()).ToUnixTimeSeconds()
    $after = ($HeadTime -gt $claimedAt)
    if ($Ahead -eq 0 -or ($Merged -and $Merged -eq $Base.Tree)) {
        if (-not $after -and $Ahead -eq 0) {
            return "evidence: NOTHING BUILT -- branch head $Short carries nothing $at lacks, and nothing was committed on it after the claim was taken"
        }
        if (-not $after) {
            return "evidence: NOTHING BUILT -- the branch has $Ahead commit(s) not on $at whose content is already there, all dated before the claim was taken"
        }
        # Merging main INTO the branch after the claim is the pulled-main case again, one commit ahead.
        if ($Ahead -gt 0 -and $NonMerge -eq 0) {
            return "evidence: NOTHING BUILT -- the branch's $Ahead commit(s) not on $at are all merges that add nothing to it"
        }
        if ($Ahead -eq 0) {
            return "evidence: ON MAIN -- branch head $Short carries nothing $at lacks (it is an ancestor) and moved after the claim; a merged branch and one that pulled main look the same"
        }
        return "evidence: CONTENT ON MAIN -- the branch has $Ahead commit(s) not on $at, but merging them changes nothing: their content is already there, the shape a squash merge leaves"
    }
    if ($null -eq $Merged) { return "evidence: UNKNOWN -- git merge-tree gave no answer for branch head $Short" }
    # A conflict is NOT "not on main": work that landed and was then edited on main conflicts too.
    # Measured on the live registry the day this was written -- #1127's branch conflicts with main
    # after its item merged -- so this says it cannot tell rather than picking the scarier verdict.
    if ($Merged -eq 'CONFLICT') {
        return "evidence: UNCLEAR -- the branch has $Ahead commit(s) not on $at, and they conflict with it; work that landed and was later edited looks the same, so this cannot say"
    }
    return "evidence: NOT ON MAIN -- the branch has $Ahead commit(s) whose changes are not on $at"
}

# Evidence lines for a SET of claims, keyed by each one's .Key. Per CLAIM, not per holder path: one
# worktree often holds several claims, and "committed after the claim" differs between them. Never throws: a
# failure is itself printed, because an evidence block that silently vanished would read as "nothing to
# report". -WithStatus adds a per-worktree `git status`, which costs a call per holder and so is only
# asked for where there is one holder (the -Release refusal).
function Get-LandedEvidenceSet($Holders, [switch]$WithStatus) {
    $out = @{}
    $index = @{}
    try { Add-WorktreeIndex $repo $index } catch { }
    $groups = @{}
    foreach ($h in $Holders) {
        $k = ConvertTo-PathKey $h.Path
        $out[$h.Key] = [System.Collections.Generic.List[string]]::new()
        if (-not $index.ContainsKey($k)) {
            # A holder in another repository (a shared registry): index THAT repository once.
            try {
                $top = & git -C $h.Path rev-parse --path-format=absolute --show-toplevel 2>$null
                if ($top) { Add-WorktreeIndex "$top".Trim() $index }
            }
            catch { }
        }
        $w = $index[$k]
        if (-not $w -or -not $w.Head) {
            # Never fall back to `git -C <path>`: a directory git no longer lists as a worktree resolves
            # to whatever checkout ENCLOSES it, which would report someone else's branch as this one's.
            $out[$h.Key].Add("evidence: UNKNOWN -- git does not list this directory as a worktree, so its branch cannot be read")
            continue
        }
        if (-not $groups.ContainsKey($w.Repo)) { $groups[$w.Repo] = [System.Collections.Generic.List[object]]::new() }
        $groups[$w.Repo].Add([pscustomobject]@{ Key = $h.Key; Path = $h.Path; Claimed = $h.Claimed; Head = $w.Head; Branch = $w.Branch; Ahead = $null; HeadTime = 0L; Merged = $null })
    }

    foreach ($r in $groups.Keys) {
        $items = $groups[$r]
        try {
            $names = @($items | Where-Object Branch | ForEach-Object Branch | Sort-Object -Unique)
            $patterns = @('refs/remotes/origin/main') + @($names | ForEach-Object { "refs/heads/$_"; "refs/remotes/origin/$_" })
            $fmt = '--format=%(refname)%09%(objectname)%09%(tree)%09%(committerdate:unix)%09%(ahead-behind:refs/remotes/origin/main)'
            $refs = @{}
            $refLines = @(& git -C $r for-each-ref $fmt @patterns 2>$null)
            $refsOk = ($LASTEXITCODE -eq 0)
            foreach ($l in $refLines) { $f = "$l" -split "`t"; $refs[$f[0]] = $f }
            $main = $refs['refs/remotes/origin/main']
            if (-not $refsOk -or -not $main) {
                # Two causes print the same empty answer, so tell them apart before saying which.
                $why = "this clone has no origin/main to compare against"
                if (& git -C $r rev-parse --verify -q refs/remotes/origin/main 2>$null) {
                    $why = "git could not compare branches here (for-each-ref failed; its ahead-behind field needs git 2.41 or later)"
                }
                foreach ($it in $items) { $out[$it.Key].Add("evidence: UNKNOWN -- $why") }
                continue
            }
            $base = [pscustomobject]@{ Main = $main[1]; Tree = $main[2]; Short = $main[1].Substring(0, 9) }

            foreach ($it in $items) {
                $b = if ($it.Branch) { $refs["refs/heads/$($it.Branch)"] } else { $null }
                if ($b -and $b[1] -eq $it.Head) {
                    $cnt = ($b[4] -split ' ')[0]
                    $ct = $b[3]
                }
                else {
                    # Detached, or a ref that moved under us: two direct calls, and rare.
                    $cnt = "$(& git -C $r rev-list --count "$($base.Main)..$($it.Head)" -- 2>$null)".Trim()
                    $ct = "$(& git -C $r log -1 --format=%ct $it.Head -- 2>$null)".Trim()
                }
                # [int]"" is 0, which would print a failed count as "nothing main lacks". Digits or unknown.
                if ("$cnt" -match '^\d+$' -and "$ct" -match '^\d+$') {
                    $it.Ahead = [int]$cnt
                    $it.HeadTime = [long]$ct
                }
            }

            # One merge-tree for every branch that is ahead. Output per merge, NUL-separated:
            # <1 clean|0 conflict>, <tree>, zero or more conflicted names, then an empty terminator.
            # Once per distinct head: several claims can share one holder.
            $aheadHeads = @($items | Where-Object { $_.Ahead -gt 0 } | ForEach-Object Head | Sort-Object -Unique)
            if ($aheadHeads) {
                $stdin = ($aheadHeads | ForEach-Object { "$($base.Main) $_" }) -join "`n"
                $raw = (@($stdin | & git -C $r merge-tree --stdin --no-messages --name-only --allow-unrelated-histories 2>$null) -join "`n")
                $tok = $raw -split "`0"
                $merged = @{}
                $i = 0
                foreach ($hd in $aheadHeads) {
                    # A merge git could not run at all ends the output early; every head after it stays
                    # unknown rather than being read as a conflict.
                    if ($i + 1 -ge $tok.Count -or $tok[$i] -notin @('0', '1')) { break }
                    $merged[$hd] = if ($tok[$i] -eq '1') { $tok[$i + 1] } else { 'CONFLICT' }
                    $i += 2
                    while ($i -lt $tok.Count -and $tok[$i] -ne '') { $i++ }
                    $i++
                }
                foreach ($it in $items) { if ($merged.ContainsKey($it.Head)) { $it.Merged = $merged[$it.Head] } }
            }

            $remoteHeads = $null
            $prCache = @{}
            $slug = $null
            if ($Online) {
                $slug = Get-OriginSlug $r
                $ls = Invoke-Bounded 'git' @('ls-remote', '--heads', 'origin') $r
                if ($null -ne $ls) {
                    $remoteHeads = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                    foreach ($l in ($ls -split "`n")) {
                        $ref = ($l -split "`t")[-1].Trim()
                        if ($ref -like 'refs/heads/*') { [void]$remoteHeads.Add($ref.Substring(11)) }
                    }
                }
            }

            foreach ($it in $items) {
                $lines = $out[$it.Key]
                # Per holder, so one unreadable `claimed` stamp cannot fail every other holder's line.
                $nonMerge = $null
                if ($it.Ahead -gt 0 -and $it.Merged -eq $base.Tree) {
                    # Rare (content already on main), so one direct call here rather than a batch.
                    $nm = "$(& git -C $r rev-list --no-merges --count "$($base.Main)..$($it.Head)" -- 2>$null)".Trim()
                    if ($nm -match '^\d+$') { $nonMerge = [int]$nm }
                }
                try { $lines.Add((Format-LandedLine $it.Ahead $it.HeadTime $it.Claimed $it.Merged $base $it.Head.Substring(0, 9) $nonMerge)) }
                catch { $lines.Add("evidence: FAILED -- $($_.Exception.Message)") }
                if ($WithStatus) {
                    # --no-optional-locks: the holder may be live, and a plain status can take index.lock.
                    $dirty = @(& git --no-optional-locks -C $it.Path status --porcelain --untracked-files=no 2>$null)
                    if ($LASTEXITCODE -ne 0) { $lines.Add("evidence: uncommitted changes: UNKNOWN -- git status failed in the holder") }
                    elseif ($dirty.Count -gt 0) { $lines.Add("evidence: the worktree has $($dirty.Count) uncommitted change(s) to tracked files, which no merge accounts for") }
                    else { $lines.Add("evidence: the worktree has no uncommitted changes to tracked files") }
                }
                if (-not $it.Branch) {
                    $lines.Add("evidence: the holder is on a detached HEAD, so there is no branch to look for on origin")
                    continue
                }
                if (-not $Online) {
                    # A tracking ref, not the branch: a fetch without --prune keeps one after a delete.
                    if ($refs.ContainsKey("refs/remotes/origin/$($it.Branch)")) {
                        $lines.Add("evidence: branch $($it.Branch) on origin: yes per this clone's tracking ref (last fetch; a deleted branch keeps one until a prune)")
                    }
                    else { $lines.Add("evidence: branch $($it.Branch) on origin: NO per this clone's tracking refs (last fetch)") }
                    continue
                }
                if ($null -eq $remoteHeads) { $lines.Add("evidence: branch $($it.Branch) on origin: UNKNOWN -- git ls-remote did not answer") }
                elseif ($remoteHeads.Contains($it.Branch)) { $lines.Add("evidence: branch $($it.Branch) on origin: yes (git ls-remote, just now)") }
                else { $lines.Add("evidence: branch $($it.Branch) on origin: NO (git ls-remote, just now)") }
                if (-not $slug) {
                    $lines.Add("evidence: pull request: UNKNOWN -- origin is not a GitHub repository")
                    continue
                }
                if (-not $prCache.ContainsKey($it.Branch)) {
                    $prCache[$it.Branch] = Invoke-Bounded 'gh' @('pr', 'list', '--repo', $slug, '--head', $it.Branch, '--state', 'all', '--json', 'number,state,mergedAt,headRefOid', '--limit', '20') $it.Path
                }
                $json = $prCache[$it.Branch]
                $prs = $null
                if ($null -ne $json) { try { $prs = @($json | ConvertFrom-Json) } catch { $prs = $null } }
                if ($null -eq $prs) { $lines.Add("evidence: pull request: UNKNOWN -- gh is missing, signed out, or did not answer") }
                elseif ($prs.Count -eq 0) { $lines.Add("evidence: pull request: none from branch $($it.Branch) in $slug") }
                else {
                    # A PR from THIS head is the fact that matters; one from another head of the same
                    # branch NAME says nothing about this head's commits, so it is labelled as such.
                    # "Different", not "earlier": nothing here checks which way the two are related.
                    # Within either set, a merged one first, then an open one, then any.
                    $exact = @($prs | Where-Object { $_.headRefOid -eq $it.Head })
                    $pool = if ($exact) { $exact } else { $prs }
                    $pr = @(@($pool | Where-Object state -EQ 'MERGED') + @($pool | Where-Object state -EQ 'OPEN') + $pool)[0]
                    $when = if ($pr.state -eq 'MERGED') { " at $(ConvertTo-Stamp $pr.mergedAt)" } else { '' }
                    if ($exact) {
                        $lines.Add("evidence: pull request #$($pr.number) from this exact head: $($pr.state)$when")
                    }
                    else {
                        $was = "$($pr.headRefOid)"
                        if ($was.Length -gt 9) { $was = $was.Substring(0, 9) }
                        $lines.Add("evidence: pull request #$($pr.number) from branch $($it.Branch): $($pr.state)$when, but from a DIFFERENT head ($was); the holder is at $($it.Head.Substring(0, 9))")
                    }
                }
            }
        }
        catch {
            foreach ($it in $items) { $out[$it.Key].Add("evidence: FAILED -- $($_.Exception.Message)") }
        }
    }
    return $out
}

function Show-List {
    $files = @(Get-ChildItem $claims -Filter *.json -EA SilentlyContinue | Sort-Object Name)
    if (-not $files) { Write-Host "No active claims."; return }
    $me = ($holder -replace '\\', '/').TrimEnd('/')
    Write-Host ""
    Write-Host "Active work claims ($($files.Count)):"
    $rows = foreach ($f in $files) {
        $state = $null
        # Rows are now printed after every one is built, so one unreadable file would otherwise hide the
        # whole listing instead of only the rows after it. Say so in its own row and carry on.
        try {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json
            if ($null -eq $c) { throw "the file is empty" }
        }
        catch {
            [pscustomobject]@{ File = $f.Name; Claim = [pscustomobject]@{ key = $f.BaseName; note = "(claim file unreadable: $($_.Exception.Message))"; branch = '?' }; Held = '?'; Mine = ''; Age = ''; State = $null }
            continue
        }
        $held = ($c.worktree -replace '\\', '/').TrimEnd('/')
        $mine = if ($held -ieq $me) { "  <-- THIS worktree" } else { "" }
        # LIVENESS, not age. This used to print "[STALE ~Nh -- release it if that session is gone]" once
        # a claim was 12h old, which measures how long the WORK has run and says nothing about whether
        # anyone is still doing it. Measured 2026-07-31: a claim reported STALE ~21h whose holder had
        # committed TWO MINUTES earlier. Releasing on that advice frees the key for a second session to
        # start building what someone is mid-flight on -- the exact duplicate-build this registry exists
        # to prevent, arrived at by following the tool's own recommendation. A long claim is the normal
        # shape of long work; report what the HOLDER is doing and let the operator decide.
        $age = ""
        try {
            $hrs = [int]((Get-Date) - [datetime]::Parse($c.claimed)).TotalHours
            # Shared with -Take and -Release, so all three surfaces answer "is the holder there?" the
            # same way. They used to disagree: this one probed, the other two did not probe at all.
            $live = Get-HolderLiveness $held
            $state = $live.State
            switch ($live.State) {
                'gone'    { $age = "  [HOLDER GONE -- worktree no longer exists; release with -Force]" }
                'occupied' {
                    $age = "  [held ${hrs}h; LIVE SESSION in the holder, last committed $($live.QuietHours)h ago]"
                    if ($live.QuietHours -ge 12) { $age += " -- QUIET but OCCUPIED, ask before releasing" }
                }
                # The probe could not run -- no Claude config root, or it failed. Says what it knows
                # and no more: the path is there. It must NOT claim a session it never looked for.
                'present' {
                    $age = "  [held ${hrs}h; holder present, last committed $($live.QuietHours)h ago; OCCUPANCY UNKNOWN -- the session probe could not run]"
                }
                # THE THIRD STATE, and the listing is the surface that matters (BACKLOG #1348).
                # -List is what a dispatching seat reads to decide where to spend attention, so a
                # directory that outlived its session must not render identically to a lane that is
                # building. It still says ESCALATE, not release: the refusal is unchanged.
                #
                # THIS LINE NAMED TWO SEATS UNTIL 2026-09-11 AND BOTH HAD RETIRED (BACKLOG #1543).
                # It read "ROUTE to the Cleaner/Dispatcher". CLAUDE.md section 5 retired both, so the
                # register's largest category had no live destination: measured that day, 56 of 80
                # claims sat in this state, median age 118h, and 48 of them over 96h. A tool that
                # names a ROLE inherits that role's lifetime; this one now names the CONDITION that
                # settles the case, which cannot retire. Do not put a seat name back here.
                'unoccupied' {
                    $age = "  [held ${hrs}h; DIRECTORY ONLY -- no live session in it, last commit $($live.QuietHours)h ago]"
                    $age += " -- not releasable on this signal alone; run -Release to see what settles it"
                }
                default   { $age = "  [held ${hrs}h; holder liveness UNKNOWN -- confirm before releasing]" }
            }
        } catch {
            # Say so. An empty annotation reads as "nothing notable about this claim", which is the same
            # silent-instrument failure the age signal had: accurate about what it measured, mute about
            # what it could not. A claim whose liveness could not be determined must not look routine.
            $age = "  [liveness check FAILED -- treat as unknown, confirm before releasing]"
        }
        [pscustomobject]@{ File = $f.Name; Claim = $c; Held = $held; Mine = $mine; Age = $age; State = $state }
    }
    # BACKLOG #1466. One batched pass over every directory-only holder, not a git call per claim.
    $unoccupied = @($rows | Where-Object State -EQ 'unoccupied')
    $evidence = @{}
    if ($unoccupied) {
        $evidence = Get-LandedEvidenceSet @($unoccupied | ForEach-Object { [pscustomobject]@{ Key = $_.File; Path = $_.Held; Claimed = $_.Claim.claimed } })
    }
    foreach ($r in $rows) {
        Write-Host ("  {0,-34} {1}" -f $r.Claim.key, $r.Claim.note)
        Write-Host ("      held by {0} [{1}]{2}{3}" -f $r.Held, $r.Claim.branch, $r.Mine, $r.Age)
        if ($r.State -eq 'unoccupied') {
            foreach ($e in $evidence[$r.File]) { Write-Host "        $e" }
        }
    }
    Write-Host ""
    if ($unoccupied) {
        # Said once, here, because the lines above read like verdicts and are not (BACKLOG #1466).
        Write-Host "  The evidence lines are FOR THE OWNER, NOT AUTHORITY TO RELEASE. A directory-only claim is" -ForegroundColor Cyan
        Write-Host "  still settled only by its item being closed or by the owner saying so. origin/main is read"
        Write-Host "  as of this clone's last fetch.$(if (-not $Online) { ' Pass -Online to add origin and pull-request lookups.' })"
        Write-Host ""
    }
}

# Resolved for BOTH paths, not just -Take. A release record that names who released the claim is only
# half an answer without the branch they were standing on -- the same question -Take records.
$branch = & git -C $holder branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git -C $holder rev-parse --short HEAD) }
$branch = $branch.Trim()

if ($Release) {
    $file = Join-Path $claims ((ConvertTo-KeyFile $Release) + ".json")
    if (-not (Test-Path $file)) { Write-Host "No claim on '$Release' -- nothing to release."; exit 0 }
    $info = Get-Mine $file
    if (-not $info.IsMine -and -not $Force) {
        Write-Host ""
        Write-Host "REFUSING to release '$Release': it is held by another worktree." -ForegroundColor Yellow
        Write-Host "  held by: $($info.Claim.worktree) [$($info.Claim.branch)]"
        Write-Host "  since  : $($info.Claim.claimed)"
        Write-Host "  note   : $($info.Claim.note)"
        # DO NOT recommend -Force without looking. This line used to read "If that session is gone,
        # re-run with -Force" unconditionally -- an instruction to guess, printed at exactly the moment
        # the operator is deciding whether to take someone else's key. Now the recommendation is only
        # made in the one state that can be proven, and the live case says the opposite.
        $live = Get-HolderLiveness $info.Claim.worktree
        Write-Host ""
        switch ($live.State) {
            'gone' {
                Write-Host "  HOLDER GONE -- that worktree no longer exists on disk." -ForegroundColor Green
                Write-Host "  Safe to take over:  claim.ps1 -Release $Release -Force"
            }
            'present' {
                Write-Host "  HOLDER IS STILL THERE -- that worktree exists and last committed $($live.QuietHours)h ago." -ForegroundColor Red
                Write-Host "  OCCUPANCY UNKNOWN: the session probe could not run, so this does NOT say whether"
                Write-Host "  anyone is in it. Treat that as MORE reason to coordinate, not less."
                Write-Host "  Do NOT -Force it on the strength of a quiet period: a session can be alive and"
                Write-Host "  simply not committing. Ask that session first -- releasing a live claim is how two"
                Write-Host "  sessions end up building the same thing."
            }
            'occupied' {
                Write-Host "  HOLDER IS STILL THERE -- that worktree exists, a live session is IN it, and it last committed $($live.QuietHours)h ago." -ForegroundColor Red
                Write-Host "  Do NOT -Force it on the strength of a quiet period: a session can be alive and"
                Write-Host "  simply not committing. Ask that session first -- releasing a live claim is how two"
                Write-Host "  sessions end up building the same thing."
            }
            'unoccupied' {
                Write-Host "  HOLDER IS A DIRECTORY, NOT A SESSION -- that worktree exists and last committed $($live.QuietHours)h ago," -ForegroundColor Yellow
                Write-Host "  but NO live session is placed in it. This is the third state (BACKLOG #1348)."
                Write-Host "  STILL NOT YOURS TO -Force ON THIS SIGNAL. Nothing on this host can prove a session is"
                Write-Host "  gone: occupancy sees a session by the cwd it launched in, so one working here BY"
                Write-Host "  ABSOLUTE PATH from elsewhere is invisible to it. Occupancy can VETO, never authorise."
                Write-Host ""
                Write-Host "  TWO THINGS SETTLE IT, and neither is a seat you have to find:" -ForegroundColor Cyan
                Write-Host "   1. THE ITEM IS ALREADY CLOSED. Then there is no work for a live session to be doing,"
                Write-Host "      so liveness stops mattering. Check the banner in docs/BACKLOG.md (or the archive)"
                Write-Host "      and, if it is closed, -Force it and say so in the note."
                Write-Host "   2. THE OWNER SAYS SO. That is the escalation, and it is deliberately a person rather"
                Write-Host "      than a role: this line named two seats until 2026-09-11 and both had retired,"
                Write-Host "      which left 56 of 80 claims with no destination at all (BACKLOG #1543)."
                Write-Host ""
                Write-Host "  A LONG QUIET PERIOD IS NOT A THIRD REASON. Age is not evidence: a session can be alive"
                Write-Host "  and simply not committing, and this state is the one where you cannot tell."
                Write-Host ""
                # BACKLOG #1466. The facts the owner would ask for first, gathered so nobody has to.
                Write-Host "  EVIDENCE FOR THE OWNER -- not authority to release, and not a third reason:" -ForegroundColor Cyan
                $set = Get-LandedEvidenceSet @([pscustomobject]@{ Key = 'this'; Path = $info.Claim.worktree; Claimed = $info.Claim.claimed }) -WithStatus
                foreach ($e in $set['this']) { Write-Host "    $e" }
                Write-Host "  Landed work does not prove the session gone. Take this to point 1 or point 2 above."
                if (-not $Online) { Write-Host "  Add -Online for origin and pull-request lookups." }
            }
            default {
                Write-Host "  HOLDER LIVENESS UNKNOWN -- the worktree exists but could not be dated." -ForegroundColor Yellow
                Write-Host "  Confirm with that session before using -Force."
            }
        }
        # BACKLOG #1358, and this is the placement that earns the most. The refusal above says the claim
        # is "held by another worktree" -- but under divergence the ownership test ran against the SCRIPT's
        # tree, so "another worktree" can be the operator's OWN, with the foreign thing being the copy of
        # this script they invoked. Without the note that reads as a genuine cross-session collision and
        # invites a -Force, which is the one action the whole block exists to talk them out of.
        Write-DivergenceNote "ownership was judged against it, NOT against your shell's tree -- re-run this from $holder, or pass -AsWorktree, before concluding anyone else holds it."
        exit 1
    }
    # RECORD FIRST, then act. Both orders can lie once and only one lie is recoverable: removing first
    # and recording after reproduces this item exactly (a completed release with no trace, and nothing
    # left to write the record from), whereas recording first can at worst claim a release that then
    # failed -- which the catch below corrects in the same ledger. Refusing when the record cannot be
    # written is safe because a release is always retryable: the claim stays where it was.
    #
    # Read ONCE and shared with the release-failed record below, so a single release can never write two
    # lines that disagree about where its operator was standing.
    $invokedFrom = Get-CallerTree
    # ConvertTo-Stamp on every field carried over from the claim file, not just the timestamp:
    # ConvertFrom-Json date-coerces ANY ISO-8601-shaped string, and note/branch/worktree are free text.
    $record = [ordered]@{
        ts              = (Get-Date).ToString("o")
        event           = "release"
        key             = $Release
        released_by     = $holder
        released_branch = $branch
        # THE ACTOR (BACKLOG #1358), read as a pair with released_by per the header. WHY A RECORD AND
        # NOT A WARNING: a misdirected -Take is refused by the commit gate at the point of use, and
        # nothing anywhere re-reads a release record, so a wrong actor here is never contradicted.
        #
        # ALWAYS WRITTEN, including when it equals released_by, and $null when the shell was not inside a
        # repository. Omitting it on the ordinary same-tree release would make absence mean two things --
        # "the caller was the holder" and "this record predates the field" -- and a reader cannot tell
        # those apart, which is the ambiguity the field exists to remove.
        #
        # -AsWorktree MAKES THIS SHARPER RATHER THAN REDUNDANT (measured 2026-09-10, BACKLOG #1346's
        # flag). `-Release <key> -AsWorktree <holder>` re-aims the ownership test at the named tree, so a
        # checkout that holds nothing can release another's claim WITHOUT -Force: prior_holder,
        # released_by and released_branch all name the holder and `force` stays false, so the line is
        # indistinguishable from that holder releasing its own claim routinely. This field is the only
        # one that says otherwise.
        #
        # The caller's BRANCH is deliberately not recorded beside it: the item asks which seat acted, and
        # the tree answers that.
        invoked_from    = $invokedFrom
        prior_holder    = ConvertTo-Stamp $info.Claim.worktree
        prior_branch    = ConvertTo-Stamp $info.Claim.branch
        # The note is what a later reader judges the release BY -- it is the field that was stale and
        # wrong in the incident above -- so the record keeps it rather than pointing at a deleted file.
        prior_note      = ConvertTo-Stamp $info.Claim.note
        claimed         = ConvertTo-Stamp $info.Claim.claimed
        # The flag AS PASSED. Whether this was a takeover is already readable from prior_holder against
        # released_by, and a record should not restate a fact it already carries.
        force           = [bool]$Force
    } | ConvertTo-Json -Compress
    if (-not (Add-HistoryLine $record)) {
        Write-Host ""
        Write-Host "REFUSING to release '$Release': the release record could not be written." -ForegroundColor Yellow
        Write-Host "  ledger : $history"
        Write-Host "  Your claim is UNCHANGED and still yours. Retry in a moment -- an untraceable"
        Write-Host "  release is the one outcome this refuses to produce."
        exit 1
    }
    try {
        Remove-Item -LiteralPath $file -Force
    }
    catch {
        # The line above says a release happened; it did not. Correct it in the same ledger rather than
        # leave a record that is now false.
        Add-HistoryLine ([ordered]@{
                ts           = (Get-Date).ToString("o")
                event        = "release-failed"
                key          = $Release
                released_by  = $holder
                # Same reason as the record above, and the correction is the half a reader is MORE
                # likely to act on: it is the line that says the ledger's previous sentence is false.
                invoked_from = $invokedFrom
                reason       = $_.Exception.Message
            } | ConvertTo-Json -Compress) | Out-Null
        throw
    }
    Write-Host "Released claim on '$Release'." -ForegroundColor Green
    if (-not $info.IsMine) {
        Write-Host "  TOOK OVER a claim held by $($info.Claim.worktree) [$($info.Claim.branch)]." -ForegroundColor Yellow
    }
    Write-Host "  recorded in $history"
    # BACKLOG #1358. The release SUCCEEDS either way, so without this the history records a tree the
    # operator was never standing in and nothing anywhere says so.
    Write-DivergenceNote "release was recorded there, and ownership was judged against it rather than against your shell's tree."
    exit 0
}

if (-not $Take) { Show-List; exit 0 }
if ($List) { Show-List; exit 0 }

$safe = ConvertTo-KeyFile $Take
$file = Join-Path $claims "$safe.json"

try {
    # ATOMIC test-and-set -- identical to alloc.ps1. 'CreateNew' + FileShare::None throws IOException if a
    # sibling session got here first, and that throw IS the mutual exclusion.
    $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
} catch [System.IO.IOException] {
    $info = Get-Mine $file
    if ($info.IsMine) {
        # Re-taking your own claim is not an error: a session should be able to re-assert freely. It was
        # also, until now, not a REFRESH -- despite the -Take parameter documenting one. A new -Note was
        # accepted, reported as success, and silently discarded.
        #
        # That is worse than an outright failure, because the note is the one field written deliberately
        # to say what a session is doing, and announce-session.ps1 broadcasts it to every session that
        # joins the repo, telling them to prefer it over the worktree name. Measured 2026-08-02: the
        # 'announce-hook' claim still read "NO PR OPENED -- honouring the #119 merge freeze" to every
        # joining session hours after both #133 and #119 had merged. A stale note broadcast as current
        # intent is a coordination fault, not a cosmetic one -- and the documented workaround (-Release
        # then -Take) drops the claim in between, re-opening the race the claim exists to close.
        if ($Note) {
            $updated = [ordered]@{
                # $Take, not the stored key: ConvertFrom-Json date-coerces any ISO-8601-SHAPED string,
                # and a key is free text, so a key like "2026-08-01T00:00:00" would come back through
                # [string] as "08/01/2026 00:00:00" -- a record naming a key nobody typed and -Release
                # cannot be spelled to match. $Take is the caller's current spelling of the same key,
                # and it folds to the same filename, which is the real identity.
                key      = $Take
                note     = $Note
                # Refresh the branch too: a worktree can have switched branches since the claim was made,
                # and a claim naming a branch nobody is on is another confidently-wrong coordination fact.
                branch   = $branch
                worktree = [string]$info.Claim.worktree
                # `claimed` is the identity of the claim and never moves; `refreshed` is what tells a
                # reader how old the NOTE is, which is the question a stale note makes urgent.
                claimed   = ConvertTo-Stamp $info.Claim.claimed
                refreshed = (Get-Date).ToString("o")
            } | ConvertTo-Json -Compress
            # Write-then-replace, not a truncating in-place write. A torn claim file does not fail loudly:
            # scripts/hooks/claim_check.py swallows a parse error into "not claimed", which would disable
            # the enforced gate for that key -- so a crash mid-write must leave the OLD file intact.
            $tmp = "$file.$PID.tmp"
            # UTF8 WITHOUT a BOM, for that same reader: a BOM makes json.loads raise.
            [System.IO.File]::WriteAllBytes($tmp, [System.Text.Encoding]::UTF8.GetBytes($updated))

            # [IO.File]::Move(.., overwrite) AND NOT `Move-Item -Force`. THE CLAIM FILE'S EXISTENCE *IS*
            # THE LOCK -- the take path above is an exclusive CreateNew, so any instant in which the name
            # does not exist is an instant another worktree can claim a key we hold. `Move-Item -Force`
            # is delete-then-rename and opens exactly that window: measured on this box, 400 moves left
            # the destination absent on 2,559 of 154,506 polls. The same harness over [IO.File]::Move
            # with overwrite -- which is MoveFileEx(MOVEFILE_REPLACE_EXISTING), atomic on NTFS -- polled
            # 134,581 times and never once saw the name missing.
            #
            # It can fail transiently instead (a scanner or an editor holding the destination without
            # FILE_SHARE_DELETE); the same harness saw 13.5% under back-to-back churn, which is nothing
            # like one refresh per invocation but is cheap to absorb. Failing is the SAFE direction: the
            # old note survives and the claim stays ours. Losing the lock is not.
            #
            # The catch is deliberately UNTYPED. PowerShell wraps an exception thrown by a .NET METHOD in
            # a MethodInvocationException, so `catch [System.IO.IOException]` around this call never
            # matches -- the failure escapes to $ErrorActionPreference = "Stop", the cleanup below never
            # runs, and the temp file is orphaned in the claim registry. (Written typed first; the
            # orphaned-temp assertion is what caught it.) Every failure here has the same right answer
            # anyway: leave the old note, keep the claim, say so.
            $moved = $false
            foreach ($attempt in 1..5) {
                try { [System.IO.File]::Move($tmp, $file, $true); $moved = $true; break }
                catch { Start-Sleep -Milliseconds (20 * $attempt) }
            }
            if (-not $moved) {
                # Never orphan the temp: this directory is the claim registry, and a k.json.<pid>.tmp
                # nothing ever removes accumulates in it for the life of the repo.
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Write-Host ""
                Write-Host "Could NOT refresh the note on '$Take' -- the file was locked by another process." -ForegroundColor Yellow
                Write-Host "  Your claim is UNCHANGED and still yours; only the note was not updated."
                Write-Host "  Retry in a moment. Do NOT -Release: that would drop a claim you still hold."
                exit 1
            }
            Write-Host ""
            Write-Host "REFRESHED '$Take' (held since $($info.Claim.claimed))." -ForegroundColor Green
            Write-Host "  note : $Note"
            exit 0
        }
        Write-Host "You already hold '$Take' (claimed $($info.Claim.claimed))." -ForegroundColor Green
        Write-Host "  note : $($info.Claim.note)"
        Write-Host "  (pass -Note to update it -- it is what other sessions are shown.)"
        exit 0
    }
    Write-Host ""
    Write-Host "BLOCKED: '$Take' is already claimed by another session." -ForegroundColor Red
    Write-Host "  held by: $($info.Claim.worktree) [$($info.Claim.branch)]"
    Write-Host "  since  : $($info.Claim.claimed)"
    Write-Host "  note   : $($info.Claim.note)"
    # THE BLOCKING PATH IS WHERE THIS MATTERS MOST. -List is where you browse; this is where a session
    # is stopped and has to decide between waiting, picking other work, and taking the key. It used to
    # offer -Force as a flat third option with no way to tell a dead holder from a live one, so the
    # cheapest way past the gate was also the one that causes the duplicate build it exists to prevent.
    $live = Get-HolderLiveness $info.Claim.worktree
    Write-Host ""
    switch ($live.State) {
        'gone' {
            Write-Host "  HOLDER GONE -- that worktree no longer exists on disk, so nobody is building this." -ForegroundColor Green
            Write-Host "  Take it over with:"
            Write-Host "      pwsh -NoProfile -File scripts\coord\claim.ps1 -Release $Take -Force"
            Write-Host "      pwsh -NoProfile -File scripts\coord\claim.ps1 -Take $Take -Note ""<what>"""
        }
        'present' {
            Write-Host "  HOLDER IS STILL THERE -- that worktree exists and last committed $($live.QuietHours)h ago." -ForegroundColor Red
            Write-Host "  OCCUPANCY UNKNOWN: the session probe could not run, so this does NOT say whether"
            Write-Host "  anyone is in it. Treat that as MORE reason to coordinate, not less."
            Write-Host "  Do NOT build it in parallel -- that is the duplicate-work this gate exists to stop,"
            Write-Host "  and do NOT -Force it: quiet is not dead. Coordinate with that session or pick"
            Write-Host "  different work. Its note above says what it is doing."
        }
        'occupied' {
            Write-Host "  HOLDER IS STILL THERE -- that worktree exists, a live session is IN it, and it last committed $($live.QuietHours)h ago." -ForegroundColor Red
            Write-Host "  Do NOT build it in parallel -- that is the duplicate-work this gate exists to stop,"
            Write-Host "  and do NOT -Force it: quiet is not dead. Coordinate with that session or pick"
            Write-Host "  different work. Its note above says what it is doing."
        }
        'unoccupied' {
            Write-Host "  HOLDER IS A DIRECTORY, NOT A SESSION -- that worktree exists and last committed $($live.QuietHours)h ago," -ForegroundColor Yellow
            Write-Host "  but NO live session is placed in it. This is the third state (BACKLOG #1348)."
            Write-Host "  STILL NOT YOURS TO -Force ON THIS SIGNAL, and the refusal is deliberate: occupancy can"
            Write-Host "  VETO but never authorise, because nothing here can prove a session is gone. A session"
            Write-Host "  working in this path BY ABSOLUTE PATH from another cwd does not appear as an occupant."
            Write-Host ""
            Write-Host "  TWO THINGS SETTLE IT: the ITEM being already closed (then no live session can be doing" -ForegroundColor Cyan
            Write-Host "  the work, so liveness stops mattering -- check its banner and -Force it saying so), or"
            Write-Host "  an OWNER decision. Escalate to the owner, not to a seat: this line named the Cleaner and"
            Write-Host "  the Dispatcher until 2026-09-11 and both had retired (BACKLOG #1543)."
            Write-Host "  Until one of those, do NOT build it in parallel."
        }
        default {
            Write-Host "  HOLDER LIVENESS UNKNOWN -- the worktree exists but could not be dated." -ForegroundColor Yellow
            Write-Host "  Treat it as live: coordinate with that session before -Force."
        }
    }
    exit 1
}
try {
    $claim = [ordered]@{
        key      = $Take
        note     = if ($Note) { $Note } else { "(no note)" }
        branch   = $branch
        worktree = $holder
        claimed  = (Get-Date).ToString("o")
    } | ConvertTo-Json -Compress
    # UTF8 WITHOUT a BOM: the python-side gate reads this with encoding="utf-8", and a BOM makes
    # json.loads raise -- which would be swallowed into "not claimed" and silently disable the gate.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($claim)
    $fs.Write($bytes, 0, $bytes.Length)
} finally {
    $fs.Dispose()
}

Write-Host ""
Write-Host "CLAIMED '$Take'" -ForegroundColor Green
Write-Host "  by   : $holder [$branch]"
Write-Host "  note : $(if ($Note) { $Note } else { '(no note)' })"
# Built outside the string: a nested double-quoted subexpression inside a double-quoted string is a
# PowerShell parse error, not a runtime one, so it takes the whole script down at load time.
$releaseArgs = "-Release $Take"
if ($AsWorktree) { $releaseArgs += " -AsWorktree `"$holder`"" }
Write-Host "  release when done:  pwsh -NoProfile -File scripts\coord\claim.ps1 $releaseArgs"
# Say where it landed WHENEVER that is not this tree's own registry. A claim written into another
# repository's registry is the correct outcome under mefor.claimsRoot and an alarming one unexplained,
# and the operator has to know the answer to read `-List` anywhere (BACKLOG #1346).
if ($registryRepo -ne $holder) {
    Write-Host "  registry: $claims" -ForegroundColor Yellow
    Write-Host "            (SHARED -- mefor.claimsRoot in $holder points at $registryRepo)" -ForegroundColor Yellow
}

# Same note alloc.ps1 prints, for the same reason (BACKLOG #1060): anchoring is correct but surprising,
# and a claim recorded to a worktree the caller is not standing in otherwise surfaces only as a refused
# commit later. Silent on the ordinary same-tree invocation.
Write-DivergenceNote 'claim is recorded there. -Release must be run against that same worktree.'
exit 0
