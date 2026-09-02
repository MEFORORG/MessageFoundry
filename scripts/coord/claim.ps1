# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    <git-common-dir>/mefor-coord/claims/.history: the key, the releasing worktree and branch, the
    prior holder, its branch and note, when the claim was taken, and whether -Force was used. The
    record is written BEFORE the claim file is removed and the release is refused if it cannot be
    written -- a release nobody can trace is the outcome this will not produce (BACKLOG #1068).

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
    [switch]$Force
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

# ONE divergence test, three call sites (BACKLOG #1358). The note used to be written inline at the very
# end of the script, which put it after the `-Take` success block and therefore made it UNREACHABLE from
# `-Release` -- the script stated the release rule at claim time and went silent at the moment the
# operator applied it. `$Subject` is the only part that varies, because the true sentence differs: a take
# is recorded to $repo, whereas a release is BOTH recorded to it and adjudicated against it.
#
# Deliberately reads $repo at CALL time from script scope rather than taking it as a parameter: a second
# copy of "which tree is this" is exactly the drift this note exists to report.
function Write-DivergenceNote([Parameter(Mandatory)][string]$Subject) {
    $cwdTop = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $cwdTop) { return }
    $a = ($cwdTop.Trim() -replace '\\', '/').TrimEnd('/')
    $b = ($repo -replace '\\', '/').TrimEnd('/')
    if ($a -ieq $b) { return }
    Write-Host "  NOTE: your shell is in $a, but this script lives in $b," -ForegroundColor Yellow
    Write-Host "        so the $Subject" -ForegroundColor Yellow
}

$common = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
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
    $me = ($repo -replace '\\', '/').TrimEnd('/')
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

function Show-List {
    $files = @(Get-ChildItem $claims -Filter *.json -EA SilentlyContinue | Sort-Object Name)
    if (-not $files) { Write-Host "No active claims."; return }
    $me = ($repo -replace '\\', '/').TrimEnd('/')
    Write-Host ""
    Write-Host "Active work claims ($($files.Count)):"
    foreach ($f in $files) {
        $c = Get-Content $f.FullName -Raw | ConvertFrom-Json
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
                # -List is what a Cleaner or Dispatcher reads to decide where to spend attention, so
                # a directory that outlived its session must not render identically to a lane that
                # is building. It still says ROUTE, not release: the refusal is unchanged.
                'unoccupied' {
                    $age = "  [held ${hrs}h; DIRECTORY ONLY -- no live session in it, last commit $($live.QuietHours)h ago]"
                    $age += " -- ROUTE to the Cleaner/Dispatcher; not releasable on this signal alone"
                }
                default   { $age = "  [held ${hrs}h; holder liveness UNKNOWN -- confirm before releasing]" }
            }
        } catch {
            # Say so. An empty annotation reads as "nothing notable about this claim", which is the same
            # silent-instrument failure the age signal had: accurate about what it measured, mute about
            # what it could not. A claim whose liveness could not be determined must not look routine.
            $age = "  [liveness check FAILED -- treat as unknown, confirm before releasing]"
        }
        Write-Host ("  {0,-34} {1}" -f $c.key, $c.note)
        Write-Host ("      held by {0} [{1}]{2}{3}" -f $held, $c.branch, $mine, $age)
    }
    Write-Host ""
}

# Resolved for BOTH paths, not just -Take. A release record that names who released the claim is only
# half an answer without the branch they were standing on -- the same question -Take records.
$branch = & git -C $repo branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git -C $repo rev-parse --short HEAD) }
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
                Write-Host "  STILL NOT YOURS TO -Force. Nothing on this host can prove a session is gone: occupancy"
                Write-Host "  sees a session by the cwd it launched in, so one working here BY ABSOLUTE PATH from"
                Write-Host "  elsewhere is invisible to it. This is reported so you can ROUTE it, not act on it."
                Write-Host "  Route to the Cleaner or the Dispatcher -- releasing another worktree's claim is theirs."
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
        Write-DivergenceNote "ownership was judged against it, NOT against your shell's tree -- re-run this from $repo before concluding anyone else holds it."
        exit 1
    }
    # RECORD FIRST, then act. Both orders can lie once and only one lie is recoverable: removing first
    # and recording after reproduces this item exactly (a completed release with no trace, and nothing
    # left to write the record from), whereas recording first can at worst claim a release that then
    # failed -- which the catch below corrects in the same ledger. Refusing when the record cannot be
    # written is safe because a release is always retryable: the claim stays where it was.
    #
    # ConvertTo-Stamp on every field carried over from the claim file, not just the timestamp:
    # ConvertFrom-Json date-coerces ANY ISO-8601-shaped string, and note/branch/worktree are free text.
    $record = [ordered]@{
        ts              = (Get-Date).ToString("o")
        event           = "release"
        key             = $Release
        released_by     = $repo
        released_branch = $branch
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
                ts          = (Get-Date).ToString("o")
                event       = "release-failed"
                key         = $Release
                released_by = $repo
                reason      = $_.Exception.Message
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
            Write-Host "  STILL NOT YOURS TO -Force, and the refusal is deliberate: occupancy can VETO but never"
            Write-Host "  authorise, because nothing here can prove a session is gone. A session working in this"
            Write-Host "  path BY ABSOLUTE PATH from another cwd does not appear as an occupant."
            Write-Host "  Hand it to the Cleaner or the Dispatcher with this line; do not build it in parallel."
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
        worktree = $repo
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
Write-Host "  by   : $repo [$branch]"
Write-Host "  note : $(if ($Note) { $Note } else { '(no note)' })"
Write-Host "  release when done:  pwsh -NoProfile -File scripts\coord\claim.ps1 -Release $Take"

# Same note alloc.ps1 prints, for the same reason (BACKLOG #1060): anchoring is correct but surprising,
# and a claim recorded to a worktree the caller is not standing in otherwise surfaces only as a refused
# commit later. Silent on the ordinary same-tree invocation.
Write-DivergenceNote 'claim is recorded there. -Release must be run against that same worktree.'
exit 0
