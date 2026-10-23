# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    SessionStart hook: surface git-worktree coordination to a Claude Code chat.

.DESCRIPTION
    Wired as a SessionStart hook in .claude/settings.json. Whatever this prints to stdout is injected
    into the chat's starting context, so a new window starts already knowing the rules for working
    alongside sibling sessions.

    Parallel-session coordination, printed ONLY when 2+ worktrees share this .git, i.e. when
    parallel build sessions are actually in play and could collide. It also:
      - warns a session that lands in the SHARED PRIMARY (trunk) checkout to branch into its
        own worktree before editing (owner often forgets to say so); and
      - nudges cleanup by counting the <repo>-<name> siblings, pointing at prune-merged.ps1
        so finished worktrees don't pile up.
    See docs/WORKTREES.md and AI memory: mf-worktree-hygiene.

    IT READS THE WORKTREE THE HOOK INPUT NAMES, NOT THE ONE IT RUNS IN. The desktop app starts a
    worktree session's CLI with `--project-config-root <primary checkout>`. Measured 2026-10-12, this
    hook then ran with its directory, CLAUDE_PROJECT_DIR and `git rev-parse` all naming the PRIMARY,
    so it named the primary as a worktree session's own and told it it sat in the shared trunk.

    Only the `cwd` field of the JSON on stdin names the session's worktree. So the hook moves there
    (scripts/hooks/_hookinput.ps1) before its first git call, and presence.ps1, overlap.ps1 and every
    git call below answer for the session. Input with no `cwd` leaves it where it started, as before.
    _hookinput.ps1 holds the rules for which worktree that is. Where they answer with the pinned
    worktree rather than the `cwd`, the banner says so. A `cwd` they refuse, or a helper that is
    missing, becomes the banner's first line, and the banner then describes the checkout the hook
    runs in.
#>
$ErrorActionPreference = "SilentlyContinue"

$lines = @()
$busyLines = @()
$overlapFault = ''
$tail = @()

# Lines the byte backstop never cuts: each says a view below is incomplete or unsafe, or names this
# session, so dropping one would hide the very hazard the banner exists to report. Add-Hazard appends
# to $lines and records the index; the backstop skips every recorded index. Callers clip each line's
# variable part with Format-Field, since a protected line that grows has nothing to cut it.
$hazard = @()
function Add-Hazard([string[]]$Text) {
    foreach ($t in $Text) { $script:lines += $t; $script:hazard += ($script:lines.Count - 1) }
}

# A claim stamp as UTC, or $null. ConvertFrom-Json has usually coerced the ISO string to a [datetime]
# already, and re-parsing that through a string reads it in the current culture, which swaps day and
# month on an en-GB box. So a [datetime] is used as it is, and only a real string is parsed.
function ConvertTo-ClaimUtc($Value) {
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if (-not $Value) { return $null }
    try { return [datetimeoffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture).UtcDateTime } catch { return $null }
}

# One field of a list row, from a peer's record, which may hold any text at any length. Control and
# format characters and the Unicode line and paragraph separators (\p{Zl}, \p{Zp}, which are not in
# \p{C}) become spaces, so a note cannot start a line of its own in the model's context. Surrogates
# are kept, and a clip never splits a pair, so an emoji survives. A [datetime] that ConvertFrom-Json
# coerced prints in ISO 8601 ('o'), not the culture's short form; its offset and precision may still
# differ from what the peer wrote. The field is clipped, not the row, so the tags after it ([STATE],
# [stale ~Nh]) survive. overlap.ps1 and the mail hooks each keep their own fold of untrusted text;
# this one does not share theirs, which maps non-ASCII to '?'.
function Format-Field($Value, [int]$Width) {
    $text = if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { $Value.ToString('o') } else { "$Value" }
    $s = ($text -replace '[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]', ' ').Trim()
    if ($s.Length -le $Width) { return $s }
    $cut = $Width - 3
    if ([char]::IsHighSurrogate($s[$cut - 1])) { $cut-- }
    return $s.Substring(0, $cut) + '...'
}

# Into the session's own directory BEFORE any git call. Under SilentlyContinue a dot-source of a
# missing file does not throw, so the helper is tested for first and its absence is said aloud.
$cwdFault = ''
$hookInput = Join-Path $PSScriptRoot '../hooks/_hookinput.ps1'
try {
    if (-not (Test-Path -LiteralPath $hookInput -PathType Leaf)) { throw "scripts/hooks/_hookinput.ps1 is missing beside this hook" }
    . $hookInput
    $session = Enter-CcxHookSession -Text (Read-CcxHookInput)
    $cwdFault = $session.Reason
    if ($session.Note) { Add-Hazard "[session-context] $(Format-Field $session.Note 200)." }
} catch { $cwdFault = "the hook could not read its input ($($_.Exception.Message))" }
if ($cwdFault) {
    Add-Hazard "[session-context] COULD NOT READ THIS SESSION'S WORKTREE: $(Format-Field $cwdFault 200). Everything below describes $(Format-Field (Get-Location).Path 200), where this hook runs, which may not be your worktree."
}

# Add parallel-session coordination only when 2+ worktrees share this .git (real collision risk).
$root = (& git rev-parse --show-toplevel 2>$null)
if ($root) {
    $wt = @(& git worktree list 2>$null)
    if ($wt.Count -gt 1) {
        $branch = (& git branch --show-current 2>$null)
        # Primary (trunk) checkout vs a linked worktree: the primary's git-dir IS the common dir. A
        # match on 'worktrees' in the git-dir misreads a primary that sits under a directory of that
        # name, once the hook runs from a subdirectory and git prints the path in full.
        $gitDir = (& git rev-parse --path-format=absolute --git-dir 2>$null)
        $commonDir = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
        # A git that does not answer leaves this UNKNOWN, never "linked": a primary read as a linked
        # worktree loses the warning below, which is the one line this banner most needs to say.
        $isPrimary = $null
        if ($gitDir -and $commonDir) {
            $isPrimary = ("$gitDir".Trim().TrimEnd('/') -ieq "$commonDir".Trim().TrimEnd('/'))
        }

        $lines += ""
        Add-Hazard "[PARALLEL SESSION ($($wt.Count) worktrees active)]", "This chat's worktree: $root  (branch: $branch)"

        if ($null -eq $isPrimary) {
            $lines += ""
            Add-Hazard "  >>> git did not say whether this is the SHARED PRIMARY checkout or your own worktree.",
                "  >>> If it is the primary, create and work in your OWN worktree before substantive edits."
        }

        # Loudest, first: if this session sits in the SHARED trunk, tell it to branch into its own worktree.
        if ($isPrimary) {
            $lines += ""
            Add-Hazard "  >>> You are in the SHARED PRIMARY checkout, where parallel sessions collide.",
                "  >>> Before any substantive edits, create and work in your OWN worktree:",
                "  >>>     scripts\worktree\new.ps1 -Name <short-task-name>",
                "  >>> (A trivial one-off read/edit here is fine; anything you'll iterate on gets a worktree.)"
        }

        # HIGH SIGNAL FIRST, AND EVERY LIST CAPPED, so the banner reaches the model whole rather than
        # as a preview of its head. docs/WORKTREES.md (the SessionStart section) holds why and the
        # measurement. Order: peers, then claims, then what peers are building; each list names the
        # command that shows the rest.
        $peerCap = 8
        $busyCap = 3
        $claimCap = 6
        $staleHours = 12

        # WHO IS ACTUALLY HERE. The worktree count is the set of checkouts, not the set of live
        # sessions -- most worktrees usually have nobody in them, and the one collision that matters
        # (someone editing the shared primary right now) is invisible from it. presence.ps1 is the only
        # roster that spans surfaces: the Desktop app's own session tooling never registers a session it
        # did not spawn, so a VS Code session working in this repo does not appear in it at all.
        $presence = Join-Path $PSScriptRoot "..\coord\presence.ps1"
        if (Test-Path $presence) {
            $peers = @()
            # A SessionStart hook must never fail loudly: whatever this prints IS the chat's starting
            # context, so a throw here would replace the coordination banner with a stack trace.
            # A roster that threw must not read as "nobody else is live", so it says so, protected.
            try { $peers = @(& $presence -Json | ConvertFrom-Json) } catch {
                $peers = @()
                Add-Hazard "", "Live sessions: NOT READ ($(Format-Field $_.Exception.Message 120)). Run: scripts\coord\presence.ps1 -All"
            }

            $others = @($peers | Where-Object { -not $_.IsSelf })
            if ($others.Count -gt 0) {
                $lines += ""
                $lines += "LIVE sessions in this repo right now ($($others.Count) besides you):"
                # LABEL THE ID IN EVERY ROW (BACKLOG #1098). Bare, the 8-hex token reads as an
                # abbreviated commit SHA -- and it reads that way for a concrete reason, not a vague
                # one: the `git worktree list` row this banner prints for your own worktree puts a REAL
                # abbreviated SHA in exactly this shape, before a bracketed branch. It is a registry
                # session id, resolves to no git object, and a session that compared "is that worktree ahead of mine"
                # against it got an error at best and the wrong tree if the prefix happened to resolve.
                # The word goes on the ROW, not in a legend, so the column cannot mean one thing in one
                # row and something else in the next.
                # The two notes test EVERY peer, not only the rows shown, so a capped row cannot drop a
                # hazard, and Add-Hazard keeps the byte backstop from cutting them.
                # The surfaces differ in what can reach them, and that changes how you coordinate.
                if (@($others | Where-Object { $_.Surface -ne "desktop" }).Count -gt 0) {
                    Add-Hazard "  NOTE: a non-desktop (e.g. VS Code) session is live. It cannot be reached by",
                        "        session messaging -- coordinate through a claim or the PR, not a message."
                }
                if (@($others | Where-Object { $_.IsPrimary }).Count -gt 0) {
                    Add-Hazard "  WARNING: a session is working in the SHARED PRIMARY checkout. Anything you do",
                        "           there can collide with it -- stay in this worktree."
                }
                # The peers the notes name come first, so the cap never hides the one they mean.
                # The index keeps presence.ps1's own order within each group. It is a sort key, not
                # -Stable, which Windows PowerShell 5.1 does not have.
                $ranked = @(for ($i = 0; $i -lt $others.Count; $i++) { [pscustomobject]@{ P = $others[$i]; I = $i } }) |
                    Sort-Object -Property @{ Expression = { -not $_.P.IsPrimary } }, @{ Expression = { $_.P.Surface -eq 'desktop' } }, I |
                    ForEach-Object { $_.P }
                foreach ($p in @($ranked | Select-Object -First $peerCap)) {
                    $where = if ($p.IsPrimary) { "the SHARED PRIMARY" } else { Format-Field $p.Worktree 40 }
                    $flag = if ($p.State -ne "LIVE") { "  [$(Format-Field $p.State 20)]" } else { "" }
                    $lines += "  session $(Format-Field $p.Short 12)  $(Format-Field $p.Surface 12)  in $where  [$(Format-Field $p.Branch 50)]$flag"
                }
                $roster = "pwsh -NoProfile -File scripts\coord\presence.ps1 -All"
                if ($others.Count -gt $peerCap) {
                    $lines += "  +$($others.Count - $peerCap) more (run: $roster)"
                } else {
                    $lines += "  Full roster:  $roster"
                }
            }

            # WHAT they are building, not just where they are. The roster above prevents you editing
            # the same FILE; this is the only thing that prevents you building the same THING. That is
            # the collision that actually cost this project rework -- three sessions independently
            # fixing one npm advisory, in DIFFERENT files, so nothing file-shaped could have caught it.
            # Sourced from each session's own task list, so no one has to declare anything.
            $overlap = Join-Path $PSScriptRoot "..\coord\overlap.ps1"
            if (Test-Path $overlap) {
                $inflight = @()
                # Work that threw must not read as "nobody is building anything", so it says so,
                # protected. It goes with the other in-flight lines, after the claims.
                try { $inflight = @(& $overlap -Json | ConvertFrom-Json) } catch {
                    $inflight = @()
                    $overlapFault = "In-flight work: NOT READ ($(Format-Field $_.Exception.Message 120)). Run: scripts\coord\overlap.ps1"
                }
                # @($null).Count is 1, so a null Work or Files is filtered out before it is counted.
                $busy = @($inflight | Where-Object { $_.Live -and (@($_.Work | Where-Object { $_ }).Count -gt 0 -or @($_.Files | Where-Object { $_ }).Count -gt 0) })
                if ($busy.Count -gt 0) {
                    # Held back and printed after the claims: a claim has no other surface, so the byte
                    # backstop, which cuts from the end, should reach this section first.
                    $busyLines += ""
                    $busyLines += "WHAT THEY ARE BUILDING -- check first, so you don't build it twice:"
                    foreach ($b in @($busy | Select-Object -First $busyCap)) {
                        # Same id, same banner, same label -- see the note on the roster rows above.
                        #
                        # "beyond yours" is not decoration. overlap.ps1's Files narrows its committed
                        # half against the HEAD of whoever asked, so this count is relative to THIS
                        # session and a bare "changed" would overstate what the peer did.
                        $work = @($b.Work | Where-Object { $_ })
                        $busyLines += "  session $(Format-Field $b.Short 12) [$(Format-Field $b.Branch 50)] -- $(@($b.Files | Where-Object { $_ }).Count) file(s) changed beyond yours"
                        if ($work.Count) { $busyLines += "      $(Format-Field $work[0] 84)" }
                    }
                    if ($busy.Count -gt $busyCap) { $busyLines += "  +$($busy.Count - $busyCap) more" }
                    $busyLines += "  Everything in flight:  pwsh -NoProfile -File scripts\coord\overlap.ps1"
                }
            }
        }

        # BACKLOG #309: what the OTHER sessions are building, before you start building it too. The commit-msg
        # claim gate only enforces NUMBERED items; this banner is the whole mechanism for ad-hoc work -- and
        # ad-hoc work is what actually collided (three sessions, one npm advisory, two duplicate PRs).
        #
        # The registry may sit on the shared root (docs/COORD-SHARED-ROOT.md), so coord-root.ps1 names it.
        # This banner only reads: a root that does not answer is one line saying so, never a local guess
        # shown as the fleet's claims.
        $claimDir = $null
        $claimFault = ''
        $coordRootScript = Join-Path $PSScriptRoot '..\coord\coord-root.ps1'
        if (Test-Path -LiteralPath $coordRootScript -PathType Leaf) {
            try {
                . $coordRootScript
                $knownLocal = if ($commonDir) { Join-Path "$commonDir".Trim() 'mefor-coord' } else { '' }
                $resolvedClaims = Resolve-CoordDir -From (Get-Location).Path -Kind 'claims' -LocalRoot $knownLocal
                if ($resolvedClaims.Error) { $claimFault = $resolvedClaims.Error } else { $claimDir = $resolvedClaims.Path }
            } catch { $claimFault = "coord-root.ps1 failed: $($_.Exception.Message)" }
        } else {
            $claimFault = "$coordRootScript is missing"
        }
        if ($claimFault) {
            $lines += ""
            Add-Hazard "Active work claims: NOT READ -- the claim registry did not resolve ($(Format-Field $claimFault 160))."
        }
        $claimFiles = @(if ($claimDir) { Get-ChildItem $claimDir -Filter *.json -EA SilentlyContinue | Sort-Object Name })
        if ($claimFiles.Count -gt 0) {
            $meNorm = ($root -replace '\\', '/').TrimEnd('/')
            # EVERY claim still holds its key, however old, and nothing else shows a free-text one:
            # claim_check.py enforces only a numbered item cited in a commit subject. So the header
            # counts every claim and no age filter hides one, but the space is finite: this session's
            # own keys print first, then other sessions' claims as rows, most recently touched first,
            # then as many more keys as one line holds. claim.ps1 -List shows every one, with each
            # holder's liveness, which age cannot show. Age reads `refreshed`, which a -Take with
            # -Note on your own claim moves, as well as `claimed`, which never moves.
            $primaryNorm = if ($commonDir) { (("$commonDir".Trim() -replace '\\', '/').TrimEnd('/') -replace '/\.git$', '') } else { '' }
            $now = [datetime]::UtcNow
            $unreadable = 0
            $rows = @(foreach ($cf in $claimFiles) {
                $c = $null
                try { $c = Get-Content $cf.FullName -Raw | ConvertFrom-Json } catch { }
                if ($null -eq $c -or -not $c.key) { $unreadable++; continue }
                $heldNorm = ("$($c.worktree)" -replace '\\', '/').TrimEnd('/')
                # A claim from another machine names that machine's path, so it is never THIS session.
                $here = Test-CoordRecordIsHere $c
                $mine = $here -and $heldNorm -ieq $meNorm
                $touched = @(ConvertTo-ClaimUtc $c.claimed; ConvertTo-ClaimUtc $c.refreshed) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
                # An unreadable date is never called stale, as before: it sorts last instead.
                $age = if ($touched) { ($now - $touched).TotalHours } else { [double]::MaxValue }
                # ConvertFrom-Json turns a date-shaped key into a [datetime] and prints it in another
                # shape. The file name is claim.ps1's folded form of the key (ConvertTo-KeyFile), which
                # -Take folds to the same file, so it still names the claim.
                $key = if ($c.key -is [datetime] -or $c.key -is [datetimeoffset]) { $cf.BaseName } else { $c.key }
                # A key is an identity a reader must be able to pass back to claim.ps1, so it is
                # clipped only far past any real one.
                [pscustomobject]@{ Claim = $c; Key = (Format-Field $key 80); Mine = $mine; Here = $here; Age = $age; Held = $heldNorm }
            })
            $recent = @($rows | Where-Object { $_.Age -lt $staleHours }).Count
            $lines += ""
            $lines += "Active work claims ($($rows.Count), $recent touched in the last ${staleHours}h; all: scripts\coord\claim.ps1 -List) -- do NOT start one another session holds:"
            if ($unreadable -gt 0) { Add-Hazard "  WARNING: $unreadable claim file(s) in $(Format-Field $claimDir 120) could not be read, so they are not listed." }
            $mineRows = @($rows | Where-Object { $_.Mine })
            if ($mineRows.Count -gt 0) {
                Add-Hazard "  THIS session holds $($mineRows.Count): $(Format-Field (($mineRows | ForEach-Object Key) -join ', ') 160)"
            }
            # Key breaks ties, so equal ages (or unreadable dates) order the same in every run.
            $theirs = @($rows | Where-Object { -not $_.Mine } | Sort-Object -Property Age, Key)
            foreach ($r in @($theirs | Select-Object -First $claimCap)) {
                $c = $r.Claim
                # The leaf names the worktree; the full path and the branch are in claim.ps1 -List.
                # String ops, not Split-Path, which fails quietly on '' or 'D:' under SilentlyContinue.
                $leaf = if ($r.Here -and $primaryNorm -and $r.Held -ieq $primaryNorm) { "the SHARED PRIMARY" } else { Format-Field (($r.Held -split '/')[-1]) 40 }
                $who = if ($r.Here) { $leaf } else { "$leaf on $(Format-Field (Get-CoordRecordHost $c) 20)" }
                $stale = if ($r.Age -ge $staleHours -and $r.Age -ne [double]::MaxValue) { " [stale ~$([int]$r.Age)h]" } else { "" }
                $lines += "  $($r.Key) -- $(Format-Field $c.note 48)  (held by $who)$stale"
            }
            if ($theirs.Count -gt $claimCap) {
                $lines += "  +$($theirs.Count - $claimCap) more, by key: $(Format-Field ((@($theirs | Select-Object -Skip $claimCap) | ForEach-Object Key) -join ', ') 240)"
            }
        }
        $lines += $busyLines
        if ($overlapFault) { Add-Hazard "", $overlapFault }

        # The checkouts, last and short: this session's own row. `git worktree list` prints every one,
        # and at 471 of them that list alone pushed everything above out of the preview.
        $rootFwd = ($root -replace '\\', '/')
        $wtFwd = @($wt -replace '\\', '/')
        # The path, then whitespace, then the commit: a regex, not -like, whose `[` and `*` are
        # wildcards, and not a bare prefix, which a sibling at "<path> more" would also match.
        $ownPattern = '^' + [regex]::Escape($rootFwd) + '\s+[0-9a-f]{4,}\b'
        $ownRow = $wtFwd | Where-Object { $_ -match $ownPattern } | Select-Object -First 1
        # This section and the rules below go in $tail, which the budget below never cuts.
        # The header already gives the count and the path, so the row prints only what follows the
        # path: the commit, the branch and any lock. git pads the path column to the longest path, so
        # the padding is squeezed out.
        $tail += ""
        $own = if ($ownRow) { $ownRow.Substring($rootFwd.Length).Trim() -replace '\s{2,}', '  ' } else { '(not in git worktree list)' }
        $tail += "Your worktree:  $own  (every worktree: git worktree list)"

        # Nudge cleanup: count the <repo>-<name> siblings new.ps1 creates, so finished ones don't pile up.
        $siblingPrefix = "$rootFwd-"
        $siblingCount = @($wtFwd | Where-Object { $_.StartsWith($siblingPrefix, [StringComparison]::OrdinalIgnoreCase) }).Count
        if ($siblingCount -ge 1) {
            $tail += "  [cleanup] $siblingCount sibling worktree(s) exist. Prune the finished (merged + clean) ones:"
            $tail += "       scripts\worktree\prune-merged.ps1        (dry-run; add -Apply to remove)"
        }

        $tail += ""
        $tail += "Coordination rules for parallel sessions (see docs/WORKTREES.md):"
        $onBranch = if ($branch) { "this worktree's branch ('$branch')" } else { "this worktree (detached HEAD)" }
        $tail += "  - Keep ALL changes on $onBranch; never edit files in a sibling worktree. Use THIS worktree's .venv."
        $tail += "  - Claim work before you start it: scripts\coord\claim.ps1 -Take <key> -Note `"<what>`""
        $tail += "  - Project memory (~/.claude/.../memory) is SHARED, last write wins: write it only if the user says this session owns it."
    }
}

# Two bounds behind the row caps, because row counts alone do not bound bytes. Format-Field clips
# each field a peer's record supplies, so a long path, branch or task line cannot grow a row. And past
# the budget the end of the lists goes, with one line naming the sections cut; the lists run in
# priority order, and the hazard lines (Add-Hazard) and the short fixed sections in $tail always print.
#
# WHICH LINES SURVIVE MUST NOT DEPEND ON WHERE THE REPO LIVES. Measured 2026-10-22: counting the path
# as it is, a CI runner's longer temp path cut two list lines that a desktop kept. So the count reads
# every copy of this worktree's path, and of the primary checkout's, which the claims directory sits
# under, in either slash form, as a fixed 260 bytes. That keeps the cut the same everywhere. A longer
# path, or another machine-dependent value (git's SHA width, the branch name), can still move it.
# The budget is a target, not a ceiling: the backstop never cuts a hazard line or $tail, so when those
# alone pass the budget the banner overshoots it, by design.
# tests/test_session_context_presence.py reads $byteBudget and $pathReserve from these lines.
$byteBudget = 4000
$pathReserve = 260
$primaryRoot = if ($commonDir) { ("$commonDir".Trim() -replace '[\\/]\.git[\\/]?$', '') } else { '' }
# Longest first, so a path that contains another is replaced whole.
$pathForms = @(foreach ($p in @("$root", $primaryRoot)) { if ($p) { $p -replace '\\', '/'; $p -replace '/', '\' } }) |
    Select-Object -Unique | Sort-Object -Property Length -Descending
$reserveToken = 'P' * $pathReserve
# -ireplace with an escaped pattern, not the three-argument String.Replace, which Windows PowerShell
# 5.1's .NET Framework does not have.
$measure = {
    param($a)
    $t = $a -join "`n"
    foreach ($f in $pathForms) { $t = $t -ireplace [regex]::Escape($f), $reserveToken }
    [Text.Encoding]::UTF8.GetByteCount($t)
}
if ((& $measure ($lines + $tail)) -gt $byteBudget) {
    # Cut from the end, skipping every line Add-Hazard recorded, until the rest fits beside $tail and
    # the closing line. The closing line names each section it cut from, so a reader knows which view
    # is short. 260 bytes is room for that line at its longest: three section names and the commands.
    $room = $byteBudget - (& $measure $tail) - 260
    $section = 'header'
    $sectionOf = @(foreach ($l in $lines) {
        if ($l -like 'LIVE sessions*') { $section = 'live peers' }
        elseif ($l -like 'Active work claims*') { $section = 'work claims' }
        elseif ($l -like 'WHAT THEY ARE BUILDING*') { $section = 'what they are building' }
        $section
    })
    $drop = New-Object bool[] $lines.Count
    $used = 0
    for ($i = 0; $i -lt $lines.Count; $i++) { $used += (& $measure @($lines[$i])) + 1 }
    for ($i = $lines.Count - 1; $i -ge 0 -and $used -gt $room; $i--) {
        if ($hazard -contains $i) { continue }
        $drop[$i] = $true
        $used -= (& $measure @($lines[$i])) + 1
    }
    $cut = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($drop[$i] -and $lines[$i]) { $i } })
    $kept = @(for ($i = 0; $i -lt $lines.Count; $i++) { if (-not $drop[$i]) { $lines[$i] } })
    $cutSections = @($cut | ForEach-Object { $sectionOf[$_] } | Select-Object -Unique) -join ', '
    $lines = $kept + "[session-context] cut $($cut.Count) line(s) from: $cutSections, to fit the budget. Run: scripts\coord\presence.ps1 -All, scripts\coord\claim.ps1 -List, scripts\coord\overlap.ps1"
}
(($lines + $tail) -join "`n") | Write-Output
