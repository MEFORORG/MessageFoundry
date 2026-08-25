# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Adjudicate stranded work claims PER KEY, against the durable protection on origin/main.
    Reports and emits commands. Writes nothing, ever -- there is no -Apply and there will not be one.

.DESCRIPTION
    `claim-reconcile.ps1` asks: "did the BRANCH this claim names land?" That question is sound, and
    where it answers yes the release is safe. But a branch is not the unit a claim is about.

    MEASURED 2026-08-18 on the live registry: 20 stranded claims sat on SIX branches, and one of
    those branches carried NINE keys. Those nine claims each received the same verdict for the same
    reason -- "74 commit(s) are not on origin/main" -- which is a fact about the branch and says
    nothing whatever about any one of the nine items. reconcile judged 0 of 20 releasable
    that day. That is not a defect in it: a seat branch accumulates commits from every item the seat
    touched, so branch containment can only ever clear a whole seat at once, and a long-lived seat
    branch never clears.

    THE QUESTION THIS FILE ASKS INSTEAD, and it is the project's own, not one invented here.

    Item #1010's banner on origin/main states the doctrine outright:

        "THE CLAIM PROTECTING IT DOES NOT REPLICATE. #1010 is claimed on one machine, so it is
         absent from the unclaimed pool THERE -- and mefor-coord/claims/ is machine-local and
         unversioned. A seat on any other checkout sees an open, unclaimed, buildable item whose
         work already shipped. This banner is the protection that travels; the claim is not."

    So a claim is not valuable in itself. It is valuable only as protection against a duplicate
    build, and it is a WEAK form of that protection, because it is machine-local and unversioned. The
    moment origin/main carries something that protects the item better -- a CLOSED status banner, or
    a do-not-rebuild banner naming the landing -- the claim is guarding a door already locked from
    the other side, on every checkout, for everyone.

    That is the single release criterion here:

        SUPERSEDED = the item exists in the backlog namespace on origin/main
                     AND its banner there already protects it.

    Nothing else is ever proposed for release. Not age, not quiet, not "the note says it is done".

.NOTES
    WHAT IS DELIBERATELY NOT A RELEASE CRITERION, each because it was tried against the live data on
    2026-08-18 and produced a wrong answer.

    * A `BACKLOG #N` CITATION IN A LANDED COMMIT. It reads like proof and is not. Grepping
      origin/main for `BACKLOG #340` hits 41a8c493, whose message reads "...ci.yml (07b6e55a) and in
      BACKLOG #340, making this the third document to..." -- PROSE REFERENCE, not delivery.
      `BACKLOG #328` hits ca8a7488, "Also BACKLOG #328, sections 1-2" -- delivery of TWO SECTIONS of
      an item, which is not the item. backlog-hygiene.yml matches the bare token `BACKLOG #[0-9]+`
      anywhere in a PR title or body ON PURPOSE, because it enforces that a claiming PR updates the
      banner; it is not, and does not pretend to be, a closure oracle. Citations are collected and
      PRINTED here so a human can follow them, and they never move a verdict.

    * A NOTE THAT SAYS THE WORK IS DONE. Claim notes are carried verbatim and shown, never believed.
      A note may NOMINATE a hypothesis; only origin/main may confirm it. #1010's note said "ALREADY
      LANDED ON MAIN ... Verify before believing me" and it was correct -- and what licenses acting
      on it is that the banner on origin/main independently says so, not that the note did.

    * A BANNER READING OPEN. This cuts one way only. #1010's item on origin/main carries NO status
      glyph at all while carrying a landed-and-do-not-rebuild banner, and its own text explains why:
      "a banner protects nobody until it is on main", and the flip was written on an unmerged branch.
      So OPEN means "not superseded HERE", never "not landed". An OPEN item whose branch carries
      unmerged commits is reported as blocking, never as available.

    WHY THERE IS NO -Apply. `claim.ps1` owns the .history ledger: it writes the record BEFORE
    removing the file and refuses the release if the record cannot be written (BACKLOG #1068). A
    second writer of that file would be a second definition of it. This emits `claim.ps1 -Release`
    lines for a human to read and run. The bias is claim-reconcile.ps1's, unchanged and restated: a
    false release hands a key to a second session and invites the duplicate build the registry
    exists to stop, which is strictly worse than a stale line in a file.

    WHAT THIS CANNOT SEE. It reads the backlog namespace on origin/main and nothing else. A key that
    is not a backlog number -- `ha-recheck-inc145` and `usage-forecast` on the live registry -- has
    no item to read and is reported NO-ITEM, which means "this instrument does not reach it", never
    "it is worthless". Read SUPERSEDED as a floor on what is safe to release, and every other verdict
    as a question this could not close.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\claim-adjudicate.ps1
    pwsh -NoProfile -File scripts\coord\claim-adjudicate.ps1 -Json
    pwsh -NoProfile -File scripts\coord\claim-adjudicate.ps1 -Key 1010
    pwsh -NoProfile -File scripts\coord\claim-adjudicate.ps1 -IncludeHeld
#>
[CmdletBinding()]
param(
    # Machine-readable output for a caller that wants to act on the classification.
    [switch]$Json,
    # Adjudicate one key only. The key as it appears in the registry, not a file name.
    [string]$Key = "",
    # Also adjudicate claims whose holder still exists. Off by default: a live holder is being worked
    # and the claim is doing its job, so the question does not arise.
    [switch]$IncludeHeld,
    # Audit a claims set that is not the live registry -- the same escape hatch, and for the same
    # reason, as claim-reconcile.ps1's: replaying these rules over already-released claims lets a
    # release be cross-checked without a second copy of the rules existing anywhere.
    [string]$ClaimsDir = ""
)

$ErrorActionPreference = "Stop"

# Banners carry emoji. On a cp1252 console git's output decodes to mojibake and every glyph test
# silently fails -- a gate unreadable exactly when it fires is BACKLOG #1221, and this file will not
# add a second instance of it.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

# Anchored on the SCRIPT, not the caller's directory: this must resolve the repo it belongs to even
# when invoked by absolute path from another worktree. Same reasoning as alloc.ps1 and claim.ps1.
$repo = (& git -C $PSScriptRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
if (-not $repo) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }
$repo = $repo.Trim()
$common = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
$claimsDir = if ($ClaimsDir) { $ClaimsDir } else { Join-Path $common "mefor-coord/claims" }
$claimTool = Join-Path $PSScriptRoot "claim.ps1"

function ConvertTo-Norm([string]$Path) {
    if (-not $Path) { return "" }
    ($Path -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $claimsDir)) {
    # NEVER LOOKED is not CLEAN. A tidy report over a directory that was never read is the silence
    # these tools exist to remove.
    if ($Json) { [pscustomobject]@{ scanned = $false; claims = @() } | ConvertTo-Json -Depth 6 }
    else { Write-Host "No claims directory at $claimsDir -- nothing was scanned." -ForegroundColor Yellow }
    exit 0
}

# origin/main is the reference, never local main: measured 2026-08-16, local main was 24 commits
# behind on this clone. Here the staleness bites in a specific way -- a banner that has landed but
# not been fetched reads as ABSENT, which holds a claim that is safe to release.
$mainRef = if ((& git -C $repo rev-parse --verify --quiet "origin/main")) { "origin/main" } else { "main" }
$mainIsRemote = ($mainRef -eq "origin/main")

# ---------------------------------------------------------------------------------------------
# THE BACKLOG NAMESPACE ON $mainRef.
#
# It spans MORE THAN ONE FILE and always has: docs/BACKLOG.md carries open items, retired ones are
# moved verbatim into docs/archive/backlog/. backlog_status_check.py parses every default source into
# ONE namespace precisely so a number re-used across the two is detectable. Reading only BACKLOG.md
# here would make every CLOSED item look like it had no item at all -- turning the safest releases
# in the population into unreachable ones, silently.
# ---------------------------------------------------------------------------------------------
$backlogFiles = @(& git -C $repo ls-tree -r --name-only $mainRef -- docs/ 2>$null |
    Where-Object { $_ -match 'BACKLOG' -and $_ -like '*.md' })
if (-not $backlogFiles.Count) {
    throw "no backlog file found on ${mainRef}: cannot adjudicate any key against a namespace that was not read"
}

$corpus = @{}
foreach ($bf in $backlogFiles) {
    $text = (& git -C $repo show "${mainRef}:$bf" 2>$null) -join "`n"
    if ($text) { $corpus[$bf] = $text }
}

# The status vocabulary is backlog_status_check.py's, not this file's. Held as codepoints so the
# source stays readable on a console that cannot render them.
$CLOSED_GLYPH = [ordered]@{}
$CLOSED_GLYPH[[char]::ConvertFromUtf32(0x2705)]  = "shipped"
$CLOSED_GLYPH[[char]::ConvertFromUtf32(0x26D4)]  = "declined"
$CLOSED_GLYPH[[char]::ConvertFromUtf32(0x1FAA6)] = "retired"
$OPEN_GLYPH = [ordered]@{}
$OPEN_GLYPH[[char]::ConvertFromUtf32(0x1F522)] = "prioritized"
$OPEN_GLYPH[[char]::ConvertFromUtf32(0x1F6A7)] = "in progress"

# A do-not-rebuild banner is prose, so it is matched on the few phrasings that assert the LANDING
# ITSELF. A bare "do not build" is deliberately absent: a note reading "DO NOT BUILD half B" is
# scope, not a landing, and #340's claim says exactly that about work nobody has done.
$LANDED_BANNER = @(
    'DO NOT REBUILD'
    'THE BUILD HAS LANDED'
    'ALREADY LANDED ON'
    'HAS LANDED ON `?origin/main'
)

function Get-ItemBlock([string]$ItemKey) {
    # The item's text and the file it came from, or $null. Only a whole-number key can name a backlog
    # item; anything else belongs to a different namespace and must not be pattern-matched into this
    # one.
    if ($ItemKey -notmatch '^\d+$') { return $null }
    foreach ($f in ($corpus.Keys | Sort-Object)) {
        $text = $corpus[$f]
        $m = [regex]::Match($text, '(?m)^##\s+' + [regex]::Escape($ItemKey) + '\.\s')
        if (-not $m.Success) { continue }
        $rest = $text.Substring($m.Index)
        $nxt = [regex]::Match($rest.Substring($m.Length), '(?m)^##\s')
        $block = if ($nxt.Success) { $rest.Substring(0, $m.Length + $nxt.Index) } else { $rest }
        return [pscustomobject]@{ File = $f; Text = $block }
    }
    return $null
}

function Get-LeadingQuote([string]$Block) {
    # The banner run: the contiguous blockquote lines that OPEN the item, blank lines allowed between
    # quoted paragraphs. Bounded at the first ordinary prose line, because a blockquote deeper in the
    # body is a citation or an aside and is not the item's status.
    #
    # THE WINDOW IS THE WHOLE RUN, NOT A FIXED NUMBER OF LINES. A 14-line window was tried first on
    # 2026-08-18 and reported #1010 as having no banner: its landed-and-do-not-rebuild banner runs
    # past thirty. A banner missed reads as "not superseded", which holds a claim that is safe to
    # release -- the harmless direction, but it silently empties this tool of its purpose.
    $lines = $Block -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*>') { $out.Add($l); continue }
        if ($l.Trim() -eq '') { continue }
        break
    }
    return ($out -join "`n")
}

# ---------------------------------------------------------------------------------------------
# Delivery citations. COLLECTED AND PRINTED, NEVER SCORED -- see .NOTES.
# ---------------------------------------------------------------------------------------------
# A SIBLING CITATION IS STILL A CITATION, AND THIS FOUND NONE OF THEM (BACKLOG #1347).
#
# The old query was `--grep="BACKLOG #$ItemKey"`, which matches only when the item is the one
# carrying the prefix. The house form writes the prefix ONCE -- `(BACKLOG #1319, #1322, #1323,
# #1331)` -- so three of those four were invisible here, and the failure direction is the expensive
# one: work that landed reads as never delivered, and a dispatcher hands a builder a finished item.
# The control is `df8acc95`, the commit that misled two seats into holding three claims for landed
# work.
#
# TWO STAGES, because neither alone is right. git finds CANDIDATES by the number, which is cheap and
# has good recall; the scoped regex then decides whether the number is really a backlog citation.
# Doing it in one `--grep` is what forces the choice between missing siblings and matching anything.
#
# THE SCOPE IS THE PARENTHETICAL, and that is what keeps a squash suffix out. A landed subject reads
# `(BACKLOG #1040) (#547)`; a rule that took every `#N` after the BACKLOG token would report #547 as
# a delivery of item 547. Measured over `git log --all` on 2026-08-25: unscoped calls 641 subjects
# multi-item, parenthetical-scoped calls 38 of 1070.
#
# STILL COLLECTED AND PRINTED, NEVER SCORED -- see .NOTES. This widens RECALL of a display; it does
# not turn a citation into proof of delivery, which the .NOTES block explains at length it is not.
function Get-Citations([string]$ItemKey) {
    if ($ItemKey -notmatch '^\d+$') { return @() }
    # Candidates: any subject naming this number at all. Deliberately broader than the old query.
    $raw = @(& git -C $repo log --format="%h%x09%s" --grep="#$ItemKey([^0-9]|`$)" -E --max-count=40 $mainRef 2>$null)
    # Inside a `(BACKLOG ... )` group, or after a bare `BACKLOG` token with no parenthetical.
    $inParen = [regex]"(?i)\(\s*BACKLOG\b[^)]*?#$ItemKey\b[^)]*\)"
    $afterTok = [regex]"(?i)\bBACKLOG\b[^(]*?#$ItemKey\b"
    $out = @()
    foreach ($r in $raw) {
        $p = $r -split "`t", 2
        if ($p.Count -lt 2) { continue }
        $subject = $p[1]
        if (-not ($inParen.IsMatch($subject) -or $afterTok.IsMatch($subject))) { continue }
        $out += [pscustomobject]@{ commit = $p[0]; subject = $subject }
        if ($out.Count -ge 5) { break }   # the old cap, applied AFTER filtering rather than before
    }
    return $out
}

# The REGISTERED worktrees -- a different set from the directories that exist. A claim pointing at a
# directory that is gone but still registered is HALF A REMOVAL: prune-merged.ps1 completes it and
# releases as it goes, and stepping in front of that here would skip its merged-and-clean proof.
$registered = @{}
foreach ($line in (& git -C $repo worktree list --porcelain)) {
    if ($line -like 'worktree *') { $registered[(ConvertTo-Norm $line.Substring(9))] = $true }
}

$rows = @()
$files = @(Get-ChildItem -LiteralPath $claimsDir -Filter *.json -File -EA SilentlyContinue | Sort-Object Name)
foreach ($f in $files) {
    $k = $f.BaseName
    try { $c = Get-Content -LiteralPath $f.FullName -Raw -Encoding utf8 -EA Stop | ConvertFrom-Json -EA Stop }
    catch {
        # An unreadable claim belongs to the registry, not to any worktree. claim_check.py reads a
        # malformed claim as UNCLAIMED, so the key is ALREADY ungated -- deleting the file would hide
        # that rather than fix it.
        $rows += [pscustomobject]@{ key = $k; holder = ""; branch = ""; note = ""; item = ""
            banner = ""; citations = @(); verdict = "UNREADABLE"; why = $_.Exception.Message }
        continue
    }

    $k = if ($c.key) { [string]$c.key } else { $f.BaseName }
    if ($Key -and $k -ne $Key) { continue }
    $holder = ConvertTo-Norm ([string]$c.worktree)
    $branch = [string]$c.branch
    $note = [string]$c.note

    $exists = $holder -and (Test-Path -LiteralPath $holder)
    if ($exists -and -not $IncludeHeld) {
        $rows += [pscustomobject]@{ key = $k; holder = $holder; branch = $branch; note = $note
            item = ""; banner = ""; citations = @(); verdict = "HELD"
            why = "holder directory exists -- the claim is doing its job and the question does not arise" }
        continue
    }
    if (-not $exists -and $holder -and $registered.ContainsKey($holder)) {
        $rows += [pscustomobject]@{ key = $k; holder = $holder; branch = $branch; note = $note
            item = ""; banner = ""; citations = @(); verdict = "STRANDED-REGISTERED"
            why = "directory gone but the worktree is still registered -- run prune-merged.ps1, which releases as it removes" }
        continue
    }

    $block = Get-ItemBlock $k
    # @() re-wraps what PowerShell unrolled on return. Without it a SINGLE citation reaches
    # ConvertTo-Json as a bare object rather than a one-element array, so a JSON consumer that
    # iterates `citations` gets field NAMES when there is one hit and records when there are two --
    # a shape that changes with the data is worse than one that is always awkward.
    $cites = @(Get-Citations $k)

    if (-not $block) {
        $rows += [pscustomobject]@{ key = $k; holder = $holder; branch = $branch; note = $note
            item = ""; banner = ""; citations = $cites; verdict = "NO-ITEM"
            why = "'$k' names no item in the backlog namespace on $mainRef -- this instrument does not reach it, which is not a finding about the work" }
        continue
    }

    $lead = Get-LeadingQuote $block.Text
    $bannerState = ""; $bannerWhy = ""

    foreach ($g in $CLOSED_GLYPH.Keys) {
        if ($lead.Contains($g)) { $bannerState = "CLOSED/" + $CLOSED_GLYPH[$g]; break }
    }
    if (-not $bannerState) {
        foreach ($p in $LANDED_BANNER) {
            if ([regex]::IsMatch($lead, $p, 'IgnoreCase')) {
                $bannerState = "LANDED-BANNER"
                # Quote the banner's own sentence back, so the verdict carries the observation it
                # rests on rather than a label the reader must take on trust.
                $line = ($lead -split "`n" | Where-Object { [regex]::IsMatch($_, $p, 'IgnoreCase') } | Select-Object -First 1)
                $bannerWhy = ($line -replace '^\s*>\s*', '') -replace '\*', ''
                $bannerWhy = $bannerWhy.Trim()
                break
            }
        }
    }
    if (-not $bannerState) {
        foreach ($g in $OPEN_GLYPH.Keys) {
            if ($lead.Contains($g)) { $bannerState = "OPEN/" + $OPEN_GLYPH[$g]; break }
        }
    }
    if (-not $bannerState) { $bannerState = "NO-BANNER" }

    if ($bannerState -like 'CLOSED/*' -or $bannerState -eq 'LANDED-BANNER') {
        $quote = if ($bannerWhy) { ": `"" + $bannerWhy.Substring(0, [Math]::Min(140, $bannerWhy.Length)) + "`"" } else { "" }
        $rows += [pscustomobject]@{ key = $k; holder = $holder; branch = $branch; note = $note
            item = $block.File; banner = $bannerState; citations = $cites; verdict = "SUPERSEDED"
            why = "the item's banner on $mainRef already protects it ($bannerState)$quote -- that protection travels to every checkout and this machine-local claim does not" }
    }
    else {
        $ahead = $null
        if ($branch) {
            $ref = $null
            foreach ($cand in @($branch, "origin/$branch")) {
                if (& git -C $repo rev-parse --verify --quiet $cand) { $ref = $cand; break }
            }
            if ($ref) { $ahead = [int](& git -C $repo rev-list --count "$mainRef..$ref") }
        }
        $aheadTxt = if ($null -eq $ahead) { "branch '$branch' is on neither this clone nor origin" }
                    elseif ($ahead -eq 0) { "'$branch' carries no commit $mainRef lacks" }
                    else { "'$branch' carries $ahead commit(s) $mainRef lacks" }
        $rows += [pscustomobject]@{ key = $k; holder = $holder; branch = $branch; note = $note
            item = $block.File; banner = $bannerState; citations = $cites; verdict = "BLOCKING"
            why = "item reads $bannerState on $mainRef and $aheadTxt -- so the key is unclaimable by any future session while nothing on $mainRef protects it" }
    }
}

# ---------------------------------------------------------------------------------------------
# OUTPUT
# ---------------------------------------------------------------------------------------------
if ($Json) {
    [pscustomobject]@{
        scanned   = $true
        reference = $mainRef
        applied   = $false
        sources   = [pscustomobject]@{ claims = $claimsDir; backlog = @($backlogFiles) }
        counts    = [pscustomobject]@{
            total      = $rows.Count
            superseded = @($rows | Where-Object verdict -eq 'SUPERSEDED').Count
            blocking   = @($rows | Where-Object verdict -eq 'BLOCKING').Count
            noitem     = @($rows | Where-Object verdict -eq 'NO-ITEM').Count
            held       = @($rows | Where-Object verdict -eq 'HELD').Count
            other      = @($rows | Where-Object { $_.verdict -in @('UNREADABLE', 'STRANDED-REGISTERED') }).Count
        }
        claims    = $rows
    } | ConvertTo-Json -Depth 6
    exit 0
}

if (-not $mainIsRemote) {
    Write-Host "WARNING: origin/main is not present on this clone; every verdict below was taken against LOCAL main." -ForegroundColor Yellow
    Write-Host "         A banner that has landed but not been fetched reads as absent, which HOLDS releasable claims." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "CLAIM ADJUDICATION -- per key, against the durable protection on $mainRef" -ForegroundColor Cyan
Write-Host "  claims  : $claimsDir"
Write-Host "  backlog : $($backlogFiles -join ', ')"
Write-Host "  writes  : NONE. This tool has no -Apply. The release lines below are for you to run."
Write-Host ""

$sup = @($rows | Where-Object verdict -eq 'SUPERSEDED')
$blk = @($rows | Where-Object verdict -eq 'BLOCKING')
$nit = @($rows | Where-Object verdict -eq 'NO-ITEM')
$oth = @($rows | Where-Object { $_.verdict -in @('UNREADABLE', 'STRANDED-REGISTERED') })
$hld = @($rows | Where-Object verdict -eq 'HELD')

Write-Host "SUPERSEDED  $($sup.Count)   -- origin/main already protects the item; the claim adds nothing and can go" -ForegroundColor Green
Write-Host "BLOCKING    $($blk.Count)   -- nothing on origin/main protects the item, so the key is stuck: unclaimable AND unbuilt" -ForegroundColor Yellow
Write-Host "NO-ITEM     $($nit.Count)   -- key is outside the backlog namespace; this instrument does not reach it"
if ($oth.Count) { Write-Host "OTHER       $($oth.Count)   -- unreadable, or a half-finished removal prune-merged.ps1 owns" }
if ($hld.Count) { Write-Host "HELD        $($hld.Count)   -- holder exists; not adjudicated" }
Write-Host ""

if ($sup.Count) {
    Write-Host "-- SUPERSEDED ------------------------------------------------------------------" -ForegroundColor Green
    foreach ($r in $sup) {
        Write-Host ("  {0,-18} {1}   [{2}]" -f $r.key, $r.banner, $r.item) -ForegroundColor Green
        Write-Host ("  {0,-18} {1}" -f "", $r.why)
        Write-Host ("  {0,-18} pwsh -NoProfile -File {1} -Release {2} -Force" -f "", $claimTool, $r.key) -ForegroundColor Cyan
        Write-Host ""
    }
}

if ($blk.Count) {
    Write-Host "-- BLOCKING, grouped by branch: the decision is per BRANCH, not per key ---------" -ForegroundColor Yellow
    # The roll-up is the point. Twenty stranded keys were six branch decisions on 2026-08-18, and a
    # per-key list hides that one "land it or abandon it" call clears nine of them at once.
    foreach ($grp in ($blk | Group-Object branch | Sort-Object Count -Descending)) {
        $keys = (@($grp.Group | ForEach-Object { $_.key }) | Sort-Object) -join ', '
        $plural = if ($grp.Count -eq 1) { "" } else { "s" }
        Write-Host ("  {0}" -f $grp.Name) -ForegroundColor Yellow
        Write-Host ("      {0} key{1}: {2}" -f $grp.Count, $plural, $keys)
        Write-Host ("      {0}" -f ($grp.Group[0].why -replace '^item reads \S+ on \S+ and ', ''))
        Write-Host ("      one decision for the branch -- land it, or abandon it and release all {0}." -f $grp.Count)
        Write-Host ""
    }
}

if ($nit.Count) {
    Write-Host "-- NO-ITEM ---------------------------------------------------------------------"
    foreach ($r in $nit) { Write-Host ("  {0,-18} {1}" -f $r.key, $r.why) }
    Write-Host ""
}

if ($oth.Count) {
    Write-Host "-- OTHER -----------------------------------------------------------------------"
    foreach ($r in $oth) { Write-Host ("  {0,-18} {1}: {2}" -f $r.key, $r.verdict, $r.why) }
    Write-Host ""
}

Write-Host "Read SUPERSEDED as a floor on what is safe to release, never as a ceiling on what has landed."
Write-Host "Every other verdict is a question this instrument could not close, not a finding that the work is live."
