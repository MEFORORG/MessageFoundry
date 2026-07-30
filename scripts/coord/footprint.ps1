<#
.SYNOPSIS
    Where has a session actually WRITTEN -- the occupancy signal that does not depend on a recorded cwd.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\footprint.ps1"
        $fp = Get-WorktreeFootprints -Worktrees $worktrees -WindowHours 36
        if (-not $fp.Available) { <refuse to do anything destructive> }

    WHY THIS EXISTS. The liveness fence in occupancy.ps1 places a session by the cwd it was LAUNCHED
    in, and nothing ever rewrites that field. A session therefore reports one location while writing
    into several. Measured on this repo 2026-07-30: of the writes that landed in a `<primary>-<slug>`
    sibling -- the only class prune-merged.ps1 destroys -- 88.9% came from a session whose recorded cwd
    was a DIFFERENT checkout, and the fence placed a session inside 0 of the 4 candidates that existed
    when the measurement was taken. The mechanism is not drift: a workflow fans subagents into N
    sibling worktrees while the registry holds ONE record, carrying ONE cwd, for the parent. No matcher
    improvement can fix that, because the field simply does not record where the writing happens.

    WHAT IT READS. Claude Code's own transcripts, `<config-root>/projects/**/*.jsonl`, one JSON object
    per line. A tool call appears as a `tool_use` block carrying the ABSOLUTE target path of the write
    (`input.file_path` / `input.notebook_path`) alongside the session's cwd -- the one place in the
    system where the two are visible together, and therefore the only place the divergence above can be
    observed. Subagent transcripts live at `projects/<projdir>/<sessionId>/subagents/[workflows/
    wf_<id>/]agent-<id>.jsonl`; they carry 100% of the cross-worktree signal on this repo, so the scan
    is recursive from `projects/` and never assumes a layout below it.

    NOTHING IS INSTALLED AND NOTHING IS RECORDED. There is no hook, no settings.json entry, no store,
    no renewal loop, and therefore no write-side race and no way for a recorder failure to touch a tool
    call. The corpus is already on disk; this reads it.

    PATHS ONLY. `input` also carries the full text a Write was given and the full command line a Bash
    call ran. Extraction is an ALLOW-LIST over two keys and everything else is discarded unread; no
    value from a transcript reaches an output row except a filesystem path and a session id, and a
    line that fails to parse is reported by file and line NUMBER, never by content (the parser's own
    exception message quotes the offending fragment, so it is deliberately not propagated).

    AVAILABILITY IS PART OF THE ANSWER. Same rule as occupancy.ps1, for the same reason: "scanned and
    found nobody" and "could not scan" produce the same empty list, so this returns a receipt and sets
    Available only when the scan could actually run -- at least one config root, and NO fault. A fault
    is an in-window transcript that will not open, a needle-bearing line that will not parse (a torn
    tail is exactly this shape), or a CANARY failure. Any of them makes this signal unavailable, which
    makes the whole fence unavailable, which refuses every candidate.

    A ROOT WITH NO CORPUS IS NOT A FAULT, AND IT IS NOT SILENCE EITHER. A machine with no transcripts
    is a legitimate state, and a fence that bricks itself on it is a fence an operator learns to
    bypass. So `RootsWithCorpus = 0` leaves this available and contributing nothing -- and says so, in
    those words. Callers must print `CandidatesWithoutFootprint` rather than a bare zero: "3 of 5
    candidates have no footprint, so for those this signal contributed nothing" is the honest reading
    of the same number.

    THE CANARY, AND WHY IT IS SHAPED LIKE THIS. This infers over a format nobody promised us. A
    recorder we own breaks loudly; inference goes quietly to zero -- which is the same "confident green
    over nothing" this repo keeps being bitten by. So the scan asserts, on live data, that the
    extractor still understands what it is reading:
      * needle-bearing transcripts exist but NOT ONE tool_use block carries a known path key => the
        input shape moved;
      * transcripts under a `subagents/` directory exist but NOT ONE parsed line reports isSidechain
        => the subagent marker moved;
      * sidechain lines exist but NOT ONE of them carries a known path key => subagent extraction
        specifically has gone to zero, while parent extraction stays green.
    The third is the one that matters and the reason the first two are not enough: every cross-tree
    write on this repo came from a sidechain line, so a canary that only proves a PARENT write is
    extractable would stay green while the entire signal disappeared. None of the three can be
    satisfied vacuously -- each requires the extractor to have produced something.
    RESIDUAL RISK, STATED RATHER THAN PAPERED OVER: if transcripts move out of `<config-root>/
    projects` altogether, every counter goes to zero together and nothing in here can tell that from a
    quiet week. `RootsWithCorpus` and `TranscriptsFound` are in the receipt for exactly that reason.

    WHAT IT CANNOT SEE:
      * a write by anything that is not a Claude tool call -- a human editing in VS Code, an editor
        autosave, a plain terminal, a background process spawned by a tool call. Those leave no
        transcript, ever;
      * a file written BY a shell command: the transcript carries the command string, not a resolved
        path list. Deliberately not parsed here (the worktree gate needed ~200 lines to model cd/-C/
        pushd/quoting and still fails open on unmodelled spellings);
      * a session that started before this window;
      * whether the writer is still alive -- a footprint is a past-tense fact. That is what the
        liveness fence below is for.

    LIVENESS, AND WHY A MISSING RECORD STILL VETOES. Each footprint is fenced through the SAME
    session-registry fence signal 1 uses. Only a POSITIVELY proven-gone verdict releases it: DEAD (the
    pid is not running) or STALE (the pid belongs to a different process). LIVE, UNVERIFIED, UNREADABLE
    and UNREGISTERED all veto -- UNREGISTERED because a session with no record looks identical to one
    that exited cleanly, and absence of evidence is not evidence of absence. The window is what bounds
    that: an unfenceable footprint vetoes until it ages out, never forever.
#>

# The liveness fence and the shared path normaliser, one level down.
. "$PSScriptRoot\session-registry.ps1"

# Tool calls that WRITE. A Read is not occupancy: a worktree somebody merely looked at is not a
# worktree somebody is working in, and treating it as one would veto on a `cat`.
$script:FootprintWriteTools = @('Write', 'Edit', 'MultiEdit', 'NotebookEdit')

# The ONLY keys read out of a tool call's input. Everything else -- the file body a Write carries, the
# command line a Bash call ran -- is discarded unread. An allow-list by key, never a regex over the
# raw line, so a path-shaped substring of a file body can never become a footprint.
$script:FootprintPathKeys = @('file_path', 'notebook_path')

# States that must VETO. Only DEAD/STALE release a footprint, because only they are positive proof the
# writer is gone; see the header on UNREGISTERED.
$script:FootprintVetoStates = @('LIVE', 'UNVERIFIED', 'UNREADABLE', 'UNREGISTERED')

# Below this, a common prefix is too weak to be worth using as a file-level filter and the full needle
# set is used instead -- slower, never wrong.
$script:FootprintMinPrefix = 8

function Test-FootprintVeto {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$State)
    return ($script:FootprintVetoStates -contains $State)
}

# A path as it is SPELLED inside a transcript line. JSON escapes a backslash as two characters, so
# C:\repo\x arrives as C:\\repo\\x; a forward-slash spelling arrives unchanged.
#
# CANONICALISE FIRST, THEN BUILD BOTH SPELLINGS. `git worktree list --porcelain` reports paths with
# FORWARD slashes on Windows, while a transcript records the write target with backslashes. Deriving
# the escaped needle by replacing backslashes in git's output is therefore a NO-OP: the two needles
# come out identical, the backslash spelling -- the only one real transcripts use -- has no needle at
# all, and the scan examines a fraction of the corpus while reporting Available with zero faults.
# Measured on this repo before the fix: 224 writes placed out of 428, with two worktrees a live
# session had written 79 times between them showing as untouched. The needle self-check in
# Get-WorktreeFootprints exists to make that specific regression a FAULT rather than a quiet green.
function Get-FootprintNeedles([string]$Path) {
    if (-not $Path) { return @() }
    $b = $Path.TrimEnd('\', '/')
    if (-not $b) { return @() }
    $fwd = $b.Replace('\', '/')
    $back = $fwd.Replace('/', '\')
    # The trailing separator is deliberate: a write is always <worktree><sep><something>, and without
    # it `<primary>` would match every `<primary>-<slug>` sibling as well.
    return @(($back.Replace('\', '\\') + '\\'), ($fwd + '/'))
}

# Longest case-insensitive common prefix, used to collapse N needles into one cheap file-level filter.
# The result is a PREFIX of every needle, so filtering on it can only ever admit too much -- which is
# the only direction a funnel in front of a safety signal may be wrong in.
function Get-FootprintCommonPrefix([string[]]$Values) {
    $vals = @($Values | Where-Object { $_ })
    if ($vals.Count -eq 0) { return '' }
    $p = $vals[0]
    foreach ($v in $vals) {
        $n = [Math]::Min($p.Length, $v.Length)
        $i = 0
        while ($i -lt $n -and [char]::ToLowerInvariant($p[$i]) -eq [char]::ToLowerInvariant($v[$i])) { $i++ }
        $p = $p.Substring(0, $i)
        if (-not $p) { break }
    }
    return $p
}

# git's own identity for a checkout, which is spelling-independent. The literal prefix match below is
# a string compare, so a path recorded as a UNC share, an 8.3 short name, a `subst` drive or through a
# junction normalises to something that is not the worktree's own path and places nowhere. Walking up
# to `.git` and reading where it points answers in git's spelling instead of ours.
# NOTE the asymmetry that makes a naive version silently split the key set: the PRIMARY's `.git` is a
# DIRECTORY (a Windows path, backslashes) while a linked worktree's `.git` is a FILE containing a
# forward-slash path. Both sides go through ConvertTo-Norm for that reason.
function Get-WorktreeGitdirIndex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Worktrees)
    $ix = @{}
    foreach ($w in $Worktrees) {
        if (-not $w.Path) { continue }
        $dot = Join-Path $w.Path '.git'
        if (Test-Path -LiteralPath $dot -PathType Container) {
            $ix[(ConvertTo-Norm $dot)] = $w
            continue
        }
        if (Test-Path -LiteralPath $dot -PathType Leaf) {
            $txt = ''
            try { $txt = Get-Content -LiteralPath $dot -Raw -EA Stop } catch { continue }
            if ($txt -match 'gitdir:\s*(.+)') { $ix[(ConvertTo-Norm ($Matches[1].Trim()))] = $w }
        }
    }
    return $ix
}

# Which worktree owns $Dir, by git's answer rather than by string shape. Memoised over every directory
# on the walk, because a scan resolves the same handful of directories thousands of times.
function Resolve-GitdirWorktree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Dir,
        [Parameter(Mandatory)][hashtable]$GitdirIndex,
        [Parameter(Mandatory)][hashtable]$Memo
    )
    if (-not $Dir) { return $null }
    $chain = @()
    $cur = $Dir
    $hit = $null
    while ($cur) {
        $k = ConvertTo-Norm $cur
        if ($Memo.ContainsKey($k)) { $hit = $Memo[$k]; break }
        $chain += $k
        $dot = Join-Path $cur '.git'
        # Lexical walk: the file itself may be long gone (it was deleted, or the worktree was), and a
        # resolution that required it to exist would go quiet exactly when a tree is being cleaned up.
        if (Test-Path -LiteralPath $dot) {
            $target = $null
            if (Test-Path -LiteralPath $dot -PathType Container) { $target = ConvertTo-Norm $dot }
            else {
                $txt = ''
                try { $txt = Get-Content -LiteralPath $dot -Raw -EA Stop } catch { $txt = '' }
                if ($txt -match 'gitdir:\s*(.+)') { $target = ConvertTo-Norm ($Matches[1].Trim()) }
            }
            if ($target -and $GitdirIndex.ContainsKey($target)) { $hit = $GitdirIndex[$target] }
            break
        }
        # Lexical, not Split-Path: `Split-Path -Parent` binds -Path, which treats [ ] in a directory
        # name as a wildcard character class -- the same trap that made the candidate-set prefix test
        # match nothing under a bracketed directory.
        $parent = ''
        try { $parent = [System.IO.Path]::GetDirectoryName($cur) } catch { $parent = '' }
        if (-not $parent -or (ConvertTo-Norm $parent) -eq $k) { break }
        $cur = $parent
    }
    foreach ($c in $chain) { $Memo[$c] = $hit }
    return $hit
}

<#
Scan the transcript corpus and report where each session has WRITTEN, fenced for liveness.

Returns a pscustomobject:
    Available            [bool]   the scan could run (>=1 config root, no fault). NEVER a claim that
                                  nobody is anywhere -- see the header.
    Detail               [string] why it is unavailable, '' when it is available
    Note                 [string] why it contributed nothing, when it did (no corpus / quiet window)
    WindowHours          [double] the window that was applied
    RootsExamined        [int]    config roots looked at
    RootsWithCorpus      [int]    of those, the ones holding a projects/ directory
    TranscriptsFound     [int]    every .jsonl under those, at any age
    TranscriptsInWindow  [int]    those whose mtime is inside the window (the ones actually opened)
    TranscriptsWithNeedle[int]    of those, the ones mentioning a worktree of this repo at all
    BytesScanned         [long]   characters read while filtering
    LinesScanned         [int]    lines looked at in needle-bearing transcripts
    LinesParsed          [int]    of those, the ones carrying a needle AND a tool_use marker
    PathBlocksExamined   [int]    tool_use blocks carrying a known path key (the canary's denominator)
    WritesExamined       [int]    write tool calls with a path, inside the window
    WritesOutsideWindow  [int]    write tool calls dropped for being older than the window
    WritesUndated        [int]    write tool calls with no readable timestamp -- kept, fail-closed
    WritesPlaced         [int]    of those examined, the ones landing in a worktree of THIS repo
    WritesUnplaced       [int]    the rest. "somewhere else" and "here, spelled differently" are
                                  indistinguishable at this line, which is why it is counted
    PlacedByPrefix       [int]    placed by the literal path match
    PlacedByGitdir       [int]    placed only after resolving through .git -- the spellings the string
                                  compare cannot see
    GitdirProbes         [int]    directories the gitdir walk had to touch. Zero while WritesUnplaced
                                  is non-zero means the fallback is not running at all
    GitdirUnresolvable   [int]    written paths with no derivable parent directory
    SidechainFiles       [int]    in-window transcripts under a subagents/ directory
    SidechainLines       [int]    parsed lines reporting isSidechain
    SidechainPathBlocks  [int]    path-bearing tool_use blocks on those lines
    CrossTreeWrites      [int]    writes whose session cwd is NOT inside the worktree written to --
                                  the population signal 1 is structurally unable to see
    Faults               [array]  {File, Why}; ANY of them => Available false
    Footprints           [array]  one row per (session, worktree) pair with a write in the window
#>
function Get-WorktreeFootprints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Worktrees,
        [string[]]$ConfigRoot,
        [double]$WindowHours = 36,
        [int]$StartSkewMinutes = 15
    )

    $now = Get-Date
    $cut = $now.AddHours(-1 * [Math]::Abs($WindowHours))

    $r = [ordered]@{
        Available = $false; Detail = ''; Note = ''
        WindowHours = $WindowHours
        RootsExamined = 0; RootsWithCorpus = 0
        TranscriptsFound = 0; TranscriptsInWindow = 0; TranscriptsWithNeedle = 0
        BytesScanned = [long]0; LinesScanned = 0; LinesParsed = 0
        PathBlocksExamined = 0
        WritesExamined = 0; WritesOutsideWindow = 0; WritesUndated = 0
        WritesPlaced = 0; WritesUnplaced = 0
        PlacedByPrefix = 0; PlacedByGitdir = 0; GitdirProbes = 0; GitdirUnresolvable = 0
        SidechainFiles = 0; SidechainLines = 0; SidechainPathBlocks = 0
        CrossTreeWrites = 0
        Faults = @(); Footprints = @()
    }
    $faults = @()

    $wts = @($Worktrees | Where-Object { $_ -and $_.Path })
    if ($wts.Count -eq 0) {
        $r.Detail = 'no worktrees to scope the scan to'
        return [pscustomobject]$r
    }

    $roots = @()
    try { $roots = @(Get-ClaudeConfigRoots -ConfigRoot $ConfigRoot) }
    catch {
        $r.Detail = "config roots unreadable: $($_.Exception.GetType().Name)"
        return [pscustomobject]$r
    }
    $r.RootsExamined = $roots.Count
    if ($roots.Count -eq 0) {
        $r.Detail = 'no Claude config root was found, so the transcript corpus could not be scanned at all'
        return [pscustomobject]$r
    }

    # --- Needles ---------------------------------------------------------------------------------
    $wtIndex = @{}
    foreach ($w in $wts) { $wtIndex[(ConvertTo-Norm $w.Path)] = $w }
    $primaryNorm = ConvertTo-Norm $wts[0].Path

    $escaped = @(); $slashed = @()
    foreach ($w in $wts) {
        $n = @(Get-FootprintNeedles $w.Path)
        if ($n.Count -eq 2) { $escaped += $n[0]; $slashed += $n[1] }
    }
    # NEEDLE SELF-CHECK, and it is not hypothetical -- it is the regression that was measured. A
    # JSON-escaped Windows path contains NO forward slash, so an "escaped" needle that still has one
    # was never converted: the backslash spelling has collapsed into the forward-slash one and this
    # signal is reading a fraction of the corpus while every counter still looks healthy. A funnel in
    # front of a safety signal that quietly narrows is the same defect as a fence that quietly finds
    # nobody. (Checking merely for a doubled backslash is NOT enough -- the trailing separator supplies
    # one on its own, so the broken needle passed that test. Measured on the mutant.)
    $badNeedles = @()
    for ($i = 0; $i -lt $escaped.Count; $i++) {
        if ($slashed[$i].IndexOf('/') -ge 0 -and $escaped[$i].IndexOf('/') -ge 0) { $badNeedles += $escaped[$i] }
    }
    if ($badNeedles.Count -gt 0) {
        $faults += [pscustomobject]@{
            File = '(needles)'
            Why = "$($badNeedles.Count) worktree path(s) produced no backslash-spelled needle, so the spelling transcripts actually use would not be searched for at all"
        }
    }

    $pe = Get-FootprintCommonPrefix $escaped
    $ps = Get-FootprintCommonPrefix $slashed
    # A family spread across drives has no useful common prefix; fall back to every needle rather than
    # to a one-character filter that admits the whole corpus.
    $fileNeedles =
    if ($pe.Length -ge $script:FootprintMinPrefix -and $ps.Length -ge $script:FootprintMinPrefix) { @($pe, $ps) }
    else { @($escaped + $slashed) }
    $fileNeedles = @($fileNeedles | Where-Object { $_ } | Select-Object -Unique)
    if ($fileNeedles.Count -eq 0) {
        $r.Detail = 'no usable path needle could be built from the worktree list'
        return [pscustomobject]$r
    }

    # --- Stage 1: enumerate, and keep only what the window can possibly contain -------------------
    $inWindow = @()
    foreach ($root in $roots) {
        $projects = Join-Path $root 'projects'
        if (-not (Test-Path -LiteralPath $projects -PathType Container)) { continue }
        $r.RootsWithCorpus++
        $files = $null
        try {
            $files = [System.IO.Directory]::EnumerateFiles($projects, '*.jsonl', [System.IO.SearchOption]::AllDirectories)
        }
        catch {
            # A corpus that cannot be ENUMERATED is the hole that lets a whole source vanish while the
            # receipt still reports the root. It is a fault, not a quiet zero.
            $faults += [pscustomobject]@{ File = $projects; Why = "the transcript corpus could not be enumerated ($($_.Exception.GetType().Name))" }
            continue
        }
        try {
            foreach ($f in $files) {
                $r.TranscriptsFound++
                $mt = [System.IO.File]::GetLastWriteTime($f)
                # A file last written before the cut cannot contain a line newer than it.
                if ($mt -lt $cut) { continue }
                $inWindow += $f
            }
        }
        catch {
            $faults += [pscustomobject]@{ File = $projects; Why = "the transcript corpus stopped enumerating part-way ($($_.Exception.GetType().Name))" }
        }
    }
    $r.TranscriptsInWindow = $inWindow.Count

    # --- Stages 2 and 3: file-level needle, then line-level parse ---------------------------------
    $gitdirIndex = Get-WorktreeGitdirIndex -Worktrees $wts
    $memo = @{}
    $agg = @{}

    foreach ($f in $inWindow) {
        $isSidechainFile = ((ConvertTo-Norm $f) -match '/subagents/')
        if ($isSidechainFile) { $r.SidechainFiles++ }
        $txt = $null
        try { $txt = [System.IO.File]::ReadAllText($f) }
        catch {
            # In the window and unreadable: it could name any worktree, including the one about to be
            # destroyed. Refuse the run; do not quietly examine one transcript fewer.
            $faults += [pscustomobject]@{ File = $f; Why = "an in-window transcript could not be read ($($_.Exception.GetType().Name))" }
            continue
        }
        $r.BytesScanned += $txt.Length
        $hit = $false
        foreach ($n in $fileNeedles) {
            if ($txt.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true; break }
        }
        if (-not $hit) { continue }
        $r.TranscriptsWithNeedle++

        $all = $txt.Split("`n")
        # A TORN TAIL IS NOT A tool_use LINE. The cheap '"tool_use"' pre-filter below is what makes
        # this scan affordable, but a line truncated mid-write may have been cut BEFORE that marker --
        # and a half-written final line naming a worktree is precisely the shape of a session writing
        # RIGHT NOW. So the last line of a file that does not end in a newline is checked on its own,
        # by PARSING it: a complete-but-unterminated line parses and costs nothing, a truncated one
        # does not and is a fault. Gating this on the marker would have let the dangerous case through.
        if ($all.Count -gt 0 -and -not $txt.EndsWith("`n")) {
            $tail = $all[$all.Count - 1]
            $tailNeedle = $false
            foreach ($n in $fileNeedles) {
                if ($tail.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $tailNeedle = $true; break }
            }
            if ($tailNeedle) {
                try { $null = $tail | ConvertFrom-Json -EA Stop }
                catch {
                    $faults += [pscustomobject]@{
                        File = $f
                        Why = "the final line mentions a worktree of this repo and will not parse -- it is half-written, which is what a session writing right now looks like"
                    }
                }
            }
        }

        $lineNo = 0
        foreach ($line in $all) {
            $lineNo++
            $r.LinesScanned++
            if ($line.Length -lt 2) { continue }
            if ($line.IndexOf('"tool_use"', [StringComparison]::Ordinal) -lt 0) { continue }
            $ln = $false
            foreach ($n in $fileNeedles) {
                if ($line.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $ln = $true; break }
            }
            if (-not $ln) { continue }
            $r.LinesParsed++

            $obj = $null
            try { $obj = $line | ConvertFrom-Json -EA Stop }
            catch {
                # A half-written final line is exactly this shape, and it is the shape of a session
                # writing RIGHT NOW. The parser's message quotes the fragment it choked on, so only the
                # location is reported -- never the content.
                $faults += [pscustomobject]@{ File = $f; Why = "line $lineNo mentions a worktree of this repo and will not parse (torn, or the format changed)" }
                continue
            }
            if (-not $obj) { continue }

            $sidechain = ($obj.PSObject.Properties['isSidechain'] -and $obj.isSidechain -eq $true)
            if ($sidechain) { $r.SidechainLines++ }

            $msg = $obj.message
            if (-not $msg) { continue }
            $content = $msg.content
            if ($null -eq $content) { continue }
            foreach ($b in @($content)) {
                if (-not $b -or -not $b.PSObject.Properties['type'] -or $b.type -ne 'tool_use') { continue }
                $inp = $b.input
                if (-not $inp) { continue }
                $target = ''
                foreach ($k in $script:FootprintPathKeys) {
                    if ($inp.PSObject.Properties[$k]) { $target = [string]$inp.$k; if ($target) { break } }
                }
                if (-not $target) { continue }
                # Counted for EVERY path-bearing tool call, a Read included: this is the canary's
                # denominator, and a denominator that only counted writes would go to zero on a quiet
                # window and make the canary vacuous.
                $r.PathBlocksExamined++
                if ($sidechain) { $r.SidechainPathBlocks++ }
                if ($script:FootprintWriteTools -notcontains [string]$b.name) { continue }

                # ConvertFrom-Json has ALREADY turned the ISO-8601 timestamp into a [datetime] with
                # Kind=Utc. Casting that back to a string renders it in the current culture and
                # re-parsing the result reads a UTC wall-clock as a LOCAL one -- an error the size of
                # the machine's UTC offset, silently applied to the window boundary. Take the typed
                # value when there is one and only parse when there is not.
                $when = $null
                $tsv = $obj.timestamp
                if ($tsv -is [datetime]) { $when = ([datetime]$tsv).ToLocalTime() }
                elseif ($tsv -is [DateTimeOffset]) { $when = ([DateTimeOffset]$tsv).LocalDateTime }
                elseif ($tsv) {
                    try {
                        $when = [DateTimeOffset]::Parse([string]$tsv, [Globalization.CultureInfo]::InvariantCulture,
                            [Globalization.DateTimeStyles]::RoundtripKind).LocalDateTime
                    }
                    catch { $when = $null }
                }
                if ($null -eq $when) { $r.WritesUndated++ }
                elseif ($when -lt $cut) { $r.WritesOutsideWindow++; continue }
                $r.WritesExamined++

                $norm = ConvertTo-Norm $target
                $match = $null; $bestLen = -1
                foreach ($k in $wtIndex.Keys) {
                    if ($norm -eq $k -or $norm.StartsWith("$k/")) {
                        if ($k.Length -gt $bestLen) { $match = $wtIndex[$k]; $bestLen = $k.Length }
                    }
                }
                $how = 'prefix'
                if ($match) { $r.PlacedByPrefix++ }
                else {
                    # The literal compare failed. Ask git, via the directory the write landed in.
                    # GetDirectoryName, NOT `Split-Path -LiteralPath ... -Parent`: -LiteralPath and
                    # -Parent are different PARAMETER SETS, so that call throws every time -- and with
                    # the throw swallowed, this whole fallback was dead code that reported 0 probes
                    # while looking like it ran. Measured before the fix: 2090 unplaced writes and not
                    # one gitdir probe attempted.
                    $dir = ''
                    try { $dir = [System.IO.Path]::GetDirectoryName($target) } catch { $dir = '' }
                    if ($dir) {
                        $before = $memo.Count
                        $match = Resolve-GitdirWorktree -Dir $dir -GitdirIndex $gitdirIndex -Memo $memo
                        $r.GitdirProbes += [Math]::Max(0, $memo.Count - $before)
                    }
                    else { $r.GitdirUnresolvable++ }
                    if ($match) { $how = 'gitdir'; $r.PlacedByGitdir++ }
                }
                if (-not $match) {
                    # NOT silence. "a write into another repo" and "a write into this one, spelled a way
                    # the matcher does not recognise" are indistinguishable here, and the second is a
                    # missed veto -- so the ambiguity is counted and reported rather than dropped.
                    $r.WritesUnplaced++
                    continue
                }
                $r.WritesPlaced++

                $sid = [string]$obj.sessionId
                $cwd = [string]$obj.cwd
                $mn = ConvertTo-Norm $match.Path
                $cn = ConvertTo-Norm $cwd
                $cross = -not ($cn -and ($cn -eq $mn -or $cn.StartsWith("$mn/")))
                if ($cross) { $r.CrossTreeWrites++ }

                $key = "$sid|$mn"
                if (-not $agg.ContainsKey($key)) {
                    $agg[$key] = [pscustomobject]@{
                        SessionId = $sid; Worktree = $match; Writes = 0
                        Last = $null; Cwd = $cwd; Cross = $false; How = $how
                    }
                }
                $e = $agg[$key]
                $e.Writes++
                if ($cross) { $e.Cross = $true }
                if ($cwd) { $e.Cwd = $cwd }
                if ($when -and ($null -eq $e.Last -or $when -gt $e.Last)) { $e.Last = $when }
            }
        }
        $txt = $null
    }

    # --- The canary ------------------------------------------------------------------------------
    # See the header. Each condition requires the extractor to have PRODUCED something, so none of them
    # can pass by measuring nothing.
    if ($r.TranscriptsWithNeedle -gt 0 -and $r.PathBlocksExamined -eq 0) {
        $faults += [pscustomobject]@{
            File = '(canary)'
            Why = "$($r.TranscriptsWithNeedle) in-window transcript(s) mention a worktree of this repo, but not one tool call carried a known path key -- the transcript format has moved and this signal is reading nothing"
        }
    }
    if ($r.SidechainFiles -gt 0 -and $r.SidechainLines -eq 0 -and $r.LinesParsed -gt 0) {
        $faults += [pscustomobject]@{
            File = '(canary)'
            Why = "$($r.SidechainFiles) subagent transcript(s) are in the window but not one parsed line reports isSidechain -- the subagent marker has moved"
        }
    }
    if ($r.SidechainLines -gt 0 -and $r.SidechainPathBlocks -eq 0) {
        $faults += [pscustomobject]@{
            File = '(canary)'
            Why = "$($r.SidechainLines) subagent line(s) were parsed but not one carried a known path key -- SUBAGENT extraction has gone to zero, which is where every cross-worktree write on this repo comes from"
        }
    }

    # --- Fence each footprint ---------------------------------------------------------------------
    $records = @()
    try { $records = @(Get-SessionRecords -ConfigRoot $ConfigRoot) }
    catch {
        $faults += [pscustomobject]@{ File = '(registry)'; Why = "the session registry could not be read to fence the footprints ($($_.Exception.GetType().Name))" }
    }
    $bySid = @{}
    foreach ($rec in $records) {
        $sid = [string]$rec.Record.sessionId
        if ($sid) { $bySid[$sid.ToLowerInvariant()] = $rec }
    }
    $liveness = @{}

    $rows = @()
    foreach ($e in $agg.Values) {
        $sidKey = ([string]$e.SessionId).ToLowerInvariant()
        if (-not $liveness.ContainsKey($sidKey)) {
            if ($sidKey -and $bySid.ContainsKey($sidKey)) {
                $rec = $bySid[$sidKey]
                $l = $null
                # A record that cannot be fenced (a non-numeric pid throws in the cast) must VETO, not
                # take the caller down and not vanish.
                try { $l = Test-RecordLiveness -Record $rec.Record -StartSkewMinutes $StartSkewMinutes }
                catch { $l = @{ State = 'UNREADABLE'; Detail = "record could not be fenced: $($_.Exception.GetType().Name)" } }
                $recPid = 0
                try { $recPid = [int]$rec.Record.pid } catch { $recPid = 0 }
                $liveness[$sidKey] = @{
                    State = $l.State; Detail = $l.Detail; Pid = $recPid
                    Entrypoint = [string]$rec.Record.entrypoint; Kind = [string]$rec.Record.kind; Root = $rec.Root
                }
            }
            else {
                $liveness[$sidKey] = @{
                    State = 'UNREGISTERED'
                    Detail = 'the session that wrote here has no registry record, which is what a clean exit and a session that never registered both look like'
                    Pid = 0; Entrypoint = ''; Kind = ''; Root = ''
                }
            }
        }
        $l = $liveness[$sidKey]
        $sid = [string]$e.SessionId
        $rows += [pscustomobject]@{
            Source       = 'footprint'
            State        = $l.State
            Detail       = $l.Detail
            SessionId    = $sid
            Short        = if ($sid) { $sid.Substring(0, [Math]::Min(8, $sid.Length)) } else { '?' }
            Pid          = $l.Pid
            Cwd          = $e.Cwd
            Entrypoint   = $l.Entrypoint
            Kind         = $l.Kind
            Root         = $l.Root
            StartedAt    = ''
            WorktreePath = $e.Worktree.Path
            Worktree     = if ((ConvertTo-Norm $e.Worktree.Path) -eq $primaryNorm) { 'primary' } else { Split-Path $e.Worktree.Path -Leaf }
            IsPrimary    = ((ConvertTo-Norm $e.Worktree.Path) -eq $primaryNorm)
            Branch       = $e.Worktree.Branch
            Writes       = $e.Writes
            LastWriteAt  = if ($e.Last) { $e.Last.ToString('o') } else { '' }
            CrossTree    = $e.Cross
            PlacedBy     = $e.How
        }
    }

    $r.Faults = @($faults | ForEach-Object { "$($_.File) -- $($_.Why)" })
    $r.Footprints = @($rows)
    if ($faults.Count -gt 0) {
        $r.Available = $false
        $r.Detail = "$($faults.Count) transcript fault(s), so the write-footprint scan is incomplete and cannot clear any worktree: $(($faults | ForEach-Object { "$($_.File) ($($_.Why))" }) -join '; ')"
    }
    else {
        $r.Available = $true
        if ($r.RootsWithCorpus -eq 0) {
            $r.Note = "$($r.RootsExamined) config root(s) examined and NOT ONE holds a transcript corpus, so this signal contributed nothing to this run"
        }
        elseif ($r.TranscriptsInWindow -eq 0) {
            $r.Note = "$($r.TranscriptsFound) transcript(s) found and none was written inside the $WindowHours h window, so this signal contributed nothing to this run"
        }
        elseif ($r.TranscriptsWithNeedle -eq 0) {
            $r.Note = "$($r.TranscriptsInWindow) transcript(s) were in the window and none mentions a worktree of this repo, so this signal contributed nothing to this run"
        }
    }
    return [pscustomobject]$r
}

# The footprint rows that must VETO an action against $Path. Same shape and same nesting rule as
# Get-WorktreeOccupants, so a caller cannot accidentally apply a laxer rule to one signal than the
# other: removing a parent takes a nested checkout with it, so a footprint in the nested tree vetoes
# the ancestor too.
function Get-WorktreeFootprintOccupants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Footprint,
        [Parameter(Mandatory)][string]$Path,
        [switch]$IncludeNested
    )
    $norm = ConvertTo-Norm $Path
    return @($Footprint.Footprints | Where-Object {
            $wt = ConvertTo-Norm $_.WorktreePath
            (Test-FootprintVeto $_.State) -and
            ($wt -eq $norm -or ($IncludeNested -and $wt.StartsWith("$norm/")))
        })
}
