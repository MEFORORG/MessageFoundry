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

    NO PATH FUNNEL IN FRONT OF THE PLACEMENT. Every tool_use line of every in-window transcript is
    parsed and every write is PLACED; nothing is skipped for failing to contain a worktree path as a
    literal substring. It used to be: a file-level and then a line-level "does this text contain
    <worktree><sep>" test ran BEFORE placement, which made the .git fallback below unreachable by
    construction -- the fallback exists precisely for the spellings (junction, UNC, 8.3, subst) that
    contain no such substring, and every line carrying one had already been dropped. Measured: a
    registered LIVE session writing into a candidate through a junction produced Available=true, zero
    faults, WritesExamined=0, WritesUnplaced=0 -- invisible to every counter -- and the worktree was
    destroyed under -Apply. Removing the funnel costs ~3% more parses (measured on the real corpus:
    31,033 -> 31,980 lines) because the files were already being READ in full to test them.
    The needles still exist, for the TranscriptsWithNeedle counter and canary 1 alone; they no longer
    decide what is examined.

    AVAILABILITY IS PART OF THE ANSWER. Same rule as occupancy.ps1, for the same reason: "scanned and
    found nobody" and "could not scan" produce the same empty list, so this returns a receipt and sets
    Available only when the scan could actually run -- at least one config root, and NO fault. A fault
    is an in-window transcript that will not open, an in-window transcript that VANISHED between being
    enumerated and being stat'd (its window membership is then unknowable), a line that will not parse
    in a transcript touching this repo family (a torn tail is exactly this shape), or a CANARY failure.
    Any of them makes this signal unavailable, which makes the whole fence unavailable, which refuses
    every candidate.

    A PARSE FAULT IS SCOPED TO THIS REPO FAMILY, AND THAT IS A DELIBERATE, MEASURED TRADE. The scan is
    machine-wide, so faulting on any unparseable line anywhere would refuse every run for as long as
    ANY session on the host is mid-append -- a fence nobody can use is a fence that gets bypassed. A
    line that will not parse is therefore a FAULT when its file mentions this repo family anywhere (the
    cheap common prefix, which deliberately over-admits) or produced a placed write, and is COUNTED as
    LinesUnparseableElsewhere otherwise. RESIDUAL, STATED: a transcript that has never named this
    family, torn exactly on its first write into a candidate, is counted rather than refused. That
    worktree is by construction brand-new, which is what the birth pin (pin.ps1, signal 4) and fresh
    git metadata (signal 2) cover.

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
      * tool calls that target a path BY DEFINITION (Read/Write/Edit/Glob/Grep/...) exist but NOT ONE
        of them carries a known path key => the input shape moved;
      * transcripts under a `subagents/` directory exist but NOT ONE parsed line reports isSidechain
        => the subagent marker moved;
      * sidechain path-tool calls exist but NOT ONE carries a known path key => subagent extraction
        specifically has gone to zero, while parent extraction stays green;
      * path-bearing tool calls exist, NOT ONE of them is named by the WRITE allow-list, AND at least
        one of them is named by something NEITHER allow-list claims => the tool vocabulary moved.
        The third clause is the canary, not decoration on it. Without it the same test also fires on a
        window that was merely quiet -- it did, once, in an hourly replay across 1,109 h of real
        history -- because a rename leaves Read/Grep/Glob intact and "no write was seen" is therefore
        the signature of a rename AND of an idle afternoon. Zero writes with every path-bearing name
        accounted for by a tool that cannot write is a NOTE instead, and signal 3 abstains for the run.
    Canary 1 is denominated on the TOOL NAME and canary 4 on the extracted PATH, deliberately in
    opposite directions: a pure key move zeroes the paths while the names stay, a pure name rename
    zeroes the names while the paths stay, and each canary is blind to the one the other catches.
    RESIDUAL, STATED: both moving in the same release defeats both, because every counter goes to zero
    together -- and canary 4's residue test with them, since a renamed tool that also dropped the path
    key never reaches PathBlocksExamined at all. What is left then is the Note ("not one write
    placed"), which the caller prints as REDUCED ASSURANCE in red -- visible, but not a refusal.
    The third is the reason the first two are not enough: every cross-tree write on this repo came from
    a sidechain line, so a canary that only proves a PARENT write is extractable would stay green while
    the entire signal disappeared. The fourth is the reason the first three are not enough either --
    all of them are denominated on PATH-BEARING blocks, which a rename of the write TOOL NAMES leaves
    completely healthy. Measured: renaming Write/Edit in the allow-list took the signal from 5 vetoes
    to 0 with Available=true, faults=0, an empty Note and pathBlocksExamined UP by three, and a live
    session's worktree went from SKIP to PRUNE. None of the four can be satisfied vacuously -- each
    requires the extractor to have produced something.
    Canary numerators and denominators are BOTH machine-wide. Canary 2 used to count sidechain FILES
    across every project on the host and sidechain LINES only within this repo, so one subagent run in
    an unrelated project refused every prune for up to 36 h and blamed a vendor schema change that had
    not happened (measured: 122 of 475 in-window subagent transcripts on this host already belong to
    other projects). Removing the path funnel above is what makes the two sides comparable.
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
# GUARDED BY CANARY 4, because this list is the single point where the whole signal can go to zero
# while every other counter stays healthy: it is matched against a vendor vocabulary nobody promised
# us, and it has already outlived one rename by the accident of being a SUPERSET (MultiEdit is in it
# and is not in the current tool surface).
$script:FootprintWriteTools = @('Write', 'Edit', 'MultiEdit', 'NotebookEdit')

# The ONLY keys read out of a tool call's input. Everything else -- the file body a Write carries, the
# command line a Bash call ran -- is discarded unread. An allow-list by key, never a regex over the
# raw line, so a path-shaped substring of a file body can never become a footprint.
# `path` (Grep/Glob) is here for the CANARY's denominator, not for placement. A non-write tool never
# becomes a footprint -- the write allow-list above is applied after this.
$script:FootprintPathKeys = @('file_path', 'notebook_path', 'path')

# Tools that target a path BY DEFINITION. Canary 1's denominator, and the reason it cannot brick on a
# quiet window: it used to be "needle-bearing transcripts exist but no path key was seen", which fires
# on a perfectly healthy 36 h window whose only in-repo tool calls were shell or search commands (a
# monitoring loop, a CI babysit, a git-only session) -- refusing every prune, with no override flag,
# and blaming a vendor schema change that had not happened. Asking instead "did a tool that MUST carry
# a path fail to carry one" is the same detection with none of the false positives.
$script:FootprintPathToolNames = @('Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'NotebookRead', 'Glob', 'Grep')

# Tools that carry a path key and CANNOT write a file through it. The NEGATIVE half of the write
# allow-list, and the entire reason canary 4 below no longer refuses a run on a window that was merely
# quiet. Canary 4 used to be denominated on the ABSENCE of writes, and absence is not evidence: a
# rename of the write tools leaves Read/Grep/Glob completely intact, so "known reads present, zero
# writes" is the signature of a moved vocabulary AND the signature of an ordinary idle afternoon, and
# nothing about the write names can tell those two apart inside one window. This list is what moves the
# question off absence and onto residue -- "did anything carry a path that NEITHER list can account
# for" -- which a single window CAN answer, because a renamed write tool arrives as a name that is by
# construction in neither list while still carrying file_path.
# MEASURED 2026-07-30, on the real corpus over the preceding 36 h (779 in-window transcripts), the tool
# names that actually carried a path key: Read 4841, Edit 3509, Grep 1048, Write 909, Glob 32,
# EnterWorktree 13. EnterWorktree was the ONLY path-bearing name neither allow-list claimed, so it is
# named here and that day's healthy corpus classified at 100% with canary 4's numerator sitting at
# exactly zero.
# ENTERWORKTREE IS LISTED ON THE TOOL'S OWN DECLARED SCHEMA, not on an inference from 13 observed
# blocks. Verified 2026-07-30 against the live tool definition: it accepts exactly two inputs, `name`
# and `path`, and `path` is documented as the path of an existing worktree to switch INTO instead of
# creating one -- a DIRECTORY the session enters, never a file it modifies. It therefore cannot be a
# write through the path key this scanner reads, whatever else it does.
# DO NOT ADD ExitWorktree HERE "BY SYMMETRY", which is the mistake this comment exists to head off: it
# takes only `action` and `discard_changes`, carries no path key at all, and so can never reach the
# path-bearing branch these lists are consulted from. Adding it would be a claim about a tool this
# scanner never sees, and every unnecessary name in this list is a name that would silently absorb a
# future rename onto it.
# Whether entering a worktree should VETO in its own right is a real question and a DIFFERENT one; it
# is not answered here, and behaviour is unchanged either way (placement has always been gated on the
# write allow-list above, so listing EnterWorktree here loses no veto that exists today).
# AN MCP-NAMESPACED TOOL THAT CARRIES A PATH KEY IS NOT EXEMPT AND MUST NOT BE MADE EXEMPT BY ITS
# NAMESPACE. A blanket "anything with a `mcp__` prefix is harmless" escape fails open in the
# destructive direction -- a connector that edits files would be waved through by the shape of its
# name -- so such names stay in the numerator and hard-fault like any other unknown. The 2026-07-30
# census found no MCP tool carrying a path key at all, so this is a theoretical cost today, and the
# remedy when it is not is per-NAME classification after somebody has established what that one tool
# does, never a namespace-wide carve-out.
# DO NOT LATER REPLACE THE RESIDUE TEST WITH A SHARE OR A VOLUME THRESHOLD -- it is the one change that
# would silently undo this fix, because the ratio is backwards at exactly the volumes the fence has to
# be right about. At the arming condition (all four write names absent) the unclassified SHARE simply
# IS the window's write share, so a quiet window carrying a handful of renamed edits sits below any
# workable bar while a single unclassified block in a one-block window sits at 100%. The rename this
# canary exists to catch is the low-volume case; a threshold suppresses precisely that one.
# THE MAINTENANCE HAZARD, SAID OUT LOUD BECAUSE THIS LIST IS THE ONLY WAY THE FIX CAN BE UNDONE: every
# name added here is an assertion about a vendor's semantics that nobody promised us, and adding a name
# to silence a fault is how a real rename becomes invisible. A fault from canary 4 means some name
# carried a path and this scan cannot say what it does. The remedy is to find out and then put it in
# $FootprintWriteTools (it writes) or here (it provably cannot) -- never to put it here because that is
# the branch that stops complaining.
$script:FootprintKnownNonWriteTools = @('Read', 'NotebookRead', 'Glob', 'Grep', 'EnterWorktree')

# WHICH STATES VETO IS NOT DECIDED HERE. Only DEAD/STALE release a footprint (see the header on
# UNREGISTERED), and that rule lives in ONE place -- $OccupancyVetoStates / Test-OccupancyVeto in
# occupancy.ps1, which is what every caller filters through. This file used to carry a second copy plus
# a Test-FootprintVeto nobody called; two copies of a safety rule drift, and the copy that drifts is
# the one nobody is testing.

# Below this, a common prefix is too weak to be worth using as a screen in front of the exact needle
# test and the full needle set is used instead -- slower, never wrong.
$script:FootprintMinPrefix = 8

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
    TranscriptsVanished  [int]    enumerated and gone before they could be stat'd -- a FAULT, because
                                  a file that is no longer there cannot be ruled in or out of the window
    TranscriptsWithNeedle[int]    of those opened, the ones mentioning a worktree of this repo at all.
                                  A COUNTER and canary 1's numerator; it does not gate anything
    BytesScanned         [long]   characters read
    LinesScanned         [int]    lines looked at, across every in-window transcript
    LinesParsed          [int]    of those, the ones carrying a tool_use marker
    LinesUnparseableElsewhere [int] lines that would not parse in a transcript with no connection to
                                  this repo family. Counted, not faulted -- see the header
    PathToolBlocks       [int]    tool_use blocks naming a tool that targets a path BY DEFINITION.
                                  Canary 1's denominator -- see the comment on FootprintPathToolNames
    PathBlocksExamined   [int]    tool_use blocks that actually carried a known path key
    PathBlocksUnclassified [int]  of those, the ones whose tool name is claimed by NEITHER allow-list.
                                  Canary 4's numerator, and the ONLY thing separating a renamed write
                                  tool from a quiet window: a rename lands here by construction, an
                                  idle afternoon leaves it at zero
    UnclassifiedPathToolNames [array] the distinct names behind that count (capped, sanitised) -- what
                                  the operator has to go and classify
    ToolNamesSeen        [array]  distinct tool names observed on those blocks (capped). The receipt
                                  for canary 4: it is how an operator sees the vocabulary drift
    WriteToolsAllowList  [array]  the names this scan was looking for, reported by the scanner that
                                  used them rather than re-derived by a caller
    KnownNonWriteTools   [array]  the names it was willing to EXCUSE for not being a write. Reported
                                  for the same reason as the line above: a negative allow-list that is
                                  not legible is a negative allow-list nobody audits
    WriteToolNamesSeen   [array]  of those in WriteToolsAllowList, the ones actually observed. EMPTY
                                  while PathBlocksExamined is non-zero is canary 4's GUARD; whether
                                  that refuses the run or merely notes it is decided by
                                  PathBlocksUnclassified
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
    SidechainPathToolBlocks [int] of those, blocks naming a tool that targets a path by definition
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
        TranscriptsFound = 0; TranscriptsInWindow = 0; TranscriptsVanished = 0; TranscriptsWithNeedle = 0
        BytesScanned = [long]0; LinesScanned = 0; LinesParsed = 0; LinesUnparseableElsewhere = 0
        PathToolBlocks = 0; PathBlocksExamined = 0; PathBlocksUnclassified = 0; ToolNamesSeen = @()
        WriteToolsAllowList = @($script:FootprintWriteTools); WriteToolNamesSeen = @()
        KnownNonWriteTools = @($script:FootprintKnownNonWriteTools); UnclassifiedPathToolNames = @()
        WritesExamined = 0; WritesOutsideWindow = 0; WritesUndated = 0
        WritesPlaced = 0; WritesUnplaced = 0
        PlacedByPrefix = 0; PlacedByGitdir = 0; GitdirProbes = 0; GitdirUnresolvable = 0
        SidechainFiles = 0; SidechainLines = 0; SidechainPathToolBlocks = 0; SidechainPathBlocks = 0
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
    # `projects` is what THIS file reads. Asking for roots that hold a `sessions` directory -- which is
    # what the default does, for the registry -- silently dropped a corpus root that had no session
    # registry, before anything counted it.
    try { $roots = @(Get-ClaudeConfigRoots -ConfigRoot $ConfigRoot -MustContain @('sessions', 'projects')) }
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

    # TWO LEVELS, AND NEITHER GATES THE PLACEMENT (see the header).
    #   $exactNeedles  -- every worktree, both spellings. TranscriptsWithNeedle and canary 1.
    #   $familyPrefix  -- their common prefix, which deliberately OVER-admits (it also matches a
    #                     sibling repo whose name starts the same way). Used only as a cheap screen in
    #                     front of the exact test, and as the RELEVANCE test for a parse fault, where
    #                     over-admitting means more faults, which is the safe direction.
    $exactNeedles = @(@($escaped + $slashed) | Where-Object { $_ } | Select-Object -Unique)
    if ($exactNeedles.Count -eq 0) {
        $r.Detail = 'no usable path needle could be built from the worktree list'
        return [pscustomobject]$r
    }
    $pe = Get-FootprintCommonPrefix $escaped
    $ps = Get-FootprintCommonPrefix $slashed
    # A family spread across drives has no useful common prefix; fall back to every needle rather than
    # to a one-character screen that admits the whole corpus.
    $familyPrefix =
    if ($pe.Length -ge $script:FootprintMinPrefix -and $ps.Length -ge $script:FootprintMinPrefix) { @($pe, $ps) }
    else { $exactNeedles }
    $familyPrefix = @($familyPrefix | Where-Object { $_ } | Select-Object -Unique)

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
                # GetLastWriteTime DOES NOT THROW on a missing file -- it returns the 1601 epoch, which
                # is always older than any cut, so a transcript that moved or was deleted between the
                # (lazy) enumeration and this stat was silently dropped from the window with
                # Available still true. `sessions.ps1 -Rehome` MOVES transcripts as normal operation.
                # Its window membership is unknowable once it is gone, so it is a fault; the remedy is
                # a re-run, which costs a minute and cannot destroy anything.
                if ($mt.Year -lt 1800 -and -not [System.IO.File]::Exists($f)) {
                    $r.TranscriptsVanished++
                    $faults += [pscustomobject]@{ File = $f; Why = 'the transcript vanished between being enumerated and being read, so it could be neither ruled in nor out of the window (moved by a rehome? re-run)' }
                    continue
                }
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
    $toolNames = @{}
    $writeNamesSeen = @{}
    # Canary 4's numerator carries the NAMES as well as the count: a fault whose text is "3 blocks were
    # unclassified" sends an operator to grep the corpus, and a fault whose text names them tells them
    # what the vendor renamed. Bounded and sanitised on exactly the same terms as $toolNames below --
    # a tool name is structural metadata, but nothing from a transcript reaches a receipt unchecked.
    $unclassifiedPathNames = @{}

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

        # The two needle levels. Neither decides what is parsed -- see the header. The exact test runs
        # only behind the cheap screen, which is a PREFIX of every needle and so can only over-admit.
        $family = $false
        foreach ($n in $familyPrefix) {
            if ($txt.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $family = $true; break }
        }
        if ($family) {
            foreach ($n in $exactNeedles) {
                if ($txt.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $r.TranscriptsWithNeedle++; break }
            }
        }

        $all = $txt.Split("`n")
        # Line number -> why, deduplicated: the tail check below and the loop can both reach the same
        # torn final line, and one torn line is one fault.
        # A PLAIN HASHTABLE, NOT [ordered]. An OrderedDictionary indexed with an INTEGER indexes BY
        # POSITION, not by key, so `$unparseable[$lineNo] = ...` set (or threw on) the Nth entry
        # instead of the entry for line N -- which took the whole scan down as "the scan threw" and
        # turned every torn-tail test into a refusal for the wrong reason.
        $unparseable = @{}
        $filePlaced = $false

        $lineNo = 0
        foreach ($line in $all) {
            $lineNo++
            $r.LinesScanned++
            if ($line.Length -lt 2) { continue }
            if ($line.IndexOf('"tool_use"', [StringComparison]::Ordinal) -lt 0) { continue }
            $r.LinesParsed++

            $obj = $null
            try { $obj = $line | ConvertFrom-Json -EA Stop }
            catch {
                # A half-written line is exactly this shape, and it is the shape of a session writing
                # RIGHT NOW. The parser's message quotes the fragment it choked on, so only the
                # LOCATION is recorded -- never the content. Whether it is a fault or a count is
                # decided after the file, once relevance is known.
                $unparseable[$lineNo] = 'will not parse (torn, or the format changed)'
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
                # The vocabulary actually observed, recorded for EVERY tool_use block rather than only
                # the ones that yielded a path -- a rename is visible in this list before it is visible
                # anywhere else, and a canary that could only see names it already understood would be
                # blind to exactly the change it exists to catch. Sanitised and bounded: a tool name is
                # structural metadata, but nothing from a transcript reaches a receipt unchecked and an
                # MCP surface can invent names.
                $tn = [string]$b.name
                if ($tn -and $tn.Length -le 60 -and $tn -match '^[A-Za-z0-9_.:-]+$' -and $toolNames.Count -lt 200) {
                    $toolNames[$tn] = $true
                }
                if ($script:FootprintPathToolNames -contains $tn) {
                    $r.PathToolBlocks++
                    if ($sidechain) { $r.SidechainPathToolBlocks++ }
                }
                $inp = $b.input
                if (-not $inp) { continue }
                $target = ''
                foreach ($k in $script:FootprintPathKeys) {
                    if ($inp.PSObject.Properties[$k]) { $target = [string]$inp.$k; if ($target) { break } }
                }
                if (-not $target) { continue }
                # Counted for EVERY path-bearing tool call, a Read included: this is the canaries'
                # denominator, and a denominator that only counted writes would go to zero on a quiet
                # window and make the canary vacuous.
                $r.PathBlocksExamined++
                if ($sidechain) { $r.SidechainPathBlocks++ }
                if ($script:FootprintWriteTools -notcontains $tn) {
                    # CANARY 4'S POSITIVE EVIDENCE, counted here because this is the only point in the
                    # scan where the tool name and the fact that this block carried a path are both in
                    # hand. A block that is not a write is one of two very different things: a tool we
                    # know cannot write (a Read, a Grep -- the shape of a quiet window), or a name
                    # neither allow-list has ever heard of (the shape of a renamed write tool). Only
                    # the second is evidence that the vocabulary moved, and separating them here is
                    # what lets the canary below refuse on evidence instead of on silence.
                    if ($script:FootprintKnownNonWriteTools -notcontains $tn) {
                        $r.PathBlocksUnclassified++
                        if ($tn -and $tn.Length -le 60 -and $tn -match '^[A-Za-z0-9_.:-]+$' -and $unclassifiedPathNames.Count -lt 40) {
                            $unclassifiedPathNames[$tn] = $true
                        }
                    }
                    continue
                }
                $writeNamesSeen[$tn] = $true

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
                $filePlaced = $true

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

        # A TORN TAIL IS NOT NECESSARILY A tool_use LINE. The cheap '"tool_use"' marker test above is
        # what makes this scan affordable, but a line truncated mid-write may have been cut BEFORE that
        # marker -- and a half-written final line is precisely the shape of a session writing RIGHT
        # NOW. So the last line of a file that does not end in a newline is checked on its own, by
        # PARSING it: a complete-but-unterminated line parses and costs nothing, a truncated one does
        # not. This used to be gated on the tail CONTAINING a worktree path, which meant a tear landing
        # anywhere before the path bytes was silently skipped -- and a tear before the path is the more
        # likely one, since the path sits deep inside the line.
        if ($all.Count -gt 0 -and -not $txt.EndsWith("`n")) {
            $tailNo = $all.Count
            $tail = $all[$tailNo - 1]
            if ($tail.Length -gt 0 -and -not $unparseable.ContainsKey($tailNo)) {
                try { $null = $tail | ConvertFrom-Json -EA Stop }
                catch { $unparseable[$tailNo] = 'will not parse -- it is half-written, which is what a session writing right now looks like' }
            }
        }

        # RELEVANCE, decided once per file and only now, because a placement is what proves relevance
        # for a spelling the needle cannot see (a junction, a UNC path). $family deliberately
        # over-admits; see the header for the trade and the residual.
        if ($unparseable.Count -gt 0) {
            if ($family -or $filePlaced) {
                foreach ($k in @($unparseable.Keys | Sort-Object)) {
                    $faults += [pscustomobject]@{ File = $f; Why = "line $k of a transcript touching this repo family $($unparseable[$k])" }
                }
            }
            else { $r.LinesUnparseableElsewhere += $unparseable.Count }
        }
        $txt = $null
    }
    $r.ToolNamesSeen = @($toolNames.Keys | Sort-Object)
    $r.WriteToolNamesSeen = @($writeNamesSeen.Keys | Sort-Object)
    $r.UnclassifiedPathToolNames = @($unclassifiedPathNames.Keys | Sort-Object)

    # --- The canary ------------------------------------------------------------------------------
    # See the header. Each condition requires the extractor to have PRODUCED something, so none of them
    # can pass by measuring nothing.
    if ($r.PathToolBlocks -gt 0 -and $r.PathBlocksExamined -eq 0) {
        $faults += [pscustomobject]@{
            File = '(canary)'
            Why = "$($r.PathToolBlocks) tool call(s) that target a path by definition ($($script:FootprintPathToolNames -join ', ')) were examined and not one carried a known path key ($($script:FootprintPathKeys -join ', ')) -- the transcript format has moved and this signal is reading nothing"
        }
    }
    if ($r.SidechainFiles -gt 0 -and $r.SidechainLines -eq 0 -and $r.LinesParsed -gt 0) {
        $faults += [pscustomobject]@{
            File = '(canary)'
            Why = "$($r.SidechainFiles) subagent transcript(s) are in the window but not one parsed line reports isSidechain -- the subagent marker has moved"
        }
    }
    if ($r.SidechainPathToolBlocks -gt 0 -and $r.SidechainPathBlocks -eq 0) {
        $faults += [pscustomobject]@{
            File = '(canary)'
            Why = "$($r.SidechainPathToolBlocks) subagent tool call(s) that target a path by definition were examined and not one carried a known path key -- SUBAGENT extraction has gone to zero, which is where every cross-worktree write on this repo comes from"
        }
    }
    # CANARY 4, and it is the one the other three structurally cannot cover. They are all denominated
    # on PATH-BEARING blocks, which stay healthy through a rename of the write TOOL NAMES -- so the
    # whole signal drops to zero vetoes with Available true, no fault and an empty Note. Measured on
    # this repo: renaming Write/Edit in the allow-list turned a LIVE session's worktree (61 cross-tree
    # writes) from SKIP into PRUNE while pathBlocksExamined went UP.
    #
    # IT IS SPLIT IN TWO, BECAUSE "NOT ONE WRITE WAS SEEN" IS NOT ONE FACT. Denominated on the absence
    # of writes, this test fires identically on a moved vocabulary and on an afternoon where nobody
    # edited anything, and no amount of looking at the write names will tell those apart -- a rename
    # leaves Read/Grep/Glob completely intact. So the numerator moved off "writes are missing" and onto
    # "something carried a path and neither allow-list can say what it does", which is a fact a single
    # window actually contains (see $FootprintKnownNonWriteTools above for the measured classification,
    # for why a share or volume threshold must never replace this test, and for why a namespaced MCP
    # tool gets no exemption from it).
    #   * residue present => FAULT, on exactly the old terms and down exactly the old path. This is the
    #     shape the measured rename produces: the renamed tool still carries file_path, and its new
    #     name is in neither list by construction. Refusing is right here because the failure is not
    #     symmetric -- a false PRUNE destroys a live session's work and a red line an operator can
    #     scroll past does not stop -Apply.
    #   * residue absent  => a NOTE, and signal 3 abstains for this run at no extra cost: nothing was
    #     recognised as a write, so there are no footprints to contribute and the receipt says so in
    #     those words. Refusing here is the bug the comment on $FootprintPathToolNames records canary 1
    #     being rewritten to remove -- "fires on a perfectly healthy 36 h window ... refusing every
    #     prune, with no override flag, and blaming a vendor schema change that had not happened".
    #     Replayed hourly across 1,109 h of real history (13,315 transcripts, 4 config roots) on
    #     2026-07-30, the undivided test fired once: 2026-06-22T18Z, 1 in-window transcript, 1
    #     path-bearing block, 0 writes. That is a quiet corpus, not a schema change -- 87% of all
    #     transcripts contain no write block at all. The note rides the channel the header already
    #     points at (the caller prints $fp.Note as REDUCED ASSURANCE in red); no new channel is
    #     invented for it.
    # THE FAULT SET IS A STRICT SUBSET OF THE OLD ONE. Every window that faults here also faulted
    # before, so this change cannot invent a refusal; it can only decline to make one. What it CAN get
    # wrong is the other direction, and there is exactly one way in: a name that writes but sits in
    # $FootprintKnownNonWriteTools. That is why that list is short, argued per entry, and carries the
    # warning it does.
    $canary4Note = ''
    if ($r.WriteToolNamesSeen.Count -eq 0 -and $r.PathBlocksExamined -gt 0) {
        if ($r.PathBlocksUnclassified -gt 0) {
            # THE EVIDENCE FIELD IS NEVER ALLOWED TO RENDER EMPTY. The count above is incremented for
            # every unclassified block, but the NAME is only kept when it survives the same shape and
            # cap test every other transcript-sourced string in here survives -- so a name too hostile
            # to record, or a 41st distinct one, leaves the list short while the count stands. An
            # accusation printed with an empty bracket is the same self-contradicting-receipt defect
            # this rewrite exists to repair, one field over. The count stays unconditional either way:
            # a block whose name could not be recorded is still a block that happened.
            $unclassifiedEvidence =
            if (@($r.UnclassifiedPathToolNames).Count -gt 0) { @($r.UnclassifiedPathToolNames | Select-Object -First 12) -join ', ' }
            else { 'none of them recordable as a name' }
            $isAre = if ($r.PathBlocksUnclassified -eq 1) { 'is' } else { 'are' }
            $faults += [pscustomobject]@{
                File = '(canary)'
                Why = "not one of the $($r.PathBlocksExamined) path-bearing tool call(s) examined is named by the write allow-list ($($script:FootprintWriteTools -join ', ')), AND $($r.PathBlocksUnclassified) of them $isAre named by something NEITHER allow-list claims ($unclassifiedEvidence) -- the tool vocabulary has moved and this signal can no longer see a write at all. Establish what those names do, then extend `$FootprintWriteTools if they write or `$FootprintKnownNonWriteTools if they provably cannot; do NOT extend the second one merely to stop this firing"
            }
        }
        else {
            $canary4Note = "not one of the $($r.PathBlocksExamined) path-bearing tool call(s) examined is a write either, and every one of them is named by a tool that cannot write a file through the path it carries ($($script:FootprintKnownNonWriteTools -join ', ')) -- an idle corpus, not a moved vocabulary, so this is a note and NOT a refusal (a rename would have left a path-bearing name neither list claims, and that is still a hard fault). Worth an eye all the same: measured 2026-07-30, over the preceding 21 days the in-window write-bearing transcript count never fell below 6, and typically ran 238"
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
        elseif ($r.WritesPlaced -eq 0) {
            # WRITES PLACED, not needles found: the needle is now a counter and a canary numerator, and
            # a write can be placed through .git in a file that carries no needle at all. "Nothing was
            # placed" is the honest statement of "this signal contributed nothing".
            $r.Note = "$($r.TranscriptsInWindow) transcript(s) were in the window and not one write placed in a worktree of this repo, so this signal contributed nothing to this run"
        }
        # Canary 4's soft half, APPENDED and never assigned. When it fires, WritesPlaced is zero by
        # construction -- nothing was recognised as a write, so nothing could be placed -- which means
        # the branch above has already claimed this string. An assignment here would silently drop the
        # honest "contributed nothing" sentence that the caller promotes to REDUCED ASSURANCE, and
        # replace a statement about the OUTCOME with one about the VOCABULARY. The operator needs both:
        # the first says the signal is not vetoing anything, the second says why that is believable.
        if ($canary4Note) {
            $r.Note = if ($r.Note) { "$($r.Note); $canary4Note" } else { $canary4Note }
        }
    }
    return [pscustomobject]$r
}
