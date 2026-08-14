<#
.SYNOPSIS
    Write this session's EPISODE RECORD -- the durable answer to "what was this seat doing" that
    survives the seat's death, its account's exhaustion, and the switch to another account.

.DESCRIPTION
    One record per (worktree, session), at
    <git-common-dir>/mefor-coord/seats/<boxKey>/<sessionKey>.json

    Dot-sourcing does nothing useful; run it.

        seat.ps1 -Record                      # the hook path: derive everything, write, exit 0
        seat.ps1 -Declare -SessionId <id> -Seat builder3 -Goal "..." -Done "..." -OutOfScope "..."
        seat.ps1 -Declare -SessionId <id> -Handoff <path>   # the doc a replacement should read
        seat.ps1 -Close -SessionId <id> [-Handback]
        seat.ps1 -BumpEpoch                   # mark an account switch; see POOL EPOCH below

    -Declare AND -Close NAME A SESSION OR WRITE NOTHING -- see rule 4. They take -SessionId, or fall
    back to CLAUDE_CODE_SESSION_ID / CLAUDE_SESSION_ID; with neither, they refuse loudly. -SessionId
    is the authoritative one: the environment names whoever is RUNNING the command, which in a
    subagent is not the session the seat's hook records under. -Record never takes that fallback.

    WHY A RECORD AND NOT A ROW IN A SHARED FILE. This layer lives inside .git, which is NOT under
    version control -- measured: `git ls-files | grep -c '^\.git/'` returns 0 while the same
    instrument returns 1952 tracked files. So there is no history, no merge, and no conflict
    detection. Two writers on one file is last-write-wins SILENTLY. One file per (worktree, session)
    is what removes the shared-write hazard rather than mitigating it.

    THE READER COMPUTES; THIS ONLY STORES. Roster state, respawn eligibility and the spawn briefing
    are all derived at read time by fleet.ps1. Nothing here stores a verdict, because a verdict
    written now is read after the world moved. What IS stored are facts with the time they were
    taken, which is a different thing and stays true.

    WHY THE HOOK-WRITTEN HALF IS THE LOAD-BEARING HALF. A seat registry was proposed and rejected
    twice on this project, and one of the two grounds was that VOLUNTARY DECLARATION DECAYS TO
    NOTHING. That ground is correct and measured: `ROLE=` adoption in claim notes reached only 8.8
    to 31 percent in two counts. So -Record derives everything it can from git and the harness
    payload and needs no discipline from anyone; -Declare adds intent on top and is expected to be
    missing. fleet.ps1 renders "declared: NONE" with its age as first-class output rather than
    showing a blank field as though it were a fact.

    FOUR HARD RULES, each paying for a measured failure on this box.

    1. NEVER MINT A BOX KEY FROM A PATH THAT IS NOT A ROOTED, EXISTING DIRECTORY. mail.ps1:392-401
       records that the unguarded version "silently mints a NEW box that no reader will ever drain",
       and 11 of 29 mailboxes on disk are that residue. A git-resolution failure here is a NO-WRITE
       path, never an empty-string path -- writing to seats/-<hash>/ would be the same defect with a
       new name.

    2. A WRITER THAT DIES MUST NOT DIE SILENTLY. Every failure appends one line to
       seats/.writer-errors.txt and the script still exits 0. Exiting non-zero from a Stop hook is
       its own hazard; leaving no trace is worse than either.

    3. TOUCH seats/.writer-alive/<boxKey>.txt ON EVERY INVOCATION, including no-op ones. "The writer
       ran" and "the seat had something to say" are different sentences, and a reader that cannot
       separate them reads a disabled writer as an idle fleet. Hooks are disabled silently by
       disableAllHooks, by org policy and by workspace trust, and all three produce exactly the
       observable of a quiet, healthy fleet.

    4. A RECORD IS PER (worktree, SESSION), SO A WRITE THAT CANNOT NAME ITS SESSION MAY NOT CARRY
       ANOTHER SESSION'S WORK. `nosid` is ONE slot per checkout, shared by every unidentified session
       that ever ran there. Measured: `-Declare` and `-Close` never read the session id, so they both
       landed in that slot while the seat's own hook record sat beside it -- the roster showed a
       phantom declared seat next to the real one, a `-Close` marked a record nobody was reading (so
       the seat that closed itself was never closed), and the next occupant to declare came back
       holding the previous occupant's goal, done and lifecycle=closed, which the roster renders as
       finished work. So: -Declare/-Close REFUSE to write without a session identity, and the
       involuntary -Record half still writes to `nosid` (losing the git facts would be worse) but
       INHERITS NOTHING there and claims no episode baseline. The refusal is on the demoted voluntary
       half only; the hook path does not depend on it.

    POOL EPOCH. `configRootLabel` names a CREDENTIAL DIRECTORY, not a Claude account -- two launcher
    scripts on this box point at the same .claude-account-2, and the Desktop runs against ~/.claude
    with CLAUDE_CONFIG_DIR unset regardless of who authenticated. So the label cannot answer "was
    this written before the switch". `poolEpoch` can: a monotonic integer bumped at the switch and
    stamped into every record thereafter, making "before the switch" a recorded fact rather than an
    inference from a directory name.

    WHAT THIS FILE DOES NOT OWN. The box key is mail-key.ps1's (ONE definition, dot-sourced). The
    liveness fence is session-registry.ps1's. Claim state is claim.ps1's and is read, never written.
    Adding a private copy of any of them here would be a second definition, and the copy that drifts
    is the one nobody is testing.
#>
[CmdletBinding(DefaultParameterSetName = 'Record')]
param(
    [Parameter(ParameterSetName = 'Record')][switch]$Record,
    [Parameter(ParameterSetName = 'Declare')][switch]$Declare,
    [Parameter(ParameterSetName = 'Declare')][string]$Seat,
    [Parameter(ParameterSetName = 'Declare')][string]$Goal,
    [Parameter(ParameterSetName = 'Declare')][string]$Done,
    [Parameter(ParameterSetName = 'Declare')][string]$OutOfScope,
    [Parameter(ParameterSetName = 'Declare')][string]$Handoff,
    [Parameter(ParameterSetName = 'Declare')][string]$Predecessor,
    [Parameter(ParameterSetName = 'Declare')][string]$Notes,
    [Parameter(ParameterSetName = 'Close')][switch]$Close,
    [Parameter(ParameterSetName = 'Close')][switch]$Handback,
    [Parameter(ParameterSetName = 'Epoch')][switch]$BumpEpoch,
    # Only for tests and for -Declare from a different cwd. Normally derived.
    [string]$Worktree,
    [string]$SessionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SCHEMA = 1
$WRITER = 'seat.ps1/1.0.0'

. "$PSScriptRoot\mail-key.ps1"

# ---------------------------------------------------------------------------------------------
# Failure recording. Rule 2: nothing below may throw out of this script.
# ---------------------------------------------------------------------------------------------

$script:SeatsDir = $null

function Write-WriterError {
    param([string]$Stage, [string]$Message)
    # Best-effort by construction: if we cannot even record the failure we must still exit 0, or a
    # broken writer takes the seat's Stop hook down with it.
    try {
        if (-not $script:SeatsDir) { return }
        $f = Join-Path $script:SeatsDir '.writer-errors.txt'
        # DOUBLE-quoted, and that is the whole point: PowerShell processes the backtick escape only
        # inside double quotes, so the single-quoted form wrote the two literal characters backtick-t
        # between the fields. Measured: the log then split into ONE field on a tab, so the column
        # naming WHICH stage failed could not be extracted, while the file itself looked healthy and
        # fleet.ps1's line count stayed correct.
        $line = "{0}`t{1}`t{2}`t{3}" -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $env:COMPUTERNAME, $Stage, ($Message -replace '\s+', ' ')
        Add-Content -Path $f -Value $line -Encoding utf8 -EA SilentlyContinue
    } catch { }
}

function Invoke-Git {
    # Returns trimmed stdout, or $null when git failed. NEVER throws: a repo in a state git dislikes
    # must degrade one field, not lose the whole record.
    #
    # -Raw SUPPRESSES THE TRIM, AND ANY COLUMN-SIGNIFICANT FORMAT MUST ASK FOR IT. Trim() is applied
    # to the JOINED output, so it eats the head of the FIRST line. Measured: `git status --porcelain`
    # writes the status in columns 1-2 and an unstaged modification is " M path", so the leading
    # space of line 1 was stripped and the fixed Substring(3) below it then stored the first dirty
    # path one character short -- 'alpha.py' recorded as 'lpha.py', with every later line intact and
    # every count still agreeing, so nothing in the record disagreed with anything else.
    param([string]$Dir, [string[]]$GitArgs, [switch]$Raw)
    try {
        $out = & git -C $Dir @GitArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($null -eq $out) { return '' }
        $joined = ($out -join "`n")
        if ($Raw) { return $joined }
        return $joined.Trim()
    } catch { return $null }
}

function ConvertTo-UtcInstant {
    # ONE conversion for every timestamp this file compares or stores, because the type here is not
    # what the code reading it assumes.
    #
    # MEASURED: ConvertFrom-Json parses "2026-08-14T13:48:25Z" into a [DateTime], and [string] on
    # THAT yields the culture form "08/14/2026 13:48:25" -- the Z is gone. Re-parsing that reads it
    # as LOCAL and shifts it by the box's offset (five hours here). Both sides of the attribution
    # comparison were being mangled the same way, so the skews cancelled and the fault was invisible;
    # normalising one side alone would have UNCANCELLED it and been worse than leaving it. So both
    # sides come through here, and the record stores what this returns.
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [DateTime]) {
            if ($Value.Kind -eq [DateTimeKind]::Utc) { return $Value }
            if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
            # Unspecified: everything this layer writes is UTC, so read it as UTC rather than
            # letting ToUniversalTime() add the local offset to a value that never carried one.
            return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc)
        }
        if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
        $s = [string]$Value
        if (-not $s.Trim()) { return $null }
        return [DateTimeOffset]::Parse($s, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime
    } catch { return $null }
}

function ConvertTo-Utc8601 {
    # The one stored shape. Round-tripping a record re-reads its timestamps as [DateTime], so every
    # value carried forward is re-canonicalised on the way back out.
    param($Value)
    $u = ConvertTo-UtcInstant $Value
    if ($null -eq $u) { return $null }
    return $u.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function ConvertTo-RefComponent {
    # git rejects a ref component with a leading dot, a '..' or a '.lock' suffix, so dots are removed
    # outright rather than each rule being special-cased. Measured with `git check-ref-format`.
    param([string]$Value)
    $c = ($Value -replace '[^A-Za-z0-9_-]', '-')
    if ($c.Length -gt 80) { $c = $c.Substring(0, 80) }
    if (-not $c) { $c = 'unknown' }
    return $c
}

function Limit-Text {
    # COLLAPSE FIRST, THEN MEASURE THE COLLAPSED STRING. Measured: taking the length from the
    # ORIGINAL and slicing the COLLAPSED copy throws on any note holding a double space, a tab or a
    # newline, because collapsing is length-reducing. That throw landed while the record literal was
    # being built, so it discarded the WHOLE write -- the involuntary git facts included -- while
    # rule 2's unconditional exit 0 reported success.
    param([string]$Text, [int]$Max = 2000)
    $t = ($Text -replace '\s+', ' ')
    if ($t.Length -le $Max) { return $t }
    return $t.Substring(0, $Max)
}

# ---------------------------------------------------------------------------------------------
# Locate the layer and the worktree.
# ---------------------------------------------------------------------------------------------

function Get-CoordDir {
    param([string]$From)
    # --path-format=absolute is not optional: the bare form returns a path relative to cwd and
    # silently resolves against wherever the caller happens to be.
    $common = Invoke-Git -Dir $From -GitArgs @('rev-parse', '--path-format=absolute', '--git-common-dir')
    if (-not $common) { return $null }
    return (Join-Path $common 'mefor-coord')
}

function Resolve-Worktree {
    param([string]$Hint)
    $start = if ($Hint) { $Hint } else { (Get-Location).Path }
    if (-not (Test-Path -LiteralPath $start -PathType Container)) { return $null }
    $top = Invoke-Git -Dir $start -GitArgs @('rev-parse', '--show-toplevel')
    if (-not $top) { return $null }
    # Rule 1. A relative or non-existent path must never reach ConvertTo-BoxKey.
    try { $full = (Resolve-Path -LiteralPath $top -EA Stop).Path } catch { return $null }
    if (-not [System.IO.Path]::IsPathRooted($full)) { return $null }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return $null }
    return $full
}

# ---------------------------------------------------------------------------------------------
# Payload (hook stdin) and session identity.
# ---------------------------------------------------------------------------------------------

function Read-HookPayload {
    # Hooks receive JSON on stdin. Absent or unparsable stdin is NORMAL for a manual run and is not
    # an error -- it just means every payload-derived field reports its source as 'absent'.
    if ([Console]::IsInputRedirected -ne $true) { return $null }
    try {
        $raw = [Console]::In.ReadToEnd()
        if (-not $raw -or -not $raw.Trim()) { return $null }
        return ($raw | ConvertFrom-Json -EA Stop)
    } catch { return $null }
}

function Get-SessionKey {
    # THE ENV FALLBACK IS FOR THE CLI PATHS ONLY, and -AllowEnvFallback is how they ask. -Record has
    # an AUTHORITATIVE payload and must not fall back: the environment names the session of whoever
    # is running the command, which is not always the session whose Stop hook is firing -- measured,
    # a subagent carries its own 36-char CLAUDE_CODE_SESSION_ID distinct from
    # CLAUDE_CODE_HOST_SESSION_ID -- and a -Record keyed on that would split one seat's episode
    # across two records, which is the "60 seats where there is one" failure `nosid` exists to stop.
    #
    # Both names are tried, and the order is measured rather than guessed: CLAUDE_CODE_SESSION_ID
    # holds a uuid of the same shape the payload carries, while CLAUDE_SESSION_ID -- the name
    # mail.ps1:230 reads -- is EMPTY on this box. A fallback that resolves to nothing is exactly the
    # failure this file exists to make visible, so it must not be the only one tried.
    param($Payload, [string]$Override, [switch]$AllowEnvFallback)
    $sid = $null
    $src = $null
    if ($Override) { $sid = $Override; $src = 'param' }
    elseif ($Payload -and ($Payload.PSObject.Properties.Name -contains 'session_id') -and $Payload.session_id) {
        $sid = [string]$Payload.session_id; $src = 'payload'
    }
    elseif ($AllowEnvFallback -and $env:CLAUDE_CODE_SESSION_ID) { $sid = $env:CLAUDE_CODE_SESSION_ID; $src = 'env:CLAUDE_CODE_SESSION_ID' }
    elseif ($AllowEnvFallback -and $env:CLAUDE_SESSION_ID) { $sid = $env:CLAUDE_SESSION_ID; $src = 'env:CLAUDE_SESSION_ID' }

    if (-not $sid) {
        # THE LITERAL STRING, NOT nosid-<pid>. A hook runs as a pwsh CHILD whose pid changes every
        # turn (presence.ps1 Get-SelfPids states this), so keying on pid would mint roughly one
        # record per turn -- about 60 identical files for a 30-turn session, and a reader would see
        # 60 seats where there is one.
        return @{ Key = 'nosid'; Id = $null; Source = 'absent' }
    }
    $clean = $sid -replace '[^A-Za-z0-9._-]', '-'
    if ($clean.Length -gt 80) { $clean = $clean.Substring(0, 80) }
    return @{ Key = $clean; Id = $sid; Source = $src }
}

function Get-ConfigRootLabel {
    # Deliberately NOT a fallback to 'default'. Measured: .claude-account-3 and -4 hold zero session
    # records against 22 and 229 transcripts, so the session-join route provably fails there, and a
    # wrong label is worse than an honest 'unknown' -- it would attribute a record to a pool it never
    # billed.
    if ($env:CLAUDE_CONFIG_DIR) {
        return @{ Label = (Split-Path $env:CLAUDE_CONFIG_DIR -Leaf); Source = 'env' }
    }
    return @{ Label = 'unknown'; Source = 'unknown' }
}

function Get-PoolEpoch {
    param([string]$SeatsDir)
    $f = Join-Path $SeatsDir '.pool-epoch'
    if (-not (Test-Path -LiteralPath $f)) { return 1 }
    try {
        $v = (Get-Content -LiteralPath $f -Raw -EA Stop).Trim()
        if ($v -match '\A[0-9]+\z') { return [int]$v }
    } catch { }
    return 1
}

# ---------------------------------------------------------------------------------------------
# Git-derived facts. Every one is a fact with a time, never a verdict.
# ---------------------------------------------------------------------------------------------

function Get-GitFacts {
    param([string]$Wt, [string]$StashRef)

    $branch = Invoke-Git -Dir $Wt -GitArgs @('rev-parse', '--abbrev-ref', 'HEAD')
    $tip = Invoke-Git -Dir $Wt -GitArgs @('rev-parse', 'HEAD')
    $upstream = Invoke-Git -Dir $Wt -GitArgs @('rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}')

    # NO-UPSTREAM is rendered distinctly from 0 by the reader. Measured: 29 of 40 sampled worktrees
    # have no upstream, so collapsing the two would report "nothing unpushed" for the majority case
    # where the true answer is "nobody has looked".
    $base = if ($upstream) { $upstream } else { 'origin/main' }
    $unpushed = $null
    $cnt = Invoke-Git -Dir $Wt -GitArgs @('rev-list', '--count', "$base..HEAD")
    if ($null -ne $cnt -and $cnt -match '\A[0-9]+\z') {
        $unpushed = [ordered]@{ count = [int]$cnt; base = $base }
    }

    $mergeBase = Invoke-Git -Dir $Wt -GitArgs @('merge-base', 'origin/main', 'HEAD')

    # touchedPaths exists so the reader's landed probe can never run UNSCOPED. An unscoped whole-tree
    # diff against origin/main is non-empty for branches that ARE landed by content -- measured up to
    # 583 files -- so a probe without a pathspec answers a different question than the one asked.
    $touched = @()
    if ($mergeBase) {
        $t = Invoke-Git -Dir $Wt -GitArgs @('diff', '--name-only', $mergeBase, 'HEAD')
        if ($t) { $touched = @($t -split "`n" | Where-Object { $_ }) }
    }

    # TRACKED AND UNTRACKED ARE SEPARATED ON PURPOSE, and the separation is load-bearing.
    #
    # MEASURED, on this script's own first real run: `git stash create` returned EMPTY while two brand
    # new files sat in the tree. It captures TRACKED modifications only -- there is no -u -- so the
    # single most valuable thing to rescue, a file that exists nowhere but that working directory, is
    # exactly what it does not cover. A record that stored a null stash and a dirty count would have
    # told a replacement seat "nothing to recover" about the very work it was replacing.
    #
    # So: the stash covers tracked edits, untracked paths are listed by name, and the reader states
    # plainly that no git object holds them. Promising a recovery that cannot be delivered is worse
    # than reporting the gap. The tracked half is anchored to a ref below for the same reason -- an
    # unreferenced sha is a promise of recovery that gc can revoke without a word.
    # -z, AND -Raw, AND NEITHER IS OPTIONAL.
    #   -Raw: the status lives in columns 1-2, so a Trim() over the joined output eats the first
    #     entry's status column and the fixed offset below then truncates that path (see Invoke-Git).
    #   -z: without it git QUOTES any path holding a space or a non-ASCII byte (core.quotepath is on
    #     by default) and the quotes are stored as part of the name -- measured: a new file
    #     `has space.txt` was recorded as `"has space.txt"`, which is not a path anyone can act on.
    #     -z emits NUL-terminated entries with the path verbatim.
    # A rename/copy entry is followed by a SECOND field carrying the ORIGINAL path; it is consumed
    # here rather than being read as a status line of its own.
    $trackedPaths = @()
    $untrackedPaths = @()
    $st = Invoke-Git -Dir $Wt -GitArgs @('status', '--porcelain', '-z') -Raw
    if ($st) {
        $entries = @($st -split "`0" | Where-Object { $_ })
        for ($i = 0; $i -lt $entries.Count; $i++) {
            $e = $entries[$i]
            if ($e.Length -lt 4) { continue }
            $xy = $e.Substring(0, 2)
            $p = $e.Substring(3)
            if ($xy[0] -eq 'R' -or $xy[0] -eq 'C') { $i++ }
            if ($xy -eq '??') { $untrackedPaths += $p } else { $trackedPaths += $p }
        }
    }

    # `git stash create` builds a commit object WITHOUT touching the working tree or the stash ref,
    # so it cannot disturb a seat that may still be using the checkout.
    #
    # IT ALSO WRITES NO REF AND NO REFLOG ENTRY, so the object is unreachable from the moment it
    # exists. Measured: `git gc --prune=now` deleted the recorded stash and the record went on
    # carrying the same sha, with no way to tell a live handle from a dead one. So the sha is
    # ANCHORED to a ref of its own here -- one plumbing call, the object becomes gc-proof, and the
    # ref name says what it is to whoever finds it later.
    $stash = $null
    $stashRefName = $null
    if ($trackedPaths.Count -gt 0) {
        $s = Invoke-Git -Dir $Wt -GitArgs @('stash', 'create')
        if ($s) {
            $stash = $s
            if ($StashRef) {
                # Invoke-Git returns '' on a silent success and $null only on failure.
                $anchored = Invoke-Git -Dir $Wt -GitArgs @('update-ref', $StashRef, $s)
                if ($null -ne $anchored) { $stashRefName = $StashRef }
                else { Write-WriterError -Stage 'stash-anchor' -Message "update-ref $StashRef failed; the stash sha is unreferenced and gc can delete it" }
            }
        }
    } elseif ($StashRef) {
        # Nothing to cover this pass. An anchor from an earlier turn would keep holding edits that
        # have since been committed or discarded, so it is dropped rather than left to outlive what
        # it described. Deleting a ref that is not there is a no-op that exits 0.
        Invoke-Git -Dir $Wt -GitArgs @('update-ref', '-d', $StashRef) | Out-Null
    }
    $dirtyPaths = @($trackedPaths) + @($untrackedPaths)

    # THE INVOLUNTARY ANSWER TO "WHAT WAS THIS SEAT DOING".
    #
    # Owner ruling, 2026-08-14: the exception permitting a stored per-seat record is granted for the
    # INVOLUNTARY half only; the voluntary half is dropped or demoted, because voluntary declaration
    # decays -- measured at 8.8 to 31 percent adoption. Rendering an empty declared field with its age
    # was explicitly ruled INSUFFICIENT: the ground was upheld, not merely the symptom.
    #
    # So the briefing must be complete WITHOUT anyone having declared anything, and this is what makes
    # that possible. A commit subject is written by the seat as a side effect of working, it is
    # durable, it is dated, and it describes what was actually DONE rather than what someone intended
    # at the start. It is strictly better evidence than a stale declared goal.
    $commits = @()
    if ($mergeBase) {
        $c = Invoke-Git -Dir $Wt -GitArgs @('log', '--format=%h %ad %s', '--date=short', "$mergeBase..HEAD", '--max-count=25')
        if ($c) { $commits = @($c -split "`n" | Where-Object { $_ }) }
    }

    return [ordered]@{
        branch    = $branch
        upstream  = $upstream
        tip       = $tip
        mergeBase = $mergeBase
        touched   = $touched
        commits   = $commits
        unpushed  = $unpushed
        dirty     = [ordered]@{
            count          = $dirtyPaths.Count
            paths          = @($dirtyPaths | Select-Object -First 200)
            trackedCount   = $trackedPaths.Count
            untrackedCount = $untrackedPaths.Count
            # Named, not counted: a replacement seat has to copy these by hand.
            untracked      = @($untrackedPaths | Select-Object -First 200)
        }
        stashSha  = $stash
        # The ref holding that sha, so a reader can test the OBJECT (`git rev-parse --verify`) rather
        # than the string. A null here with a non-null stashSha means the anchor did not take.
        stashRef  = $stashRefName
        # What the stash actually covers, so the reader never over-promises recovery. An unanchored
        # sha is named as such: it is a handle that can go dead between the write and the read.
        stashCovers = if ($stash -and $stashRefName) { 'tracked-only' }
                      elseif ($stash) { 'tracked-only-unanchored' }
                      elseif ($untrackedPaths.Count -gt 0) { 'nothing-untracked-only' }
                      else { 'nothing-clean' }
    }
}

# A WORKTREE PATH OUTLIVES THE SESSION THAT OCCUPIED IT, so matching on path alone over-attributes
# across episodes. Measured on the FIRST record this script ever wrote: 18 backlog allocations
# resolved to the writing worktree, the oldest claimed EIGHT DAYS EARLIER on a different branch by a
# different session that had occupied the same directory. A replacement seat handed those as "yours"
# would try to rehome ledger numbers belonging to work that finished last week.
#
# So every claim and allocation carries an ATTRIBUTION rather than being silently included or
# silently dropped. Dropping would be worse: an inherited allocation still sits in this worktree and
# a human may still need to deal with it. The reader renders the two groups separately.
#
# THE BASELINE IS `episodeStart`, NOT `lifecycleAt`. They are different sentences and one variable
# was serving both: lifecycleAt says WHEN THE LIFECYCLE LAST CHANGED, and -Close sets it to now. So
# the deliberate handback -- the one path where a replacement is meant to inherit the work -- moved
# the baseline to the close time, put every number the episode had just allocated BEFORE its own
# "start", and handed the replacement "allocated to that PATH by earlier occupants -- not this
# seat's, do not rehome or cite". Measured end to end: this-episode before the -Close -Handback,
# worktree-inherited after it, with nothing else changed.
#
# NOT [string] PARAMETERS. Binding a [DateTime] (which is what ConvertFrom-Json hands back) to a
# [string] parameter is a lossy culture-formatted cast; both operands go through ConvertTo-UtcInstant
# instead. See the note there for why fixing only one side would have been worse than fixing neither.
function Get-Attribution {
    param($At, $EpisodeStart)
    $a = ConvertTo-UtcInstant $At
    $e = ConvertTo-UtcInstant $EpisodeStart
    if ($null -eq $a -or $null -eq $e) { return 'unknown' }
    if ($a -ge $e) { return 'this-episode' }
    return 'worktree-inherited'
}

function Get-ClaimsFor {
    # $EpisodeStart is deliberately untyped: a [string] parameter would culture-cast a [DateTime] on
    # the way in, which is the exact loss ConvertTo-UtcInstant exists to stop.
    param([string]$CoordDir, [string]$Wt, $EpisodeStart)
    # Claims are claim.ps1's to write. This reads them and attributes by holder worktree only.
    $out = @()
    $dir = Join-Path $CoordDir 'claims'
    if (-not (Test-Path -LiteralPath $dir)) { return $out }
    $norm = $Wt.TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter *.json -EA SilentlyContinue)) {
        try {
            $j = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop
        } catch { continue }
        $holder = $null
        foreach ($n in @('worktree', 'holderWorktree', 'cwd')) {
            if ($j.PSObject.Properties.Name -contains $n) { $holder = [string]$j.$n; break }
        }
        if (-not $holder) { continue }
        $hnorm = $holder.TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
        if ($hnorm -ne $norm) { continue }
        $at = $null
        foreach ($n in @('claimedAt', 'at', 'created')) {
            if ($j.PSObject.Properties.Name -contains $n) { $at = $j.$n; break }
        }
        # Stored in the canonical shape, not as the culture-formatted cast of whatever
        # ConvertFrom-Json produced. A value that will not parse is kept VERBATIM rather than dropped:
        # an unparsable timestamp is still evidence, and its attribution is already 'unknown'.
        $atIso = ConvertTo-Utc8601 $at
        $out += [ordered]@{
            key         = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            claimedAt   = if ($atIso) { $atIso } elseif ($null -ne $at) { [string]$at } else { $null }
            attribution = (Get-Attribution -At $at -EpisodeStart $EpisodeStart)
        }
    }
    return $out
}

function Get-AllocationsFor {
    param([string]$CoordDir, [string]$Wt, $EpisodeStart)
    $out = @()
    $dir = Join-Path $CoordDir 'alloc'
    if (-not (Test-Path -LiteralPath $dir)) { return $out }
    $norm = $Wt.TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
    foreach ($kindDir in @(Get-ChildItem -LiteralPath $dir -Directory -EA SilentlyContinue)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $kindDir.FullName -Filter *.json -EA SilentlyContinue)) {
            try { $j = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
            $aw = $null
            foreach ($n in @('worktree', 'allocWorktree', 'cwd')) {
                if ($j.PSObject.Properties.Name -contains $n) { $aw = [string]$j.$n; break }
            }
            if (-not $aw) { continue }
            if ((($aw.TrimEnd('\', '/').ToLowerInvariant()) -replace '/', '\') -ne $norm) { continue }
            $at = $null
            foreach ($n in @('claimed', 'allocatedAt', 'at')) {
                if ($j.PSObject.Properties.Name -contains $n) { $at = $j.$n; break }
            }
            $atIso = ConvertTo-Utc8601 $at
            $out += [ordered]@{
                kind          = $kindDir.Name
                number        = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
                allocWorktree = $aw
                allocatedAt   = if ($atIso) { $atIso } elseif ($null -ne $at) { [string]$at } else { $null }
                allocBranch   = if ($j.PSObject.Properties.Name -contains 'branch') { [string]$j.branch } else { $null }
                attribution   = (Get-Attribution -At $at -EpisodeStart $EpisodeStart)
            }
        }
    }
    return $out
}

# ---------------------------------------------------------------------------------------------
# Atomic write.
# ---------------------------------------------------------------------------------------------

function Write-RecordAtomic {
    param([string]$Path, $Object)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # Temp file in the SAME directory: a rename across volumes is a copy, and a copy is not atomic.
    $tmp = Join-Path $dir ('.' + [System.IO.Path]::GetFileName($Path) + '.tmp')
    $json = $Object | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $tmp -Value $json -Encoding utf8 -EA Stop
    Move-Item -LiteralPath $tmp -Destination $Path -Force -EA Stop
}

# ---------------------------------------------------------------------------------------------
# Main. Everything is wrapped: rule 2 says this exits 0 whatever happens.
# ---------------------------------------------------------------------------------------------

$exit = 0
try {
    # STILL GATED ON -Record, and the reason is not the one it looks like. Reading stdin is what
    # supplies the session id, and -Declare/-Close were writing to the anonymous slot for want of it
    # (rule 4) -- but they get theirs from -SessionId or the environment (Get-SessionKey), because
    # [Console]::In.ReadToEnd() BLOCKS on an inherited pipe that nobody closes. A hook never invokes
    # -Declare; a human at a terminal never pipes it a payload. So the identity gap is closed without
    # putting a blocking read on a path that has no payload to read.
    $payload = if ($Record) { Read-HookPayload } else { $null }

    $wtHint = $Worktree
    if (-not $wtHint -and $payload -and ($payload.PSObject.Properties.Name -contains 'cwd')) { $wtHint = [string]$payload.cwd }
    $wt = Resolve-Worktree -Hint $wtHint

    if (-not $wt) {
        # Rule 1: no worktree, no key, NO WRITE. There is nowhere legitimate to record this, so it
        # goes to stderr and the script still exits 0.
        Write-Error "seat.ps1: could not resolve a rooted existing worktree; nothing written." -EA Continue
        exit 0
    }

    $coord = Get-CoordDir -From $wt
    if (-not $coord) {
        Write-Error "seat.ps1: could not resolve the git common dir from '$wt'; nothing written." -EA Continue
        exit 0
    }

    $script:SeatsDir = Join-Path $coord 'seats'
    if (-not (Test-Path -LiteralPath $script:SeatsDir)) {
        New-Item -ItemType Directory -Path $script:SeatsDir -Force | Out-Null
    }

    $boxKey = ConvertTo-BoxKey -Path $wt

    # Rule 3. BEFORE any early return, so a no-op invocation still proves the writer ran.
    try {
        $aliveDir = Join-Path $script:SeatsDir '.writer-alive'
        if (-not (Test-Path -LiteralPath $aliveDir)) { New-Item -ItemType Directory -Path $aliveDir -Force | Out-Null }
        Set-Content -LiteralPath (Join-Path $aliveDir "$boxKey.txt") `
            -Value ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) -Encoding utf8 -EA Stop
    } catch { Write-WriterError -Stage 'writer-alive' -Message $_.Exception.Message }

    if ($BumpEpoch) {
        $f = Join-Path $script:SeatsDir '.pool-epoch'
        $next = (Get-PoolEpoch -SeatsDir $script:SeatsDir) + 1
        Set-Content -LiteralPath $f -Value ([string]$next) -Encoding utf8
        Write-Host "pool epoch is now $next"
        exit 0
    }

    $sk = Get-SessionKey -Payload $payload -Override $SessionId -AllowEnvFallback:(-not $Record)
    $identified = [bool]$sk.Id

    # RULE 4, THE REFUSAL. A declaration or a close that cannot name its session has nowhere
    # legitimate to go: the anonymous slot belongs to whoever was here last, so writing there both
    # invents a seat the roster counts and marks a record the closing seat is not the subject of.
    # This is a NO-WRITE path, like rule 1, and it says how to fix it rather than failing quietly.
    if (($Declare -or $Close) -and -not $identified) {
        $how = "pass -SessionId <id>, or set CLAUDE_CODE_SESSION_ID"
        Write-Error "seat.ps1: -Declare/-Close needs a session identity and found none ($how); nothing written." -EA Continue
        Write-WriterError -Stage 'no-session-identity' -Message "declare/close refused: no session id ($how)"
        exit 0
    }

    $recPath = Join-Path (Join-Path $script:SeatsDir $boxKey) ("$($sk.Key).json")

    # Read the prior record so -Declare and -Close amend rather than truncate, and so `writes` and
    # the declared half survive a -Record that knows nothing about them.
    $prior = $null
    if (Test-Path -LiteralPath $recPath) {
        try { $prior = Get-Content -LiteralPath $recPath -Raw -EA Stop | ConvertFrom-Json -EA Stop }
        catch { Write-WriterError -Stage 'read-prior' -Message $_.Exception.Message }
    }

    function Prior([string]$Name, $Default) {
        if ($prior -and ($prior.PSObject.Properties.Name -contains $Name)) { return $prior.$Name }
        return $Default
    }

    # PriorOwn IS Prior FOR AN IDENTIFIED RECORD AND NOTHING AT ALL FOR AN ANONYMOUS ONE. The `nosid`
    # file is one slot per CHECKOUT, so its prior contents may be a different session's; carrying them
    # forward is how a fresh seat came back holding someone else's goal and lifecycle. `writes` still
    # uses Prior: it counts writes to that FILE, which is true of the slot regardless of who wrote.
    function PriorOwn([string]$Name, $Default) {
        if (-not $identified) { return $Default }
        return (Prior $Name $Default)
    }

    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    # One ref per (box, session), overwritten each turn exactly as the record is, so anchoring adds no
    # cardinality the layer did not already have. The name is self-documenting to whoever finds it in
    # `git for-each-ref` months later.
    $stashRef = "refs/mefor-seat/$(ConvertTo-RefComponent $boxKey)/$(ConvertTo-RefComponent $sk.Key)"
    $g = Get-GitFacts -Wt $wt -StashRef $stashRef
    $cr = Get-ConfigRootLabel

    $lifecycle = PriorOwn 'lifecycle' 'open'
    $lifecycleAt = ConvertTo-Utc8601 (PriorOwn 'lifecycleAt' $now)
    if (-not $lifecycleAt) { $lifecycleAt = $now }
    if ($Close) {
        $lifecycle = if ($Handback) { 'handed' } else { 'closed' }
        $lifecycleAt = $now
    }

    # THE EPISODE BASELINE, minted once and never moved. It is a separate field from lifecycleAt for
    # the reason given at Get-Attribution: a -Close must not be able to disown the episode's own work.
    $episodeStart = ConvertTo-Utc8601 (PriorOwn 'episodeStart' $null)
    $episodeStartSource = PriorOwn 'episodeStartSource' $null
    if (-not $identified) {
        # No identity, no baseline. Attribution then answers 'unknown' for every claim and allocation,
        # which is the truth: this record cannot say whose episode it is. Inventing a baseline here
        # would hand a confident answer either way, and both directions are wrong (claiming another
        # occupant's ledger numbers, or disowning your own).
        $episodeStart = $null
        $episodeStartSource = 'unknown-session'
    } elseif (-not $episodeStart) {
        # The first Stop hook fires at the END of turn 1, so minting the baseline here would put every
        # turn-1 allocation before its own episode -- and allocating a ledger number early is the
        # normal shape of a turn 1. The transcript the payload names was created when the SESSION was,
        # which is the question actually being asked.
        $tp = $null
        if ($payload -and ($payload.PSObject.Properties.Name -contains 'transcript_path')) { $tp = [string]$payload.transcript_path }
        if ($tp -and (Test-Path -LiteralPath $tp)) {
            try {
                $episodeStart = ConvertTo-Utc8601 ((Get-Item -LiteralPath $tp -EA Stop).CreationTimeUtc)
                $episodeStartSource = 'payload-transcript'
            } catch { $episodeStart = $null }
        }
        if (-not $episodeStart) {
            # Honest about what it is: an UPPER bound on the true start, so turn-1 work can still read
            # as inherited. The source is stored so a reader can tell which kind of baseline this is.
            $episodeStart = $now
            $episodeStartSource = 'first-write'
        }
    }

    $handoffObj = PriorOwn 'handoff' $null
    if ($Declare -and $Handoff) {
        if (Test-Path -LiteralPath $Handoff) {
            $hi = Get-Item -LiteralPath $Handoff
            $handoffObj = [ordered]@{
                path      = $hi.FullName
                bytes     = $hi.Length
                sha256    = (Get-FileHash -LiteralPath $hi.FullName -Algorithm SHA256).Hash
                pointedAt = $now
            }
        } else {
            # A pointer that does not resolve is recorded AS not resolving. Measured: a live claim
            # note already points at a handoff filename that no longer exists, and nothing reported
            # it because nothing validates a pointer.
            $handoffObj = [ordered]@{ path = $Handoff; bytes = $null; sha256 = $null; pointedAt = $now; unresolved = $true }
            Write-WriterError -Stage 'handoff-pointer' -Message "declared handoff does not exist: $Handoff"
        }
    }

    $pred = PriorOwn 'predecessor' $null
    if ($Declare -and $Predecessor) {
        $parts = $Predecessor -split '[/\\]', 2
        if ($parts.Count -eq 2) { $pred = [ordered]@{ boxKey = $parts[0]; sessionKey = $parts[1] } }
    }

    # THE OPTIONAL FIELDS ARE BUILT BEFORE THE RECORD LITERAL, EACH DEGRADING ON ITS OWN. A throw
    # inside the literal costs the ENTIRE write -- the involuntary git facts along with it -- and rule
    # 2's exit 0 then reports that as success. Measured: one note holding a double space did exactly
    # that, and the seat's whole episode went unrecorded behind a clean exit code.
    $notesValue = PriorOwn 'notes' ''
    if ($Declare -and $Notes) {
        try { $notesValue = Limit-Text -Text $Notes }
        catch {
            $notesValue = "[note dropped by the writer: $($_.Exception.Message)]"
            Write-WriterError -Stage 'notes' -Message $_.Exception.Message
        }
    }

    $rec = [ordered]@{
        schema           = $SCHEMA
        writerVersion    = $WRITER
        asOf             = $now
        asOfSource       = if ($Record) { 'hook:Stop' } elseif ($Declare) { 'cli:Declare' } elseif ($Close) { 'cli:Close' } else { 'cli:other' }
        writes           = [int](Prior 'writes' 0) + 1
        lifecycle        = $lifecycle
        # WHEN THE LIFECYCLE LAST CHANGED. It is NOT the episode baseline -- that is episodeStart,
        # below -- and it must never be read as one again.
        lifecycleAt      = $lifecycleAt
        episodeStart     = $episodeStart
        episodeStartSource = $episodeStartSource
        boxKey           = $boxKey
        worktree         = $wt
        worktreeSource   = 'git rev-parse --show-toplevel'
        sessionId        = $sk.Id
        sessionKey       = $sk.Key
        sessionIdSource  = $sk.Source
        kind             = if ($payload -and ($payload.PSObject.Properties.Name -contains 'kind')) { [string]$payload.kind } else { $null }
        entrypoint       = if ($payload -and ($payload.PSObject.Properties.Name -contains 'entrypoint')) { [string]$payload.entrypoint } else { $null }
        pid              = $PID
        configRootLabel  = $cr.Label
        configRootSource = $cr.Source
        poolEpoch        = Get-PoolEpoch -SeatsDir $script:SeatsDir
        # PriorOwn, not Prior: the declared half of an anonymous record would be the previous
        # occupant's (rule 4).
        seat             = if ($Declare -and $Seat) { $Seat } else { PriorOwn 'seat' $null }
        seatSource       = if ($Declare -and $Seat) { 'declared' } else { PriorOwn 'seatSource' $null }
        declaredAt       = if ($Declare -and $Seat) { $now } else { ConvertTo-Utc8601 (PriorOwn 'declaredAt' $null) }
        goal             = if ($Declare -and $Goal) { $Goal } else { PriorOwn 'goal' $null }
        done             = if ($Declare -and $Done) { $Done } else { PriorOwn 'done' $null }
        outOfScope       = if ($Declare -and $OutOfScope) { $OutOfScope } else { PriorOwn 'outOfScope' $null }
        branch           = $g.branch
        upstream         = $g.upstream
        tip              = $g.tip
        mergeBase        = $g.mergeBase
        touchedPaths     = $g.touched
        # The involuntary answer to "what was this seat doing". Owner ruling 2026-08-14 demoted the
        # voluntary declared half, so the briefing has to stand up without it, and this is what it
        # stands on: subjects written as a side effect of working, dated, and describing what was
        # actually DONE rather than what was intended at the start.
        commits          = $g.commits
        unpushed         = $g.unpushed
        dirty            = $g.dirty
        stashSha         = $g.stashSha
        stashRef         = $g.stashRef
        stashCovers      = $g.stashCovers
        claims           = @(Get-ClaimsFor -CoordDir $coord -Wt $wt -EpisodeStart $episodeStart)
        allocations      = @(Get-AllocationsFor -CoordDir $coord -Wt $wt -EpisodeStart $episodeStart)
        handoff          = $handoffObj
        predecessor      = $pred
        notes            = $notesValue
    }

    Write-RecordAtomic -Path $recPath -Object $rec

    if (-not $Record) { Write-Host "wrote $recPath" }
} catch {
    Write-WriterError -Stage 'main' -Message $_.Exception.Message
    Write-Error "seat.ps1: $($_.Exception.Message)" -EA Continue
    $exit = 0
}

exit $exit
