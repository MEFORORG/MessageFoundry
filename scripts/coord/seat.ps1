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
    removes the CROSS-SEAT half of that hazard: seat A can no longer overwrite seat B.

    IT DOES NOT REMOVE THE OTHER HALF, AND THIS FILE USED TO CLAIM IT DID. One record still has
    several writers OF ITS OWN -- the seat's Stop hook and the same seat's `-Close`, and every
    subagent turn -- and each of them is a read-modify-write, not a write. Measured on this box: the
    gap between the prior read and the write is ~500 ms, and firing `-Close -Handback` with a rival
    `-Record` starting 120 ms later lost the close in 3 of 3 trials -- close exit 0, the words
    "wrote <path>" on stdout, `lifecycle=open` on disk, `.writer-errors.txt` absent, and the roster
    then calling that seat INTERRUPTED. Rule 5 is what actually removes it.

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

    SIX HARD RULES, each paying for a measured failure on this box.

    1. NEVER MINT A BOX KEY FROM A PATH THAT IS NOT A ROOTED, EXISTING DIRECTORY. mail.ps1:392-401
       records that the unguarded version "silently mints a NEW box that no reader will ever drain",
       and 11 of 29 mailboxes on disk are that residue. A git-resolution failure here is a NO-WRITE
       path, never an empty-string path -- writing to seats/-<hash>/ would be the same defect with a
       new name.

    2. A WRITER THAT DIES MUST NOT DIE SILENTLY, AND A WRITER THAT MERELY DEGRADED MUST NOT BE
       REPORTED AS ONE THAT DIED. Every failure appends one line and the script still exits 0.
       Exiting non-zero from a Stop hook is its own hazard; leaving no trace is worse than either.

       TWO FILES, BECAUSE THEY ARE TWO SENTENCES AND A READER ACTS DIFFERENTLY ON EACH. Same four
       tab-separated columns (utc, host, stage, message), so one splitter reads both:
         * seats/.writer-errors.txt   THE RECORD DID NOT LAND, OR LANDED SHORT. Stages: writer-alive
           (rule 3's proof-of-life was not written, so a reader will age a running writer as dead),
           read-prior (the carried-forward fields were lost), record-lock (applied unserialised, so a
           concurrent update may have been overwritten), no-session-identity (rule 4 refused the
           write), main (the write may not have happened at all). "Missing or stale" is TRUE of a
           seat named here.
         * seats/.writer-degraded.txt A PROBE COULD NOT ANSWER AND THE RECORD SAYS SO IN ITS OWN
           FIELDS. Stages: status-probe (dirty.probe=failed, dirty.probeError, and the counts and
           lists all null), stash-probe / stash-anchor (stashProbe.outcome + exitCode + error,
           stashCovers, stashSha/stashRef), handoff-pointer (handoff.unresolved), notes (the note
           field holds the drop marker). The record for a seat named here is present and complete.
       Every line in the degraded log is ALSO carried in that turn's own record, as `writerDegraded`,
       so the per-seat evidence stands without the fleet-wide file.

       WHY THE SPLIT IS NOT COSMETIC. Measured on a throwaway repo: one sibling holding
       .git/index.lock across exactly one -Record produced a record that was fresh, complete and
       correct in every field, and a roster banner reading "STOP CONDITIONS FIRED -- ... the writer
       FAILED that many times inside 120 minutes ... Any seat it failed on is missing or stale
       below". Both halves of that sentence were false of that seat, and rule 6's own text says this
       contention "is not hypothetical -- sibling agents commit in the same checkout while the hook
       fires". A stop channel that fires when nothing is wrong is a stop channel a cold-start reader
       learns to skip, and the turn it finally carries a real "this turn was NOT recorded" is the
       turn that gets skipped with it.

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

    5. EVERY UPDATE TO A RECORD IS SERIALISED, AND THE SERIALISATION HAS A DEADLINE. Read-prior ->
       ~8 git subprocesses + a claims/alloc scan -> write is a ~500 ms window in which another
       writer's committed update is invisible; whoever renames last wins and the loser's fields are
       gone with no trace anywhere. Measured before the fix: 3 of 3 `-Close -Handback` runs lost the
       close to a rival `-Record` started 120 ms later, and 6 concurrent `-Record` runs moved the
       `writes` counter 1 -> 3 where 7 was owed. So the SLOW half (git facts, the claims scan) runs
       unlocked, and only read-prior -> assemble -> rename is held under
       seats/<box>/.<sessionKey>.json.lock -- a hold of milliseconds, not half a second.

       THE DEADLINE IS THE OTHER HALF OF THE RULE, and it outranks the serialisation. This runs as a
       Stop hook; a lock that blocks forever is a worse defect than the race it prevents, so the wait
       is bounded, a lock older than any legitimate hold is broken as an orphan, and a wait that
       still times out PROCEEDS UNLOCKED and records that it did (rule 2). Blocking is never the
       failure mode.

    6. A PROBE THAT COULD NOT ASK MUST NOT BE STORED AS AN ANSWER OF NONE. `git stash create` needs
       the index lock; `git status --porcelain` does not. Measured with a sibling process holding
       .git/index.lock: status returned ' M tracked.txt' (exit 0) while stash create exited 1, and
       the record stored trackedCount=1 beside stashCovers=nothing-untracked-only with
       .writer-errors.txt absent -- "there is nothing to rescue" asserted over a tracked edit held by
       no commit, no stash and no remote, in the one file a replacement seat reads to decide whether
       the checkout is safe to reuse. Index-lock contention is not hypothetical here: sibling agents
       commit in the same checkout while the hook fires. So each probe stores its OUTCOME and its
       PROVENANCE next to its result, and a result that was never obtained is null, never zero.

       THE RULE COVERS THE LISTS, NOT ONLY THE COUNTS, and it was applied to the counts alone for
       one pass. Measured with a peer process holding .git/index open exclusively, so
       `git status --porcelain -z` exited 128: dirty.count/trackedCount/untrackedCount were all
       null -- correct -- beside dirty.paths=[] and dirty.untracked=[], while the checkout held
       ' M tracked.txt' and an untracked ONLY-COPY.md. The lists are the half a reader triages on,
       so the empty ones rendered as "no untracked files were recorded" under the heading "WORK AT
       RISK -- ... the only category that cannot be recovered elsewhere". An answer of none is a
       measurement; both lists are null when there was no measurement to list.

       AND A LATER PROBE THAT COULD NOT ASK MUST NOT DELETE AN EARLIER PROBE'S ANSWER. `stashSha`
       and `stashRef` were re-derived every turn from this turn's probe alone, so turn 2 under
       contention rewrote a live anchor to null: measured, turn 1 stored a sha and a ref that
       `git rev-parse --verify` still resolved AFTER turn 2 declared stashCovers=
       tracked-edits-NOT-captured. The anchor lives in the common git dir and outlives
       `git worktree remove --force`, which this project's own remove.ps1 and prune-merged.ps1 both
       call, so the record was pointing away from the only surviving copy of the work. When the
       probe cannot ask, the REF STORE is re-read instead -- a measurement taken now, not a value
       copied out of the prior record -- and the object's own committer date is stored as
       `stashAsOf` so the reader sees the anchor's age rather than inheriting a claim about now.

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
# Every degradation recorded during THIS run, in order. Carried into the record so a reader has a
# PER-SEAT operand and does not have to infer one from a fleet-wide log (rule 2's second channel).
$script:Degraded = @()

function Write-SeatLog {
    param([string]$File, [string]$Stage, [string]$Message)
    # Best-effort by construction: if we cannot even record the failure we must still exit 0, or a
    # broken writer takes the seat's Stop hook down with it.
    try {
        if (-not $script:SeatsDir) { return }
        $f = Join-Path $script:SeatsDir $File
        # DOUBLE-quoted, and that is the whole point: PowerShell processes the backtick escape only
        # inside double quotes, so the single-quoted form wrote the two literal characters backtick-t
        # between the fields. Measured: the log then split into ONE field on a tab, so the column
        # naming WHICH stage failed could not be extracted, while the file itself looked healthy and
        # fleet.ps1's line count stayed correct.
        $line = "{0}`t{1}`t{2}`t{3}" -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $env:COMPUTERNAME, $Stage, ($Message -replace '\s+', ' ')
        Add-Content -Path $f -Value $line -Encoding utf8 -EA SilentlyContinue
    } catch { }
}

function Write-WriterError {
    # THE RECORD DID NOT LAND, OR LANDED SHORT. See rule 2 for the split and why it is not cosmetic.
    param([string]$Stage, [string]$Message)
    Write-SeatLog -File '.writer-errors.txt' -Stage $Stage -Message $Message
}

function Write-WriterDegraded {
    # THE RECORD LANDED AND SAYS SO ITSELF. A probe that could not answer is not a writer that died,
    # and routing it into the same file made a reader's completeness stop fire on this project's
    # ordinary multi-agent workflow -- measured: one sibling holding .git/index.lock across one Stop
    # hook produced a fresh, complete, correct record and a roster banner reading "the writer FAILED
    # ... Any seat it failed on is missing or stale below", which was false of that seat in both
    # halves. Same four tab-separated columns as the error log, so any reader's splitter works
    # verbatim on either file.
    param([string]$Stage, [string]$Message)
    $script:Degraded += [ordered]@{
        stage  = $Stage
        at     = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        detail = ($Message -replace '\s+', ' ')
    }
    Write-SeatLog -File '.writer-degraded.txt' -Stage $Stage -Message $Message
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

function Invoke-GitProbe {
    # Invoke-Git answers WHAT GIT SAID. This answers WHETHER GIT ANSWERED AT ALL, which is a
    # different question and the only one that can be asked by a caller whose empty result would
    # otherwise be stored as the fact "there is nothing here" (rule 6).
    #
    # Returns @{ ok; exitCode; out; err } and NEVER throws. `ok` is a fact about the PROBE, not about
    # the tree: ok=$true with an empty `out` is git saying "none", ok=$false is git saying nothing at
    # all. Collapsing those two is the defect.
    #
    # STDERR GOES TO A FILE, not through 2>&1. Merging a native command's stderr into the success
    # stream under $ErrorActionPreference='Stop' turns a diagnostic line into a terminating error in
    # this shell, and a probe whose whole job is to survive a failure must not be the thing that
    # throws.
    param([string]$Dir, [string[]]$GitArgs, [switch]$Raw)
    $errFile = $null
    try {
        $errFile = [System.IO.Path]::GetTempFileName()
        $out = & git -C $Dir @GitArgs 2>$errFile
        $code = $LASTEXITCODE
        $errText = ''
        try { $errText = [string](Get-Content -LiteralPath $errFile -Raw -EA Stop) } catch { }
        $joined = if ($null -eq $out) { '' } else { ($out -join "`n") }
        if (-not $Raw) { $joined = $joined.Trim() }
        return @{
            ok       = ($code -eq 0)
            exitCode = $code
            out      = $joined
            err      = (Limit-Text -Text $errText -Max 400)
        }
    } catch {
        return @{ ok = $false; exitCode = $null; out = ''; err = (Limit-Text -Text $_.Exception.Message -Max 400) }
    } finally {
        if ($errFile) { Remove-Item -LiteralPath $errFile -Force -EA SilentlyContinue }
    }
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
    #
    # RULE 6 APPLIES TO THIS PROBE FIRST, AND TO THE LISTS AS WELL AS THE COUNTS. Every count AND
    # every path below is downstream of ONE git call, and if that call cannot run, "0 dirty paths"
    # and "[]" are not measurements -- they are the absence of one, wearing the same clothes as a
    # clean tree. So the outcome is recorded beside the results, and a status that did not answer
    # leaves counts and lists alike NULL rather than zero and empty.
    $trackedPaths = @()
    $untrackedPaths = @()
    $statusOk = $true
    $statusError = $null
    $stProbe = Invoke-GitProbe -Dir $Wt -GitArgs @('status', '--porcelain', '-z') -Raw
    if (-not $stProbe.ok) {
        $statusOk = $false
        $statusError = "git status --porcelain exit=$($stProbe.exitCode): $($stProbe.err)"
        # DEGRADED, not an error: the record below carries probe=failed, probeError, and null counts
        # and lists, so it describes this failure itself (rule 2).
        Write-WriterDegraded -Stage 'status-probe' -Message $statusError
    } else {
        $st = $stProbe.out
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
    }

    # `git stash create` builds a commit object WITHOUT touching the working tree or the stash ref,
    # so it cannot disturb a seat that may still be using the checkout.
    #
    # IT ALSO WRITES NO REF AND NO REFLOG ENTRY, so the object is unreachable from the moment it
    # exists. Measured: `git gc --prune=now` deleted the recorded stash and the record went on
    # carrying the same sha, with no way to tell a live handle from a dead one. So the sha is
    # ANCHORED to a ref of its own here -- one plumbing call, the object becomes gc-proof, and the
    # ref name says what it is to whoever finds it later.
    #
    # AND IT IS THE PROBE RULE 6 WAS WRITTEN FOR. `git stash create` TAKES THE INDEX LOCK; the status
    # call above does not. A sibling agent committing in the same checkout at the instant the Stop
    # hook fires therefore fails this call and nothing else -- measured: status exit 0 with
    # ' M tracked.txt', stash create exit 1 'Unable to create ... index.lock: File exists', record
    # written with trackedCount=1 and stashCovers=nothing-untracked-only, .writer-errors.txt absent.
    # A replacement seat reading that record is told the only thing to rescue is an untracked file,
    # about a tracked edit held by no commit, no stash and no remote.
    #
    # So the outcome is a stored FACT with its provenance -- outcome, attempts, git's own exit code
    # and stderr -- and stashCovers is derived from trackedCount as well as the sha, so it can say
    # NOT-CAPTURED instead of "nothing". ONE retry, because an index lock is typically another
    # process's short critical section rather than a persistent state; a second failure is reported,
    # not fought.
    $stash = $null
    $stashRefName = $null
    $stashAt = $null
    $stashProbe = [ordered]@{
        attempted = $false
        # created | none | failed | not-attempted | not-attempted-status-failed
        outcome   = if ($statusOk) { 'not-attempted' } else { 'not-attempted-status-failed' }
        reason    = if ($statusOk) { 'no tracked modifications to cover' } else { 'git status did not answer, so tracked modifications are unknown' }
        attempts  = 0
        exitCode  = $null
        error     = $null
        # TRUE when this turn could not ask and the sha/ref below therefore name an EARLIER turn's
        # anchor, re-read from the ref store just now. The pair (carried, stashAsOf) is what stops a
        # reader mistaking a surviving anchor for one taken this turn.
        carried   = $false
        at        = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($statusOk -and $trackedPaths.Count -gt 0) {
        $stashProbe.attempted = $true
        $stashProbe.reason = $null
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            $p = Invoke-GitProbe -Dir $Wt -GitArgs @('stash', 'create')
            $stashProbe.attempts = $attempt
            $stashProbe.exitCode = $p.exitCode
            if ($p.ok) {
                if ($p.out) {
                    $stash = $p.out
                    $stashProbe.outcome = 'created'
                    # Dated where it is MADE, not where it is anchored: an unanchored sha is still a
                    # thing that was true at a time, and the failed-anchor path must not leave it
                    # undated.
                    $stashAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
                }
                else {
                    # git ANSWERED, and the answer was none. Distinct from the branch below, and the
                    # distinction is the whole finding.
                    $stashProbe.outcome = 'none'
                    $stashProbe.reason = 'git stash create succeeded and produced no object'
                }
                $stashProbe.error = $null
                break
            }
            $stashProbe.outcome = 'failed'
            $stashProbe.error = $p.err
            if ($attempt -lt 2) { Start-Sleep -Milliseconds 300 }
        }
        if ($stashProbe.outcome -eq 'failed') {
            # DEGRADED, not an error: this record carries stashProbe.outcome/exitCode/error and a
            # stashCovers that says a rescue is owed, so it describes the failure itself (rule 2).
            Write-WriterDegraded -Stage 'stash-probe' -Message "git stash create failed after $($stashProbe.attempts) attempts (exit=$($stashProbe.exitCode)): $($stashProbe.error); $($trackedPaths.Count) tracked path(s) are NOT captured this turn"
        }
        if ($stash -and $StashRef) {
            # Invoke-Git returns '' on a silent success and $null only on failure.
            $anchored = Invoke-Git -Dir $Wt -GitArgs @('update-ref', $StashRef, $stash)
            if ($null -ne $anchored) { $stashRefName = $StashRef }
            else { Write-WriterDegraded -Stage 'stash-anchor' -Message "update-ref $StashRef failed; the stash sha is unreferenced and gc can delete it" }
        }
    } elseif ($statusOk -and $StashRef) {
        # Nothing to cover this pass. An anchor from an earlier turn would keep holding edits that
        # have since been committed or discarded, so it is dropped rather than left to outlive what
        # it described. Deleting a ref that is not there is a no-op that exits 0.
        #
        # GATED ON $statusOk, and that gate is load-bearing: if status could not answer, "nothing to
        # cover" is not known to be true, and deleting the anchor would destroy the last handle on
        # the previous turn's tracked edits on the strength of a measurement that never happened.
        Invoke-Git -Dir $Wt -GitArgs @('update-ref', '-d', $StashRef) | Out-Null
    }

    # A PROBE THAT COULD NOT ASK MUST NOT ERASE THE ANSWER AN EARLIER ONE OBTAINED (rule 6, and the
    # record's first principle: facts keep their time and a verdict is computed at read time).
    #
    # Before this, stashSha and stashRef came from THIS turn's probe alone, so a single contended
    # turn rewrote a live anchor to null -- measured, with the turn-1 ref still resolving to the
    # turn-1 sha at the instant the record said there was nothing capturing the tracked edits.
    #
    # THE RECOVERY IS A MEASUREMENT, NOT A COPY. The prior record's field would be a label written
    # in the past; the REF STORE is the authority and is re-read here, so the record names an object
    # only while that object is genuinely reachable. `for-each-ref` gives the sha and the commit's
    # own committer date in one call, and a ref that is not there exits 0 with no output -- so an
    # anchor that has since been pruned or deleted correctly yields nothing to carry.
    #
    # ONLY THE TWO could-not-ask OUTCOMES CARRY. 'none' means git answered and the answer was
    # nothing; 'not-attempted' means the tree was measured clean and the branch above has already
    # DELETED the ref. Carrying on either would resurrect a claim the writer just measured away.
    $stashCarried = $false
    if (-not $stash -and $StashRef -and ($stashProbe.outcome -in @('failed', 'not-attempted-status-failed'))) {
        $anchor = Invoke-Git -Dir $Wt -GitArgs @('for-each-ref', '--format=%(objectname)%09%(committerdate:iso-strict)', $StashRef)
        if ($anchor) {
            $parts = $anchor -split "`t"
            if ($parts[0] -match '\A[0-9a-f]{7,64}\z') {
                $stash = $parts[0]
                $stashRefName = $StashRef
                $stashCarried = $true
                $stashProbe.carried = $true
                # The object's OWN date, so the age is the anchor's and not this write's.
                $stashAt = if ($parts.Count -gt 1) { ConvertTo-Utc8601 $parts[1] } else { $null }
            }
        }
    }

    $dirtyPaths = @($trackedPaths) + @($untrackedPaths)

    # RULE 6 FOR THE LISTS, NOT ONLY THE COUNTS. Built here rather than inline in the literal
    # because an `if` whose true branch yields an EMPTY array collapses to $null on assignment --
    # which would silently turn "measured clean" into "could not ask", the inverse of this defect
    # and just as wrong. A variable holds the empty array; the literal only references it.
    $dirtyPathsOut = $null
    $untrackedOut = $null
    if ($statusOk) {
        $dirtyPathsOut = @($dirtyPaths | Select-Object -First 200)
        $untrackedOut = @($untrackedPaths | Select-Object -First 200)
    }

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
            # NULL, NOT 0, WHEN THE PROBE DID NOT ANSWER (rule 6). Zero is a measurement; null is the
            # absence of one, and only one of those two is true when git could not be asked.
            count          = if ($statusOk) { $dirtyPaths.Count } else { $null }
            # NULL, NOT [], FOR THE SAME REASON AND ON THE SAME GATE. These two lists are the half a
            # reader triages on -- an empty one rendered as "no untracked files were recorded" under
            # "WORK AT RISK" while an only-copy file sat in the checkout.
            paths          = $dirtyPathsOut
            trackedCount   = if ($statusOk) { $trackedPaths.Count } else { $null }
            untrackedCount = if ($statusOk) { $untrackedPaths.Count } else { $null }
            # Named, not counted: a replacement seat has to copy these by hand.
            untracked      = $untrackedOut
            # The provenance of every number above. 'ok' means git answered; 'failed' means the counts
            # are unknown rather than zero, and `probeError` says why.
            probe          = if ($statusOk) { 'ok' } else { 'failed' }
            probeError     = $statusError
        }
        stashSha  = $stash
        # The ref holding that sha, so a reader can test the OBJECT (`git rev-parse --verify`) rather
        # than the string. A null here with a non-null stashSha means the anchor did not take.
        stashRef  = $stashRefName
        # WHEN THE OBJECT ABOVE WAS MADE -- not when this record was written. They are the same
        # instant only on a turn that actually created one; on a carried anchor this is the earlier
        # turn's commit date, read off the object itself, and it is what stops "there is a stash"
        # being read as "there is a stash of what the tree holds right now".
        stashAsOf = $stashAt
        # The probe's own outcome, kept beside its result so "could not ask" is never read as "asked,
        # and the answer was none" (rule 6).
        stashProbe = $stashProbe
        # What the stash actually covers, so the reader never over-promises recovery. An unanchored
        # sha is named as such: it is a handle that can go dead between the write and the read.
        #
        # DERIVED FROM trackedCount AS WELL AS THE SHA. Before that, a failed probe over a dirty tree
        # emitted 'nothing-untracked-only' -- a stored claim that nothing tracked needs rescuing,
        # contradicting trackedCount in the same record. The 'NOT-captured' arms are the ones that
        # say a rescue is owed and this writer could not provide it.
        #
        # THE CARRIED ARMS COME FIRST AND SAY BOTH HALVES. A surviving anchor is a real rescue
        # object, so the record must name it; it was made on an EARLIER turn, so it must not be
        # reported as covering what the tree holds now. 'tracked-only' would say the second thing.
        stashCovers = if ($stashCarried -and -not $statusOk) { 'earlier-anchor-held-status-probe-failed' }
                      elseif ($stashCarried -and $untrackedPaths.Count -gt 0) { 'earlier-anchor-held-this-turn-NOT-captured-and-untracked-only' }
                      elseif ($stashCarried) { 'earlier-anchor-held-this-turn-NOT-captured' }
                      elseif (-not $statusOk) { 'unknown-status-probe-failed' }
                      elseif ($stash -and $stashRefName) { 'tracked-only' }
                      elseif ($stash) { 'tracked-only-unanchored' }
                      elseif ($trackedPaths.Count -gt 0 -and $untrackedPaths.Count -gt 0) { 'tracked-edits-NOT-captured-and-untracked-only' }
                      elseif ($trackedPaths.Count -gt 0) { 'tracked-edits-NOT-captured' }
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

# THE SCAN AND THE ATTRIBUTION ARE SEPARATE STEPS, and the separation is what lets rule 5 keep its
# critical section short. Scanning several hundred claim/alloc files is the slow half and depends on
# nothing but the worktree; attributing them needs `episodeStart`, which comes from the PRIOR RECORD
# and must therefore be read under the lock. Fused, the whole scan would have to run inside the
# critical section and every Stop hook would serialise behind every other one for half a second.
function Get-ClaimsFor {
    param([string]$CoordDir, [string]$Wt)
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
        # rawAt is carried so the attribution step gets the ORIGINAL value rather than a string it
        # would have to re-parse. It is dropped by Add-Attribution and never reaches the record.
        $out += @{
            key       = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            claimedAt = if ($atIso) { $atIso } elseif ($null -ne $at) { [string]$at } else { $null }
            rawAt     = $at
        }
    }
    return $out
}

function Get-AllocationsFor {
    param([string]$CoordDir, [string]$Wt)
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
            $out += @{
                kind          = $kindDir.Name
                number        = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
                allocWorktree = $aw
                allocatedAt   = if ($atIso) { $atIso } elseif ($null -ne $at) { [string]$at } else { $null }
                allocBranch   = if ($j.PSObject.Properties.Name -contains 'branch') { [string]$j.branch } else { $null }
                rawAt         = $at
            }
        }
    }
    return $out
}

function Add-Attribution {
    # The cheap half of the two steps above: one comparison per entry, so it can run inside the
    # critical section where `episodeStart` is finally known. Key ORDER is fixed here rather than in
    # the scan, because it is what the record stores.
    # $EpisodeStart AND $Entries ARE DELIBERATELY UNTYPED, and rawAt is passed through untouched: a
    # [string] parameter culture-casts the [DateTime] ConvertFrom-Json hands back, which is the exact
    # loss ConvertTo-UtcInstant exists to stop (see the note above Get-Attribution). Carrying the raw
    # value from the scan to here rather than the formatted one is what keeps that true across the
    # split.
    param($Entries, $EpisodeStart, [string[]]$Keys)
    $out = @()
    foreach ($e in @($Entries)) {
        $row = [ordered]@{}
        foreach ($k in $Keys) { $row[$k] = $e[$k] }
        $row['attribution'] = (Get-Attribution -At $e['rawAt'] -EpisodeStart $EpisodeStart)
        $out += $row
    }
    return $out
}

# ---------------------------------------------------------------------------------------------
# Atomic write, and the serialisation that makes an UPDATE atomic (rule 5).
# ---------------------------------------------------------------------------------------------

function Write-TextAtomic {
    # Write-then-rename, so a reader never sees a half-written file and a crash never leaves a
    # truncated one. Used for the record AND for the heartbeat, which is one file per BOX and
    # therefore written by every session in that checkout at once.
    #
    # THE TEMP NAME CARRIES THE PID AND A TICK COUNT, and that is a fix, not decoration. A temp path
    # derived from the destination alone means two concurrent writers collide ON THE TEMP FILE: the
    # loser threw 'the process cannot access the file ... because it is being used by another
    # process', logged a line and wrote NOTHING, having already done all the work. Measured on both
    # files. The suffix stays '.tmp' so no reader's *.json or *.txt glob can ever pick one up.
    param([string]$Path, [string]$Text, [int]$Attempts = 4)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # Temp file in the SAME directory: a rename across volumes is a copy, and a copy is not atomic.
    $tmp = Join-Path $dir ('.' + [System.IO.Path]::GetFileName($Path) + ".$PID." + [string]([DateTime]::UtcNow.Ticks) + '.tmp')
    try {
        Set-Content -LiteralPath $tmp -Value $Text -Encoding utf8 -EA Stop
        # The RENAME can still lose a race with a reader holding the destination open. It is a
        # sub-millisecond window and retrying is cheap; failing is not.
        for ($i = 1; $i -le $Attempts; $i++) {
            try { Move-Item -LiteralPath $tmp -Destination $Path -Force -EA Stop; return }
            catch { if ($i -eq $Attempts) { throw }; Start-Sleep -Milliseconds (20 * $i) }
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue }
    }
}

function Write-RecordAtomic {
    param([string]$Path, $Object)
    Write-TextAtomic -Path $Path -Text ($Object | ConvertTo-Json -Depth 8)
}

function Invoke-WithRecordLock {
    # RULE 5. Runs $Body with the record's update lock held, and RETURNS WHETHER IT HELD IT --
    # the body runs either way. The caller records the difference; it never skips the write.
    #
    # WHY THE BODY STILL RUNS ON FAILURE. This is a Stop hook. A writer that refuses to record
    # because it could not take a lock converts a rare lost field into a guaranteed lost episode, and
    # a writer that waits indefinitely hangs the seat it is supposed to be documenting. Both are
    # worse than the race. So the wait is bounded, the answer is reported, and progress is
    # unconditional -- which is rule 2 applied to contention.
    #
    # THE ORPHAN BREAK IS NOT OPTIONAL. The lock is a file; a process killed mid-hold (an exhausted
    # account, a closed terminal, a rebooted box) leaves it behind forever, and nothing else on this
    # box would ever clear it. StaleMs is set far above any legitimate hold: the critical section is
    # a read, a compare and a rename -- single-digit milliseconds -- so a lock file that has not been
    # touched for seconds is not held by anyone still running.
    param(
        [string]$LockPath,
        [scriptblock]$Body,
        [int]$TimeoutMs = 5000,
        [int]$StaleMs = 3000
    )
    $dir = Split-Path $LockPath -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $handle = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        try {
            # CreateNew is the atomic test-and-set: it fails if the file exists, and the check and the
            # creation are one filesystem operation. Test-Path-then-create is two, and two is a race.
            $handle = [System.IO.File]::Open($LockPath, [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            break
        } catch [System.IO.IOException] {
            # THE SLEEP IS SKIPPED ONLY WHEN THE BREAK ACTUALLY SUCCEEDED. -EA Stop, not
            # SilentlyContinue: a lock whose holder is ALIVE cannot be deleted (the handle above is
            # opened FileShare::Read, which does not permit delete), and a hold that legitimately
            # outlasts StaleMs would then have looked stale on every pass and spun this loop at full
            # tilt for the whole timeout -- burning a core inside a Stop hook to reach the same
            # answer. A failed break falls through and waits like ordinary contention.
            $broke = $false
            try {
                $fi = Get-Item -LiteralPath $LockPath -EA Stop
                if (([DateTime]::UtcNow - $fi.LastWriteTimeUtc).TotalMilliseconds -gt $StaleMs) {
                    Remove-Item -LiteralPath $LockPath -Force -EA Stop
                    $broke = $true
                }
            } catch { }
            if (-not $broke) { Start-Sleep -Milliseconds 15 }
        } catch {
            # Not contention -- a permission or path fault. Spinning on it would burn the whole
            # budget for nothing.
            break
        }
    }
    if ($handle) {
        try {
            # Who holds it, since the file is the only evidence a later orphan-break has to go on.
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("$PID $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))")
            $handle.Write($bytes, 0, $bytes.Length)
            $handle.Flush()
            & $Body
        } finally {
            try { $handle.Dispose() } catch { }
            Remove-Item -LiteralPath $LockPath -Force -EA SilentlyContinue
        }
        return $true
    }
    & $Body
    return $false
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
    #
    # WRITTEN ATOMICALLY, because this file is keyed per BOX and every session in that checkout
    # touches it. Set-Content truncates in place and takes an exclusive handle: measured, six
    # simultaneous writers produced 'the process cannot access the file ... .writer-alive\<box>.txt
    # because it is being used by another process', so the losers left the file holding an OLDER
    # timestamp -- and a reader that ages this file would then read a running fleet as a dead one.
    # It also means a reader can never catch the file mid-truncate and parse an empty string as an
    # unreadable heartbeat. Path and contents are unchanged: one ISO-8601 Z instant, per box.
    try {
        $aliveDir = Join-Path $script:SeatsDir '.writer-alive'
        Write-TextAtomic -Path (Join-Path $aliveDir "$boxKey.txt") `
            -Text ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
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
    # Beside the record, not inside the seats root: the lock's granularity IS the record, so two
    # sessions in one checkout never wait on each other. '.lock' cannot be picked up by the reader's
    # *.json glob.
    $lockPath = "$recPath.lock"

    # ------------------------------------------------------------------------------------------
    # GATHER (unlocked). Everything here is slow -- ~8 git subprocesses and a scan of every claim
    # and alloc file -- and none of it depends on the record's current contents, so holding the lock
    # across it would serialise every seat's Stop hook behind every other one for half a second to
    # buy nothing. Rule 5.
    # ------------------------------------------------------------------------------------------
    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    # One ref per (box, session), overwritten each turn exactly as the record is, so anchoring adds no
    # cardinality the layer did not already have. The name is self-documenting to whoever finds it in
    # `git for-each-ref` months later.
    $stashRef = "refs/mefor-seat/$(ConvertTo-RefComponent $boxKey)/$(ConvertTo-RefComponent $sk.Key)"
    $g = Get-GitFacts -Wt $wt -StashRef $stashRef
    $cr = Get-ConfigRootLabel
    $rawClaims = @(Get-ClaimsFor -CoordDir $coord -Wt $wt)
    $rawAllocs = @(Get-AllocationsFor -CoordDir $coord -Wt $wt)

    # ------------------------------------------------------------------------------------------
    # COMMIT (locked). Read prior -> derive the carried-forward fields from THAT read -> write.
    # The prior read has to be inside the lock: it is the read half of the read-modify-write, and
    # reading it in the gather phase is exactly the ~500 ms of blindness that lost a -Close.
    # ------------------------------------------------------------------------------------------
    $applyUpdate = {

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
            # DEGRADED: the record carries handoff.unresolved=true, so it says this itself (rule 2).
            Write-WriterDegraded -Stage 'handoff-pointer' -Message "declared handoff does not exist: $Handoff"
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
            # DEGRADED: the notes field itself holds the drop marker, so the record says this (rule
            # 2). The rest of the write -- the whole involuntary half -- landed intact.
            Write-WriterDegraded -Stage 'notes' -Message $_.Exception.Message
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
        # The anchor's OWN age. A carried anchor is a fact from an earlier turn and this record must
        # not date it to now (see Get-GitFacts).
        stashAsOf        = $g.stashAsOf
        # THE PROBE'S OWN OUTCOME (rule 6), and it is listed here for the reason
        # test_missing_field_is_absent_not_empty exists: a field added to Get-GitFacts and not wired
        # into this literal is absent from the record while every count still agrees. It happened to
        # `commits` once and to this field once, caught by a rig that printed the field rather than
        # counting it.
        stashProbe       = $g.stashProbe
        stashCovers      = $g.stashCovers
        # Scanned in the gather phase, attributed here: attribution needs episodeStart, which is only
        # known once the prior record has been read under the lock.
        claims           = @(Add-Attribution -Entries $rawClaims -EpisodeStart $episodeStart -Keys @('key', 'claimedAt'))
        allocations      = @(Add-Attribution -Entries $rawAllocs -EpisodeStart $episodeStart -Keys @('kind', 'number', 'allocWorktree', 'allocatedAt', 'allocBranch'))
        handoff          = $handoffObj
        predecessor      = $pred
        notes            = $notesValue
        # EVERY DEGRADATION THIS TURN RECORDED, IN THE TURN'S OWN RECORD (rule 2's second channel).
        # seats/.writer-degraded.txt is fleet-wide and append-only; this is per-seat and per-turn, so
        # a reader can say WHICH seat degraded and WHEN without parsing a shared log, and an empty
        # list here is a measurement -- this write reached this line, so the list is complete for it.
        writerDegraded   = @($script:Degraded)
    }

    Write-RecordAtomic -Path $recPath -Object $rec

    }   # end $applyUpdate

    # THE RETURN VALUE IS A FACT ABOUT THIS WRITE, and it is recorded rather than acted on: the body
    # ran either way (rule 5's deadline clause), so an unserialised update is a caveat in the writer
    # error log, not a lost episode and never a hang.
    $held = Invoke-WithRecordLock -LockPath $lockPath -Body $applyUpdate
    if (-not $held) {
        Write-WriterError -Stage 'record-lock' -Message "could not take $lockPath within the deadline; the update was applied WITHOUT serialisation and a concurrent write may have been overwritten"
    }

    if (-not $Record) { Write-Host "wrote $recPath" }
} catch {
    Write-WriterError -Stage 'main' -Message $_.Exception.Message
    Write-Error "seat.ps1: $($_.Exception.Message)" -EA Continue
    $exit = 0
}

exit $exit
