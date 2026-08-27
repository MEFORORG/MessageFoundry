# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Write this session's EPISODE RECORD -- the durable answer to "what was this seat doing" that
    survives the seat's death, its account's exhaustion, and the switch to another account.

.DESCRIPTION
    One record per (worktree, session), at
    <git-common-dir>/mefor-coord/seats/<boxKey>/<sessionKey>.json

    Dot-sourcing does nothing useful; run it.

        seat.ps1 -Record                      # the hook path: derive everything, write, exit 0
        seat.ps1 -Declare -Seat builder3 -Goal "..." -Done "..." -OutOfScope "..."
        seat.ps1 -Declare -Handoff <path>     # point at the document a replacement should read
        seat.ps1 -Close [-Handback]
        seat.ps1 -BumpEpoch                   # mark an account switch; see POOL EPOCH below

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

    THREE HARD RULES, each paying for a measured failure on this box.

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
    # THE HOOK PATH FOR DECLARATION. -Prompt records that a seat was ASKED for a goal and had not
    # given one at that moment. It never invents a goal: a hook cannot know intent, and a goal a
    # machine wrote is not a declaration of anything.
    #
    # It exists because "this seat has no goal" was indistinguishable from "nobody ever asked it
    # for one", and those want opposite responses. Measured 2026-08-18: 1 of 22 episode records
    # carried a goal, with no way to tell whether the other 21 ignored a prompt or never saw one.
    [Parameter(ParameterSetName = 'Prompt')][switch]$Prompt,
    # A seat label the CALLER derived mechanically -- e.g. from the session record's own name.
    # Written only when nothing has been declared, and always with seatSource='derived:caller' so
    # it can never be read as a declaration. A derived label is a measurement; a declaration is a
    # statement of intent, and this file does not let one wear the other's clothes.
    [Parameter(ParameterSetName = 'Prompt')][string]$DerivedSeat,
    # Only for tests and for -Declare from a different cwd. Normally derived.
    [string]$Worktree,
    # Precedence for the record's session key, highest first: this parameter, then the hook's stdin
    # payload session_id, then $env:CLAUDE_CODE_SESSION_ID, then the literal 'nosid'. See
    # Get-SessionKey -- the env rung is what keeps a CLI -Declare on the same record as the hooks.
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
        $line = "{0}`t{1}`t{2}`t{3}" -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $env:COMPUTERNAME, $Stage, ($Message -replace '\s+', ' ')
        Add-Content -Path $f -Value $line -Encoding utf8 -EA SilentlyContinue
    } catch { }
}

function Test-HandoffPointer {
    <#
    .SYNOPSIS
        Re-check a recorded handoff pointer against the file it names, and return the pointer with a
        live verdict beside the recorded values. NEVER throws and NEVER edits what was declared.

    .DESCRIPTION
        A POINTER WAS ONLY EVER CHECKED ONCE, AT -Declare. `unresolved` is set in that one branch and
        no code path anywhere re-reads it, so a pointer that was true when recorded stays reported as
        true forever. Measured 2026-08-22 over every record on disk: THREE pointers exist and TWO ARE
        WRONG.

            nice-payne-4dcee0-26279d9a  6232 bytes recorded, file absent      DANGLING
            lander-5c09c3-6b54f797      6246 bytes recorded, 110001 on disk   DRIFTED
            vigorous-hugle-802758-...   4801 bytes recorded, 4801 on disk     resolves

        THE DRIFTED ONE IS THE WORSE DEFECT AND NOTHING REPORTED IT. A dangling pointer advertises its
        own brokenness -- a reader opens nothing and knows. A drifted one resolves, so fleet.ps1 tells
        an arriving seat "READ THE HANDOFF" for a document it believes is 6 KB and hands them 110 KB,
        and that reads as a working reference for as long as the record survives. This is the same
        shape as the stale-anchor rule in CLAUDE.md section 11: the evidence moved, and the citation
        kept resolving to something.

        RECORDED VALUES ARE NEVER REPAIRED. `path`, `bytes`, `sha256` and `pointedAt` are what the
        declaring seat asserted; overwriting them with today's numbers would erase the drift instead
        of reporting it, turning the instrument into the thing it exists to catch.

        NO RE-HASH ON THIS PATH. The live pointer names a 110,001-byte file and this runs on every
        Stop across every seat; size plus existence separates all three states and costs a stat.
        sha256 is re-taken only under -Declare, where the seat is asserting a new pointer anyway.
    #>
    param($Pointer, [string]$Now)

    # Reads one field off EITHER shape. -Declare builds an ordered hashtable and ConvertFrom-Json
    # hands back a PSCustomObject, and a single -Declare turn runs this over both.
    function Get-PointerField($Obj, [string]$Name) {
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [System.Collections.IDictionary]) {
            if ($Obj.Contains($Name)) { return $Obj[$Name] }
            return $null
        }
        if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
        return $null
    }

    $path = [string](Get-PointerField $Pointer 'path')
    if (-not $path) { return $Pointer }

    $out = [ordered]@{
        path      = $path
        bytes     = Get-PointerField $Pointer 'bytes'
        sha256    = Get-PointerField $Pointer 'sha256'
        pointedAt = Get-PointerField $Pointer 'pointedAt'
    }
    # Kept when present. It is the historical fact "this did not resolve the day it was declared",
    # which `state` does not carry and which a reader may still want.
    $wasUnresolved = Get-PointerField $Pointer 'unresolved'
    if ($null -ne $wasUnresolved) { $out['unresolved'] = $wasUnresolved }

    # `unreadable` is the DEFAULT, not an error branch, for the reason session-registry.ps1:241 gives
    # about its own fence: an unevaluated check is not a passed check. A pointer this function could
    # not stat must never fall through reading as one that resolved.
    $state = 'unreadable'
    $bytesNow = $null
    try {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $bytesNow = (Get-Item -LiteralPath $path -EA Stop).Length
            $recorded = $out['bytes']
            $state = if ($null -eq $recorded) { 'resolves' }
                     elseif ([long]$recorded -eq [long]$bytesNow) { 'resolves' }
                     else { 'drifted' }
        } else {
            $state = 'dangling'
        }
    } catch {
        Write-WriterError -Stage 'handoff-recheck' -Message $_.Exception.Message
    }

    $out['state'] = $state
    $out['bytesNow'] = $bytesNow
    $out['checkedAt'] = $Now
    return $out
}

function Invoke-Git {
    # Returns trimmed stdout, or $null when git failed. NEVER throws: a repo in a state git dislikes
    # must degrade one field, not lose the whole record.
    param([string]$Dir, [string[]]$GitArgs)
    try {
        $out = & git -C $Dir @GitArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($null -eq $out) { return '' }
        return ($out -join "`n").Trim()
    } catch { return $null }
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
    param($Payload, [string]$Override)
    $sid = $null
    $src = $null
    if ($Override) { $sid = $Override; $src = 'param' }
    elseif ($Payload -and ($Payload.PSObject.Properties.Name -contains 'session_id')) {
        $sid = [string]$Payload.session_id; $src = 'payload'
    }
    elseif ($env:CLAUDE_CODE_SESSION_ID) {
        # THE CLI PATH, AND IT IS THE ONE THE BANNER TELLS EVERY SEAT TO RUN. The two hooks read
        # session_id off their stdin payload and pass it as -SessionId; a person or agent typing
        # `-Declare -Seat x -Goal "..."` has no payload and no id to type, so before this fell to
        # 'nosid' -- and the DECLARATION, which is the whole point of the CLI path, landed in a
        # record attributable to no session.
        #
        # Measured 2026-08-21 across the live seats directory: 18 of 21 declarations sat in
        # nosid.json while the session-keyed record written by the hooks in the SAME BOX read
        # seat=null, goal=null. fleet.ps1 rendered each of those boxes twice -- once declared and
        # once NOT-DECLARED -- and nothing reported a problem, because both records were valid.
        # That is the hollow-record failure CLAUDE.md section 5 exists to prevent, arriving one
        # layer further in: the schema was fed, and what fed it could not be joined to a session.
        #
        # The variable is authoritative rather than a guess: on this session the SessionStart hook
        # wrote its record with sessionIdSource='param' carrying the id from its payload, and
        # $env:CLAUDE_CODE_SESSION_ID held THE SAME VALUE. Env is deliberately ranked BELOW the
        # payload so a hook holding the real thing always wins.
        #
        # NOT CLAUDE_CODE_HOST_SESSION_ID, which is a different namespace -- it carries the
        # `local_`-prefixed id the session-management MCP addresses, and keying records on it
        # would silently split every box in two all over again.
        $sid = [string]$env:CLAUDE_CODE_SESSION_ID; $src = 'env'
    }

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
    param([string]$Wt)

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
    # than reporting the gap.
    $trackedPaths = @()
    $untrackedPaths = @()
    $st = Invoke-Git -Dir $Wt -GitArgs @('status', '--porcelain')
    if ($st) {
        foreach ($line in ($st -split "`n" | Where-Object { $_ })) {
            $p = $line.Substring(3)
            if ($line.StartsWith('??')) { $untrackedPaths += $p } else { $trackedPaths += $p }
        }
    }

    # `git stash create` builds a commit object WITHOUT touching the working tree or the stash ref,
    # so it cannot disturb a seat that may still be using the checkout.
    $stash = $null
    if ($trackedPaths.Count -gt 0) {
        $s = Invoke-Git -Dir $Wt -GitArgs @('stash', 'create')
        if ($s) { $stash = $s }
    }
    $dirtyPaths = @($trackedPaths) + @($untrackedPaths)

    return [ordered]@{
        branch    = $branch
        upstream  = $upstream
        tip       = $tip
        mergeBase = $mergeBase
        touched   = $touched
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
        # What the stash actually covers, so the reader never over-promises recovery.
        stashCovers = if ($stash) { 'tracked-only' } elseif ($untrackedPaths.Count -gt 0) { 'nothing-untracked-only' } else { 'nothing-clean' }
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
function Get-Attribution {
    param([string]$At, [string]$EpisodeStart)
    if (-not $At -or -not $EpisodeStart) { return 'unknown' }
    try {
        if ([DateTimeOffset]::Parse($At).ToUniversalTime() -ge [DateTimeOffset]::Parse($EpisodeStart).ToUniversalTime()) {
            return 'this-episode'
        }
        return 'worktree-inherited'
    } catch { return 'unknown' }
}

function Get-ClaimsFor {
    param([string]$CoordDir, [string]$Wt, [string]$EpisodeStart)
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
            if ($j.PSObject.Properties.Name -contains $n) { $at = [string]$j.$n; break }
        }
        $out += [ordered]@{
            key         = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            claimedAt   = $at
            attribution = (Get-Attribution -At $at -EpisodeStart $EpisodeStart)
        }
    }
    return $out
}

function Get-AllocationsFor {
    param([string]$CoordDir, [string]$Wt, [string]$EpisodeStart)
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
                if ($j.PSObject.Properties.Name -contains $n) { $at = [string]$j.$n; break }
            }
            $out += [ordered]@{
                kind          = $kindDir.Name
                number        = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
                allocWorktree = $aw
                allocatedAt   = $at
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

    $sk = Get-SessionKey -Payload $payload -Override $SessionId
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

    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $g = Get-GitFacts -Wt $wt
    $cr = Get-ConfigRootLabel

    $lifecycle = Prior 'lifecycle' 'open'
    $lifecycleAt = Prior 'lifecycleAt' $now
    if ($Close) {
        $lifecycle = if ($Handback) { 'handed' } else { 'closed' }
        $lifecycleAt = $now
    }

    $handoffObj = Prior 'handoff' $null
    if ($Declare -and $Handoff) {
        # A BARE FILENAME IS WHAT CALLERS ACTUALLY PASS, AND IT COULD NEVER RESOLVE. Test-Path on a
        # relative path resolves against the CALLER's cwd, which is a worktree, never the handoffs
        # directory -- so the pointer was stored unresolved and the seat was told nothing, because
        # Write-WriterError goes to a file. Measured: ALL 17 lines ever written to .writer-errors.txt
        # are this one failure, and 2 of the 32 live pointers name a file that exists and is reported
        # as missing. The skill documents "-Handoff needs an ABSOLUTE path" and four seats walked
        # past that sentence inside twenty minutes on 2026-08-24; this seat made it five on 08-27.
        # Prose was doing a mechanism's job.
        #
        # The as-given test still runs FIRST, so an absolute path and a genuinely relative one both
        # behave exactly as before. This only adds a fallback for the shape that had no working
        # meaning at all.
        if (-not (Test-Path -LiteralPath $Handoff) -and -not [System.IO.Path]::IsPathRooted($Handoff)) {
            $hoDir = Join-Path (Split-Path -Parent $script:SeatsDir) 'handoffs'
            $cand = Join-Path $hoDir $Handoff
            if (Test-Path -LiteralPath $cand -PathType Leaf) { $Handoff = $cand }
        }
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
    # ON EVERY INVOCATION, INCLUDING -Record. Rule 3 above keeps "the writer ran" separate from "the
    # seat had something to say"; this is the same separation for the pointer. A seat that declares a
    # handoff and then works for six hours has a pointer whose truth was established once, at the
    # start, and the file it names is the one thing in the record that a DIFFERENT process is still
    # writing to.
    if ($handoffObj) { $handoffObj = Test-HandoffPointer -Pointer $handoffObj -Now $now }

    $pred = Prior 'predecessor' $null
    if ($Declare -and $Predecessor) {
        $parts = $Predecessor -split '[/\\]', 2
        if ($parts.Count -eq 2) { $pred = [ordered]@{ boxKey = $parts[0]; sessionKey = $parts[1] } }
    }

    $rec = [ordered]@{
        schema           = $SCHEMA
        writerVersion    = $WRITER
        asOf             = $now
        asOfSource       = if ($Record) { 'hook:Stop' } elseif ($Declare) { 'cli:Declare' } elseif ($Close) { 'cli:Close' } else { 'cli:other' }
        writes           = [int](Prior 'writes' 0) + 1
        lifecycle        = $lifecycle
        lifecycleAt      = $lifecycleAt
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
        # A DERIVED label never overwrites a DECLARED one, and never claims to be one. The order
        # here is the whole rule: declared wins, derived fills only a vacuum, prior survives both.
        seat             = if ($Declare -and $Seat) { $Seat }
                           elseif ($Prompt -and $DerivedSeat -and -not (Prior 'seat' $null)) { $DerivedSeat }
                           else { Prior 'seat' $null }
        seatSource       = if ($Declare -and $Seat) { 'declared' }
                           elseif ($Prompt -and $DerivedSeat -and -not (Prior 'seat' $null)) { 'derived:caller' }
                           else { Prior 'seatSource' $null }
        # Only a declaration is dated as one. A derived seat leaves this null on purpose, so
        # "somebody said what this seat is for" stays answerable from the record alone.
        declaredAt       = if ($Declare -and $Seat) { $now } else { Prior 'declaredAt' $null }
        goal             = if ($Declare -and $Goal) { $Goal } else { Prior 'goal' $null }
        # WHEN THE SEAT WAS LAST ASKED, and only ever set while the goal is still missing. Once a
        # goal exists the question is answered and re-stamping it would turn a silence into noise.
        # This is the field that makes an undeclared seat readable: asked-and-ignored and
        # never-asked are different failures with different fixes.
        goalPromptedAt   = if ($Prompt -and -not (Prior 'goal' $null)) { $now } else { Prior 'goalPromptedAt' $null }
        done             = if ($Declare -and $Done) { $Done } else { Prior 'done' $null }
        outOfScope       = if ($Declare -and $OutOfScope) { $OutOfScope } else { Prior 'outOfScope' $null }
        branch           = $g.branch
        upstream         = $g.upstream
        tip              = $g.tip
        mergeBase        = $g.mergeBase
        touchedPaths     = $g.touched
        unpushed         = $g.unpushed
        dirty            = $g.dirty
        stashSha         = $g.stashSha
        stashCovers      = $g.stashCovers
        claims           = @(Get-ClaimsFor -CoordDir $coord -Wt $wt -EpisodeStart $lifecycleAt)
        allocations      = @(Get-AllocationsFor -CoordDir $coord -Wt $wt -EpisodeStart $lifecycleAt)
        handoff          = $handoffObj
        predecessor      = $pred
        notes            = if ($Declare -and $Notes) { ($Notes -replace '\s+', ' ').Substring(0, [Math]::Min(2000, $Notes.Length)) } else { Prior 'notes' '' }
    }

    Write-RecordAtomic -Path $recPath -Object $rec

    # -Prompt is a hook path like -Record: it must not narrate into a session's context. What the
    # session should SEE is the prompt itself, and that is the hook's line to write, not this one's.
    if (-not $Record -and -not $Prompt) { Write-Host "wrote $recPath" }
} catch {
    Write-WriterError -Stage 'main' -Message $_.Exception.Message
    Write-Error "seat.ps1: $($_.Exception.Message)" -EA Continue
    $exit = 0
}

exit $exit
