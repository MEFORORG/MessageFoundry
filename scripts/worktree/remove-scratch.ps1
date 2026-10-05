# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Delete a scratch folder tree under the user's temp root, but only when every check says it is safe.

.DESCRIPTION
    WHY THIS EXISTS. The tracked .claude/settings.json denies `Bash(rm -rf:*)` and
    `PowerShell(Remove-Item -Recurse -Force:*)`. Those two rules are a blanket, so a session cannot
    delete even a temp folder it made a minute ago, and the owner ends up running the delete by hand.
    This script is the checked route. It leaves both rules alone.

    THE BIAS IS FIXED, in the words prune-merged.ps1 uses for itself: a false SKIP is a minor
    annoyance, a false delete destroys a session. Every check that cannot reach a confident answer
    REFUSES. No switch turns a check off.

    DRY RUN BY DEFAULT. Without -Delete it prints what would go, with a file count and a byte count,
    and one receipt line per check. Nothing on disk changes.

    SEVERAL TARGETS ARE FINE. Each is judged alone and one refusal does not stop the others. Give
    them as separate arguments. Only literal paths are taken: a wildcard is refused, because a
    pattern deletes whatever happens to match on the day it runs. Let your shell expand the pattern
    and read the dry run first.

    THE CHECKS, in the order the receipt prints them. The first refusal stops that target.

      spelling    The path must be drive-absolute and spelled plainly. Refused: a UNC or device path,
                  a relative path, a '.' or '..' component, a component ending in a dot or a space
                  (Windows drops both, so it names a different directory), an 8.3 short name, a colon
                  after the drive letter, a wildcard, a reserved device name. Forward slashes are
                  accepted.
      temp-root   Strictly inside the temp root, which is <LocalApplicationData>\Temp read from the
                  known-folder API. It is NOT read from TEMP or TMP: those are environment variables,
                  and [IO.Path]::GetTempPath() follows a forged TMP. When TEMP names any other
                  spelling the run prints a NOTE and refuses EVERY target, an 8.3 spelling of the same
                  directory included. Minimum depth is one level below the root. Under <root>\claude
                  the only deletable place is INSIDE a session scratchpad:
                  <root>\claude\<project>\<session id>\scratchpad\<name> or deeper. The scratchpad
                  directory itself, a session directory and a project directory are refused.
      exists      The target is a directory, stored under the name given. A single file is refused.
                  Letter case is not compared.
      reparse     No reparse point (junction, symbolic link, mount point, cloud placeholder) on the
                  path from the drive root down, and none anywhere inside the tree. One inside refuses
                  the whole target. The walk never follows one.
      git         Not a git checkout. Refused when the tree holds a `.git` entry at any depth, holds
                  a bare repository (HEAD, objects and refs side by side), sits inside either shape
                  anywhere between the target and the temp root, or is, holds or sits inside a
                  registered worktree. The worktrees compared are those of the repository this script
                  lives in and of every root in the worktree gate's own list
                  (<profile>\.claude\hooks\worktree-gate.repos.txt). A scratchpad worktree goes
                  through remove.ps1, never this script.
      cwd         The shell running this script is not standing in the target.
      sessions    The session registry (coord/session-registry.ps1) is read on EVERY run. If it
                  cannot look, every target is refused: no registry, no record in it, a record that
                  will not parse or carries no session id or no working directory, a listing that
                  disagrees with itself. Then three rules.
                    * No session the fence cannot rule out (LIVE, UNVERIFIED, UNREADABLE) may have its
                      working directory in the target.
                    * A target inside the CALLER's own scratchpad passes this check.
                    * A target inside ANY OTHER session's scratchpad is refused outright, whether
                      that session is live, dead or absent from the registry. A dead session can be
                      resumed, and its scratchpad is its notes.
      idle        Nothing in the tree was created or modified inside a window: 10 minutes for the
                  caller's own scratchpad, 60 minutes for everything else under the temp root.
                  Creation time counts as well as write time, because an extracted or copied tree
                  keeps old write times. A stamp in the future refuses. -IdleMinutes can raise a
                  window and never lower it.
      in-use      -Delete only. The folder is renamed to <name>.removing-<id> before anything is
                  deleted. Windows refuses that rename while any process holds a handle anywhere in
                  the tree, so a refusal here changes nothing on disk.

    WHO THE CALLER IS. The script walks its own parent-process chain and takes the nearest ancestor
    whose pid holds a LIVE registry record. That record's session id is the caller. Measured
    2026-10-04 from a Bash tool call: pwsh, three bash processes, then claude, whose pid held the
    LIVE record, and that record's id equalled the scratchpad directory name. CLAUDE_CODE_SESSION_ID
    is NOT used: any process can set it. A subagent runs inside its parent's process and shares its
    session id, so "the caller's own scratchpad" covers a whole session family. That is why the
    caller's own scratchpad still waits out a window: the caller cannot list its own workers.

    WHAT IT CANNOT SEE. At least these. State them wherever this script is recommended:
      * A folder at the top of the temp root belongs to nobody the script can name. Another session's
        `mkdtemp` folder and another program's working folder look the same. Only the 60-minute idle
        window and the rename protect them, so a program that keeps old files and holds none open
        can lose them.
      * A session that never registered, and a session that writes into the target by absolute path
        from a working directory somewhere else. occupancy.ps1 says the same of every cwd-keyed fence.
      * A session that only READS a folder. Reading leaves no creation or write stamp, and no open
        handle between reads, so a tree somebody has been reading for over an hour can go.
      * A child session with no registry record of its own. The caller walk passes over it and stops
        at its nearest registered ancestor, so it is judged as that ancestor.
      * A hard link. Deleting one name leaves the file's other names alone.

    IF A DELETE FAILS PART-WAY the script lists exactly what remains, under the renamed folder, and
    exits 3. It never deletes through a reparse point that appeared after the walk; it leaves it.

    EXIT CODES. 0 every target passed. 1 at least one target was refused, or the script itself failed
    (a bad parameter, say). 3 at least one delete was left part-done. Read the SUMMARY line for what
    was deleted: exit 1 does not mean nothing was.

    -TempRoot RE-ROOTS THE SCRIPT FOR TESTS, AND CAN ONLY NARROW IT. It must itself sit strictly
    inside the real temp root and outside <root>\claude, so a re-rooted run reaches nothing the plain
    run could not. -ConfigRoot (a fixture session registry, read INSTEAD of the real one) and
    -RepoRoot (one more repository whose worktrees are compared) work only together with -TempRoot.
    NARROW IS ABOUT REACH, AND TWO THINGS DO LOOSEN, for targets under -TempRoot only. A fixture
    registry hides the real sessions from the sessions check. And a folder laid out as
    claude\<project>\<caller's session id>\scratchpad\<name> below -TempRoot takes the 10-minute
    window. The rename still refuses a folder any process is standing in.

    See docs/WORKTREES.md, section "Deleting a scratch folder".

.EXAMPLE
    .\remove-scratch.ps1 C:\Users\me\AppData\Local\Temp\rv2747-a C:\Users\me\AppData\Local\Temp\rv2747-b
    .\remove-scratch.ps1 -Delete C:\Users\me\AppData\Local\Temp\rv2747-a
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Path,

    # Actually delete. Without it the run is a dry run.
    [switch]$Delete,

    # Raise the idle window. The window used is the larger of this and the built-in one (10 minutes
    # for the caller's own scratchpad, 60 for anything else), so a small value changes nothing.
    [ValidateRange(0, 525600)]
    [int]$IdleMinutes = 0,

    # Tests only: judge targets against this directory instead of the real temp root.
    [string]$TempRoot,

    # Tests only, with -TempRoot: a fixture session registry, read instead of the real one.
    [string]$ConfigRoot,

    # Tests only, with -TempRoot: one more repository whose registered worktrees are compared.
    [string]$RepoRoot
)

$ErrorActionPreference = 'Stop'

# Get-RepoWorktrees, ConvertTo-Norm, Test-OccupancyVeto, and the liveness fence one level down.
. "$PSScriptRoot\..\coord\occupancy.ps1"

$ReparseFlag = [IO.FileAttributes]::ReparsePoint
$DirectoryFlag = [IO.FileAttributes]::Directory
$OwnScratchpadIdleMinutes = 10
$OtherIdleMinutes = 60

# Split a caller-supplied path into components, refusing every spelling that could name a different
# directory than the one written. Nothing here touches the disk.
function Split-StrictPath([string]$Raw) {
    function No([string]$why) { return @{ Ok = $false; Why = $why } }
    if ([string]::IsNullOrWhiteSpace($Raw)) { return (No 'the path is empty') }
    $p = $Raw -replace '/', '\'
    if ($p.StartsWith('\\')) { return (No 'a UNC or device path (\\server\share, \\?\, \\.\) is refused') }
    if ($p -notmatch '\A[A-Za-z]:\\') { return (No 'the path is not drive-absolute (X:\...); a relative path depends on where the shell stands') }
    $rest = $p.Substring(3)
    if ($rest -match '[\x00-\x1f]') { return (No 'the path holds a control character') }
    if ($rest.Contains(':')) { return (No 'a colon after the drive letter is an alternate-stream spelling') }
    if ($rest -match '[*?]') { return (No 'a wildcard is refused; give literal paths') }
    if ($rest -match '[<>|"]') { return (No 'the path holds a character Windows does not allow in a name') }
    if ($rest.EndsWith('\')) { $rest = $rest.Substring(0, $rest.Length - 1) }
    if (-not $rest) { return (No 'the path is a drive root') }
    $parts = @($rest -split '\\')
    foreach ($c in $parts) {
        if ($c -eq '') { return (No 'the path holds an empty component (a doubled separator)') }
        if ($c -eq '.' -or $c -eq '..') { return (No "a '.' or '..' component is refused") }
        if ($c -match '[. ]\z') { return (No "the component '$c' ends in a dot or a space, which Windows drops, so it names a different directory") }
        if ($c -match '~\d') { return (No "the component '$c' looks like an 8.3 short name; spell the long name") }
        if ($c -match '\A(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?\z') { return (No "the component '$c' is a reserved device name") }
    }
    $drive = $p.Substring(0, 1).ToUpperInvariant() + ':\'
    $full = $drive + ($parts -join '\')
    # GetFullPath should now have nothing left to change. If it does, the spelling is not plain.
    $again = ''
    try { $again = [IO.Path]::GetFullPath($full) } catch { return (No "the path cannot be resolved: $($_.Exception.Message)") }
    if ($again -ine $full) { return (No "the path resolves to a different spelling ('$again')") }
    return @{ Ok = $true; Why = ''; Full = $full; Drive = $drive; Parts = $parts }
}

# Walk a path one component at a time from the drive root, reading each name back from its parent.
# Refuses a reparse point anywhere on the way, and a component whose stored name is not the one given.
# State is 'ok', 'missing', 'reparse', 'alias' or 'error'. Path is spelled from the STORED names.
function Resolve-TruePath([string]$Drive, [string[]]$Parts) {
    $cur = $Drive
    $leaf = $null
    foreach ($c in $Parts) {
        $hits = @()
        try { $hits = @([IO.DirectoryInfo]::new($cur).GetFileSystemInfos($c)) }
        catch { return @{ State = 'error'; Why = "could not list '$cur': $($_.Exception.Message)" } }
        if ($hits.Count -ne 1) { return @{ State = 'missing'; Why = "'$c' was not found in '$cur'" } }
        $leaf = $hits[0]
        if ($leaf.Attributes -band $ReparseFlag) { return @{ State = 'reparse'; Why = "'$($leaf.FullName)' is a reparse point" } }
        if ($leaf.Name -ine $c) { return @{ State = 'alias'; Why = "'$c' is stored as '$($leaf.Name)'; spell the stored name" } }
        $cur = Join-Path $cur $leaf.Name
    }
    return @{ State = 'ok'; Why = ''; Path = $cur; Leaf = $leaf }
}

# True when the directory listing is a bare git repository: HEAD, objects and refs side by side.
function Test-BareShape([string[]]$Names) {
    return (($Names -contains 'HEAD') -and ($Names -contains 'objects') -and ($Names -contains 'refs'))
}

# Measure a tree without ever following a reparse point. It walks EVERYTHING it may enter, so each of
# the three fault fields is the whole answer for its own check: WalkFault (a directory could not be
# listed), ReparseFault (the first reparse point inside), GitFault (the first git shape inside).
function Measure-Tree([string]$Root) {
    $r = @{
        WalkFault = ''; ReparseFault = ''; GitFault = ''
        Files = 0; Dirs = 0; Bytes = [long]0; Newest = [datetime]::MinValue; NewestPath = ''
    }
    $top = [IO.DirectoryInfo]::new($Root)
    $r.Newest = if ($top.CreationTimeUtc -gt $top.LastWriteTimeUtc) { $top.CreationTimeUtc } else { $top.LastWriteTimeUtc }
    $r.NewestPath = $Root
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $entries = @()
        try { $entries = @([IO.DirectoryInfo]::new($dir).GetFileSystemInfos()) }
        catch { $r.WalkFault = "could not list '$dir': $($_.Exception.Message)"; return $r }
        if (-not $r.GitFault -and (Test-BareShape @($entries | ForEach-Object { $_.Name }))) {
            $r.GitFault = "'$dir' holds HEAD, objects and refs, which is a git repository"
        }
        foreach ($e in $entries) {
            if ($e.Attributes -band $ReparseFlag) {
                if (-not $r.ReparseFault) { $r.ReparseFault = "'$($e.FullName)' is a reparse point inside the tree" }
                continue
            }
            if (($e.Name -ieq '.git') -and -not $r.GitFault) { $r.GitFault = "'$($e.FullName)' is a git entry inside the tree" }
            $stamp = if ($e.CreationTimeUtc -gt $e.LastWriteTimeUtc) { $e.CreationTimeUtc } else { $e.LastWriteTimeUtc }
            if ($stamp -gt $r.Newest) { $r.Newest = $stamp; $r.NewestPath = $e.FullName }
            if ($e.Attributes -band $DirectoryFlag) { $r.Dirs++; $stack.Push($e.FullName) }
            else { $r.Files++; $r.Bytes += $e.Length }
        }
    }
    return $r
}

# Delete a tree bottom-up, one entry at a time, never through a reparse point. Failures are collected
# and the walk carries on, so the caller can say exactly what is left.
function Remove-TreeNoFollow([string]$Dir, [System.Collections.Generic.List[string]]$Failures) {
    $entries = @()
    try {
        # Read again here, not only in the listing above it: the walk that cleared this tree is over.
        if ([IO.File]::GetAttributes($Dir) -band $ReparseFlag) { $Failures.Add("$Dir (a reparse point; left in place)"); return }
        $entries = @([IO.DirectoryInfo]::new($Dir).GetFileSystemInfos())
    }
    catch { $Failures.Add("$Dir (could not list: $($_.Exception.Message))"); return }
    foreach ($e in $entries) {
        if ($e.Attributes -band $ReparseFlag) { $Failures.Add("$($e.FullName) (a reparse point; left in place)"); continue }
        if ($e.Attributes -band $DirectoryFlag) { Remove-TreeNoFollow $e.FullName $Failures; continue }
        try {
            if ($e.Attributes -band [IO.FileAttributes]::ReadOnly) { [IO.File]::SetAttributes($e.FullName, [IO.FileAttributes]::Normal) }
            [IO.File]::Delete($e.FullName)
        }
        catch { $Failures.Add("$($e.FullName) ($($_.Exception.Message))") }
    }
    # Non-recursive on purpose: it fails on a directory that still holds something.
    try {
        $attrs = [IO.File]::GetAttributes($Dir)
        if ($attrs -band [IO.FileAttributes]::ReadOnly) { [IO.File]::SetAttributes($Dir, $DirectoryFlag) }
        [IO.Directory]::Delete($Dir, $false)
    }
    catch { $Failures.Add("$Dir ($($_.Exception.Message))") }
}

# Everything still under $Dir, listed without following a reparse point.
function Get-Remains([string]$Dir) {
    $out = [System.Collections.Generic.List[string]]::new()
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Dir)
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        try {
            foreach ($e in @([IO.DirectoryInfo]::new($d).GetFileSystemInfos())) {
                $out.Add($e.FullName)
                if (($e.Attributes -band $DirectoryFlag) -and -not ($e.Attributes -band $ReparseFlag)) { $stack.Push($e.FullName) }
            }
        }
        catch { $out.Add("$d (could not list: $($_.Exception.Message))") }
    }
    return $out
}

function Test-Inside([string]$Child, [string]$Parent) {
    return $Child.StartsWith($Parent.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

# --- run-wide facts: the temp root, the worktree registries, the session registry ----------------
# A fault here refuses EVERY target, because each one is a fence that could not look.
$runFault = ''
$note = @()

# The real temp root, from the known-folder API. See the header for why not TEMP.
$realRoot = ''
$local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if (-not $local) { $runFault = 'the known-folder API returned no LocalApplicationData directory' }
else {
    $rs = Split-StrictPath (Join-Path $local 'Temp')
    if (-not $rs.Ok) { $runFault = "the temp root is not plainly spelled: $($rs.Why)" }
    else {
        $rt = Resolve-TruePath $rs.Drive $rs.Parts
        if ($rt.State -ne 'ok') { $runFault = "the temp root could not be confirmed: $($rt.Why)" }
        else { $realRoot = $rt.Path }
    }
}
if (-not $runFault) {
    $envTemp = ([IO.Path]::GetTempPath() -replace '/', '\').TrimEnd('\')
    if ($envTemp -ine $realRoot) {
        $note += "NOTE: TEMP resolves to '$envTemp'. This script deletes only under '$realRoot', and it refuses every target while the two are spelled differently."
        $runFault = "TEMP resolves to '$envTemp', which is not the temp root '$realRoot'"
    }
}

$root = $realRoot
$reRooted = [bool]$TempRoot
if (-not $runFault -and $reRooted) {
    $ts = Split-StrictPath $TempRoot
    if (-not $ts.Ok) { $runFault = "-TempRoot is refused: $($ts.Why)" }
    else {
        $tt = Resolve-TruePath $ts.Drive $ts.Parts
        $claudeRoot = Join-Path $realRoot 'claude'
        if ($tt.State -ne 'ok') { $runFault = "-TempRoot is refused: $($tt.Why)" }
        elseif (-not ($tt.Leaf.Attributes -band $DirectoryFlag)) { $runFault = '-TempRoot is refused: it is not a directory' }
        elseif (-not (Test-Inside $tt.Path $realRoot)) { $runFault = "-TempRoot must sit strictly inside the real temp root '$realRoot'" }
        elseif (($tt.Path -ieq $claudeRoot) -or (Test-Inside $tt.Path $claudeRoot)) {
            $runFault = "-TempRoot may not be '$claudeRoot' or anything inside it"
        }
        else { $root = $tt.Path }
    }
}
if (-not $runFault -and -not $reRooted -and ($ConfigRoot -or $RepoRoot)) {
    $runFault = '-ConfigRoot and -RepoRoot work only together with -TempRoot'
}

# git answers for a different checkout when any of these is set.
$gitRedirects = @('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE') |
    Where-Object { [Environment]::GetEnvironmentVariable($_) }
if (-not $runFault -and $gitRedirects) {
    $runFault = "$($gitRedirects -join ', ') is set, so git would answer for a different checkout"
}

$profileDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if (-not $runFault -and -not $profileDir) { $runFault = 'the known-folder API returned no user profile directory' }

# Registered worktrees: this script's own repository, every root the worktree gate governs, and
# -RepoRoot on a re-rooted run. A repository that cannot be listed is a fence that could not look.
$worktreePaths = @()
$reposCompared = 0
if (-not $runFault) {
    $repos = @((Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath)
    $gateList = Join-Path $profileDir '.claude\hooks\worktree-gate.repos.txt'
    if (Test-Path -LiteralPath $gateList -PathType Leaf) {
        try {
            $repos += @(Get-Content -LiteralPath $gateList -ErrorAction Stop |
                    Where-Object { $_ -and $_.Trim() -and -not $_.TrimStart().StartsWith('#') } |
                    ForEach-Object { $_.Trim() })
        }
        catch { $runFault = "the worktree gate's list '$gateList' could not be read: $($_.Exception.Message)" }
    }
    if ($RepoRoot) { $repos += $RepoRoot }
    # Keyed on the shared git directory: this checkout and its primary are one repository, and listing
    # it twice costs a second `git worktree list` for the same answer.
    $seen = @{}
    foreach ($repo in $repos) {
        if ($runFault) { break }
        $key = Get-RepoCommonDir $repo
        if (-not $key) { $runFault = "'$repo' is not a git repository, so its registered worktrees cannot be listed"; break }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $listed = @(Get-RepoWorktrees $repo)
        if ($listed.Count -eq 0) { $runFault = "could not list the registered worktrees of '$repo'" }
        else { $worktreePaths += @($listed | ForEach-Object { $_.Path }); $reposCompared++ }
    }
}

# The session registry. Read once, listed a second time with -ErrorAction Stop, and the two must agree:
# Get-SessionRecords swallows a failed listing, and a failed listing must not read as an empty one.
$records = @()
$registryLine = ''
if (-not $runFault) {
    try {
        $roots = @()
        if ($ConfigRoot) {
            if (-not (Test-Path -LiteralPath (Join-Path $ConfigRoot 'sessions') -PathType Container)) {
                throw "-ConfigRoot '$ConfigRoot' holds no sessions directory"
            }
            $roots = @($ConfigRoot)
        }
        else {
            # Get-ClaudeConfigRoots reads USERPROFILE, so it has to name the real profile.
            if ("$env:USERPROFILE".TrimEnd('\') -ine $profileDir.TrimEnd('\')) {
                throw "USERPROFILE ('$env:USERPROFILE') is not the profile directory ('$profileDir'), so the registry would be read from the wrong place"
            }
            $roots = @(Get-ClaudeConfigRoots)
            # A config root outside the profile would hold this very session's record, unseen.
            $cfg = $env:CLAUDE_CONFIG_DIR
            if ($cfg -and (Test-Path -LiteralPath (Join-Path $cfg 'sessions')) -and
                -not ($roots | Where-Object { (ConvertTo-Norm $_) -eq (ConvertTo-Norm $cfg) })) {
                throw "CLAUDE_CONFIG_DIR ('$cfg') holds a session registry outside the profile's .claude* directories"
            }
        }
        if ($roots.Count -eq 0) { throw 'no config root with a session registry was found' }
        $listed = 0
        foreach ($r in $roots) {
            $listed += @(Get-ChildItem -LiteralPath (Join-Path $r 'sessions') -Filter *.json -File -Force -ErrorAction Stop).Count
        }
        $all = @(Get-SessionRecords -ConfigRoot $roots -IncludeUnreadable)
        if ($all.Count -ne $listed) { throw "the registry read returned $($all.Count) record(s) and a second listing found $listed" }
        if ($all.Count -eq 0) { throw "$($roots.Count) config root(s) examined, but not one session record in them" }
        $bad = @($all | Where-Object { $_.Unreadable -or -not $_.Record.sessionId -or -not $_.Record.cwd })
        if ($bad.Count -gt 0) {
            throw "$($bad.Count) session record(s) could not be read, or carry no session id or no working directory, so no session can be ruled out: $(($bad | ForEach-Object { $_.File }) -join '; ')"
        }
        foreach ($e in $all) {
            $live = $null
            try { $live = Test-RecordLiveness -Record $e.Record }
            catch { $live = @{ State = 'UNREADABLE'; Detail = "record could not be fenced: $($_.Exception.Message)" } }
            $recPid = 0
            try { $recPid = [int]$e.Record.pid } catch { $recPid = 0 }
            $records += [pscustomobject]@{
                Sid = [string]$e.Record.sessionId; Pid = $recPid; State = $live.State
                CwdNorm = (ConvertTo-Norm ([string]$e.Record.cwd)); Veto = (Test-OccupancyVeto $live.State)
            }
        }
        $registryLine = "$($roots.Count) root(s), $($records.Count) record(s), $(@($records | Where-Object Veto).Count) not ruled out"
    }
    catch { $runFault = "the session registry could not be read: $($_.Exception.Message)" }
}

# The caller: the nearest ancestor process whose pid holds exactly one LIVE record. An ancestor that
# started AFTER its child is a recycled pid, so the walk stops there. A failure to walk leaves the
# caller unknown, which only ever refuses more.
$callerSid = ''
$callerPid = 0
if (-not $runFault) {
    try {
        $p = Get-Process -Id $PID
        for ($i = 0; $i -lt 24 -and $p; $i++) {
            $hit = @($records | Where-Object { $_.Pid -eq $p.Id -and $_.State -eq 'LIVE' })
            if ($hit.Count -eq 1) { $callerSid = $hit[0].Sid; $callerPid = $p.Id; break }
            if ($hit.Count -gt 1) { break }
            $parent = $p.Parent
            if (-not $parent -or $parent.StartTime -gt $p.StartTime) { break }
            $p = $parent
        }
    }
    catch { $callerSid = ''; $callerPid = 0 }
}

$sidPattern = '\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z'
$checkNames = @('spelling', 'temp-root', 'exists', 'reparse', 'git', 'cwd', 'sessions', 'idle', 'in-use')

# Run the checks for one target, in order, writing each result into $receipt and the verdict into $out.
function Invoke-Checks([string]$Raw, $receipt, $out) {
    function Fail([string]$check, [string]$why) { $receipt[$check] = "REFUSED $why" }

    if ($runFault) { Fail 'run' $runFault; return }

    $s = Split-StrictPath $Raw
    if (-not $s.Ok) { Fail 'spelling' $s.Why; return }
    $full = $s.Full
    $out.Full = $full
    $receipt['spelling'] = 'PASS plain drive-absolute path'

    if ($full -ieq $root) { Fail 'temp-root' 'the target is the temp root itself'; return }
    if (-not (Test-Inside $full $root)) { Fail 'temp-root' "the target is not inside the temp root '$root'"; return }
    $rel = @($full.Substring($root.Length + 1) -split '\\')
    $ownerSid = ''
    if ($rel[0] -ieq 'claude') {
        if ($rel.Count -lt 5 -or $rel[3] -ine 'scratchpad') {
            Fail 'temp-root' "under '$root\claude' only the inside of a session scratchpad is deletable (claude\<project>\<session id>\scratchpad\<name>)"
            return
        }
        if ($rel[2] -notmatch $sidPattern) { Fail 'temp-root' "'$($rel[2])' is not a session id, so the owner of this scratchpad cannot be looked up"; return }
        $ownerSid = $rel[2]
    }
    $receipt['temp-root'] = "PASS inside '$root', $($rel.Count) level(s) down"

    $t = Resolve-TruePath $s.Drive $s.Parts
    if ($t.State -eq 'missing') { Fail 'exists' $t.Why; return }
    if ($t.State -eq 'reparse') { $receipt['exists'] = 'not decided'; Fail 'reparse' "on the path: $($t.Why)"; return }
    if ($t.State -ne 'ok') { Fail 'exists' $t.Why; return }
    if (-not ($t.Leaf.Attributes -band $DirectoryFlag)) { Fail 'exists' 'the target is a file; this script deletes folder trees only'; return }
    # From here on the path is the one spelled from the stored names.
    $full = $t.Path
    $out.Full = $full
    $receipt['exists'] = 'PASS a directory, stored under the name given'

    $tree = Measure-Tree $full
    if ($tree.WalkFault) { Fail 'reparse' "the tree could not be walked: $($tree.WalkFault)"; return }
    if ($tree.ReparseFault) { Fail 'reparse' $tree.ReparseFault; return }
    $receipt['reparse'] = 'PASS none on the path, none in the tree'

    if ($tree.GitFault) { Fail 'git' $tree.GitFault; return }
    # A checkout that starts between the target and the real temp root, the root included. Above the
    # temp root is not this script's business: the temp root is disposable whatever sits over it.
    $up = Split-Path $full -Parent
    while ($up -and (($up -ieq $realRoot) -or (Test-Inside $up $realRoot))) {
        $names = @()
        try { $names = @([IO.DirectoryInfo]::new($up).GetFileSystemInfos() | ForEach-Object { $_.Name }) }
        catch { Fail 'git' "could not look for a git checkout at '$up': $($_.Exception.Message)"; return }
        if ($names -contains '.git') { Fail 'git' "the target sits inside the git checkout at '$up'"; return }
        if (Test-BareShape $names) { Fail 'git' "the target sits inside the bare git repository at '$up'"; return }
        $up = Split-Path $up -Parent
    }
    $norm = ConvertTo-Norm $full
    foreach ($w in $worktreePaths) {
        $wn = ConvertTo-Norm $w
        if ($wn -eq $norm -or $wn.StartsWith("$norm/") -or $norm.StartsWith("$wn/")) {
            Fail 'git' "the registered worktree '$w' is, holds or sits inside the target; use remove.ps1 for a worktree"
            return
        }
    }
    $receipt['git'] = "PASS no git entry at any depth, no checkout above it, $($worktreePaths.Count) registered worktree(s) of $reposCompared repositor$(if ($reposCompared -eq 1) { 'y' } else { 'ies' }) compared"

    foreach ($here in @($PWD.ProviderPath, [Environment]::CurrentDirectory)) {
        $hn = ConvertTo-Norm $here
        if ($hn -eq $norm -or $hn.StartsWith("$norm/")) { Fail 'cwd' "the shell running this script is standing in the target ('$here')"; return }
    }
    $receipt['cwd'] = 'PASS'

    $inCwd = @($records | Where-Object { $_.Veto -and ($_.CwdNorm -eq $norm -or $_.CwdNorm.StartsWith("$norm/")) })
    if ($inCwd.Count -gt 0) {
        Fail 'sessions' "$($inCwd.Count) session(s) the fence cannot rule out have their working directory in the target: $(($inCwd | ForEach-Object { "$($_.State) $($_.Sid) pid $($_.Pid)" }) -join '; ')"
        return
    }
    $sessionNote = "registry $registryLine; no session's working directory is in the target"
    $window = $OtherIdleMinutes
    if ($ownerSid) {
        if (-not $callerSid) {
            Fail 'sessions' "the target is in the scratchpad of session $ownerSid, and no ancestor of this process holds a LIVE session record, so the script cannot show the scratchpad is the caller's own"
            return
        }
        if ($ownerSid -ine $callerSid) {
            $owners = @($records | Where-Object { $_.Sid -ieq $ownerSid })
            $state = if ($owners.Count -gt 0) { ($owners | ForEach-Object { "$($_.State) pid $($_.Pid)" }) -join '; ' } else { 'no registry record' }
            Fail 'sessions' "the target is in the scratchpad of session $ownerSid ($state), and the caller is session $callerSid. Another session's scratchpad is never deleted, live or not: a dead session can be resumed"
            return
        }
        $sessionNote += "; the scratchpad is the caller's own (ancestor pid $callerPid holds the LIVE record for $callerSid)"
        $window = $OwnScratchpadIdleMinutes
    }
    $receipt['sessions'] = "PASS $sessionNote"

    if ($IdleMinutes -gt $window) { $window = $IdleMinutes }
    $age = ([datetime]::UtcNow - $tree.Newest).TotalMinutes
    if ($age -lt $window) {
        $ageText = if ($age -lt 0) { 'in the future' } else { "$([int][Math]::Floor($age)) minute(s) ago" }
        Fail 'idle' "'$($tree.NewestPath)' was created or modified $ageText, inside the $window-minute window"
        return
    }
    $receipt['idle'] = "PASS newest entry is $([int][Math]::Floor($age)) minute(s) old, window $window"

    $out.Ok = $true
    $out.Tree = $tree
}

# Judge one target. Returns the receipt and, when every check passed, the measured tree. A check that
# THROWS has not reached a confident answer, so it refuses this target and the run goes on to the next.
function Test-Target([string]$Raw) {
    $receipt = [ordered]@{}
    $out = @{ Receipt = $receipt; Ok = $false; Full = $Raw; Tree = $null }
    try { Invoke-Checks $Raw $receipt $out | Out-Null }
    catch {
        $out.Ok = $false
        $out.Tree = $null
        $receipt['error'] = "REFUSED a check threw, so it reached no answer: $($_.Exception.Message)"
    }
    return $out
}

$mode = if ($Delete) { 'delete' } else { 'dry-run' }
Write-Host "remove-scratch: mode=$mode temp-root='$root'$(if ($reRooted) { ' (RE-ROOTED by -TempRoot)' }) targets=$($Path.Count)"
$note | ForEach-Object { Write-Host $_ }

$counts = @{ deleted = 0; would = 0; refused = 0; partial = 0 }
foreach ($raw in $Path) {
    Write-Host ''
    Write-Host "TARGET $raw"
    $res = Test-Target $raw
    $receipt = $res.Receipt
    $verdict = ''
    $failures = [System.Collections.Generic.List[string]]::new()
    $remains = @()
    $size = if ($res.Tree) { "$($res.Tree.Files) file(s), $($res.Tree.Dirs) folder(s), $($res.Tree.Bytes) byte(s)" } else { '' }

    if ($res.Ok -and $Delete) {
        # The handle test and the delete share one act: rename first, then delete the renamed tree.
        $tomb = "$($res.Full).removing-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
        $renamed = $false
        if (Test-Path -LiteralPath $tomb) { $receipt['in-use'] = "REFUSED '$tomb' already exists" }
        else {
            try { [IO.Directory]::Move($res.Full, $tomb); $renamed = $true }
            catch { $receipt['in-use'] = "REFUSED the folder could not be renamed, so something holds a handle inside it or it cannot be changed: $($_.Exception.Message)" }
        }
        if ($renamed) {
            $receipt['in-use'] = "PASS renamed to '$tomb' with no handle open inside"
            Remove-TreeNoFollow $tomb $failures
            if (Test-Path -LiteralPath $tomb) {
                $remains = @(Get-Remains $tomb)
                $verdict = "PARTIAL $($res.Full): the delete stopped part-way. The tree was renamed to '$tomb' and $($remains.Count) entr$(if ($remains.Count -eq 1) { 'y remains' } else { 'ies remain' }) under it."
                $counts.partial++
            }
            else {
                $verdict = "DELETED $($res.Full): $size"
                $counts.deleted++
            }
        }
    }
    elseif ($res.Ok) {
        $receipt['in-use'] = 'NOT TESTED in a dry run (-Delete renames the folder first and refuses if anything holds a handle in it)'
        $verdict = "WOULD DELETE $($res.Full): $size. Dry run; re-run with -Delete."
        $counts.would++
    }

    foreach ($c in @('run', 'error')) {
        if ($receipt.Contains($c)) { Write-Host "  ${c}: $($receipt[$c])" }
    }
    foreach ($c in $checkNames) {
        $v = if ($receipt.Contains($c)) { $receipt[$c] } else { 'not run (an earlier check refused)' }
        Write-Host "  ${c}: $v"
    }
    if (-not $verdict) {
        $first = @($receipt.Keys | Where-Object { $receipt[$_] -like 'REFUSED*' })[0]
        $verdict = "REFUSED $($res.Full): ${first}: $($receipt[$first] -replace '\AREFUSED ', ''). Nothing was deleted."
        $counts.refused++
    }
    Write-Host $verdict
    if ($verdict -like 'PARTIAL*') {
        $failures | ForEach-Object { Write-Host "  failed: $_" }
        $remains | ForEach-Object { Write-Host "  remains: $_" }
    }
}

Write-Host ''
Write-Host "SUMMARY mode=$mode targets=$($Path.Count) deleted=$($counts.deleted) would-delete=$($counts.would) refused=$($counts.refused) partial=$($counts.partial)"
if ($counts.partial -gt 0) { exit 3 }
if ($counts.refused -gt 0) { exit 1 }
exit 0
