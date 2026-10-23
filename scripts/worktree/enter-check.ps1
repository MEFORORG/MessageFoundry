# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Does the worktree at -Path look safe for this session to enter? An advisory verdict (ADR 0212).

.DESCRIPTION
    Read-only. Prints `SAFE` or `UNSAFE` as its first stdout line, then the reasons, one per line,
    and exits 0 for SAFE and 1 for UNSAFE. When this machine's OFF file exists it prints `OFF`,
    runs no check, and exits 2. scripts/hooks/enter-worktree-check.ps1 runs it before an
    EnterWorktree call and shows the verdict in the owner's permission prompt.

    THE VERDICT IS ADVICE, NEVER A PERMISSION. This script runs from the session's own editable
    tree, so the session could change what it prints; nothing may allow a call on its word.

    IT FAILS CLOSED. The verdict starts false and is set only by the last statement of the checks,
    and only when every one of the six checks below recorded its own pass. A check that throws,
    times out, or is skipped because an earlier one failed records no pass. Every child process
    is bounded by -BudgetSeconds as well as its own timeout. The in-process reads (path
    canonicalisation, Test-Path) are not, so a stalled volume runs into the hook's settings timeout.

    SAFE requires ALL of:

      a. The path canonicalises: full path, every junction and symlink along it resolved to its
         final target, every segment present on disk under the name given (so an 8.3 short name
         is refused, not expanded). A `\\?\`, `\\.\`, UNC, relative, drive-relative (`C:x`) or
         root-relative (`\x`) path is refused outright, never joined to a directory.
      b. It is a LINKED worktree (never the primary) listed by `git worktree list --porcelain -z`
         of one of the fleet repositories (-FleetRepos), compared canonical to canonical.
      c. It is under THIS session's own scratchpad, by segments:
         <temp>\claude\<one project segment>\<SessionId>\scratchpad\<at least one more>.
         `.claude/worktrees/` is never allowed: another session's subagent trees live there, and
         nothing here can tell whose they are. The path given must already be canonical: one
         through a link is refused, because the session can repoint its own link afterwards.
      d. The session neither is nor was launched in the primary checkout of a fleet repository.
         Rule 4 of scripts/hooks/worktree_gate.ps1 exists because relocating out of the primary
         re-files the chat transcript, so that case reads UNSAFE. Two reads, because a `cd`
         moves the cwd: -SessionCwd, where the session is now, and the project directory of
         -TranscriptPath, which is where the transcript is filed. Only an exact match with a
         primary's slug counts (a slug maps a separator and a `-` alike), so a session launched
         in a primary's SUBDIRECTORY is caught only while its cwd stays in that primary. The
         transcript's own records are not read: a desktop-app worktree session records the
         primary as its first `cwd` while its transcript is filed under the worktree's slug.
      e. The worktree is not locked, its `.git` file names its own admin dir under the
         repository's `worktrees/` (and that dir names it back), and that dir shows no rebase,
         merge, cherry-pick, revert, sequencer or bisect in progress.
      f. Its HEAD is a commit of the remote's `main`: an ancestor of, or equal to, the commit
         `git ls-remote <pinned URL> refs/heads/main` names (-FleetRemotes), read with no
         repository and no user or system config. Never a local ref, and never `origin`: both
         live in the clone's shared state, which any session can write. So every tracked file,
         settings, hook code and instructions alike, is one that merged. The same shared state
         may not stand in for an object either: replace refs and the commit-graph are off, an
         `info/grafts` file fails f, and the HEAD the verified admin dir names must be the one
         git listed, before and after the reads. Its working tree matches HEAD up to git's
         line-ending conversion: no tracked path carries a filter, ident or
         working-tree-encoding attribute, every tracked file's on-disk content, hashed through
         the eol conversion git applies on add, equals its HEAD blob (a stat-cache read alone
         can be fooled; a file that differs only in its line endings passes), no index entry is flagged assume-unchanged or skip-worktree, nothing is
         modified or untracked, and no ignored file sits where the harness reads settings or
         instructions (`.claude`, `.mcp.json`, `CLAUDE.md`, `CLAUDE.local.md`, at any depth and
         in any case). Ignored means ignored by the tree's own `.gitignore` files, never by
         `info/exclude` or `core.excludesFile`. The tree holds no symlink or submodule.

    Every line printed goes through Get-SafeForMessage, loaded from worktree_gate.ps1's own
    definition (parsed, never copied), because a path or a git message is attacker-choosable text.

    TO SILENCE IT (ADR 0212):
      * this machine only: create the OFF file, which the hook reads as no verdict at all. Put
        this machine's name for <HOST>. A failed git call stops before New-Item, which would
        otherwise create the file at the drive root and report success:
            if ([Environment]::MachineName -ne '<HOST>') { Write-Host "STOP     this must run on <HOST>, but this is $([Environment]::MachineName); nothing ran" } else {
                $common = git -C D:/Code/MessageFoundry rev-parse --path-format=absolute --git-common-dir
                if ($LASTEXITCODE -ne 0 -or -not $common) { Write-Host "STOP     git did not name the engine's git common dir; nothing ran" }
                else { New-Item -ItemType File -Force -Path (Join-Path $common 'mefor-coord/enter-check/OFF') }
            }
        and delete that file to turn it back on;
      * permanently: remove the EnterWorktree entry from .claude/settings.json.

.PARAMETER BudgetSeconds
    The bound on the run's child processes. Every child is killed at its own timeout or at this
    budget, whichever comes first, and none starts once it is spent. 40 s plus pwsh's start-up
    stays under the 60 s timeout the settings entry gives the hook, unless an in-process read
    (a directory enumeration or Test-Path on a stalled volume) holds the run past it.

.PARAMETER FleetRepos
    The fleet repositories. The FIRST is the engine, whose git common dir holds the OFF file. The
    hook passes none, so the defaults apply; tests pass their own.

.PARAMETER FleetRemotes
    Each fleet repository's remote URL, paired with -FleetRepos by position. Check f reads main
    from this URL, never from the clone's `origin`. A repository with no URL here fails f.

.PARAMETER TempRoot
    The directory that holds `claude\<project>\<session>\scratchpad`. Defaults to the temp
    directory in the order Node's os.tmpdir() reads it (TEMP, then TMP, on Windows; TMPDIR, TMP,
    TEMP elsewhere), which is where the harness puts a session's scratchpad. .NET's own
    GetTempPath prefers TMP, so it can name another directory. A TEMP spelled with an 8.3 short
    name fails check c, so the verdict reads UNSAFE.

.PARAMETER TranscriptPath
    The hook input's `transcript_path`. With none, check d fails.
#>
param(
    [string]$Path,
    [string]$SessionId,
    [string]$SessionCwd = (Get-Location).ProviderPath,
    [string[]]$FleetRepos = @('D:/Code/MessageFoundry', 'D:/Code/MessageFoundry-vault', 'D:/Code/korus'),
    [string[]]$FleetRemotes = @('https://github.com/MEFORORG/MessageFoundry.git', 'https://github.com/MEFORORG/MessageFoundry-vault.git', 'https://github.com/MEFORORG/korus.git'),
    [string]$TempRoot = $(@(if ($IsWindows) { $env:TEMP; $env:TMP } else { $env:TMPDIR; $env:TMP; $env:TEMP }
            [System.IO.Path]::GetTempPath()) | Where-Object { $_ } | Select-Object -First 1),
    [string]$TranscriptPath,
    [ValidateRange(1, 120)][int]$RemoteTimeoutSeconds = 20,
    [ValidateRange(1, 45)][int]$BudgetSeconds = 40
)

$safe = $false
# Monotonic, so a wall-clock step cannot stretch or cut the budget.
$budgetWatch = [System.Diagnostics.Stopwatch]::StartNew()
function Get-BudgetLeftMs { [Math]::Max(0, $BudgetSeconds * 1000 - $script:budgetWatch.ElapsedMilliseconds) }
$budgetSpent = "the check's $BudgetSeconds s budget ran out"
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$failures = [System.Collections.Generic.List[string]]::new()
$passed = [System.Collections.Generic.HashSet[string]]::new()
function Add-Failure([string]$Check, [string]$Why) { $failures.Add("$Check. $Why") }

# A git child inherits none of this process's git variables but three. GIT_DIR and its kin would
# redirect `git -C` at another repository than the one named. GIT_EXEC_PATH, GIT_SSH_COMMAND,
# GIT_TRACE*, GIT_SSL_NO_VERIFY and GIT_SSL_CAINFO would choose what runs, where output goes, or
# which server is trusted. So every GIT_* name goes, except the three that say where this
# machine's own config lives: a `safe.directory` there is what lets git read a clone at all.
# The remote read overrides two of them with its isolated config, and GIT_CONFIG_NOSYSTEM=1 makes
# the third moot. The OpenSSL names go as well: they are not GIT_* but pick the trusted roots, the
# config or the loadable modules all the same. CURL_CA_BUNDLE is read by the curl tool, not by
# libcurl, and goes anyway because it costs nothing. The proxy names stay. A proxy carries the
# remote read's TLS but cannot forge it while verification holds, and a machine behind one could
# not reach the remote at all without them.
$gitEnvKeep = @('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM')
$caEnvStrip = @('SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES')
# Set on every git child. Without it, a promisor remote written into the clone's shared config
# would let a lookup of a missing object (f's cat-file and merge-base) fetch it, and that fetch
# runs the remote's upload-pack, a command any session can choose. Git before 2.44 ignores the
# variable, so the `--no-lazy-fetch` option goes on every argv too: an older git rejects it and
# exits non-zero, and the check fails closed.
$gitEnvSet = @{ GIT_NO_LAZY_FETCH = '1' }

function Start-Child {
    # A git child, the only kind this script starts, with argv passed as a list (no quoting to
    # get wrong) and UTF-8 output. The hardening is unconditional, so no call can skip it.
    param([string]$Exe, [string[]]$ArgList, [string]$StdinText, [hashtable]$SetEnv)
    if ((Get-BudgetLeftMs) -le 0) { throw "$Exe was not started: $budgetSpent" }
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
    $psi.ArgumentList.Add('--no-lazy-fetch')
    foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardInputEncoding = [System.Text.UTF8Encoding]::new($false)
    $names = @($psi.Environment.Keys | Where-Object {
            ($_.StartsWith('GIT_', [System.StringComparison]::OrdinalIgnoreCase) -and $_ -notin $gitEnvKeep) -or $_ -in $caEnvStrip })
    foreach ($v in $names) { [void]$psi.Environment.Remove($v) }
    foreach ($k in $gitEnvSet.Keys) { $psi.Environment[$k] = $gitEnvSet[$k] }
    if ($SetEnv) { foreach ($k in $SetEnv.Keys) { $psi.Environment[$k] = [string]$SetEnv[$k] } }
    $p = [System.Diagnostics.Process]::Start($psi)
    # Readers first, so a child that answers as it reads cannot fill its pipe and stall the write.
    $child = [pscustomobject]@{ Process = $p; Name = (Split-Path -Leaf $Exe); Out = $p.StandardOutput.ReadToEndAsync(); Err = $p.StandardError.ReadToEndAsync(); Write = $null }
    # The input is written asynchronously and waited on inside Wait-Child's bound: a child that
    # never reads it would otherwise block a plain write here, outside any timeout, once the pipe fills.
    if ($StdinText) { $child.Write = $p.StandardInput.WriteAsync($StdinText) }
    else { $p.StandardInput.Close() }
    $child
}

function Wait-Child($Child, [int]$TimeoutSeconds = 30) {
    # The child's exit code and output. A child still running at its bound, or at the run's
    # budget, is killed and this throws.
    $p = $Child.Process
    try {
        $allowMs = [long]$TimeoutSeconds * 1000
        $bound = "did not finish within $TimeoutSeconds s"
        if ((Get-BudgetLeftMs) -lt $allowMs) { $allowMs = Get-BudgetLeftMs; $bound = "was stopped: $budgetSpent" }
        $waited = [System.Diagnostics.Stopwatch]::StartNew()
        $left = { [int][Math]::Max(0, $allowMs - $waited.ElapsedMilliseconds) }
        $done = $true
        if ($Child.Write) {
            $done = $Child.Write.Wait((& $left))
            if ($done) { $p.StandardInput.Close() }
        }
        # The output is read to its end too, inside the same bound: a grandchild left running
        # holds the pipe open after the child itself has exited.
        $done = $done -and $p.WaitForExit((& $left)) -and
        [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($Child.Out, $Child.Err), (& $left))
        if (-not $done) { throw "$($Child.Name) $bound" }
        $p.WaitForExit()
        return [pscustomobject]@{ Code = $p.ExitCode; Out = $Child.Out.Result; Err = $Child.Err.Result }
    }
    catch {
        # Whatever stopped the wait, a timeout or a failed write, the child's tree is killed.
        # Unconditional: a child that has exited can leave a grandchild holding its pipes, and on
        # Windows Kill($true) still reaches it then. On Linux and macOS it does not, since .NET
        # stops at a child that has exited and the grandchild is reparented, so it can outlive the run.
        try { $p.Kill($true) } catch { Write-Verbose "kill failed: $($_.Exception.Message)" }
        throw
    }
    finally { $p.Dispose() }
}

# git by its resolved path: a bare name given to CreateProcess is looked for in the current
# directory before PATH (scripts/worktree/install-gate.ps1 records it), and PowerShell's own command
# lookup never searches the current directory.
# Resolved at first use, inside a check, so a machine with no git fails that check.
$gitExe = $null

function Invoke-Git([string]$Repo, [string[]]$GitArgs, [string]$StdinText, [int]$TimeoutSeconds = 15) {
    if (-not $script:gitExe) { $script:gitExe = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    # The clone's shared state is writable by every session, so none of it may stand in for an
    # object: a replace ref swaps a commit's content and a commit-graph can lie about parents.
    # The untracked cache sits in the index, which the worktree's owner writes.
    $argv = @('-C', $Repo, '--no-replace-objects', '-c', 'core.commitGraph=false', '-c', 'core.untrackedCache=false',
        '-c', 'core.fsmonitor=false', '-c', 'core.quotePath=off', '--no-optional-locks') + $GitArgs
    Wait-Child (Start-Child -Exe $gitExe -ArgList $argv -StdinText $StdinText) -TimeoutSeconds $TimeoutSeconds
}

function Get-RemoteMain([string]$Url, [int]$TimeoutSeconds) {
    # The commit the pinned URL's main names, read with no repository and no user or system
    # config: `origin`, `url.*.insteadOf`, `core.sshCommand` and a ProgramData config are all
    # writable by a session, and each could point the read at a remote the session controls.
    if (-not $script:gitExe) { $script:gitExe = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    $isolated = @{
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL   = $(if ($IsWindows) { 'NUL' } else { '/dev/null' })
        GIT_DIR             = (Join-Path ([System.IO.Path]::GetTempPath()) "enter-check-no-repo-$([guid]::NewGuid().ToString('N'))")
        GIT_TERMINAL_PROMPT = '0'
        GCM_INTERACTIVE     = 'never'
    }
    $argv = @('-c', 'credential.helper=', '-c', 'credential.helper=manager', 'ls-remote', '--exit-code', $Url, 'refs/heads/main')
    $ls = Wait-Child (Start-Child -Exe $gitExe -SetEnv $isolated -ArgList $argv) -TimeoutSeconds $TimeoutSeconds
    if ($ls.Code -ne 0) { throw "git ls-remote of the pinned remote failed (exit $($ls.Code))" }
    $ids = @($ls.Out.Split("`n") | Where-Object { $_ -cmatch '^([0-9a-f]{40}|[0-9a-f]{64})\trefs/heads/main$' } | ForEach-Object { $_.Split("`t")[0] })
    if ($ids.Count -ne 1) { throw 'the remote names no single main commit' }
    return $ids[0]
}


$nameCmp = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }

function Split-PathSegments([string]$Full) {
    $root = [System.IO.Path]::GetPathRoot($Full)
    $segs = @($Full.Substring($root.Length).Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
    [pscustomobject]@{ Root = $root; Segs = $segs }
}

# One directory lookup per (directory, segment) per run: the fleet's worktree lists share their
# leading directories, and every listed worktree is canonicalised for check b.
$segmentCache = [System.Collections.Generic.Dictionary[string, System.IO.FileSystemInfo]]::new([System.StringComparer]::Ordinal)

function Find-Segment([string]$Dir, [string]$Seg) {
    $key = "$Dir`0$Seg"
    $hit = $null
    if ($segmentCache.TryGetValue($key, [ref]$hit)) { return $hit }
    $found = @(foreach ($e in [System.IO.DirectoryInfo]::new($Dir).EnumerateFileSystemInfos($Seg)) {
            if ([string]::Equals($e.Name, $Seg, $nameCmp)) { $e }
        })
    if ($found.Count -ne 1) { throw 'a path segment is not on disk under that name (missing, or an 8.3 short name)' }
    $segmentCache[$key] = $found[0]
    return $found[0]
}

function Resolve-Canonical([string]$Raw) {
    <#
      The final on-disk path: every segment as the directory lists it, every link replaced by its
      final target and re-walked from the root (a target may itself sit under a link). Throws on
      anything it cannot canonicalise, which every caller treats as a failed check.
    #>
    if ([string]::IsNullOrWhiteSpace($Raw)) { throw 'no path given' }
    if ($Raw -match '^[\\/]{2}') { throw 'a \\?\, \\.\ or UNC path is refused' }
    # `C:x` and `\x` are rooted but not fully qualified: they resolve against this process's
    # current drive or directory, which need not be the session's.
    if (-not [System.IO.Path]::IsPathFullyQualified($Raw)) { throw 'a path that is not fully qualified is refused' }
    $full = [System.IO.Path]::GetFullPath($Raw)
    for ($hop = 0; $hop -lt 40; $hop++) {
        $split = Split-PathSegments $full
        $root = $split.Root
        if (-not $root -or $root -match '^[\\/]{2}') { throw 'a path with no local root is refused' }
        $cur = if ($IsWindows) { $root.ToUpperInvariant() } else { $root }
        $segs = $split.Segs
        $relinked = $false
        for ($i = 0; $i -lt $segs.Count; $i++) {
            $seg = $segs[$i]
            if ($seg.IndexOfAny([char[]]'*?<>"') -ge 0) { throw 'a path segment holds a wildcard character' }
            if ($IsWindows -and $seg.Contains(':')) { throw 'a path segment holds a colon (an alternate data stream)' }
            $item = Find-Segment $cur $seg
            $cur = $item.FullName
            if ($null -ne $item.LinkTarget) {
                $target = $item.ResolveLinkTarget($true)
                if ($null -eq $target -or -not $target.Exists) { throw 'a link along the path has no existing target' }
                $rest = if ($i + 1 -lt $segs.Count) { $segs[($i + 1)..($segs.Count - 1)] } else { @() }
                # Typed, or PowerShell hands Join the whole array as ONE space-joined string.
                $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Join([string[]](@($target.FullName) + $rest)))
                $relinked = $true
                break
            }
        }
        if (-not $relinked) { return $cur }
    }
    throw 'more than 40 links along the path'
}

function Test-SamePath([string]$A, [string]$B) {
    if (-not $A -or -not $B) { return $false }
    return [string]::Equals($A, $B, $nameCmp)
}

function Test-AtOrUnder([string]$Child, [string]$Parent) {
    if (Test-SamePath $Child $Parent) { return $true }
    $c = Split-PathSegments $Child
    $p = Split-PathSegments $Parent
    if (-not (Test-SamePath $c.Root $p.Root) -or $c.Segs.Count -le $p.Segs.Count) { return $false }
    for ($i = 0; $i -lt $p.Segs.Count; $i++) { if (-not [string]::Equals($c.Segs[$i], $p.Segs[$i], $nameCmp)) { return $false } }
    return $true
}

function Get-WorktreeList([string]$Repo) {
    # Blocks of `git worktree list --porcelain -z`; the first is the primary.
    $r = Invoke-Git $Repo @('worktree', 'list', '--porcelain', '-z')
    if ($r.Code -ne 0) { throw "git worktree list failed in $Repo (exit $($r.Code))" }
    $blocks = [System.Collections.Generic.List[object]]::new()
    $cur = $null
    foreach ($tok in $r.Out.Split([char]0)) {
        if ($tok -eq '') { $cur = $null; continue }
        if ($tok.StartsWith('worktree ')) {
            $cur = [pscustomobject]@{ Path = $tok.Substring(9); Head = ''; Locked = $false; Canon = $null; CanonError = ''; Primary = ($blocks.Count -eq 0) }
            $blocks.Add($cur)
            continue
        }
        if ($null -eq $cur) { throw "git worktree list printed an attribute outside a block in $Repo" }
        if ($tok.StartsWith('HEAD ')) { $cur.Head = $tok.Substring(5) }
        elseif ($tok -eq 'locked' -or $tok.StartsWith('locked ')) { $cur.Locked = $true }
    }
    foreach ($b in $blocks) {
        # A listed path that no longer exists (prunable) can match nothing. One that exists and
        # will not canonicalise is recorded, and checks b and d fail on it.
        if (-not (Test-Path -LiteralPath $b.Path)) { continue }
        try { $b.Canon = Resolve-Canonical $b.Path }
        catch { $b.CanonError = $_.Exception.Message }
    }
    return $blocks
}

function Get-Slug([string]$Dir) {
    # The harness's project directory name for a launch directory: every character but an ASCII
    # letter or digit becomes '-'.
    $Dir.TrimEnd('\', '/') -replace '[^A-Za-z0-9]', '-'
}

function Get-VerifiedGitDir([string]$Repo, [string]$Worktree) {
    # The worktree's admin dir, read from its `.git` file and accepted only when it sits in the
    # repository's own `worktrees/` and its `gitdir` file names this worktree back. Throws otherwise.
    $c = Invoke-Git $Repo @('rev-parse', '--path-format=absolute', '--git-common-dir')
    if ($c.Code -ne 0 -or -not $c.Out.Trim()) { throw "the git common dir of $Repo could not be read" }
    $common = Resolve-Canonical $c.Out.Trim()
    $dotGit = Join-Path $Worktree '.git'
    if (-not (Test-Path -LiteralPath $dotGit -PathType Leaf)) { throw 'its .git is not a file' }
    $line = [string](Get-Content -LiteralPath $dotGit -TotalCount 1)
    if ($line -notmatch '^gitdir:\s*(.+?)\s*$') { throw 'its .git file names no gitdir' }
    $named = $Matches[1]
    if (-not [System.IO.Path]::IsPathRooted($named)) { $named = Join-Path $Worktree $named }
    $gd = Resolve-Canonical $named
    if (-not (Test-SamePath (Split-Path -Parent $gd) (Join-Path $common 'worktrees'))) { throw "its .git file names $gd, outside $common/worktrees" }
    $back = Join-Path $gd 'gitdir'
    if (-not (Test-Path -LiteralPath $back -PathType Leaf)) { throw 'its admin dir has no gitdir file' }
    $backTo = ([string](Get-Content -LiteralPath $back -TotalCount 1)).Trim()
    # `git worktree add --relative-paths` writes it relative to the admin dir.
    if (-not [System.IO.Path]::IsPathRooted($backTo)) { $backTo = Join-Path $gd $backTo }
    if (-not (Test-SamePath (Resolve-Canonical $backTo) (Resolve-Canonical $dotGit))) { throw 'its admin dir names another worktree' }
    # Every read through this admin dir takes objects, refs and config from what `commondir`
    # names, so it must name this repository's own common dir.
    $cd = Join-Path $gd 'commondir'
    if (-not (Test-Path -LiteralPath $cd -PathType Leaf)) { throw 'its admin dir has no commondir file' }
    $cdTo = ([string](Get-Content -LiteralPath $cd -TotalCount 1)).Trim()
    if (-not [System.IO.Path]::IsPathRooted($cdTo)) { $cdTo = Join-Path $gd $cdTo }
    if (-not (Test-SamePath (Resolve-Canonical $cdTo) $common)) { throw 'its admin dir names another repository as its common dir' }
    return $gd
}

function Get-PrimaryHolding([string]$Canon, $Lists) {
    # The fleet repositories whose primary checkout holds $Canon, not through a linked worktree.
    foreach ($l in $Lists) {
        $primary = @($l.Blocks | Where-Object { $_.Primary })[0]
        if (-not $primary.Canon) { throw "the primary of $($l.Repo) does not canonicalise" }
        if ((Test-AtOrUnder $Canon $primary.Canon) -and
            -not @($l.Blocks | Where-Object { -not $_.Primary -and $_.Canon -and (Test-AtOrUnder $Canon $_.Canon) })) { $l.Repo }
    }
}

# This machine's OFF file silences the check, so it is read before anything else, the sanitiser
# included, and a silenced run costs one git call. A read that fails only means not silenced and
# costs no reason line. Its stderr line reaches a person running the check by hand; under the
# hook, which exits 0, the harness does not surface it.
try {
    if (-not $FleetRepos) { throw 'no engine repository named' }
    $c = Invoke-Git $FleetRepos[0] @('rev-parse', '--path-format=absolute', '--git-common-dir')
    if ($c.Code -ne 0 -or -not $c.Out.Trim()) { throw "the engine's git common dir could not be read (exit $($c.Code))" }
    if (Test-Path -LiteralPath (Join-Path $c.Out.Trim() 'mefor-coord/enter-check/OFF')) {
        Write-Output 'OFF'
        Write-Output '  this machine has turned the check off with its local OFF file'
        exit 2
    }
}
catch { [Console]::Error.WriteLine("enter-check: the local OFF file could not be read: $($_.Exception.Message)") }

# One sanitiser for every line printed. Loaded before any check: with none, no attacker-chosen text may be
# printed at all, so the verdict is UNSAFE with a fixed reason.
try {
    $gate = Join-Path (Split-Path -Parent $PSScriptRoot) 'hooks/worktree_gate.ps1'
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($gate, [ref]$null, [ref]$parseErrors)
    if (@($parseErrors).Count) { throw 'worktree_gate.ps1 does not parse' }
    $defs = @($ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SafeForMessage'
            }, $true))
    if ($defs.Count -ne 1) { throw "worktree_gate.ps1 defines Get-SafeForMessage $($defs.Count) times" }
    # Dot-sourced at script level, so the gate's own definition lands in this script's scope.
    . ([scriptblock]::Create($defs[0].Extent.Text))
}
catch {
    Write-Output 'UNSAFE'
    Write-Output '  the message sanitiser could not be loaded from scripts/hooks/worktree_gate.ps1, so no other reason is printed'
    exit 1
}

try {
    $target = $null
    $rawFull = $null
    $lists = @()
    $match = $null
    $verifiedGitDir = $null

    # a. Canonical target.
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { throw 'no -Path given' }
        # Never joined to a directory: which one the harness resolves a relative path against is
        # not something this check can see, so Resolve-Canonical refuses any path not fully qualified.
        $target = Resolve-Canonical $Path
        # Kept for c: the harness keeps the path it was given, not the target judged here.
        $rawFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        [void]$passed.Add('a')
    }
    catch { Add-Failure 'a' "the path $Path does not canonicalise: $($_.Exception.Message)" }

    # Every fleet repository's worktree list, for b and d. A repository not on this machine holds
    # no worktree and no primary, so it is skipped; one that is here and will not list throws.
    try {
        $lists = @(for ($ri = 0; $ri -lt @($FleetRepos).Count; $ri++) {
                $repo = $FleetRepos[$ri]
                if (Test-Path -LiteralPath $repo -PathType Container) {
                    # Its pinned remote, paired by position; none is a failure at f.
                    $remote = if ($ri -lt @($FleetRemotes).Count) { $FleetRemotes[$ri] } else { '' }
                    [pscustomobject]@{ Repo = $repo; Remote = $remote; Blocks = @(Get-WorktreeList $repo) }
                }
            })
    }
    catch { Add-Failure 'b' "a fleet repository's worktree list could not be read: $($_.Exception.Message)"; $lists = $null }

    # b. A linked worktree of a fleet repository.
    $unresolved = @(if ($null -ne $lists) { foreach ($l in $lists) { foreach ($b in $l.Blocks) { if ($b.CanonError) { $b.Path } } } })
    if ($unresolved) { Add-Failure 'b' "$($unresolved.Count) listed worktree(s) exist but do not canonicalise, first $($unresolved[0])"; $lists = $null }
    if ($target -and $null -ne $lists) {
        $hits = @(foreach ($l in $lists) { foreach ($b in $l.Blocks) { if (Test-SamePath $b.Canon $target) { [pscustomobject]@{ Repo = $l.Repo; Remote = $l.Remote; Block = $b } } } })
        if ($hits.Count -eq 0) { Add-Failure 'b' "$target is not a worktree listed by any fleet repository" }
        elseif ($hits.Count -gt 1) { Add-Failure 'b' "$target is listed $($hits.Count) times across the fleet repositories" }
        elseif ($hits[0].Block.Primary) { Add-Failure 'b' "$target is the primary checkout of $($hits[0].Repo), not a linked worktree" }
        else { $match = $hits[0]; [void]$passed.Add('b') }
    }

    # c. Under this session's own scratchpad, by exact segments.
    if ($target) {
        try {
            if ($SessionId -cnotmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                throw "the session id $SessionId is not a session uuid"
            }
            $tempCanon = Resolve-Canonical $TempRoot
            $t = Split-PathSegments $target
            $n = (Split-PathSegments $tempCanon).Segs.Count
            $own = (Test-AtOrUnder $target $tempCanon) -and ($t.Segs.Count -ge $n + 5)
            $own = $own -and ($t.Segs[$n] -ceq 'claude') -and ($t.Segs[$n + 2] -ceq $SessionId) -and ($t.Segs[$n + 3] -ceq 'scratchpad')
            # A link the session owns can be repointed after this check, and the path the harness
            # keeps then names another tree. So the path given must already be the canonical one.
            if ($own -and -not (Test-SamePath $rawFull $target)) {
                Add-Failure 'c' "the path given passes through a link to $target; give the target itself"
            }
            elseif ($own) { [void]$passed.Add('c') }
            else { Add-Failure 'c' "$target is not under $tempCanon/claude/<project>/$SessionId/scratchpad/, this session's own scratchpad" }
        }
        catch { Add-Failure 'c' "ownership could not be checked: $($_.Exception.Message)" }
    }

    # d. The session is not in a primary checkout.
    if ($null -ne $lists) {
        try {
            $cwdCanon = Resolve-Canonical $SessionCwd
            if ([string]::IsNullOrWhiteSpace($TranscriptPath)) { throw 'no transcript path, so where the session launched is unknown' }
            # <config root>/projects/<slug>/..., read at the segment after the last `projects`, so a
            # transcript filed deeper (a subagent's, say) still yields the session's own slug.
            $tSegs = @($TranscriptPath.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
            $at = [Array]::LastIndexOf([string[]]$tSegs, 'projects')
            if ($at -lt 0 -or $at + 2 -ge $tSegs.Count) { throw 'the transcript path names no project directory' }
            $launchSlug = $tSegs[$at + 1]
            $inPrimary = @(
                Get-PrimaryHolding $cwdCanon $lists | ForEach-Object { "$_ (the cwd)" }
                foreach ($l in $lists) {
                    $primary = @($l.Blocks | Where-Object { $_.Primary })[0]
                    if (@((Get-Slug $primary.Canon), (Get-Slug $primary.Path)) | Where-Object { [string]::Equals($launchSlug, $_, $nameCmp) }) {
                        "$($l.Repo) (the transcript's project directory)"
                    }
                })
            if ($inPrimary) { Add-Failure 'd' "the session is in the primary checkout of $($inPrimary -join ', '); relocating from there re-files the transcript" }
            else { [void]$passed.Add('d') }
        }
        catch { Add-Failure 'd' "where the session is or was launched could not be checked: $($_.Exception.Message)" }
    }

    # e. Not locked, and no operation in progress.
    if ($match) {
        try {
            # Verified first, and kept for f whatever else e finds.
            $gitDir = Get-VerifiedGitDir $match.Repo $target
            $verifiedGitDir = $gitDir
            if ($match.Block.Locked) { Add-Failure 'e' "$target is locked" }
            else {
                $busy = @('rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'sequencer', 'BISECT_LOG', 'BISECT_START' |
                        Where-Object { Test-Path -LiteralPath (Join-Path $gitDir $_) })
                if ($busy) { Add-Failure 'e' "$target has an operation in progress ($($busy -join ', '))" }
                else { [void]$passed.Add('e') }
            }
        }
        catch { Add-Failure 'e' "the worktree state could not be read: $($_.Exception.Message)" }
    }

    # f. HEAD is a merged commit of the remote's main, and the working tree is HEAD up to git's eol conversion.
    if ($match) {
        try {
            $repo = $match.Repo
            $head = $match.Block.Head
            if ($head -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { throw 'the worktree has no HEAD commit' }
            if (-not $verifiedGitDir) { throw 'its admin dir was not verified (check e)' }
            if (-not $match.Remote) { throw "no pinned remote is named for $repo" }
            # Against the verified admin dir, never whatever the worktree's own .git names.
            $wt = @("--git-dir=$verifiedGitDir", "--work-tree=$target")
            # The listing's HEAD came from whichever admin dir git listed at this path; everything
            # below reads the verified one. They must be the same commit, and stay it to the end.
            $headNow = {
                $r = Invoke-Git $target ($wt + @('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
                if ($r.Code -ne 0) { throw "git rev-parse HEAD failed (exit $($r.Code))" }
                $r.Out.Trim()
            }
            if ((& $headNow) -cne $head) { throw "the verified admin dir's HEAD is not the commit git lists for the worktree" }
            # A graft file rewrites a commit's parents for merge-base, and --no-replace-objects does not turn it off.
            $common = Split-Path -Parent (Split-Path -Parent $verifiedGitDir)
            if (Test-Path -LiteralPath (Join-Path $common 'info/grafts')) { throw 'the clone has an info/grafts file, which rewrites ancestry' }
            $remoteMain = Get-RemoteMain $match.Remote $RemoteTimeoutSeconds
            if ((Invoke-Git $repo @('cat-file', '-e', "$remoteMain^{commit}")).Code -ne 0) {
                throw "the remote's main is not in this clone yet; fetch origin first"
            }
            $anc = Invoke-Git $repo @('merge-base', '--is-ancestor', $head, $remoteMain)
            if ($anc.Code -gt 1) { throw "git merge-base failed (exit $($anc.Code))" }

            $tree = Invoke-Git $target ($wt + @('ls-tree', '-r', '-z', '--end-of-options', $head))
            if ($tree.Code -ne 0) { throw "git ls-tree failed (exit $($tree.Code))" }
            $paths = [System.Collections.Generic.List[string]]::new()
            $blobs = [System.Collections.Generic.List[string]]::new()
            $odd = 0
            foreach ($e in $tree.Out.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
                $meta, $p = $e -split "`t", 2
                $mode, $type, $id = $meta.Split(' ')
                # hash-object --stdin-paths reads a line: it unquotes one that starts with `"` and
                # may drop a trailing CR, so either would hash another file than the one tracked.
                if ($type -cne 'blob' -or $mode -notin @('100644', '100755') -or $p.Contains("`n") -or $p.Contains("`r") -or $p.StartsWith('"')) { $odd++; continue }
                $paths.Add($p); $blobs.Add($id)
            }
            # A filter, ident or working-tree-encoding attribute converts content between disk and
            # blob, and its rules can come from the clone's shared .git/info/attributes and config.
            # A filter also runs a command. So no tracked path may carry one; read before any hash.
            $converted = 0
            if ($paths.Count) {
                $ca = Invoke-Git $target ($wt + @('check-attr', '-z', '--stdin', 'filter', 'ident', 'working-tree-encoding')) -StdinText (($paths -join [char]0) + [char]0) -TimeoutSeconds 60
                if ($ca.Code -ne 0) { throw "git check-attr failed (exit $($ca.Code))" }
                $triples = $ca.Out.Split([char]0)
                for ($i = 0; $i + 2 -lt $triples.Count; $i += 3) { if ($triples[$i + 2] -cne 'unspecified') { $converted++ } }
            }
            if ($converted) { throw "$converted tracked-path attributes set a filter, ident or working-tree-encoding" }
            # One process hashes every tracked file as it sits on disk, through the eol conversion
            # git applies, so a line-ending conversion is not a difference and a forged stat is.
            $bytesDiffer = 0
            if ($paths.Count) {
                $h = Invoke-Git $target ($wt + @('hash-object', '--stdin-paths')) -StdinText (($paths -join "`n") + "`n") -TimeoutSeconds 60
                if ($h.Code -ne 0) { throw "git hash-object failed (exit $($h.Code)); a tracked file may be missing" }
                $ids = @($h.Out.Split("`n", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
                if ($ids.Count -ne $paths.Count) { throw 'git hash-object answered for a different number of files' }
                for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i] -cne $blobs[$i]) { $bytesDiffer++ } }
            }
            # `ls-files -v` tags a normal entry H; assume-unchanged is lowercase and skip-worktree S,
            # and git status reports neither kind of entry as modified.
            $flags = Invoke-Git $target ($wt + @('ls-files', '-v', '-z'))
            if ($flags.Code -ne 0) { throw "git ls-files failed (exit $($flags.Code))" }
            $flagged = @($flags.Out.Split([char]0) | Where-Object { $_ -and -not $_.StartsWith('H ') })
            $st1 = Invoke-Git $target ($wt + @('status', '--porcelain=v1', '-z', '--untracked-files=all'))
            # Untracked files the tree's own .gitignore files do not ignore. Not --exclude-standard:
            # that adds the clone's info/exclude and core.excludesFile, which any session can write.
            $st3 = Invoke-Git $target ($wt + @('ls-files', '-z', '--others', '--exclude-per-directory=.gitignore'))
            # ls-files, not status: status names a whole ignored directory such as `.venv/` against
            # any pathspec, while ls-files names each ignored file and filters it by the pathspec.
            # icase, because NTFS opens CLAUDE.md for a file named claude.md.
            $st2 = Invoke-Git $target ($wt + @('ls-files', '-z', '--others', '--ignored', '--exclude-per-directory=.gitignore', '--',
                    ':(glob,icase)**/.claude/**', ':(glob,icase)**/.mcp.json', ':(glob,icase)**/CLAUDE.md', ':(glob,icase)**/CLAUDE.local.md'))
            if ($st1.Code -ne 0 -or $st2.Code -ne 0 -or $st3.Code -ne 0) { throw 'git status failed' }
            $stray = @(($st1.Out + [char]0 + $st2.Out + [char]0 + $st3.Out).Split([char]0) | Where-Object { $_ })
            if ((& $headNow) -cne $head) { throw 'the worktree moved to another commit while it was checked' }

            if ($anc.Code -ne 0) { Add-Failure 'f' "the worktree's HEAD is not a commit of the remote's main, so its branch could carry its own hooks or instructions" }
            elseif ($odd) { Add-Failure 'f' "the worktree's HEAD holds $odd symlink, submodule or unreadable entries" }
            elseif ($bytesDiffer) { Add-Failure 'f' "$bytesDiffer tracked files on disk differ from HEAD" }
            elseif ($flagged) { Add-Failure 'f' "$($flagged.Count) index entries are flagged assume-unchanged or skip-worktree" }
            elseif ($stray) { Add-Failure 'f' "the worktree has changed, untracked, or ignored settings or instruction files ($($stray.Count) entries)" }
            else { [void]$passed.Add('f') }
        }
        catch { Add-Failure 'f' "branch provenance could not be checked: $($_.Exception.Message)" }
    }

    # The only statement that sets the verdict: every check passed, by name, and none failed.
    $safe = ($failures.Count -eq 0) -and ((@($passed) | Sort-Object) -join '') -ceq 'abcdef'
}
catch {
    Add-Failure '-' "the check stopped on an error: $($_.Exception.Message)"
}

if ($safe) {
    Write-Output 'SAFE'
    Write-Output (Get-SafeForMessage "  all six checks passed for $target")
    exit 0
}
Write-Output 'UNSAFE'
if (-not $failures.Count) { $failures.Add('-. not every check recorded a pass') }
foreach ($f in $failures) { Write-Output (Get-SafeForMessage "  $f") }
exit 1
