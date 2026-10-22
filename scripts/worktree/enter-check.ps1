# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Is it safe for this session to enter the worktree at -Path without asking the owner? (ADR 0212)

.DESCRIPTION
    Read-only. Prints `SAFE` or `UNSAFE` as its first stdout line, then the reasons, one per line.
    Exits 0 for SAFE and 1 for anything else. scripts/hooks/enter-worktree-check.ps1 runs it before
    an EnterWorktree call and auto-allows the call only on SAFE; on UNSAFE the owner's normal
    permission prompt shows, as it did before this check existed.

    IT FAILS CLOSED. The verdict starts false and is set only by the last statement of the checks,
    and only when every one of the eight checks below recorded its own pass. A check that throws,
    times out, or is skipped because an earlier one failed records no pass, so it can only ever
    cost a prompt, never grant one.

    SAFE requires ALL of:

      a. The path canonicalises: full path, every junction and symlink along it resolved to its
         final target, every segment present on disk under the name given (so an 8.3 short name
         is refused, not expanded). A `\\?\`, `\\.\`, UNC, drive-relative (`C:x`) or
         root-relative (`\x`) path is refused outright.
      b. It is a LINKED worktree (never the primary) listed by `git worktree list --porcelain -z`
         of one of the fleet repositories (-FleetRepos), compared canonical to canonical.
      c. It is under THIS session's own scratchpad, by segments:
         <temp>\claude\<one project segment>\<SessionId>\scratchpad\<at least one more>.
         `.claude/worktrees/` is never allowed: another session's subagent trees live there, and
         nothing here can tell whose they are.
      d. The session neither is nor was launched in the primary checkout of a fleet repository.
         Rule 4 of scripts/hooks/worktree_gate.ps1 exists because relocating out of the primary
         re-files the chat transcript, so that case keeps its prompt. Two reads, because a `cd`
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
         `git ls-remote origin refs/heads/main` names, never a local ref, which any session can
         move. So every tracked file, settings, hook code and instructions alike, is one that
         merged. Its working tree matches HEAD byte for byte: every tracked file's on-disk hash
         equals its HEAD blob (a stat-cache read alone can be fooled), no index entry is flagged
         assume-unchanged or skip-worktree, nothing is modified or untracked, and no ignored file
         sits where the harness reads settings or instructions (`.claude`, `.mcp.json`,
         `CLAUDE.md`, `CLAUDE.local.md`, at any depth). The tree holds no symlink or submodule.
      g. scripts/coord/afk-kill.ps1 -Status prints OFF. Any other output, an error or a timeout
         is a failure.
      h. No local disable file exists at <git common dir of the engine>/mefor-coord/enter-check/OFF.

    Every line printed goes through Get-SafeForMessage, loaded from worktree_gate.ps1's own
    definition (parsed, never copied), because a path or a git message is attacker-choosable text.

    TO DISABLE IT (ADR 0212):
      * fleet-wide: set the repository variable MEFOR_AFK_KILL to anything but `off` (check g);
      * this machine only: create the OFF file (check h):
            New-Item -ItemType File -Force -Path "$(git -C D:/Code/MessageFoundry rev-parse --path-format=absolute --git-common-dir)/mefor-coord/enter-check/OFF"
        and delete that file to turn it back on;
      * permanently: remove the EnterWorktree entry from .claude/settings.json.

.PARAMETER FleetRepos
    The fleet repositories. The FIRST is the engine, whose git common dir holds the OFF file. The
    hook passes none, so the defaults apply; tests pass their own.

.PARAMETER TempRoot
    The directory that holds `claude\<project>\<session>\scratchpad`. Defaults to the temp
    directory in the order Node's os.tmpdir() reads it (TEMP, then TMP, on Windows; TMPDIR, TMP,
    TEMP elsewhere), which is where the harness puts a session's scratchpad. .NET's own
    GetTempPath prefers TMP, so it can name another directory. A TEMP spelled with an 8.3 short
    name fails check c, which costs a prompt.

.PARAMETER TranscriptPath
    The hook input's `transcript_path`. With none, check d fails.
#>
param(
    [string]$Path,
    [string]$SessionId,
    [string]$SessionCwd = (Get-Location).ProviderPath,
    [string[]]$FleetRepos = @('D:/Code/MessageFoundry', 'D:/Code/MessageFoundry-vault', 'D:/Code/korus'),
    [string]$TempRoot = $(@(if ($IsWindows) { $env:TEMP; $env:TMP } else { $env:TMPDIR; $env:TMP; $env:TEMP }
            [System.IO.Path]::GetTempPath()) | Where-Object { $_ } | Select-Object -First 1),
    [string]$TranscriptPath,
    [ValidateRange(1, 120)][int]$RemoteTimeoutSeconds = 20,
    [ValidateRange(1, 120)][int]$KillSwitchTimeoutSeconds = 20
)

$safe = $false
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One sanitiser for every line printed. Loaded first: with none, no attacker-chosen text may be
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

$failures = [System.Collections.Generic.List[string]]::new()
$passed = [System.Collections.Generic.HashSet[string]]::new()
function Add-Failure([string]$Check, [string]$Why) { $failures.Add("$Check. $Why") }

# Inherited git variables would redirect `git -C` at another repository than the one named.
$gitEnvStrip = @('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE', 'GIT_CEILING_DIRECTORIES', 'GIT_DISCOVERY_ACROSS_FILESYSTEM')

function Start-Child {
    # A child process with argv passed as a list (no quoting to get wrong) and UTF-8 output.
    param([string]$Exe, [string[]]$ArgList, [switch]$StripGit, [string]$StdinText)
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
    foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardInputEncoding = [System.Text.UTF8Encoding]::new($false)
    if ($StripGit) { foreach ($v in $gitEnvStrip) { [void]$psi.Environment.Remove($v) } }
    $p = [System.Diagnostics.Process]::Start($psi)
    # Readers first, so a child that answers as it reads cannot fill its pipe and stall the write.
    $child = [pscustomobject]@{ Process = $p; Name = (Split-Path -Leaf $Exe); Out = $p.StandardOutput.ReadToEndAsync(); Err = $p.StandardError.ReadToEndAsync() }
    if ($StdinText) { $p.StandardInput.Write($StdinText) }
    $p.StandardInput.Close()
    $child
}

function Wait-Child($Child, [int]$TimeoutSeconds = 30) {
    # The child's exit code and output. A child still running at the bound is killed and this throws.
    $p = $Child.Process
    try {
        # The output is read to its end too, inside the same bound: a grandchild left running (a
        # hung gh behind afk-kill.ps1) holds the pipe open after the child itself has exited.
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $exited = $p.WaitForExit($TimeoutSeconds * 1000)
        $left = [Math]::Max(0, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $exited -or -not [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($Child.Out, $Child.Err), $left)) {
            try { $p.Kill($true) } catch { Write-Verbose "kill failed: $($_.Exception.Message)" }
            throw "$($Child.Name) did not finish within $TimeoutSeconds s"
        }
        $p.WaitForExit()
        return [pscustomobject]@{ Code = $p.ExitCode; Out = $Child.Out.Result; Err = $Child.Err.Result }
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
    $argv = @('-C', $Repo, '-c', 'core.fsmonitor=false', '-c', 'core.quotePath=off', '--no-optional-locks') + $GitArgs
    Wait-Child (Start-Child -Exe $gitExe -StripGit -ArgList $argv -StdinText $StdinText) -TimeoutSeconds $TimeoutSeconds
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

try {
    # Started first and read at check g: the read is a child pwsh and a network call, and nothing
    # before g depends on it.
    $killSwitch = $null
    $killSwitchFault = ''
    try {
        $kill = Join-Path (Split-Path -Parent $PSScriptRoot) 'coord/afk-kill.ps1'
        $killSwitch = Start-Child -Exe ([Environment]::ProcessPath) -ArgList @('-NoProfile', '-NonInteractive', '-File', $kill, '-Status')
    }
    catch { $killSwitchFault = $_.Exception.Message }

    $target = $null
    $lists = @()
    $match = $null
    $verifiedGitDir = $null

    # a. Canonical target.
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { throw 'no -Path given' }
        $raw = $Path
        if (-not [System.IO.Path]::IsPathRooted($raw)) {
            if ([string]::IsNullOrWhiteSpace($SessionCwd)) { throw 'a relative -Path with no -SessionCwd' }
            $raw = Join-Path $SessionCwd $raw
        }
        $target = Resolve-Canonical $raw
        [void]$passed.Add('a')
    }
    catch { Add-Failure 'a' "the path $Path does not canonicalise: $($_.Exception.Message)" }

    # Every fleet repository's worktree list, for b and d. A repository not on this machine holds
    # no worktree and no primary, so it is skipped; one that is here and will not list throws.
    try {
        $lists = @(foreach ($repo in $FleetRepos) {
                if (Test-Path -LiteralPath $repo -PathType Container) {
                    [pscustomobject]@{ Repo = $repo; Blocks = @(Get-WorktreeList $repo) }
                }
            })
    }
    catch { Add-Failure 'b' "a fleet repository's worktree list could not be read: $($_.Exception.Message)"; $lists = $null }

    # b. A linked worktree of a fleet repository.
    $unresolved = @(if ($null -ne $lists) { foreach ($l in $lists) { foreach ($b in $l.Blocks) { if ($b.CanonError) { $b.Path } } } })
    if ($unresolved) { Add-Failure 'b' "$($unresolved.Count) listed worktree(s) exist but do not canonicalise, first $($unresolved[0])"; $lists = $null }
    if ($target -and $null -ne $lists) {
        $hits = @(foreach ($l in $lists) { foreach ($b in $l.Blocks) { if (Test-SamePath $b.Canon $target) { [pscustomobject]@{ Repo = $l.Repo; Block = $b } } } })
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
            if ($own) { [void]$passed.Add('c') }
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
            if ($inPrimary) { Add-Failure 'd' "the session is in the primary checkout of $($inPrimary -join ', '); relocating from there re-files the transcript, so the prompt stays" }
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

    # f. HEAD is a merged commit of the remote's main, and the working tree is HEAD, byte for byte.
    if ($match) {
        try {
            $repo = $match.Repo
            $head = $match.Block.Head
            if ($head -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { throw 'the worktree has no HEAD commit' }
            if (-not $verifiedGitDir) { throw 'its admin dir was not verified (check e)' }
            $ls = Invoke-Git $repo @('ls-remote', '--exit-code', 'origin', 'refs/heads/main') -TimeoutSeconds $RemoteTimeoutSeconds
            if ($ls.Code -ne 0) { throw "git ls-remote origin refs/heads/main failed (exit $($ls.Code))" }
            $remoteMain = @($ls.Out.Split("`n") | Where-Object { $_ -cmatch '^([0-9a-f]{40}|[0-9a-f]{64})\trefs/heads/main$' } | ForEach-Object { $_.Split("`t")[0] })
            if ($remoteMain.Count -ne 1) { throw 'the remote names no single main commit' }
            if ((Invoke-Git $repo @('cat-file', '-e', "$($remoteMain[0])^{commit}")).Code -ne 0) {
                throw "the remote's main is not in this clone yet; fetch origin first"
            }
            $anc = Invoke-Git $repo @('merge-base', '--is-ancestor', $head, $remoteMain[0])
            if ($anc.Code -gt 1) { throw "git merge-base failed (exit $($anc.Code))" }

            # Against the verified admin dir, never whatever the worktree's own .git names.
            $wt = @("--git-dir=$verifiedGitDir", "--work-tree=$target")
            $tree = Invoke-Git $target ($wt + @('ls-tree', '-r', '-z', 'HEAD'))
            if ($tree.Code -ne 0) { throw "git ls-tree failed (exit $($tree.Code))" }
            $paths = [System.Collections.Generic.List[string]]::new()
            $blobs = [System.Collections.Generic.List[string]]::new()
            $odd = 0
            foreach ($e in $tree.Out.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
                $meta, $p = $e -split "`t", 2
                $mode, $type, $id = $meta.Split(' ')
                if ($type -cne 'blob' -or $mode -notin @('100644', '100755') -or $p.Contains("`n")) { $odd++; continue }
                $paths.Add($p); $blobs.Add($id)
            }
            # One process hashes every tracked file as it sits on disk, through the same filters
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
            # ls-files, not status: status names a whole ignored directory such as `.venv/` against
            # any pathspec, while ls-files names each ignored file and filters it by the pathspec.
            $st2 = Invoke-Git $target ($wt + @('ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--',
                    ':(glob)**/.claude/**', ':(glob)**/.mcp.json', ':(glob)**/CLAUDE.md', ':(glob)**/CLAUDE.local.md'))
            if ($st1.Code -ne 0 -or $st2.Code -ne 0) { throw 'git status failed' }
            $stray = @(($st1.Out + [char]0 + $st2.Out).Split([char]0) | Where-Object { $_ })

            if ($anc.Code -ne 0) { Add-Failure 'f' "the worktree's HEAD is not a commit of the remote's main, so its branch could carry its own hooks or instructions" }
            elseif ($odd) { Add-Failure 'f' "the worktree's HEAD holds $odd symlink, submodule or unreadable entries" }
            elseif ($bytesDiffer) { Add-Failure 'f' "$bytesDiffer tracked files on disk differ from HEAD" }
            elseif ($flagged) { Add-Failure 'f' "$($flagged.Count) index entries are flagged assume-unchanged or skip-worktree" }
            elseif ($stray) { Add-Failure 'f' "the worktree has changed, untracked, or ignored settings or instruction files ($($stray.Count) entries)" }
            else { [void]$passed.Add('f') }
        }
        catch { Add-Failure 'f' "branch provenance could not be checked: $($_.Exception.Message)" }
    }
    # g. The AFK kill switch reads OFF.
    try {
        if ($null -eq $killSwitch) { throw "it did not start ($killSwitchFault)" }
        $k = Wait-Child $killSwitch -TimeoutSeconds $KillSwitchTimeoutSeconds
        $word = $k.Out.Trim()
        if ($k.Code -eq 0 -and $word -ceq 'OFF') { [void]$passed.Add('g') }
        else { Add-Failure 'g' "the AFK kill switch does not read OFF (it printed '$word', exit $($k.Code)); only the owner sets it" }
    }
    catch { Add-Failure 'g' "the AFK kill switch could not be read: $($_.Exception.Message)" }

    # h. No local disable file.
    try {
        if (-not $FleetRepos) { throw 'no engine repository named' }
        $c = Invoke-Git $FleetRepos[0] @('rev-parse', '--path-format=absolute', '--git-common-dir')
        if ($c.Code -ne 0 -or -not $c.Out.Trim()) { throw "the engine's git common dir could not be read (exit $($c.Code))" }
        $off = Join-Path $c.Out.Trim() 'mefor-coord/enter-check/OFF'
        # The reason reaches the session, so it does not say which file to delete.
        if (Test-Path -LiteralPath $off) { Add-Failure 'h' 'this machine has turned the check off with its local OFF file' }
        else { [void]$passed.Add('h') }
    }
    catch { Add-Failure 'h' "the local disable file could not be checked: $($_.Exception.Message)" }

    # The only statement that sets the verdict: every check passed, by name, and none failed.
    $safe = ($failures.Count -eq 0) -and ((@($passed) | Sort-Object) -join '') -ceq 'abcdefgh'
}
catch {
    Add-Failure '-' "the check stopped on an error: $($_.Exception.Message)"
}

if ($safe) {
    Write-Output 'SAFE'
    Write-Output (Get-SafeForMessage "  all eight checks passed for $target")
    exit 0
}
Write-Output 'UNSAFE'
if (-not $failures.Count) { $failures.Add('-. not every check recorded a pass') }
foreach ($f in $failures) { Write-Output (Get-SafeForMessage "  $f") }
exit 1
