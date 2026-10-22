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
         is refused, not expanded). A `\\?\`, `\\.\` or UNC path is refused outright.
      b. It is a LINKED worktree (never the primary) listed by `git worktree list --porcelain -z`
         of one of the fleet repositories (-FleetRepos), compared canonical to canonical.
      c. It is under THIS session's own scratchpad, by segments:
         <temp>\claude\<one project segment>\<SessionId>\scratchpad\<at least one more>.
         `.claude/worktrees/` is never allowed: another session's subagent trees live there, and
         nothing here can tell whose they are.
      d. The session is not in the primary checkout of any fleet repository (-SessionCwd). Rule 4
         of scripts/hooks/worktree_gate.ps1 exists because relocating out of the primary re-files
         the chat transcript, so that case keeps its prompt.
      e. The worktree is not locked, and no rebase, merge, cherry-pick, revert or bisect is in
         progress in its git dir.
      f. Its HEAD tree's `.claude/` and `.mcp.json` have the same object ids as `origin/main`'s
         (an absent path must be absent on both sides), AND its working tree holds no modified,
         untracked or ignored file under either path but the two markers this repository's own
         hooks write ($localMarkers below). A branch, or a file left in the working tree such as
         a `.claude/settings.local.json`, could otherwise carry its own hooks or permissions.
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
    The directory that holds `claude\<project>\<session>\scratchpad`. Defaults to the user's temp
    directory, which is where the harness puts a session's scratchpad.
#>
param(
    [string]$Path,
    [string]$SessionId,
    [string]$SessionCwd = (Get-Location).ProviderPath,
    [string[]]$FleetRepos = @('D:/Code/MessageFoundry', 'D:/Code/MessageFoundry-vault', 'D:/Code/korus'),
    [string]$TempRoot = [System.IO.Path]::GetTempPath(),
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

function Invoke-Child {
    # A child process with argv passed as a list (no quoting to get wrong), UTF-8 output, and a
    # bound. A child still running at the bound is killed and the call throws.
    param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSeconds = 30, [switch]$StripGit)
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
    foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    if ($StripGit) { foreach ($v in $gitEnvStrip) { [void]$psi.Environment.Remove($v) } }
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $p.StandardInput.Close()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill($true) } catch { Write-Verbose "kill failed: $($_.Exception.Message)" }
            throw "$(Split-Path -Leaf $Exe) did not finish within $TimeoutSeconds s"
        }
        $p.WaitForExit()
        return [pscustomobject]@{ Code = $p.ExitCode; Out = $outTask.Result; Err = $errTask.Result }
    }
    finally { $p.Dispose() }
}

function Invoke-Git([string]$Repo, [string[]]$GitArgs) {
    Invoke-Child -Exe 'git' -StripGit -ArgList (@('-C', $Repo, '-c', 'core.fsmonitor=false', '--no-optional-locks') + $GitArgs)
}

# The ignored files this repository's own hooks write into every worktree's .claude/: the seat
# marker (seat.ps1 -Declare) and the role card copy (role-card-inject.ps1). Neither is read by the
# harness as settings, hooks or permissions. Any other file there fails check f.
$localMarkers = @('.claude/seat.local.txt', '.claude/ROLE.local.md')

$nameCmp = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }

function Resolve-Canonical([string]$Raw) {
    <#
      The final on-disk path: every segment as the directory lists it, every link replaced by its
      final target and re-walked from the root (a target may itself sit under a link). Throws on
      anything it cannot canonicalise, which every caller treats as a failed check.
    #>
    if ([string]::IsNullOrWhiteSpace($Raw)) { throw 'no path given' }
    if ($Raw -match '^[\\/]{2}') { throw 'a \\?\, \\.\ or UNC path is refused' }
    $full = [System.IO.Path]::GetFullPath($Raw)
    for ($hop = 0; $hop -lt 40; $hop++) {
        $root = [System.IO.Path]::GetPathRoot($full)
        if (-not $root -or $root -match '^[\\/]{2}') { throw 'a path with no local root is refused' }
        $cur = if ($IsWindows) { $root.ToUpperInvariant() } else { $root }
        $segs = $full.Substring($root.Length).Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries)
        $relinked = $false
        for ($i = 0; $i -lt $segs.Count; $i++) {
            $seg = $segs[$i]
            if ($seg.IndexOfAny([char[]]'*?<>"') -ge 0) { throw 'a path segment holds a wildcard character' }
            $parent = [System.IO.DirectoryInfo]::new($cur)
            $found = @($parent.EnumerateFileSystemInfos($seg) | Where-Object { [string]::Equals($_.Name, $seg, $nameCmp) })
            if ($found.Count -ne 1) { throw 'a path segment is not on disk under that name (missing, or an 8.3 short name)' }
            $item = $found[0]
            $cur = $item.FullName
            if ($null -ne $item.LinkTarget) {
                $target = $item.ResolveLinkTarget($true)
                if ($null -eq $target -or -not $target.Exists) { throw 'a link along the path has no existing target' }
                $rest = if ($i + 1 -lt $segs.Count) { $segs[($i + 1)..($segs.Count - 1)] } else { @() }
                $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Join(@($target.FullName) + $rest))
                $relinked = $true
                break
            }
        }
        if (-not $relinked) { return $cur }
    }
    throw 'more than 40 links along the path'
}

function Split-Canonical([string]$Canon) {
    $root = [System.IO.Path]::GetPathRoot($Canon)
    $segs = @($Canon.Substring($root.Length).Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
    [pscustomobject]@{ Root = $root; Segs = $segs }
}

function Test-SamePath([string]$A, [string]$B) {
    if (-not $A -or -not $B) { return $false }
    if ($IsWindows) { return [string]::Equals($A.ToUpperInvariant(), $B.ToUpperInvariant(), [System.StringComparison]::Ordinal) }
    return [string]::Equals($A, $B, [System.StringComparison]::Ordinal)
}

function Test-AtOrUnder([string]$Child, [string]$Parent) {
    if (Test-SamePath $Child $Parent) { return $true }
    $c = Split-Canonical $Child
    $p = Split-Canonical $Parent
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
            $cur = [pscustomobject]@{ Path = $tok.Substring(9); Head = ''; Locked = $false; Canon = $null; Primary = ($blocks.Count -eq 0) }
            $blocks.Add($cur)
            continue
        }
        if ($null -eq $cur) { throw "git worktree list printed an attribute outside a block in $Repo" }
        if ($tok.StartsWith('HEAD ')) { $cur.Head = $tok.Substring(5) }
        elseif ($tok -eq 'locked' -or $tok.StartsWith('locked ')) { $cur.Locked = $true }
    }
    foreach ($b in $blocks) {
        # A listed path that no longer exists (prunable) can match nothing.
        try { $b.Canon = Resolve-Canonical $b.Path } catch { $b.Canon = $null }
    }
    return $blocks
}

function Get-ObjectId([string]$Repo, [string]$Spec) {
    # The object id, or '' when the path is absent at that revision. Anything else throws.
    $r = Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', '--end-of-options', $Spec)
    if ($r.Code -eq 0) { return $r.Out.Trim() }
    if ($r.Code -eq 1 -and -not $r.Out.Trim()) { return '' }
    throw "git rev-parse could not read $Spec (exit $($r.Code))"
}

try {
    $target = $null
    $tempCanon = $null
    $cwdCanon = $null
    $lists = @()
    $match = $null

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
            $t = Split-Canonical $target
            $r = Split-Canonical $tempCanon
            $n = $r.Segs.Count
            $own = (Test-SamePath $t.Root $r.Root) -and ($t.Segs.Count -ge $n + 5)
            for ($i = 0; $own -and $i -lt $n; $i++) { $own = [string]::Equals($t.Segs[$i], $r.Segs[$i], $nameCmp) }
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
            $inPrimary = @(foreach ($l in $lists) {
                    $primary = @($l.Blocks | Where-Object { $_.Primary })[0]
                    if ($primary.Canon -and (Test-AtOrUnder $cwdCanon $primary.Canon)) {
                        $inLinked = @($l.Blocks | Where-Object { -not $_.Primary -and $_.Canon -and (Test-AtOrUnder $cwdCanon $_.Canon) })
                        if (-not $inLinked) { $l.Repo }
                    }
                })
            if ($inPrimary) { Add-Failure 'd' "the session is in the primary checkout of $($inPrimary -join ', '); relocating from there re-files the transcript, so the prompt stays" }
            else { [void]$passed.Add('d') }
        }
        catch { Add-Failure 'd' "the session's cwd $SessionCwd could not be checked: $($_.Exception.Message)" }
    }

    # e. Not locked, and no operation in progress.
    if ($match) {
        try {
            if ($match.Block.Locked) { Add-Failure 'e' "$target is locked" }
            else {
                $g = Invoke-Git $target @('rev-parse', '--absolute-git-dir')
                if ($g.Code -ne 0 -or -not $g.Out.Trim()) { throw "git rev-parse --absolute-git-dir failed (exit $($g.Code))" }
                $gitDir = $g.Out.Trim()
                $busy = @('rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'BISECT_LOG', 'BISECT_START' |
                        Where-Object { Test-Path -LiteralPath (Join-Path $gitDir $_) })
                if ($busy) { Add-Failure 'e' "$target has an operation in progress ($($busy -join ', '))" }
                else { [void]$passed.Add('e') }
            }
        }
        catch { Add-Failure 'e' "the worktree state could not be read: $($_.Exception.Message)" }
    }

    # f. Branch provenance of .claude/ and .mcp.json, committed and in the working tree.
    if ($match) {
        try {
            $repo = $match.Repo
            $head = $match.Block.Head
            if ($head -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { throw 'the worktree has no HEAD commit' }
            if (-not (Get-ObjectId $repo 'origin/main^{commit}')) { throw "$repo has no origin/main" }
            $differs = @(foreach ($p in '.claude', '.mcp.json') {
                    if ((Get-ObjectId $repo "${head}:$p") -cne (Get-ObjectId $repo "origin/main:$p")) { $p }
                })
            $st = Invoke-Git $target @('status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--', '.claude', '.mcp.json')
            if ($st.Code -ne 0) { throw "git status failed (exit $($st.Code))" }
            # Each -z entry is `XY <path>`; a rename's second token has no XY, so it never matches.
            $stray = @($st.Out.Split([char]0) | Where-Object { $_ } | Where-Object {
                    -not ($_.Length -gt 3 -and $localMarkers -ccontains $_.Substring(3)) })
            if ($differs) { Add-Failure 'f' "the worktree's HEAD differs from origin/main in $($differs -join ', '), so its branch could carry its own hooks" }
            elseif ($stray) { Add-Failure 'f' "the worktree has modified, untracked or ignored files under .claude/ or .mcp.json ($($stray.Count) entries)" }
            else { [void]$passed.Add('f') }
        }
        catch { Add-Failure 'f' "branch provenance could not be checked: $($_.Exception.Message)" }
    }

    # g. The AFK kill switch reads OFF.
    try {
        $kill = Join-Path (Split-Path -Parent $PSScriptRoot) 'coord/afk-kill.ps1'
        $k = Invoke-Child -Exe ([Environment]::ProcessPath) -TimeoutSeconds $KillSwitchTimeoutSeconds -ArgList @('-NoProfile', '-NonInteractive', '-File', $kill, '-Status')
        $word = $k.Out.Trim()
        if ($k.Code -eq 0 -and $word -ceq 'OFF') { [void]$passed.Add('g') }
        else { Add-Failure 'g' "the AFK kill switch does not read OFF (it printed '$word', exit $($k.Code)); set MEFOR_AFK_KILL to off to allow" }
    }
    catch { Add-Failure 'g' "the AFK kill switch could not be read: $($_.Exception.Message)" }

    # h. No local disable file.
    try {
        if (-not $FleetRepos) { throw 'no engine repository named' }
        $c = Invoke-Git $FleetRepos[0] @('rev-parse', '--path-format=absolute', '--git-common-dir')
        if ($c.Code -ne 0 -or -not $c.Out.Trim()) { throw "the engine's git common dir could not be read (exit $($c.Code))" }
        $off = Join-Path $c.Out.Trim() 'mefor-coord/enter-check/OFF'
        if (Test-Path -LiteralPath $off) { Add-Failure 'h' "this machine has turned the check off: $off exists" }
        else { [void]$passed.Add('h') }
    }
    catch { Add-Failure 'h' "the local disable file could not be checked: $($_.Exception.Message)" }

    # The only statement that sets the verdict: every check passed, by name, and none failed.
    $safe = ($failures.Count -eq 0) -and ((@($passed) | Sort-Object) -join '') -ceq 'abcdefgh'
}
catch {
    $safe = $false
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
