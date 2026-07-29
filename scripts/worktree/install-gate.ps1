<#
.SYNOPSIS
    Install (or remove) the worktree gate -- a PreToolUse hook that stops sessions BUILDING in the
    shared primary checkout, and hijacking a linked worktree onto another session's branch.

.DESCRIPTION
    Copies scripts\hooks\worktree_gate.ps1 to a shared USER-scope location (%USERPROFILE%\.claude\hooks\)
    and registers it as a PreToolUse hook in the settings.json of EVERY Claude config dir this box uses:
    ~/.claude (the Desktop app) AND each ~/.claude-account-N (the VS Code launchers that set
    CLAUDE_CONFIG_DIR). Override the set with -ConfigDir.

    WHY EVERY CONFIG DIR. The gate used to wire only ~/.claude, which left every ~/.claude-account-N
    session UNGATED -- and those are where the parallel VS Code chats run. A session running under an
    ungoverned account checked its own branch out inside another session's linked worktree (a hijack that
    silently swapped that session's files mid-task); the gate that would have blocked it was simply not
    installed there. This mirrors what install-selfheal.ps1 already does: wire all of them.

    WHY USER SCOPE, and why an installed COPY:

      * Reach. A hook in the project's .claude\settings.json is git-tracked, so it lives on ONE branch and
        does not exist in the other worktrees until each of them merges it. A user-scope hook governs every
        session on the machine the moment it is written. Hook definitions from the user, project and local
        scopes are unioned, so this ADDS to the repo's existing guards rather than replacing them.

      * Survivability. The command must not point into a working tree. The primary checkout is routinely
        on a detached HEAD or an old commit; a hook whose script path lives there vanishes on a checkout,
        and a hook whose script is missing exits non-zero-but-not-2 -- which means the tool call RUNS
        ANYWAY, silently. The gate would be off in every session and nothing would say so. So we install a
        copy outside every tree (once, shared, referenced by absolute path from each account) and re-copy
        it on each install.

    The gate only governs the checkouts listed in worktree-gate.repos.txt. That file IS the kill switch:
    -Uninstall removes it (and the hook entries from every config dir).

    Run from a PLAIN TERMINAL, not from inside Claude Code -- a session that can install its own gate can
    uninstall it. The script refuses when $env:CLAUDECODE is set.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Repo C:\Users\me\Code\Probe   # govern a test repo
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -ConfigDir C:\Users\me\.claude-account-3
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Status
#>
[CmdletBinding()]
param(
    # Primary checkout(s) to govern. Defaults to this repo's root.
    [string[]]$Repo,
    [switch]$Uninstall,
    [switch]$Status,
    # Do not gate Task/Agent/Workflow dispatch from the primary (writes are still gated).
    [switch]$NoDispatchGate,
    # Gate the EnterWorktree tool (rule 4), which relocates a LIVE session into a worktree.
    #
    # OPT-IN, and deliberately OFF by default. Rule 4 has never been installed, and turning it on as a
    # SIDE EFFECT of installing an unrelated fix would be a trap: with rules 2 and 4 both live, a session
    # started in the primary has no in-session path to isolation at all -- it can neither dispatch a
    # subagent nor relocate itself, so it must be restarted elsewhere by a human. That is a hard stop on
    # workflow-by-default from the directory sessions naturally open in, and it is a decision the owner
    # makes on purpose (docs/WORKTREES.md), not one that rides along with a regex fix.
    #
    # It also duplicates a guard the vendor now ships: since v2.1.206 EnterWorktree into a path OUTSIDE
    # .claude/worktrees/ raises a confirmation prompt that no permission rule can suppress, and since
    # v2.1.198 the transcript follows the session's cwd BOTH ways, so relocation re-files a chat rather
    # than losing it. See docs/SESSION-DRIFT-CONTROLS.md.
    [switch]$EnterWorktreeGate,
    # Config dirs to wire the hook into. Default: ~/.claude plus every existing ~/.claude-account-*.
    [string[]]$ConfigDir
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# The gate SCRIPT + its allowlist live ONCE, shared, under ~/.claude\hooks -- referenced by absolute path
# from every config dir's settings.json, so a single copy (and a single kill switch) governs all accounts.
# Null-safely: $env:USERPROFILE is Windows-only and NULL elsewhere, where Join-Path throws a
# parameter-binding error instead of returning a path. Same idiom as its sibling scripts.
$HomeDir   = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
$HooksDir  = Join-Path $HomeDir ".claude/hooks"
$GateDst   = Join-Path $HooksDir "worktree_gate.ps1"
$ReposFile = Join-Path $HooksDir "worktree-gate.repos.txt"

# Marker so we can find (and remove) exactly the entries we added, without disturbing other hooks.
$Marker = "worktree_gate.ps1"

# Config dirs to wire. Default: ~/.claude + every existing ~/.claude-account-* (the VS Code launchers).
if (-not $ConfigDir -or $ConfigDir.Count -eq 0) {
    $cands = @( (Join-Path $HomeDir ".claude") )
    $cands += @(
        Get-ChildItem -LiteralPath $HomeDir -Directory -Filter ".claude-account-*" -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName }
    )
    $ConfigDir = @($cands | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
}

function Read-Settings([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return [ordered]@{} }
    try { return ($raw | ConvertFrom-Json -AsHashtable) }
    catch { throw "$Path is not valid JSON -- fix it by hand before installing (it is live config for every session)." }
}

function Write-Settings([string]$Path, $Data) {
    # Two sessions installing at once could interleave a read-modify-write and leave INVALID JSON, which
    # would break hooks in every session on the machine at once. Serialize to a temp file, parse it back
    # to prove it is valid, keep a backup, then move it into place in one atomic operation. Done PER FILE,
    # so a failure wiring one config dir can never corrupt another.
    $json = $Data | ConvertTo-Json -Depth 20
    $null = $json | ConvertFrom-Json      # throws before we touch the real file
    $tmp = "$Path.tmp-$PID"
    Set-Content -LiteralPath $tmp -Value $json -Encoding utf8
    if (Test-Path -LiteralPath $Path) { Copy-Item -LiteralPath $Path "$Path.bak" -Force }
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Remove-GateHooks($Data) {
    if (-not $Data.hooks -or -not $Data.hooks.PreToolUse) { return $Data }
    $kept = @(
        $Data.hooks.PreToolUse | Where-Object {
            $entry = $_
            -not (@($entry.hooks) | Where-Object { "$($_.command)" -like "*$Marker*" })
        }
    )
    if ($kept.Count -gt 0) { $Data.hooks.PreToolUse = $kept }
    else { $null = $Data.hooks.Remove("PreToolUse") }
    return $Data
}

function Get-GateVersion([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $m = [regex]::Match((Get-Content -LiteralPath $Path -Raw), '\$GateVersion\s*=\s*"([^"]+)"')
    if ($m.Success) { $m.Groups[1].Value } else { "(unstamped)" }
}

function Get-GateHash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# Every tool a gate script branches on. -Status calls this on the INSTALLED copy, deliberately: the
# question it answers is "which rules does the gate that is RUNNING have, and are they all wired", and the
# source's rule set is not evidence for either. That is the whole point of the audit -- rule 4 was in the
# source, declared by this installer, and covered by tests, while the running gate had never heard of it.
function Get-HandledTools([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $text = Get-Content -LiteralPath $Path -Raw
    $tools = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in [regex]::Matches($text, '\$tool\s+-(?:not)?in\s+@\(([^)]*)\)')) {
        foreach ($q in [regex]::Matches($m.Groups[1].Value, '"([^"]+)"')) { $null = $tools.Add($q.Groups[1].Value) }
    }
    @($tools)
}

# ------------------------------------------------------------------------------------------ status
# NB this branch runs BEFORE the CLAUDECODE refusal below, deliberately. Auditing is not installing, and
# a session that cannot see whether the gate is current has no way to notice the exact failure that let
# rule 4 sit unshipped for five days while every test reported it present. Installing stays a human act.
if ($Status) {
    $srcGate = Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1"
    $iVer = Get-GateVersion $GateDst ; $sVer = Get-GateVersion $srcGate
    $iSha = Get-GateHash    $GateDst ; $sSha = Get-GateHash    $srcGate

    # Print the SHA alongside the version. The version is a hand-bumped label and can disagree with
    # reality -- it did: three rules shipped without a bump, so both lines read the same version directly
    # above a STALE verdict. Showing the hash makes agreement VISIBLE instead of asserted.
    # Lowercased: Get-FileHash returns uppercase, and every other hash a reader sees here (git, the
    # parity test's output) is lowercase. Two spellings of the same digest invite a false "these differ".
    $shortSha = { param($h) if ($h) { " sha $($h.Substring(0, 12).ToLowerInvariant())" } else { "" } }
    Write-Host "installed   : $(if ($iSha) { "$GateDst  v$iVer$(& $shortSha $iSha)" } else { 'NOT installed' })"
    Write-Host "source      : $(if ($sSha) { "$srcGate  v$sVer$(& $shortSha $sSha)" } else { 'NOT FOUND' })"
    if ($iSha -and $sSha) {
        if ($iSha -eq $sSha) {
            Write-Host "parity      : IN SYNC" -ForegroundColor Green
        } else {
            Write-Host "parity      : *** STALE *** the running gate is NOT this checkout's script." -ForegroundColor Red
            Write-Host "              Re-run this installer to update it. Until you do, rules added or"
            Write-Host "              removed in source have no effect, and the tests still pass."
        }
    }

    if (Test-Path -LiteralPath $ReposFile) {
        Write-Host "governing   :"
        Get-Content -LiteralPath $ReposFile | Where-Object { $_ -and -not $_.StartsWith('#') } |
            ForEach-Object { Write-Host "              $_" }
    } else {
        Write-Host "governing   : nothing (no allowlist -> gate is OFF)"
    }

    # Compare the wired matchers against the rules the INSTALLED script actually implements -- an
    # expectation, not a count. A count of "3" is not information unless you know whether 3 is right.
    $handled = @(Get-HandledTools $GateDst)
    foreach ($cd in $ConfigDir) {
        $sp = Join-Path $cd "settings.json"
        $s = Read-Settings $sp
        $wired = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($e in @($s.hooks.PreToolUse)) {
            if (@($e.hooks) | Where-Object { "$($_.command)" -like "*$Marker*" }) {
                foreach ($t in "$($e.matcher)".Split("|")) { if ($t) { $null = $wired.Add($t) } }
            }
        }
        # Rules that are deliberately unwired are reported as such, never as UNWIRED. A status line that
        # cries wolf about a known-and-intended state is one a reader learns to skip, which is how a real
        # UNWIRED would go unnoticed -- the exact failure this whole block exists to surface.
        $optIn   = @("EnterWorktree")
        $absent  = @($handled | Where-Object { -not $wired.Contains($_) })
        $missing = @($absent  | Where-Object { $optIn -notcontains $_ } | Sort-Object)
        $offByChoice = @($absent | Where-Object { $optIn -contains $_ } | Sort-Object)
        $stray   = @($wired   | Where-Object { $handled -notcontains $_ } | Sort-Object)
        Write-Host "wiring      : $sp"
        Write-Host "              matched  : $(@($wired | Sort-Object) -join ', ')"
        if ($offByChoice) {
            Write-Host "              opt-in   : $($offByChoice -join ', ')  <- off by default, add -EnterWorktreeGate to enable"
        }
        if ($missing) {
            Write-Host "              UNWIRED  : $($missing -join ', ')  <- implemented but NEVER FIRES" -ForegroundColor Yellow
        }
        if ($stray) {
            Write-Host "              stray    : $($stray -join ', ')  <- matched but the script ignores it" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "scanned $($ConfigDir.Count) config dir(s) against $(@($handled).Count) implemented rule(s)."
    return
}

if ($env:CLAUDECODE -eq "1") {
    throw "Refusing to run inside Claude Code. A session that can install this gate can also remove it. Run from a plain pwsh terminal. (-Status is allowed from a session: auditing is not installing.)"
}

# --------------------------------------------------------------------------------------- uninstall
if ($Uninstall) {
    foreach ($cd in $ConfigDir) {
        $sp = Join-Path $cd "settings.json"
        if (-not (Test-Path -LiteralPath $sp)) { continue }
        Write-Settings $sp (Remove-GateHooks (Read-Settings $sp))
    }
    Remove-Item -LiteralPath $ReposFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GateDst   -Force -ErrorAction SilentlyContinue
    Write-Host "Worktree gate REMOVED from $($ConfigDir.Count) config dir(s). Sessions are no longer gated (takes effect immediately)." -ForegroundColor Yellow
    return
}

# ----------------------------------------------------------------------------------------- install
if (-not $Repo -or $Repo.Count -eq 0) {
    # Default to the MAIN worktree, not to wherever this script happens to be running from. You will
    # usually install from a worktree (that is the whole point of the gate), and governing that worktree
    # instead of the primary would be exactly backwards.
    $main = (& git -C $RepoRoot worktree list --porcelain 2>$null |
                Select-String -Pattern '^worktree (.+)$' |
                Select-Object -First 1).Matches[0].Groups[1].Value
    $Repo = @(if ($main) { $main } else { $RepoRoot })
}

$resolved = foreach ($r in $Repo) {
    $p = (Resolve-Path -LiteralPath $r -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $p ".git"))) { throw "Not a git checkout: $p" }
    $p
}

New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null
Copy-Item -LiteralPath (Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1") -Destination $GateDst -Force

@(
    "# Primary checkouts governed by the worktree gate (scripts\hooks\worktree_gate.ps1)."
    "# Writes INTO these trees are denied; a linked worktree may not be switched onto an existing branch."
    "# Deleting this file turns the gate OFF everywhere, immediately."
    $resolved
) | Set-Content -LiteralPath $ReposFile -Encoding utf8

$command = "pwsh -NoProfile -File `"$GateDst`""

# One matcher per rule in scripts/hooks/worktree_gate.ps1. A rule the hook implements but that is not
# matched here NEVER FIRES -- the hook is simply not invoked for that tool, and nothing says so. Rule 3
# shipped in exactly that state. tests/test_install_gate_wiring.py now asserts that every tool the script
# branches on appears in this list, so the two cannot drift apart again. (Rule 3b -- worktree hijack --
# rides the same Bash|PowerShell matcher as rule 3, so it needs no new tool here.)
$matchers = @(
    "Write|Edit|MultiEdit|NotebookEdit"   # rule 1 -- writes INTO the primary's tree
    "Bash|PowerShell"                     # rules 3 + 3b -- git verbs that swap the primary / hijack a worktree
)
if (-not $NoDispatchGate) {
    $matchers += "Task|Agent|Workflow"    # rule 2 -- subagent dispatch FROM the primary
}
if ($EnterWorktreeGate) {
    $matchers += "EnterWorktree"          # rule 4 -- OPT-IN, see the parameter's note for why
}

$entries = foreach ($m in $matchers) {
    [ordered]@{
        matcher = $m
        hooks   = @([ordered]@{
            type          = "command"
            command       = $command
            timeout       = 15
            statusMessage = "Checking worktree gate"
        })
    }
}

# Wire (idempotently) into every target config dir. Each file is read-modified-written independently with
# its own backup/validate/rollback, so a failure on one account cannot corrupt another.
foreach ($cd in $ConfigDir) {
    $sp = Join-Path $cd "settings.json"
    $data = Remove-GateHooks (Read-Settings $sp)   # idempotent: drop our old entries, then re-add
    if (-not $data.hooks)            { $data.hooks = [ordered]@{} }
    if (-not $data.hooks.PreToolUse) { $data.hooks.PreToolUse = @() }
    $data.hooks.PreToolUse = @($data.hooks.PreToolUse) + @($entries)
    Write-Settings $sp $data
    Write-Host "  wired : $sp"
}

Write-Host ""
Write-Host "Worktree gate INSTALLED into $($ConfigDir.Count) config dir(s) (every session, no restart)." -ForegroundColor Green
Write-Host "  gate      : $GateDst"
Write-Host "  allowlist : $ReposFile"
$resolved | ForEach-Object { Write-Host "  governing : $_" }
Write-Host "  matchers  : $($matchers -join '  +  ')"
Write-Host ""
Write-Host "Writes into a governed tree are DENIED; a linked worktree may not be switched onto an existing branch."
Write-Host "To turn it off:  pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall"
