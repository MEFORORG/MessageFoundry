<#
.SYNOPSIS
    Install the ledger gate as a pre-commit hook in the SHARED .git/hooks — one copy governs every
    worktree at once.

.DESCRIPTION
    `.git/hooks` lives in the COMMON git directory, which every linked worktree shares. So a single file
    there:

      * reaches ALL worktrees the instant it is written -- no branch, no merge, no propagation lag (a
        hook committed to a branch protects nothing until every other worktree merges it);
      * survives a branch switch in any of them (it sits outside every working tree); and
      * sees EVERY write route -- the Edit tool, a shell redirect, Set-Content, python -c, VS Code, a
        subagent -- because it inspects the TREE at commit time, not a tool call.

    That last property is why this exists alongside the worktree gate (scripts/hooks/worktree_gate.ps1):
    the worktree gate inspects tool arguments, so a file written by a shell command is invisible to it.
    This is that backstop.

    The hook shells to `python scripts/hooks/ledger_check.py`, which is stdlib-only and imports nothing
    from messagefoundry -- most worktrees have no .venv, and a gate that silently skips is worse than no
    gate at all. If python is missing entirely it prints a loud warning and lets the commit through
    (fail-open); CI re-runs the same rules with --ci, so nothing reaches main unchecked.

    Run from a plain terminal. `git commit --no-verify` bypasses it -- that is a guardrail, not a security
    boundary, and the --ci leg is the backstop for exactly that.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1
    pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Status
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$common = (& git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir).Trim()
if (-not $common) { throw "Not inside a git repository." }

$hooksPath = (& git -C $RepoRoot config --get core.hooksPath)
if ($hooksPath) {
    $hooksDir = if ([System.IO.Path]::IsPathRooted($hooksPath)) { $hooksPath } else { Join-Path $RepoRoot $hooksPath }
} else {
    $hooksDir = Join-Path $common "hooks"
}
$preCommit = Join-Path $hooksDir "pre-commit"
$marker = "MessageFoundry ledger gate"
# BACKLOG #309: the claim gate must be a COMMIT-MSG hook, not pre-commit -- pre-commit never receives the
# commit message, so a claim check bolted onto it would look installed and silently never fire.
$commitMsg = Join-Path $hooksDir "commit-msg"
$claimMarker = "MessageFoundry claim gate"

if ($Status) {
    $installed = (Test-Path $preCommit) -and ((Get-Content $preCommit -Raw -EA SilentlyContinue) -match [regex]::Escape($marker))
    $claimInstalled = (Test-Path $commitMsg) -and ((Get-Content $commitMsg -Raw -EA SilentlyContinue) -match [regex]::Escape($claimMarker))
    Write-Host "hooks dir  : $hooksDir"
    Write-Host "pre-commit : $(if ($installed) { 'INSTALLED (ledger gate)' } elseif (Test-Path $preCommit) { 'present, but NOT ours' } else { 'not installed' })"
    Write-Host "commit-msg : $(if ($claimInstalled) { 'INSTALLED (claim gate)' } elseif (Test-Path $commitMsg) { 'present, but NOT ours' } else { 'not installed' })"
    Write-Host "worktrees  : $(@(& git -C $RepoRoot worktree list).Count) share this hook"
    return
}

if ($Uninstall) {
    $removed = $false
    if ((Test-Path $preCommit) -and ((Get-Content $preCommit -Raw) -match [regex]::Escape($marker))) {
        Remove-Item -LiteralPath $preCommit -Force
        Write-Host "Ledger pre-commit hook REMOVED." -ForegroundColor Yellow
        $removed = $true
    }
    if ((Test-Path $commitMsg) -and ((Get-Content $commitMsg -Raw) -match [regex]::Escape($claimMarker))) {
        Remove-Item -LiteralPath $commitMsg -Force
        Write-Host "Claim commit-msg hook REMOVED." -ForegroundColor Yellow
        $removed = $true
    }
    if (-not $removed) { Write-Host "Nothing to remove (no MessageFoundry hooks installed)." }
    return
}

if ((Test-Path $preCommit) -and ((Get-Content $preCommit -Raw) -notmatch [regex]::Escape($marker))) {
    throw "A pre-commit hook that is not ours already exists at $preCommit. Refusing to overwrite it -- merge them by hand."
}
if ((Test-Path $commitMsg) -and ((Get-Content $commitMsg -Raw) -notmatch [regex]::Escape($claimMarker))) {
    throw "A commit-msg hook that is not ours already exists at $commitMsg. Refusing to overwrite it -- merge them by hand."
}

New-Item -ItemType Directory -Force -Path $hooksDir | Out-Null

# Resolve the checker from the COMMON dir, not from a working tree: a worktree can be on any branch (or a
# detached HEAD), and a hook that points into one would break the moment that branch lacks the file.
Copy-Item (Join-Path $RepoRoot "scripts\hooks\ledger_check.py") (Join-Path $hooksDir "ledger_check.py") -Force

# LF endings and no BOM: git runs this through sh, which chokes on CRLF.
$hook = @'
#!/bin/sh
# MessageFoundry ledger gate -- INSTALLED COPY. Source: scripts/hooks/ledger_check.py
# Lives in the SHARED .git/hooks, so ONE copy governs every worktree, survives any branch switch, and
# fires for EVERY write route (Edit tool, shell redirect, VS Code, a subagent) -- it inspects the staged
# TREE, not a tool call.
# Re-install after changing the source:  pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1
HOOK_DIR=$(dirname "$0")
PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "MessageFoundry: python not found -- THE LEDGER GATE IS OFF for this commit." >&2
  exit 0
fi
exec "$PY" "$HOOK_DIR/ledger_check.py"
'@ -replace "`r`n", "`n"

[System.IO.File]::WriteAllText($preCommit, $hook, (New-Object System.Text.UTF8Encoding $false))

# --- claim gate (BACKLOG #309) -------------------------------------------------------------------
# A commit-msg hook, because only commit-msg is handed the message file (as $1). The claim gate keys off
# the SUBJECT declaring `BACKLOG #N`, so on pre-commit it would have nothing to read.
Copy-Item (Join-Path $RepoRoot "scripts\hooks\claim_check.py") (Join-Path $hooksDir "claim_check.py") -Force

$claimHook = @'
#!/bin/sh
# MessageFoundry claim gate -- INSTALLED COPY. Source: scripts/hooks/claim_check.py
# commit-msg (NOT pre-commit): only this hook receives the message file, and the gate reads the subject.
# Re-install after changing the source:  pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1
HOOK_DIR=$(dirname "$0")
PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "MessageFoundry: python not found -- THE CLAIM GATE IS OFF for this commit." >&2
  exit 0
fi
exec "$PY" "$HOOK_DIR/claim_check.py" "$1"
'@ -replace "`r`n", "`n"

[System.IO.File]::WriteAllText($commitMsg, $claimHook, (New-Object System.Text.UTF8Encoding $false))

# Git for Windows does not need the exec bit, but a WSL/Linux checkout of the same repo would.
if ($IsLinux -or $IsMacOS) { & chmod +x $preCommit; & chmod +x $commitMsg }

Write-Host ""
Write-Host "MessageFoundry git hooks INSTALLED." -ForegroundColor Green
Write-Host "  pre-commit: $preCommit"
Write-Host "              $(Join-Path $hooksDir 'ledger_check.py')  (ledger gate)"
Write-Host "  commit-msg: $commitMsg"
Write-Host "              $(Join-Path $hooksDir 'claim_check.py')   (claim gate, BACKLOG #309)"
Write-Host "  governs   : all $(@(& git -C $RepoRoot worktree list).Count) worktree(s) of this repo, immediately"
Write-Host ""
Write-Host "Ledger gate: blocks a commit that reuses an ADR/BACKLOG number, or adds an ADR with no index row."
Write-Host "Claim gate : blocks a CODE commit whose subject says 'BACKLOG #N' unless THIS worktree claims N,"
Write-Host "             so two sessions cannot build the same item in parallel. Docs-only commits pass."
Write-Host ""
Write-Host "Allocate numbers with:  pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title `"<title>`""
Write-Host "Claim work with:        pwsh -NoProfile -File scripts\coord\claim.ps1 -Take <key> -Note `"<what>`""
Write-Host "See who holds what:     pwsh -NoProfile -File scripts\coord\claim.ps1 -List"
Write-Host "Remove with:            pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Uninstall"
