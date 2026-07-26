# Queue a mid-task steering note for the Claude Code session running in this repo.
#
# Pairs with scripts/hooks/steer-inject.ps1 (a PreToolUse hook, opt-in -- see docs/STEERING.md).
# Run this from a SECOND terminal while a session is mid-task; the note is delivered at that
# session's next tool-call boundary instead of waiting for the turn to end.
#
# ASCII-only on purpose: a note is read back by a hook that must not depend on console encoding.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Message,

    # The worktree to steer. Defaults to the repo containing the current directory, which is what
    # you want when you are already standing in the worktree whose session you mean to steer.
    [string]$ProjectDir
)

$ErrorActionPreference = 'Stop'

function Resolve-ProjectDir {
    param([string]$Explicit)

    if ($Explicit) { return (Resolve-Path -LiteralPath $Explicit).Path }
    if ($env:CLAUDE_PROJECT_DIR) { return $env:CLAUDE_PROJECT_DIR }

    # Fall back to the enclosing worktree root. NOT `Get-Location`: the hook only ever reads
    # <project root>/.claude/steer.txt, so writing relative to an arbitrary CWD drops the note
    # somewhere nothing looks -- silently, while also littering a stray .claude directory.
    $root = & git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -eq 0 -and $root) { return $root.Trim() }

    throw "Not inside a git worktree and no -ProjectDir given: refusing to guess where the session is."
}

$projectRoot = Resolve-ProjectDir -Explicit $ProjectDir
$claudeDir = Join-Path $projectRoot ".claude"

# The directory must already exist: every real worktree has one. Creating it here is how the old
# version turned a wrong-directory invocation into a stray .claude that silently swallowed notes.
if (-not (Test-Path -LiteralPath $claudeDir -PathType Container)) {
    throw "No .claude directory at $projectRoot -- is that really a Claude Code worktree?"
}

$noteFile = Join-Path $claudeDir "steer.txt"
if (Test-Path -LiteralPath $noteFile) {
    Write-Warning "A steering note was already queued and not yet consumed; replacing it."
}

Set-Content -LiteralPath $noteFile -Value $Message -NoNewline -Encoding utf8

Write-Host "Queued steering note for the Claude Code session in ${projectRoot}:"
Write-Host "  `"$Message`""
Write-Host "It is delivered at the session's next tool-call boundary -- but ONLY if that worktree"
Write-Host "has the PreToolUse hook enabled (it is opt-in; see docs/STEERING.md)."
