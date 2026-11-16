# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# No parameter block: forward native arguments, including script-specific flags, unchanged.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

function Resolve-BridgePython {
    $python = Join-Path $root '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $python)) {
        $python = Join-Path $root '.venv/bin/python'
    }
    if (-not (Test-Path -LiteralPath $python)) {
        throw 'Create this worktree''s .venv first; see docs/WORKTREES.md.'
    }
    $python
}

if ($args.Count -gt 0 -and $args[0] -eq 'hook') {
    # The bridge decides with exit 0, or with 10 (BLOCK_EXIT in bridge.py) for a block, which
    # becomes 2 here. Anything else, a missing .venv, a crash, or the 2 that Python and argparse
    # exit with, is no decision: it blocks on the PreToolUse registration and is a non-blocking 1
    # on every other event. docs/CODEX.md, "Who decides a block", states the rule.
    $noDecision = 1
    for ($i = 1; $i -lt $args.Count - 1; $i++) {
        if ($args[$i] -eq '--event' -and $args[$i + 1] -eq 'PreToolUse') { $noDecision = 2 }
    }
    $code = $noDecision
    try {
        & (Resolve-BridgePython) (Join-Path $PSScriptRoot 'bridge.py') @args
        if ($LASTEXITCODE -eq 0) { $code = 0 } elseif ($LASTEXITCODE -eq 10) { $code = 2 }
    } catch {
        [Console]::Error.WriteLine("Codex bridge launcher: $_")
    }
    # Codex starts this through pwsh -Command, which reports a script's exit 2 as 1. Ending the
    # process keeps the code. Hook mode only: an interactive caller's window must survive `run`.
    [Environment]::Exit($code)
}

& (Resolve-BridgePython) (Join-Path $PSScriptRoot 'bridge.py') @args
exit $LASTEXITCODE
