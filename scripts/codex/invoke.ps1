# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# No parameter block: forward native arguments, including script-specific flags, unchanged.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$python = Join-Path $root '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    $python = Join-Path $root '.venv/bin/python'
}
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Create this worktree''s .venv first; see docs/WORKTREES.md.'
}
& $python (Join-Path $PSScriptRoot 'bridge.py') @args
# Codex starts a hook as pwsh -Command, which reports a script's exit 2 as 1, so a block would
# reach Codex as 1. Ending the process keeps the code. Hook mode only: an interactive caller's
# window must survive `run`.
if ($args.Count -gt 0 -and $args[0] -eq 'hook') { [Environment]::Exit($LASTEXITCODE) }
exit $LASTEXITCODE
