# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# No parameter block: forward native arguments, including script-specific flags, unchanged, plus
# `--block-exit 10` in hook mode.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$python = Join-Path $root '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    $python = Join-Path $root '.venv/bin/python'
}
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Create this worktree''s .venv first; see docs/WORKTREES.md.'
}
# Only where `hook` is the first argument, the bridge exits 10 for a hook's exit 2 (--block-exit in
# bridge.py), and the mapping below ends the process with 2 for it.
$hookMode = $args[0] -ceq 'hook'
$blockExit = 10
# Assigned, never from an if expression, which would unroll a one-element array to a string.
$bridgeArgs = @($args)
if ($hookMode) { $bridgeArgs += '--block-exit', "$blockExit" }
& $python (Join-Path $PSScriptRoot 'bridge.py') @bridgeArgs
# Ending the process keeps the block as 2, which the caller's pwsh -Command would report as 1.
# Hook mode only, so a caller's window survives `run`.
if ($hookMode -and $LASTEXITCODE -eq $blockExit) { [Environment]::Exit(2) }
exit $LASTEXITCODE
