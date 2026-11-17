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
# The bridge exits 10 (BLOCK_EXIT in bridge.py) for a hook's exit 2 only where this flag is set,
# and only under the same condition as the mapping below. It pops the flag, so no child sees it.
$env:MEFOR_CODEX_BLOCK_SENTINEL = if ($args[0] -eq 'hook') { '1' } else { $null }
& $python (Join-Path $PSScriptRoot 'bridge.py') @args
$env:MEFOR_CODEX_BLOCK_SENTINEL = $null
# Ending the process keeps the block as 2, which the caller's pwsh -Command would report as 1.
# Hook mode only, so a caller's window survives `run`.
if ($LASTEXITCODE -eq 10 -and $args[0] -eq 'hook') { [Environment]::Exit(2) }
exit $LASTEXITCODE
