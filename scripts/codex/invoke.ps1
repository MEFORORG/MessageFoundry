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
# The bridge exits 10 (BLOCK_EXIT in bridge.py) for a hook block only where this flag is set, and
# it is set only in hook mode, where the mapping below ends the process with 2. The bridge pops it,
# so no child sees it; the finally keeps it out of a caller's session.
$hookMode = $args[0] -ceq 'hook'
$env:MEFOR_CODEX_BLOCK_SENTINEL = if ($hookMode) { '1' } else { $null }
try {
    & $python (Join-Path $PSScriptRoot 'bridge.py') @args
} finally {
    $env:MEFOR_CODEX_BLOCK_SENTINEL = $null
}
# Ending the process keeps the block as 2, which the caller's pwsh -Command would report as 1.
# Hook mode only, so a caller's window survives `run`.
if ($hookMode -and $LASTEXITCODE -eq 10) { [Environment]::Exit(2) }
exit $LASTEXITCODE
