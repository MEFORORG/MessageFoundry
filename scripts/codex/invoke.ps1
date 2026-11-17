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

# The subcommand is the first argument that is not an option, as bridge.py's argparse reads it, so
# `--session-id S hook` is hook mode too and never returns the bridge's raw block code.
$mode = $null
for ($i = 0; $i -lt $args.Count; $i++) {
    $word = [string]$args[$i]
    if ($word -notlike '-*') { $mode = $word; break }
    # argparse takes any unambiguous prefix of --session-id, and it consumes the next argument.
    if ($word -notlike '*=*' -and $word.Length -ge 3 -and '--session-id'.StartsWith($word, [StringComparison]::Ordinal)) { $i++ }
}
if ($mode -eq 'hook') {
    # 10 (BLOCK_EXIT in bridge.py) becomes 2 here.
    # With this preference on, the bridge's block exit 10 would throw and read as no decision.
    $PSNativeCommandUseErrorActionPreference = $false
    $code = 1
    $why = ''
    try {
        & (Resolve-BridgePython) (Join-Path $PSScriptRoot 'bridge.py') @args
        if ($LASTEXITCODE -eq 0) { $code = 0 } elseif ($LASTEXITCODE -eq 10) { $code = 2 }
        else { $why = "the bridge exited $LASTEXITCODE" }
    } catch {
        $why = "$_"
    }
    if ($code -eq 1) {
        $message = "Codex bridge launcher: no decision, not blocking: $why"
        [Console]::Error.WriteLine($message)
        [Console]::Out.WriteLine((@{ systemMessage = $message } | ConvertTo-Json -Compress))
    }
    # Codex starts this through pwsh -Command, which reports a script's exit 2 as 1. Ending the
    # process keeps the code. Hook mode only: an interactive caller's window must survive `run`.
    [Environment]::Exit($code)
}

& (Resolve-BridgePython) (Join-Path $PSScriptRoot 'bridge.py') @args
exit $LASTEXITCODE
