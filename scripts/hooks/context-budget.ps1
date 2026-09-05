# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
# UserPromptSubmit hook: report how much of THIS SESSION'S CONTEXT WINDOW is spent, and warn a seat
# before it runs out of room. Reads the tool-call JSON on stdin, opens the transcript the harness
# names there, and takes the token counts from the last assistant message's usage object.
#
# WHAT THIS MEASURES, AND WHAT IT DOES NOT. This is the CONTEXT WINDOW of one session -- how full
# the conversation is. It is NOT account pool headroom, which is what usage-headroom-inject.ps1
# reads and reports. The two are different quantities that both get called "usage", and a seat with
# a fresh pool can still be one turn from a compaction. Adopted from gastown's
# scripts/guards/context-budget-guard.sh (BACKLOG #1453); the thresholds below are theirs.
#
# WHY A BUILDER NEEDS IT. A Builder gets one turn and cannot ask for another. CLAUDE.md tells it not
# to keep grinding in a polluted context, but nothing tells it the context IS polluted, so the rule
# has no trigger. This is the trigger.
#
# FAIL-OPEN ON EVERY PATH. The transcript JSONL shape is a Claude Code implementation detail that can
# change without notice. If anything here cannot be read, parsed or found, the hook says nothing and
# exits 0. A guard that wedges a turn is worse than a guard that misses one.
#
# THIS HOOK DOES NOT BLOCK. gastown's original hard-gates named roles at 0.92. Ours only reports,
# because a KORUS Builder that gets blocked at its prompt has no way to ask for relief and no next
# turn in which to be told -- blocking it would burn the brief rather than save it. The decision to
# stop is left to the seat reading the warning.
#
# WIRING IS NOT ASSERTED HERE ON PURPOSE. Whether this script is referenced by a UserPromptSubmit
# matcher is a property of settings.json, not of this file.
# See docs/WORKTREES.md.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Thresholds, overridable per seat. Carried from gastown's guard so the numbers have a provenance
# rather than being invented here.
function Get-Threshold {
    param([string]$Name, [double]$Default)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if (-not $v) { return $Default }
    $parsed = 0.0
    if ([double]::TryParse($v, [ref]$parsed) -and $parsed -gt 0 -and $parsed -le 1) { return $parsed }
    return $Default
}

function Write-Context {
    param([string]$Text)
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{
            hookEventName    = 'UserPromptSubmit'
            additionalContext = $Text
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
}

try {
    if ($env:MEFOR_CONTEXT_BUDGET_DISABLE -eq '1') { exit 0 }

    $warn = Get-Threshold 'MEFOR_CONTEXT_BUDGET_WARN' 0.75
    $soft = Get-Threshold 'MEFOR_CONTEXT_BUDGET_SOFT' 0.85
    $hard = Get-Threshold 'MEFOR_CONTEXT_BUDGET_HARD' 0.92

    $maxTokens = 200000
    if ($env:MEFOR_CONTEXT_BUDGET_MAX_TOKENS) {
        $parsed = 0
        if ([int]::TryParse($env:MEFOR_CONTEXT_BUDGET_MAX_TOKENS, [ref]$parsed) -and $parsed -gt 0) {
            $maxTokens = $parsed
        }
    }

    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $j = $raw | ConvertFrom-Json

    # An explicit override exists so the guard can be tested without a transcript, and so a caller
    # that already knows the count does not pay for a re-parse.
    $used = 0
    if ($env:MEFOR_CONTEXT_BUDGET_TOKENS) {
        $parsed = 0
        if ([int]::TryParse($env:MEFOR_CONTEXT_BUDGET_TOKENS, [ref]$parsed)) { $used = $parsed }
    }

    if ($used -le 0) {
        $tp = [string]$j.transcript_path
        if (-not $tp -or -not (Test-Path -LiteralPath $tp)) { exit 0 }

        # Walk BACKWARDS. The last assistant message carries the running total, so reading the whole
        # file forward and keeping the last hit costs the entire transcript on every prompt. A long
        # session's transcript is tens of megabytes and this hook runs on every turn.
        $lines = [System.IO.File]::ReadAllLines($tp)
        for ($i = $lines.Length - 1; $i -ge 0; $i--) {
            $line = $lines[$i]
            if (-not $line -or $line -notmatch '"usage"') { continue }
            try { $rec = $line | ConvertFrom-Json } catch { continue }
            $u = $rec.message.usage
            if (-not $u) { continue }
            # input_tokens EXCLUDES the cached prefix, and the cache is most of a long session, so
            # input alone reads as a nearly-empty window on the fullest sessions. Sum all four.
            foreach ($f in 'input_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens', 'output_tokens') {
                $val = $u.PSObject.Properties[$f]
                if ($val -and $val.Value) { $used += [int]$val.Value }
            }
            if ($used -gt 0) { break }
        }
    }

    if ($used -le 0) { exit 0 }

    $frac = [double]$used / [double]$maxTokens
    if ($frac -lt $warn) { exit 0 }

    $pct = [math]::Round($frac * 100, 1)
    $k = [math]::Round($used / 1000.0, 1)

    if ($frac -ge $hard) {
        $level = 'HARD'
        $advice = 'Stop taking new work. Push what is green, write the PR body, and say in it what is unfinished. A fresh seat with a better brief beats one more turn here.'
    } elseif ($frac -ge $soft) {
        $level = 'SOFT'
        $advice = 'Finish the change in hand and push. Do not start a new line of investigation in this session.'
    } else {
        $level = 'WARN'
        $advice = 'Land what you can before a compaction. A compaction drops the seat, the goal and the brief, and nothing re-declares them for you.'
    }

    Write-Context "[context-budget] $level -- this session's CONTEXT WINDOW is ${pct}% spent (about ${k}k of $($maxTokens / 1000)k tokens). $advice This is the conversation's own window, NOT account pool headroom; a full pool does not buy room here."
    exit 0
} catch {
    # Fail open, always. See the header.
    exit 0
}
