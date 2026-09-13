# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

    # THE WINDOW IS RESOLVED, NEVER GUESSED. There is no default, and that absence is the fix.
    #
    # WHAT WENT WRONG WHEN THERE WAS ONE. This hook shipped with $maxTokens = 200000 as a default.
    # Nothing on this machine ever set the override, the model's real window is 1,000,000, and so
    # every percentage this hook printed was five times too large. Measured 2026-09-13: a session
    # holding 190.3k tokens -- 19 percent of its window -- was told it was at 95 percent, three turns
    # running. The seat believed it, told a peer it was about to go quiet, and the peer began
    # sequencing around a handoff that was not going to happen.
    #
    # THE GUARD BELOW ONLY CATCHES A CEILING THAT IS TOO SMALL, AND ONLY WHILE THE COUNT EXCEEDS IT.
    # That is why the wrong number survived. Before a compaction the count was 871k against the
    # assumed 200k, the impossibility fired, and the ceiling was correctly reported as wrong. The
    # compaction then dropped the count to 178k -- back under the false ceiling -- and the same wrong
    # denominator started producing 89, 93 and 95 percent with no alarm at all. A compaction converted
    # a correctly-alarming instrument into a confidently-wrong one.
    #
    # A CEILING CANNOT BE VALIDATED FROM BELOW. No arithmetic over the token count can tell a correct
    # window from one that is too large; the percentage just comes out small and plausible. So the
    # only honest options are to KNOW the window or to report no percentage, and this hook now does
    # exactly that. Do not reintroduce a default to make the gauge look complete.
    $maxTokens = 0
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
    $modelId = ''
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
            # The SAME record carries the model that produced it, so resolving the window costs
            # nothing extra -- no second pass, no second file. Measured 2026-09-13 on a live
            # transcript: 1,256 of 1,260 usage-bearing records name a real model and the record this
            # walk lands on is one of them. The other four say "<synthetic>", which is not a model
            # and must not match the table below.
            if (-not $modelId -and $rec.message.model) { $modelId = [string]$rec.message.model }
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

    $k = [math]::Round($used / 1000.0, 1)

    # SECOND SOURCE: the model that wrote the transcript. Claude Code hands the STATUS LINE a
    # resolved context_window_size and hands a HOOK neither the window nor the model, so this walks
    # back to the model id in the transcript and maps it. Reported upstream; see the PR.
    #
    # AN ABSENT ENTRY IS SAFE, AND THAT IS THE DESIGN. A model this table does not know falls
    # through to the no-percentage branch below, so the table may be incomplete or out of date
    # without ever producing a wrong figure. It can only add correctness. THE ONE CHANGE THAT WOULD
    # BREAK THAT IS GIVING IT A FALLBACK -- do not add an "else 200000", which is the exact defect
    # this file was rewritten to remove.
    #
    # The windows differ across the roster, which is why one constant could never have worked:
    # measured 2026-09-13 against the shipped build's own model registry, eight entries are 200k and
    # eight are 1M. An operator override still wins over everything here.
    if ($maxTokens -le 0 -and $modelId) {
        # A "[1m]" suffix on any model id means the 1M variant, and it is checked first because it
        # overrides whatever the base id would otherwise map to.
        if ($modelId -match '\[1m\]') {
            $maxTokens = 1000000
        } else {
            switch -Regex ($modelId) {
                '^claude-(opus-5|sonnet-5|fable-5|mythos-5)' { $maxTokens = 1000000; break }
                '^claude-opus-4-(7|8)'                       { $maxTokens = 1000000; break }
                '^claude-haiku-4-5'                          { $maxTokens = 200000;  break }
                '^claude-(opus|sonnet)-4'                    { $maxTokens = 200000;  break }
                default { }
            }
        }
    }

    # WINDOW UNKNOWN. Report the absolute count, which is measured, and NO percentage, which would be
    # invented. The absolute number is still worth printing -- a seat that knows it is holding 190k
    # tokens can judge for itself -- and naming the one-line fix is what eventually removes this
    # branch. What must never happen again is a confident percentage over an assumed denominator.
    if ($maxTokens -le 0) {
        $seen = if ($modelId) { "Model '$modelId' is not in this hook's window table." }
                else { 'No model id was found in the transcript.' }
        Write-Context ("[context-budget] NO WINDOW RESOLVED, so no fullness figure is given -- one " +
            "would be a percentage of a guess. This session holds about ${k}k tokens. That is the " +
            "measured part; whether it is nearly full depends on a window this hook could not " +
            "determine. $seen Set MEFOR_CONTEXT_BUDGET_MAX_TOKENS to this model's real window, or " +
            "add the model to the table in this hook. This is the conversation's own window, NOT " +
            "account pool headroom.")
        exit 0
    }

    $frac = [double]$used / [double]$maxTokens

    # A CONFIGURED CEILING CAN STILL BE WRONG, and this catches the half of that which is catchable.
    # There is no default any more -- reaching here means an operator set MEFOR_CONTEXT_BUDGET_MAX_TOKENS
    # -- but a set value can be stale, copied from another model, or simply mistyped. When the count
    # exceeds it the ARITHMETIC is not what failed, the ceiling is, and printing "172.9% spent" is a
    # percentage of the wrong thing.
    #
    # READ THIS AS THE HALF-GUARD IT IS. It fires only for a ceiling that is TOO SMALL, and only while
    # the count is above it -- so it is silent for a ceiling that is too LARGE, and it goes silent
    # again the moment a compaction drops the count back underneath. Both silences have been paid for
    # here: the too-large case is the 2026-09-13 defect described where the window is resolved above,
    # and the compaction case is why that defect survived three turns. An impossible number is
    # visible; a merely wrong one is believed. Report the absolute figure and name the fix.
    if ($frac -gt 1.0) {
        Write-Context ("[context-budget] CEILING WRONG, not a reading. This session reports about ${k}k " +
            "tokens against an assumed $($maxTokens / 1000)k window, which is impossible as a percentage " +
            "-- so the assumed window is wrong for this model, not the count. No fullness figure is " +
            "given because none can be trusted. The session IS large; treat that as the signal. Set " +
            "MEFOR_CONTEXT_BUDGET_MAX_TOKENS to this model's real window to restore the gauge.")
        exit 0
    }

    if ($frac -lt $warn) { exit 0 }

    $pct = [math]::Round($frac * 100, 1)

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
