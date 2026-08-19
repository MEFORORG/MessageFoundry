# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    PreToolUse gate: refuse to edit a file another LIVE session is already changing.

.DESCRIPTION
    Worktrees stop two sessions from overwriting each other's bytes. They do NOT stop two sessions
    from editing the same file in parallel and discovering it at merge -- by which point both have
    built on divergent assumptions and someone's work is thrown away. This gate turns that from a
    merge-time surprise into an edit-time refusal, which is the only point where it is still cheap.

    NOTHING TO OPT INTO. It reads git state and the session registry, both by-products of working
    normally. That is the whole design: `claim.ps1` has existed for some time and has been used
    exactly ZERO times, because a coordination step you must remember is one you will skip. A guard
    that needs cooperation to work does not work.

    ONLY LIVE SESSIONS BLOCK. A dormant worktree with changes cannot be racing you -- its owner is not
    typing -- so it is reported and allowed. Blocking on dormant worktrees would deny edits to every
    file any abandoned branch ever touched, and a gate that cries wolf gets uninstalled.

    FAILS OPEN, DELIBERATELY. Any error -- unparseable payload, no git, no registry, a broken overlap
    script -- exits 0 and allows the edit. This gate prevents rework; it must never be the reason a
    session cannot work. That is the opposite of the worktree gate's posture (which protects the
    shared tree and should fail closed), and the difference is intentional.

    FAILS OPEN, BUT NOT SILENTLY. Every one of those error paths used to `exit 0` with no output, which
    on stdout is byte-for-byte what "checked, nobody else is touching this file" looks like. So a gate
    that had checked NOTHING was indistinguishable from a gate reporting all-clear, and a session could
    read the absence of a warning as evidence -- while the guard was inert. An unresolved run now says
    so via additionalContext. It still allows: the posture is unchanged, only the silence is.

    Rate-limited per reason (`-NoticeCooldownMinutes`), because a persistently broken overlap script
    would otherwise inject a notice into EVERY Edit and Write. If the throttle state cannot be read or
    written the notice is emitted anyway -- silence is the defect being fixed, so the fallback is noise.

    Wired on Edit|Write|MultiEdit|NotebookEdit. The overlap map is cached, so the common case is a
    cache read, not a git walk across every worktree.
#>
[CmdletBinding()]
param(
    # Overlap script to consult. Parameterised so tests drive the REAL gate against a fixture rather
    # than re-implementing its rule -- a test that asserts a copy of the rule proves nothing.
    [string]$OverlapScript = (Join-Path $PSScriptRoot "..\coord\overlap.ps1"),
    # Emit the decision and skip reading stdin (tests).
    [string]$PathOverride,
    # Where the per-reason "already told them" stamps live. Defaults to the repo's coordination dir.
    # Parameterised so tests are isolated from the real repo AND from each other -- a throttle sharing
    # one directory with the suite would make the first test's notice suppress the second's.
    [string]$StateDir,
    # How long one unresolved reason stays quiet after being reported.
    [int]$NoticeCooldownMinutes = 30
)

# No $ErrorActionPreference = Stop: this gate fails OPEN, and a throw would be a deny-by-crash.
$ErrorActionPreference = "SilentlyContinue"

# Fold a CALLER-SUPPLIED value before it goes into a deny reason or an additionalContext notice.
#
# BACKLOG #1040 was filed against the worktree gate, and its closing sentence is the reason this exists
# here too: "every hook in scripts/hooks/ that emits a remediation an agent is told to run has this
# shape -- the gate is where it was noticed, not where it is confined." Measured on THIS gate: a
# PreToolUse payload whose file_path carried embedded newlines produced a notice with TWO
# "Before overriding:" blocks, the FORGED one FIRST, replacing the real `overlap.ps1` line with a
# command of the attacker's choosing. A model reading top-down reaches the forged one first. Nothing
# has to exist on disk -- only the JSON field -- so no other gate sees it either.
#
# THE VALUES ARE NOT ONLY THE PATH. The rows come from overlap.ps1, so Branch is a git refname and
# Worktree a directory name, and a refname is attacker-choosable from a public fork (`gh pr checkout`
# and `git fetch origin <ref>:<ref>` both create refs/heads/<their-name>). Work is free text from the
# session registry. All of them are folded, because deciding value by value is what left the last one
# bare.
#
# PROSE ONLY, and that is a statement about this file rather than a general rule. Every command this
# gate prints is a LITERAL with no interpolation in it, so there is no command-bound value here and no
# quoting helper. If a command line here ever gains an interpolation, folding is NOT the treatment for
# it -- see the worktree gate's Get-SafeForCommand, and keep the two named apart.
#
# A LOCAL COPY, deliberately, and the alternative is worse. worktree_gate.ps1 is installed OUTSIDE
# every working tree by install-gate.ps1, so it can dot-source nothing from a checkout; a shared module
# would therefore be importable by this hook and not by that one, which is two definitions of one rule
# that drift invisibly. Four lines duplicated, with the divergence visible to grep, beats that.
function Get-SafeForMessage([string]$Value) {
    $t = ("$Value" -replace '[\r\n\t]', ' ')
    if ($t.Length -gt 400) { return $t.Substring(0, 400) + '...' }
    return $t
}

function Deny([string]$Reason) {
    # The hookSpecificOutput wrapper is MANDATORY -- a bare permissionDecision is silently ignored,
    # which would leave this looking installed while permitting everything.
    $payload = @{
        hookSpecificOutput = @{
            hookEventName            = "PreToolUse"
            permissionDecision       = "deny"
            permissionDecisionReason = $Reason
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

function Write-Unresolved([string]$Slug, [string]$Detail) {
    # THE GATE DID NOT CHECK. Say so, and allow anyway.
    #
    # It must be a JSON hookSpecificOutput.additionalContext payload and never a bare line: this is a
    # PreToolUse hook whose stdout is PARSED AS A DECISION, so a stray line risks a misparse on every
    # single Edit and Write -- turning a diagnostic into a worse fault than the one it reports.
    #
    # No permissionDecision key: adding one here would convert a broken guard into a blocked session,
    # which is the fail-open posture inverted.
    $emit = $true
    try {
        $dir = $StateDir
        if (-not $dir) {
            $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
            if ($LASTEXITCODE -eq 0 -and $common) { $dir = Join-Path ([string]$common).Trim() "mefor-coord" }
        }
        if ($dir) {
            # PER WORKTREE, not per repo. The stamp lives in the SHARED git-common-dir, so a single
            # repo-wide stamp would mean the first session to hit a broken gate silences it for every
            # other session for the whole cooldown -- and those sessions would read that silence as
            # "checked, nobody is here", which is precisely the defect this notice exists to remove.
            # One session's diagnostic must never become another session's false all-clear.
            $who = "shared"
            $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
            if ($LASTEXITCODE -eq 0 -and $top) {
                $who = (Split-Path ([string]$top).Trim() -Leaf) -replace '[^A-Za-z0-9._-]+', '-'
                if (-not $who) { $who = "shared" }
            }
            $stamp = Join-Path $dir "gate-unresolved/$who.$Slug.stamp"
            $prev = Get-Item -LiteralPath $stamp -ErrorAction SilentlyContinue
            if ($prev) {
                $mins = ((Get-Date) - $prev.LastWriteTime).TotalMinutes
                # Bound BOTH ways. A stamp dated in the future (clock skew, a copied tree) would read as
                # eternally fresh and suppress this notice forever -- the same silence, now self-inflicted.
                if ($mins -ge 0 -and $mins -lt $NoticeCooldownMinutes) { $emit = $false }
            }
            if ($emit) {
                New-Item -ItemType Directory -Force -Path (Split-Path $stamp) | Out-Null
                Set-Content -LiteralPath $stamp -Value ((Get-Date).ToString("o")) -Encoding UTF8
            }
        }
    } catch {
        # Cannot throttle -> report. Silence is the defect being fixed, so the failure mode of the
        # noise-suppressor must be noise, never quiet.
        $emit = $true
    }
    if ($emit) {
        $payload = @{
            hookSpecificOutput = @{
                hookEventName     = "PreToolUse"
                additionalContext = "[collision] The collision gate could NOT check this edit ($(Get-SafeForMessage $Slug)): $(Get-SafeForMessage $Detail). It allowed the edit without consulting any peer worktree, so an absent collision warning means UNKNOWN here, not clear. Check by hand before assuming nobody else is in this file:  pwsh -NoProfile -File scripts\coord\overlap.ps1"
            }
        }
        [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    }
    exit 0
}

$target = $PathOverride
if (-not $target) {
    if (-not [Console]::IsInputRedirected) { exit 0 }
    try { $hook = [Console]::In.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop } catch {
        Write-Unresolved "payload-unreadable" `
            "the PreToolUse payload on stdin was not readable JSON, so the gate never learned which file this edit targets"
    }
    # Parsed, but to nothing. An empty payload or a literal `null` on stdin does not throw, so this
    # used to be the one unreadable-input path that still exited silently -- the gate had learned no
    # more than in the case above, and said no more than an all-clear.
    if (-not $hook) {
        Write-Unresolved "payload-empty" `
            "stdin carried no PreToolUse payload, so the gate never learned which file this edit targets"
    }
    $target = [string]$hook.tool_input.file_path
    # NotebookEdit and some variants name the path differently; absence just means nothing to check.
    if (-not $target) { $target = [string]$hook.tool_input.notebook_path }
}
if (-not $target) { exit 0 }

if (-not (Test-Path -LiteralPath $OverlapScript)) {
    Write-Unresolved "overlap-missing" "no overlap script at $OverlapScript"
}

$raw = $null
$code = 0
try {
    $raw = & pwsh -NoProfile -NonInteractive -File $OverlapScript -File $target -Json 2>$null
    $code = $LASTEXITCODE
} catch {
    Write-Unresolved "overlap-threw" "invoking the overlap script raised: $($_.Exception.Message)"
}
if ($code -ne 0) {
    Write-Unresolved "overlap-failed" "the overlap script exited $code"
}

# EMPTY OUTPUT IS NOT AN ANSWER. Under -Json a resolved "nobody else is in this file" is the two bytes
# `[]`; nothing at all is a script that never produced a verdict. Folding those together is precisely
# how this gate came to report all-clear while checking nothing.
$text = (@($raw) -join "`n").Trim()
if (-not $text) {
    Write-Unresolved "overlap-empty" "the overlap script produced no output at all (a resolved 'nobody else' is '[]', not nothing)"
}

$rows = @()
try { $rows = @($text | ConvertFrom-Json -ErrorAction Stop) } catch {
    Write-Unresolved "overlap-unparseable" "the overlap script's output was not JSON"
}
if (-not $rows -or $rows.Count -eq 0) { exit 0 }   # RESOLVED, and nobody else is touching it

$live = @($rows | Where-Object { $_.Live })
if ($live.Count -eq 0) { exit 0 }   # dormant only: worth knowing, not worth blocking

# DENY ONLY ON AN UNCOMMITTED EDIT IN A LIVE WORKTREE. `Files` is the union of what a branch COMMITTED
# and what is dirty in its tree, so a session that committed a file, went clean and finished still
# appears here -- and a committed file stays until the branch LANDS. Reported 2026-08-01 with a repro:
# a session committed a file, confirmed in writing it was done, and the peer it handed off to was still
# refused. While PRs cannot merge, "until it lands" is indefinite, so the blocked set only ever grows.
# That is this gate's own stated failure mode -- "a gate that cries wolf gets uninstalled".
#
# MatchedDirty is the narrower predicate and it is exactly the question being asked: is someone editing
# this file NOW. A row lacking the property (a stale overlap cache written before this change) is
# treated as dirty, so the gate degrades to its previous over-blocking behaviour rather than silently
# permitting a real collision -- over-block is safe, under-block is a silent collision.
$editing = @($live | Where-Object { $null -eq $_.PSObject.Properties['MatchedDirty'] -or $_.MatchedDirty })
if ($editing.Count -eq 0) {
    # Committed-and-clean in every live worktree: report it, do not block. The peer may well have
    # already done what you are about to do, which is worth knowing and not worth refusing over.
    $names = (@($live | ForEach-Object {
                "$(Get-SafeForMessage $_.Short) [$(Get-SafeForMessage $_.Branch)]" }) -join ', ')
    [Console]::Out.Write((@{
                hookSpecificOutput = @{
                    hookEventName     = "PreToolUse"
                    additionalContext = "[collision] $(Get-SafeForMessage (Split-Path $target -Leaf)) was already CHANGED AND COMMITTED on another live session's branch ($names), whose tree is now clean. Not blocking -- but that work may overlap yours, so check its commits before you duplicate or revert it."
                }
            } | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

$leaf = Get-SafeForMessage (Split-Path $target -Leaf)
$lines = @("$leaf has UNCOMMITTED changes in another LIVE session's worktree -- editing it now means one of you loses work at merge.", "")
foreach ($r in $editing) {
    $lines += "  $(Get-SafeForMessage $r.Short) ($(Get-SafeForMessage $r.Surface)) in " +
              "$(Get-SafeForMessage $r.Worktree) [$(Get-SafeForMessage $r.Branch)]"
    foreach ($w in @($r.Work | Select-Object -First 2)) {
        $lines += "      building: $(Get-SafeForMessage $w)"
    }
}
$lines += ""
$lines += "Before overriding: that session may already be doing what you are about to do."
$lines += "  see everything in flight :  pwsh -NoProfile -File scripts\coord\overlap.ps1"
$lines += "  who is live              :  pwsh -NoProfile -File scripts\coord\presence.ps1"
$lines += "If you genuinely need this file, coordinate first -- or edit a different one."

Deny ($lines -join "`n")
