# PreToolUse guard: block blanket git staging so parallel Claude Code sessions sharing a working
# tree can't sweep each other's files into one commit. Reads the tool-call JSON on stdin; if the
# command does a broad stage (git add -A/--all/-u/. or git commit -a/-am/--all) it returns a
# PreToolUse "deny" decision asking for explicit paths. Anything else passes silently (exit 0).
# Fail-OPEN on any error: a guardrail must never wedge all git work.
# Wired in .claude/settings.json (PreToolUse, Bash + PowerShell). See docs/WORKTREES.md.
# ASCII-only on purpose (PS 5.1 ANSI-read lesson); run under pwsh 7 by the hook.

$ErrorActionPreference = 'SilentlyContinue'

$cmd = $null
try {
    $raw = [Console]::In.ReadToEnd()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $j = $raw | ConvertFrom-Json
        $cmd = [string]$j.tool_input.command
    }
} catch {
    exit 0
}
if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }

$reason = $null
# Examine each shell-separated simple command on its own, so '... && git add -A' is still caught.
foreach ($seg in [regex]::Split($cmd, '(\|\||&&|[;|&\n])')) {
    $s = $seg.Trim()
    if ($s -cnotmatch '^git(\s|$)') { continue }

    # git add with -A / --all / -u / a bare '.' (stages the whole tree).
    if ($s -cmatch '\badd\b' -and $s -cmatch '(^|\s)(-A|--all|-u|\.)(\s|$)') {
        $reason = "git add -A/--all/-u/. stages everything, including files another session may be editing."
        break
    }
    # git commit with -a / -am / --all (auto-stages every tracked change). A single-dash flag
    # cluster containing 'a' catches -a, -am, -na, etc.; '--amend' (double dash) is left alone.
    if ($s -cmatch '\bcommit\b' -and ($s -cmatch '(^|\s)--all(\s|$)' -or $s -cmatch '(^|\s)-[A-Za-z]*a[A-Za-z]*(\s|$)')) {
        $reason = "git commit -a/-am/--all auto-stages every tracked change before committing."
        break
    }
}

if (-not $reason) { exit 0 }

$msg = "Blocked blanket git staging: $reason Stage explicit paths instead: 'git add <path> ...' then 'git commit -m ...'. (MessageFoundry guard; disable via /hooks.)"
$payload = [pscustomobject]@{
    hookSpecificOutput = [pscustomobject]@{
        hookEventName            = 'PreToolUse'
        permissionDecision       = 'deny'
        permissionDecisionReason = $msg
    }
}
[Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
exit 0
