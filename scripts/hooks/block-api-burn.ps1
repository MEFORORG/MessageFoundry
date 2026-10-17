# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# PreToolUse guard: deny GitHub CLI commands that POLL in a loop and burn the shared API rate limit.
# Reads the tool-call JSON on stdin; if the command watches a run or a PR in a polling loop it
# returns a "deny" decision naming the single-shot command to use instead. Anything else passes
# silently (exit 0). Fail-OPEN on any error.
#
# WHY THIS IS A SHARED-RESOURCE PROBLEM, NOT A STYLE ONE. Every seat in this fleet acts as the same
# GitHub identity, so all of them draw on ONE 5000-requests-per-hour budget. `gh run watch` polls
# every 3 seconds, which is 1200 requests an hour from a SINGLE seat. Three seats watching runs
# exhaust the hour's budget for everybody, and the failure surfaces on some unrelated seat's next
# `gh` call as an opaque rate-limit error. Adopted from beads' .claude/hooks/block-gh-watch.sh
# (BACKLOG #1453), whose comment records that it "repeatedly exhausted the quota during releases".
#
# THE REASON STRING NAMES THE REPLACEMENT. A denial that only forbids leaves the agent to guess, and
# the guess is usually the same command with a flag moved. Every branch below hands back a command
# that does the same job in one request.
#
# STILL NEEDED, RE-MEASURED 2026-10-17 ON mefordev01. There, every Claude account shares one
# GitHub token: `gh auth status` read it from the Windows user's keyring, and no account's
# settings.json sets GH_TOKEN or GITHUB_TOKEN (environment variables and other machines were not
# checked). A scan of the last 30 days of its transcripts, across all accounts, found 2,035 gh
# tool calls, a busiest hour of 234, and zero `gh run watch` or `--watch` calls.
# The guard still matters, for two reasons. First, the hazard is a single call: one watch from
# one seat is about a quarter of the hour's budget. Second, seats still write poll loops; the same
# scan found four distinct ones, sleeping 30 to 600 seconds, each denied by the loop rule below.
#
# A KNOWN FALSE DENY, LEFT OPEN. Heredoc bodies and quoted text are not blanked, so a heredoc that
# writes a file mentioning a gh loop and a sleep is denied as if it ran them (measured 2026-10-17).
# Write such a file with a file tool instead. Blanking quoted text would also hide
# `bash -c "gh run watch"`, which is a real call.
#
# WIRING IS NOT ASSERTED HERE ON PURPOSE. Whether this script is referenced by a PreToolUse matcher
# is a property of settings.json, not of this file.
# See docs/WORKTREES.md.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Deny {
    param([string]$Reason)
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{
            hookEventName            = 'PreToolUse'
            permissionDecision       = 'deny'
            permissionDecisionReason = $Reason
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $j = $raw | ConvertFrom-Json
    $cmd = [string]$j.tool_input.command
    if (-not $cmd) { exit 0 }

    # Normalise runs of whitespace so a line-wrapped or oddly-spaced command cannot slip past a
    # pattern written against single spaces.
    $c = ($cmd -replace '\s+', ' ').Trim()

    # `gh` must sit in COMMAND POSITION: at the start, or after a shell separator, optionally behind
    # a loop/conditional keyword. Without this anchor the guard fires on any command that merely
    # MENTIONS the forbidden string -- `echo "gh run watch is banned"` denied itself in testing, which
    # would block writing the very documentation that explains this rule. A pattern for a claim also
    # matches the sentence disclaiming it, and the careful spelling is the one that produces that bug.
    #
    # Behind an interpreter counts too, for at least `bash/sh -c`, `pwsh/powershell -c/-Command`
    # and `cmd /c`: `bash -c "gh run watch"` is the same call and was ALLOWED before. The program
    # name is required, so `grep -c gh` is not read as one. Still open: pwsh's other abbreviations
    # of -Command, -EncodedCommand, and a script file. The price: a quoted MENTION of such a
    # command, as in `echo "never run bash -c 'gh run watch'"`, is denied too.
    $POS = '(?:^|[;&|(){}]\s*|\s(?:do|then|else)\s)'
    $INTERP = '(?:\b(?:ba|z|da)?sh(?:\.exe)?\s+(?:-\w+\s+)*(?-i:-[a-z]*c)|\b(?:pwsh|powershell)(?:\.exe)?\s+(?:-\w+\s+)*-(?:c|Command)|\bcmd(?:\.exe)?\s+/[ck])\s+["'']?'
    # A loop or conditional keyword may sit in front: `until gh pr merge 5; do :; done`.
    $GH = "(?:$POS(?:(?:while|until|if|!)\s+)?|$INTERP)gh\s"
    if ($c -notmatch $GH) { exit 0 }

    # `gh run watch` -- the measured 1200/hr offender.
    if ($c -match ($GH + '.*\brun\s+watch\b')) {
        Deny ("BLOCKED: `gh run watch` polls every 3 seconds, about 1200 of the 5000 hourly GitHub API " +
              "requests, and every seat in this fleet shares ONE budget as the same identity. Use a " +
              "single-shot read instead: `gh run view <run-id>` for status now, or " +
              "`gh run list --branch <branch> --limit 5 --json status,conclusion,createdAt` for the " +
              "branch's runs. To wait, sleep first and then read once -- never poll.")
    }

    # `--watch` on any gh subcommand is the same loop wearing a flag.
    # Behind an interpreter the closing quote ends the flag too, so `pwsh -Command 'gh pr checks 5
    # --watch'` is caught; elsewhere a quote after it is a mention, as in `--body "never --watch"`.
    if ($c -match '(^|\s)--watch(\s|$)' -or
        $c -match ("$INTERP" + 'gh\s[^"'']*\s--watch["'']')) {
        Deny ("BLOCKED: a `--watch` flag on a `gh` command polls in a loop and draws on the fleet's " +
              "shared 5000/hr GitHub API budget. Drop `--watch` and read once. For a run: " +
              "`gh run view <run-id>`. For a PR's checks: `gh pr checks <N>` or " +
              "`gh pr view <N> --json statusCheckRollup`.")
    }

    # A hand-rolled poll loop around gh is the same cost without the flag, and it is what an agent
    # writes the moment the two patterns above are denied.
    #
    # THE LOOP KEYWORD MUST BE IN COMMAND POSITION AND COME BEFORE THE SLEEP. In a poll the sleep is
    # inside the loop, so it follows the keyword that opens it. Testing the two words anywhere
    # denied `...; sleep 5; for n in 1 2 3; do gh pr view $n; done`, which sleeps once and then
    # reads three PRs once each (the one false deny in the 2026-10-17 scan), and `for` or `while`
    # in a message body read as a loop. `do {` is PowerShell's `do { } while`.
    #
    # AND A LOOP THAT NEVER ENDS ON ITS OWN IS A POLL WITH OR WITHOUT A SLEEP. `while true`,
    # `while :`, `while ($true)` and `until` around gh spend requests as fast as gh returns, which
    # is the worst rate of all. `... | while read n` iterates over input, ends, and stays allowed.
    $LOOP = "(?:$POS(?:while|until|for|foreach|ForEach-Object)\b|\bdo\s*\{|\|\s*%\s*\{)"
    $FOREVER = "$POS(?:while\s+(?:true|:)(?:\s|;|$)|while\s*\(\s*\`$true\s*\)|until\s)"
    if ($c -match ($LOOP + '.*\b(sleep|Start-Sleep)\b') -or $c -match $FOREVER) {
        Deny ("BLOCKED: this is a hand-rolled polling loop around `gh`, which costs the fleet's shared " +
              "GitHub API budget the same way `gh run watch` does. Make ONE call per turn and let the " +
              "next turn make the next one. If you must wait inside a turn, sleep once and then read " +
              "once -- do not loop. A script that must re-read one endpoint can add " +
              "`gh api --cache 60s`, which answers repeats from gh's local cache instead of the API.")
    }

    exit 0
} catch {
    # Fail open, always. A broken guard must not wedge every gh call in the fleet.
    exit 0
}
