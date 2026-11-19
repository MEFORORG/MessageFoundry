# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# PreToolUse guard: deny GitHub CLI commands that POLL in a loop and burn the shared API rate limit.
# Reads the tool-call JSON on stdin; if the command watches a run or a PR in a polling loop it
# returns a "deny" decision naming the single-shot command to use instead. Anything else passes
# silently (exit 0). Fail-OPEN on any error but a spent time budget, which denies (see $BUDGET).
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
# A KNOWN FALSE DENY, LEFT OPEN. On a line the original anchor ($GH0 below) reads, the whole-line
# rules do not skip heredoc bodies or quoted text, so a heredoc that writes a file mentioning a gh
# loop and a sleep is denied as if it ran them (measured 2026-10-17). The narrower rules added
# for BACKLOG #5449 skip quoted text but not heredoc bodies. Write such a file with a file tool
# instead. Skipping quoted text in the whole-line rules would also hide `bash -c "gh run watch"`,
# which is a real call.
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
    $GH0 = "(?:$POS(?:(?:while|until|if|!)\s+)?|$INTERP)gh\s"

    # SO MAY AN ASSIGNMENT, AND THE PROGRAM MAY BE gh.exe (BACKLOG #5449). `$r = gh ...` and
    # `` s=`gh ...` `` run gh exactly as a bare call does, and `gh.exe` is gh, but $GH0 reads none
    # of them, so a poll loop around one passed. $GHN reads them. The assignment must itself sit in
    # command position, and a bash one must open a backtick substitution (`$(` already counts
    # through the `(`). So `--grep=gh`, `a == gh`, `[ $x = gh ]` and `s=gh run watch`, which runs
    # `run` with s set to the string gh, are not one.
    #
    # A LINE $GH0 READS KEEPS EVERY RULE IT HAD BEFORE. One that only $GHN reads gets only the
    # narrower rules below, each tied to that gh: it sits outside any quoted string ($Q), and the
    # flag or the loop belongs to it. Widening the anchor alone handed the old whole-line rules
    # commands that call gh once, such as `$n = gh pr view 1; npx jest --watch`.
    #
    # This reads at least those shapes, not every way to run gh. Still open, at least: an
    # assignment after another on one line (`a=1 b=`` `gh ...` ``), `NAME=value gh ...`, `export`,
    # `local` and `declare`, a typed PowerShell assignment (`[string]$r = gh ...`), `+=` and the
    # other compound assignments, a quoted substitution (`` s="`gh ...`" ``), a full path to gh,
    # gh behind a wrapper such as `env`, `time` or `xargs`, gh inside an interpreter string other
    # than the three $INTERP names, and gh at the start of any line but the first.
    $GHN = "(?:$POS(?:(?:while|until|if|!)\s+|[A-Za-z_]\w*=``|\`$[\w:.]+\s*=\s*)?|$INTERP)gh(?:\.exe)?\s"
    $tool = ''
    if ($j.PSObject.Properties['tool_name']) { $tool = [string]$j.tool_name }
    $ps = $tool -eq 'PowerShell'
    # A quoted string, whole. Inside double quotes the tool's own escape character escapes the next
    # one: a backtick for PowerShell, where a backslash is literal, so `"a `"x; gh`" b"` is one
    # string and `"C:\x\"` ends at its last quote; a backslash otherwise, as in bash. $QSPAN is
    # text that ends outside any quote.
    $DQ = if ($ps) { '"(?:[^"`]|`.)*"' } else { '"(?:[^"\\]|\\.)*"' }
    $QSPAN = "(?:[^`"']|$DQ|'[^']*')*?"
    $Q = '^' + $QSPAN
    $GHQ = $Q + $GHN
    $wide = $c -match $GH0
    # $lines keeps each line break as a \x01, which no rule reads as a separator, so a tied rule
    # stops at the end of gh's line: `gh pr view 5`, then `npx jest --watch;` on the next line, is
    # not gh's flag. The tool's own line continuation is joined first: a backtick for PowerShell,
    # a backslash otherwise, so a PowerShell path ending in `\` is not glued to the next line.
    $cont = if ($ps) { '`\r?\n' } else { '\\\r?\n' }
    $lines = (($cmd -replace $cont, ' ') -replace '\r?\n', " $([char]1) " -replace '\s+', ' ').Trim()

    # THE RULES ADDED FOR BACKLOG #5449 SHARE ONE TIME BUDGET, AND RUNNING OUT DENIES. Their
    # quote-aware patterns can rescan the line once per gh, so 8000 repeats of ` do gh x` took
    # 28.5 s where origin/main's rules took 2.6 s. $clock runs only while one of those matches
    # runs, and each match takes what is left as its regex timeout; when it runs out the command
    # is denied (see the catch below) rather than allowed. origin/main's own rules, the `$wide`
    # half of each test, stay untimed and run first, so a DENY from them stands as it did; an
    # ALLOW from them does not, since the timed rules after them can still run out and deny.
    # This bounds only time. The 32-keyword cap in Test-LoopPoll is a separate bound, and it
    # still fails open.
    $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $BUDGET = 4.0
    $clock = [System.Diagnostics.Stopwatch]::new()
    function Invoke-Tied([string]$Pattern, [scriptblock]$Use) {
        $left = $BUDGET - $clock.Elapsed.TotalSeconds
        # Below a millisecond the timeout could round to zero ticks, which the constructor refuses
        # with an error the fail-open catch would turn into an allow.
        if ($left -lt 0.001) { throw [System.Text.RegularExpressions.RegexMatchTimeoutException]::new('budget spent') }
        $re = [regex]::new($Pattern, $opt, [timespan]::FromSeconds($left))
        $clock.Start()
        try { & $Use $re } finally { $clock.Stop() }
    }
    function Test-Tied([string]$Pattern, [string]$Text, [int]$At = 0) {
        Invoke-Tied $Pattern { param($re) $re.IsMatch($Text, $At) }
    }
    function Find-Tied([string]$Pattern, [string]$Text, [int]$At = 0) {
        Invoke-Tied $Pattern { param($re) , $re.Match($Text, $At) }
    }
    try {
    if (-not $wide -and -not (Test-Tied $GHQ $lines)) { exit 0 }
    # From gh to its own flag: no separator, bracket, comment, backtick or line end, and a quoted
    # argument whole, so `-R 'o/r' --watch;` is read and `--body "never --watch"` is not.
    $SPAN = "(?:[^`"'``;&|(){}#\x01]|$DQ|'[^']*')*?"

    # `gh run watch` -- the measured 1200/hr offender.
    if (($wide -and $c -match ($GH0 + '.*\brun\s+watch\b')) -or
        (Test-Tied ($GHQ + $SPAN + '\brun\s+watch\b') $lines)) {
        Deny ("BLOCKED: `gh run watch` polls every 3 seconds, about 1200 of the 5000 hourly GitHub API " +
              "requests, and every seat in this fleet shares ONE budget as the same identity. Use a " +
              "single-shot read instead: `gh run view <run-id>` for status now, or " +
              "`gh run list --branch <branch> --limit 5 --json status,conclusion,createdAt` for the " +
              "branch's runs. To wait, sleep first and then read once -- never poll.")
    }

    # `--watch` on any gh subcommand is the same loop wearing a flag.
    # Behind an interpreter the closing quote ends the flag too, so `pwsh -Command 'gh pr checks 5
    # --watch'` is caught; elsewhere a quote after it is a mention, as in `--body "never --watch"`.
    # On a line $GH0 reads, any ` --watch` that whitespace or the end closes is denied, whichever
    # command owns it, so `gh pr checkout 5 && npx jest --watch` is denied as it was before.
    #
    # The tied rule also ends the flag at a shell delimiter, a redirect, a backtick, a line end or
    # an `=value` that is one of pflag's true spellings (true, t, 1, optionally quoted), and reads
    # a flag only where $SPAN reaches it from gh (BACKLOG #5449). So a later command's own
    # `--watch;`, as in `gh pr checkout 5 && npx jest --watch;` or
    # `if (gh pr view 1) { echo --watch; }`, gh inside quoted prose or after a `#`, and
    # `--watch=0`, `--watch="false"` or a value gh refuses are not read. Still open, at least:
    # `$(gh ... --watch)` and `(gh ... --watch)`, because a `)` is not a delimiter here, and a
    # redirect such as `2>&1` between gh and the flag, because its `&` ends $SPAN.
    if (($wide -and $c -match '(^|\s)--watch(\s|$)') -or
        $c -match ("$INTERP" + 'gh(?:\.exe)?\s[^"'']*\s--watch["'']') -or
        (Test-Tied ($GHQ + $SPAN +
            '\s--watch(?=$|[\s;&|}<>`\x01]|=["'']?(?:true|t|1)["'']?(?:$|[\s;&|}<>`\x01]))') $lines)) {
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
    # On a line $GH0 reads, those rules stand as they were, with gh anywhere on the line.
    #
    # `while (1)`, bash `while ((1))`, and `for (;;)` or `for ((;;))` never end on their own either
    # (BACKLOG #5449). Those, and every loop that only $GHN's shapes put gh in, are read per loop
    # instead (Test-LoopPoll): the loop runs from its keyword, outside any quote, to the end of its
    # own body. That body is a balanced `{ }` right after the keyword, behind at most one
    # parenthesised header (`while (...) {`, `foreach ($p in $x) {`), or, for `while`, `until`
    # and `for`, a `do ... done` behind a header that crosses no separator but a last `;` or line
    # break before the `do`. When the body opens there but does not close, the loop runs to the end
    # of the line. A keyword with no body of its own, such as `ForEach-Object Name` or
    # `foreach Prop`, is no loop region (`ForEach-Object -Process { }` has one), so it borrows no later brace and no rest of the command.
    # Nor is the `} while (...)` or `} until (...)` tail of a `do { }` body, which belongs to the
    # do loop. A region is a poll when it holds a gh outside quotes and either a sleep or a forever
    # spelling, including `do { } while (1)` or `while ($true)` after a `do` body. So reading a PR
    # once before or after another loop, a bounded loop and then one sleep, and gh in a loop's
    # quoted text are not polls. Still open, at least: a loop keyword or gh at the start of any
    # line but the first, and `for (;;$i++)`. Only the first 32 loop keywords on a command are
    # read, and every match here runs under the time budget above, so running out denies.
    # ForEach-Object first, so the match takes the whole name and its body follows it directly.
    $LOOP = "(?:$POS(?:ForEach-Object|foreach|while|until|for)\b|\bdo\s*(?=\{)|\|\s*%\s*(?=\{))"
    $FOREVER = "$POS(?:while\s+(?:true|:)(?:\s|;|$)|while\s*\(\s*\`$true\s*\)|until\s)"
    $FOREVER_ANY = "^$POS(?:while\s+(?:true|:)(?:\s|;|$)|while\s*\(\s*\`$true\s*\)|until\s|" +
                   'while\s*\(\(?\s*1\s*\)\)?|for\s*\(\(?\s*;\s*;\s*\)\)?)'
    $BRACE = "\{(?:(?>\}(?<-d>)|\{(?<d>)|$DQ|'[^']*'|[^`"'{}]+))*?(?(d)(?!))\}"
    $DODONE = "\bdo\b(?:(?>\bdone\b(?<-d>)|\bdo\b(?<d>)|$DQ|'[^']*'|[^`"']))*?(?(d)(?!))\bdone\b"
    $PAREN = "\((?:(?>\)(?<-p>)|\((?<p>)|$DQ|'[^']*'|[^`"'()]+))*?(?(p)(?!))\)"
    # The keyword's own header: named parameters such as `-Process` or `-Parallel`, each with at
    # most one value, then one optional ( ) before a brace body; or bash's text before `do`.
    $PARAMS = "(?:-\w+[\s\x01]+(?:[^-\s\x01{}();|&`"'][^\s\x01{}();|&`"']*[\s\x01]+)?)*"
    $HEADBRACE = "[\s\x01]*$PARAMS(?:$PAREN[\s\x01]*)?"
    $HEADDO = "(?:$DQ|'[^']*'|$PAREN|[^`"'(){};\x01])*?(?:[;\x01]\s*|\s)(?=do\b)"
    function Test-LoopPoll {
        $doEnds = @{}
        $seen = 0
        foreach ($m in (Invoke-Tied $LOOP { param($re) @($re.Matches($lines)) })) {
            if (++$seen -gt 32) { break }
            if (-not (Test-Tied "^$QSPAN`$" $lines.Substring(0, $m.Index))) { continue }
            # The `} while (...)` / `} until (...)` tail of a do body is that loop's, not a new one.
            if ($m.Value.StartsWith('}') -and $doEnds.ContainsKey($m.Index + 1)) { continue }
            $braceOnly = $m.Value -match '(?:\bdo|%)\s*$|foreach|ForEach-Object'
            $head = if ($braceOnly) { "\G$HEADBRACE" } else { "\G(?:$HEADBRACE(?=\{)|$HEADDO)" }
            $from = $m.Index + $m.Length
            $body = Find-Tied ($head + "(?:$BRACE|$DODONE)") $lines $from
            if ($body.Success) {
                $end = $body.Index + $body.Length
                if ($m.Value -match '\bdo\s*$') { $doEnds[$end] = $true }
            } elseif (Test-Tied ($head + '(?:\{|\bdo\b)') $lines $from) {
                $end = $lines.Length
            } else {
                continue
            }
            $region = $lines.Substring($m.Index, $end - $m.Index)
            if (-not (Test-Tied ($Q + $GHN) $region)) { continue }
            $forever = (Test-Tied $FOREVER_ANY $lines.Substring($m.Index)) -or
                       ($body.Success -and (Test-Tied '\G\s*while\s*\(\s*(?:\$true|1)\s*\)' $lines $end))
            if ($forever -or (Test-Tied ($Q + '\b(?:sleep|Start-Sleep)\b') $region)) { return $true }
        }
        return $false
    }
    if (($wide -and ($c -match ($LOOP + '.*\b(sleep|Start-Sleep)\b') -or $c -match $FOREVER)) -or
        (Test-LoopPoll)) {
        Deny ("BLOCKED: this is a hand-rolled polling loop around `gh`, which costs the fleet's shared " +
              "GitHub API budget the same way `gh run watch` does. Make ONE call per turn and let the " +
              "next turn make the next one. If you must wait inside a turn, sleep once and then read " +
              "once -- do not loop. A script that must re-read one endpoint can add " +
              "`gh api --cache 60s`, which answers repeats from gh's local cache instead of the API.")
    }
    } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        # Fail CLOSED here, unlike every other error: the budget ran out before the rules could
        # read the command, and letting it through would let a large enough poll pass unread.
        Deny ("BLOCKED: this command is too large for the API-burn guard to read within its time " +
              "budget, so it is denied rather than run unread. Split it into smaller commands, or " +
              "write a long script to a file with a file tool and run the file.")
    }

    exit 0
} catch {
    # Fail open on every other error. A broken guard must not wedge every gh call in the fleet.
    # The spent time budget is the one exception, denied by the inner catch above.
    exit 0
}
