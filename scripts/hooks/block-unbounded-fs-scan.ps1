# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# PreToolUse guard: deny a filesystem walk rooted at the MSYS root, at its synthetic /proc, or at
# the MSYS network root. Reads the tool-call JSON on stdin; if the command would walk one of those
# it returns a "deny" decision naming the bounded command to use instead. Anything else passes
# silently (exit 0). Fail-OPEN on any error.
#
# The network root carries a DIFFERENT cause and says so; see $WHY_NET below.
#
# WHY THIS IS A MACHINE-WIDE RESOURCE PROBLEM, NOT A STYLE ONE. Git Bash's `/` is
# C:\Program Files\Git and carries a synthetic /proc. /proc holds 32 entries, and THREE of them are
# the pump: /proc/registry, /proc/registry32 and /proc/registry64, which are the WINDOWS REGISTRY
# mounted as filesystem trees by the MSYS2 runtime. Walking one opens a kernel handle per registry
# key, and HKEY_CLASSES_ROOT alone is effectively unbounded. That is also why a runaway walk shows
# almost no disk I/O: the registry is in memory, not on disk.
#
# Measured 2026-09-20, paired arms on one find.exe binary, handles sampled every 3 seconds:
#
#   find /proc/registry                        7,619 -> 15,590 -> 22,185 -> 26,594 -> 30,471, still
#                                              running when the arm was stopped
#   find /proc, all 3 registry mounts pruned   exited immediately, 3,866 lines, no handle growth
#   find /proc -maxdepth 2                     exited immediately, 302 lines
#   find /                                     flat at about 205 handles until it REACHES /proc,
#                                              which sorts late
#
# The registry mounts are the whole of the effect: prune them and the same walk finishes at once.
# Machine-wide before the cleanup that produced these numbers: 4,183,509 handles and 4,620 MB of
# paged pool out of 32.5 GB of RAM, with a 10-second test run taking 26 minutes.
#
# AND AN INTERRUPT CANNOT STOP ONE. Killing a bash.exe wrapper does NOT kill its grandchildren --
# measured on a claude -> bash -> bash -> bash -> python -> python chain, where killing the
# innermost bash left both pythons alive, reparented to a dead pid. IsProcessInJob answers True for
# all of them and the job carries no kill-on-close. An orphan's parent is dead, so no pipe ever
# closes, no SIGPIPE ever arrives, and the walk runs until the box dies. That is why this is a
# PreToolUse DENY and not a timeout: there is no reliable way to stop one once it has started.
# scripts/coord/reap-orphans.ps1 is the after-the-fact half, and it is report-only by default.
#
# WHY -maxdepth IS NOT AN EXEMPTION ON `/` OR `/proc`. A shallow walk really is cheap -- the
# `find /proc -maxdepth 2` arm above exited at once -- but an exemption would have to know the
# depth at which the registry mounts start, and that depth moves with the root you gave. A
# recognition that can turn a deny into an ALLOW is the construct that fails open (the reasoning is
# BACKLOG #1229's, recorded in the sibling block-blanket-git-stage.ps1), so the escape offered in
# the deny message is the explicit prune guard, which NAMES the thing to skip rather than guessing
# how deep it is.
#
# AND THE PRUNE MUST COVER THE WHOLE OF /proc. Pruning /proc/registry alone was tried and the walk
# fell straight into /proc/registry32 and kept leaking. Use `-path /proc -prune -o`, or name all
# three mounts.
#
# THE REASON STRING NAMES THE REPLACEMENT. A denial that only forbids leaves the agent to guess,
# and the guess is usually the same command with a flag moved. Every branch below hands back a way
# to do the same job with a bounded root.
#
# THE PROGRAM LIST IS THIS FILE'S FAIL-OPEN AXIS, AND IT IS NOT COVERAGE. Only `find` and `grep`
# are recognised, because those are the two spellings that were measured. Recognising the program
# is REQUIRED to produce a deny, so every other walker passes silently -- at least `rg -uu /`,
# `ls -R /proc`, `du -sh /`, `tar` and `7z` over the same roots, and anything reached through a
# dispatching wrapper other than xargs. Each new program would cost another option table beside
# the three below, so the file is O(programs) by construction.
#
# ***DO NOT READ THE XARGS NOTE BELOW AS SAYING THAT IS SAFE.*** An earlier draft of it argued the
# polarity was the opposite of BACKLOG #1229's because a name missing from the list "costs a MISSED
# deny, never a wrong one". A missed deny IS #1229's outcome: a command that should have been
# refused is allowed. The difference is only that this file ACCEPTS that exposure knowingly and
# bounds it here, rather than avoiding it.
#
# A WALK ROOTED AT THE SEGMENT'S OWN `cd` IS ON THE SAME AXIS AND IS ALSO OPEN. `cd /proc && find .`
# was measured ALLOWED: the splitter judges `find .` on its own and never reads the cd's operand.
# It is named here because the splitter's comments talk about `cd X && find /proc`, which makes the
# other direction read as covered when it is not.
#
# THE DEEPER FIX, NOT TAKEN HERE. Apply Get-WalkRootKind to every non-option token of ANY program
# and move recognition entirely to the suppression side -- a list of programs that provably cannot
# walk (`cat`, `head`, `tail`, `stat`, `readlink`, `echo`, `ls` without -R, `grep` without -r),
# plus the prune escape. An unknown program would then cost a visible false deny instead of a
# silent hole. It is not in this change because the suppression list has to exist before the
# inversion lands, and building it is a larger piece of work than the two measured spellings.
#
# A ROOT IS A PATH, NOT A STRING, AND AN OPTION IS A GRAMMAR, NOT A NAME. Two families of bypass
# were measured on 2026-09-20 against the committed guard, and each one had the same cause: a test
# that compared SPELLINGS where it should have compared the thing the spelling names.
#
#   Path spelling. `/.`, `//` and `/./` are not the literal string `/`, so three walks of the root
#   were allowed. Patching those three would have left `/..`, `/.//`, `///`, `/tmp/../proc`,
#   `find /pro'c'` and `find /pro\c` open, so the fix folds the operand instead -- Get-Operand and
#   Get-NormalizedPath below carry the rules and the measurement each one rests on.
#
#   Option grammar. `--regexp=foo` and `-rm5` were both allowed, and for opposite reasons: the
#   long form's `=` hid the option's NAME behind its value, and the short bundle's attached digit
#   hid the `-r` inside it. Both are read structurally now, in the grep branch below.
#
# ***THE FOLD IS NOT THE WHOLE OF A ROOT, AND THE PRUNE EXEMPTION IS WHERE THAT BITES.*** `-path` is
# a glob matched against the string find itself generates by appending to the LITERAL root, so an
# exemption is only valid when the pattern starts with that literal root. Four more walks were
# measured running under a `-path /proc -prune` that could never fire, `find /.` among them. The
# scoping lives at the find deny site; the reason is written there.
#
# WHAT IS STILL OPEN ON THE OPTION AXIS, NAMED SO IT IS NOT MISTAKEN FOR COVERAGE. GNU getopt_long
# accepts any unambiguous ABBREVIATION of a long option, so `grep --rec pattern /proc` is a
# recursive walk this guard reads as a plain one. It is left open because the abbreviation set is
# the whole option table rather than a list -- a real piece of work, on the same fail-open axis the
# program list sits on, and not something to half-do here.
#
# WIRING IS NOT ASSERTED HERE ON PURPOSE. Whether this script is referenced by a PreToolUse matcher
# is a property of settings.json, not of this file.
# The after-the-fact half is scripts/coord/reap-orphans.ps1; the structural sibling this follows is
# scripts/hooks/block-api-burn.ps1.
# ASCII-only on purpose (PS 5.1 ANSI-read lesson); run under pwsh 7 by the hook.

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

# Blank the BODY of every heredoc, preserving line structure and LENGTH. A heredoc body is data
# being written to a file, not a command, but its lines sit at the front of a newline-split segment
# and are read there as program position. Written against the shape of the sibling guard's pass in
# block-blanket-git-stage.ps1 rather than dot-sourced from it.
#
# ***THIS AND Hide-QuotedSpans BELOW ARE BOTH SECOND COPIES, AND THE SIBLING'S REASON FOR KEEPING
# ITS OWN NO LONGER HOLDS.*** Naming only one of them would send whoever acts on this note to
# extract half the seam and leave the other half diverging.
# That file says it is "one function with one caller for exactly that reason" and should be
# replaced by a shared helper when BACKLOG #1332 settles. A second caller is the event that
# retires that argument, so read this as a debt rather than a decision. The two copies have
# already diverged in error posture (the sibling runs SilentlyContinue; this runs Stop with a
# fail-open catch). Extracting them is blocked on a real constraint rather than on taste:
# tests/test_claude_settings_contract.py globs scripts/hooks/*.ps1 and demands every file there be
# wired, installer-wired, or listed as deliberately unwired -- so a LIBRARY in that directory needs
# a new entry on a list whose own comment says growth is the signal, not the workaround.
#
# ***THE OPENER IS FOUND ON THE QUOTE-MASKED TEXT AND THE DELIMITER IS READ FROM THE RAW TEXT.***
# Doing both on one view is wrong in opposite directions, and the raw-only version shipped a
# fail-open that was measured: `grep -rn "x << y" .` followed by a newline and `find /proc` was
# ALLOWED, because `<< y` inside a quoted pattern set the terminator to a word that never appears
# again, so every later line -- the real walk included -- was blanked away. `bash <<< 'hello'` did
# the same through the herestring operator. But masking first and reading the delimiter from the
# masked text loses it outright: `<<'EOF'` masks to `<<'   '`. Both views preserve LENGTH, so the
# opener's offset in one is its offset in the other, which is what lets each question be asked of
# the view that can answer it.
#
# TWO MORE BOUNDS, both of them the safe direction. `<<<` is excluded outright, and the delimiter
# must start with a letter or underscore, so an arithmetic shift (`$((1<<2))`) opens nothing. A
# heredoc written with no space before it (`cat<<EOF`) is therefore missed, which costs a possible
# false DENY on a heredoc whose body quotes this rule -- visible and reportable, never a hole.
function Hide-HeredocBodies([string]$Text, [string]$Masked) {
    # This hook runs as a fresh pwsh on EVERY shell tool call, so the common case pays for the
    # uncommon one unless it is short-circuited. Almost no command contains a heredoc.
    if ($Masked.IndexOf('<<') -lt 0) { return $Masked }
    $rawLines = $Text.Split([char]10)
    $maskedLines = $Masked.Split([char]10)
    $out = New-Object 'System.Collections.Generic.List[string]'
    $terminator = $null
    for ($n = 0; $n -lt $maskedLines.Count; $n++) {
        $line = $maskedLines[$n]
        if ($null -ne $terminator) {
            if ($line.Trim() -ceq $terminator) { $terminator = $null; $out.Add($line) }
            else { $out.Add(' ' * $line.Length) }
            continue
        }
        $out.Add($line)
        $m = [regex]::Match($line, '(?:^|\s)(?<!<)<<(?!<)-?[ \t]*')
        if (-not $m.Success) { continue }
        # The delimiter word itself, taken from the RAW line at the offset the masked line found.
        $raw = $rawLines[$n]
        $rest = $raw.Substring([Math]::Min($m.Index + $m.Length, $raw.Length))
        $d = [regex]::Match($rest, '^(?:''([^'']+)''|"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))')
        if ($d.Success) {
            $terminator = @($d.Groups[1].Value, $d.Groups[2].Value, $d.Groups[3].Value) |
                Where-Object { $_ } | Select-Object -First 1
        }
    }
    return ($out -join "`n")
}

# Replace the CONTENTS of quoted spans with spaces, keeping the quote characters and the overall
# LENGTH. A separator inside a quoted span is then invisible to the splitter, and a find-looking
# token inside one cannot reach program position -- which is what keeps `echo "find /proc"` and a
# commit message quoting this very rule out of the deny path. Length preservation is what lets an
# offset into the blanked text index the raw text.
function Hide-QuotedSpans([string]$Text) {
    # Same reason as the heredoc pass: one interpreted loop iteration per character is the most
    # expensive thing in this file, and a command with no quote at all has nothing to blank.
    if ($Text.IndexOf('"') -lt 0 -and $Text.IndexOf("'") -lt 0) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    $quote = $null
    foreach ($ch in $Text.ToCharArray()) {
        if ($null -ne $quote) {
            if ($ch -ceq $quote) { $quote = $null; [void]$sb.Append($ch) }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
            else { [void]$sb.Append(' ') }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; [void]$sb.Append($ch); continue }
        [void]$sb.Append($ch)
    }
    return $sb.ToString()
}

# A token as the shell would hand it to the program: quote removal and backslash escaping applied,
# nothing else. The walk roots below are compared as whole strings, so `find "/"` and `find /` must
# produce the same operand.
#
# ***QUOTES ARE REMOVED THROUGHOUT THE WORD, NOT JUST FROM ITS ENDS.*** Stripping only a matched
# outer pair shipped a fail-open that was measured: `find /''`, `find /""`, `find '/'""` and
# `find /pro'c'` were all ALLOWED, because the concatenated spellings have no matched outer pair
# and so reached the comparison with their quote characters still in them. An unterminated quote
# loses its delimiter too; that word cannot reach program position anyway, because the blanked
# view's first token carries a quote and the segment is skipped before this is called.
#
# ***AND AN UNQUOTED BACKSLASH IS AN ESCAPE, WHICH IS WHERE THE FIRST CUT OF THIS FUNCTION WENT
# WRONG.*** It left backslashes in place and let the path fold read them as separators, which is
# wrong in BOTH directions and was measured that way. Four walks of /proc were allowed --
# `find /\proc`, `find \/proc`, `find /pro\c` and `grep -r foo /\proc` -- because bash deletes the
# backslash and hands the program `/proc`, while the guard compared a string still carrying it. And
# `find /proc\registry` was DENIED with the registry cause although bash hands find
# `/procregistry`, which does not exist. Deciding the escape HERE, where quoting is still visible,
# is what makes both answers follow from one rule. Measured 2026-09-20 by printing the words bash
# produces; the quoted spelling `find '/proc\registry'` keeps its backslash and is the one that
# really reaches the registry mount.
function Get-Operand([string]$Token) {
    # Almost no token carries a quote or an escape, and this hook pays for its loops on every call.
    if ($Token.IndexOf('"') -lt 0 -and $Token.IndexOf("'") -lt 0 -and
        $Token.IndexOf('\') -lt 0) { return $Token }
    $sb = [System.Text.StringBuilder]::new()
    $quote = $null
    for ($n = 0; $n -lt $Token.Length; $n++) {
        $ch = $Token[$n]
        # Single quotes protect everything, the backslash included.
        if ($quote -ceq "'") {
            if ($ch -ceq "'") { $quote = $null } else { [void]$sb.Append($ch) }
            continue
        }
        if ($ch -ceq '\') {
            $next = if ($n + 1 -lt $Token.Length) { $Token[$n + 1] } else { $null }
            if ($null -eq $quote) {
                # Unquoted: the backslash guards the next character and is itself removed. A
                # trailing one is a line continuation, so it leaves nothing behind.
                if ($null -ne $next) { [void]$sb.Append($next); $n++ }
                continue
            }
            # Inside double quotes bash keeps the backslash unless it guards one of " $ ` \ .
            if ($next -ceq '"' -or $next -ceq '$' -or $next -ceq '`' -or $next -ceq '\') {
                [void]$sb.Append($next); $n++; continue
            }
            [void]$sb.Append($ch)
            continue
        }
        if ($null -ne $quote) {
            if ($ch -ceq $quote) { $quote = $null } else { [void]$sb.Append($ch) }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        [void]$sb.Append($ch)
    }
    return $sb.ToString()
}

# Fold a path operand to the spelling the resolver would reach, as a PURE STRING decision: `\` read
# as a separator, repeated separators collapsed, `.` segments dropped, `..` segments popped, and a
# trailing separator gone. The filesystem is never touched and no symlink is resolved -- this runs
# on the hot path of every shell call, and a stat here would be paid by every command that merely
# contains the word "find".
#
# ***EVERY RULE HERE IS A MEASUREMENT, NOT AN ASSUMPTION ABOUT POSIX.*** Measured 2026-09-20 against
# this machine's Git Bash, with `ls` (bounded, one level) rather than a walk:
#
#   /.  /./  /.//  ///    the MSYS root        -- dot segments and 3+ slashes collapse
#   /..  /tmp/..  /c/..   the MSYS root        -- `..` is resolved LEXICALLY, not through the mount
#                                                 table, so textual popping matches the resolver
#                                                 exactly and costs no false deny
#   /proc/../tmp          /tmp                 -- and so a `..` that leaves /proc must ALLOW again
#   /proc\registry        the registry mount   -- listing it returned the six HKEY_* roots, so a
#                                                 backslash IS a separator once a path has resolved
#                                                 through the POSIX root. Reachable only QUOTED:
#                                                 unquoted, bash eats the backslash (Get-Operand)
#   /\proc  \proc  \       none of the above    -- a backslash in the leading position resolves
#                                                 nothing, and a lone `\` is the current DRIVE root
#                                                 rather than the MSYS one. So the conversion below
#                                                 is anchored on a leading `/`
#   //  //.               the NETWORK root     -- `ls //` listed `wsl$`. EXACTLY two leading slashes
#                                                 are the UNC namespace, which is why they are NOT
#                                                 collapsed and get their own verdict below
#   //proc                nothing              -- a UNC host named "proc", not the /proc mount, so
#                                                 it must stay ALLOWED
#   /PROC  /Proc          nothing              -- the mount is case-SENSITIVE, so the comparisons
#                                                 below stay case-sensitive; folding case would only
#                                                 add false denies
function Get-NormalizedPath([string]$Operand) {
    if (-not $Operand) { return $Operand }
    # The conversion is anchored on a LEADING SLASH, which is the one place the measurements above
    # say a backslash reaches a walk root. `\`, `\proc` and `/\proc` were each driven at `ls` and
    # resolved to nothing this guard is about, so folding them would only add false denies.
    $p = if ($Operand.StartsWith('/')) { $Operand.Replace('\', '/') } else { $Operand }
    $prefix = ''
    if ($p -cmatch '^//(?!/)') { $prefix = '//' }
    elseif ($p.StartsWith('/')) { $prefix = '/' }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($seg in $p.Split('/')) {
        if ($seg -ceq '' -or $seg -ceq '.') { continue }
        if ($seg -ceq '..') {
            if ($parts.Count -gt 0 -and $parts[$parts.Count - 1] -cne '..') {
                $parts.RemoveAt($parts.Count - 1)
                continue
            }
            # At a root, `..` is the root. In a RELATIVE path it cannot be resolved without the
            # tree, so it is kept -- and a path that keeps a leading `..` can never equal a root.
            if ($prefix) { continue }
            $parts.Add('..')
            continue
        }
        $parts.Add($seg)
    }
    $joined = $parts -join '/'
    if ($prefix) { return $prefix + $joined }
    if (-not $joined) { return '.' }
    return $joined
}

# The roots this guard exists for, and ONLY these. `/proc/<anything>` counts: a walk of one
# process's synthetic directory is the same pump, just started lower down. STATED ONCE, because the
# two callers below differ in what they FEED it and not in what a root is -- a copy in each would
# let a later edit move one and leave the other, and the prune caller's disagreement would fail
# open and silently (CLAUDE.md section 11).
function Test-MsysRootSpelling([string]$Path) {
    return ($Path -ceq '/') -or ($Path -ceq '/proc') -or $Path.StartsWith('/proc/')
}

# Returns 'msys' for the MSYS root or its synthetic /proc, 'net' for the MSYS network root, or
# $null for anything bounded.
function Get-WalkRootKind([string]$Operand) {
    # A walk root is absolute, and the fold can only ever reach one from a leading `/` (the
    # backslash rule above is anchored there too). Everything relative -- `.`, `./src`, `..`, a
    # drive path -- is the common case, and this returns it without allocating anything.
    if ($Operand.Length -eq 0 -or $Operand[0] -cne '/') { return $null }
    $p = Get-NormalizedPath $Operand
    if ($p -ceq '//') { return 'net' }
    if (Test-MsysRootSpelling $p) { return 'msys' }
    return $null
}

# ***THE PRUNE SIDE READS THE LITERAL OPERAND AND MUST NOT NORMALIZE.*** find's `-path` is a GLOB
# matched against the path string find itself generates, and find generates `/proc` -- never
# `/./proc` and never `/proc\`. Normalizing here would turn a pattern that matches NOTHING into an
# exemption, and an exemption is the direction that fails open (the deny side can only over-deny,
# which is visible; the suppression side goes silent). So `find / -path /./proc -prune -o -name x`
# stays a DENY even though `/./proc` and `/proc` name the same directory. The asymmetry lives in
# the ARGUMENT -- folded there, literal here -- not in a second idea of what a root is.
function Test-ProcPrunePattern([string]$Operand) {
    return Test-MsysRootSpelling $Operand
}

try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $j = $raw | ConvertFrom-Json
    $cmd = [string]$j.tool_input.command
    if (-not $cmd) { exit 0 }

    # THE EARLY OUT, AND IT CARRIES THE COST OF THIS WHOLE FILE. A fresh pwsh runs this on every
    # Bash and PowerShell call -- about 19 a turn on this repo -- and almost none of them can deny.
    # Every deny below needs a program token of find or grep, and neither blanking pass ever
    # INTRODUCES a character (they only overwrite with spaces), so a raw substring test is a strict
    # superset of every reachable deny: it can skip work, never a deny. The sibling
    # block-api-burn.ps1 short-circuits the same way on its own program name.
    if ($cmd.IndexOf('find', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
        $cmd.IndexOf('grep', [StringComparison]::OrdinalIgnoreCase) -lt 0) { exit 0 }

    # Scan the BLANKED form for structure. Both Hide- passes preserve length exactly, so an offset
    # into $scan is the same offset into $cmd: the blanked view answers "where does a command start
    # and what program is it", where quoted text must not count, and the raw view answers "what are
    # this command's operands", where a quoted token is an ordinary argument.
    # Quotes first, then heredoc bodies -- see Hide-HeredocBodies' header for why the order matters
    # and why it needs both views.
    $scan = Hide-HeredocBodies $cmd (Hide-QuotedSpans $cmd)

    # Judge each shell-separated simple command on its own, so `cd X && find /proc` is still caught
    # and `echo hi | xargs find /` is reached through the pipe.
    $bounds = New-Object 'System.Collections.Generic.List[int[]]'
    $cursor = 0
    # `(` and `)` and the backtick are separators too, and they are not cosmetic: without them
    # `echo $(find /proc)`, a backtick substitution and a `( find /proc )` subshell all put the walk
    # somewhere program position never looks, and each was measured ALLOWED. Splitting on them costs
    # nothing -- a segment starting mid-expression, such as the `-name x` after a `\(` group, is not
    # a program name and is skipped.
    foreach ($m in [regex]::Matches($scan, '(\|\||&&|[;|&\n()`])')) {
        $bounds.Add(@($cursor, ($m.Index - $cursor)))
        $cursor = $m.Index + $m.Length
    }
    $bounds.Add(@($cursor, ($scan.Length - $cursor)))

    # Options that take a SEPARATE value. Skipping the value is what stops `xargs -I {} find /` and
    # `grep -m 5 pattern /proc` mis-reading a value as a program or an operand. An option missing
    # from either list only ever mis-reads toward a NON-match, which is an allow -- so these lists
    # bound the guard's reach and can never open a hole somewhere else.
    # ONLY OPTIONS WHOSE VALUE IS A SEPARATE WORD BELONG HERE. An optional-argument option such as
    # grep's --color or xargs' -i takes its value ATTACHED (--color=auto, -i{}), so listing one
    # would consume a word the real program never does -- and that word is usually the pattern,
    # which shifts everything after it and turns a deny into a miss. Measured by inspection of the
    # two grammars: with --color listed, 'grep -r --color pattern /proc' read /proc as the pattern
    # and allowed.
    # grep's two lists are LONG-form only: the short options live in the per-character cluster read
    # below, where `efmABCDd` is the same set spelled as characters. Keeping the short spellings
    # here as well would be a second statement of one fact, kept in step by nothing.
    $XARGS_VALUE_OPTS = '^(-I|-n|-L|-P|-s|-d|-E|-a|--max-args|--max-lines|--max-procs|--delimiter|--arg-file)$'
    $GREP_VALUE_OPTS = '^(--regexp|--file|--max-count|--after-context|--before-context|--context|--devices|--directories|--include|--exclude|--exclude-dir|--binary-files|--label)$'
    $GREP_PATTERN_OPTS = '^(--regexp|--file)$'

    # THE MEASUREMENT LIVES ONCE. It was written out in both deny branches, so a re-measurement
    # would have updated one arm and left the other asserting a superseded number -- the shape
    # CLAUDE.md section 11 forbids (state a load-bearing fact once). The uninterruptibility half is
    # split out for the same reason: it is true of BOTH roots below, so it must not be re-spelled
    # inside each one's cause.
    $UNSTOPPABLE = "It cannot be interrupted reliably either, because killing a bash wrapper " +
                   "leaves its grandchildren running. "
    $WHY = "/proc/registry, /proc/registry32 and /proc/registry64 are the Windows registry " +
           "mounted as filesystem trees, so reading them opens a kernel handle per registry key " +
           "and HKEY_CLASSES_ROOT alone is effectively unbounded: measured 2026-09-20, a walk of " +
           "one mount passed 30,000 machine-wide handles in 15 seconds and was still climbing. " +
           $UNSTOPPABLE
    # THE NETWORK ROOT IS A DIFFERENT MECHANISM AND MUST NOT BORROW THE REGISTRY ONE. Exactly two
    # leading slashes are the UNC namespace in Git Bash, not the MSYS root, so a deny here that
    # named the registry mounts would rest on a premise that is false for the command in front of
    # the reader (CLAUDE.md section 11, SDS-3.7).
    $WHY_NET = "In Git Bash exactly two leading slashes are the UNC namespace rather than the " +
               "MSYS root: measured 2026-09-20, 'ls //' listed the network root, so the walk " +
               "enumerates network and WSL shares with no bound. " + $UNSTOPPABLE

    foreach ($b in $bounds) {
        if ($b[1] -le 0) { continue }
        $s = $scan.Substring($b[0], $b[1]).Trim()
        $rawSeg = $cmd.Substring($b[0], $b[1]).Trim()
        if (-not $s) { continue }

        # PROGRAM POSITION IS DECIDED ON THE BLANKED VIEW. `echo "find /proc"` blanks to
        # `echo "         "`, whose first token is echo, so the quoted text can never be read as a
        # program. A first token carrying a quote character IS the quoted case, and is skipped
        # outright rather than unquoted and trusted.
        $head = @($s -split '\s+' | Where-Object { $_ })
        if ($head.Count -eq 0) { continue }
        if ($head[0].Contains('"') -or $head[0].Contains("'")) { continue }

        $tokens = @($rawSeg -split '\s+' | Where-Object { $_ })
        if ($tokens.Count -eq 0) { continue }

        # Step past an xargs prefix so `ls | xargs find /proc -name x` is judged as the find it is.
        # Only this one wrapper is stepped past, and that is a GAP, not a bound -- `cmd /c`,
        # `env`, `sh -c`, `time` and a path-qualified program all still hide the walk behind them.
        # This sits on the same fail-open axis the header names: recognition is required to reach a
        # deny, so a wrapper missing here is a command that should have been refused and was not.
        $i = 0
        if ($tokens[0] -imatch '^xargs(\.exe)?$') {
            $i = 1
            while ($i -lt $tokens.Count) {
                $t = $tokens[$i]
                if (-not $t.StartsWith('-')) { break }
                $i++
                if ($t -cmatch $XARGS_VALUE_OPTS) { $i++ }
            }
            if ($i -ge $tokens.Count) { continue }
        }

        $prog = Get-Operand $tokens[$i]

        # ------------------------------------------------------------------ find
        if ($prog -imatch '^find(\.exe)?$') {
            # An explicit prune guard is the sanctioned way to walk from / and is the escape this
            # guard's own deny message names. Recognising it SUPPRESSES a deny and can never
            # produce one, so a spelling missing here costs a false deny -- noisy and visible --
            # rather than a silent hole.
            #
            # ***READ AS TOKENS, NOT AS A SUBSTRING OF THE SEGMENT.*** A regex over the raw text
            # exempted two things it should not have, both measured: `find / -path /procurement
            # -prune -o -print` matched because the pattern had no trailing boundary, and
            # `find / -name x # use -path /proc -prune -o instead` matched because the COMMENT
            # satisfied both halves. The second is the dangerous one -- this guard's own deny
            # message tells the agent to write exactly that text, so pasting the advice into a
            # comment would have turned the retry into an exemption.
            #
            # Comments are cut first (bash starts one at a `#` that begins a word), then `-path`
            # or `-wholename` must be a real token whose NEXT token is exactly /proc or below it,
            # and `-prune` must be its own token.
            $exprTokens = @()
            foreach ($tk in $tokens) {
                if ($tk.StartsWith('#')) { break }
                $exprTokens += $tk
            }
            $prunePattern = $null
            for ($n = 0; $n -lt $exprTokens.Count - 1; $n++) {
                if (($exprTokens[$n] -ieq '-path' -or $exprTokens[$n] -ieq '-wholename') -and
                    (Test-ProcPrunePattern (Get-Operand $exprTokens[$n + 1])) -and
                    ($exprTokens -ccontains '-prune')) {
                    $prunePattern = Get-Operand $exprTokens[$n + 1]
                    break
                }
            }

            $k = $i + 1
            # find's own leading global options, which sit BEFORE the path operands. `-D` always
            # takes a SEPARATE word (there is no attached form for it), so it consumes two; `-O`
            # is always attached to its level.
            #
            # THE TWO OPTION SHAPES THAT BROKE THE grep BRANCH DO NOT ARISE HERE, checked rather
            # than assumed: find has no short-option CLUSTER (`-HL` is not `-H -L`) and no long
            # option carrying a value with `=` that could sit in front of a path. So the whole of
            # find's option grammar is these three lines, and the path loop below starts where
            # they stop.
            # `--` ends find's options, and GNU findutils really does accept it -- measured
            # 2026-09-20, `find -- . -maxdepth 0` printed `.` and exited 0. Without this case the
            # path loop below stopped at the leading `-`, and `find -- /proc -name x` was ALLOWED.
            $endOfFindOptions = $false
            while ($k -lt $tokens.Count) {
                $t = Get-Operand $tokens[$k]
                if ($t -ceq '--') { $endOfFindOptions = $true; $k++; break }
                if ($t -cmatch '^-[HLP]$') { $k++; continue }
                if ($t -ceq '-D') { $k += 2; continue }
                if ($t -cmatch '^-O') { $k++; continue }
                break
            }
            # The path operands run until the expression starts. GNU find ends them at the first
            # token that begins an expression: an option, a group, a negation or a comma. After a
            # `--` the first operand is a path however it is spelled, so the leading-dash test is
            # dropped for it alone.
            while ($k -lt $tokens.Count) {
                $t = Get-Operand $tokens[$k]
                if ((-not $endOfFindOptions -and $t.StartsWith('-')) -or
                    $t -ceq '(' -or $t -ceq '!' -or $t -ceq ',') { break }
                $endOfFindOptions = $false
                $kind = Get-WalkRootKind $t
                if ($kind -ceq 'net') {
                    Deny ("BLOCKED: 'find $t' walks the MSYS network root. " + $WHY_NET +
                          "Do one of these instead: use the Glob tool; or name the share you " +
                          "mean and bound the depth, as in 'find //server/share -maxdepth 3'.")
                }
                if ($kind -ceq 'msys') {
                    # ***THE PRUNE EXEMPTION IS SCOPED TO THE ROOT IT CAN ACTUALLY BOUND, AND IT IS
                    # CHECKED HERE RATHER THAN BEFORE THE LOOP.*** find builds the path it tests by
                    # appending to the LITERAL root you gave it, so `-path P` can match something
                    # only when P starts with that literal root. Exempting on the pattern alone was
                    # measured letting four walks through: `find /. -path /proc -prune -o -name x
                    # -print` generates `/./proc`, the glob matches nothing, and the registry walk
                    # ran -- and this guard's own deny message hands the agent that exact text, so
                    # an agent following the advice landed there. Same for `find /proc/.`,
                    # `find /tmp/..` and `find /proc/registry -path /proc -prune`. The 'net' arm
                    # above is deliberately decided FIRST: there is no /proc under the UNC
                    # namespace, so pruning it bounds nothing there.
                    if ($null -ne $prunePattern -and $prunePattern.StartsWith($t)) { $k++; continue }
                    Deny ("BLOCKED: 'find $t' walks the MSYS root. " + $WHY +
                          "Do one of these instead: use the Glob tool; or name a real root and " +
                          "bound the depth, as in 'find ./src -maxdepth 4 -name *.py'; or put " +
                          "'-path /proc -prune -o' before the rest of the expression -- that same " +
                          "walk with all of /proc pruned exits at once. Prune the WHOLE of /proc: " +
                          "pruning /proc/registry alone falls into /proc/registry32 and keeps " +
                          "leaking.")
                }
                $k++
            }
            continue
        }

        # ------------------------------------------------------------------ grep
        if ($prog -imatch '^grep(\.exe)?$') {
            $recursive = $false
            $patternTaken = $false
            $targets = New-Object 'System.Collections.Generic.List[string]'
            $k = $i + 1
            $endOfOptions = $false
            while ($k -lt $tokens.Count) {
                $t = Get-Operand $tokens[$k]
                if (-not $endOfOptions -and $t -ceq '--') { $endOfOptions = $true; $k++; continue }

                # ------------------------------------------------ a LONG option
                # ***THE VALUE MAY BE ATTACHED WITH `=` OR BE THE NEXT WORD, AND THE TWO DECIDE
                # DIFFERENT THINGS.*** Matching the whole token against a name list shipped a
                # fail-open that was measured: `grep -r --regexp=foo /proc` was ALLOWED, because
                # `--regexp=foo` matched neither list, so the pattern was never marked taken and
                # `/proc` was read as the pattern instead of as a target. Split at the first `=`
                # first: the NAME decides what the option is, and whether a value was attached
                # decides whether the next word belongs to it.
                if (-not $endOfOptions -and $t.StartsWith('--')) {
                    $eq = $t.IndexOf('=')
                    $name = if ($eq -ge 0) { $t.Substring(0, $eq) } else { $t }
                    $attached = if ($eq -ge 0) { $t.Substring($eq + 1) } else { $null }
                    # Long option NAMES are compared case-sensitively, like getopt_long's own
                    # table: `grep --RECURSIVE foo /proc` is an unrecognised option that walks
                    # nothing, and denying it would hand the reader the registry cause for a
                    # command that never ran. The VALUE stays case-insensitive, which can only
                    # over-deny.
                    if ($name -cmatch '^--(recursive|dereference-recursive)$') { $recursive = $true }
                    if ($name -ceq '--directories' -and $attached -ieq 'recurse') {
                        $recursive = $true
                    }
                    if ($name -cmatch $GREP_PATTERN_OPTS) { $patternTaken = $true }
                    $k++
                    if ($null -eq $attached -and $name -cmatch $GREP_VALUE_OPTS -and
                        $k -lt $tokens.Count) {
                        # `-d recurse` is `-r` spelled long-hand, and GNU grep accepts the long
                        # option with its value as a SEPARATE word too. Testing only the short
                        # spelling let `grep --directories recurse pattern /proc` through: the
                        # value was consumed here without being read, so the scan saw an
                        # option-only grep and never set $recursive.
                        if ($name -ceq '--directories' -and
                            (Get-Operand $tokens[$k]) -ieq 'recurse') { $recursive = $true }
                        $k++
                    }
                    continue
                }

                # ------------------------------------------------ a SHORT-option cluster
                # ***READ THE CLUSTER CHARACTER BY CHARACTER.*** Testing the whole token against
                # `^-[A-Za-z]*[rR][A-Za-z]*$` shipped a fail-open that was measured: `grep -rm5 foo
                # /proc` was ALLOWED, because the digit in the attached value of `-m` broke the
                # all-letters shape and the `-r` inside the bundle went unseen. `-rA2`, `-rC3` and
                # `-r5` failed the same way. A per-character read also gets the OTHER direction
                # right, which the old shape got only by luck: in `grep -er foo /proc` the `r` is
                # the ARGUMENT of `-e`, so that command really is non-recursive and must stay
                # ALLOWED -- the walk it looks like is a walk it never does.
                if (-not $endOfOptions -and $t.StartsWith('-') -and $t.Length -gt 1) {
                    $chars = $t.Substring(1)
                    $valueShort = $null
                    for ($c = 0; $c -lt $chars.Length; $c++) {
                        $ch = [string]$chars[$c]
                        if ($ch -cmatch '^[rR]$') { $recursive = $true; continue }
                        # Anything not taking a value -- including a `-NUM` context shortcut --
                        # carries no argument and cannot shift the reading, so it is skipped.
                        if ($ch -cnotmatch '^[efmABCDd]$') { continue }
                        if ($ch -cmatch '^[ef]$') { $patternTaken = $true }
                        $rest = $chars.Substring($c + 1)
                        if ($rest) {
                            if ($ch -ceq 'd' -and $rest -ieq 'recurse') { $recursive = $true }
                        } else {
                            $valueShort = $ch
                        }
                        # The remainder of the cluster is this option's value, never more flags.
                        break
                    }
                    $k++
                    if ($null -ne $valueShort -and $k -lt $tokens.Count) {
                        if ($valueShort -ceq 'd' -and
                            (Get-Operand $tokens[$k]) -ieq 'recurse') { $recursive = $true }
                        $k++
                    }
                    continue
                }

                if (-not $patternTaken) { $patternTaken = $true; $k++; continue }
                $targets.Add($t)
                $k++
            }
            if ($recursive) {
                foreach ($t in $targets) {
                    $kind = Get-WalkRootKind $t
                    if ($kind -ceq 'net') {
                        Deny ("BLOCKED: 'grep -r $t' walks the MSYS network root. " + $WHY_NET +
                              "Do one of these instead: use the Grep tool; or name the share you " +
                              "mean, as in 'grep -rn pattern //server/share'.")
                    }
                    if ($kind -ceq 'msys') {
                        Deny ("BLOCKED: 'grep -r $t' walks the MSYS root. " + $WHY +
                              "Do one of these instead: use the Grep tool; or name a real " +
                              "directory, as in 'grep -rn pattern ./src'.")
                    }
                }
            }
            continue
        }
    }

    exit 0
} catch {
    # Fail open, always. A broken guard must not wedge every shell call in the fleet.
    exit 0
}
