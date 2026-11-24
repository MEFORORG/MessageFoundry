# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# PreToolUse guard: deny a `find` or recursive `grep` rooted at the MSYS root `/`, at its synthetic
# /proc, or at the MSYS network root `//`, and name the bounded command to use instead. Anything
# else passes silently (exit 0). Fail-OPEN on any error: a broken guard must not wedge every call.
#
# WHY A DENY AND NOT A TIMEOUT. /proc/registry, /proc/registry32 and /proc/registry64 are the
# Windows registry mounted as trees, so a walk opens a kernel handle per key and does not end; the
# measurement is in $WHY below. Killing a bash wrapper leaves its grandchildren running, so a walk
# cannot be stopped once started. scripts/coord/reap-orphans.ps1 is the after-the-fact half.
# -maxdepth is not an exemption, because the depth at which the mounts start moves with the root;
# the escape is an explicit prune of the WHOLE of /proc (pruning one mount falls into the next).
#
# WHAT IT DOES NOT CATCH, at least: any walker other than find and grep (`rg -uu /`, `ls -R /proc`,
# `du`, `tar`, `7z`); any wrapper other than xargs (`env`, `sh -c`, `time`, a path-qualified
# program); a walk of the segment's own `cd` (`cd /proc && find .`); and a grep long option
# abbreviation (`grep --rec x /proc`). Recognising the program is required to deny, so each of these
# is a silent allow. Inverting that, so only provably non-walking programs are allowed, is the
# deeper fix and is not built.
#
# ROOTS ARE COMPARED AS PATHS, OPTIONS AS GRAMMAR. Every bypass measured on 2026-09-20 came from
# comparing a spelling instead of what it names: `/.`, `//`-variants, `/pro'c'`, `/pro\c`,
# `--regexp=foo`, `-rm5`. The functions below fold each one to what the shell and the program see.
#
# WIRING IS A PROPERTY OF settings.json, NOT OF THIS FILE. ASCII-only on purpose (PS 5.1).

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

# Blank heredoc BODIES, keeping line structure and length: a body is data, but its lines would sit
# in program position. The opener is found on the quote-masked text and its delimiter read from the
# raw text, at the same offset. Raw-only let `grep "x << y"` open a heredoc that never ends, and
# blank the real walk after it; masked-only loses `<<'EOF'`. `<<<` opens nothing, and the delimiter
# must start with a letter or underscore, so `$((1<<2))` opens nothing either. A missed opener such
# as `cat<<EOF` can only add a false deny.
# DEBT: this and Hide-QuotedSpans are second copies of block-blanket-git-stage.ps1's helpers, and
# have already diverged in error posture. Extracting them needs a library entry in the unwired list
# of tests/test_claude_settings_contract.py, which globs every scripts/hooks/*.ps1.
function Hide-HeredocBodies([string]$Text, [string]$Masked) {
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

# Blank the CONTENTS of quoted spans, keeping the quotes and the length, so a separator or a
# find-looking word inside quotes never reaches program position (`echo "find /proc"`). Equal
# length is what lets an offset into the blanked text index the raw text.
#
# READ AS BASH READS IT, NOT AS A QUOTE TOGGLE (BACKLOG #5607). A toggle that blanked every span
# whole and ignored backslashes allowed three kinds of walk. Inside double quotes bash still runs a
# `$(...)` or backtick substitution, so `echo "$(find /proc)"` hid the walk; such a substitution is
# left visible here, and starts its own quoting. An unquoted `"` or `'`, and a `"` inside double
# quotes, opens or closes nothing, so a toggle shifted every later span by one and blanked the
# separator and the walk after it. And `$'...'` takes backslash escapes, so `$'\''` is one quote
# character rather than the end of a span. Unclosed contexts at the end simply stop.
#
# BASH ONLY. The PowerShell tool is screened too, and there the backtick is the escape and a
# backslash is literal, so `"done`n"` and `"D:\dir\"` would read as a substitution and an escaped
# quote and blank the command after them. -Plain keeps the toggle this guard had before, which
# reads neither PowerShell's `"$(...)"` subexpression nor a backtick-escaped quote;
# Hide-PowerShellSpans, below, reads the escape. The same toggle
# also runs beside the bash reading, as a floor; the call site says why.
#
# A HEREDOC BODY IS DATA, and it is blanked here too, line for line. Hide-HeredocBodies runs on the
# output of this function, so a quote in a body (`don't`) would otherwise open a span here that
# blanks the terminator and the walk after it -- most often inside "$(cat <<'EOF' ... EOF)", the
# commit-message form. Arithmetic, `$((...))`, is blanked for the same reason: `1 << n` would read
# as a heredoc opener. A substitution inside it still runs, so that is left visible, and so is the
# `#` of a comment, whose body is blanked.
# THE REFINED VIEW, -Refined, ONLY ADDS DENIES (BACKLOG #5607). It is this bash reading with
# corrections, and every line it adds sits in an `if ($Refined)` block, so the bash view is
# unchanged. `$((` is read as arithmetic, but if a `)` at its depth 0 is not followed by `)`, that
# `$((` is read again as `$(` and `(`, as bash does; inside it a quote or a backslash keeps a paren
# from counting. `((` starting a word, outside `${...}`, is read the same way. `$[ ... ]` is
# arithmetic. A `<<` glued to a plain word (`cat<<EOF`) opens a heredoc, unless the line has
# already opened arithmetic or a `[`, it is inside `${...}`, or the word is not a plain name. Every heredoc
# opened on a line gets its own body, and each terminator line stays visible. The delimiter is read in place, never from a
# slice of the text. Past a processed-character budget it gives up and returns $null, and the
# caller then adds nothing. It still does not read at least these, which stay as the bash view
# reads them: a spaced shift in a command with no quote, `((` glued to a keyword (`do((`), a
# substitution in the body of a heredoc whose delimiter is unquoted, a glued opener after a bare
# `(` or later on a line that opened arithmetic, a `$((cmd) )` nested inside arithmetic, a case
# pattern's `)`, a terminator compared after trimming, delimiters such as `<<END-X` and
# `<<E"O"F`, and a glued opener whose word is not a plain name. The older masker in block-blanket-git-stage.ps1 is untouched.
# Get-SiteTexts, below, adds texts for at least some of two of these, a spaced shift in arithmetic
# and a `$((cmd) )` nested inside arithmetic, and for some nestings past this view's budget; this
# view is unchanged.
function Hide-QuotedSpans([string]$Text, [switch]$Plain, [switch]$Refined) {
    if ($Text.IndexOf('"') -lt 0 -and $Text.IndexOf("'") -lt 0) { return $Text }
    if ($Plain) {
        $sb = [System.Text.StringBuilder]::new($Text.Length)
        $quote = $null
        foreach ($ch in $Text.ToCharArray()) {
            if ($null -ne $quote) {
                if ($ch -ceq $quote) { $quote = $null; [void]$sb.Append($ch) }
                elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
                else { [void]$sb.Append(' ') }
                continue
            }
            if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch }
            [void]$sb.Append($ch)
        }
        return $sb.ToString()
    }
    $sb = [System.Text.StringBuilder]::new($Text.Length)
    # The context stack: top (unquoted), dq, sq, ansi ($'...'), sub ($( inside double quotes, with
    # its open-paren depth) and bt (a backtick substitution inside double quotes). Only top, sub and
    # bt are unquoted; a substitution OUTSIDE double quotes needs no context, as it was never blanked.
    $kinds = [System.Collections.Generic.List[string]]::new()
    $depths = [System.Collections.Generic.List[int]]::new()
    $kinds.Add('top'); $depths.Add(0)
    $prevDollar = $false
    # Whether the next unquoted character starts a word, which is where a `#` starts a comment, and
    # the depth of unquoted `${...}`, inside which it never does.
    $wordStart = $true
    $braceDepth = 0
    # The delimiter of a heredoc opened on this line, then of the body being blanked.
    $pending = $null
    $bodyTerm = $null
    $n = 0
    if ($Refined) {
        # One save per open arithmetic frame, to restore when the frame turns out to be a subshell;
        # the sites already read as subshells; heredoc delimiters opened on this line, then the
        # bodies still to blank, in order.
        # A site's reading depends only on the text from it and on the state $siteKey records, so
        # a site is keyed by both and kept across a restore. Cutting every later site there
        # instead made each restore re-read the frames nested in it, and about ten nested levels
        # of `$(($(...) ) )` then spent the budget (BACKLOG #5607). Each restore still re-reads its
        # own frame, so deeper nesting still spends it, and so can a nesting whose key changes on
        # the re-read, such as one inside an unclosed `${`.
        $saves = [System.Collections.Generic.List[object]]::new()
        $subshellSites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $siteKey = {
            param([int]$Site)
            # Delimiters hold no newline, so the counts and newline joins keep each key unambiguous.
            $p = if ($null -eq $pending) { '-' } else { '+' + $pending }
            $b = if ($null -eq $bodyTerm) { '-' } else { '+' + $bodyTerm }
            "$Site $([int]$prevDollar)$([int]$wordStart)$([int]$arithOnLine)$([int]$bracketOnLine) $braceDepth" +
                "`n$p`n$b`n$($pendingQ.Count)`n$($pendingQ -join "`n")`n$($bodyQ.Count)`n$($bodyQ -join "`n")"
        }
        $pendingQ = [System.Collections.Generic.List[string]]::new()
        $bodyQ = [System.Collections.Generic.List[string]]::new()
        $arithOnLine = $false
        # An unquoted `[` earlier on the line: bash reads a subscript such as `a[ x<<y ]=1` whole.
        $bracketOnLine = $false
        $steps = 0
        $budget = 8 * $Text.Length + 4096
        $delimRe = [regex]::new('\G-?[ \t]*(?:''([^''\n]+)''|"([^"\n]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))')
        $newSave = {
            param([int]$Site, [string]$Key)
            @{
                Site = $Site; Key = $Key; Frame = $kinds.Count; SbLen = $sb.Length
                Kinds = [System.Collections.Generic.List[string]]::new($kinds)
                Depths = [System.Collections.Generic.List[int]]::new($depths)
                PrevDollar = $prevDollar; WordStart = $wordStart; BraceDepth = $braceDepth
                Pending = $pending; BodyTerm = $bodyTerm; ArithOnLine = $arithOnLine; BracketOnLine = $bracketOnLine
                PendingQ = [System.Collections.Generic.List[string]]::new($pendingQ)
                BodyQ = [System.Collections.Generic.List[string]]::new($bodyQ)
            }
        }
    }
    while ($n -lt $Text.Length) {
        if ($Refined) {
            if (++$steps -gt $budget) { return $null }
            if ($bodyQ.Count -gt 0) {
                $end = $Text.IndexOf("`n", $n)
                if ($end -lt 0) { $end = $Text.Length }
                $line = $Text.Substring($n, $end - $n)
                if ($line.Trim() -ceq $bodyQ[0]) { [void]$sb.Append($line); $bodyQ.RemoveAt(0) }
                else { [void]$sb.Append(' ' * $line.Length) }
                if ($end -lt $Text.Length) { [void]$sb.Append("`n") }
                $n = $end + 1
                continue
            }
        }
        if ($null -ne $bodyTerm) {
            # At the start of a body line: blank it whole, or keep the terminator line as it is.
            $end = $Text.IndexOf("`n", $n)
            if ($end -lt 0) { $end = $Text.Length }
            $line = $Text.Substring($n, $end - $n)
            if ($line.Trim() -ceq $bodyTerm) { [void]$sb.Append($line); $bodyTerm = $null }
            else { [void]$sb.Append(' ' * $line.Length) }
            if ($end -lt $Text.Length) { [void]$sb.Append("`n") }
            $n = $end + 1
            continue
        }
        $ch = $Text[$n]
        $top = $kinds.Count - 1
        $kind = $kinds[$top]
        $next = if ($n + 1 -lt $Text.Length) { $Text[$n + 1] } else { $null }
        if ($kind -ceq 'arith') {
            if ($Refined) {
                # A `)` at depth 0 not followed by `)` ends a subshell, so this frame was never
                # arithmetic: restore the state saved at its site and read the site again as one.
                if ($ch -ceq ')' -and $depths[$top] -eq 0 -and $saves.Count -gt 0 -and
                    $saves[$saves.Count - 1].Frame -eq $top) {
                    $sv = $saves[$saves.Count - 1]
                    $saves.RemoveAt($saves.Count - 1)
                    if ($next -cne ')') {
                        [void]$subshellSites.Add($sv.Key)
                        $sb.Length = $sv.SbLen
                        $kinds = $sv.Kinds; $depths = $sv.Depths
                        $prevDollar = $sv.PrevDollar; $wordStart = $sv.WordStart; $braceDepth = $sv.BraceDepth
                        $pending = $sv.Pending; $bodyTerm = $sv.BodyTerm; $arithOnLine = $sv.ArithOnLine
                        $bracketOnLine = $sv.BracketOnLine
                        $pendingQ = $sv.PendingQ; $bodyQ = $sv.BodyQ
                        $n = $sv.Site; continue
                    }
                }
                # A quote or an escape keeps a paren from counting, as bash reads the frame.
                if ($ch -ceq '\' -and $null -ne $next) {
                    [void]$sb.Append(' ')
                    [void]$sb.Append($(if ($next -ceq "`n") { $next } else { ' ' }))
                    $n += 2; continue
                }
                if ($ch -ceq "'" -or $ch -ceq '"') {
                    $kinds.Add($(if ($ch -ceq "'") { 'sq' } else { 'dq' })); $depths.Add(0); [void]$sb.Append($ch)
                    $n++; continue
                }
            }
            # Arithmetic still runs a substitution, so that is left visible as in double quotes.
            if ($ch -ceq '$' -and $next -ceq '(' -and -not ($n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq '(')) {
                $kinds.Add('sub'); $depths.Add(0); [void]$sb.Append('$('); $wordStart = $true; $n += 2; continue
            }
            if ($ch -ceq '`') { $kinds.Add('bt'); $depths.Add(0); [void]$sb.Append($ch); $wordStart = $true; $n++; continue }
            if ($ch -ceq '(') { $depths[$top]++; [void]$sb.Append(' ') }
            elseif ($ch -ceq ')' -and $depths[$top] -gt 0) { $depths[$top]--; [void]$sb.Append(' ') }
            elseif ($ch -ceq ')' -and $next -ceq ')') {
                $kinds.RemoveAt($top); $depths.RemoveAt($top); [void]$sb.Append('))'); $wordStart = $false; $n += 2; continue
            }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
            else { [void]$sb.Append(' ') }
            $n++; continue
        }
        if ($Refined -and $kind -ceq 'arithb') {
            # `$[ ... ]`, read as the arithmetic frame above is, closing at its matching `]`.
            if ($ch -ceq '$' -and $next -ceq '(' -and -not ($n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq '(')) {
                $kinds.Add('sub'); $depths.Add(0); [void]$sb.Append('$('); $wordStart = $true; $n += 2; continue
            }
            if ($ch -ceq '`') { $kinds.Add('bt'); $depths.Add(0); [void]$sb.Append($ch); $wordStart = $true; $n++; continue }
            if ($ch -ceq '\' -and $null -ne $next) {
                [void]$sb.Append(' ')
                [void]$sb.Append($(if ($next -ceq "`n") { $next } else { ' ' }))
                $n += 2; continue
            }
            if ($ch -ceq "'" -or $ch -ceq '"') {
                $kinds.Add($(if ($ch -ceq "'") { 'sq' } else { 'dq' })); $depths.Add(0); [void]$sb.Append($ch)
                $n++; continue
            }
            if ($ch -ceq '[') { $depths[$top]++; [void]$sb.Append(' ') }
            elseif ($ch -ceq ']' -and $depths[$top] -gt 0) { $depths[$top]--; [void]$sb.Append(' ') }
            elseif ($ch -ceq ']') { $kinds.RemoveAt($top); $depths.RemoveAt($top); [void]$sb.Append($ch); $wordStart = $false }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
            else { [void]$sb.Append(' ') }
            $n++; continue
        }
        if ($Refined -and $ch -ceq '$' -and $kind -cne 'sq' -and $kind -cne 'ansi') {
            if ($next -ceq '(' -and $n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq '(') {
                $key = & $siteKey $n
                if ($subshellSites.Contains($key)) {
                    # Read again as `$(`, then `(`, as the bash view reads a `$(`.
                    $arithOnLine = $true
                    if ($kind -cne 'top') { $kinds.Add('sub'); $depths.Add(0) }
                    [void]$sb.Append('$('); $prevDollar = $false; $wordStart = $true
                    $n += 2; continue
                }
                $saves.Add((& $newSave $n $key))
                $arithOnLine = $true
                $kinds.Add('arith'); $depths.Add(0); [void]$sb.Append('$(('); $prevDollar = $false
                $n += 3; continue
            }
            if ($next -ceq '[') {
                $arithOnLine = $true
                $kinds.Add('arithb'); $depths.Add(0); [void]$sb.Append('$['); $prevDollar = $false
                $n += 2; continue
            }
        }
        if ($ch -ceq '$' -and $next -ceq '(' -and $n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq '(' -and
            $kind -cne 'sq' -and $kind -cne 'ansi') {
            $kinds.Add('arith'); $depths.Add(0); [void]$sb.Append('$(('); $prevDollar = $false
            $n += 3; continue
        }
        if ($kind -ceq 'sq' -or $kind -ceq 'ansi') {
            if ($kind -ceq 'ansi' -and $ch -ceq '\' -and $null -ne $next) {
                [void]$sb.Append(' ')
                [void]$sb.Append($(if ($next -ceq "`n") { $next } else { ' ' }))
                $n += 2; continue
            }
            if ($ch -ceq "'") { $kinds.RemoveAt($top); $depths.RemoveAt($top); [void]$sb.Append($ch) }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
            else { [void]$sb.Append(' ') }
            $n++; continue
        }
        if ($kind -ceq 'dq') {
            # A backslash is consumed inside double quotes when it guards one of " $ ` \. Before a
            # newline it is blanked alone, so the newline stays where Hide-HeredocBodies counts it.
            if ($ch -ceq '\' -and $null -ne $next -and '"$`\'.IndexOf($next) -ge 0) {
                [void]$sb.Append('  '); $n += 2; continue
            }
            if ($ch -ceq '"') { $kinds.RemoveAt($top); $depths.RemoveAt($top); [void]$sb.Append($ch) }
            elseif ($ch -ceq '$' -and $next -ceq '(') {
                $kinds.Add('sub'); $depths.Add(0); [void]$sb.Append('$('); $wordStart = $true; $n += 2; continue
            }
            elseif ($ch -ceq '`') { $kinds.Add('bt'); $depths.Add(0); [void]$sb.Append($ch); $wordStart = $true }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
            else { [void]$sb.Append(' ') }
            $n++; continue
        }
        # Unquoted: top, sub or bt. A newline ends the line a heredoc was opened on, so its body
        # starts here. A heredoc opener is read as Hide-HeredocBodies reads it: after a space or at
        # the start, not `<<<`, and a delimiter that starts with a letter or underscore.
        if ($Refined) {
            if ($ch -ceq '[') { $bracketOnLine = $true }
            if ($ch -ceq "`n") {
                $arithOnLine = $false; $bracketOnLine = $false
                if ($pendingQ.Count -gt 0) {
                    [void]$sb.Append($ch); $bodyQ.AddRange($pendingQ); $pendingQ.Clear()
                    $prevDollar = $false; $wordStart = $true
                    $n++; continue
                }
            }
            if ($ch -ceq '<' -and $next -ceq '<' -and -not ($n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq '<') -and
                -not ($n -gt 0 -and $Text[$n - 1] -ceq '<')) {
                $opens = $n -eq 0 -or [char]::IsWhiteSpace($Text[$n - 1])
                if (-not $opens -and $braceDepth -eq 0 -and -not $arithOnLine -and -not $bracketOnLine) {
                    # Glued: the word before it must be a plain name, starting after whitespace,
                    # `;`, `&`, `|`, `$(` or a backtick -- never after a bare `(`.
                    $w = $n - 1
                    while ($w -ge 0 -and 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-'.IndexOf($Text[$w]) -ge 0) { $w-- }
                    $opens = $w -lt $n - 1 -and ($w -lt 0 -or [char]::IsWhiteSpace($Text[$w]) -or
                        ';&|`'.IndexOf($Text[$w]) -ge 0 -or ($Text[$w] -ceq '(' -and $w -gt 0 -and $Text[$w - 1] -ceq '$'))
                }
                if ($opens) {
                    $d = $delimRe.Match($Text, $n + 2)
                    if ($d.Success) {
                        $pendingQ.Add((@($d.Groups[1].Value, $d.Groups[2].Value, $d.Groups[3].Value) |
                            Where-Object { $_ } | Select-Object -First 1))
                    }
                    [void]$sb.Append('<<'); $prevDollar = $false; $wordStart = $false
                    $n += 2; continue
                }
            }
            if ($ch -ceq '(' -and $next -ceq '(') {
                $key = if ($wordStart -and $braceDepth -eq 0) { & $siteKey $n } else { $null }
                if ($null -ne $key -and -not $subshellSites.Contains($key)) {
                    $saves.Add((& $newSave $n $key))
                    $arithOnLine = $true
                    $kinds.Add('arith'); $depths.Add(0); [void]$sb.Append('(('); $prevDollar = $false
                    $n += 2; continue
                }
                $arithOnLine = $true
            }
        }
        if ($ch -ceq "`n" -and $null -ne $pending) {
            [void]$sb.Append($ch); $bodyTerm = $pending; $pending = $null; $prevDollar = $false; $wordStart = $true
            $n++; continue
        }
        if ($ch -ceq '<' -and $next -ceq '<' -and ($n -eq 0 -or [char]::IsWhiteSpace($Text[$n - 1])) -and
            -not ($n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq '<')) {
            $d = [regex]::Match($Text.Substring($n + 2), '^-?[ \t]*(?:''([^''\n]+)''|"([^"\n]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))')
            if ($d.Success) {
                $pending = @($d.Groups[1].Value, $d.Groups[2].Value, $d.Groups[3].Value) |
                    Where-Object { $_ } | Select-Object -First 1
            }
            [void]$sb.Append('<<'); $prevDollar = $false; $wordStart = $false
            $n += 2; continue
        }
        # A `#` starting a word starts a comment, which bash never runs and in which a quote opens
        # nothing. It is blanked up to the newline (or, in a backtick substitution, the closing
        # backtick), keeping the `#`. A word starts after unquoted, unescaped whitespace, `;`, `&`,
        # `|`, `(` or an opening `$(` or backtick -- never after a `)`, a quote or an escape, nor
        # inside `${...}`, where bash carries the word on (`$(echo a)#b` and `a\ #b` are words).
        if ($ch -ceq '#' -and $wordStart -and $braceDepth -eq 0) {
            $end = $Text.IndexOf("`n", $n)
            if ($end -lt 0) { $end = $Text.Length }
            if ($kind -ceq 'bt') {
                $tick = $Text.IndexOf('`', $n)
                if ($tick -ge 0 -and $tick -lt $end) { $end = $tick }
            }
            [void]$sb.Append('#' + ' ' * ($end - $n - 1)); $prevDollar = $false
            # The operand loop reads the RAW text to the end of a bound, so a comment the refined
            # view exposes would hand it the comment's words (`find . # see; ls /proc`). Ending the
            # bound at the `#` keeps them out.
            if ($Refined) { $sb[$sb.Length - ($end - $n)] = [char]';' }
            $n = $end; continue
        }
        # An unquoted backslash escapes the next character, whatever it is.
        if ($ch -ceq '\') {
            [void]$sb.Append($ch)
            if ($null -ne $next) { [void]$sb.Append($next) }
            $prevDollar = $false; $wordStart = $false
            $n += 2; continue
        }
        if ($ch -ceq "'") {
            $kinds.Add($(if ($prevDollar) { 'ansi' } else { 'sq' })); $depths.Add(0)
        }
        elseif ($ch -ceq '"') { $kinds.Add('dq'); $depths.Add(0) }
        elseif ($kind -ceq 'sub' -and $ch -ceq '(') { $depths[$top]++ }
        elseif ($kind -ceq 'sub' -and $ch -ceq ')') {
            if ($depths[$top] -gt 0) { $depths[$top]-- } else { $kinds.RemoveAt($top); $depths.RemoveAt($top) }
        }
        elseif ($kind -ceq 'bt' -and $ch -ceq '`') { $kinds.RemoveAt($top); $depths.RemoveAt($top) }
        # A top-level backtick is pushed too, only so that a comment inside it ends at its close.
        elseif (($kind -ceq 'sub' -or $kind -ceq 'top') -and $ch -ceq '`') {
            $kinds.Add('bt'); $depths.Add(0); [void]$sb.Append($ch); $prevDollar = $false; $wordStart = $true
            $n++; continue
        }
        elseif ($kind -cne 'top' -and $ch -ceq '$' -and $next -ceq '(') {
            $kinds.Add('sub'); $depths.Add(0); [void]$sb.Append('$('); $prevDollar = $false; $wordStart = $true
            $n += 2; continue
        }
        elseif ($ch -ceq '{' -and $prevDollar) { $braceDepth++ }
        elseif ($ch -ceq '}' -and $braceDepth -gt 0) { $braceDepth-- }
        [void]$sb.Append($ch)
        $wordStart = [char]::IsWhiteSpace($ch) -or ';&|('.IndexOf($ch) -ge 0
        $prevDollar = ($ch -ceq '$') -and -not $prevDollar
        $n++
    }
    return $sb.ToString()
}

# THE POWERSHELL TOOL'S READING (BACKLOG #5451), with the same contract as Hide-QuotedSpans: equal
# length, newlines kept. The plain toggle reads a backtick-escaped quote as a quote, so `"a`"b"` and
# `` `" `` outside a string shifted every later span by one and blanked the walk after it. Here a
# backtick outside single quotes escapes the next character, and a backtick ending a line, LF or
# CRLF, is a line continuation that separates tokens without ending the statement.
#
# AMONG A COMMAND'S ARGUMENTS a `#` or `<#` STARTS A COMMENT ONLY AT A TOKEN START, as
# PowerShell's tokenizer reads it: at least at the start, after whitespace or one of `;|&(){},`,
# after a quoted string that itself began a token, after a here-string's close, and after a `>&1`
# or `>&2` redirection. Elsewhere it continues a bareword and is literal: at least after `a`, `^`,
# `/`, `_`, `a<`, an escaped character, a quote glued to a word (`a'b'#`), and `$b` (`$b#c` is one
# argument). An argument with a member access or an index (`$x.Name#`, `$a[0]#`, `$a::b#`,
# `(gci).Name#`, `'a'.Length#`) is an expression, and `#` after it starts a comment, until a glued
# `-`, `=` or a word after `]` makes it a word again.
#
# AN EXPRESSION reads `#` as a comment after any of its tokens, glued or not: at least after a
# variable (`$y#`), a number (`5#`, `1kb#`), a member (`$x.Count#`), a string, a closing
# parenthesis or bracket, and an operator (`=+-*/%!` or `-eq`). A statement is read as an
# expression from its first character when that is `$`, `[`, a quote, a here-string, `!`, `@{`,
# `@(`, a number, a negative number, or `-not`, `-bnot`, `-split` or `-join`. A statement starts
# at least at the start, after a line end, `;`, `|`, `&&` or `||`, inside `(`, `$(`, `@(` or `{`,
# and after `return`, `throw` or `exit`. A bareword at a token start in an expression, such as the
# command in `$x = Get-ChildItem *#`, ends expression mode, and so does a word starting with a
# digit that is not a number (`7z`, `1_000`, `7.Foo`), and a call `&`. From there the reading
# takes a command's arguments, where `=#` is one bareword. The close of `(`, `$(`, `@(` or `{`
# restores the reading before it. `@{` at a token start opens a hashtable, whose keys, after `@{`,
# `;` or a line end that does not follow an operator, are read as expressions. `${...}` is a
# variable name, never a comment or a brace.
#
# THIS READING ONLY ADDS DENIES to the plain toggle's, which is judged first. At least two of its
# misreadings add a false deny. A comment read where PowerShell has none blanks an opening quote and
# exposes the prose the quote holds. A comment left unread keeps its backtick as an escape and its
# `${` as a variable, so a quote after it pairs wrong, and its `;` can split a command out of it.
# An unread comment's apostrophe can also hide a walk after it, which then goes undenied.
#
# A comment, a `<# ... #>` block and a here-string body (`@'` or `@"` ending its line, closed by
# `'@` or `"@` starting one) are blanked whole, so an apostrophe in one opens no span. It still
# does not read at least these: a `"$(...)"` subexpression, a backtick inside a program name or a
# path, a `-Param:'x'#` argument, a statement starting with `-1`, a bare CR as a line end, and a
# typographic quote.
function Hide-PowerShellSpans([string]$Text) {
    $sb = [System.Text.StringBuilder]::new($Text.Length)
    $quote = $null
    $here = $null
    $inWord = $false        # the last character continues a bareword, so a `#` here is literal
    $quoteGlued = $false    # the open quote was glued to a bareword
    $stmtStart = $true
    $exprStmt = $false      # this statement is read as an expression
    $firstToken = $false    # still inside that expression statement's first token
    $hashKey = $false       # the next token is a hashtable key, read as an expression
    $atStart = -1           # where an `@` began a token, so a `{` after it opens a hashtable
    # One frame per open `(` or `{`: its kind ('h' for a hashtable) and the reading to restore.
    $frames = [System.Collections.Generic.List[object]]::new()
    # Once one `${` finds no `}` before the end, none after it can, so a run of them stays linear.
    $braceRunsOut = $false
    # A number as PowerShell scans one, anchored where a token starts. Anything else that starts
    # with a digit (`7z`, `1_000`, `7.Foo`, `1e`) is a generic word, and among those `#` is literal.
    # The digits are one atomic group: backtracking into a long run before a letter was quadratic.
    $numberAt = [regex]::new(
        '\G(?>0x[0-9a-f]*|0b[01]+|(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(?:u?[ysl]?|n|d)?(?:kb|mb|gb|tb|pb)?(?!\w|\.[a-z_])',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $keywordAt = [regex]::new('\G(?:return|throw|exit)(?=[ \t])', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $unaryAt = [regex]::new('\G-(?:not|bnot|split|join)(?![\w-])', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $varTok = $false        # inside a `$name` argument, so a glued `.`, `[` or `::` makes it an expression
    $exprArg = $false       # an argument read as an expression (`$x.Name`), where `#` starts a comment
    $n = 0
    while ($n -lt $Text.Length) {
        $ch = $Text[$n]
        $next = if ($n + 1 -lt $Text.Length) { $Text[$n + 1] } else { $null }
        if ($null -ne $here) {
            if (($n -eq 0 -or $Text[$n - 1] -ceq "`n") -and $null -ne $next -and "$ch$next" -ceq $here) {
                [void]$sb.Append($here); $here = $null; $inWord = $false; $n += 2; continue
            }
            [void]$sb.Append($(if ($ch -ceq "`n") { $ch } else { ' ' })); $n++; continue
        }
        if ($ch -ceq '`' -and $quote -cne "'" -and $null -ne $next) {
            # An escaped CRLF is one line end, so the LF is not read as a statement end.
            $width = if ($next -ceq "`r" -and $n + 2 -lt $Text.Length -and $Text[$n + 2] -ceq "`n") { 3 } else { 2 }
            $continuation = $Text[$n + $width - 1] -ceq "`n"
            if ($null -ne $quote) {
                # Blanked inside a string, except a newline.
                [void]$sb.Append(' ')
                for ($k = $n + 1; $k -lt $n + $width; $k++) {
                    [void]$sb.Append($(if ($Text[$k] -ceq "`n") { "`n" } else { ' ' }))
                }
            } else {
                [void]$sb.Append($Text, $n, $width)
                if ($continuation) { $inWord = $false; $firstToken = $false }
                else {
                    $inWord = $true
                    if ($stmtStart) { $exprStmt = $false; $stmtStart = $false }
                }
            }
            $n += $width; continue
        }
        if ($null -ne $quote) {
            if ($ch -ceq $quote) { $quote = $null; $inWord = $quoteGlued; [void]$sb.Append($ch) }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }
            else { [void]$sb.Append(' ') }
            $n++; continue
        }
        if ($ch -ceq '@' -and ($next -ceq "'" -or $next -ceq '"')) {
            # Scanned in place: a Substring of the rest at every `@'` made a long command quadratic.
            $k = $n + 2
            while ($k -lt $Text.Length -and ($Text[$k] -ceq ' ' -or $Text[$k] -ceq "`t")) { $k++ }
            if ($k -lt $Text.Length -and $Text[$k] -ceq "`r") { $k++ }
            if ($k -lt $Text.Length -and $Text[$k] -ceq "`n") {
                $here = "$next@"; [void]$sb.Append("@$next"); $n += 2
                if ($stmtStart) { $exprStmt = $true; $firstToken = $false; $stmtStart = $false }
                continue
            }
        }
        if ($stmtStart -and 'rteRTE'.IndexOf($ch) -ge 0 -and $keywordAt.IsMatch($Text, $n)) {
            # `return`, `throw` and `exit` take a pipeline, which starts a statement of its own.
            $kw = $keywordAt.Match($Text, $n).Length
            [void]$sb.Append($Text, $n, $kw); $n += $kw; continue
        }
        if ($ch -ceq '$' -and $next -ceq '{' -and -not $braceRunsOut) {
            # `${#x}` is the variable `#x`: its name is blanked, and it is one word. A backtick
            # escapes a `}` inside the name.
            $close = $n + 2
            while ($close -lt $Text.Length -and $Text[$close] -cne '}') {
                $close += $(if ($Text[$close] -ceq '`') { 2 } else { 1 })
            }
            if ($close -lt $Text.Length) {
                [void]$sb.Append('${')
                [void]$sb.Append([regex]::Replace($Text.Substring($n + 2, $close - $n - 2), '[^\n]', ' '))
                [void]$sb.Append('}')
                if ($stmtStart) { $exprStmt = $true; $firstToken = $true; $stmtStart = $false }
                $hashKey = $false; $inWord = $true; $n = $close + 1; continue
            }
            # A later `${` starts its scan at or past an aligned point of this one, so it runs out too.
            $braceRunsOut = $true
        }
        $end = -1
        if ($ch -ceq '#' -or ($ch -ceq '<' -and $next -ceq '#')) {
            # A merge redirection such as `2>&1` ends in a digit and is still a whole token.
            $tokenStart = -not $inWord -or $exprStmt -or $exprArg -or
                ($n -ge 3 -and $Text.Substring($n - 3, 3) -cmatch '^>&[12]$')
            if ($tokenStart -and $ch -ceq '<') {
                $end = $Text.IndexOf('#>', $n + 2, [StringComparison]::Ordinal)
                $end = if ($end -lt 0) { $Text.Length } else { $end + 2 }
            } elseif ($tokenStart -and $ch -ceq '#') {
                $end = $Text.IndexOf([char]10, $n)
                if ($end -lt 0) { $end = $Text.Length }
            }
        }
        if ($end -ge 0) {
            [void]$sb.Append($ch)
            [void]$sb.Append([regex]::Replace($Text.Substring($n + 1, $end - $n - 1), '[^\n]', ' '))
            $n = $end; continue
        }
        if ([char]::IsWhiteSpace($ch) -or ';|&(){},'.IndexOf($ch) -ge 0) {
            $inWord = $false; $firstToken = $false; $varTok = $false; $exprArg = $false
            if ($ch -ceq "`n" -or $ch -ceq ';') {
                if ($frames.Count -gt 0 -and $frames[$frames.Count - 1][0] -ceq 'h') {
                    # A line end after a value's `=` continues it: `@{ a =` then `Get-Thing *#` on
                    # the next line is a command's argument, not a key.
                    $k = $n - 1
                    while ($ch -ceq "`n" -and $k -ge 0 -and " `t`r".IndexOf($Text[$k]) -ge 0) { $k-- }
                    if (-not ($ch -ceq "`n" -and $k -ge 0 -and '=+-*/%!,'.IndexOf($Text[$k]) -ge 0)) {
                        $exprStmt = $true; $hashKey = $true; $stmtStart = $false
                    }
                } else { $stmtStart = $true }
            } elseif (($ch -ceq '|' -or $ch -ceq '&') -and $next -ceq $ch) {
                # `&&` and `||` start a pipeline, whose first element may be an expression.
                [void]$sb.Append($ch); $n++; $exprStmt = $false; $stmtStart = $true
            } elseif ($ch -ceq '(' -or $ch -ceq '{') {
                # A statement start here is an expression, as `(gci).Count#` and `@{a=1}.b#` are.
                $outer = $stmtStart -or $exprStmt
                if ($ch -ceq '{' -and $atStart -eq $n - 1) {
                    $frames.Add(@('h', $outer)); $exprStmt = $true; $hashKey = $true; $stmtStart = $false
                } else {
                    $frames.Add(@('s', $outer)); $hashKey = $false; $stmtStart = $true
                }
            } elseif ($ch -ceq ')' -or $ch -ceq '}') {
                if ($frames.Count -gt 0) {
                    $exprStmt = $frames[$frames.Count - 1][1]; $frames.RemoveAt($frames.Count - 1)
                }
                $hashKey = $false; $stmtStart = $false
            } elseif ($ch -ceq '|') {
                # A pipeline element may be an expression too: `gci | $x#` holds a comment.
                $exprStmt = $false; $stmtStart = $true
            } elseif ($ch -ceq '&') { $exprStmt = $false; $stmtStart = $false }
        } else {
            $digitLed = ($ch -ge '0' -and $ch -le '9') -or
                ($ch -ceq '.' -and $null -ne $next -and $next -ge '0' -and $next -le '9')
            if ($hashKey) {
                $hashKey = $false
            } elseif ($stmtStart) {
                # A string, `!`, `-not` or a negative number leads an expression as `$` does.
                $exprStmt = $ch -ceq '$' -or $ch -ceq '[' -or $ch -ceq "'" -or $ch -ceq '"' -or $ch -ceq '!' -or
                    ($ch -ceq '@' -and ($next -ceq '{' -or $next -ceq '(')) -or
                    ($digitLed -and $numberAt.IsMatch($Text, $n)) -or
                    ($ch -ceq '-' -and ($unaryAt.IsMatch($Text, $n) -or
                        ($null -ne $next -and (($next -ge '0' -and $next -le '9') -or $next -ceq '.') -and
                         $numberAt.IsMatch($Text, $n + 1))))
                $firstToken = $exprStmt; $stmtStart = $false
            } elseif ($exprStmt -and -not $inWord -and -not $firstToken) {
                if ($digitLed) {
                    # `7z` in `$x = 7z -a` is a command, as a bareword is; `7kb` is a number.
                    if (-not $numberAt.IsMatch($Text, $n)) { $exprStmt = $false }
                } elseif (([char]::IsLetter($ch) -or '._\~^'.IndexOf($ch) -ge 0) -and $Text[$n - 1] -cne '-' -and
                          -not ($ch -ceq '.' -and ')}"@'''.IndexOf($Text[$n - 1]) -ge 0)) {
                    # A bareword here is a command, such as `Get-ChildItem` in `$x = Get-ChildItem`;
                    # a letter after `-` is an operator name such as `-eq`, and a `.` glued to a
                    # close or a string is a member access, as in `$y.Foo(1).Bar` and `'a'.Length`.
                    $exprStmt = $false
                }
            }
            if (-not $exprStmt) {
                # AMONG ARGUMENTS, a member access or an index makes the argument an expression,
                # where `#` starts a comment: `$x.Name#`, `$a[0]#`, `$a::b#`, `(gci).Name#` and
                # `'a'.Length#`, though `$b#` alone is one word.
                if ($exprArg) {
                    # `$x.Name-foo` is a parameter and `$x[0]x` a word, so the expression ends there.
                    if (-not ([char]::IsLetterOrDigit($ch) -or '_.[]:?$"'''.IndexOf($ch) -ge 0) -or
                        ($Text[$n - 1] -ceq ']' -and [char]::IsLetterOrDigit($ch))) { $exprArg = $false }
                } elseif ($varTok) {
                    if ($ch -ceq '.' -or $ch -ceq '[' -or ($ch -ceq ':' -and $next -ceq ':')) {
                        $exprArg = $true; $varTok = $false
                    } elseif (-not ([char]::IsLetterOrDigit($ch) -or '_?:'.IndexOf($ch) -ge 0)) { $varTok = $false }
                } elseif (-not $inWord) {
                    if ($ch -ceq '$') { $varTok = $true }
                    elseif ($ch -ceq '.' -and ')}"@'''.IndexOf($Text[$n - 1]) -ge 0) { $exprArg = $true }
                }
            }
            if ($ch -ceq '@' -and -not $inWord) { $atStart = $n }
            if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; $quoteGlued = $inWord }
            elseif ($exprStmt -and '=+-*/%!'.IndexOf($ch) -ge 0) {
                $inWord = $false
                if ($ch -ceq '=') { $firstToken = $false }
            }
            else { $inWord = $true }
        }
        [void]$sb.Append($ch)
        $n++
    }
    return $sb.ToString()
}

# THE PER-SITE TEXTS (BACKLOG #5607). Bash decides a `$((` or word-start `((` site by matching its
# parens as arithmetic reads them, where quotes and escapes count and a `#` or `<<` is only text: if
# the `)` closing the inner `(` is followed by `)`, the site is arithmetic, and otherwise it is read
# again as a subshell, `$(` or `(` around a `(`. The refined
# view decides each site by backtracking, and past its budget it gives up on the whole command:
# measured, about 45 nested `$((cmd) )` levels. This pass decides the sites in one pass with a
# stack, and names texts for the caller to read on their own, after every other view:
#   - a subshell site gives its subshell's text, which bash reads as a fresh command whatever quotes
#     surround the site;
#   - the shifts in arithmetic sites are blanked, in one copy of the whole command and in each
#     subshell text that holds one. A spaced `<<` is no heredoc opener there, but Hide-HeredocBodies
#     reads `(( a << b ))` as one, and in a command with no quote no view masks it first, so the walk
#     on the lines after it was blanked;
#   - in arithmetic, single quotes are literal and a substitution in them still runs, so the quoted
#     text gives a text of its own, read as if double-quoted.
# Where a `#`, or a line end after a `<<`, falls inside a subshell site before its decision, or the
# site never closes, this pass finds the site's end again by a command's reading, and the sites it
# found inside give no text of their own; the site's own text, read by the views above, stands for
# them. That matches bash for at least a `$((` site holding a whole heredoc, whose body bash reads
# as data. It does not match bash for at least a `$((` site holding a `#`, whose end bash finds by
# matching parens, so the re-read can run past it and add a false deny; nor for a word-start `((`
# site holding a heredoc, whose body's lines bash runs and which stays allowed, as on main.
# Outside arithmetic and outside a `${...}` within double quotes, none of these holds a site in bash:
# single-quoted text, `$'...'` text, and the body of a heredoc whose delimiter is quoted. This pass
# skips all three, and it also skips the body of a heredoc whose delimiter is unquoted. It still does
# not read at least these:
#   - a case pattern's `)`, and a `((` glued to a keyword;
#   - a `$'...'` inside arithmetic. Bash drops its `$` and decodes its escapes before the expansion,
#     so a substitution in it runs, including one spelled with escapes such as `\x24(`;
#   - a `'` in the word of a `${x:-...}`, `${x:+...}` or `${x:=...}` within double quotes, or of the
#     colon-less `-`, `+` and `=` forms. Bash reads that `'` as a literal character, so a site after
#     it runs. Measured on bash 5.3: after `#`, `%`, `/`, `^`, `,` and `?`, bash honours the quote;
#   - a heredoc terminator line that matches only after `.Trim()`, and a quoted delimiter with
#     space around it. In either case the pass and bash can disagree on which lines are body, and a
#     walk can go undenied (found by a Lander probe on 2026-11-23);
#   - a heredoc delimiter it captures only part of, such as `<<END-X`. The pass then reads the body as
#     running past the real terminator, so a site on a later line is skipped;
#   - a substitution in the body of a heredoc whose delimiter is unquoted, which bash runs.
# Past its step budget it returns $null, and the caller then adds nothing. With -From, it reads a
# command from that offset inside an open `(` and returns where that `(` closes.
function Get-SiteTexts([string]$Text, [int]$From = -1) {
    $len = $Text.Length
    $steps = 0
    $budget = 8 * $len + 4096
    $frames = [System.Collections.Generic.List[object]]::new()
    $frames.Add(@{ K = 'top'; U = $false; Site = $null; D = 0 })
    $n = 0
    if ($From -ge 0) { $frames.Add(@{ K = 'par'; U = $false; Site = $null; D = 0 }); $n = $From }
    $sites = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.List[string]]::new()
    $wordStart = $true
    $delimRe = [regex]::new('\G-?[ \t]*(?:''([^''\n]+)''|"([^"\n]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))')
    $readDelim = {
        param([int]$At)
        $d = $delimRe.Match($Text, $At)
        if ($d.Success) {
            $pending.Add((@($d.Groups[1].Value, $d.Groups[2].Value, $d.Groups[3].Value) |
                Where-Object { $_ } | Select-Object -First 1))
        }
    }
    while ($n -lt $len) {
        if (++$steps -gt $budget) { return $null }
        $f = $frames[$frames.Count - 1]
        $k = $f.K
        $ch = $Text[$n]
        $next = if ($n + 1 -lt $len) { $Text[$n + 1] } else { [char]0 }
        $quoted = $k -ceq 'dq'
        if ($quoted) {
            if ($ch -ceq '\') { $n += 2; continue }
            if ($ch -ceq '"') { $frames.RemoveAt($frames.Count - 1); $wordStart = $false; $n++; continue }
        }
        if ($ch -ceq '$' -and $next -ceq '(' -and $n + 2 -lt $len -and $Text[$n + 2] -ceq '(') {
            $s = @{ Brk = $false; S = $n; ILo = $n + 2; IHi = $len; Dec = $null; Unc = $false; NoText = $false
                Sh = [System.Collections.Generic.List[int]]::new(); Q = [System.Collections.Generic.List[object]]::new() }
            $sites.Add($s)
            $frames.Add(@{ K = 'A'; U = $f.U; Site = $s; D = 0 })
            $frames.Add(@{ K = 'B'; U = $true; Site = $s; D = 0 })
            $wordStart = $true; $n += 3; continue
        }
        if ($ch -ceq '$' -and $next -ceq '(') {
            $frames.Add(@{ K = 'sub'; U = $false; Site = $null; D = 0 }); $wordStart = $true; $n += 2; continue
        }
        if ($ch -ceq '$' -and $next -ceq '[') {
            $s = @{ Brk = $true; NoText = $false; Sh = [System.Collections.Generic.List[int]]::new()
                Q = [System.Collections.Generic.List[object]]::new() }
            $sites.Add($s)
            $frames.Add(@{ K = 'brk'; U = $true; Site = $s; D = 0 }); $wordStart = $true; $n += 2; continue
        }
        if ($ch -ceq '$' -and $next -ceq '{') {
            $frames.Add(@{ K = 'brace'; U = $f.U; Site = $null; D = 0 }); $wordStart = $false
            $n += 2; continue
        }
        if ($ch -ceq '`') {
            if ($k -ceq 'bt') { $frames.RemoveAt($frames.Count - 1); $wordStart = $false }
            else { $frames.Add(@{ K = 'bt'; U = $false; Site = $null; D = 0 }); $wordStart = $true }
            $n++; continue
        }
        if ($quoted) { $n++; continue }
        # Unquoted from here. A newline under heredoc openers starts their bodies, read as data.
        if ($ch -ceq "`n" -and $pending.Count -gt 0 -and -not $f.U) {
            $n++
            foreach ($term in $pending) {
                while ($n -lt $len) {
                    $end = $Text.IndexOf([char]10, $n)
                    if ($end -lt 0) { $end = $len }
                    $steps++
                    $hit = $Text.Substring($n, $end - $n).Trim() -ceq $term
                    $n = $end + 1
                    if ($hit) { break }
                }
            }
            $pending.Clear(); $wordStart = $true; continue
        }
        if ($f.U -and ($ch -ceq "`n" -or ($ch -ceq '#' -and $wordStart))) {
            # Inside a site before its decision: a command would read a comment, or a line end after
            # a `<<`, where arithmetic reads text.
            for ($i = $frames.Count - 1; $i -ge 0 -and $frames[$i].U; $i--) {
                $steps++
                $fs = $frames[$i].Site
                if ($frames[$i].K -ceq 'B' -and ($ch -ceq '#' -or $fs.Sh.Count -gt 0 -or $pending.Count -gt 0)) {
                    $fs.Unc = $true
                }
            }
            $wordStart = $ch -ceq "`n"; $n++; continue
        }
        if ($ch -ceq '\') { $wordStart = $false; $n += 2; continue }
        if ($ch -ceq "'") {
            $close = $Text.IndexOf([char]39, $n + 1)
            $end = if ($close -lt 0) { $len } else { $close + 1 }
            if ($f.U -and ($Text.IndexOf('$(', $n, $end - $n, [StringComparison]::Ordinal) -ge 0 -or
                $Text.IndexOf([char]96, $n, $end - $n) -ge 0)) {
                # Kept with the innermost site, and read only if that site is arithmetic.
                for ($i = $frames.Count - 1; $i -ge 0 -and $frames[$i].U; $i--) {
                    $steps++
                    if ($frames[$i].K -ceq 'B' -or $frames[$i].K -ceq 'brk') {
                        $frames[$i].Site.Q.Add(@{ Cost = $end - $n; Lo = $n; Hi = $end; Dq = $true; Whole = $false })
                        break
                    }
                }
            }
            $n = $end; $wordStart = $false; continue
        }
        if ($ch -ceq '$' -and $next -ceq "'") {
            $n += 2
            while ($n -lt $len -and $Text[$n] -cne "'") { $n += $(if ($Text[$n] -ceq '\') { 2 } else { 1 }) }
            $n++; $wordStart = $false; continue
        }
        if ($ch -ceq '"') { $frames.Add(@{ K = 'dq'; U = $f.U; Site = $null; D = 0 }); $wordStart = $false; $n++; continue }
        if ($ch -ceq '#' -and $wordStart -and $k -cne 'brace') {
            $end = $Text.IndexOf([char]10, $n)
            if ($end -lt 0) { $end = $len }
            if ($k -ceq 'bt') {
                $tick = $Text.IndexOf([char]96, $n)
                if ($tick -ge 0 -and $tick -lt $end) { $end = $tick }
            }
            $n = $end; continue
        }
        if ($ch -ceq '<' -and $next -ceq '<' -and -not ($n + 2 -lt $len -and $Text[$n + 2] -ceq '<') -and
            -not ($n -gt 0 -and $Text[$n - 1] -ceq '<')) {
            if ($f.U) {
                # Text to arithmetic, kept with the innermost site that reads it.
                for ($i = $frames.Count - 1; $i -ge 0 -and $frames[$i].U; $i--) {
                    $steps++
                    if ($frames[$i].K -ceq 'B' -or $frames[$i].K -ceq 'brk') { $frames[$i].Site.Sh.Add($n); break }
                }
            } else { & $readDelim ($n + 2) }
            $wordStart = $false; $n += 2; continue
        }
        if ($ch -ceq '(') {
            if ($next -ceq '(' -and $wordStart -and $k -cne 'brace' -and -not $f.U) {
                $s = @{ Brk = $false; S = $n; ILo = $n + 1; IHi = $len; Dec = $null; Unc = $false; NoText = $false
                    Sh = [System.Collections.Generic.List[int]]::new(); Q = [System.Collections.Generic.List[object]]::new() }
                $sites.Add($s)
                $frames.Add(@{ K = 'A'; U = $f.U; Site = $s; D = 0 })
                $frames.Add(@{ K = 'B'; U = $true; Site = $s; D = 0 })
                $n += 2; continue
            }
            $frames.Add(@{ K = 'par'; U = $f.U; Site = $null; D = 0 }); $wordStart = $true; $n++; continue
        }
        if ($ch -ceq ')' -and ($k -ceq 'par' -or $k -ceq 'sub' -or $k -ceq 'A' -or $k -ceq 'B')) {
            $frames.RemoveAt($frames.Count - 1)
            if ($From -ge 0 -and $frames.Count -eq 1) { return $n }
            if ($k -ceq 'B') {
                $s = $f.Site
                if ($next -ceq ')') { $s.Dec = 'arith' }
                else {
                    # A subshell: the rest of it is read as a command. Each `<<` read so far is read
                    # as opening a heredoc whose body starts at the next line end, unless one already
                    # passed inside the site, which then has its end found again below. Bash does
                    # that for a word-start `((` site; for a `$((` site it takes no body from the
                    # lines after the site and runs them, and a walk there can be missed.
                    $s.Dec = 'sub'
                    $frames[$frames.Count - 1].U = $false
                    if (-not $s.Unc) { foreach ($p in $s.Sh) { & $readDelim ($p + 2) } }
                    $s.Sh.Clear(); $s.Q.Clear()
                }
            }
            elseif ($k -ceq 'A') { $f.Site.IHi = $n }
            $wordStart = $false; $n++; continue
        }
        if ($k -ceq 'brk' -and $ch -ceq '[') { $f.D++ }
        elseif ($k -ceq 'brk' -and $ch -ceq ']') {
            if ($f.D -gt 0) { $f.D-- } else { $frames.RemoveAt($frames.Count - 1) }
        }
        elseif ($k -ceq 'brace' -and $ch -ceq '}') { $frames.RemoveAt($frames.Count - 1) }
        $wordStart = [char]::IsWhiteSpace($ch) -or ';&|('.IndexOf($ch) -ge 0
        $n++
    }
    if ($From -ge 0) { return $len }
    # A site read differently by a command: find its end again, and drop the texts of the sites
    # inside it. Each re-read costs up to the whole text, so only the first few are re-read.
    $reread = 0
    foreach ($s in $sites) {
        if ($s.Brk -or $s.NoText -or $s.Dec -ceq 'arith' -or -not ($s.Unc -or $null -eq $s.Dec)) { continue }
        if (++$reread -gt 16) { $s.NoText = $true; continue }
        $end = Get-SiteTexts $Text $s.ILo
        if ($null -eq $end) { $s.NoText = $true; continue }
        $s.IHi = [int]$end
        foreach ($t in $sites) {
            if (-not $t.Brk -and $t.S -gt $s.ILo -and $t.S -lt $s.IHi) { $t.NoText = $true }
            foreach ($q in $t.Q) { if ($q.Lo -gt $s.ILo -and $q.Lo -lt $s.IHi) { $q.Cost = -1 } }
        }
    }
    $shifts = [System.Collections.Generic.List[int]]::new()
    foreach ($s in $sites) { if ($s.Brk -or $s.Dec -ceq 'arith') { $shifts.AddRange($s.Sh) } }
    $shifts.Sort()
    # Each entry names a text without building it, so a deep nesting costs nothing it does not read.
    $texts = [System.Collections.Generic.List[object]]::new()
    if ($shifts.Count -gt 0) { $texts.Add(@{ Cost = $len; Lo = 0; Hi = $len; Dq = $false; Whole = $true }) }
    $local = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $sites) {
        if (($s.Brk -or $s.Dec -ceq 'arith') -and -not $s.NoText) {
            foreach ($q in $s.Q) { if ($q.Cost -ge 0) { $local.Add($q) } }
        }
        if ($s.Brk -or $s.NoText -or $s.Dec -ceq 'arith') { continue }
        $local.Add(@{ Cost = $s.IHi - $s.ILo; Lo = $s.ILo; Hi = $s.IHi; Dq = $false; Whole = $false })
    }
    # Shortest first: the innermost site of a deep nesting is read before the budget can run out.
    $local.Sort([System.Comparison[object]] { param($x, $y) $x.Cost.CompareTo($y.Cost) })
    $texts.AddRange($local)
    return @{ Texts = $texts; Shifts = $shifts }
}

# The text a Get-SiteTexts entry names: its range, with the arithmetic shifts in it blanked, and a
# single-quoted span in arithmetic turned into a double-quoted one.
function Get-SiteText([string]$Text, $Entry, $Shifts) {
    $chars = $Text.ToCharArray($Entry.Lo, $Entry.Hi - $Entry.Lo)
    $i = $Shifts.BinarySearch($Entry.Lo)
    if ($i -lt 0) { $i = -bnot $i }
    for (; $i -lt $Shifts.Count -and $Shifts[$i] + 1 -lt $Entry.Hi; $i++) {
        $chars[$Shifts[$i] - $Entry.Lo] = ' '; $chars[$Shifts[$i] - $Entry.Lo + 1] = ' '
    }
    if ($Entry.Dq) {
        # A `"` outside any substitution would end the double quotes; inside one it nests.
        $depth = 0
        for ($c = 1; $c -lt $chars.Length - 1; $c++) {
            if ($chars[$c] -ceq '$' -and $chars[$c + 1] -ceq '(') { $depth++; $c++ }
            elseif ($depth -gt 0 -and $chars[$c] -ceq '(') { $depth++ }
            elseif ($depth -gt 0 -and $chars[$c] -ceq ')') { $depth-- }
            elseif ($depth -eq 0 -and $chars[$c] -ceq '"') { $chars[$c] = ' ' }
        }
        $chars[0] = '"'
        if ($chars.Length -gt 1 -and $chars[$chars.Length - 1] -ceq "'") { $chars[$chars.Length - 1] = '"' }
    }
    return [string]::new($chars)
}

# A token as bash hands it to the program. Quotes are removed throughout the word, not just at its
# ends (`/''` and `/pro'c'` are /proc), and an unquoted backslash escapes the next character and is
# itself removed (`/\proc` is /proc; unquoted `/proc\registry` is /procregistry, which is nothing).
# Inside double quotes a backslash survives unless it guards one of " $ ` \ .
function Get-Operand([string]$Token) {
    if ($Token.IndexOf('"') -lt 0 -and $Token.IndexOf("'") -lt 0 -and
        $Token.IndexOf('\') -lt 0) { return $Token }
    $sb = [System.Text.StringBuilder]::new()
    $quote = $null
    for ($n = 0; $n -lt $Token.Length; $n++) {
        $ch = $Token[$n]
        if ($quote -ceq "'") {
            if ($ch -ceq "'") { $quote = $null } else { [void]$sb.Append($ch) }
            continue
        }
        if ($ch -ceq '\') {
            $next = if ($n + 1 -lt $Token.Length) { $Token[$n + 1] } else { $null }
            if ($null -eq $quote) {
                if ($null -ne $next) { [void]$sb.Append($next); $n++ }
                continue
            }
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

# Fold a path to what the MSYS resolver reaches, as a pure string decision (no stat on the hot
# path). Measured against Git Bash on 2026-09-20: `.` segments and 3+ slashes collapse; `..` is
# resolved lexically, so `/tmp/..` is the root and `/proc/../tmp` is /tmp; a quoted backslash is a
# separator once a path starts at `/`; EXACTLY two leading slashes are the UNC namespace, so `//`
# keeps its own verdict and `//proc` is a host, not /proc; the mount is case-sensitive.
# It assumes an operand starting with `/`; Get-WalkRootKind enforces that, and is its only caller.
function Get-NormalizedPath([string]$Operand) {
    if (-not $Operand) { return $Operand }
    $p = $Operand.Replace('\', '/')
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

# The roots this guard exists for, stated once for both callers below.
function Test-MsysRootSpelling([string]$Path) {
    return ($Path -ceq '/') -or ($Path -ceq '/proc') -or $Path.StartsWith('/proc/')
}

# 'msys', 'net', or $null for anything bounded. Only an operand starting with `/` can reach the
# MSYS root (`\`, `\proc` and `C:\x` do not), which also returns the common `.` at once.
function Get-WalkRootKind([string]$Operand) {
    if ($Operand.Length -eq 0 -or $Operand[0] -cne '/') { return $null }
    $p = Get-NormalizedPath $Operand
    if ($p -ceq '//') { return 'net' }
    if (Test-MsysRootSpelling $p) { return 'msys' }
    return $null
}

try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $j = $raw | ConvertFrom-Json
    $cmd = [string]$j.tool_input.command
    if (-not $cmd) { exit 0 }

    # Every deny needs a find or grep token, and the blanking passes only overwrite with spaces, so
    # this substring test can skip work but never a deny.
    if ($cmd.IndexOf('find', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
        $cmd.IndexOf('grep', [StringComparison]::OrdinalIgnoreCase) -lt 0) { exit 0 }

    # The blanked view says where a command starts and what program it is; the raw view, at the
    # same offsets, gives its operands. Quotes are masked before heredocs, for the reason above.
    # Read safely: under strict mode a missing tool_name would throw, and the catch would allow.
    $tool = if ($j.PSObject.Properties['tool_name']) { [string]$j.tool_name } else { '' }
    # THE PLAIN TOGGLE IS A FLOOR UNDER THE BASH READING, NOT REPLACED BY IT (BACKLOG #5607). The
    # bash reading was added to deny walks the toggle blanked, but a misreading of its own blanked
    # walks the toggle sees: measured, an arithmetic `$((...))` holding a substitution, `$((cmd) )`,
    # `cat<<` with no space, two heredocs on one line, and a `#` comment holding an apostrophe inside
    # "$(...)". So a bash command is scanned under BOTH views and denied if either denies: the bash
    # reading can only add denies to the toggle's, never remove one. The floor does NOT make the bash
    # reading right. Where the toggle blanks the same walk -- inside one double-quoted span, say --
    # a misreading still allows it, unless the refined view below reads that form; Hide-QuotedSpans
    # names at least the forms it does not.
    # The price is the toggle's own false denies, such as `'It'\''s; find /proc'`, which main had.
    # Most commands mask the same under both, and then one scan is enough.
    $scans = @(Hide-HeredocBodies $cmd (Hide-QuotedSpans $cmd -Plain))
    if ($tool -cne 'PowerShell') {
        $bashScan = Hide-HeredocBodies $cmd (Hide-QuotedSpans $cmd)
        if ($bashScan -cne $scans[0]) { $scans += $bashScan }
    }
    # The PowerShell tool's reading, beside the toggle under the same rule (BACKLOG #5451). Without
    # a backtick, `#`, `@` or `${` it masks exactly as the toggle does, so it is skipped. THE TOGGLE
    # IS JUDGED FIRST, and this reading is built only once every toggle segment allows, so a slow
    # path in it can delay an allow but never the toggle's own deny.
    $psPending = @{ Value = ($tool -ceq 'PowerShell' -and
        ($cmd.IndexOfAny([char[]]('`', '#', '@')) -ge 0 -or $cmd.IndexOf('${', [StringComparison]::Ordinal) -ge 0)) }

    # Split into simple commands. `(`, `)` and the backtick are separators too, or `$(find /proc)`,
    # a backtick substitution and a `( find /proc )` subshell were each allowed.
    $bounds = New-Object 'System.Collections.Generic.List[object[]]'
    # A bound is a range of a view, the raw text its operands are read from at the same offsets, and
    # a tag that keeps a per-site text's ranges apart from the command's own in $checked below.
    function Add-ScanBounds([string]$Scan, [string]$Raw = $cmd, [string]$Tag = '') {
        $cursor = 0
        foreach ($m in [regex]::Matches($Scan, '(\|\||&&|[;|&\n()`])')) {
            $bounds.Add(@($Scan, $cursor, ($m.Index - $cursor), $Raw, $Tag))
            $cursor = $m.Index + $m.Length
        }
        $bounds.Add(@($Scan, $cursor, ($Scan.Length - $cursor), $Raw, $Tag))
    }
    # Called once the loop below has judged every bound it holds; true when it added more.
    function Add-PowerShellBounds {
        if (-not $psPending.Value) { return $false }
        $psPending.Value = $false
        $psScan = Hide-HeredocBodies $cmd (Hide-PowerShellSpans $cmd)
        if ($psScan -ceq $scans[0]) { return $false }
        $before = $bounds.Count
        Add-ScanBounds $psScan
        return $bounds.Count -gt $before
    }
    # THE REFINED VIEW (BACKLOG #5607) IS BUILT LAST, under the same rule: it is built only once every
    # toggle, bash and PowerShell bound has been judged and allowed, and it only appends bounds, so
    # a throw, a slow path or its budget giving up returns the allow those views reached. It is built
    # only for a command holding at least one of `((`, `<<` or `$[`. Its other change, ending a bound
    # at a comment, only removes tokens, so skipping the view elsewhere loses no deny.
    $refinedPending = @{ Value = ($tool -cne 'PowerShell' -and
        ($cmd.IndexOf('((', [StringComparison]::Ordinal) -ge 0 -or $cmd.IndexOf('<<', [StringComparison]::Ordinal) -ge 0 -or
         $cmd.IndexOf('$[', [StringComparison]::Ordinal) -ge 0)) }
    function Add-RefinedBounds {
        if (-not $refinedPending.Value) { return $false }
        $refinedPending.Value = $false
        $refinedMask = Hide-QuotedSpans $cmd -Refined
        if ($null -eq $refinedMask) { return $false }
        $refinedScan = Hide-HeredocBodies $cmd $refinedMask
        if ($scans -ccontains $refinedScan) { return $false }
        $before = $bounds.Count
        Add-ScanBounds $refinedScan
        return $bounds.Count -gt $before
    }
    # THE PER-SITE TEXTS (BACKLOG #5607) COME AFTER EVERY VIEW ABOVE, under the same rule, so they can
    # only add denies to the verdict those views reach: they are read only once every earlier bound
    # has been judged and allowed, their bounds are appended, and a throw or a budget giving up
    # returns that allow. The budgets bound how much text they read, not the time it takes to judge
    # it, and that time counts against the timeout this guard shares with the hooks run after it in
    # the same dispatch. Each text is read under the plain and bash views, and under the refined view
    # where it holds a quote and fits the budget, one text per call, so the loop judges it before the
    # next is read. Built only for a command holding `((` or `$[`.
    $sitePending = @{ Value = ($tool -cne 'PowerShell' -and
        ($cmd.IndexOf('((', [StringComparison]::Ordinal) -ge 0 -or $cmd.IndexOf('$[', [StringComparison]::Ordinal) -ge 0))
        Site = $null; Next = 0; Spent = 0 }
    function Add-SiteBounds {
        if (-not $sitePending.Value) { return $false }
        if ($null -eq $sitePending.Site) {
            $sitePending.Site = Get-SiteTexts $cmd
            if ($null -eq $sitePending.Site) { $sitePending.Value = $false; return $false }
        }
        $texts = $sitePending.Site.Texts
        $cap = 16 * $cmd.Length + 65536
        while ($sitePending.Next -lt $texts.Count) {
            $entry = $texts[$sitePending.Next]
            $sitePending.Next++
            if ($sitePending.Spent + 2 * $entry.Cost -gt $cap) { break }
            $sitePending.Spent += 2 * $entry.Cost
            $t = Get-SiteText $cmd $entry $sitePending.Site.Shifts
            # The refined view changes nothing in a text with no quote, and its own budget is about 8
            # characters a character, so it is read only where it fits.
            $refine = ($t.IndexOf('"') -ge 0 -or $t.IndexOf("'") -ge 0) -and
                ($t.IndexOf('((', [StringComparison]::Ordinal) -ge 0 -or $t.IndexOf('<<', [StringComparison]::Ordinal) -ge 0 -or
                 $t.IndexOf('$[', [StringComparison]::Ordinal) -ge 0) -and $sitePending.Spent + 8 * $entry.Cost -le $cap
            if ($refine) { $sitePending.Spent += 8 * $entry.Cost }
            $views = [System.Collections.Generic.List[string]]::new()
            $views.Add((Hide-HeredocBodies $t (Hide-QuotedSpans $t -Plain)))
            $v = Hide-HeredocBodies $t (Hide-QuotedSpans $t)
            if (-not $views.Contains($v)) { $views.Add($v) }
            if ($refine) {
                $r = Hide-QuotedSpans $t -Refined
                if ($null -ne $r) {
                    $v = Hide-HeredocBodies $t $r
                    if (-not $views.Contains($v)) { $views.Add($v) }
                }
            }
            # The whole-command copy is read against the command itself, untagged, so each of its
            # bounds the earlier views already judged is skipped; it differs only at blanked shifts.
            if ($entry.Whole) { foreach ($v in $views) { Add-ScanBounds $v $cmd '' } }
            else { foreach ($v in $views) { Add-ScanBounds $v $t "site $($sitePending.Next)|" } }
            return $true
        }
        $sitePending.Value = $false
        return $false
    }
    foreach ($scan in $scans) { Add-ScanBounds $scan }

    # Options whose value is a SEPARATE word, so the value is skipped rather than read as a program,
    # pattern or path. Only separate-word options belong here: listing an attached-value one such
    # as --color would eat the pattern and turn a deny into a miss. A missing name can only allow.
    # grep's short options are the `efmABCDd` cluster below, so this list is long-form only.
    $XARGS_VALUE_OPTS = '^(-I|-n|-L|-P|-s|-d|-E|-a|--max-args|--max-lines|--max-procs|--delimiter|--arg-file)$'
    $GREP_VALUE_OPTS = '^(--regexp|--file|--max-count|--after-context|--before-context|--context|--devices|--directories|--include|--exclude|--exclude-dir|--binary-files|--label)$'
    $GREP_PATTERN_OPTS = '^(--regexp|--file)$'

    # The causes, stated once. The network root is a different mechanism and must not borrow the
    # registry one.
    $UNSTOPPABLE = "It cannot be interrupted reliably either, because killing a bash wrapper " +
                   "leaves its grandchildren running. "
    $WHY = "/proc/registry, /proc/registry32 and /proc/registry64 are the Windows registry " +
           "mounted as filesystem trees, so reading them opens a kernel handle per registry key " +
           "and HKEY_CLASSES_ROOT alone is effectively unbounded: measured 2026-09-20, a walk of " +
           "one mount passed 30,000 machine-wide handles in 15 seconds and was still climbing. " +
           $UNSTOPPABLE
    $WHY_NET = "In Git Bash exactly two leading slashes are the UNC namespace rather than the " +
               "MSYS root: measured 2026-09-20, 'ls //' listed the network root, so the walk " +
               "enumerates network and WSL shares with no bound. " + $UNSTOPPABLE

    # A segment both views mask alike is checked once.
    $checked = [System.Collections.Generic.HashSet[string]]::new()
    for ($bi = 0; $bi -lt $bounds.Count -or (Add-PowerShellBounds) -or (Add-RefinedBounds) -or (Add-SiteBounds); $bi++) {
        $b = $bounds[$bi]
        if ($b[2] -le 0) { continue }
        $seg = $b[0].Substring($b[1], $b[2])
        if (-not $checked.Add("$($b[4])$($b[1]):$seg")) { continue }
        $s = $seg.Trim()
        $rawSeg = $b[3].Substring($b[1], $b[2]).Trim()
        if (-not $s) { continue }

        # Program position is decided on the blanked view; a first token carrying a quote is the
        # quoted case and is skipped rather than unquoted and trusted.
        $head = @($s -split '\s+' | Where-Object { $_ })
        if ($head.Count -eq 0) { continue }
        if ($head[0].Contains('"') -or $head[0].Contains("'")) { continue }

        $tokens = @($rawSeg -split '\s+' | Where-Object { $_ })
        if ($tokens.Count -eq 0) { continue }

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
            # The prune escape, read as TOKENS after cutting a `#` comment: a substring test
            # exempted `-path /procurement -prune` and a comment that quoted this guard's own
            # advice. The pattern is read LITERALLY, never folded, because find matches `-path`
            # against the path it generates, so `-path /./proc` prunes nothing and must not exempt.
            $exprTokens = @()
            foreach ($tk in $tokens) {
                if ($tk.StartsWith('#')) { break }
                $exprTokens += $tk
            }
            $prunePattern = $null
            for ($n = 0; $n -lt $exprTokens.Count - 1; $n++) {
                if (($exprTokens[$n] -ieq '-path' -or $exprTokens[$n] -ieq '-wholename') -and
                    (Test-MsysRootSpelling (Get-Operand $exprTokens[$n + 1])) -and
                    ($exprTokens -ccontains '-prune')) {
                    $prunePattern = Get-Operand $exprTokens[$n + 1]
                    break
                }
            }

            # find's leading options: -H -L -P, -D <word>, -O<level>, and `--`, which GNU find
            # accepts (`find -- /proc` was allowed without this). No clusters, no `=` values.
            $k = $i + 1
            $endOfFindOptions = $false
            while ($k -lt $tokens.Count) {
                $t = Get-Operand $tokens[$k]
                if ($t -ceq '--') { $endOfFindOptions = $true; $k++; break }
                if ($t -cmatch '^-[HLP]$') { $k++; continue }
                if ($t -ceq '-D') { $k += 2; continue }
                if ($t -cmatch '^-O') { $k++; continue }
                break
            }
            # Path operands run until the expression starts: an option, `(`, `!` or `,`.
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
                    # The prune bounds a walk only when its pattern starts with the LITERAL root
                    # given: `find /. -path /proc -prune` generates `/./proc` and walked anyway.
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

                # A LONG option: split at the first `=`, because the name decides what it is and an
                # attached value decides whether the next word is its value (`--regexp=foo` was
                # allowed). Names compare case-sensitively, as getopt_long does.
                if (-not $endOfOptions -and $t.StartsWith('--')) {
                    $eq = $t.IndexOf('=')
                    $name = if ($eq -ge 0) { $t.Substring(0, $eq) } else { $t }
                    $attached = if ($eq -ge 0) { $t.Substring($eq + 1) } else { $null }
                    if ($name -cmatch '^--(recursive|dereference-recursive)$') { $recursive = $true }
                    if ($name -ceq '--directories' -and $attached -ieq 'recurse') {
                        $recursive = $true
                    }
                    if ($name -cmatch $GREP_PATTERN_OPTS) { $patternTaken = $true }
                    $k++
                    if ($null -eq $attached -and $name -cmatch $GREP_VALUE_OPTS -and
                        $k -lt $tokens.Count) {
                        if ($name -ceq '--directories' -and
                            (Get-Operand $tokens[$k]) -ieq 'recurse') { $recursive = $true }
                        $k++
                    }
                    continue
                }

                # A SHORT cluster, read character by character: `-rm5` hides an r behind an attached
                # value, and in `-er` the r IS the value of -e, so that grep is not recursive.
                if (-not $endOfOptions -and $t.StartsWith('-') -and $t.Length -gt 1) {
                    $chars = $t.Substring(1)
                    $valueShort = $null
                    for ($c = 0; $c -lt $chars.Length; $c++) {
                        $ch = [string]$chars[$c]
                        if ($ch -cmatch '^[rR]$') { $recursive = $true; continue }
                        if ($ch -cnotmatch '^[efmABCDd]$') { continue }
                        if ($ch -cmatch '^[ef]$') { $patternTaken = $true }
                        $rest = $chars.Substring($c + 1)
                        if ($rest) {
                            if ($ch -ceq 'd' -and $rest -ieq 'recurse') { $recursive = $true }
                        } else {
                            $valueShort = $ch
                        }
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
    exit 0
}
