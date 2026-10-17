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
function Hide-QuotedSpans([string]$Text) {
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
    $scan = Hide-HeredocBodies $cmd (Hide-QuotedSpans $cmd)

    # Split into simple commands. `(`, `)` and the backtick are separators too, or `$(find /proc)`,
    # a backtick substitution and a `( find /proc )` subshell were each allowed.
    $bounds = New-Object 'System.Collections.Generic.List[int[]]'
    $cursor = 0
    foreach ($m in [regex]::Matches($scan, '(\|\||&&|[;|&\n()`])')) {
        $bounds.Add(@($cursor, ($m.Index - $cursor)))
        $cursor = $m.Index + $m.Length
    }
    $bounds.Add(@($cursor, ($scan.Length - $cursor)))

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

    foreach ($b in $bounds) {
        if ($b[1] -le 0) { continue }
        $s = $scan.Substring($b[0], $b[1]).Trim()
        $rawSeg = $cmd.Substring($b[0], $b[1]).Trim()
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
