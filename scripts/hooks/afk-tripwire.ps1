# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PreToolUse tripwire: record a Class C act in a shell command, and tell the session (ADR 0211;
    docs/AUTONOMY-PLAN.md section 4.4).

.DESCRIPTION
    IT DOES NOT BLOCK, AND SO IT DOES NOT MEET PLAN SECTION 4.4, which says a tripwire "stops the
    act". Blocking was left out of this slice by its brief. Most of these acts are not denied by
    anything else either: the deny rules in .claude/settings.json match a few command prefixes
    only (read them there), so forms such as `--force-with-lease`, `--delete`, `--no-verify` and
    `cd x && git reset --hard` run. The context this hook
    returns reaches the session with the call, not before it: the act has already run when the
    session reads "stop". What this hook gives is the RECORD and the reminder.

    When a Bash or PowerShell command carries one of the acts below, it appends a `tripwire` record
    through scripts/coord/decision.ps1 -NoPost (spooled locally, posted to the vault by the next
    flush) and returns additionalContext telling the session the act is Class C. A record means the
    act was ATTEMPTED: this hook runs before the permission rules, so a command they then refuse is
    recorded too. A command an earlier guard in the dispatcher denied never reaches this one.

    WHAT IT DETECTS, at least:
      * a hook bypass: `--no-verify` on any git subcommand, `-n` on `git commit`,
        `git -c core.hooksPath=...` or `git --config-env core.hooksPath=...`, and pre-commit's `SKIP=`
        in front of a command;
      * a `-c` or `--config-env` override of `include.path` or `includeIf.*`, which can load a
        hooksPath from a file; of `alias.*`, which can run a git command under a new name, or any shell
        command with `!`; of `remote.<name>.mirror`; and of `remote.<name>.push` with a `+` or `:`
        refspec under `-c`, or with any value under `--config-env`, whose value names a variable;
      * a force push: `--force`, `-f`, `--force-with-lease`, `--mirror`, or a `+` refspec;
      * a ref deletion by push: `--delete`, `-d`, `--prune`, or a `:<branch>` refspec;
      * `git reset --hard`;
      * a long option git accepts abbreviated (`--forc`, `--no-veri`), or one written in quotes;
      * `-Force` on scripts/worktree/remove.ps1 or scripts/coord/claim.ps1;
      * `-AllowOrphanedAllocations` on any command;
      * a write to the kill switch: `gh variable set|delete MEFOR_AFK_KILL`, or a non-GET
        `gh api` call on its path. The owner sets it; nothing else stops a seat from doing so.

    HOW IT READS A COMMAND. It splits the text into segments at shell separators, honouring quotes,
    so a flag inside a quoted message (`git commit -m "never --no-verify"`) is a mention, not a use.
    Heredoc bodies and PowerShell here-strings are dropped first for the same reason. The body of
    `bash -c`, `pwsh -Command` and `cmd /c` is read as a command of its own, and `pwsh -File <x>`
    reads <x> as the program.

    It reads the text twice: with no escapes, as it always did, and with the escapes of the shell
    that runs it (bash's backslash for the Bash tool and `bash -c`, PowerShell's backtick and doubled
    quote for the PowerShell tool and `pwsh -Command`; both when the tool is unknown). It records an
    act either reading sees. A reading that ignored `\"` closed the span there, so the span's real
    closing quote opened another, and a later act read as quoted text.

    WHAT IT DOES NOT SEE (SAIDS section 9: a rule is not a control until something enforces it).
    A script file that runs one of these acts, an alias or variable that spells the command, git
    plumbing that deletes or moves a ref (`update-ref -d`, `branch -D`), and every non-shell tool.
    Nor config that does an act without a flag, at least: a `-c` key that runs a command
    (`core.pager`, `core.editor`, `sequence.editor`, `core.sshCommand`, `core.fsmonitor`,
    `diff.external`, `credential.helper`, `gpg.program`) or moves the work tree (`core.worktree`);
    config set through the environment (`GIT_CONFIG_COUNT` with `GIT_CONFIG_KEY_<n>` and
    `GIT_CONFIG_VALUE_<n>`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, or a
    moved `HOME` or `XDG_CONFIG_HOME`); and a persistent `git config core.hooksPath <dir>` write.
    The other section 4.4 tripwires -- a diff touching Class C paths, the same permission denial
    twice, `main` red for two hours, two seats on one item -- are rules only in this slice; ADR 0211
    says which the digest reports.

    A KNOWN DUPLICATE. This is one more hand-written reading of shell text beside the ones in
    block-blanket-git-stage.ps1 and block-unbounded-fs-scan.ps1, whose header says the copies should
    become one shared helper; each copy has its own blind spots until then.

    FAST, AND OFFLINE AS FAR AS decision.ps1 CAN TELL: no network call and no git call of its own.
    On a hit, decision.ps1 -NoPost runs a few local `git rev-parse` calls, never probes a shared
    root, and skips a seat registry on a share it can detect: at least a UNC path, a drive letter
    Windows reports as a network drive, and a path whose kind cannot be told. It does NOT detect a
    share mounted under `/`, or a junction or symlink to a share; a registry there is read, and a
    dead server can then hang the hook. A command naming none of the words a hit needs is not
    tokenised at all. It runs under
    scripts/hooks/shell-guard-dispatch.ps1, after block-blanket-git-stage.ps1, whose length cap
    bounds what reaches it, and the dispatcher passes its context-only answer through. Fail-open on
    any error.

    WIRING IS NOT ASSERTED HERE ON PURPOSE. Which guards run is a property of settings.json.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Split-TripwireSegments([string]$Text, [string]$Dialect = 'literal') {
    <#
      Segments of tokens; a token is @{ T = text; Q = any part of it was quoted or escaped }.

      $Dialect is how an escape reads. 'literal' honours none, so a quoted span closes at the next
      same quote. 'bash' honours a backslash: outside quotes, before `"`, `\`, `$` or a backtick
      inside double quotes, and anywhere inside $'...'. 'pwsh' honours a backtick, outside quotes and
      inside double quotes, and a doubled quote inside either kind. Find-Tripwires reads the text
      literally and in its shell's dialect, and keeps every hit: a reading that took an escaped quote
      for a close read the command after it as quoted text.
    #>
    $segs = [System.Collections.Generic.List[object]]::new()
    $toks = [System.Collections.Generic.List[object]]::new()
    $cur = [System.Text.StringBuilder]::new()
    $quoted = $false
    $inTok = $false
    # `(` and `{` open a new command (a subshell, a block), unless they follow `$`: `$(...)` and
    # `${X}` are arguments of the command around them. `)` and `}` only end a token, so the flags
    # after `git push origin $(git branch --show-current) --force` stay in the push's segment.
    $separators = ';|&({' + "`n"
    # Dot-invoked, so they run in this scope and reset its variables.
    $endToken = {
        if ($inTok) { $toks.Add([pscustomobject]@{ T = $cur.ToString(); Q = $quoted }) }
        $null = $cur.Clear(); $quoted = $false; $inTok = $false
    }
    $endSegment = {
        . $endToken
        if ($toks.Count) { $segs.Add($toks.ToArray()); $toks.Clear() }
    }
    $i = 0
    $n = $Text.Length
    while ($i -lt $n) {
        $ch = $Text[$i]
        if ($ch -eq "'" -or $ch -eq '"') {
            # bash's $'...' takes backslash escapes, as a plain '...' does not.
            $ansi = $Dialect -eq 'bash' -and $ch -eq "'" -and $i -gt 0 -and $Text[$i - 1] -eq '$'
            $j = $i + 1
            if ($Dialect -eq 'literal') {
                $j = $Text.IndexOf($ch, $j)
                if ($j -lt 0) { $j = $n }
                $null = $cur.Append($Text, $i + 1, $j - $i - 1)
            }
            while ($j -lt $n -and $Dialect -ne 'literal') {
                $c = $Text[$j]
                $escape = $false
                if ($j + 1 -lt $n) {
                    $next = $Text[$j + 1]
                    if ($Dialect -eq 'pwsh') { $escape = ($c -eq $ch -and $next -eq $ch) -or ($ch -eq '"' -and $c -eq '`') }
                    elseif ($Dialect -eq 'bash') { $escape = $c -eq '\' -and ($ansi -or ($ch -eq '"' -and '"\$`'.Contains($next))) }
                }
                if ($escape) { $null = $cur.Append($Text[$j + 1]); $j += 2; continue }
                if ($c -eq $ch) { break }
                $null = $cur.Append($c)
                $j++
            }
            $quoted = $true; $inTok = $true
            $i = $j + 1
            continue
        }
        # A line continuation, bash's or PowerShell's, joins two lines into one command; with CRLF
        # line ends it is three characters.
        # Each shell's own character only: PowerShell runs the line after `D:\x\` as a new command.
        $joins = if ($Dialect -eq 'bash') { $ch -eq '\' } elseif ($Dialect -eq 'pwsh') { $ch -eq '`' } else { $ch -eq '\' -or $ch -eq '`' }
        if ($joins -and $i + 1 -lt $n -and ($Text[$i + 1] -eq "`n" -or $Text[$i + 1] -eq "`r")) {
            $i += $(if ($Text[$i + 1] -eq "`r" -and $i + 2 -lt $n -and $Text[$i + 2] -eq "`n") { 3 } else { 2 })
            continue
        }
        # An escaped character outside quotes is the character itself, quoted: bash hands git
        # `--force` for `\--force`, and a `\"` opens no span.
        if ($i + 1 -lt $n -and (($Dialect -eq 'bash' -and $ch -eq '\') -or ($Dialect -eq 'pwsh' -and $ch -eq '`'))) {
            $null = $cur.Append($Text[$i + 1])
            $quoted = $true; $inTok = $true
            $i += 2
            continue
        }
        # A comment runs to the end of its line, and a flag named in it is a mention.
        if ($ch -eq '#' -and -not $inTok) {
            $eol = $Text.IndexOf("`n", $i)
            $i = if ($eol -lt 0) { $n } else { $eol }
            continue
        }
        if ($ch -eq ' ' -or $ch -eq "`t" -or $ch -eq "`r" -or $ch -eq ')' -or $ch -eq '}') { . $endToken; $i++; continue }
        if (($ch -eq '(' -or $ch -eq '{') -and $i -gt 0 -and $Text[$i - 1] -eq '$') { . $endToken; $i++; continue }
        if ($separators.Contains($ch)) { . $endSegment; $i++; continue }
        $null = $cur.Append($ch); $inTok = $true
        $i++
    }
    . $endSegment
    return , $segs
}

function Get-ProgramLeaf([string]$T) {
    $leaf = ($T -split '[\\/]')[-1].ToLowerInvariant()
    if ($leaf.EndsWith('.exe')) { $leaf = $leaf.Substring(0, $leaf.Length - 4) }
    return $leaf
}

function Test-ShortCluster([string]$T, [char]$Letter, [string]$ValueLetters) {
    # True when a short-flag cluster such as -fu sets $Letter before any flag that takes a value.
    if ($T -cnotmatch '^-[A-Za-z]+$') { return $false }
    foreach ($c in $T.Substring(1).ToCharArray()) {
        if ($c -ceq $Letter) { return $true }
        if ($ValueLetters.Contains([string]$c)) { return $false }
    }
    return $false
}

function Test-LongOption([string]$T, [string]$Full, [int]$Min) {
    # git accepts an unambiguous abbreviation of a long option; $Min is the shortest one that is
    # not also the start of another option of the same subcommand.
    $name = $T.Split('=')[0]
    return ($name -ceq $Full -or ($name.Length -ge $Min -and $Full.StartsWith($name, [StringComparison]::Ordinal)))
}

function Test-KillSwitchWrite($Argv) {
    # `gh variable set|delete MEFOR_AFK_KILL`, or `gh api` on its path with a method other than GET:
    # -X/--method, or a field or input, which makes gh send a POST.
    $words = @($Argv | ForEach-Object { $_.T })
    if (-not @($words | Where-Object { $_ -match 'MEFOR_AFK_KILL' }).Count) { return $false }
    if ($words.Count -ge 2 -and $words[0] -eq 'variable' -and $words[1] -in @('set', 'delete', 'remove')) { return $true }
    if (-not $words.Count -or $words[0] -ne 'api') { return $false }
    for ($p = 1; $p -lt $words.Count; $p++) {
        $w = $words[$p]
        if ($w -cin @('-X', '--method') -and $p + 1 -lt $words.Count) { if ($words[$p + 1] -ne 'GET') { return $true } }
        elseif ($w -cmatch '^(-X|--method=)(.+)$') { if ($Matches[2] -ne 'GET') { return $true } }
        elseif ($w -cin @('-f', '-F', '--field', '--raw-field', '--input')) { return $true }
    }
    return $false
}

function Get-ConfigOverrideHit([string]$Option, [string]$Pair) {
    # A config override that points the hooks elsewhere skips them as surely as --no-verify; an
    # include can load a file that does the same; an alias can run a git command under a new name,
    # or any shell command with `!`; a remote's mirror setting, valueless meaning true, turns a plain
    # push into a forced one, and so can a `+` push refspec, while a `:<dst>` one deletes (a bare `:`
    # is the matching refspec, recorded all the same). -match folds case, as git does for a section and
    # variable name; it also folds a subsection, which git does not, and so records more, never less.
    if ($Pair -match '^core\.hooksPath=') { return "git $Option core.hooksPath (hook bypass)" }
    if ($Pair -match '^include\.path=') { return "git $Option include.path (config include, can bypass hooks)" }
    if ($Pair -match '^includeIf\.') { return "git $Option includeIf (config include, can bypass hooks)" }
    if ($Pair -match '^alias\.') { return "git $Option alias (command alias override)" }
    # Under --config-env the text after `=` names an environment variable, so the refspec is unseen.
    $push = if ($Option -ceq '--config-env') { 'push=' } else { 'push=[+:]' }
    if ($Pair -match "^remote\..+\.(mirror(=|$)|$push)") { return "git $Option remote mirror or push refspec (can force a push)" }
    return $null
}

# Global options taking their value as the next argument. The first list is the one origin/main read
# with before BACKLOG #5448; it skips the value of --exec-path, which takes none, and misses
# --config-env, --attr-source and --shallow-file, which do (measured on git 2.55.0). Both parses run
# and every hit either one sees is recorded, because a tripwire may only tighten: under the first, a
# Class C word in the value position (`git --attr-source reset log --hard`) is the subcommand.
# Resolve-GitSubcommand in block-blanket-git-stage.ps1 kept a copy of the first list. BACKLOG #5450
# changes that copy on its own branch, whose wider list keeps --exec-path, so the lists here and
# there differ, at least until one is changed to match the other; nothing tests them together.
$script:GitValuedOptionLists = @(
    @('-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix'),
    @('-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env', '--attr-source', '--shallow-file')
)

function Find-GitTripwires($Argv, $Hits) {
    $starts = [System.Collections.Generic.List[int]]::new()
    foreach ($valued in $script:GitValuedOptionLists) {
        $k = 0
        # Global options before the subcommand.
        while ($k -lt $Argv.Count -and $Argv[$k].T.StartsWith('-')) {
            $t = $Argv[$k].T
            $next = if ($k + 1 -lt $Argv.Count) { $Argv[$k + 1].T } else { '' }
            # --config-env is -c with the value read from an environment variable, in both spellings
            # git accepts (BACKLOG #5448): `--config-env=<key>=<var>` and `--config-env <key>=<var>`.
            # The option NAME is matched case-sensitively, as git does; only the key folds.
            $hit = if ($t -cin @('-c', '--config-env')) { Get-ConfigOverrideHit $t $next }
            elseif ($t -cmatch '^--config-env=(.*)$') { Get-ConfigOverrideHit '--config-env' $Matches[1] }
            if ($hit) { $Hits.Add($hit) }
            if ($t -cin $valued) { $k++ }
            $k++
        }
        if ($k -lt $Argv.Count -and -not $starts.Contains($k)) { $starts.Add($k) }
    }
    foreach ($k in $starts) { Find-GitSubcommandTripwires $Argv $k $Hits }
}

function Find-GitSubcommandTripwires($Argv, [int]$k, $Hits) {
    $sub = $Argv[$k].T
    $rest = @(if ($k + 1 -lt $Argv.Count) { $Argv[($k + 1)..($Argv.Count - 1)] })
    # A flag is an unquoted token, or a quoted one that is a single flag-shaped word: the shell
    # hands git `--force` either way. A quoted word right after an option that takes a value is
    # that value (`-m "--no-verify"`), not a flag.
    $valued = @('-m', '--message', '-F', '--file', '-C', '-c', '-t', '--template', '-o', '--push-option')
    $flags = @(for ($p = 0; $p -lt $rest.Count; $p++) {
            $t = $rest[$p]
            $after = $p -gt 0 -and $rest[$p - 1].T -cin $valued
            if (-not $t.Q -or ($t.T -cmatch '^--?[A-Za-z][\w-]*(=\S*)?$' -and -not $after)) { $t.T }
        })
    # The record names acts, never command text, and the first parse can put an option's value (a path,
    # a key=VAR) where the subcommand goes; only a subcommand-shaped word is named.
    $subName = if ($sub -cmatch '^[a-z][a-z0-9-]*$') { $sub } else { '<subcommand>' }
    if (@($flags | Where-Object { Test-LongOption $_ '--no-verify' 9 }).Count) { $Hits.Add("git $subName --no-verify") }
    switch -CaseSensitive ($sub) {
        'commit' {
            # -u takes its mode stuck on (`-uno`), so it ends a cluster like the value letters.
            if (@($flags | Where-Object { Test-ShortCluster $_ ([char]'n') 'mFCctu' }).Count) { $Hits.Add('git commit -n (no-verify)') }
        }
        'reset' {
            if (@($flags | Where-Object { Test-LongOption $_ '--hard' 4 }).Count) { $Hits.Add('git reset --hard') }
        }
        'push' {
            foreach ($f in $flags) {
                if ((Test-LongOption $f '--force' 6) -or $f.StartsWith('--force-w') -or (Test-LongOption $f '--mirror' 4) -or
                    (Test-ShortCluster $f ([char]'f') 'o')) { $Hits.Add('git push --force') }
                if ((Test-LongOption $f '--delete' 4) -or (Test-LongOption $f '--prune' 5) -or
                    (Test-ShortCluster $f ([char]'d') 'o')) { $Hits.Add('git push ref deletion') }
            }
            $positional = [System.Collections.Generic.List[string]]::new()
            for ($p = 0; $p -lt $rest.Count; $p++) {
                $t = $rest[$p].T
                if ($t.StartsWith('-')) {
                    if ($t -cin @('-o', '--push-option', '--repo', '--receive-pack', '--exec')) { $p++ }
                    continue
                }
                $positional.Add($t)
            }
            # The first positional is the remote; every later one is a refspec.
            foreach ($spec in @($positional | Select-Object -Skip 1)) {
                if ($spec.StartsWith('+')) { $Hits.Add('git push --force') }
                if ($spec.StartsWith(':') -and $spec.Length -gt 1) { $Hits.Add('git push ref deletion') }
            }
        }
    }
}

function Find-Tripwires([string]$Command, [int]$Depth, $Hits, [string]$Shell = '') {
    if ($Depth -gt 2 -or -not $Command) { return }
    # Heredoc bodies and here-strings are file content or messages, not commands. The delimiter may
    # be quoted or backslash-escaped, and may hold dots and dashes (`<<"END-OF-MSG"`, `<<\EOF`).
    # Only the body lines and the terminator go: the opener line stays, because a command after the
    # heredoc on that line (`cat <<EOF | git commit --no-verify -F -`) is a command. The body is
    # whole lines matched lazily, so an empty body ends at its own terminator.
    $text = [regex]::Replace($Command, '(<<-?[ \t]*\\?([''"]?)([\w.-]+)\2[^\n]*\n)(?:[^\n]*\n)*?[ \t]*\3[ \t]*\r?(?=\n|$)', '$1')
    $text = [regex]::Replace($text, '(?s)@''\r?\n.*?\r?\n''@', "''")
    $text = [regex]::Replace($text, '(?s)@"\r?\n.*?\r?\n"@', "''")
    $skip = @('sudo', 'command', 'exec', 'time', 'nohup', 'env', 'do', 'then', 'else', 'if', 'while', 'until', '!', '.', 'elif')
    # The literal reading, as before, and the reading of the shell that runs the text: $Shell is the
    # tool's (Bash or PowerShell) or the one a `-c` names; unknown reads both. An act either reading
    # sees is recorded. Reading the other shell's escapes too would shift every later span in text
    # that merely holds its escape character (a path ending `\` under PowerShell) and record acts
    # that are only mentioned. A reading whose escape character the text lacks would only repeat the
    # literal one, so it is skipped. Either character counts for either shell, because the literal
    # reading joins a line ending in either, and each shell joins only on its own. A doubled quote
    # alone changes content, never where spans end.
    $dialects = @('literal')
    if ($text.Contains('\') -or $text.Contains('`')) {
        if ($Shell -in @('bash', '')) { $dialects += 'bash' }
        if ($Shell -in @('pwsh', '')) { $dialects += 'pwsh' }
    }
    $scannedBodies = [System.Collections.Generic.HashSet[string]]::new()
    $segments = [System.Collections.Generic.List[object]]::new()
    foreach ($dialect in $dialects) {
        foreach ($s in (Split-TripwireSegments $text $dialect)) { $segments.Add($s) }
    }
    foreach ($seg in $segments) {
        if (@($seg | Where-Object { -not $_.Q -and $_.T -match '^-AllowOrphanedAllocations(:\$?true)?$' }).Count) {
            $Hits.Add('-AllowOrphanedAllocations')
        }
        $k = 0
        # Skip an environment assignment (X=1), a PowerShell assignment ($r = ... , $null = ...)
        # and the keywords that can stand in front of a command.
        while ($k -lt $seg.Count -and -not $seg[$k].Q -and (
                $seg[$k].T -match '^[A-Za-z_][A-Za-z0-9_]*=' -or $seg[$k].T -match '^\$[\w:]+$' -or
                $seg[$k].T -in @('=', '+=') -or $skip -contains $seg[$k].T)) { $k++ }
        if ($k -ge $seg.Count) { continue }
        # pre-commit's own skip list, set in front of the command it governs.
        if (@($seg[0..$k] | Where-Object { -not $_.Q -and $_.T -match '^SKIP=.' }).Count) { $Hits.Add('SKIP= (pre-commit hook skip)') }
        $prog = Get-ProgramLeaf $seg[$k].T
        $argv = @(if ($k + 1 -lt $seg.Count) { $seg[($k + 1)..($seg.Count - 1)] })
        if ($prog -in @('bash', 'sh', 'zsh', 'dash', 'pwsh', 'powershell', 'cmd')) {
            for ($a = 0; $a -lt $argv.Count; $a++) {
                $t = $argv[$a].T
                $isCmd = if ($prog -eq 'cmd') { $t -in @('/c', '/k') }
                elseif ($prog -in @('pwsh', 'powershell')) { $t -match '^-(c|co|com|comm|comma|comman|command)$' }
                else { $t -cmatch '^-[a-z]*c$' }
                if ($isCmd) {
                    $body = (@($argv | Select-Object -Skip ($a + 1) | ForEach-Object { $_.T }) -join ' ')
                    $inner = if ($prog -in @('pwsh', 'powershell')) { 'pwsh' } elseif ($prog -eq 'cmd') { 'cmd' } else { 'bash' }
                    # Two readings often give one body; read it once.
                    if ($scannedBodies.Add("$inner|$body")) { Find-Tripwires $body ($Depth + 1) $Hits $inner }
                    break
                }
                if ($prog -in @('pwsh', 'powershell') -and $t -match '^-(f|fi|fil|file)$' -and $a + 1 -lt $argv.Count) {
                    $prog = Get-ProgramLeaf $argv[$a + 1].T
                    $argv = @($argv | Select-Object -Skip ($a + 2))
                    break
                }
            }
        }
        if ($prog -eq 'git') {
            Find-GitTripwires $argv $Hits
        } elseif ($prog -eq 'gh') {
            if (Test-KillSwitchWrite $argv) { $Hits.Add('a write to the MEFOR_AFK_KILL kill switch') }
        } elseif ($prog -in @('remove.ps1', 'claim.ps1')) {
            if (@($argv | Where-Object { -not $_.Q -and $_.T -match '^-Force(:\$?true)?$' }).Count) { $Hits.Add("$prog -Force") }
        }
    }
}

try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $j = $raw | ConvertFrom-Json
    $input_ = $j.PSObject.Properties['tool_input']
    if (-not $input_) { exit 0 }
    $cmdProp = $input_.Value.PSObject.Properties['command']
    if (-not $cmdProp) { exit 0 }
    # Every hit needs one of these words, so most shell calls stop here without being tokenised.
    if ([string]$cmdProp.Value -notmatch '\bgit\b|remove\.ps1|claim\.ps1|AllowOrphanedAllocations|MEFOR_AFK_KILL|SKIP=') { exit 0 }
    $hits = [System.Collections.Generic.List[string]]::new()
    $toolProp = $j.PSObject.Properties['tool_name']
    $toolName = if ($toolProp) { [string]$toolProp.Value } else { '' }
    $shell = if ($toolName -eq 'Bash') { 'bash' } elseif ($toolName -eq 'PowerShell') { 'pwsh' } else { '' }
    Find-Tripwires ([string]$cmdProp.Value) 0 $hits $shell
    if (-not $hits.Count) { exit 0 }
    $what = (@($hits | Select-Object -Unique) -join ', ')

    $sidProp = $j.PSObject.Properties['session_id']
    $sid = if ($sidProp) { [string]$sidProp.Value } else { '' }
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
        $logged = 'Not recorded here: a cloud session keeps no decision log, so your Manager logs it.'
    } else {
        try {
            # The record names the acts, never the command text, which can carry a secret.
            $decision = Join-Path (Split-Path -Parent $PSScriptRoot) 'coord/decision.ps1'
            $tool = if ($toolProp) { $toolName } else { 'shell' }
            $out = @(& $decision -Log -Kind tripwire -Class C -Session $sid -NoPost -Note "$tool command carried: $what" 2>$null)
            $id = @($out | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^LOGGED (\S+)' } | ForEach-Object { $Matches[1] })
            $logged = if ($id) { "Recorded as tripwire $($id[0]) in the decision log." } else { 'Not recorded: decision.ps1 wrote no record.' }
        } catch {
            $logged = "Not recorded: $($_.Exception.Message)"
        }
    }
    # CLAUDE.md section 5 gives a session two of these acts as its own, so name them only on a hit
    # that could be one of them; any other hit keeps the plain Class C advice.
    $narrow = ''
    if ($hits -contains 'git push --force' -or $hits -contains 'remove.ps1 -Force') {
        $narrow = 'Two narrow cases are yours, only while the kill switch reads off and every condition holds: ' +
            'a force-push of your own unshared branch (CLAUDE.md section 5), and a cache-only remove.ps1 ' +
            '-Force on your own worktree (docs\WORKTREES.md, "Remove one"). This record stands either way. '
    }
    $context = "AFK TRIPWIRE (ADR 0211; docs/AUTONOMY-PLAN.md section 4.4): this command carries $what. " +
        'Under the AFK-autonomy plan that makes it a Class C act. This hook does not block it, but do not ' +
        'run it on your own judgment: stop, and bring it to the owner in the Class C bundle, unless the ' +
        "owner asked for exactly this in your own chat. $narrow$logged"
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{ hookEventName = 'PreToolUse'; additionalContext = $context }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 4))
    exit 0
} catch {
    # Fail open, always: a broken tripwire must not wedge every shell call in the fleet.
    exit 0
}
