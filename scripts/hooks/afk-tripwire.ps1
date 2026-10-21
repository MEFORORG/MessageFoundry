# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PreToolUse tripwire: record a Class C act in a shell command, and tell the session (ADR 0211;
    docs/AUTONOMY-PLAN.md section 4.4).

.DESCRIPTION
    IT DOES NOT BLOCK. Permission rules in .claude/settings.json and the other guards already deny
    most of these acts; this hook's job is the record and the reminder. When a Bash or PowerShell
    command carries one of the acts below, it appends a `tripwire` record through
    scripts/coord/decision.ps1 -NoPost (spooled locally, posted to the vault by the next flush) and
    returns additionalContext telling the session that the act is Class C: stop, and bring it to the
    owner in the Class C bundle. A command an earlier guard denied never reaches this one, so it
    leaves no record; it did not run.

    WHAT IT DETECTS, at least:
      * `--no-verify` on any git subcommand, and `-n` on `git commit`;
      * a force push: `--force`, `-f`, `--force-with-lease`, `--mirror`, or a `+` refspec;
      * a ref deletion by push: `--delete`, `-d`, `--prune`, or a `:<branch>` refspec;
      * `git reset --hard`;
      * `-Force` on scripts/worktree/remove.ps1 or scripts/coord/claim.ps1;
      * `-AllowOrphanedAllocations` on any command.

    HOW IT READS A COMMAND. It splits the text into segments at shell separators, honouring quotes,
    so a flag inside a quoted message (`git commit -m "never --no-verify"`) is a mention, not a use.
    Heredoc bodies and PowerShell here-strings are dropped first for the same reason. The body of
    `bash -c`, `pwsh -Command` and `cmd /c` is read as a command of its own, and `pwsh -File <x>`
    reads <x> as the program.

    WHAT IT DOES NOT SEE (SAIDS section 9: a rule is not a control until something enforces it).
    A script file that runs one of these acts, an alias or variable that spells the command, git
    plumbing that deletes or moves a ref (`update-ref -d`, `branch -D`), and every non-shell tool.
    The other section 4.4 tripwires -- a diff touching Class C paths, the same permission denial
    twice, `main` red for two hours, two seats on one item -- are rules only in this slice; ADR 0211
    says which the digest reports.

    A KNOWN DUPLICATE. This is one more hand-written reading of shell text beside the ones in
    block-blanket-git-stage.ps1 and block-unbounded-fs-scan.ps1, whose header says the copies should
    become one shared helper; each copy has its own blind spots until then.

    FAST AND OFFLINE: no network, no git call of its own (decision.ps1 runs one `git rev-parse` on a
    hit), and a command naming none of the words a hit needs is not tokenised at all. It runs under scripts/hooks/shell-guard-dispatch.ps1, which passes a context-only answer
    through. Fail-open on any error.

    WIRING IS NOT ASSERTED HERE ON PURPOSE. Which guards run is a property of settings.json.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Split-TripwireSegments([string]$Text) {
    <# Segments of tokens; a token is @{ T = text; Q = any part of it was quoted }. #>
    $segs = [System.Collections.Generic.List[object]]::new()
    $toks = [System.Collections.Generic.List[object]]::new()
    $cur = [System.Text.StringBuilder]::new()
    $quoted = $false
    $inTok = $false
    $separators = ';|&(){}' + "`n"
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
            $close = $Text.IndexOf($ch, $i + 1)
            if ($close -lt 0) { $close = $n }
            $null = $cur.Append($Text, $i + 1, [Math]::Max(0, $close - $i - 1))
            $quoted = $true; $inTok = $true
            $i = $close + 1
            continue
        }
        # A line continuation, bash's or PowerShell's, joins two lines into one command.
        if (($ch -eq '\' -or $ch -eq '`') -and $i + 1 -lt $n -and ($Text[$i + 1] -eq "`n" -or $Text[$i + 1] -eq "`r")) { $i += 2; continue }
        if ($ch -eq ' ' -or $ch -eq "`t" -or $ch -eq "`r") { . $endToken; $i++; continue }
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

function Find-GitTripwires($Argv, $Hits) {
    $k = 0
    # Global options before the subcommand; -C, -c and the bare long forms take a value.
    while ($k -lt $Argv.Count -and $Argv[$k].T.StartsWith('-')) {
        # The list Resolve-GitSubcommand in block-blanket-git-stage.ps1 uses; keep the two equal.
        if ($Argv[$k].T -cin @('-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix')) { $k++ }
        $k++
    }
    if ($k -ge $Argv.Count) { return }
    $sub = $Argv[$k].T
    $rest = @(if ($k + 1 -lt $Argv.Count) { $Argv[($k + 1)..($Argv.Count - 1)] })
    $flags = @($rest | Where-Object { -not $_.Q } | ForEach-Object { $_.T })
    if ($flags -ccontains '--no-verify') { $Hits.Add("git $sub --no-verify") }
    switch -CaseSensitive ($sub) {
        'commit' {
            if (@($flags | Where-Object { Test-ShortCluster $_ ([char]'n') 'mFCct' }).Count) { $Hits.Add('git commit -n (no-verify)') }
        }
        'reset' {
            if ($flags -ccontains '--hard') { $Hits.Add('git reset --hard') }
        }
        'push' {
            foreach ($f in $flags) {
                if ($f -ceq '--force' -or $f.StartsWith('--force-with-lease') -or $f -ceq '--mirror' -or (Test-ShortCluster $f ([char]'f') 'o')) { $Hits.Add('git push --force') }
                if ($f -ceq '--delete' -or $f -ceq '--prune' -or (Test-ShortCluster $f ([char]'d') 'o')) { $Hits.Add('git push ref deletion') }
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

function Find-Tripwires([string]$Command, [int]$Depth, $Hits) {
    if ($Depth -gt 2 -or -not $Command) { return }
    # Heredoc bodies and here-strings are file content or messages, not commands. The delimiter may
    # be quoted or backslash-escaped, and may hold dots and dashes (`<<"END-OF-MSG"`, `<<\EOF`).
    $text = [regex]::Replace($Command, '(?s)<<-?[ \t]*\\?([''"]?)([\w.-]+)\1[^\n]*\n.*?\n[ \t]*\2[ \t]*(?=\r?\n|$)', '<<HEREDOC')
    $text = [regex]::Replace($text, '(?s)@''\r?\n.*?\r?\n''@', "''")
    $text = [regex]::Replace($text, '(?s)@"\r?\n.*?\r?\n"@', "''")
    $skip = @('sudo', 'command', 'exec', 'time', 'nohup', 'env', 'do', 'then', 'else', 'if', 'while', 'until', '!', '.', 'elif')
    foreach ($seg in (Split-TripwireSegments $text)) {
        if (@($seg | Where-Object { -not $_.Q -and $_.T -match '^-AllowOrphanedAllocations(:\$?true)?$' }).Count) {
            $Hits.Add('-AllowOrphanedAllocations')
        }
        $k = 0
        while ($k -lt $seg.Count -and -not $seg[$k].Q -and ($seg[$k].T -match '^[A-Za-z_][A-Za-z0-9_]*=' -or $skip -contains $seg[$k].T)) { $k++ }
        if ($k -ge $seg.Count) { continue }
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
                    Find-Tripwires $body ($Depth + 1) $Hits
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
    if ([string]$cmdProp.Value -notmatch 'git|remove\.ps1|claim\.ps1|AllowOrphanedAllocations') { exit 0 }
    $hits = [System.Collections.Generic.List[string]]::new()
    Find-Tripwires ([string]$cmdProp.Value) 0 $hits
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
            $toolProp = $j.PSObject.Properties['tool_name']
            $tool = if ($toolProp) { [string]$toolProp.Value } else { 'shell' }
            $out = @(& $decision -Log -Kind tripwire -Class C -Session $sid -NoPost -Note "$tool command carried: $what" 2>$null)
            $id = @($out | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^LOGGED (\S+)' } | ForEach-Object { $Matches[1] })
            $logged = if ($id) { "Recorded as tripwire $($id[0]) in the decision log." } else { 'Not recorded: decision.ps1 wrote no record.' }
        } catch {
            $logged = "Not recorded: $($_.Exception.Message)"
        }
    }
    $context = "AFK TRIPWIRE (ADR 0211; docs/AUTONOMY-PLAN.md section 4.4): this command carries $what. " +
        'Under the AFK-autonomy plan that makes it a Class C act. This hook does not block it, but do not ' +
        'run it on your own judgment: stop, and bring it to the owner in the Class C bundle, unless the ' +
        "owner asked for exactly this in your own chat. $logged"
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{ hookEventName = 'PreToolUse'; additionalContext = $context }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 4))
    exit 0
} catch {
    # Fail open, always: a broken tripwire must not wedge every shell call in the fleet.
    exit 0
}
