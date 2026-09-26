# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Stop hook: after substantive work, ask the seat to write ONE fleet wiki note, or to say it has none.

.DESCRIPTION
    WHY IT EXISTS. The fleet wiki (korus spec 002) has run since 2026-09-24. In its first two days,
    with about a dozen live sessions, seats wrote one note between them. The arrival step says "write
    a lesson after", and nothing prompted it at the moment a lesson happens. Owner decision
    2026-09-26: a Stop hook prompts for it.

    WHEN IT FIRES. Only in an attended session (see ATTENDED SESSIONS ONLY below). Then all three
    must hold, counted over the window since the last prompt or the last wiki write, whichever is
    later:
      1. substantive work: at least $MinToolUses tool uses, or at least one `git commit` / `git push`;
      2. no call to the wiki's write.ps1 in the window (a write empties the window);
      3. at least $CooldownMinutes minutes since this session was last prompted.
    It never blocks while stop_hook_active is true. That is the loop guard: the turn the prompt
    forces ends in a Stop that carries stop_hook_active, and that Stop must be let through.

    HOW IT MAKES THE MODEL ACT. It prints the Stop-hook block form, {"decision":"block","reason":...}.
    Claude Code then continues the turn with the reason as the instruction. Field names confirmed
    against the Claude Code hook schema: the common input carries session_id, transcript_path and cwd,
    and the Stop input adds stop_hook_active.

    INCREMENTAL. The transcript can run to many megabytes, so each call reads only the bytes past a
    per-session offset, and never more than the newest $MaxReadBytes. Anything older than that is
    history from before the hook saw it, and is skipped rather than counted.

    STATE AND LOG live under <coord>/wiki-prompt/, where <coord> is <git common dir>/mefor-coord. The
    wiki scripts own <coord>/wiki/, so nothing here writes under it. Each prompt that FIRES appends
    one JSON line to log-<yyyy-MM>.jsonl, so prompts can be compared with writes and with the wiki's
    own query log.

    KORUS CHECKOUT. The prompt prints query.ps1 and write.ps1 commands from a korus checkout. It
    takes the first of these whose scripts/wiki/write.ps1 exists:
      1. $env:MEFOR_KORUS_CHECKOUT, made absolute (the prompt says when it names no checkout);
      2. <primary parent>/korus-wiki-main, which the wiki cycle task (korus scripts/wiki/cycle.ps1)
         keeps detached at origin/main;
      3. <primary parent>/korus, a working tree that goes stale whenever nobody pulls it.
    Measured 2026-09-26: that working tree sat 9 commits behind origin/main, and its query.ps1 had no
    -Seat, so the printed query command would have failed. So the hook text-searches the chosen
    query.ps1 for a Seat parameter and leaves -Seat off the QUERY command when it finds none;
    write.ps1 has always taken -Seat. The prompt names the checkout it used, so a stale one shows.
    With none found it prints the literal <korus checkout>. No git calls: this runs on every Stop.

    OPT OUT with $env:MEFOR_WIKI_PROMPT = 'off', or create <coord>/wiki-prompt/OFF. The file reaches
    sessions that are already running; the variable does not.

    FAIL OPEN. Any error, a missing transcript, unreadable state or bad stdin: exit 0 with no stdout.
    A memory prompt must never block work or wedge a session. Unreadable state is also rewritten from
    the transcript's end, so one bad file cannot silence a session for good.

    ATTENDED SESSIONS ONLY. A block makes the wiki exchange the session's last message. A headless
    `claude -p` run, a spawned Builder or a scheduled job reports through that last message, so the
    hook must never block one. Test-AttendedSession decides, and it rests on this reading of the
    Claude Code 2.1.281 binary (grep -a, 2026-09-26):
      - Claude Code sets CLAUDE_CODE_SESSION_ATTENDED to "1" or "0" in every command hook's
        environment. It is "0" for a bg or daemon session and for a teammate agent. It is "1" for an
        interactive session. A print-mode session gets "1" only when it is not a child session and
        its entrypoint is a host surface such as claude-desktop or claude-vscode. The hook's own
        Claude Code process computes that value and writes it over any copy it inherited; the
        inherited copy feeds a separate spawnedByAttendedSession flag the computation does not read.
        So a `claude -p` Builder spawned from a Desktop session reads "0".
      - A host marks its own scheduled runs with CLAUDE_CODE_HOST_SCHEDULED_RUN=1, and the attended
        test above ignores it. So a scheduled run is refused here on its own, when a hook can see it.
        Any value but an explicit no counts as scheduled, the quiet side.
    A skipped session writes no state and no log line, by design. So the log cannot show a gate that
    wrongly stays quiet; if prompts stop in sessions a person is at, check this reading first.
      - When the attended variable is absent (an older Claude Code), CLAUDE_CODE_ENTRYPOINT decides,
        and only "cli" counts. Claude Code rewrites an inherited "cli" to "sdk-cli" in print mode,
        but keeps any other inherited value, so a print-mode child of a Desktop session still reads
        "claude-desktop". Absent both, the hook stays quiet.
    A subagent is not affected either way: it ends on SubagentStop, which this hook is not wired to.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Thresholds. Named so a tuning change is a one-line diff that reads as one.
$MinToolUses = 25
$CooldownMinutes = 60
$MaxReadBytes = 8MB
$StateRetentionDays = 14

# A git verb that ends work worth recording. Global flags such as -C <path> may sit between. The
# first character after the dashes must be a word character, so a flag matches ONE way; with
# `--?[\w-]+` a run of flags backtracked exponentially. The timeout is a second guard.
#
# `git` must start a command (line start, or after ; & | or an opening paren), so a search for the
# words, as in grep -rn "git push" docs, is not a push. Each value alternative is exclusive of the
# others, so no option can be matched two ways.
$RegexTimeout = [TimeSpan]::FromSeconds(1)
$CommandStart = '(?:^|[;&|(\n])\s*'
$OptValue = '(?:"[^"]*"|''[^'']*''|[^\s"''-]\S*)'
$CommitRegex = [regex]::new(
    $CommandStart + 'git(?:\s+-[Cc]\s+' + $OptValue +
    '|\s+--(?:git-dir|work-tree|namespace)\s+' + $OptValue +
    '|\s+-{1,2}\w[\w-]*(?:=\S+)?)*\s+(?:commit|push)(?![\w-])',
    'IgnoreCase', $RegexTimeout)
# An actual call to the wiki's only write path: write.ps1 run as a script (after -File, after the
# call operator, or starting a command) with -Type or -FromJson. Reading, grepping or showing the
# file is not a write, and -CheckOnly writes nothing.
$WriteRegex = [regex]::new(
    '(?:-File\s+|&\s*|' + $CommandStart + ')["'']?[^\s"'']*write\.ps1["'']?\s(?!.*-CheckOnly\b).*-(?:Type|FromJson)\b',
    'IgnoreCase, Singleline', $RegexTimeout)

function Test-Truthy([string]$Value) {
    # Claude Code writes the attended flag as 1 or 0. The wider set is its general flag parser's,
    # accepted in case a host writes a word.
    return @('1', 'true', 'yes', 'on') -contains $Value.Trim().ToLowerInvariant()
}

function Test-AttendedSession {
    # True only when a person is at this session to answer. The header says which reading this
    # rests on. Every doubtful case is false: a missed prompt costs one note, a wrong one costs a
    # headless run its report.
    $scheduled = ([string]$env:CLAUDE_CODE_HOST_SCHEDULED_RUN).Trim().ToLowerInvariant()
    if ($scheduled -and @('0', 'false', 'no', 'off') -notcontains $scheduled) { return $false }
    if ($null -ne $env:CLAUDE_CODE_SESSION_ATTENDED) { return (Test-Truthy $env:CLAUDE_CODE_SESSION_ATTENDED) }
    if (@('bg', 'daemon', 'daemon-worker') -contains [string]$env:CLAUDE_CODE_SESSION_KIND) { return $false }
    return ([string]$env:CLAUDE_CODE_ENTRYPOINT -eq 'cli')
}

function Test-Match([regex]$Regex, [string]$Text) {
    # A pathological command must not stall the hook. A timeout counts as no match.
    try { return $Regex.IsMatch($Text) } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return $false }
}

function Read-NewTranscript([string]$Path, [long]$Offset, [hashtable]$State) {
    # Returns the new offset. Counts land in $State.tools and $State.commits.
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        # A transcript that shrank was replaced. Start it again, and its counts with it.
        if ($fs.Length -lt $Offset) { $Offset = 0; $State.tools = 0; $State.commits = 0 }
        # Never more than the newest $MaxReadBytes. A session first seen long after it started, or a
        # backlog left by earlier calls, is old history; catching up on it chunk by chunk would fire
        # prompts for work done before the hook saw it. The partial first line fails to parse.
        if ($fs.Length - $Offset -gt $MaxReadBytes) { $Offset = $fs.Length - $MaxReadBytes }
        $want = [int]($fs.Length - $Offset)
        if ($want -le 0) { return $Offset }
        $buf = [byte[]]::new($want)
        $null = $fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $fs.ReadExactly($buf, 0, $want)
    }
    finally { $fs.Dispose() }

    # Only whole lines. A partial last line is still being written; it is read next time.
    $end = [Array]::LastIndexOf($buf, [byte]10)
    if ($end -lt 0) {
        # One line longer than the cap. Step past it, or every later call stalls on it.
        if ($want -ge $MaxReadBytes) { return $Offset + $want }
        return $Offset
    }
    $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $end + 1)
    foreach ($line in $text.Split("`n")) {
        # Cheap screen first. A tool_result line carries "tool_use_id", which this does not match.
        if (-not $line.Contains('"tool_use"')) { continue }
        try { $entry = $line | ConvertFrom-Json } catch { continue }
        foreach ($item in @($entry.message.content)) {
            if ($item.type -ne 'tool_use') { continue }
            # Only a shell tool's command counts. A Read of write.ps1 is not a write.
            $cmd = [string]$item.input.command
            if ($cmd -and (Test-Match $WriteRegex $cmd)) {
                # A write empties the window: the seat has recorded, so count afresh from here.
                $State.tools = 0
                $State.commits = 0
                continue
            }
            $State.tools = [int]$State.tools + 1
            if ($cmd -and (Test-Match $CommitRegex $cmd)) { $State.commits = [int]$State.commits + 1 }
        }
    }
    return $Offset + $end + 1
}

function Get-Seat([string]$Cwd) {
    # The marker seat.ps1 -Declare writes, in the same order role-card-inject.ps1 reads it: the
    # Codex state path when set, else .claude/, else $env:KORUS_SEAT.
    $raw = ''
    try {
        $top = & git -C $Cwd rev-parse --path-format=absolute --show-toplevel 2>$null
        if ($LASTEXITCODE -eq 0 -and $top) {
            $rel = if ($env:KORUS_AGENT -eq 'codex' -and $env:KORUS_STATE_REL) { "$env:KORUS_STATE_REL/seat.local.txt" } else { '.claude/seat.local.txt' }
            $marker = Join-Path $top.Trim() $rel
            if (Test-Path -LiteralPath $marker) { $raw = [string](Get-Content -LiteralPath $marker -Raw) }
        }
    }
    catch { }
    if (-not $raw.Trim()) { $raw = [string]$env:KORUS_SEAT }
    $raw = $raw.Trim().ToLowerInvariant()
    # The seat goes into a command line and a log. Anything but a plain label is dropped.
    if ($raw -match '^[a-z][a-z0-9-]{0,39}$') { return $raw }
    return ''
}

function Resolve-Korus([string]$Coord) {
    # The header's KORUS CHECKOUT section gives the order and the reason for it. Returns the path
    # with forward slashes and the source it came from, or $null when none has write.ps1.
    # <coord> is <primary>/.git/mefor-coord, so the checkouts sit beside <primary>.
    $primaryParent = Split-Path (Split-Path (Split-Path $Coord -Parent) -Parent) -Parent
    $candidates = @()
    $pinned = ([string]$env:MEFOR_KORUS_CHECKOUT).Trim().Trim('"', "'")
    # Absolute, so the printed command works from whatever directory the seat runs it in.
    if ($pinned) {
        try { $candidates += , @([System.IO.Path]::GetFullPath($pinned), 'MEFOR_KORUS_CHECKOUT') } catch { }
    }
    if ($primaryParent) {
        $candidates += , @((Join-Path $primaryParent 'korus-wiki-main'), 'korus-wiki-main')
        $candidates += , @((Join-Path $primaryParent 'korus'), 'korus')
    }
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $c[0] 'scripts/wiki/write.ps1') -PathType Leaf) {
            return @{ path = $c[0].Replace('\', '/').TrimEnd('/'); source = $c[1] }
        }
    }
    return $null
}

function Test-QueryTakesSeat([string]$Korus) {
    # A text search is enough: a typed $Seat declaration, such as `[string] $Seat`, inside the
    # script's param( ... ) block, which closes on a `)` at column 0. A stale checkout's query.ps1
    # predates -Seat and refuses it, so the printed command would fail. A missing file is false.
    try {
        $text = [string](Get-Content -LiteralPath (Join-Path $Korus 'scripts/wiki/query.ps1') -Raw)
        $block = [regex]::Match($text, '(?ims)^param\s*\((.*?)^\)')
        if (-not $block.Success) { return $false }
        return [regex]::IsMatch($block.Groups[1].Value, '(?im)^\s*\[[^\r\n]*\]\s*\$Seat\b')
    }
    catch { return $false }
}

function Get-Reason([string]$Coord, [string]$Seat) {
    $resolved = Resolve-Korus $Coord
    $korus = '<korus checkout>'
    # Unknown seat: leave -Seat off, and write.ps1 resolves it or says how to declare one.
    $seatArg = if ($Seat) { " -Seat $Seat" } else { '' }
    # With no checkout found, assume a current korus, whose query.ps1 takes -Seat.
    $querySeatArg = $seatArg
    if ($resolved) {
        $korus = $resolved.path
        $korusLine = "Korus checkout used: $korus (from $($resolved.source)). If it is stale, pull it or set MEFOR_KORUS_CHECKOUT."
        if (-not (Test-QueryTakesSeat $korus)) {
            $querySeatArg = ''
            $korusLine += ' Its query.ps1 is missing or has no Seat parameter, so it is probably stale.'
        }
    }
    else {
        $korusLine = 'Korus checkout used: none found. Set MEFOR_KORUS_CHECKOUT, or keep korus-wiki-main or korus beside the primary checkout.'
    }
    if ($env:MEFOR_KORUS_CHECKOUT -and (-not $resolved -or $resolved.source -ne 'MEFOR_KORUS_CHECKOUT')) {
        $korusLine += ' MEFOR_KORUS_CHECKOUT is set but names no checkout with scripts/wiki/write.ps1, so it was ignored.'
    }
    $coordArg = $Coord.Replace('\', '/')
    $lines = @(
        '[fleet wiki] Write prompt. A lesson nobody writes down is lost when this session ends.'
        'Record AT MOST ONE event, and only a lesson, gotcha, decision or correction that will still be true next month.'
        'Never live state such as open PRs or who is running, nor what a playbook already says. No PHI, no secrets, no customer or site names.'
        'Evidence must be a commit SHA, a PR with its repo, ref:path such as origin/main:docs/X.md, or an owner ruling with its date.'
        $korusLine
        'Query first, so you reuse an existing key or write a correction:'
        "  pwsh -NoProfile -File `"$korus/scripts/wiki/query.ps1`" -StateRoot `"$coordArg`" -Text `"<subject>`"$querySeatArg"
        'Then write:'
        "  pwsh -NoProfile -File `"$korus/scripts/wiki/write.ps1`" -StateRoot `"$coordArg`" -Type <lesson|gotcha|decision|correction> -Key <area/thing/aspect> -Summary `"<one line>`" -Evidence `"<...>`"$seatArg"
        'If nothing qualifies, reply exactly: wiki: nothing to record'
        'That reply is a normal outcome. The schema is korus roles/WIKI.md at origin/main.'
    )
    # The prose is ASCII. A path is kept exact, since a '?' in it would name a directory that does
    # not exist; stdout stays ASCII because the JSON escapes it.
    return ($lines -join "`n")
}

try {
    if ($env:MEFOR_WIKI_PROMPT -eq 'off') { exit 0 }

    # Claude Code sends UTF-8, and git prints UTF-8. The console default is the OEM code page, which
    # garbles any non-ASCII path in the payload or in git's output.
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

    $raw = ''
    if ([Console]::IsInputRedirected) { $raw = [Console]::In.ReadToEnd() }
    # After stdin is drained, so the writer never meets a closed pipe, and before any state or log
    # is touched: a session nobody attends is never prompted. Its saved offset, if any, is left as
    # it was. Should the same session id later run attended (a resume on another surface), the first
    # attended Stop counts from that offset, so it also counts this session's unattended work, capped
    # at $MaxReadBytes. That is still this session's work, so a prompt for it is fair.
    if (-not (Test-AttendedSession)) { exit 0 }
    if (-not $raw.Trim()) { exit 0 }
    $hook = $raw | ConvertFrom-Json

    # The loop guard, before anything else can go wrong.
    if ($hook.stop_hook_active -eq $true) { exit 0 }

    $sessionId = [string]$hook.session_id
    $transcript = [string]$hook.transcript_path
    $cwd = [string]$hook.cwd
    # The id names a state file. Refuse anything that could climb out of the directory.
    if ($sessionId -notmatch '^[A-Za-z0-9_-]{1,100}$') { exit 0 }
    if (-not $transcript -or -not (Test-Path -LiteralPath $transcript -PathType Leaf)) { exit 0 }
    if (-not $cwd -or -not (Test-Path -LiteralPath $cwd -PathType Container)) { exit 0 }

    $common = & git -C $cwd rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $common) { exit 0 }
    $coord = Join-Path $common.Trim() 'mefor-coord'
    $promptDir = Join-Path $coord 'wiki-prompt'
    if (Test-Path -LiteralPath (Join-Path $promptDir 'OFF')) { exit 0 }

    $stateDir = Join-Path $promptDir 'state'
    $statePath = Join-Path $stateDir "$sessionId.json"
    # The last prompt is kept as Unix seconds, never as an ISO string: ConvertFrom-Json turns an ISO
    # string into a DateTime, and the round trip back through [string] loses its UTC kind.
    $now = [DateTimeOffset]::UtcNow
    $state = @{ offset = [long]0; tools = 0; commits = 0; lastPromptUnix = [long]0; transcript = $transcript }
    $resync = $false
    if (Test-Path -LiteralPath $statePath) {
        $saved = $null
        try { $saved = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable } catch { }
        $valid = $false
        if ($saved -is [hashtable]) {
            try {
                # Cast every field here, so a wrong type fails into the resync below rather than
                # later, past the point where the state would be rewritten.
                $state.offset = [long]$saved.offset
                $state.tools = [int]$saved.tools
                $state.commits = [int]$saved.commits
                $state.lastPromptUnix = [long]$saved.lastPromptUnix
                $state.transcript = [string]$saved.transcript
                $valid = ($state.offset -ge 0) -and ($state.tools -ge 0) -and ($state.commits -ge 0)
            }
            catch { }
        }
        if ($valid) {
            # A different transcript under the same id starts from its own beginning.
            if ($state.transcript -ne $transcript) {
                $state.offset = [long]0; $state.tools = 0; $state.commits = 0; $state.transcript = $transcript
            }
        }
        else {
            # Unreadable state. Stay silent this time, but rewrite it from the transcript's end with
            # a fresh cooldown, so one bad file cannot silence the session for good.
            $resync = $true
            $state = @{
                offset = (Get-Item -LiteralPath $transcript).Length; tools = 0; commits = 0
                lastPromptUnix = $now.ToUnixTimeSeconds(); transcript = $transcript
            }
        }
    }
    else {
        # First sight of this session: sweep state that no session has touched for a while, so the
        # directory does not grow by one file per session forever. Cheap, and at most once a session.
        try {
            $cutoff = $now.UtcDateTime.AddDays(-$StateRetentionDays)
            Get-ChildItem -LiteralPath $stateDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTimeUtc -lt $cutoff } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
        catch { }
    }

    if (-not $resync) {
        $state.offset = Read-NewTranscript -Path $transcript -Offset ([long]$state.offset) -State $state
    }

    $substantive = ([int]$state.tools -ge $MinToolUses) -or ([int]$state.commits -gt 0)
    $cooled = ($now.ToUnixTimeSeconds() - [long]$state.lastPromptUnix) -ge ($CooldownMinutes * 60)
    $fire = $substantive -and $cooled -and -not $resync
    if ($fire) {
        # Everything the prompt needs is built BEFORE the state records it. A failure here then
        # costs neither the cooldown nor a false line in the log.
        $seat = Get-Seat $cwd
        $out = [ordered]@{ decision = 'block'; reason = (Get-Reason -Coord $coord -Seat $seat) } |
            ConvertTo-Json -Compress -EscapeHandling EscapeNonAscii
        $logLine = [ordered]@{
            utc        = $now.ToString('o')
            session_id = $sessionId
            seat       = $seat
            trigger    = $(if ([int]$state.commits -gt 0) { 'commit' } else { 'tools' })
            tools      = [int]$state.tools
            commits    = [int]$state.commits
        } | ConvertTo-Json -Compress
        $state.tools = 0
        $state.commits = 0
        $state.lastPromptUnix = $now.ToUnixTimeSeconds()
    }

    # State is saved BEFORE the prompt is emitted. A prompt whose cooldown was not recorded would
    # fire again at the very next Stop.
    if (-not (Test-Path -LiteralPath $stateDir)) { $null = New-Item -ItemType Directory -Path $stateDir -Force }
    $tmp = "$statePath.$PID.tmp"
    Set-Content -LiteralPath $tmp -Value ($state | ConvertTo-Json -Compress) -Encoding utf8NoBOM -NoNewline
    try { [System.IO.File]::Move($tmp, $statePath, $true) }
    catch { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; throw }

    if (-not $fire) { exit 0 }

    [Console]::Out.Write($out)
    try {
        $logPath = Join-Path $promptDir ("log-{0}.jsonl" -f $now.ToString('yyyy-MM'))
        Add-Content -LiteralPath $logPath -Value $logLine -Encoding utf8NoBOM
    }
    catch { }   # A lost log line must not cost the prompt, which is already out.
}
catch {
    exit 0
}
exit 0
