# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Read the AFK-autonomy kill switch (ADR 0211; docs/AUTONOMY-PLAN.md section 4.3).

.DESCRIPTION
    The switch is the repository Actions variable MEFOR_AFK_KILL on MEFORORG/MessageFoundry, read
    over REST. When it is ON, every decision class reverts to ask-mode.

    THE OWNER SETS IT, AND NOTHING ENFORCES THAT. Every seat acts as the one shared GitHub identity,
    which can write repository variables, so a session could turn it off. The tripwire hook records
    a `gh variable set|delete` or a non-GET `gh api` call on it (ADR 0211); that is a record, not a
    block, and a write by any other route leaves none.

    IT FAILS SAFE: ONLY A READ THAT RETURNS EXACTLY `off` (case and surrounding space ignored) IS
    OFF. A missing variable, any other value, a gh error, no gh at all, or a read that does not
    finish inside -TimeoutSeconds is ON. An unread switch must never read as permission.

    -Status prints `ON` or `OFF` as its only stdout line, and the reason on stderr. It exits 0
    either way, so a caller reads the word rather than an exit code.

    -Banner is the SessionStart hook's mode: when the switch is ON it prints a hook JSON object
    whose systemMessage the owner sees and whose additionalContext the session reads. A fault in
    the read prints the ON banner, so only a real `off` read prints no banner, and it exits 0, so a
    broken read can never block a session from starting. A hook that cannot start at all (a cloud
    VM before cloud-setup.sh installs pwsh) prints nothing; that gap is outside this script.

    WHEN THE SWITCH READS OFF, -Banner may print the skill instruction ADR 0211 describes. Who gets
    it is stated there. The seat is read the way scripts/hooks/role-card-inject.ps1 reads it: the
    worktree the hook input's `cwd` sits in, its `.claude/seat.local.txt`, then $env:KORUS_SEAT,
    then the roster's aliases. A fault on this path prints no instruction, so it fails toward no
    instruction rather than a wrong one. It never runs while the switch reads ON.

    It writes nothing. Of local state it reads at least the seat marker, the roster and the `.git`
    entries above the hook input's `cwd`, and no coordination state, so it runs in a cloud session
    too, where the kill switch must hold as well.
#>
param(
    [switch]$Status,
    [switch]$Banner,
    [string]$Repo = 'MEFORORG/MessageFoundry',
    [string]$Name = 'MEFOR_AFK_KILL',
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-KillSwitch {
    # The read runs in its own runspace so a hung gh cannot outlast the hook's timeout: the
    # SessionStart hook would then be killed and print no banner, which fails OPEN.
    # The runspace gets the decision log's one gh wrapper by its text, because a script block
    # stays bound to the runspace that made it. A hung gh child is left to finish on its own.
    $ps = [powershell]::Create()
    try {
        $null = $ps.AddScript('param($Path, $Fn) Set-Item function:Invoke-DecisionGh ([scriptblock]::Create($Fn)); Invoke-DecisionGh @(''api'', $Path)').
            AddArgument("repos/$Repo/actions/variables/$Name").AddArgument(${function:Invoke-DecisionGh}.ToString())
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $null = $ps.BeginStop($null, $null)
            return [pscustomobject]@{ On = $true; Reason = "the read did not finish within $TimeoutSeconds s" }
        }
        $r = @($ps.EndInvoke($async)) | Select-Object -Last 1
    } catch {
        return [pscustomobject]@{ On = $true; Reason = "the read failed: $($_.Exception.Message)" }
    }
    if ($null -eq $r) { return [pscustomobject]@{ On = $true; Reason = 'the read returned nothing' } }
    if ($r.Code -ne 0) {
        $why = if ($r.Err) { $r.Err } else { "gh exited $($r.Code)" }
        return [pscustomobject]@{ On = $true; Reason = "unreadable ($why)" }
    }
    try {
        $value = [string]($r.Out | ConvertFrom-Json -ErrorAction Stop).value
    } catch {
        return [pscustomobject]@{ On = $true; Reason = 'the read returned no variable value' }
    }
    if ($value.Trim() -eq 'off') { return [pscustomobject]@{ On = $false; Reason = "$Name is 'off'" } }
    return [pscustomobject]@{ On = $true; Reason = "$Name is '$($value.Trim())', and only 'off' is OFF" }
}

if (@($Status, $Banner | Where-Object { $_ }).Count -ne 1) {
    [Console]::Error.WriteLine('afk-kill.ps1: give exactly one of -Status or -Banner.')
    exit 2
}

try {
    # Functions only; it reads no coordination state on load, so this still runs in a cloud session.
    . (Join-Path $PSScriptRoot '_decisionlog.ps1')
    $sw = Read-KillSwitch
} catch {
    # A fault is ON, never a silent OFF.
    $sw = [pscustomobject]@{ On = $true; Reason = "the read failed: $($_.Exception.Message)" }
}
if ($Status) {
    [Console]::Error.WriteLine("afk-kill.ps1: $($sw.Reason)")
    Write-Output $(if ($sw.On) { 'ON' } else { 'OFF' })
    exit 0
}

function ConvertTo-JsonText([string]$Text) {
    # Built by hand rather than with ConvertTo-Json, so nothing on the banner path can throw.
    return ($Text -replace '[\x00-\x1f]', ' ').Replace('\', '\\').Replace('"', '\"')
}

function Test-SkillInstructionDue {
    # True only when this session's seat is known not to be Special. Anything it cannot establish
    # throws, and the caller reads that as no instruction.
    if ($env:KORUS_AGENT -eq 'codex') { return $false }  # the Skill tool is Claude Code's
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'hooks/_hookinput.ps1')
    # The payload's worktree, never this process's: under the desktop app the hook runs in the
    # PRIMARY checkout, whose marker names another session's seat. Walked up from the `cwd` as
    # role-card-inject.ps1 walks it, NOT through Resolve-CcxHookSession's pin: the two hooks must
    # name one seat at one SessionStart, or a session holds a Special card beside an instruction
    # for non-Special seats. The pin would also refuse every /clear in a desktop-app worktree, the
    # one source whose session has just lost both skills.
    $text = Read-CcxHookInput
    if ($script:CcxHookInputTimedOut) { throw 'the hook input was still open when the read stopped waiting' }
    $p = Get-CcxHookPayloadCwd -Text $text
    if ($p.Reason) { throw $p.Reason }
    if (-not $p.Named) { throw 'the hook input names no cwd' }
    $root = Get-CcxWorktreeRoot $p.Cwd
    if (-not $root) { throw "the hook input's cwd $($p.Cwd) is inside no checkout" }
    $raw = $null
    $marker = Join-Path $root '.claude/seat.local.txt'
    if (Test-Path -LiteralPath $marker) { $raw = Get-Content -LiteralPath $marker -Raw -ErrorAction Stop }
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $env:KORUS_SEAT }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $true }  # undeclared
    $label = $raw.Trim().ToLowerInvariant()
    if ($label -eq 'special') { return $false }
    # An alias of Special is Special too, so the roster must be read; an unreadable one throws.
    $seats = Join-Path $root 'docs/roles/seats.json'
    if (-not (Test-Path -LiteralPath $seats -PathType Leaf)) {
        $seats = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'docs/roles/seats.json'
    }
    $aliases = (Get-Content -LiteralPath $seats -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).aliases
    $alias = $aliases.PSObject.Properties[$label]
    return -not ($alias -and [string]$alias.Value -eq 'special')
}

if (-not $sw.On) {
    try { $due = Test-SkillInstructionDue }
    catch {
        # On stderr for whoever runs the hook by hand or reads the hook debug log. Claude Code does
        # not show a hook's stderr at exit 0, so this is a diagnostic, not an alarm, and the tests
        # are what catch a change that silences every seat.
        [Console]::Error.WriteLine("afk-kill.ps1: no skill instruction, because $($_.Exception.Message)")
        $due = $false
    }
    if ($due -eq $true) {
        # One text for every SessionStart source, with no "skip what is loaded" clause: after a
        # compact or a /clear the summary may say both were loaded although their text is gone, and
        # a resumed conversation may itself have been compacted. A redundant load costs one call.
        $text = 'Before your first other action, load the `driver` skill and then the `empower` skill ' +
            'with the Skill tool, as the owner instructs every non-Special seat. In a cloud session ' +
            '(CLAUDE_CODE_REMOTE=true) they may be named `anthropic-skills:driver` and ' +
            '`anthropic-skills:empower`. If either is not available, say so in one line and continue. ' +
            'Load both even if this conversation, or a summary of it, says they were loaded: a ' +
            'compaction or a /clear drops their text, so load them again. A Special seat skips this, ' +
            'including one the owner names as Special in its first message.'
        Write-Output ('{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"' + (ConvertTo-JsonText $text) + '"}}')
    }
    exit 0
}
$text = "AFK KILL SWITCH IS ON. $Name on $Repo reads ON: $($sw.Reason). Every decision class is in " +
    'ask-mode: act on no Class B judgment without the owner, and bring every decision to the owner ' +
    'as you would have before the AFK-autonomy plan. Only the owner turns it off, by setting the ' +
    "variable to 'off'. ADR 0211; docs/AUTONOMY-PLAN.md section 4.3."
$json = ConvertTo-JsonText $text
Write-Output ('{"systemMessage":"=== ' + $json + ' ===","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"' + $json + '"}}')
exit 0
