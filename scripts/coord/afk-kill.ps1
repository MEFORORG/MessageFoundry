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
    then the roster's aliases. Only a worktree sharing this script's git common dir may name the
    seat; for a `cwd` in another repository's checkout, or one whose common dir cannot be read, the
    seat comes from $env:KORUS_SEAT and this script's roster, else it is undeclared. That
    checkout's marker cannot name the seat, but one naming Special, or an alias of Special in
    either roster, still vetoes the instruction. A fault on this path prints no instruction, so it
    fails toward no instruction rather than a wrong one. It never runs while the
    switch reads ON.

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

function Get-SkillInstructionSource {
    # The hook input's SessionStart source ('' when it names none) only when this session's seat is
    # known not to be Special, else $null. Anything it cannot establish throws, and the caller
    # reads that as no instruction.
    if ($env:KORUS_AGENT -eq 'codex') { return $null }  # the Skill tool is Claude Code's
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'hooks/_hookinput.ps1')
    # The payload's worktree, never this process's: under the desktop app the hook runs in the
    # PRIMARY checkout, whose marker names another session's seat. Walked up from the `cwd` as
    # role-card-inject.ps1 walks it, NOT through Resolve-CcxHookSession's pin, so within this
    # repository the two hooks name one seat at one SessionStart. They can differ for a cwd in
    # another repository's checkout: role-card-inject.ps1 still follows it and reads that marker,
    # while this hook reads the seat as undeclared unless that marker vetoes (below). The pin would also refuse every /clear
    # in a desktop-app worktree, the one source whose session has just lost both skills.
    $text = Read-CcxHookInput
    if ($script:CcxHookInputTimedOut) { throw 'the hook input was still open when the read stopped waiting' }
    if ($script:CcxHookInputFault) { throw $script:CcxHookInputFault }
    $payload = $null
    # -NoEnumerate, as the helper parses it, so an array holding one object is refused here too.
    if (-not [string]::IsNullOrWhiteSpace($text)) { $payload = $text | ConvertFrom-Json -NoEnumerate -ErrorAction Stop }
    $p = Get-CcxHookPayloadCwd -Payload $payload
    if ($p.Reason) { throw $p.Reason }
    if (-not $p.Named) { throw 'the hook input names no cwd' }
    $root = Get-CcxWorktreeRoot $p.Cwd
    if (-not $root) { throw "the hook input's cwd $($p.Cwd) is inside no checkout" }
    # Only a checkout of this repository may name the seat: another repository's marker, or its
    # roster with no Special alias, would hand a Special seat the instruction. Such a cwd, or one
    # whose common dir (or this script's) cannot be read, is read as undeclared instead: its roster
    # is skipped, its marker may only VETO (below), $env:KORUS_SEAT is read against this script's
    # own roster, and an undeclared seat gets the instruction with its Special-skips sentence.
    # Refusing would cost a non-Special seat whose shell sits in another checkout its reload after
    # a compaction. Compared through links as well as by text, because the script's path and a
    # worktree's gitdir line may spell one directory differently.
    $ownRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ownSeats = Join-Path $ownRoot 'docs/roles/seats.json'
    $own = Get-CcxGitCommonDir (Get-CcxWorktreeRoot $PSScriptRoot)
    $theirs = Get-CcxGitCommonDir $root
    $ours = $own -and $theirs -and ((Test-CcxSamePath $own $theirs) -or
        (Test-CcxSamePath (ConvertTo-CcxRealPath $own) (ConvertTo-CcxRealPath $theirs)))
    $source = ''
    if ($payload.PSObject.Properties['source']) { $source = ([string]$payload.source).Trim().ToLowerInvariant() }
    $raw = $null
    $marker = Join-Path $root '.claude/seat.local.txt'
    if (Test-Path -LiteralPath $marker) { $raw = Get-Content -LiteralPath $marker -Raw -ErrorAction Stop }
    $theirSeats = Join-Path $root 'docs/roles/seats.json'
    if (-not $ours) {
        # A marker that cannot NAME the seat may still VETO the instruction: one naming Special, or
        # an alias of it in either roster, prints nothing, as the cwd's marker did before the
        # repository check. The cwd's roster only adds vetoes here, so a fault reading it is noted
        # and skipped; this script's roster, or the marker itself, failing to read still throws.
        # Like the marker it vetoes as, it outranks $env:KORUS_SEAT. The cost is accepted: a stale
        # Special marker in a shared foreign checkout silences a non-Special seat there too.
        $extra = @()
        if (-not [string]::IsNullOrWhiteSpace($raw) -and (Test-Path -LiteralPath $theirSeats -PathType Leaf)) {
            try { $extra = @(Get-SeatAliasMap $theirSeats) }
            catch { [Console]::Error.WriteLine("afk-kill.ps1: the roster $theirSeats could not be read for a veto, so only this script's is used: $($_.Exception.Message)") }
        }
        if (Test-SpecialSeatLabel $raw @($ownSeats) $extra) {
            [Console]::Error.WriteLine("afk-kill.ps1: the hook input's cwd $($p.Cwd) is in $root, which is not shown to be a checkout of this repository, and its seat marker names a Special seat, so no instruction")
            return $null
        }
        [Console]::Error.WriteLine("afk-kill.ps1: the hook input's cwd $($p.Cwd) is in $root, which is not shown to be a checkout of this repository, so its seat marker does not name the seat")
        $raw = $null
        $theirSeats = $ownSeats
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $env:KORUS_SEAT }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $source }  # undeclared
    if (-not (Test-Path -LiteralPath $theirSeats -PathType Leaf)) { $theirSeats = $ownSeats }
    if (Test-SpecialSeatLabel $raw @($theirSeats)) { return $null }
    return $source
}

$script:SeatAliasMaps = @{}
function Get-SeatAliasMap([string]$Seats) {
    # The roster's alias map, parsed once per path. An unreadable roster, or one with no alias
    # map, throws.
    if (-not $script:SeatAliasMaps.ContainsKey($Seats)) {
        $aliases = (Get-Content -LiteralPath $Seats -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).aliases
        if ($null -eq $aliases) { throw "the roster $Seats has no alias map" }
        $script:SeatAliasMaps[$Seats] = $aliases
    }
    return $script:SeatAliasMaps[$Seats]
}

function Test-SpecialSeatLabel([string]$Raw, [string[]]$Seats, [object[]]$Maps = @()) {
    # True when $Raw names Special or an alias of it in the rosters at $Seats or in the alias $Maps
    # already read. A blank label names no seat and reads no roster. An alias of Special is
    # Special too, so the rosters are read when the label is not `special` itself.
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $false }
    $label = $Raw.Trim().ToLowerInvariant()
    if ($label -eq 'special') { return $true }
    foreach ($map in @(@($Seats | ForEach-Object { Get-SeatAliasMap $_ }) + $Maps)) {
        $alias = $map.PSObject.Properties[$label]
        if ($alias -and [string]$alias.Value -eq 'special') { return $true }
    }
    return $false
}

if (-not $sw.On) {
    try { $source = Get-SkillInstructionSource }
    catch {
        # On stderr for whoever runs the hook by hand or reads the hook debug log. Claude Code does
        # not show a hook's stderr at exit 0, so this is a diagnostic, not an alarm, and the tests
        # are what catch a change that silences every seat.
        [Console]::Error.WriteLine("afk-kill.ps1: no skill instruction, because $($_.Exception.Message)")
        $source = $null
    }
    if ($null -ne $source) {
        # Which source gets which sentence, and why, is ADR 0211's to state.
        if ($source -in @('compact', 'clear')) {
            $reload = 'This session restarted from a compaction or a /clear, which can leave a summary ' +
                'saying both were loaded while their text is gone, so load both again. '
        }
        else {
            $reload = 'Skip a skill only if its full text is in your context now; a summary saying it ' +
                'was loaded does not count. '
        }
        $text = 'Before your first other action, load the `driver` skill and then the `empower` skill ' +
            'with the Skill tool, as the owner instructs every non-Special seat. In a cloud session ' +
            '(CLAUDE_CODE_REMOTE=true) they may be named `anthropic-skills:driver` and ' +
            '`anthropic-skills:empower`. If either is not available, say so in one line and continue. ' +
            $reload + 'An owner instruction in this conversation to stop using either skill outranks ' +
            'this one. A Special seat skips this, including one the owner names as Special in its ' +
            'first message.'
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
