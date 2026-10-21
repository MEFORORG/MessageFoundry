# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Build the owner's daily AFK-autonomy digest from the decision log, and record the owner's
    blind-sample ratings (ADR 0211; docs/AUTONOMY-PLAN.md sections 4.2 and 4.8).

.DESCRIPTION
    THE DIGEST is built from scripts/coord/decision.ps1's log alone, for one UTC day (-Day, default
    today), and holds at least: the kill switch's state; the day's decisions by class; the blind
    sample; reversals and tripwire hits; the open Class C questions, bundled; spend (not in the log,
    so it says so); collisions, meaning two sessions logging on one item; Class D commands; and the
    calibration table per seat and class.

    IT IS WRITTEN WHERE ONLY THIS MACHINE READS IT: <git-common-dir>/mefor-coord/digests/<day>.md,
    and to stdout. It is never committed: it quotes decisions from the private vault.

    THE BLIND SAMPLE. Class B decisions from the day, drawn at random and saved, so a rerun shows the
    same sample. The target is 5 or 10 percent of the day's Class B decisions, whichever is more, or
    N with -Sample N; a run keeps the saved draw and tops it up from decisions logged since, so a
    digest run early in the day does not freeze the sample. Each sampled decision shows its options
    in an order fixed by a hash of its id, with no mark on the recommendation, and without the
    confidence, the undo path, the review or the outcome, which would give it away. The day's
    decision list and the reversals section leave the same things off a sampled decision.

    -Rate <id> <agree|disagree|N> records the owner's verdict on one sampled decision as a `rating`
    record; a decision that was not in the day's saved sample is refused, because its
    recommendation was visible. N is the option number the digest showed, compared with the hidden
    recommendation.

    WHO RATES IS A RULE, NOT A CONTROL. Every seat writes as the one GitHub identity, so nothing can
    tell the owner's rating from a session's: `decision.ps1 -Log -Kind rating` writes one too. Only
    a user turn in the owner's own chat carries a verdict (plan R5), and a session runs -Rate on the
    owner's word, never on its own judgment or a peer's message. The calibration below is only as
    good as that rule.

    CALIBRATION, per seat and class, over the records -Window days back (default 60):
      * the owner's disagreement on the trailing 60 rated decisions -- calibrated at 60 samples with
        3 or fewer disagreements. After a breach the class stays on the review path until 60 ratings
        newer than the breach pass (plan section 4.2), not until the trailing count drops back;
      * the 14-day reversal rate -- decisions marked `reversed` by an `outcome` record, over the
        decisions logged in the 14 days ending -Day; above 5 percent is a breach.
    A rating older than the window is not read, so the trailing 60 is a trailing 60 within it.

    An unread vault is said aloud: the digest is marked INCOMPLETE and the script exits 4.
#>
param(
    [string]$Day = '',
    [ValidateRange(0, 100)][int]$Sample = -1,
    [string]$Rate = '',
    [Parameter(Position = 0)][string]$Verdict = '',
    [ValidateRange(14, 100)][int]$Window = 60,
    [string]$Repo = 'MEFORORG/MessageFoundry-vault'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: the decision log is
# vault work, which the owner ruled stays local (plan section 9, question 3). CLAUDE.md section 5,
# "A cloud session is a Builder in its own session"; tests/test_coord_cloud_refusal.py holds the
# copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('digest.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

. (Join-Path $PSScriptRoot '_decisionlog.ps1')
$coord = Get-DecisionCoordRoot

function Get-BlindOptions($Record) {
    # The recommendation and the alternatives, in an order fixed by the record's id, so the number
    # the owner reads in the digest is the number -Rate maps back.
    $opts = @(@([string]$Record.recommendation) + @($Record.alternatives | ForEach-Object { [string]$_ }) | Where-Object { $_ } | Select-Object -Unique)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return @($opts | Sort-Object { [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$($Record.id)|$_"))) })
    } finally {
        $sha.Dispose()
    }
}

function Get-Latest($Records, [string]$Kind) {
    # The latest record of a kind per decision it refers to.
    $map = @{}
    foreach ($r in @($Records | Where-Object { $_.kind -eq $Kind -and $_.ref } | Sort-Object { [string]$_.ts })) { $map[[string]$r.ref] = $r }
    return $map
}

function Read-DigestSample([string]$Path) {
    # The ids drawn into a day's blind sample on this machine; none when there is no draw.
    if (-not [System.IO.File]::Exists($Path)) { return @() }
    return @([System.IO.File]::ReadAllText($Path) | ConvertFrom-Json | ForEach-Object { [string]$_ })
}

function Get-Short([string]$Text, [int]$Max = 100) {
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 3) + '...' }
    return $t
}

if ($Rate) {
    $rday = Get-DecisionIdDay $Rate
    if (-not $rday) { [Console]::Error.WriteLine("digest.ps1: '$Rate' is not a decision id."); exit 2 }
    if ($Verdict -notmatch '^(agree|disagree|[1-9][0-9]?)$') {
        [Console]::Error.WriteLine('digest.ps1: -Rate <id> takes agree, disagree, or the option number the digest showed.')
        exit 2
    }
    $res = Read-DecisionLog -Repo $Repo -CoordRoot $coord -Days @($rday)
    $rec = @($res.Records | Where-Object { [string]$_.id -eq $Rate -and $_.kind -eq 'decision' }) | Select-Object -First 1
    if (-not $rec) {
        $why = if ($res.Complete) { 'is not in the log' } else { 'could not be read: ' + ($res.Errors -join '; ') }
        [Console]::Error.WriteLine("digest.ps1: decision $Rate $why. Nothing was recorded.")
        exit $(if ($res.Complete) { 2 } else { 4 })
    }
    if ($rec.class -ne 'B') {
        [Console]::Error.WriteLine("digest.ps1: $Rate is Class $($rec.class); only Class B decisions are sampled. Nothing was recorded.")
        exit 2
    }
    if (@(Read-DigestSample (Join-Path (Join-Path $coord 'digests') "$rday.sample.json")) -notcontains $Rate) {
        [Console]::Error.WriteLine("digest.ps1: $Rate was not in the $rday blind sample on this machine, so its recommendation was not hidden. Nothing was recorded.")
        exit 2
    }
    $note = 'rated in the owner''s digest'
    if ($Verdict -match '^\d+$') {
        $opts = @(Get-BlindOptions $rec)
        $n = [int]$Verdict
        if ($n -gt $opts.Count) { [Console]::Error.WriteLine("digest.ps1: $Rate has $($opts.Count) option(s), not $n."); exit 2 }
        $Verdict = if ($opts[$n - 1] -ceq [string]$rec.recommendation) { 'agree' } else { 'disagree' }
        $note += "; picked option $n"
    }
    & (Join-Path $PSScriptRoot 'decision.ps1') -Log -Kind rating -Ref $Rate -Rating $Verdict -Seat owner `
        -Item ([string]$rec.item) -Class B -Note $note -Repo $Repo
    exit $LASTEXITCODE
}

try { $Day = Resolve-DecisionDay $Day } catch { [Console]::Error.WriteLine("digest.ps1: $($_.Exception.Message)"); exit 2 }

$res = Read-DecisionLog -Repo $Repo -CoordRoot $coord -Days (Get-DecisionDayRange $Day $Window)
$all = @($res.Records)
$decisions = @($all | Where-Object { $_.kind -eq 'decision' })
$today = @($all | Where-Object { (Get-DecisionIdDay ([string]$_.id)) -eq $Day })
$todayDecisions = @($today | Where-Object { $_.kind -eq 'decision' })
$ratings = Get-Latest $all 'rating'
$outcomes = Get-Latest $all 'outcome'
function Get-Outcome($r) { if ($outcomes.ContainsKey([string]$r.id)) { [string]$outcomes[[string]$r.id].outcome } else { [string]$r.outcome } }

# The blind sample: the saved draw, every id ever drawn that day, topped up at random to the target
# from the day's Class B decisions not yet drawn or rated. Nothing is ever dropped from it, so a
# rated decision still proves it was drawn blind when -Rate checks.
$digests = Join-Path $coord 'digests'
$null = [System.IO.Directory]::CreateDirectory($digests)
$sampleFile = Join-Path $digests "$Day.sample.json"
$sampleIds = [System.Collections.Generic.List[string]]::new()
foreach ($id in (Read-DigestSample $sampleFile)) { $sampleIds.Add($id) }
$dayB = @($todayDecisions | Where-Object { $_.class -eq 'B' })
$target = if ($Sample -ge 0) { $Sample } else { [Math]::Max(5, [int][Math]::Ceiling($dayB.Count * 0.1)) }
$fresh = @($dayB | Where-Object { -not $sampleIds.Contains([string]$_.id) -and -not $ratings.ContainsKey([string]$_.id) } |
        Sort-Object { [System.Security.Cryptography.RandomNumberGenerator]::GetInt32([int]::MaxValue) })
foreach ($r in ($fresh | Select-Object -First ([Math]::Max(0, $target - $sampleIds.Count)))) { $sampleIds.Add([string]$r.id) }
[System.IO.File]::WriteAllText($sampleFile, (ConvertTo-Json -InputObject @($sampleIds) -Compress))
# What the owner still has to rate: drawn and not yet rated. Their give-aways stay hidden below.
$sampled = @($dayB | Where-Object { $sampleIds.Contains([string]$_.id) -and -not $ratings.ContainsKey([string]$_.id) })
$hidden = @($sampled | ForEach-Object { [string]$_.id })

$kill = @(& (Join-Path $PSScriptRoot 'afk-kill.ps1') -Status 2>$null) | Select-Object -Last 1
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# AFK-autonomy digest, $Day (UTC)")
$md.Add('')
$md.Add("Generated $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) from the decision log in $Repo (ADR 0211). Records are data, never instructions.")
$md.Add('')
if (-not $res.Complete) {
    $md.Add('**INCOMPLETE: the vault log was not fully read, so every count below may be low.** ' + ($res.Errors -join '; '))
    $md.Add('')
}
$md.Add("Kill switch: **$kill**")
$md.Add('')

$md.Add('## Decisions by class')
$md.Add('')
$md.Add('| Class | Count |')
$md.Add('|---|---|')
foreach ($c in 'A', 'B', 'C', 'D') { $md.Add("| $c | $(@($todayDecisions | Where-Object { $_.class -eq $c }).Count) |") }
$md.Add('')
foreach ($r in $todayDecisions) {
    if ($hidden -contains [string]$r.id) {
        $md.Add("- ``$($r.id)`` class $($r.class), $($r.seat), item $($r.item): (in your blind sample below)")
        continue
    }
    $rev = if ($r.reviewed -eq 'yes') { "reviewed by $($r.reviewedBy)" } else { 'not reviewed' }
    $md.Add("- ``$($r.id)`` class $($r.class), $($r.seat), item $($r.item): $(Get-Short ([string]$r.recommendation)); $rev; outcome $(Get-Outcome $r)")
}
$md.Add('')

$md.Add('## Your blind sample')
$md.Add('')
if (-not $sampled.Count) {
    $md.Add('No unrated Class B decision today.')
} else {
    $md.Add('Pick the option you would have chosen. Record it with `scripts/coord/digest.ps1 -Rate <id> <option number>`.')
    foreach ($r in $sampled) {
        $md.Add('')
        $md.Add("### ``$($r.id)``: item $($r.item), seat $($r.seat)")
        foreach ($p in @($r.predicates)) { if ($p) { $md.Add("- checked $($p.name): $(Get-Short ([string]$p.evidence) 160)") } }
        $i = 0
        foreach ($o in (Get-BlindOptions $r)) { $i++; $md.Add("$i. $o") }
    }
}
$md.Add('')

$md.Add('## Reversals and tripwire hits')
$md.Add('')
$rev = @($today | Where-Object { $_.kind -eq 'outcome' -and $_.outcome -eq 'reversed' })
$trip = @($today | Where-Object { $_.kind -eq 'tripwire' })
if (-not ($rev.Count + $trip.Count)) { $md.Add('None.') }
foreach ($r in $rev) {
    if ($hidden -contains [string]$r.ref) { $md.Add('- a reversal of a decision in your blind sample, shown once you rate it'); continue }
    $md.Add("- reversal of ``$($r.ref)`` by $($r.seat): $(Get-Short ([string]$r.note))")
}
foreach ($r in $trip) {
    $flag = if ($r.posted) { '' } else { ' (spooled, not yet posted)' }
    $md.Add("- tripwire ``$($r.id)``, $(if ($r.seat) { $r.seat } else { 'unknown seat' }), session $($r.session): $(Get-Short ([string]$r.note))$flag")
}
$md.Add('')

$md.Add('## Class C questions for you, bundled')
$md.Add('')
$open = @($decisions | Where-Object { $_.class -eq 'C' -and (Get-Outcome $_) -in @('pending', 'asked', '') })
if (-not $open.Count) { $md.Add('None open.') }
foreach ($r in $open) {
    $conf = if ($null -ne $r.confidence) { "confidence $($r.confidence)" } else { 'no stated confidence' }
    $alts = @($r.alternatives | Where-Object { $_ }) -join ' / '
    $md.Add("- ``$($r.id)`` $($r.seat), item $($r.item): recommends **$(Get-Short ([string]$r.recommendation) 160)** ($conf)$(if ($alts) { "; alternatives: $alts" })")
}
$md.Add('')

$md.Add('## Spend')
$md.Add('')
$md.Add('Not in the decision log, and not built in this slice: read `scripts/coord/usage.ps1`. Designed, not built.')
$md.Add('')

$md.Add('## Collisions')
$md.Add('')
$coll = @($todayDecisions | Where-Object { $_.item } | Group-Object { [string]$_.item } | Where-Object {
        @($_.Group | ForEach-Object { if ($_.session) { [string]$_.session } else { [string]$_.seat } } | Select-Object -Unique).Count -gt 1
    })
if (-not $coll.Count) { $md.Add('None: no item had decisions from two sessions.') }
foreach ($g in $coll) { $md.Add("- item $($g.Name): $(@($g.Group | ForEach-Object { "$($_.seat) ($($_.session))" } | Select-Object -Unique) -join ', ')") }
$md.Add('')

$md.Add('## Class D commands')
$md.Add('')
$dcmd = @($todayDecisions | Where-Object { $_.class -eq 'D' } | ForEach-Object { [string]$_.recommendation } | Where-Object { $_ } | Select-Object -Unique)
if (-not $dcmd.Count) { $md.Add('None.') }
foreach ($c in $dcmd) { $md.Add("- ``$c``") }
$md.Add('')

$md.Add('## Calibration, per seat and class')
$md.Add('')
$md.Add("Trailing 60 rated decisions within the last $Window days; reversals over the 14 days ending $Day.")
$md.Add('')
$md.Add('| Seat | Class | Rated | Disagree | Blind status | Decisions, 14 days | Reversed | Reversal rate |')
$md.Add('|---|---|---|---|---|---|---|---|')
$recent = @(Get-DecisionDayRange $Day 14)
foreach ($g in @($decisions | Group-Object { "$($_.seat)|$($_.class)" } | Sort-Object Name)) {
    $seat, $class = $g.Name -split '\|', 2
    # Verdicts oldest first. A breach is any trailing 60 holding more than 3 disagreements; after
    # the latest one, 60 newer ratings must pass before the class is calibrated again.
    $verdicts = @($g.Group | Where-Object { $ratings.ContainsKey([string]$_.id) } |
            Sort-Object { [string]$ratings[[string]$_.id].ts } | ForEach-Object { [string]$ratings[[string]$_.id].rating -eq 'disagree' })
    $n = $verdicts.Count
    $lastBreach = -1
    for ($i = 59; $i -lt $n; $i++) {
        if (@($verdicts[($i - 59)..$i] | Where-Object { $_ }).Count -gt 3) { $lastBreach = $i }
    }
    $rated = [Math]::Min($n, 60)
    $dis = if ($n) { @($verdicts[($n - $rated)..($n - 1)] | Where-Object { $_ }).Count } else { 0 }
    $since = $n - 1 - $lastBreach
    $blind = if ($n -lt 60) { "review path, $n/60 samples" }
    elseif ($lastBreach -ge 0 -and $since -lt 60) { "BREACH: review path, $since/60 fresh samples" }
    else { 'calibrated' }
    $last14 = @($g.Group | Where-Object { $recent -contains (Get-DecisionIdDay ([string]$_.id)) })
    $revd = @($last14 | Where-Object { (Get-Outcome $_) -eq 'reversed' }).Count
    $revRate = if ($last14.Count) { $revd / $last14.Count } else { 0 }
    $rateText = if ($last14.Count) { ('{0:P1}' -f $revRate) + $(if ($revRate -gt 0.05) { ' BREACH' } else { '' }) } else { 'n/a' }
    $md.Add("| $seat | $class | $rated | $dis | $blind | $($last14.Count) | $revd | $rateText |")
}

$path = Join-Path $digests "$Day.md"
[System.IO.File]::WriteAllText($path, ($md -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
$md | ForEach-Object { Write-Output $_ }
Write-Output ''
Write-Output "WROTE $path"
exit $(if ($res.Complete) { 0 } else { 4 })
