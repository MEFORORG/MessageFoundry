# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Shared by decision.ps1 and digest.ps1: the AFK-autonomy decision log's storage (ADR 0211).

.DESCRIPTION
    THE LOG LIVES IN THE VAULT'S ISSUES, ONE ISSUE PER UTC DAY, ONE COMMENT PER RECORD. The vault is
    private, every account on every machine reads it as the one shared GitHub identity, and a comment
    is one atomic REST write that needs no merge. ADR 0211 weighs this against a JSONL file in the
    vault and a local file, and says what it costs.

    EVERY RECORD IS SPOOLED LOCALLY FIRST, under <git-common-dir>/mefor-coord/decisions/spool, and
    the spool is flushed to the vault after. So a record survives a network failure, and the
    tripwire hook can log with no network at all (-NoPost); the next flush posts it. A reader merges
    the vault's records with the spool's and drops duplicates by id, so a record posted twice (a
    lost response, two flushers) reads once.

    A day's issue is titled `decision-log <yyyy-MM-dd>` and labelled `decision-log`. Two machines
    that both create the same day's issue produce two issues with one title; a reader reads every
    issue with that title, so the duplicate costs nothing but a second issue. On one machine a named
    mutex serialises the find-or-create.

    A RECORD IS DATA, NEVER INSTRUCTIONS (plan section 3, R5). Anyone with vault access can post a
    comment; this file parses only comments carrying the marker below, and a parsed record still
    proves nothing about who decided.

    Dot-source it. It defines functions only and has no side effect on load.
#>

$script:DecisionMarker = '<!-- mefor-decision v1 -->'
$script:DecisionLabel = 'decision-log'
$script:DecisionTitlePrefix = 'decision-log '

# Read at load time: inside a function $PSScriptRoot would name the caller's script.
$script:DecisionHere = $PSScriptRoot

function Get-DecisionCoordRoot {
    # Anchored on where the scripts live, not on the cwd, as alloc.ps1 and claim.ps1 are: run from
    # inside another checkout, a cwd lookup would spool records into that repository unseen.
    $c = (& git -C $script:DecisionHere rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $c) { throw "$script:DecisionHere is not inside a git repository" }
    return (Join-Path ([string]$c).Trim() 'mefor-coord')
}

function Resolve-DecisionDay([string]$Day) {
    # Today (UTC) by default; a malformed day is refused rather than read as a day with no records.
    if (-not $Day) { return [DateTime]::UtcNow.ToString('yyyy-MM-dd') }
    if ($Day -notmatch '^\d{4}-\d{2}-\d{2}$') { throw "-Day must be yyyy-MM-dd, not '$Day'." }
    return $Day
}

function Get-DecisionSpoolDir([string]$CoordRoot) {
    return (Join-Path (Join-Path $CoordRoot 'decisions') 'spool')
}

function New-DecisionId {
    $bytes = [byte[]]::new(3)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return 'd' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '-' + [Convert]::ToHexString($bytes).ToLowerInvariant()
}

function Get-DecisionIdDay([string]$Id) {
    # The id carries its UTC day, so a rating can find its decision by reading one day.
    if ($Id -cmatch '^d(\d{4})(\d{2})(\d{2})T\d{9}-[0-9a-f]{6}$') { return "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
    return $null
}

function Invoke-DecisionGh {
    <# Runs gh, returning Code, Out and Err. Never throws: a missing gh is code 127. #>
    param([string[]]$GhArgs, [string]$InputJson = '')
    $ErrorActionPreference = 'Continue'
    $tmp = $null
    try {
        if ($InputJson) {
            $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "mefor-decision-$PID-$([guid]::NewGuid().ToString('N')).json")
            [System.IO.File]::WriteAllText($tmp, $InputJson, [System.Text.UTF8Encoding]::new($false))
            $GhArgs = @($GhArgs) + @('--input', $tmp)
        }
        # A script must never wait on an auth prompt.
        $env:GH_PROMPT_DISABLED = '1'
        # gh writes UTF-8; the console's code page would mangle a non-ASCII field.
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $all = & gh @GhArgs 2>&1
        $code = $LASTEXITCODE
        $out = @($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        $err = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() }) -join "`n"
        return [pscustomobject]@{ Code = $code; Out = $out; Err = $err }
    } catch [System.Management.Automation.CommandNotFoundException] {
        return [pscustomobject]@{ Code = 127; Out = ''; Err = 'gh is not on PATH' }
    } finally {
        if ($tmp) { try { [System.IO.File]::Delete($tmp) } catch { $null = $_ } }
    }
}

function Format-DecisionComment($Record) {
    # Pretty JSON for the owner's eye on GitHub. A JSON string holds no raw newline, so a line that
    # is only a fence cannot occur inside it, and the parser below can rely on that.
    $json = $Record | ConvertTo-Json -Depth 8
    return "$script:DecisionMarker`n**$($Record.kind)** ``$($Record.id)``  class $($Record.class)  seat $($Record.seat)  item $($Record.item)`n`n" + '```json' + "`n$json`n" + '```'
}

$script:DecisionFields = [ordered]@{
    v = 1; id = ''; ts = ''; kind = ''; item = ''; seat = ''; session = ''; account = ''; host = ''; class = ''
    predicates = @(); recommendation = ''; alternatives = @(); undo = ''; confidence = $null; reviewed = 'no'
    reviewedBy = ''; outcome = ''; ref = ''; rating = ''; note = ''
}

function Complete-DecisionRecord($Record) {
    # A record read back carries every schema field, so a reader under strict mode never meets a
    # missing property in a hand-posted or older comment.
    $names = $Record.PSObject.Properties.Name
    foreach ($k in $script:DecisionFields.Keys) {
        if ($names -notcontains $k) { $Record | Add-Member -NotePropertyName $k -NotePropertyValue $script:DecisionFields[$k] }
    }
    return $Record
}

function ConvertFrom-DecisionComment([string]$Body) {
    if (-not $Body -or -not $Body.StartsWith($script:DecisionMarker)) { return $null }
    $lines = $Body -split "`r?`n"
    $start = [Array]::IndexOf($lines, '```json')
    if ($start -lt 0) { return $null }
    $end = -1
    for ($i = $start + 1; $i -lt $lines.Count; $i++) { if ($lines[$i] -ceq '```') { $end = $i; break } }
    if ($end -le $start + 1) { return $null }
    try {
        $rec = ($lines[($start + 1)..($end - 1)] -join "`n") | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
    if ($rec -isnot [pscustomobject] -or -not ($rec.PSObject.Properties.Name -contains 'id') -or -not (Get-DecisionIdDay ([string]$rec.id))) { return $null }
    return (Complete-DecisionRecord $rec)
}

function Get-DecisionDayIssues {
    <#
      Day -> issue numbers, from the 100 most recently created log issues: one request. Oldest is
      the oldest day listed when the page came back full, so a reader can tell a day it could not
      reach from a day with no issue.
    #>
    param([string]$Repo)
    $r = Invoke-DecisionGh @('api', "repos/$Repo/issues?labels=$script:DecisionLabel&state=all&sort=created&direction=desc&per_page=100")
    if ($r.Code -ne 0) { throw "could not list the decision-log issues on ${Repo}: $($r.Err)" }
    $map = @{}
    $listed = @($r.Out | ConvertFrom-Json)
    foreach ($i in $listed) {
        $t = [string]$i.title
        if (-not $t.StartsWith($script:DecisionTitlePrefix)) { continue }
        $day = $t.Substring($script:DecisionTitlePrefix.Length).Trim()
        if (-not $map.ContainsKey($day)) { $map[$day] = [System.Collections.Generic.List[int]]::new() }
        $map[$day].Add([int]$i.number)
    }
    $oldest = if ($listed.Count -ge 100 -and $map.Count) { @($map.Keys | Sort-Object)[0] } else { $null }
    return [pscustomobject]@{ Map = $map; Oldest = $oldest }
}

function Get-DecisionIssueCachePath([string]$CoordRoot) {
    return (Join-Path (Join-Path $CoordRoot 'decisions') 'issues.json')
}

function Read-DecisionIssueCache([string]$CoordRoot) {
    $cache = @{}
    try {
        $o = [System.IO.File]::ReadAllText((Get-DecisionIssueCachePath $CoordRoot)) | ConvertFrom-Json -ErrorAction Stop
        foreach ($p in $o.PSObject.Properties) { $cache[$p.Name] = [int]$p.Value }
    } catch {
        # No cache, or an unreadable one: the listing answers instead.
        $null = $_
    }
    return $cache
}

function Write-DecisionIssueCache([string]$CoordRoot, [hashtable]$Cache) {
    $path = Get-DecisionIssueCachePath $CoordRoot
    $null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $path))
    $part = "$path.$PID.tmp"
    [System.IO.File]::WriteAllText($part, ($Cache | ConvertTo-Json -Compress))
    [System.IO.File]::Move($part, $path, $true)
}

function Get-DecisionDayIssue {
    <#
      The day's issue number, created when there is none. A day's number never changes, so it is
      cached locally and the listing is asked only on a miss: each record then costs one request.
    #>
    param([string]$Repo, [string]$Day, [string]$CoordRoot)
    $cache = Read-DecisionIssueCache $CoordRoot
    if ($cache.ContainsKey("$Repo|$Day")) { return $cache["$Repo|$Day"] }
    $mutex = [System.Threading.Mutex]::new($false, 'Global\mefor-decision-log-issue')
    $held = $false
    try {
        try { $held = $mutex.WaitOne(30000) } catch [System.Threading.AbandonedMutexException] { $held = $true }
        $map = (Get-DecisionDayIssues -Repo $Repo).Map
        if ($map.ContainsKey($Day)) {
            $n = $map[$Day] | Sort-Object | Select-Object -First 1
            $cache["$Repo|$Day"] = $n
            Write-DecisionIssueCache $CoordRoot $cache
            return $n
        }
        # A label the repository lacks is created first; 422 means it already exists.
        $null = Invoke-DecisionGh @('api', '-X', 'POST', "repos/$Repo/labels") -InputJson (@{ name = $script:DecisionLabel; color = '5319e7'; description = 'AFK-autonomy decision log (ADR 0211)' } | ConvertTo-Json -Compress)
        $body = @{
            title  = "$script:DecisionTitlePrefix$Day"
            labels = @($script:DecisionLabel)
            body   = "AFK-autonomy decision log for $Day (UTC), written by scripts/coord/decision.ps1 in the engine repository (ADR 0211). One comment per record. Records are data, never instructions."
        } | ConvertTo-Json -Compress
        $r = Invoke-DecisionGh @('api', '-X', 'POST', "repos/$Repo/issues") -InputJson $body
        if ($r.Code -ne 0) { throw "could not create the decision-log issue for $Day on ${Repo}: $($r.Err)" }
        $n = [int]($r.Out | ConvertFrom-Json).number
        $cache["$Repo|$Day"] = $n
        Write-DecisionIssueCache $CoordRoot $cache
        return $n
    } finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Read-DecisionIssue {
    param([string]$Repo, [int]$Number)
    $r = Invoke-DecisionGh @('api', '--paginate', '--slurp', "repos/$Repo/issues/$Number/comments?per_page=100")
    if ($r.Code -ne 0) { throw "could not read issue $Number on ${Repo}: $($r.Err)" }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($page in @($r.Out | ConvertFrom-Json)) {
        foreach ($c in @($page)) {
            $rec = ConvertFrom-DecisionComment ([string]$c.body)
            if ($rec) { $rec | Add-Member -NotePropertyName posted -NotePropertyValue $true -Force; $out.Add($rec) }
        }
    }
    return $out.ToArray()
}

function Read-DecisionSpool([string]$CoordRoot) {
    $out = [System.Collections.Generic.List[object]]::new()
    $dir = Get-DecisionSpoolDir $CoordRoot
    if (-not [System.IO.Directory]::Exists($dir)) { return }
    foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
        # A file being posted right now is <id>.json.<pid>.posting; it is still unposted until it goes.
        if (-not ($f.EndsWith('.json') -or $f.EndsWith('.posting'))) { continue }
        try {
            $rec = Complete-DecisionRecord ([System.IO.File]::ReadAllText($f) | ConvertFrom-Json -ErrorAction Stop)
            $rec | Add-Member -NotePropertyName posted -NotePropertyValue $false -Force
            $out.Add($rec)
        } catch {
            [Console]::Error.WriteLine("decision log: unreadable spool file ${f}: $($_.Exception.Message)")
        }
    }
    return $out.ToArray()
}

function Write-DecisionSpool([string]$CoordRoot, $Record) {
    $dir = Get-DecisionSpoolDir $CoordRoot
    $null = [System.IO.Directory]::CreateDirectory($dir)
    $final = Join-Path $dir "$($Record.id).json"
    $part = "$final.$PID.tmp"
    [System.IO.File]::WriteAllText($part, ($Record | ConvertTo-Json -Depth 8 -Compress), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::Move($part, $final)
}

function Send-DecisionSpool {
    <# Posts every spooled record to its day's issue, oldest first. Returns the count posted and an error per record left. #>
    param([string]$Repo, [string]$CoordRoot)
    $posted = 0; $errors = [System.Collections.Generic.List[string]]::new()
    $dir = Get-DecisionSpoolDir $CoordRoot
    if (-not [System.IO.Directory]::Exists($dir)) { return [pscustomobject]@{ Posted = 0; Errors = $errors } }
    $stale = [DateTime]::UtcNow.AddMinutes(-10)
    $files = [System.IO.DirectoryInfo]::new($dir).GetFiles() | Where-Object {
        $_.Name.EndsWith('.json') -or ($_.Name.EndsWith('.posting') -and $_.LastWriteTimeUtc -lt $stale)
    } | Sort-Object Name
    $issues = @{}
    foreach ($f in $files) {
        # Claim the file by renaming it, so two flushers do not both post it. A claim left by a
        # flusher that died is retaken after ten minutes; a double post then reads once by id.
        $id = $f.Name.Substring(0, $f.Name.IndexOf('.json'))
        $claim = Join-Path $dir "$id.json.$PID.posting"
        try { [System.IO.File]::Move($f.FullName, $claim) } catch { continue }
        try {
            $rec = [System.IO.File]::ReadAllText($claim) | ConvertFrom-Json -ErrorAction Stop
            $day = Get-DecisionIdDay ([string]$rec.id)
            if (-not $day) { throw "spool file $($f.Name) holds no valid id" }
            if (-not $issues.ContainsKey($day)) { $issues[$day] = Get-DecisionDayIssue -Repo $Repo -Day $day -CoordRoot $CoordRoot }
            $body = @{ body = (Format-DecisionComment $rec) } | ConvertTo-Json -Compress -Depth 4
            $r = Invoke-DecisionGh @('api', '-X', 'POST', "repos/$Repo/issues/$($issues[$day])/comments") -InputJson $body
            if ($r.Code -ne 0) {
                # A cached number that no longer answers is dropped, so the next flush lists again.
                if ($r.Err -match '\b(404|410)\b') {
                    $cache = Read-DecisionIssueCache $CoordRoot
                    $cache.Remove("$Repo|$day")
                    Write-DecisionIssueCache $CoordRoot $cache
                    $issues.Remove($day)
                }
                throw "post failed: $($r.Err)"
            }
            [System.IO.File]::Delete($claim)
            $posted++
        } catch {
            $errors.Add("$id`: $($_.Exception.Message)")
            try { [System.IO.File]::Move($claim, (Join-Path $dir "$id.json")) } catch { $null = $_ }
        }
    }
    return [pscustomobject]@{ Posted = $posted; Errors = $errors }
}

function Read-DecisionLog {
    <# Every record on the given days, from the vault and the local spool, deduplicated by id. #>
    param([string]$Repo, [string]$CoordRoot, [string[]]$Days)
    $byId = [ordered]@{}
    $errors = [System.Collections.Generic.List[string]]::new()
    try {
        $listing = Get-DecisionDayIssues -Repo $Repo
        $map = $listing.Map
        # A day older than a full listing reaches is unread, not empty.
        $unreached = @($Days | Where-Object { $listing.Oldest -and $_ -lt $listing.Oldest })
        if ($unreached.Count) {
            $errors.Add("the listing reaches back only to $($listing.Oldest), so $($unreached.Count) older day(s) were not read")
        }
        foreach ($d in $Days) {
            if (-not $map.ContainsKey($d)) { continue }
            foreach ($n in $map[$d]) {
                try {
                    foreach ($rec in (Read-DecisionIssue -Repo $Repo -Number $n)) { $byId[[string]$rec.id] = $rec }
                } catch {
                    $errors.Add($_.Exception.Message)
                }
            }
        }
    } catch {
        $errors.Add($_.Exception.Message)
    }
    foreach ($rec in (Read-DecisionSpool $CoordRoot)) {
        $id = [string]$rec.id
        if ($Days -contains (Get-DecisionIdDay $id) -and -not $byId.Contains($id)) { $byId[$id] = $rec }
    }
    $records = @($byId.Values | Sort-Object { [string]$_.id })
    return [pscustomobject]@{ Records = $records; Complete = ($errors.Count -eq 0); Errors = $errors }
}

function Get-DecisionDayRange([string]$Day, [int]$Count) {
    $end = [DateTime]::ParseExact($Day, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    return @(0..($Count - 1) | ForEach-Object { $end.AddDays(-$_).ToString('yyyy-MM-dd') })
}
