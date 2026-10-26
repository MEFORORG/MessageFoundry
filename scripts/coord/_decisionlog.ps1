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
    tripwire hook can log without posting (-NoPost); the next flush posts it. With -NoPost,
    decision.ps1 also skips a seat registry it can tell is on a share; its header lists what it can
    and cannot tell, and a share it cannot tell is still read. A reader merges
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
    if (-not $Day) { return [DateTime]::UtcNow.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    $parsed = [DateTime]::MinValue
    if ($Day -notmatch '^\d{4}-\d{2}-\d{2}$' -or -not [DateTime]::TryParseExact($Day, 'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw "-Day must be a real date as yyyy-MM-dd, not '$Day'."
    }
    return $Day
}

function Get-DecisionSpoolDir([string]$CoordRoot) {
    return (Join-Path (Join-Path $CoordRoot 'decisions') 'spool')
}

function New-DecisionId {
    $bytes = [byte[]]::new(3)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    # Invariant, or a Thai culture writes a Buddhist-era year: an id 543 years ahead.
    return 'd' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff', [Globalization.CultureInfo]::InvariantCulture) + '-' + [Convert]::ToHexString($bytes).ToLowerInvariant()
}

function Get-DecisionInstant([string]$Id) {
    # The UTC instant a record id carries, to the millisecond, or $null for a string that is not one.
    # The gate reads it rather than `ts`, which reads back as a DateTime whose Kind depends on its text.
    if ($Id -cnotmatch '^d(\d{8}T\d{9})-[0-9a-f]{6}$') { return $null }
    try {
        return [DateTime]::ParseExact($Matches[1], 'yyyyMMddTHHmmssfff', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    } catch {
        return $null
    }
}

function Get-DecisionIdDay([string]$Id) {
    # The id carries its UTC day, so a rating can find its decision by reading one day.
    $at = Get-DecisionInstant $Id
    if ($null -eq $at) { return $null }
    # Invariant, or a Thai culture writes a Buddhist-era year and reads another day's issue.
    return $at.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
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
    reviewedBy = ''; outcome = ''; ref = ''; rating = ''; note = ''; buildsOn = @(); gate = ''
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
      Day -> issue numbers, from every log issue: one request per 100 issues, so about one per
      quarter-year of log. The whole listing is read, so a day missing from it has no issue.
    #>
    param([string]$Repo)
    $r = Invoke-DecisionGh @('api', '--paginate', '--slurp', "repos/$Repo/issues?labels=$script:DecisionLabel&state=all&per_page=100")
    if ($r.Code -ne 0) { throw "could not list the decision-log issues on ${Repo}: $($r.Err)" }
    $map = @{}
    foreach ($i in @(@($r.Out | ConvertFrom-Json) | ForEach-Object { $_ })) {
        $t = [string]$i.title
        if (-not $t.StartsWith($script:DecisionTitlePrefix)) { continue }
        $day = $t.Substring($script:DecisionTitlePrefix.Length).Trim()
        if (-not $map.ContainsKey($day)) { $map[$day] = [System.Collections.Generic.List[int]]::new() }
        $map[$day].Add([int]$i.number)
    }
    return $map
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
        $map = Get-DecisionDayIssues -Repo $Repo
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

function Test-DecisionSpoolName([string]$Path) {
    # A spooled record is <id>.json, or <id>.json.<pid>.posting while a flusher posts it; it is
    # unposted until the claim goes. <id>.json.<pid>.tmp is a part file no reader takes.
    return ($Path.EndsWith('.json') -or $Path.EndsWith('.posting'))
}

function Get-DecisionSpoolId([string]$Name) {
    # The record id a spool file name starts with, or '' for a name that is not one.
    $at = $Name.IndexOf('.json')
    if ($at -lt 1) { return '' }
    return $Name.Substring(0, $at)
}

function Read-DecisionSpoolFile([string]$Dir, [string]$Path) {
    <#
      One spooled record, $null when it has left the spool, and a throw when it cannot be read. A
      flusher renames a file as it claims it, renames it back when a post fails, and deletes it only
      once the post is answered. So a file that vanishes is looked for again under its id: a
      record still spooled under another name is read there, and one with no name left was posted
      before this looked, so the vault read that follows holds it.
    #>
    $id = Get-DecisionSpoolId ([System.IO.Path]::GetFileName($Path))
    $tries = @($Path)
    for ($round = 1; $round -le 5; $round++) {
        foreach ($t in $tries) {
            try { $text = Read-DecisionSpoolText $t }
            catch [System.IO.FileNotFoundException] { continue }
            $rec = $text | ConvertFrom-Json -ErrorAction Stop
            if ($rec -isnot [System.Management.Automation.PSCustomObject]) { throw 'it holds no JSON object' }
            return $rec
        }
        $tries = @([System.IO.Directory]::GetFiles($Dir, "$id.json*") | Where-Object { Test-DecisionSpoolName $_ })
        if (-not $tries.Count) { return $null }
    }
    throw "it moved each time it was read"
}

function Read-DecisionSpool([string]$CoordRoot) {
    <#
      Every spooled record, and an error per file that could not be read. A caller counts an error
      as an incomplete read: the file may hold a record the gate must count.
    #>
    $out = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $dir = Get-DecisionSpoolDir $CoordRoot
    $files = @()
    if ([System.IO.Directory]::Exists($dir)) {
        try { $files = [System.IO.Directory]::GetFiles($dir) }
        catch { $errors.Add("the spool $dir could not be listed: $($_.Exception.Message)") }
    }
    foreach ($f in @($files | Where-Object { Test-DecisionSpoolName $_ })) {
        try {
            $raw = Read-DecisionSpoolFile $dir $f
            if ($null -eq $raw) { continue }
            $rec = Complete-DecisionRecord $raw
            $rec | Add-Member -NotePropertyName posted -NotePropertyValue $false -Force
            $out.Add($rec)
        } catch {
            $errors.Add("unreadable spool file ${f}: $($_.Exception.Message)")
        }
    }
    return [pscustomobject]@{ Records = $out.ToArray(); Errors = $errors }
}

function Read-DecisionSpoolText([string]$Path) {
    # A spool file being rewritten (Update-DecisionSpool) is locked for a moment, and a gate that
    # skipped it would count one record fewer, so a sharing violation is retried briefly.
    for ($try = 1; ; $try++) {
        try { return [System.IO.File]::ReadAllText($Path) }
        catch [System.IO.FileNotFoundException] { throw }
        catch [System.IO.IOException] { if ($try -ge 5) { throw }; Start-Sleep -Milliseconds 50 }
    }
}

function Get-DecisionSpoolPaths([string]$CoordRoot, [string]$Id) {
    # A record's spool name, <id>.json, and its part file <id>.json.<pid>.tmp beside it, which no
    # reader or flusher takes.
    $final = Join-Path (Get-DecisionSpoolDir $CoordRoot) "$Id.json"
    return [pscustomobject]@{ Part = "$final.$PID.tmp"; Final = $final }
}

function Write-DecisionSpoolPart($Paths, $Record) {
    [System.IO.File]::WriteAllText($Paths.Part, ($Record | ConvertTo-Json -Depth 8 -Compress), [System.Text.UTF8Encoding]::new($false))
}

function Write-DecisionSpool([string]$CoordRoot, $Record) {
    $null = [System.IO.Directory]::CreateDirectory((Get-DecisionSpoolDir $CoordRoot))
    $f = Get-DecisionSpoolPaths $CoordRoot ([string]$Record.id)
    Write-DecisionSpoolPart $f $Record
    [System.IO.File]::Move($f.Part, $f.Final)
}

function Update-DecisionSpool([string]$CoordRoot, $Record) {
    <#
      Rewrites a record still spooled as <id>.json, and returns whether it did. A flusher that has
      claimed the file (renamed it to post) leaves nothing to replace: on Windows File.Replace then
      refuses rather than spool a second copy. On Linux and macOS it checks and then renames, so a
      claim between the two would spool the record twice, which a reader dedups by id; a flusher
      does not claim a fresh PENDING record (Send-DecisionSpool), which keeps that window shut in
      practice. A lock from a reader is retried briefly. It throws when the part file cannot be
      written; the caller reports that, since the gate has answered by then.
    #>
    $f = Get-DecisionSpoolPaths $CoordRoot ([string]$Record.id)
    try {
        Write-DecisionSpoolPart $f $Record
        for ($try = 1; $try -le 5; $try++) {
            if (-not [System.IO.File]::Exists($f.Final)) { return $false }
            try {
                # [NullString], since PowerShell passes $null to a string parameter as ''.
                [System.IO.File]::Replace($f.Part, $f.Final, [NullString]::Value)
                return $true
            } catch [System.IO.IOException], [System.UnauthorizedAccessException] {
                Start-Sleep -Milliseconds 100
            }
        }
        return $false
    } finally {
        # A part file that cannot be deleted is left: no reader or flusher takes a .tmp name.
        try { if ([System.IO.File]::Exists($f.Part)) { [System.IO.File]::Delete($f.Part) } } catch { $null = $_ }
    }
}

# How long a flusher leaves a PENDING record to its gate, and a claim to the flusher that took it.
$script:DecisionHoldMinutes = 10

function Test-DecisionSpoolPending([System.IO.FileInfo]$File) {
    <#
      A record whose -Log is still waiting on its gate: PENDING, and minted in the last ten minutes.
      Posting it now would post PENDING for good. Older, its gate crashed or hung, and it is posted
      as it stands. The age is the id's own instant, never the file's write time, which a claim
      stamps and a failed post carries back. A file this cannot read is not held: the claim takes
      it, and the claim or the post reports it if it still cannot be read.
    #>
    $at = Get-DecisionInstant (Get-DecisionSpoolId $File.Name)
    if ($null -eq $at -or $at -lt [DateTime]::UtcNow.AddMinutes(-$script:DecisionHoldMinutes)) { return $false }
    try { return [string](Read-DecisionSpoolText $File.FullName | ConvertFrom-Json -ErrorAction Stop).gate -eq 'PENDING' }
    catch { return $false }
}

function Send-DecisionSpool {
    <#
      Posts every spooled record to its day's issue, oldest first. Returns the count Posted, an
      error per record left (Errors), the count Held, still waiting on its gate
      (Test-DecisionSpoolPending) for the next -Log or -Flush to post, and an entry per file Skipped
      because it could not be claimed, such as one another process holds open. A file another
      flusher claimed first is that flusher's to post, and is none of these.
    #>
    param([string]$Repo, [string]$CoordRoot)
    $posted = 0; $held = 0
    $errors = [System.Collections.Generic.List[string]]::new()
    $skipped = [System.Collections.Generic.List[string]]::new()
    $dir = Get-DecisionSpoolDir $CoordRoot
    $stale = [DateTime]::UtcNow.AddMinutes(-$script:DecisionHoldMinutes)
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    if ([System.IO.Directory]::Exists($dir)) {
        foreach ($f in [System.IO.DirectoryInfo]::new($dir).GetFiles()) {
            if ($f.Name.EndsWith('.json')) {
                if (Test-DecisionSpoolPending $f) { $held++ } else { $files.Add($f) }
            } elseif ($f.Name.EndsWith('.posting') -and $f.LastWriteTimeUtc -lt $stale) {
                $files.Add($f)
            }
        }
    }
    $issues = @{}
    $dayFailed = @{}
    foreach ($f in @($files | Sort-Object Name)) {
        # Claim the file by renaming it, so two flushers do not both post it. A claim left by a
        # flusher that died is retaken after ten minutes; a double post then reads once by id.
        $id = Get-DecisionSpoolId $f.Name
        $claim = Join-Path $dir "$id.json.$PID.posting"
        # A reader holding the file for a moment blocks the rename on Windows, so a refusal is
        # retried briefly; one that outlasts the retries is a lasting lock, reported as Skipped.
        $taken = $false; $gone = $false; $why = ''
        for ($try = 1; $try -le 5 -and -not $taken -and -not $gone; $try++) {
            try { [System.IO.File]::Move($f.FullName, $claim); $taken = $true }
            catch [System.IO.FileNotFoundException] { $gone = $true }
            catch { $why = $_.Exception.Message; Start-Sleep -Milliseconds 100 }
        }
        if ($gone) { continue }
        if (-not $taken) { $skipped.Add("$($f.Name): could not be claimed to post: $why"); continue }
        # A rename keeps the old write time; stamp the claim's own, or a record spooled long ago
        # would look like an abandoned claim the moment it is taken.
        try { [System.IO.File]::SetLastWriteTimeUtc($claim, [DateTime]::UtcNow) } catch { $null = $_ }
        try {
            $rec = [System.IO.File]::ReadAllText($claim) | ConvertFrom-Json -ErrorAction Stop
            $day = Get-DecisionIdDay ([string]$rec.id)
            if (-not $day) { throw "spool file $($f.Name) holds no valid id" }
            # A day whose issue could not be found or made fails once per flush, not once per
            # record: each try costs a listing and two POSTs from the shared REST budget.
            if ($dayFailed.ContainsKey($day)) { throw $dayFailed[$day] }
            if (-not $issues.ContainsKey($day)) {
                try { $issues[$day] = Get-DecisionDayIssue -Repo $Repo -Day $day -CoordRoot $CoordRoot }
                catch { $dayFailed[$day] = $_.Exception.Message; throw }
            }
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
    return [pscustomobject]@{ Posted = $posted; Errors = $errors; Held = $held; Skipped = $skipped }
}

function Read-DecisionLog {
    <#
      Every record on the given days, from the local spool and the vault, deduplicated by id; the
      vault's copy wins. THE SPOOL IS READ FIRST. A flusher deletes a spooled record only after its
      post is answered, so a record that leaves the spool after this read is in the vault before
      the vault read starts. Read the other way round, a record posted between the two reads
      would be in neither, and the gate would count one record too few. A spool file that cannot
      be read makes the read incomplete, as a vault read that fails does.
    #>
    param([string]$Repo, [string]$CoordRoot, [string[]]$Days)
    $byId = [ordered]@{}
    $spooled = Read-DecisionSpool $CoordRoot
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $spooled.Errors) { $errors.Add($e) }
    try {
        $map = Get-DecisionDayIssues -Repo $Repo
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
    foreach ($rec in $spooled.Records) {
        $id = [string]$rec.id
        if ($Days -contains (Get-DecisionIdDay $id) -and -not $byId.Contains($id)) { $byId[$id] = $rec }
    }
    $records = @($byId.Values | Sort-Object { [string]$_.id })
    return [pscustomobject]@{ Records = $records; Complete = ($errors.Count -eq 0); Errors = $errors }
}

function Get-DecisionDayRange([string]$Day, [int]$Count) {
    $end = [DateTime]::ParseExact($Day, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    return @(0..($Count - 1) | ForEach-Object { $end.AddDays(-$_).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) })
}

# --- What the class B gate reads (docs/AUTONOMY-PLAN.md 4.2 and 4.5-4.7) ---------------------------
#
# decision.ps1 -Gate and digest.ps1 both call these, so the digest's tables and the gate's answer are
# one computation, not two that agree by luck.

function Get-DecisionKillSwitch {
    # afk-kill.ps1 -Status's word, ON or OFF. Its reason goes to stderr. ON unless the read says OFF.
    return [string](@(& (Join-Path $script:DecisionHere 'afk-kill.ps1') -Status 2>$null) | Select-Object -Last 1)
}

function Get-DecisionLatest($Records, [string]$Kind) {
    # The latest record of a kind per decision it refers to. Ordered by id, which is the UTC write
    # time to the millisecond with a random tail: `ts` reads back as a DateTime, whose string form
    # sorts month first and drops the milliseconds.
    $map = @{}
    foreach ($r in @($Records | Where-Object { $_.kind -eq $Kind -and $_.ref } | Sort-Object { [string]$_.id })) { $map[[string]$r.ref] = $r }
    return $map
}

function Get-DecisionOutcome($Record, [hashtable]$Outcomes) {
    # A decision's outcome: its latest `outcome` record's, else the one it was logged with.
    if ($Outcomes.ContainsKey([string]$Record.id)) { return [string]$Outcomes[[string]$Record.id].outcome }
    return [string]$Record.outcome
}

function Get-DecisionCalibration {
    <#
      One seat and class's calibration, plan section 4.2: the owner's disagreement on the trailing 60
      rated decisions (calibrated at 60 with 3 or fewer; after a breach, 60 ratings newer than it must
      pass), and the reversal rate over the decisions logged on -RecentDays (a breach above 5
      percent). Calibrated means both hold. The digest's calibration table prints this, and the gate
      reads Calibrated.
    #>
    param($Decisions, [hashtable]$Ratings, [hashtable]$Outcomes, [string[]]$RecentDays)
    # Verdicts oldest first. A breach is any trailing 60 holding more than 3 disagreements; after
    # the latest one, 60 newer ratings must pass before the class is calibrated again.
    $verdicts = @($Decisions | Where-Object { $Ratings.ContainsKey([string]$_.id) } |
            Sort-Object { [string]$Ratings[[string]$_.id].id } | ForEach-Object { [string]$Ratings[[string]$_.id].rating -eq 'disagree' })
    $n = $verdicts.Count
    $lastBreach = -1
    for ($i = 59; $i -lt $n; $i++) {
        if (@($verdicts[($i - 59)..$i] | Where-Object { $_ }).Count -gt 3) { $lastBreach = $i }
    }
    $rated = [Math]::Min($n, 60)
    $dis = if ($n) { @($verdicts[($n - $rated)..($n - 1)] | Where-Object { $_ }).Count } else { 0 }
    $since = $n - 1 - $lastBreach
    $blindOk = $false
    $blind = if ($n -lt 60) { "review path, $n/60 samples" }
    elseif ($lastBreach -ge 0 -and $since -lt 60) { "BREACH: review path, $since/60 fresh samples" }
    else { $blindOk = $true; 'calibrated' }
    $recent = @($Decisions | Where-Object { $RecentDays -contains (Get-DecisionIdDay ([string]$_.id)) })
    $revd = @($recent | Where-Object { (Get-DecisionOutcome $_ $Outcomes) -eq 'reversed' }).Count
    $revRate = if ($recent.Count) { $revd / $recent.Count } else { 0 }
    $breach = $revRate -gt 0.05
    # Invariant culture, so the table reads the same on every machine.
    $pct = ($revRate * 100).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture) + '%'
    $rateText = if ($recent.Count) { $pct + $(if ($breach) { ' BREACH' } else { '' }) } else { 'n/a' }
    return [pscustomobject]@{
        Rated = $rated; Disagree = $dis; Blind = $blind; Recent = $recent.Count; Reversed = $revd
        RateText = $rateText; Calibrated = ($blindOk -and -not $breach)
    }
}

function Get-DecisionReversals($Records) {
    <#
      Each reversed decision once: an `outcome` record with outcome `reversed`, deduplicated by its
      ref, and the earliest such record is when it was reversed. A decision whose LATEST outcome is
      something else (a mistaken `reversed`, corrected) is not one, as the calibration reads it.
      Seat and Item are the DECISION's, joined through the ref, never the seat that logged the
      outcome. A ref the records do not hold has no Seat, and its Item is the outcome record's own,
      which may be empty.
    #>
    $byId = @{}
    foreach ($r in @($Records | Where-Object { $_.kind -eq 'decision' })) { $byId[[string]$r.id] = $r }
    $latest = Get-DecisionLatest $Records 'outcome'
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($o in @($Records | Where-Object { $_.kind -eq 'outcome' -and [string]$_.outcome -eq 'reversed' -and $_.ref } | Sort-Object { [string]$_.id })) {
        $ref = [string]$o.ref
        if ([string]$latest[$ref].outcome -ne 'reversed') { continue }
        if (-not $seen.Add($ref)) { continue }
        $d = if ($byId.ContainsKey($ref)) { $byId[$ref] } else { $null }
        $out.Add([pscustomobject]@{
                Ref  = $ref
                At   = Get-DecisionInstant ([string]$o.id)
                Seat = $(if ($d) { [string]$d.seat } else { $null })
                Item = $(if ($d) { [string]$d.item } else { [string]$o.item })
            })
    }
    return $out.ToArray()
}

function Read-DecisionLogForGate {
    <#
      Read-DecisionLog over -Days, then over the day of each reversed decision older than them, so
      every reversal read is charged to its decision's seat and item rather than to none. The gate
      and the digest both read through this. The older days' records are added for that join only:
      a caller that needs the window itself (calibration) filters by day.
    #>
    param([string]$Repo, [string]$CoordRoot, [string[]]$Days)
    $res = Read-DecisionLog -Repo $Repo -CoordRoot $CoordRoot -Days $Days
    $older = @(Get-DecisionReversals @($res.Records) | Where-Object { $null -eq $_.Seat } | ForEach-Object { Get-DecisionIdDay $_.Ref } |
            Where-Object { $_ -and $Days -notcontains $_ } | Select-Object -Unique)
    if (-not $res.Complete -or -not $older.Count) { return $res }
    $more = Read-DecisionLog -Repo $Repo -CoordRoot $CoordRoot -Days $older
    return [pscustomobject]@{
        Records = @(@($res.Records) + @($more.Records)); Complete = $more.Complete; Errors = @($res.Errors) + @($more.Errors)
    }
}

function Get-DecisionBudget {
    <#
      Plan 4.5's reversal budget: -Limit reversals inside any 24 hours closes the scope's no-review
      path for 24 hours from the one that reached the limit. Returns Limit, the reversals in the
      trailing 24 hours (Count), and ClosedUntil, $null while open. With -Seat it is that seat's
      budget, limit 2, over the reversals of its own decisions and of every decision the log does
      not hold (no seat, so charged to all). Without, it is the fleet's, limit 3, over all of them.
    #>
    param($Reversals, [datetime]$Now, [string]$Seat = '')
    $Limit = 3
    if ($Seat) {
        $Limit = 2
        $Reversals = @($Reversals | Where-Object { $_.Seat -eq $Seat -or $null -eq $_.Seat })
    }
    $day = [TimeSpan]::FromHours(24)
    # A reversal that could still close the scope at $Now happened in the last 24 hours, and the 24
    # before it can count toward it. A future-dated one (a skewed clock wrote its id) counts as now,
    # so it closes the budget rather than slipping past it.
    $times = @($Reversals | Where-Object { $null -ne $_.At -and $_.At -gt $Now - $day - $day } |
            ForEach-Object { if ($_.At -gt $Now) { $Now } else { $_.At } } | Sort-Object)
    $closedUntil = $null
    for ($i = $Limit - 1; $i -lt $times.Count; $i++) {
        if ($times[$i] - $times[$i - $Limit + 1] -lt $day -and $times[$i] + $day -gt $Now) { $closedUntil = $times[$i] + $day }
    }
    return [pscustomobject]@{ Limit = $Limit; Count = @($times | Where-Object { $_ -gt $Now - $day }).Count; ClosedUntil = $closedUntil }
}

function Format-DecisionInstant([datetime]$At) { return $At.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }

function Test-DecisionUnsampledB($Record, [hashtable]$Ratings) {
    # A Class B decision the owner has not rated. Plan 4.6 counts these, whoever logged them. One the
    # gate answered HALT for was deferred, not acted on, so nothing builds on it.
    return ($Record.kind -eq 'decision' -and [string]$Record.class -eq 'B' -and [string]$Record.gate -ne 'HALT' -and
        -not $Ratings.ContainsKey([string]$Record.id))
}

function Get-DecisionChain {
    <#
      Plan 4.6's chain depth for a Class B decision on -Item that builds on -BuildsOn: the larger of
      the unsampled Class B decisions on -Item reachable through buildsOn links (Walked), and the
      unsampled Class B decisions on -Item logged in the 24 hours before -Now (Floor). The floor is
      there because buildsOn is self-reported: a session that names nothing still meets it. Missing
      lists each linked id the records do not hold; a caller fails closed on it.

      The walk stops at a decision the owner rated, which ends the unsampled chain, and once it has
      counted three, which already goes to review: so a chain that reaches past the days read fails
      closed only while it is still unsampled and short.
    #>
    param($Records, [string]$Item, [string[]]$BuildsOn, [datetime]$Now, [hashtable]$Ratings)
    $byId = @{}
    foreach ($r in @($Records | Where-Object { $_.kind -eq 'decision' })) { $byId[[string]$r.id] = $r }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($b in @($BuildsOn | Where-Object { $_ })) { $queue.Enqueue([string]$b) }
    $walked = 0
    $missing = [System.Collections.Generic.List[string]]::new()
    while ($queue.Count) {
        $id = $queue.Dequeue()
        if ($walked -gt 2) { break }
        if (-not $seen.Add($id)) { continue }
        if (-not $byId.ContainsKey($id)) { $missing.Add($id); continue }
        $r = $byId[$id]
        if ($Ratings.ContainsKey($id)) { continue }
        if ([string]$r.item -eq $Item -and (Test-DecisionUnsampledB $r $Ratings)) { $walked++ }
        foreach ($p in @($r.buildsOn | Where-Object { $_ })) { $queue.Enqueue([string]$p) }
    }
    $floor = @(Get-DecisionRecentUnsampledB -Records $byId.Values -Now $Now -Ratings $Ratings | Where-Object { [string]$_.item -eq $Item }).Count
    return [pscustomobject]@{ Walked = $walked; Floor = $floor; Depth = [Math]::Max($walked, $floor); Missing = $missing.ToArray() }
}

function Get-DecisionRecentUnsampledB {
    # The unsampled Class B decisions logged in the 24 hours before -Now: plan 4.6's floor, per item.
    # One dated after -Now (a skewed clock wrote its id) counts, as though logged now.
    param($Records, [datetime]$Now, [hashtable]$Ratings)
    $since = $Now.AddHours(-24)
    return @($Records | Where-Object {
            (Test-DecisionUnsampledB $_ $Ratings) -and ($at = Get-DecisionInstant ([string]$_.id)) -and $at -gt $since
        })
}

function Test-DecisionLanderSeat([string]$Seat) {
    # The Lander, or a roster alias of it (docs/roles/seats.json). An unreadable roster is no
    # exemption: this only ever relaxes the cost rung, so a fault must not grant it.
    if (-not $Seat) { return $false }
    $s = $Seat.Trim().ToLowerInvariant()
    if ($s -eq 'lander') { return $true }
    try {
        $roster = Join-Path (Split-Path -Parent (Split-Path -Parent $script:DecisionHere)) 'docs/roles/seats.json'
        $alias = ([System.IO.File]::ReadAllText($roster) | ConvertFrom-Json -ErrorAction Stop).aliases.PSObject.Properties[$s]
        return [bool]($alias -and [string]$alias.Value -eq 'lander')
    } catch {
        return $false
    }
}

function Get-DecisionJsonValue($Object, [string]$Name) {
    # A property's value, or $null when the object is not one or lacks it: strict mode throws on a
    # missing property, and usage.ps1 leaves keys out on some paths on purpose.
    if ($Object -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-DecisionUsageScript { return (Join-Path $script:DecisionHere 'usage.ps1') }

function Get-DecisionThresholdsFile {
    # Beside the Steward's watch.py, which reads it from its own directory: <home>\.claude\mefor-usage,
    # whatever config root this session runs under.
    $home_ = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
    return (Join-Path (Join-Path (Join-Path $home_ '.claude') 'mefor-usage') 'thresholds.json')
}

function Get-DecisionRungLevels([string]$ThresholdsFile) {
    <#
      The session (5-hour) window's start-nothing rung: the HOLD NEW WORK percentage and its
      time-to-cutoff in minutes. The defaults are korus roles/STEWARD.md section 3's table, the row
      `| **1. HOLD NEW WORK** | 20 minutes | 80 percent | 90 percent | Start nothing new. ...`
      (line 444 at korus origin/main 8940b3d): 20 minutes, and the Session column's 80. The weekly
      column is not read, because only the 5-hour window carries the stop (STEWARD.md 3a; the owner's
      2026-08-14 ruling quoted there).

      The Steward's thresholds.json overrides them the way its watch.py does: `levels."5-hour"` and
      `minutes`, each three numbers, HOLD first. The key is "5-hour", as watch.py names the window.
      A missing file keeps the defaults. A file that cannot be read, or is malformed in a way
      watch.py would also refuse, throws: the gate then fails closed rather than grade against a
      guess.
    #>
    $holdAt = 80.0
    $holdMin = 20.0
    $source = 'korus roles/STEWARD.md section 3 defaults'
    if (-not [System.IO.File]::Exists($ThresholdsFile)) { return [pscustomobject]@{ HoldAt = $holdAt; HoldMin = $holdMin; Source = $source } }
    $doc = [System.IO.File]::ReadAllText($ThresholdsFile) | ConvertFrom-Json -ErrorAction Stop
    if ($doc -isnot [System.Management.Automation.PSCustomObject]) { throw "$ThresholdsFile is not a JSON object" }
    function Get-Triple($Raw, [string]$What) {
        $vals = @($Raw)
        if ($Raw -isnot [array] -or $vals.Count -ne 3 -or @($vals | Where-Object { $_ -isnot [int] -and $_ -isnot [long] -and $_ -isnot [double] -and $_ -isnot [decimal] }).Count) {
            throw "$ThresholdsFile $What is not three numbers"
        }
        return @($vals | ForEach-Object { [double]$_ })
    }
    $levels = Get-DecisionJsonValue $doc 'levels'
    if ($null -ne $levels) {
        if ($levels -isnot [System.Management.Automation.PSCustomObject]) { throw "$ThresholdsFile levels is not an object" }
        foreach ($p in $levels.PSObject.Properties) {
            if ($p.Name -cnotin @('5-hour', 'weekly')) { throw "$ThresholdsFile names unknown window '$($p.Name)'" }
            $t = Get-Triple $p.Value "levels[$($p.Name)]"
            if ($p.Name -ceq '5-hour') { $holdAt = $t[0]; $source = $ThresholdsFile }
        }
    }
    $minutes = Get-DecisionJsonValue $doc 'minutes'
    if ($null -ne $minutes) { $holdMin = (Get-Triple $minutes 'minutes')[0]; $source = $ThresholdsFile }
    return [pscustomobject]@{ HoldAt = $holdAt; HoldMin = $holdMin; Source = $source }
}

function Get-DecisionCostRung {
    <#
      Plan 4.7's cost rung, for the account this session runs on: State HIT (at or past the
      start-nothing rung), OK, or UNKNOWN, and why.

      It reads usage.ps1 -Json, the one reader of the statusLine's published files, in a child pwsh:
      usage.ps1 runs without strict mode, and an in-process call would inherit the caller's.
      THE SESSION (5-HOUR) WINDOW ONLY: a weekly rung names a severity and stops nobody (korus
      roles/STEWARD.md 3a). RATE GOVERNS (STEWARD.md 9.6a, owner-ratified 2026-08-14): with a burn
      rate, the rung is hit when the window is projected to run out within HoldMin minutes and
      before it resets, whatever the level. Only with no rate is the level the backstop.

      A WINDOW AT THE CEILING IS HIT WHATEVER THE RATE: 98 percent or more, the band usage.ps1 itself
      calls CRITICAL "at the ceiling". A flat or falling rate there says there is no room, not room.

      UNKNOWN when the reading is missing, stale, refused, or usage.ps1 calls it UNKNOWN overall (its
      overall UNKNOWN also carries its refusal of a statusLine wired to another root, which the
      5-hour state does not), unless the 5-hour window grades HIT: a hit is never downgraded, since
      that would fail open. usage.ps1 skips that refusal when it reads CRITICAL overall, so a
      CRITICAL reading that this grades below the rung is UNKNOWN too: it may be another root's. A
      reader that does not finish within -TimeoutSeconds is UNKNOWN. A Desktop session that runs no
      statusLine reads UNKNOWN here; the Steward's status.json fallback that
      usage-headroom-inject.ps1 prints is not read, because it would be a third copy of watch.py's
      pool rules.
    #>
    param([string]$UsageScript, [string]$ThresholdsFile, [int]$TimeoutSeconds = 30)
    function New-DecisionRung([string]$State, [string]$Reason) { [pscustomobject]@{ State = $State; Reason = $Reason } }
    try { $lv = Get-DecisionRungLevels $ThresholdsFile }
    catch { return (New-DecisionRung 'UNKNOWN' "the rung levels could not be read: $($_.Exception.Message)") }
    if (-not [System.IO.File]::Exists($UsageScript)) {
        return (New-DecisionRung 'UNKNOWN' "the usage reader $UsageScript does not exist")
    }
    $p = $null
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
        foreach ($a in @('-NoProfile', '-NonInteractive', '-File', $UsageScript, '-Json')) { $psi.ArgumentList.Add($a) }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEndAsync()
        $null = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill($true) } catch { $null = $_ }
            return (New-DecisionRung 'UNKNOWN' "usage.ps1 -Json did not finish within $TimeoutSeconds s")
        }
        $j = $out.GetAwaiter().GetResult().Trim() | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return (New-DecisionRung 'UNKNOWN' "usage.ps1 -Json gave no reading: $($_.Exception.Message)")
    } finally {
        if ($p) { $p.Dispose() }
    }
    $overall = [string](Get-DecisionJsonValue $j 'state')
    if ($overall -eq 'UNAVAILABLE') {
        return (New-DecisionRung 'HIT' 'usage.ps1 reads UNAVAILABLE: this account has no subscription, so there is no pool to spend')
    }
    $five = Get-DecisionJsonValue $j 'five_hour'
    $pct = Get-DecisionJsonValue $five 'used_percentage'
    $fiveState = [string](Get-DecisionJsonValue $five 'state')
    if ($null -eq $five -or $null -eq $pct -or $fiveState -notin @('OK', 'WARN', 'CRITICAL')) {
        $why = [string](Get-DecisionJsonValue $five 'reason')
        if (-not $why) { $why = [string](Get-DecisionJsonValue $j 'reason') }
        return (New-DecisionRung 'UNKNOWN' "the 5-hour window is UNKNOWN: $why")
    }
    $pct = [double]$pct
    $rate = Get-DecisionJsonValue $five 'rate_pct_per_hr'
    $toEmpty = Get-DecisionJsonValue $five 'minutes_to_empty'
    $toReset = Get-DecisionJsonValue $five 'minutes_to_reset'
    $at = "5-hour at $pct%; rung $($lv.HoldMin) min to cutoff or $($lv.HoldAt)% with no rate, from $($lv.Source)"
    $rung = if ($pct -ge 98) {
        New-DecisionRung 'HIT' "$at. At the ceiling (98 percent, usage.ps1's own CRITICAL band), whatever the rate"
    } elseif ($null -ne $rate) {
        $cut = [double]$rate -gt 0 -and $null -ne $toEmpty -and ($null -eq $toReset -or [double]$toEmpty -lt [double]$toReset)
        if ($cut -and [double]$toEmpty -le $lv.HoldMin) {
            New-DecisionRung 'HIT' "$at. Projected to run out in about $toEmpty min, before the window resets"
        } else {
            New-DecisionRung 'OK' "$at. The burn rate governs, and it does not reach the rung"
        }
    } elseif ($pct -ge $lv.HoldAt) {
        New-DecisionRung 'HIT' "$at. No burn rate, so the level is the backstop, and it is reached"
    } else {
        New-DecisionRung 'OK' "$at. No burn rate; below the level backstop"
    }
    # A HIT stands whatever the overall state: halting on a reading that may be another root's
    # costs a deferral, while dropping it to UNKNOWN would let a session at the ceiling act.
    if ($rung.State -eq 'HIT') { return $rung }
    if ($overall -notin @('OK', 'WARN', 'CRITICAL')) {
        return (New-DecisionRung 'UNKNOWN' "$($rung.Reason); but usage.ps1 reads '$overall' overall: $(Get-DecisionJsonValue $j 'statusline_state')")
    }
    if ($overall -eq 'CRITICAL') {
        return (New-DecisionRung 'UNKNOWN' "$($rung.Reason); but usage.ps1 reads CRITICAL overall, which skips its statusLine trust check, so this reading may be another root's")
    }
    return $rung
}
