# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Measure whether the NSSM service account and the provisioning operator can both open one
    SQLite store, in a given order. CI measurement for ADR 0183 Amendment A, Wave 0 (BACKLOG #1136).

.DESCRIPTION
    ADR 0163 consequences 1 and 2 read MessageStore.open as re-securing the SQLite trio (the .db
    and its -wal/-shm sidecars) to the CURRENT user alone on every open, with inheritance removed.
    If that reading holds, whichever identity opens a fresh store first becomes its only principal,
    and the other identity is locked out. The bootstrap account hides this today, because the
    service creates its own account inside its own process. ADR 0183 Amendment A retires that
    account, which makes `provision-admin` the only way in, so Wave 0 measures FILE ACCESS in both
    orders before anything is deleted. This script is that measurement. It fixes nothing.

    -Order ProvisionFirst
        1. The operator (the identity running this script) provisions a fresh store through
           `messagefoundry provision-admin --email`, via _provision_admin's own open path. The
           ONLY patch is the password reader: a hosted runner has no terminal.
        2. The NSSM service starts under the default virtual account, NT SERVICE\<ServiceName>.
        3. The operator signs in over https as the provisioned administrator and gets a session.

    -Order StartFirst
        1. The service starts on a fresh store. It creates the store and is REFUSED by the ADR 0167
           gate: before Wave 2 because the bootstrap account it minted had no notification address,
           and since Wave 2 because no Administrator exists at all. The gate runs after the store is
           opened and its user table read, so the refusal text in the service log is the proof that
           the service opened it. Either refusal counts here; this arm measures file access.
        2. The operator opens that store through the same CLI path. Before Wave 2 `provision-admin`
           declined, because the bootstrap account was an enabled Administrator; since Wave 2 it
           provisions. Either outcome is reached only after the store opened, so it is the proof
           that the operator opened it.
        3. The service is started again and must reach the same refusal, which proves it can still
           open the store that the operator's open re-secured. If step 2 instead PROVISIONED (no
           bootstrap account existed), the gate would pass, so the proof is /health and sign-in. If
           step 2 FAILED, the service is restarted anyway as a control: reopening the store it
           created itself tells "restricted to the service" apart from "restricted to nobody usable".

    -Order StartFirstEndToEnd (ADR 0183 Amendment A, Wave 2: AC-11 and AC-13 across two identities)
        The start-first flow an operator now meets, with no outcome left open.
        1. The service starts on a fresh store and MUST be refused for want of an Administrator,
           and the refusal MUST name `provision-admin`. A refusal for a missing address instead means
           the start created an account nobody named, which is the retired default coming back.
           The data directory must hold no bootstrap-admin.txt.
        2. The operator runs `provision-admin --email` against that store and MUST succeed. A
           decline there means an enabled Administrator was already in a store no operator had
           provisioned, which is the same regression seen from the other side.
        3. The service is started again and must serve, and the operator must sign in as the
           administrator just provisioned.

    THE SERVICE IDENTITY IS CHECKED, NOT ASSUMED. The SCM's configured run-as account must be
    NT SERVICE\<ServiceName>, and every process sampled under the service must run as it. Where the
    engine is up (provision first), the sample must include the engine process itself.

    WHAT A RED MEANS. Every red names the identity that could not open the store, and lists for each
    file of the trio the entries it carries and whether any grants that identity read and write. That
    list is a READING of the DACL, not an access check: it names the file, and the behaviour above
    says the open failed. A red is tagged [STORE ACCESS] only when the service log or the probe
    output shows an open failure; otherwise it is tagged [NOT SHOWN TO BE STORE ACCESS], because a
    refused start gate or a held port also stops the engine from serving.

    CONFINEMENT IS CHECKED AFTER EVERY OPEN. Opening is half of the question; the other half is the
    property ADR 0163's restriction exists for. After each identity's open, every trio file may grant
    only SYSTEM, BUILTIN\Administrators, the service account and the operator, block inheritance, and
    be owned by one of them, or the arm goes RED.
    A GREEN CAN BE CONDITIONAL, and says so: store.py only logs when it cannot restrict a file, so a
    restriction warning in the service log or the CLI output prints GREEN (CONDITIONAL) with a warning.

    The start gates are satisfied with synthetic values: a store key minted by `gen-key`, an SMTP
    relay on loopback that nothing listens on (the start gates read configuration only; nothing
    connects at start), bounded retention, and deny-by-default egress. Sign-in stays REQUIRED.

    Run elevated on a disposable Windows host, as the windows-service-smoke CI job does. It
    installs and uninstalls the service and creates -DataDir from scratch.

.PARAMETER Order
    ProvisionFirst, StartFirst or StartFirstEndToEnd.

.PARAMETER DataDir
    A data directory this script owns for the run. It is DELETED first if it exists.

.EXAMPLE
    .\measure-store-access.ps1 -Order ProvisionFirst -DataDir C:\ProgramData\MessageFoundry-w0-provision-first
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet("ProvisionFirst", "StartFirst", "StartFirstEndToEnd")][string]$Order,
    [Parameter(Mandatory)][string]$DataDir,
    [string]$ServiceName = "MessageFoundry",
    [string]$AppExe,
    [int]$Port = 8765,
    [int]$MllpPort = 2699,
    [int]$WaitSeconds = 120
)

$ErrorActionPreference = "Stop"
# Absolute before anything consumes it: install-service.ps1 resolves a relative -DataDir against
# $PWD, while the operator's CLI runs from the repository root, so a relative path here would put
# the two identities on two different stores.
$DataDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DataDir)
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ServiceIdentity = "NT SERVICE\$ServiceName"
$Operator = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$DbPath = Join-Path $DataDir "messagefoundry.db"
$LogDir = Join-Path $DataDir "logs"
$CertPath = Join-Path $DataDir "api-generated-cert.pem"
$Username = "w0admin"
$Email = "w0-admin@example.invalid"
# The ADR 0167 gate's own words (messagefoundry/api/app.py, _assert_security_notice_is_deliverable),
# and the words provision_first_administrator declines with (messagefoundry/auth/service.py). If
# either is reworded, the arm goes RED on a missing proof rather than passing on a stale one.
# $GateRefusal is the clause BOTH of the gate's branches open with, so the file-access arms prove the
# service read the user table whichever branch fired. $NoAdminRefusal and $ProvisionHint are the
# no-Administrator branch alone, which StartFirstEndToEnd requires (ADR 0183 Wave 2, AC-11).
$GateRefusal = "no enabled Administrator"
$NoAdminRefusal = "no enabled Administrator exists"
$ProvisionHint = "provision-admin --username"
# The words that make it a REFUSAL. The skipped-gate WARNING and the warn-mode line carry the two
# phrases above too, so without this an engine that started and served would pass step 1.
$StartRefused = "refusing to start"
$ProvisionDecline = "already has an enabled Administrator"
$OpenErrorPattern = "unable to open database file|Access is denied|PermissionError|OperationalError"
# store.py logs these and carries on; each means that open did not restrict the trio as it tried to
# (a DACL it could not read falls back to the owner-only rewrite, which is the Wave 0 lockout).
$RestrictFailPattern = "could not restrict|could not determine current user|could not read the DACL|could not render the DACL|restricted owner-only"
$EngineImages = @("python.exe", "pythonw.exe", "messagefoundry.exe")

$Failures = New-Object System.Collections.ArrayList
$Readings = New-Object System.Collections.ArrayList
$Conditions = New-Object System.Collections.ArrayList
$OwnersSeen = @{}
# The engine processes whose run-as account was READ in the current serving phase. Reset per phase,
# so an earlier phase's sample cannot vouch for a later engine.
$PhaseEngineOwners = New-Object System.Collections.ArrayList
$CurrentPhase = "setup"

function Format-Annotation([string]$Text) {
    # GitHub workflow-command data must escape these three, or a multi-line message is cut at the
    # first newline and the rest prints as ordinary log lines nobody reads as part of the annotation.
    return $Text.Replace("%", "%25").Replace("`r", "%0D").Replace("`n", "%0A")
}

function Add-Failure([string]$Message) {
    [void]$Failures.Add($Message)
    Write-Host "::error title=ADR 0183 Wave 0 ($Order)::$(Format-Annotation $Message)"
}

function Add-Reading([string]$Message) {
    [void]$Readings.Add($Message)
    Write-Host "READING: $Message"
}

function Add-Condition([string]$Message) {
    [void]$Conditions.Add($Message)
    Write-Host "CONDITION: $Message"
}

function Get-Excerpt([string]$Text, [int]$Max = 400) {
    $flat = ($Text -replace "\s+", " ").Trim()
    if ($flat.Length -gt $Max) { return $flat.Substring(0, $Max) + " ..." }
    return $flat
}

function New-SyntheticPassword {
    # Synthetic and per run: never a literal in the repository, never printed, never on argv.
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return (([Convert]::ToBase64String($bytes)) -replace "[^A-Za-z0-9]", "").Substring(0, 32)
}

function Get-Sid([string]$Account) {
    try {
        return ([Security.Principal.NTAccount]$Account).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Get-ServiceSids {
    # The virtual account plus groups a service token carries that could appear on a DACL: Everyone,
    # Authenticated Users, SERVICE, Users, LOCAL and NT SERVICE\ALL SERVICES.
    $sids = @("S-1-1-0", "S-1-5-11", "S-1-5-6", "S-1-5-32-545", "S-1-2-0", "S-1-5-80-0")
    $own = Get-Sid $ServiceIdentity
    if ($own) { $sids += $own }
    return $sids
}

function Get-OperatorSids {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sids = @($id.User.Value)
    foreach ($g in $id.Groups) { $sids += $g.Value }
    return $sids
}

function Get-DataBits([int]$Rights) {
    <#
      Reduce an ACE's access mask to the two bits an open for writing needs: 1 = ReadData, 2 = WriteData.
      Generic rights are mapped, because a raw mask carrying GENERIC_ALL (0x10000000), GENERIC_READ
      (0x80000000) or GENERIC_WRITE (0x40000000) sets neither bit yet grants both.
    #>
    $v = [long]$Rights
    if ($v -lt 0) { $v += 4294967296 }
    $bits = $v -band 3
    if ($v -band 268435456) { $bits = $bits -bor 3 }
    if ($v -band 2147483648) { $bits = $bits -bor 1 }
    if ($v -band 1073741824) { $bits = $bits -bor 2 }
    return [int]$bits
}

function Get-TrioReport {
    <#
      For each file of the trio: absent, or its owner, whether inheritance is removed (protected),
      its entries, and whether the entries naming $Identity (through $IdentitySids) allow both read
      and write data without a matching deny. A DACL the caller cannot read is reported as such,
      because an identity refused READ_CONTROL on the file is itself the finding.
    #>
    param([string]$Identity, [string[]]$IdentitySids)
    $need = 3
    $lines = @()
    $missing = @()
    foreach ($suffix in "", "-wal", "-shm") {
        $f = "$DbPath$suffix"
        $name = Split-Path -Leaf $f
        if (-not (Test-Path -LiteralPath $f)) { $lines += "$name absent"; continue }
        try {
            $acl = Get-Acl -LiteralPath $f
        } catch {
            $lines += "$name DACL unreadable by $Operator ($($_.Exception.Message))"
            $missing += $name
            continue
        }
        $aces = @()
        $allowed = 0
        $denied = 0
        foreach ($rule in $acl.Access) {
            $sid = "$($rule.IdentityReference)"
            try {
                $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            } catch { }
            $kind = if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) { "DENY " } else { "" }
            $aces += "$kind$($rule.IdentityReference):$($rule.FileSystemRights)"
            if ($IdentitySids -notcontains $sid) { continue }
            $bits = Get-DataBits ([int]$rule.FileSystemRights)
            if ($kind) { $denied = $denied -bor $bits } else { $allowed = $allowed -bor $bits }
        }
        $grantsRw = (($allowed -band $need) -eq $need) -and (($denied -band $need) -eq 0)
        $verdict = if ($grantsRw) { "grants $Identity read+write" }
                   elseif ($allowed -ne 0) { "names $Identity WITHOUT read+write" }
                   else { "NO entry for $Identity" }
        $lines += ("$name owner=$($acl.Owner) protected=$($acl.AreAccessRulesProtected) " +
            "aces=[$($aces -join '; ')] $verdict")
        if (-not $grantsRw) { $missing += $name }
    }
    return New-Object PSObject -Property @{ Text = ($lines -join " | "); Missing = $missing }
}

function Get-LogMatches {
    <#
      Lines matching $Pattern in the service logs. Top level only by default: earlier phases are moved
      into subdirectories, so a match there belongs to this phase. Read through Get-Content, which
      opens with read-write sharing, because NSSM may still hold the file open for writing; a reader
      that hit a sharing violation here would return nothing and turn a success into a timeout.
    #>
    param([string]$Pattern)
    if (-not (Test-Path -LiteralPath $LogDir)) { return @() }
    $files = @(Get-ChildItem -LiteralPath $LogDir -File -Filter "*.log")
    $found = @()
    foreach ($f in $files) {
        $lines = @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
        if ($lines.Count -gt 0) { $found += @($lines | Select-String -Pattern $Pattern) }
    }
    return $found
}

function Get-Attribution {
    <#
      One sentence for a red: which trio files carry no read+write grant for $Identity, whether the
      log shows an open failure, and the trio itself. Stated as readings so a red caused by something
      other than file access (a start gate, a port) is not dressed up as one.
    #>
    param([string]$Identity, [string[]]$IdentitySids, [string]$Output)
    $trio = Get-TrioReport -Identity $Identity -IdentitySids $IdentitySids
    $files = if ($trio.Missing.Count -gt 0) { "Trio file(s) granting $Identity no read+write: $($trio.Missing -join ', ')." }
             else { "Every present trio file grants $Identity read+write, so the cause is probably NOT file access; read the output below." }
    $hits = @(Get-LogMatches $OpenErrorPattern | Select-Object -First 3 | ForEach-Object { Get-Excerpt $_.Line 240 })
    if ($Output -and $Output -match $OpenErrorPattern) { $hits += "probe output: " + (Get-Excerpt $Output 240) }
    # The KIND leads the message, so a red that is not shown to be file access cannot be read as the
    # lockout Wave 0 is looking for: a refused start gate or a held port also fails to serve.
    $kind = if ($hits.Count -gt 0) { "[STORE ACCESS]" } else { "[NOT SHOWN TO BE STORE ACCESS]" }
    $log = if ($hits.Count -gt 0) { "Open-failure evidence: $($hits -join ' || ')." }
           else { "No open-failure line was found in the service log or the probe output." }
    $out = if ($Output) { " Output: $(Get-Excerpt $Output)." } else { "" }
    return "$kind $files $log Trio: $($trio.Text).$out"
}

function Show-Trio([string]$Label) {
    Write-Host "===== trio DACL after: $Label ====="
    foreach ($suffix in "", "-wal", "-shm") {
        $f = "$DbPath$suffix"
        if (Test-Path -LiteralPath $f) { & icacls $f | Out-Host } else { Write-Host "$f (absent)" }
    }
}

function Test-Resecured {
    <#
      After an identity's open, is the store still CONFINED -- the property ADR 0163's restriction
      exists for? Every present trio file must block inheritance, be OWNED by, and grant only, SYSTEM,
      BUILTIN\Administrators, the service account or the operator. Anything else is a RED: an
      outside entry makes the store readable by that principal; an outside owner keeps WRITE_DAC and
      can grant itself access; an inheriting file takes whatever the directory is later given.

      This replaced a check on the MECHANISM ("the .db still inherits", "the DACL did not change"),
      which encoded the pre-0b rewrite-to-the-opener design and would have flagged Wave 0b's
      same-DACL-for-every-opener as a failure. Note what it cannot see: SQLite deletes -wal and -shm
      on a clean close, and this runs after the service stops, so it measures the .db. A restriction
      warning is still a CONDITION: the open did not do what it tried to.
      -FromServiceLog reads the service's current logs for that warning, and is passed only for the
      service's own opens, so an earlier service warning is never charged to the operator.
    #>
    param([string]$Identity, [string]$Output, [switch]$FromServiceLog)
    $allowed = @("S-1-5-18", "S-1-5-32-544") + @(Get-Sid $ServiceIdentity) + @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    foreach ($suffix in "", "-wal", "-shm") {
        $f = "$DbPath$suffix"
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try { $acl = Get-Acl -LiteralPath $f } catch {
            Add-Condition "after $Identity's open, $Operator could not read the DACL of $(Split-Path -Leaf $f), so its confinement is unmeasured"
            continue
        }
        $leaf = Split-Path -Leaf $f
        if (-not $acl.AreAccessRulesProtected) {
            Add-Failure ("after $Identity's open, $leaf still inherits its directory's entries, so a later " +
                "change to the directory would reach the store")
        }
        $ownerSid = "$($acl.Owner)"
        try {
            $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
        } catch { }
        if ($allowed -notcontains $ownerSid) {
            Add-Failure ("after $Identity's open, $leaf is owned by $($acl.Owner), outside SYSTEM, " +
                "Administrators, $ServiceIdentity and $Operator; an owner keeps WRITE_DAC over it")
        }
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = "$($rule.IdentityReference)"
            try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
            if ($allowed -notcontains $sid) {
                Add-Failure ("after $Identity's open, $(Split-Path -Leaf $f) grants $($rule.IdentityReference) " +
                    "($($rule.FileSystemRights)), a principal outside SYSTEM, Administrators, " +
                    "$ServiceIdentity and $Operator, so the store is no longer confined")
            }
        }
    }
    $notes = @()
    if ($FromServiceLog) {
        foreach ($m in (Get-LogMatches -Pattern $RestrictFailPattern | Select-Object -First 2)) {
            $notes += "service log: $(Get-Excerpt $m.Line 200)"
        }
    }
    if ($Output -and $Output -match $RestrictFailPattern) { $notes += "CLI: $(Get-Excerpt $Output 200)" }
    if ($notes.Count -gt 0) {
        Add-Condition "$Identity's open reported a failed restriction: $($notes -join '; ')"
    }
}

function Show-LogTail {
    if (-not (Test-Path -LiteralPath $LogDir)) { Write-Host "(no log directory)"; return }
    foreach ($f in (Get-ChildItem -LiteralPath $LogDir -File -Filter "*.log")) {
        Write-Host "===== $($f.Name) (tail) ====="
        Get-Content -LiteralPath $f.FullName -Tail 40 | Out-Host
    }
}

function Move-PhaseLogs([string]$Phase) {
    if (-not (Test-Path -LiteralPath $LogDir)) { return }
    $dest = Join-Path $LogDir $Phase
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Get-ChildItem -LiteralPath $LogDir -File | Move-Item -Destination $dest -Force
}

function Get-ServiceProcess {
    <#
      Every process under the service's root process, as {Name, Account}. A child must be at least as
      new as its parent: a process whose parent id was merely REUSED by the root is not under it.
    #>
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $svc -or [int]$svc.ProcessId -eq 0) { return @() }
    $all = @(Get-CimInstance Win32_Process)
    $root = $all | Where-Object { [int]$_.ProcessId -eq [int]$svc.ProcessId } | Select-Object -First 1
    if (-not $root) { return @() }
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($root)
    $seen = @{}
    $result = @()
    while ($queue.Count -gt 0) {
        $proc = $queue.Dequeue()
        if ($seen.ContainsKey([int]$proc.ProcessId)) { continue }
        $seen[[int]$proc.ProcessId] = $true
        $account = "unreadable"
        try {
            $o = Invoke-CimMethod -InputObject $proc -MethodName GetOwner
            if ($o.ReturnValue -eq 0) { $account = "$($o.Domain)\$($o.User)" }
        } catch { }
        $result += New-Object PSObject -Property @{ Name = "$($proc.Name)"; Account = $account }
        foreach ($child in ($all | Where-Object {
                    [int]$_.ParentProcessId -eq [int]$proc.ProcessId -and $_.CreationDate -ge $proc.CreationDate })) {
            $queue.Enqueue($child)
        }
    }
    return $result
}

function Update-OwnerSample([string]$When) {
    # Record every sampled process's account. Any account other than the virtual account is a red:
    # the arm would then not be measuring the default virtual account at all.
    foreach ($p in @(Get-ServiceProcess)) {
        if ($p.Account -ne "unreadable" -and $EngineImages -contains $p.Name.ToLowerInvariant()) {
            [void]$PhaseEngineOwners.Add($p.Account)
        }
        $key = "$($p.Name)=$($p.Account)"
        if ($OwnersSeen.ContainsKey($key)) { continue }
        $OwnersSeen[$key] = $true
        Add-Reading "service process $key ($When)"
        if ($p.Account -eq "unreadable") { continue }
        if ($p.Account -ne $ServiceIdentity) {
            Add-Failure ("a process under service '$ServiceName' ($($p.Name)) runs as '$($p.Account)', " +
                "not $ServiceIdentity ($When), so this arm is not measuring the default virtual account")
        }
    }
}

function Test-EngineSampled {
    # True only when an engine process's owner was READ in the current phase. An unreadable owner, or
    # one sampled in an earlier phase, does not verify the engine that is serving now.
    return ($PhaseEngineOwners.Count -gt 0)
}

function Stop-ServiceProcessTree {
    # Bounded fallback for a service that will not stop: end the service process and every engine
    # process naming this store. Stop-Service is not used here because under Windows PowerShell 5.1
    # it waits on a STOP_PENDING service with no time limit.
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($svc -and [int]$svc.ProcessId -ne 0) {
        Stop-Process -Id ([int]$svc.ProcessId) -Force -ErrorAction SilentlyContinue
    }
    foreach ($p in (Get-CimInstance Win32_Process | Where-Object {
                $_.CommandLine -and $_.CommandLine.IndexOf($DbPath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $EngineImages -contains $_.Name.ToLowerInvariant() })) {
        Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction SilentlyContinue
    }
}

function Stop-TheService {
    <#
      Stop the service and CONFIRM it: the SCM reports Stopped, and no process still names this store
      on its command line (the SCM reports process id 0 once stopped, so it cannot name an orphaned
      engine child). Throws when either fails, because every later phase would race a live engine
      that re-secures the trio each time NSSM restarts it.
    #>
    $global:LASTEXITCODE = $null
    & $Nssm stop $ServiceName | Out-Host
    $deadline = (Get-Date).AddSeconds(60)
    while ($true) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq "Stopped") { break }
        if ((Get-Date) -ge $deadline) {
            Stop-ServiceProcessTree
            $grace = (Get-Date).AddSeconds(15)
            while ((Get-Date) -lt $grace) {
                $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if (-not $svc -or $svc.Status -eq "Stopped") { break }
                Start-Sleep -Milliseconds 500
            }
            if ($svc -and $svc.Status -ne "Stopped") {
                throw "service '$ServiceName' is still '$($svc.Status)' after the stop and a forced end of its processes"
            }
            break
        }
        Start-Sleep -Milliseconds 500
    }
    $deadline = (Get-Date).AddSeconds(30)
    while ($true) {
        $alive = @(Get-CimInstance Win32_Process | Where-Object {
            $_.CommandLine -and $_.CommandLine.IndexOf($DbPath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $EngineImages -contains $_.Name.ToLowerInvariant() })
        if ($alive.Count -eq 0) { return }
        if ((Get-Date) -ge $deadline) {
            throw ("an engine process (pid $($alive[0].ProcessId)) still names $DbPath 30 s after the " +
                "service stopped; the next open would race it")
        }
        Start-Sleep -Milliseconds 500
    }
}

function Invoke-OperatorCli {
    <#
      Run the Python probe as THIS identity. Start-Process with redirected files, because a native
      stderr merge under Windows PowerShell 5.1 and ErrorActionPreference=Stop aborts the script.
      Secrets reach the child through its inherited environment, never argv, and are cleared after.
    #>
    param([string[]]$Arguments, [hashtable]$Secrets)
    $out = Join-Path $Work "cli.out.txt"
    $err = Join-Path $Work "cli.err.txt"
    foreach ($k in $Secrets.Keys) { Set-Item -Path "Env:$k" -Value $Secrets[$k] }
    try {
        $quoted = @("`"$Probe`"") + ($Arguments | ForEach-Object { "`"$_`"" })
        $p = Start-Process -FilePath $Python -ArgumentList ($quoted -join " ") -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -Wait -PassThru
        $code = $p.ExitCode
    } finally {
        foreach ($k in $Secrets.Keys) { Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue }
    }
    $text = ((Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) + "`n" +
        (Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue)).Trim()
    Write-Host "----- operator CLI ($($Arguments[0])) exit=$code -----"
    Write-Host $text
    return New-Object PSObject -Property @{ Code = $code; Text = $text }
}

function Start-TheService([string]$Phase) {
    <#
      Start the service for a named phase. Moves the previous phase's logs aside first, so a log line
      found later belongs to this phase, and resets the per-phase engine sample. A non-zero `nssm
      start` is recorded, not failed: an engine that dies early on an unreadable store can make NSSM
      report the start as failed, and that is the very case the phase's own proof must attribute.
    #>
    $script:CurrentPhase = "service $Phase"
    $PhaseEngineOwners.Clear()
    Move-PhaseLogs ("before-" + ($Phase -replace "[^A-Za-z0-9]+", "-"))
    $global:LASTEXITCODE = $null
    & $Nssm start $ServiceName | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Add-Reading "nssm start for $Phase exited '$LASTEXITCODE'; the phase's own proof decides the verdict"
    }
}

function Wait-ForGateRefusal([string]$Phase) {
    <#
      Wait until the service logs the ADR 0167 refusal, which it reaches only after opening the store
      and reading its users. Samples process owners throughout, since NSSM restarts the refused engine
      and each restart is a new process. Returns $true on the refusal, $false on timeout.
    #>
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        Update-OwnerSample "during $Phase"
        if ((Get-LogMatches ([regex]::Escape($GateRefusal))).Count -gt 0) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Test-ServiceServes([string]$Phase, [string]$StoreOrigin) {
    <#
      The engine is up on this store and a session can be had: /health over https pinned to the
      engine's own certificate, then sign-in as the provisioned administrator. The engine process
      itself must be among the sampled processes, so the identity check cannot pass on nssm.exe alone.
    #>
    $h = Invoke-OperatorCli -Arguments @("health", $BaseUrl, $CertPath, "$WaitSeconds") -Secrets @{}
    for ($i = 0; $i -lt 3; $i++) { Update-OwnerSample "during $Phase"; Start-Sleep -Seconds 1 }
    if ($h.Code -ne 0) {
        Add-Failure ("$ServiceIdentity did not answer /health within $WaitSeconds s on $DbPath, which " +
            "$StoreOrigin ($Phase). " + (Get-Attribution $ServiceIdentity (Get-ServiceSids) $h.Text))
        Show-LogTail
        return
    }
    if (-not (Test-EngineSampled)) {
        Add-Failure ("the engine answered /health but no engine process ($($EngineImages -join ', ')) " +
            "was found under service '$ServiceName' ($Phase), so its run-as account is unverified")
    }
    $l = Invoke-OperatorCli -Arguments @("login", $BaseUrl, $CertPath, $Username) `
        -Secrets @{ MEFOR_W0_ADMIN_PASSWORD = $Password }
    if ($l.Code -ne 0) {
        Add-Failure ("$ServiceIdentity served /health on $DbPath ($Phase), but signing in as " +
            "'$Username' did not yield a session. Output: $(Get-Excerpt $l.Text)")
        return
    }
    Add-Reading "$ServiceIdentity opened $DbPath, which $StoreOrigin, and sign-in as '$Username' yielded a session ($Phase)"
}

# --- setup ------------------------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "measure-store-access.ps1 installs a service and must run elevated."
}
if (-not $AppExe) { $AppExe = (Get-Command messagefoundry).Source }
$Python = (Get-Command python).Source
$Nssm = (Get-Command nssm).Source
$TempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$Work = Join-Path $TempRoot "w0-store-access-$Order"
$ConfigDir = Join-Path $TempRoot "w0-store-access-config"
$Probe = Join-Path $Work "probe.py"

if (Test-Path -LiteralPath $DataDir) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Work | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

# The smallest graph `serve` accepts: one loopback MLLP inbound whose router selects nothing. The
# measurement is store access, so no connector the store question does not need is wired.
$ConfigModule = @'
from messagefoundry import MLLP, inbound, router

inbound("IB_W0_STORE_ACCESS", MLLP(port=__MLLP_PORT__), router="w0_store_access_router")


@router("w0_store_access_router")
def route(msg):
    return []
'@
Set-Content -LiteralPath (Join-Path $ConfigDir "IB_W0_STORE_ACCESS.py") -Encoding Ascii `
    -Value ($ConfigModule -replace "__MLLP_PORT__", "$MllpPort")

# The probe. `provision` replaces ONLY _read_new_password, then runs the real CLI entry point, so
# settings, the at-rest gate, open_store(create=True) and provision_first_administrator are the
# shipped code path. `health` and `login` speak https pinned to the engine's own minted certificate.
$ProbeSource = @'
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request


def _provision(argv):
    import messagefoundry.__main__ as cli

    password = os.environ.pop("MEFOR_W0_ADMIN_PASSWORD")

    def _read_new_password(prompt):
        return password

    cli._read_new_password = _read_new_password
    return cli.main(["provision-admin", *argv])


def _call(method, url, cafile, body=None, token=None):
    ctx = ssl.create_default_context(cafile=cafile)
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _health(base, cafile, seconds):
    # Retries inside one process until the deadline; the certificate is minted during startup, so
    # early misses are ordinary. Prints the last outcome only.
    deadline = time.monotonic() + float(seconds)
    last = "never tried"
    while time.monotonic() < deadline:
        try:
            status, _ = _call("GET", base + "/health", cafile)
        except (OSError, ssl.SSLError) as exc:
            last = f"unreachable: {exc}"
        else:
            if status == 200:
                print("health status=200")
                return 0
            last = f"status={status}"
        time.sleep(2)
    print(f"health never answered 200 in {seconds} s; last: {last}")
    return 1


def _login(base, cafile, username):
    password = os.environ.pop("MEFOR_W0_ADMIN_PASSWORD")
    status, text = _call(
        "POST", base + "/auth/login", cafile, {"username": username, "password": password}
    )
    print(f"login status={status}")
    if status != 200:
        print(f"login body={text[:300]}")
        return 1
    token = json.loads(text).get("token") or ""
    if not token:
        print("login answered 200 with no session token")
        return 1
    status, text = _call("GET", base + "/auth/me", cafile, token=token)
    print(f"me status={status}")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "provision":
        sys.exit(_provision(sys.argv[2:]))
    if mode == "health":
        sys.exit(_health(sys.argv[2], sys.argv[3], sys.argv[4]))
    if mode == "login":
        sys.exit(_login(sys.argv[2], sys.argv[3], sys.argv[4]))
    sys.exit("unknown mode " + mode)
'@
Set-Content -LiteralPath $Probe -Value $ProbeSource -Encoding Ascii

$StoreKey = (& $AppExe gen-key).Trim()
if (-not $StoreKey) { throw "messagefoundry gen-key produced no store key" }
$Password = New-SyntheticPassword
if ($env:GITHUB_ACTIONS -eq "true") {
    # Both are synthetic and per run. Masked anyway, so no later echo can print either in clear.
    Write-Host "::add-mask::$StoreKey"
    Write-Host "::add-mask::$Password"
}
$BaseUrl = "https://127.0.0.1:$Port"

Write-Host "===== ADR 0183 Wave 0: $Order, operator=$Operator, service=$ServiceIdentity ====="
Write-Host "store: $DbPath"

try {
    # --- install under the DEFAULT virtual account (no -ServiceAccount, no -AllowLocalSystem) ------
    & (Join-Path $PSScriptRoot "install-service.ps1") -ServiceName $ServiceName -AppExe $AppExe `
        -Config $ConfigDir -DataDir $DataDir -Port $Port -LogLevel INFO -Environment prod -LockConfigDir
    $startName = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").StartName
    Add-Reading "SCM run-as account for '$ServiceName' is '$startName'"
    # The engine's store rule reads the data directory's OWNER as well as its DACL, so record it.
    Add-Reading "data directory owner is '$((Get-Acl -LiteralPath $DataDir).Owner)'"
    if ($startName -ne $ServiceIdentity) {
        throw ("the service is configured to run as '$startName', not $ServiceIdentity; this arm " +
            "would not measure the default virtual account, so it measures nothing")
    }
    # The key reaches the service the way the auth-off smoke above passes its own: NSSM's
    # AppEnvironmentExtra, which docs/SERVICE.md documents. It is synthetic, per run, and masked.
    $global:LASTEXITCODE = $null
    & $Nssm set $ServiceName AppEnvironmentExtra `
        "MEFOR_STORE_ENCRYPTION_KEY=$StoreKey" `
        "MEFOR_ALERTS_EMAIL_SMTP_HOST=127.0.0.1" `
        "MEFOR_ALERTS_EMAIL_SMTP_PORT=2525" `
        "MEFOR_ALERTS_EMAIL_FROM=mefor-w0@example.invalid" `
        "MEFOR_ALERTS_EMAIL_TO=mefor-w0@example.invalid" `
        "MEFOR_SECURITY_DELETE_MESSAGE_BODIES_AFTER_DAYS=30" `
        "MEFOR_RETENTION_DEAD_LETTER_DAYS=30" `
        "MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND=true" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "nssm set AppEnvironmentExtra failed (exit $LASTEXITCODE)" }

    $provisionArgs = @("provision", "--username", $Username, "--email", $Email, "--db", $DbPath, "--json")
    $cliSecrets = @{ MEFOR_STORE_ENCRYPTION_KEY = $StoreKey; MEFOR_W0_ADMIN_PASSWORD = $Password }

    if ($Order -eq "ProvisionFirst") {
        # 1. The operator provisions the fresh store.
        $CurrentPhase = "operator provision"
        $r = Invoke-OperatorCli -Arguments $provisionArgs -Secrets $cliSecrets
        Show-Trio "operator provisioned"
        if ($r.Code -ne 0) {
            Add-Failure ("$Operator could not provision the fresh store $DbPath through provision-admin " +
                "(exit $($r.Code)). " + (Get-Attribution $Operator (Get-OperatorSids) $r.Text))
        } else {
            Test-Resecured -Identity $Operator -Output $r.Text
            # 2 and 3. The service starts on the store the operator created and secured, and serves.
            Start-TheService "start"
            $failed = $Failures.Count
            Test-ServiceServes "the start" "$Operator provisioned"
            Stop-TheService
            Show-Trio "service started"
            if ($Failures.Count -eq $failed) {
                Test-Resecured -Identity $ServiceIdentity -FromServiceLog
            }
        }
    } elseif ($Order -eq "StartFirstEndToEnd") {
        # 1. The service starts first on a fresh store. No account exists, so the ADR 0167 gate must
        #    refuse for want of an Administrator, and name provision-admin.
        Start-TheService "first start"
        $opened = Wait-ForGateRefusal "the first start"
        Stop-TheService
        Show-Trio "service first start"
        $credentialFile = Join-Path $DataDir "bootstrap-admin.txt"
        if (Test-Path -LiteralPath $credentialFile) {
            Add-Failure ("$ServiceIdentity wrote $credentialFile on its first start; since ADR 0183 " +
                "Wave 2 no path writes a bootstrap credential file (AC-13)")
        }
        $noAdmin = @(Get-LogMatches ([regex]::Escape($NoAdminRefusal)) |
            Where-Object { $_.Line -match [regex]::Escape($StartRefused) })
        if (-not $opened) {
            $what = if (Test-Path -LiteralPath $DbPath) { "created $DbPath but never reached the account gate, so its open is unproven" }
                    else { "never created $DbPath" }
            Add-Failure ("$ServiceIdentity $what within $WaitSeconds s on a fresh store. " +
                (Get-Attribution $ServiceIdentity (Get-ServiceSids) ""))
            Show-LogTail
        } elseif ($noAdmin.Count -eq 0) {
            $line = @(Get-LogMatches ([regex]::Escape($GateRefusal)) | Select-Object -First 1 |
                ForEach-Object { Get-Excerpt $_.Line 300 })
            Add-Failure ("$ServiceIdentity reached the ADR 0167 gate on a fresh store, but no line said " +
                "both '$StartRefused' and '$NoAdminRefusal'. Either the start was not refused, or it " +
                "was refused for a missing address, which means the first start created an account no " +
                "operator named. Gate line: $($line -join ' ')")
            Show-LogTail
        } elseif (@($noAdmin | Where-Object { $_.Line -match [regex]::Escape($ProvisionHint) }).Count -eq 0) {
            Add-Failure ("$ServiceIdentity was refused for want of an Administrator, but the refusal " +
                "does not name '$ProvisionHint', so it does not lead to the fix (AC-11). Gate line: " +
                "$(Get-Excerpt $noAdmin[0].Line 300)")
            Show-LogTail
        } else {
            Add-Reading "$ServiceIdentity created and opened $DbPath, then the ADR 0167 gate refused it for want of an Administrator and named provision-admin (expected)"
            Test-Resecured -Identity $ServiceIdentity -FromServiceLog
            # 2. The operator provisions the store the service created and was refused on.
            $CurrentPhase = "operator provision"
            $r = Invoke-OperatorCli -Arguments $provisionArgs -Secrets $cliSecrets
            Show-Trio "operator provisioned"
            if ($r.Code -ne 0) {
                $why = if ($r.Text -match [regex]::Escape($ProvisionDecline)) {
                    "provision-admin found an enabled Administrator already in a store no operator had provisioned, so a start created one. "
                } else { "" }
                Add-Failure ("$Operator could not provision $DbPath, which $ServiceIdentity created and " +
                    "was refused on (exit $($r.Code)). " + $why +
                    (Get-Attribution $Operator (Get-OperatorSids) $r.Text))
            } else {
                Add-Reading "$Operator provisioned '$Username' into $DbPath after the refused start"
                Test-Resecured -Identity $Operator -Output $r.Text
                # 3. The service starts again on the store the operator provisioned, and serves.
                Start-TheService "restart"
                $failed = $Failures.Count
                Test-ServiceServes "the restart" "$ServiceIdentity created and $Operator provisioned"
                Stop-TheService
                Show-Trio "service restart"
                if ($Failures.Count -eq $failed) {
                    Test-Resecured -Identity $ServiceIdentity -FromServiceLog
                }
            }
        }
    } else {
        # 1. The service starts first on a fresh store and is refused by the ADR 0167 gate.
        Start-TheService "first start"
        $opened = Wait-ForGateRefusal "the first start"
        Stop-TheService
        Show-Trio "service first start"
        if (-not $opened) {
            $what = if (Test-Path -LiteralPath $DbPath) { "created $DbPath but never reached the account gate, so its open is unproven" }
                    else { "never created $DbPath" }
            Add-Failure ("$ServiceIdentity $what within $WaitSeconds s on a fresh store. " +
                (Get-Attribution $ServiceIdentity (Get-ServiceSids) ""))
            Show-LogTail
        } else {
            Add-Reading "$ServiceIdentity created and opened $DbPath, then the ADR 0167 gate refused it (expected)"
            Test-Resecured -Identity $ServiceIdentity -FromServiceLog
            # 2. The operator opens that store through the CLI's path.
            $CurrentPhase = "operator open"
            $r = Invoke-OperatorCli -Arguments $provisionArgs -Secrets $cliSecrets
            Show-Trio "operator open"
            $provisioned = ($r.Code -eq 0)
            $declined = ($r.Text -match [regex]::Escape($ProvisionDecline))
            if (-not ($provisioned -or $declined)) {
                Add-Failure ("$Operator could not open $DbPath, which $ServiceIdentity created and " +
                    "secured, through provision-admin's open path (exit $($r.Code)). " +
                    (Get-Attribution $Operator (Get-OperatorSids) $r.Text))
                # CONTROL: nothing re-secured the store, so a service that cannot reopen even its own
                # store means the first open locked out EVERY identity, not only the operator. That
                # separates "restricted to the service" from "restricted to nobody usable".
                Start-TheService "reopen of its own store (control)"
                $own = Wait-ForGateRefusal "the control reopen"
                Stop-TheService
                if ($own) {
                    Add-Reading "control: $ServiceIdentity reopened the store it created, so the store is restricted to the service and not to nobody"
                } else {
                    Add-Failure ("control: $ServiceIdentity could not reopen even the store it created " +
                        "itself, which nobody else touched, so its own first open locked out every " +
                        "identity. " + (Get-Attribution $ServiceIdentity (Get-ServiceSids) ""))
                    Show-LogTail
                }
            } else {
                $how = if ($provisioned) { "and provisioned it (no account existed, as since ADR 0183 Wave 2)" }
                       else { "and provision-admin declined on an existing Administrator (the pre-Wave 2 bootstrap shape)" }
                Add-Reading "$Operator opened $DbPath $how"
                Test-Resecured -Identity $Operator -Output $r.Text
                # 3. The service starts again on the store the operator's open re-secured.
                Start-TheService "restart"
                if ($provisioned) {
                    # An addressed Administrator now exists, so the gate passes: prove the open by serving.
                    $failed = $Failures.Count
                    Test-ServiceServes "the restart" "$Operator's open re-secured"
                    Stop-TheService
                    if ($Failures.Count -eq $failed) {
                        Test-Resecured -Identity $ServiceIdentity -FromServiceLog
                    }
                } else {
                    $reopened = Wait-ForGateRefusal "the restart"
                    Stop-TheService
                    if (-not $reopened) {
                        Add-Failure ("$ServiceIdentity could not open $DbPath after $Operator's open " +
                            "re-secured it: the restart never reached the account gate in $WaitSeconds s. " +
                            (Get-Attribution $ServiceIdentity (Get-ServiceSids) ""))
                        Show-LogTail
                    } else {
                        Add-Reading "$ServiceIdentity reopened $DbPath after $Operator's open"
                        Test-Resecured -Identity $ServiceIdentity -FromServiceLog
                    }
                }
                Show-Trio "service restart"
            }
        }
    }
} catch {
    # Name the phase in flight and read the trio from that phase's identity, so an aborted arm still
    # says whose step it was.
    $who = if ($CurrentPhase -like "operator*") { $Operator } else { $ServiceIdentity }
    $sids = if ($CurrentPhase -like "operator*") { Get-OperatorSids } else { Get-ServiceSids }
    $detail = if (Test-Path -LiteralPath $DbPath) { " Trio: $((Get-TrioReport -Identity $who -IdentitySids $sids).Text)" } else { "" }
    Add-Failure ("the $Order arm stopped during '$CurrentPhase' ($who) before its measurement " +
        "finished: $($_.Exception.Message).$detail")
    Show-LogTail
} finally {
    try {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            & (Join-Path $PSScriptRoot "uninstall-service.ps1") -ServiceName $ServiceName -DataDir $DataDir
        }
    } catch {
        Write-Host "::warning title=ADR 0183 Wave 0 ($Order)::$(Format-Annotation "uninstall after the arm failed, so the next arm may find this registration: $($_.Exception.Message)")"
    }
    Remove-Item -LiteralPath $Probe -Force -ErrorAction SilentlyContinue
}

Write-Host "===== ADR 0183 Wave 0 summary: $Order ====="
foreach ($r in $Readings) { Write-Host "READING: $r" }
foreach ($c in $Conditions) { Write-Host "CONDITION: $c" }
if ($Failures.Count -gt 0) {
    foreach ($f in $Failures) { Write-Host "RED: $f" }
    throw "RED [$Order]: $($Failures.Count) failure(s); the first: $($Failures[0])"
}
if ($Conditions.Count -gt 0) {
    $why = "both identities opened the store, but at least one open reported a failed restriction or an unreadable DACL: $($Conditions -join ' / ')"
    Write-Host "::warning title=ADR 0183 Wave 0 ($Order) GREEN (CONDITIONAL)::$(Format-Annotation $why)"
    Write-Host "GREEN (CONDITIONAL) [$Order]: $why"
} else {
    Write-Host "GREEN [$Order]: both identities opened the store in this order, and it stayed confined after each open."
}
# The Actions wrapper exits with $LASTEXITCODE, which the last native command (nssm, icacls) set.
exit 0
