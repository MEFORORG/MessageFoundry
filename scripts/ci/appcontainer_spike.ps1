# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
  CPython in an AppContainer launched by a real NT SERVICE account, on a hosted runner. A spike: it
  measures and builds nothing (vault BACKLOG #3411, wave 3.1).

.DESCRIPTION
  RUN ONLY ON A THROWAWAY HOSTED RUNNER. .github/workflows/appcontainer-spike.yml is the only
  caller. Never run it on a machine you keep. It changes at least these: one Windows service,
  "Log on as a service" for its account, an NSSM download into an administrator-only folder under
  Program Files, folders under C:\, and the access lists of the interpreter's folder and of two
  files in the checkout, which it opens to ALL APPLICATION PACKAGES for reading. The finally block
  removes the service, and nothing else: the runner is thrown away after the job.

  The questions it answers are in that workflow's header. scripts/ci/appcontainer_spike_worker.py
  does the measuring, as the service and inside the container, and judge_reports() there holds the
  rule for each answer. This script is the rig around them.

  THE SERVICE IS REGISTERED THE WAY install-service.ps1 REGISTERS THE ENGINE, because a launch
  under some other token would not answer the question. Its definitions are lifted out of that
  script by the PowerShell AST and run as written, exactly as scripts/ci/dpapi_spike.ps1 lifts
  them; tests/test_dpapi_spike_judge.py checks both rigs' lift lists. So the service runs as its
  virtual account with a restricted service SID and the installer's privilege list, and the judge
  checks the running token by service_token_probe.py's token_problems.

  THE LIFT IS BY NAME. If a lifted function starts calling another of the installer's helpers, this
  rig fails at that call with "not recognized", on its next run. Add the helper to $lifted.

  THE GRANTS THE CONTAINER NEEDS ARE THE RIG'S, and each is what a deploying site would have to
  make too: read on the interpreter's folder, and on the worker and the one file it loads, for
  ALL APPLICATION PACKAGES; and modify, for the same group, on the folders a container writes. No
  integrity label is set: a container ran at low integrity and still wrote an unlabelled folder
  that grants the group (measured on Windows 11 build 26300, as an interactive user). The blob
  file the third question is about gets none of these grants.

  Runs under Windows PowerShell 5.1, as the windows-service-smoke install step runs the installer.
#>
[CmdletBinding()]
param(
    # An administrator-only folder for the checked nssm.exe. Resolve-Nssm creates and checks it.
    [Parameter(Mandatory)][string]$NssmDir,
    # The interpreter the service and both containers run.
    [Parameter(Mandatory)][string]$PythonExe,
    # The runner image, for the summary.
    [Parameter(Mandatory)][string]$Image,
    [string]$WorkRoot = "C:\mefor-ac-spike",
    # Markdown summary to append the answers to. The job passes $env:GITHUB_STEP_SUMMARY.
    [string]$Summary
)

# The circuit breaker (CLAUDE.md section 5): this rig changes the host and undoes almost none of
# it, so it refuses anywhere but a GitHub-hosted runner. No machine name serves, since a hosted
# runner's changes per job; these two variables are what the runner sets for every step.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run on a GitHub-hosted runner, but this is $([Environment]::MachineName); nothing ran" } }

# As install-service.ps1 sets it, and no strict mode, which that script does not set either: the
# definitions lifted from it below run here under the conditions they run under there.
$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 draws a progress bar per chunk of a download, which slows the NSSM fetch.
$ProgressPreference = "SilentlyContinue"

$Service = "MeforAcSpikeA"
$Account = "NT SERVICE\$Service"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Installer = Join-Path $RepoRoot "scripts\service\install-service.ps1"
$Worker = Join-Path $PSScriptRoot "appcontainer_spike_worker.py"
# The files a container reads from the checkout: the worker, and what it loads by path.
$ContainerReads = @($Worker, (Join-Path $RepoRoot "messagefoundry\secrets_dpapi.py"))
$OwnerDir = Join-Path $WorkRoot "owner"
$SharedDir = Join-Path $WorkRoot "shared"
$ControlDir = Join-Path $WorkRoot "control"
$PythonHome = Split-Path -Parent $PythonExe
# SDDL's AC, a well-known SID, so no name lookup can differ by locale.
$AllAppPackages = "*S-1-15-2-1"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This rig registers a service and must run elevated."
}
if (-not (Test-Path -LiteralPath $PythonExe)) { throw "No interpreter at $PythonExe" }

# --- the installer's own definitions ---------------------------------------------------------------
$lifted = @(
    "Get-FilePinProblem", "Get-BroadWriteHolders", "Set-AdminOnlyAcl", "New-AdminOnlyFolder",
    "Get-NssmHomeProblem",
    "Save-PinnedNssm", "Resolve-Nssm", "Get-ServiceImageProblem", "Set-ServiceImage",
    "Set-ServiceAccount", "Disable-RefusedService", "Set-ServiceLogonRight",
    "Get-ServiceSidTypeChoice", "Get-ServiceTokenProblem", "Set-ServiceTokenHardening",
    "Test-LegacyNativeArgumentPassing", "ConvertTo-NativeArgument", "Invoke-Nssm",
    "Assert-NoNssmExpansion", "Stop-ServiceAndConfirm"
)
$liftedValues = @("NssmUrl", "NssmMirrorUrls", "NssmSha256", "NssmExeSha256", "ServicePrivileges")
$parseErrors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$parseErrors)
if ($parseErrors -and $parseErrors.Count -gt 0) { throw "install-service.ps1 does not parse: $($parseErrors[0].Message)" }
# Top level only: a function or an assignment nested in a block is not the installer's definition.
$topLevel = @($tree.EndBlock.Statements)
foreach ($name in $lifted) {
    $found = @($topLevel | Where-Object {
        $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $name })
    if ($found.Count -ne 1) { throw "install-service.ps1 defines '$name' $($found.Count) times at top level, not once" }
    . ([scriptblock]::Create($found[0].Extent.Text))
}
foreach ($name in $liftedValues) {
    $found = @($topLevel | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $_.Left.VariablePath.UserPath -eq $name })
    if ($found.Count -ne 1) { throw "install-service.ps1 assigns `$$name $($found.Count) times at top level, not once" }
    # SafeGetValue evaluates constants only and throws on anything else, so nothing in the
    # installer runs here, and an assignment that stops being a constant fails by name.
    Set-Variable -Name $name -Scope Script -Value ($found[0].Right.Expression.SafeGetValue())
}

# The service parameters are one string, split at white space, so no path in it may hold any; and
# nssm expands %NAME% in what it stores, which the installer's own check refuses.
foreach ($path in @($PythonExe, $Worker, $OwnerDir, $SharedDir)) {
    if ($path -match '[\s"]') { throw "A path the service is registered with holds white space or a quote: $path" }
    Assert-NoNssmExpansion $path
}

function Invoke-Icacls {
    & icacls @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

function New-SpikeFolder([string]$Path, [string[]]$Grants) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $all = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F") + $Grants
    Invoke-Icacls $Path /inheritance:r /grant:r @all
}

function Wait-ForReport([string]$Path, [string]$Name) {
    # Bounded, and over early when the service has stopped: AppExit is Exit, so a worker that died
    # stops its service, and no report is coming.
    foreach ($i in 1..240) {
        if (Test-Path -LiteralPath $Path) { return }
        if ($i -gt 10 -and (Get-Service -Name $Name).Status -eq "Stopped") { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-Path -LiteralPath $Path)) { Write-Warning "$Name wrote no $(Split-Path -Leaf $Path)" }
}

function Get-Sddl([string]$Path) {
    if (Test-Path -LiteralPath $Path) { (Get-Acl -LiteralPath $Path).Sddl } else { $null }
}

function Show-Folder([string]$Path) {
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".json", ".log", ".txt" })) {
        "===== $($file.FullName) ====="
        Get-Content -LiteralPath $file.FullName -Raw
    }
}

$judged = 1
try {
    if (Test-Path -LiteralPath $WorkRoot) { throw "$WorkRoot already exists; this rig runs once, on a fresh runner" }
    New-Item -ItemType Directory -Path $WorkRoot | Out-Null
    $script:NssmPath = Resolve-Nssm -NssmDir $NssmDir

    # The container's reads, and nothing it writes. /T puts the grant on every file the
    # interpreter's folder already holds, the standard library with it, whatever their inheritance.
    Invoke-Icacls $PythonHome /grant "${AllAppPackages}:(OI)(CI)RX" /T /Q
    foreach ($file in $ContainerReads) { Invoke-Icacls $file /grant "${AllAppPackages}:RX" }

    # The control, before the service exists: the same launcher, from the runner's administrator.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    New-SpikeFolder $ControlDir @("*${me}:(OI)(CI)M", "${AllAppPackages}:(OI)(CI)M")
    & $PythonExe -I -B $Worker control --dir $ControlDir
    if ($LASTEXITCODE -ne 0) { Write-Warning "the control exited $LASTEXITCODE; the judge reads what it wrote" }
    if (-not (Test-Path -LiteralPath (Join-Path $ControlDir "control.json"))) { Write-Warning "the control wrote no control.json" }

    # Every nssm set comes before the account changes: this nssm build prints "Invalid account name!"
    # on a set made once the service runs as a virtual account.
    Invoke-Nssm install $Service $PythonExe
    Set-ServiceImage -ServiceName $Service -Path $NssmPath
    Invoke-Nssm set $Service AppParameters "-I -B $Worker owner --dir $OwnerDir --shared $SharedDir"
    Invoke-Nssm set $Service AppDirectory $OwnerDir
    $serviceLog = Join-Path $OwnerDir "worker.log"
    Invoke-Nssm set $Service AppStdout $serviceLog
    Invoke-Nssm set $Service AppStderr $serviceLog
    Invoke-Nssm set $Service AppStopMethodConsole 5000
    # Exit, not Restart: a worker that dies must not start again and write a second report.
    Invoke-Nssm set $Service AppExit Default Exit
    Invoke-Nssm set $Service Start SERVICE_DEMAND_START
    Set-ServiceLogonRight -Account $Account
    Set-ServiceAccount -ServiceName $Service -Account $Account
    $choice = Get-ServiceSidTypeChoice -ServiceName $Service -ServiceAccount $Account
    Set-ServiceTokenHardening -ServiceName $Service -SidType $choice.SidType -Privileges $ServicePrivileges
    "$Service registered as $Account, SID type $($choice.SidType), privileges $($ServicePrivileges -join ', ')"
    "===== sc.exe qc $Service ====="; (& sc.exe qc $Service | Out-String).Trim()
    "===== sc.exe qsidtype $Service ====="; (& sc.exe qsidtype $Service | Out-String).Trim()

    # After the registration: a virtual account's SID resolves only once its service exists. The
    # grant is to the account by name, which under the restricted service SID is the service SID
    # itself, on the write-restricted token's restricting list, so it counts for a write.
    New-SpikeFolder $OwnerDir @("${Account}:(OI)(CI)M")
    New-SpikeFolder $SharedDir @("${Account}:(OI)(CI)M", "${AllAppPackages}:(OI)(CI)M")
    $OwnerSid = ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]).Value

    try { Start-Service -Name $Service } catch { Write-Warning "Start-Service $Service : $($_.Exception.Message)" }
    Wait-ForReport (Join-Path $OwnerDir "owner.json") $Service
    if (-not (Test-Path -LiteralPath (Join-Path $SharedDir "container.json"))) {
        Write-Warning "the service's container wrote no container.json; read container.log"
    }
    if (-not (Stop-ServiceAndConfirm -ServiceName $Service)) { Write-Warning "$Service did not stop within 30 seconds" }

    # The access lists the third question rests on, read by the judge, never by the container.
    $acl = @{
        denied      = Get-Sddl (Join-Path $OwnerDir "denied.blob")
        granted     = Get-Sddl (Join-Path $SharedDir "granted.blob")
        interpreter = Get-Sddl $PythonHome
    } | ConvertTo-Json
    # Without a byte-order mark, which Set-Content -Encoding UTF8 writes on Windows PowerShell 5.1.
    [IO.File]::WriteAllText((Join-Path $OwnerDir "acl.json"), $acl)
    foreach ($dir in $ControlDir, $OwnerDir, $SharedDir) { Show-Folder $dir }

    $judgeArgs = @("-I", "-B", $Worker, "judge", "--owner-dir", $OwnerDir, "--shared-dir", $SharedDir,
        "--control-dir", $ControlDir, "--owner-sid", $OwnerSid, "--owner-account", $Account,
        "--image", $Image)
    foreach ($privilege in $ServicePrivileges) { $judgeArgs += @("--privilege", $privilege) }
    if ($Summary) { $judgeArgs += @("--summary", $Summary) }
    $global:LASTEXITCODE = $null
    & $PythonExe @judgeArgs
    $judged = $LASTEXITCODE
    if ($null -eq $judged) { throw "the judge did not run" }
} finally {
    # Tidy, though the runner is thrown away after the job. The SCM removes the service; no nssm.
    if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Service | Out-Null
    }
}
# 3 is the judge's EXIT_UNANSWERED; CPython exits 1 on a traceback, which is the next line's case.
if ($judged -eq 3) { throw "the judge found an answer the instrument could not give; read the APPCONTAINER-SPIKE lines" }
if ($judged -ne 0) { throw "the judge itself failed (exit $judged), so no answer was judged; read its output above" }
# The runner's powershell wrapper exits with $LASTEXITCODE, which the tidy-up's sc.exe set last. The
# answers are in; a failed tidy-up on a runner about to be thrown away must not turn them red.
$global:LASTEXITCODE = 0
