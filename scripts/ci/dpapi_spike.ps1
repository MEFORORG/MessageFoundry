# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
  User-scope DPAPI under a real NT SERVICE account, on a hosted runner. A spike: it measures and
  builds nothing (vault BACKLOG #3411, wave 3.0).

.DESCRIPTION
  RUN ONLY ON A THROWAWAY HOSTED RUNNER. It registers two Windows services, creates a local user,
  grants that user "Log on as a service" and writes under C:\. .github/workflows/dpapi-spike.yml is
  the only caller. Never run it on a machine you keep.

  The key-custody draft makes user-scope DPAPI, done by the service account itself, the Windows
  default wrap for the master key, and asks three questions before anything is built on it:

    1. Does CryptProtectData in user scope succeed under NT SERVICE\<name>?
    2. Does a different, non-elevated account fail to unprotect that blob?
    3. Does the blob still open after a service restart, and after a host reboot?

  This rig answers 1, 2 and the restart half of 3. THE REBOOT HALF IS NOT RUN: a hosted runner cannot
  reboot inside a job. scripts/ci/dpapi_spike_worker.py does the DPAPI calls, as each service, with
  the engine's own messagefoundry.secrets_dpapi, and holds the rule for what each answer is.

  THE OWNER SERVICE IS REGISTERED THE WAY install-service.ps1 REGISTERS THE ENGINE, because a DPAPI
  answer under some other token would not answer the question. Its definitions are lifted out of
  that script by the PowerShell AST and run as written, not copied here: the pinned NSSM download
  and check (Resolve-Nssm), the quoted image path (Set-ServiceImage), the run-as account through the
  SCM (Set-ServiceAccount), "Log on as a service" (Set-ServiceLogonRight), and the SID type and
  privilege list (Get-ServiceSidTypeChoice, Set-ServiceTokenHardening). So the owner runs as its
  virtual account with a restricted service SID and the installer's privilege list, and the judge
  checks the running token by service_token_probe.py's token_problems, the windows-service-smoke
  leg's own rule. The other service runs as a local user with SID type none, which is what the
  installer gives such an account. Only the registration is the installer's: the two work folders
  are plain folders with one grant each, not the engine's data directory.

  THE LIFT IS BY NAME. If a lifted function starts calling another of the installer's helpers, this
  rig fails at that call with "not recognized", on its next run. Add the helper to $lifted.

  The other account never reads the owner's folder. This script copies the owner's two blobs into
  the other account's folder, which models an attacker who already holds the bytes: the question is
  whether DPAPI refuses them, not whether a file's access list does.

  THE PASSWORD OF THE LOCAL USER arrives in $env:DPAPI_SPIKE_OTHER_PASSWORD, drawn and masked by the
  workflow. It becomes a SecureString here, the variable is removed, and no message carries it.

  Runs under Windows PowerShell 5.1, as the windows-service-smoke install step runs the installer.
#>
[CmdletBinding()]
param(
    # An administrator-only folder for the checked nssm.exe. Resolve-Nssm creates and checks it.
    [Parameter(Mandatory)][string]$NssmDir,
    # The interpreter both services run. Its path goes into the service parameters unquoted.
    [Parameter(Mandatory)][string]$PythonExe,
    # The runner image, for the summary.
    [Parameter(Mandatory)][string]$Image,
    [string]$WorkRoot = "C:\mefor-dpapi-spike",
    # Markdown summary to append the answers to. The job passes $env:GITHUB_STEP_SUMMARY.
    [string]$Summary
)

# As install-service.ps1 sets it, and no strict mode, which that script does not set either: the
# definitions lifted from it below run here under the conditions they run under there.
$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 draws a progress bar per chunk of a download, which slows the NSSM fetch.
$ProgressPreference = "SilentlyContinue"

$OwnerService = "MeforDpapiSpikeA"
$OtherService = "MeforDpapiSpikeB"
$OtherUser = "mefor-dpapi-b"
$OwnerAccount = "NT SERVICE\$OwnerService"
$OtherAccount = "$env:COMPUTERNAME\$OtherUser"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Installer = Join-Path $RepoRoot "scripts\service\install-service.ps1"
$Worker = Join-Path $PSScriptRoot "dpapi_spike_worker.py"
$OwnerDir = Join-Path $WorkRoot "owner"
$OtherDir = Join-Path $WorkRoot "other"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This rig registers services and must run elevated."
}
if (-not (Test-Path -LiteralPath $PythonExe)) { throw "No interpreter at $PythonExe" }

# --- the installer's own definitions ---------------------------------------------------------------
$lifted = @(
    "Get-FilePinProblem", "Get-BroadWriteHolders", "Set-AdminOnlyAcl", "Get-NssmHomeProblem",
    "Save-PinnedNssm", "Resolve-Nssm", "Get-ServiceImageProblem", "Set-ServiceImage",
    "Set-ServiceAccount", "Disable-RefusedService", "Set-ServiceLogonRight",
    "Get-ServiceSidTypeChoice", "Get-ServiceTokenProblem", "Set-ServiceTokenHardening",
    "Test-LegacyNativeArgumentPassing", "ConvertTo-NativeArgument", "Invoke-Nssm",
    "Assert-NoNssmExpansion"
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
foreach ($path in @($PythonExe, $Worker, $OwnerDir, $OtherDir)) {
    if ($path -match '[\s"]') { throw "A path the services are registered with holds white space or a quote: $path" }
    Assert-NoNssmExpansion $path
}

function Wait-ForReport([string]$Path, [string]$Service) {
    # Bounded, and over early when the service has stopped: AppExit is Exit, so a worker that died
    # stops its service, and no report is coming.
    foreach ($i in 1..180) {
        if (Test-Path -LiteralPath $Path) { return }
        if ($i -gt 10 -and (Get-Service -Name $Service).Status -eq "Stopped") { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-Path -LiteralPath $Path)) { Write-Warning "$Service wrote no $(Split-Path -Leaf $Path)" }
}

function Start-SpikeService([string]$Name) {
    # The service is judged by the report it writes, not by this call: a start that the SCM
    # reports late, or a worker that dies, both show as a missing report with the logs printed.
    try { Start-Service -Name $Name } catch { Write-Warning "Start-Service $Name : $($_.Exception.Message)" }
}

function Stop-SpikeService([string[]]$Name) {
    try { Stop-Service -Name $Name -Force } catch { Write-Warning "Stop-Service $Name : $($_.Exception.Message)" }
    foreach ($one in $Name) { (Get-Service -Name $one).WaitForStatus("Stopped", "00:00:30") }
}

function Register-SpikeService {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$Account,
        [SecureString]$Password
    )
    # Every nssm set comes before the account changes: this nssm build prints "Invalid account name!"
    # on a set made once the service runs as a virtual account.
    Invoke-Nssm install $Name $PythonExe
    Set-ServiceImage -ServiceName $Name -Path $NssmPath
    Invoke-Nssm set $Name AppParameters "-I -B $Worker $Role --dir $Dir"
    Invoke-Nssm set $Name AppDirectory $Dir
    Invoke-Nssm set $Name AppStdout (Join-Path $Dir "worker.log")
    Invoke-Nssm set $Name AppStderr (Join-Path $Dir "worker.log")
    Invoke-Nssm set $Name AppStopMethodConsole 5000
    # Exit, not Restart: a worker that dies must not start again and write a second report.
    Invoke-Nssm set $Name AppExit Default Exit
    Invoke-Nssm set $Name Start SERVICE_DEMAND_START
    # As install-service.ps1 does for every named account: the right first, then the account.
    Set-ServiceLogonRight -Account $Account
    if ($Password) { Set-ServiceAccount -ServiceName $Name -Account $Account -Password $Password }
    else { Set-ServiceAccount -ServiceName $Name -Account $Account }
    $choice = Get-ServiceSidTypeChoice -ServiceName $Name -ServiceAccount $Account
    Set-ServiceTokenHardening -ServiceName $Name -SidType $choice.SidType -Privileges $ServicePrivileges
    "$Name registered as $Account, SID type $($choice.SidType), privileges $($ServicePrivileges -join ', ')"
    "===== sc.exe qsidtype $Name ====="; (& sc.exe qsidtype $Name | Out-String).Trim()
    "===== sc.exe qprivs $Name ====="; (& sc.exe qprivs $Name | Out-String).Trim()
}

function New-SpikeFolder([string]$Path, [string]$Grantee) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    # The grant is to the account by name. Under the owner's restricted service SID that is the
    # service SID itself, the one grant a write-restricted token still counts.
    & icacls $Path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${Grantee}:(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls on $Path failed (exit $LASTEXITCODE)" }
}

function Get-Sid([string]$Account) {
    ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Show-Folder([string]$Path) {
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".json", ".log", ".txt" })) {
        "===== $($file.FullName) ====="
        Get-Content -LiteralPath $file.FullName -Raw
    }
}

$secret = $null
if ($env:DPAPI_SPIKE_OTHER_PASSWORD) {
    $secret = ConvertTo-SecureString $env:DPAPI_SPIKE_OTHER_PASSWORD -AsPlainText -Force
}
Remove-Item Env:DPAPI_SPIKE_OTHER_PASSWORD -ErrorAction SilentlyContinue
if (-not $secret) { throw "DPAPI_SPIKE_OTHER_PASSWORD is empty, so the local user cannot be created" }

$judged = 1
try {
    if (Test-Path -LiteralPath $WorkRoot) { throw "$WorkRoot already exists; this rig runs once, on a fresh runner" }
    New-Item -ItemType Directory -Path $WorkRoot | Out-Null
    $script:NssmPath = Resolve-Nssm -NssmDir $NssmDir

    # A standard user: a member of Users, as an account made by hand is, and of no other group.
    # The judge checks its token holds no enabled Administrators.
    New-LocalUser -Name $OtherUser -Password $secret -PasswordNeverExpires -AccountNeverExpires `
        -Description "dpapi-spike second account" | Out-Null
    Add-LocalGroupMember -SID "S-1-5-32-545" -Member $OtherUser

    Register-SpikeService -Name $OwnerService -Role owner -Dir $OwnerDir -Account $OwnerAccount
    Register-SpikeService -Name $OtherService -Role other -Dir $OtherDir -Account $OtherAccount -Password $secret
    # After the registration: a virtual account's SID resolves only once its service exists.
    New-SpikeFolder $OwnerDir $OwnerAccount
    New-SpikeFolder $OtherDir $OtherAccount
    $OwnerSid = Get-Sid $OwnerAccount
    $OtherSid = Get-Sid $OtherAccount

    # Question 1: the first start protects and unprotects.
    Start-SpikeService $OwnerService
    Wait-ForReport (Join-Path $OwnerDir "owner-start-1.json") $OwnerService

    # Question 2: the other account is handed byte-for-byte copies of both blobs.
    foreach ($pair in @(@("user.blob", "owner-user.blob"), @("machine.blob", "owner-machine.blob"))) {
        $from = Join-Path $OwnerDir $pair[0]
        if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination (Join-Path $OtherDir $pair[1]) }
    }
    Start-SpikeService $OtherService
    Wait-ForReport (Join-Path $OtherDir "other.json") $OtherService

    # Question 3: stop the owner, then start it again. A new process under a new service start.
    Stop-SpikeService $OwnerService
    Start-SpikeService $OwnerService
    Wait-ForReport (Join-Path $OwnerDir "owner-start-2.json") $OwnerService

    Stop-SpikeService @($OwnerService, $OtherService)
    Show-Folder $OwnerDir
    Show-Folder $OtherDir

    $judgeArgs = @("-I", "-B", $Worker, "judge", "--owner-dir", $OwnerDir, "--other-dir", $OtherDir,
        "--owner-sid", $OwnerSid, "--other-sid", $OtherSid,
        "--owner-account", $OwnerAccount, "--other-account", $OtherAccount, "--image", $Image)
    foreach ($privilege in $ServicePrivileges) { $judgeArgs += @("--privilege", $privilege) }
    if ($Summary) { $judgeArgs += @("--summary", $Summary) }
    $global:LASTEXITCODE = $null
    & $PythonExe @judgeArgs
    $judged = $LASTEXITCODE
    if ($null -eq $judged) { throw "the judge did not run" }
} finally {
    # Tidy, though the runner is thrown away after the job. The SCM removes the services; no nssm.
    foreach ($name in $OwnerService, $OtherService) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $name | Out-Null
        }
    }
    Remove-LocalUser -Name $OtherUser -ErrorAction SilentlyContinue
}
if ($judged -ne 0) { throw "the judge found an answer the instrument could not give (exit $judged); read the DPAPI-SPIKE lines" }
# The runner's powershell wrapper exits with $LASTEXITCODE, which the tidy-up's sc.exe set last. The
# answers are in; a failed tidy-up on a runner about to be thrown away must not turn them red.
$global:LASTEXITCODE = 0
