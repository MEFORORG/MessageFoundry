<#
.SYNOPSIS
    Stop and remove the MessageFoundry Windows service (NSSM).

.DESCRIPTION
    Stops the service (Ctrl+C, letting the engine drain connections) and removes its NSSM
    registration. Log files and the message store under -DataDir are left in place.

    Run from an elevated (Administrator) PowerShell prompt.

.EXAMPLE
    .\uninstall-service.ps1
#>
[CmdletBinding()]
param(
    [string]$NssmPath,
    [string]$ServiceName = "MessageFoundry",
    [string]$DataDir = "C:\ProgramData\MessageFoundry"
)

$ErrorActionPreference = "Stop"

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Removing a Windows service requires an elevated (Administrator) PowerShell."
}

# Detect via Get-Service (no stderr/Stop pitfalls like `nssm status` on a missing service).
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Host "Service '$ServiceName' is not installed - nothing to do."
    return
}

# Find nssm: explicit path, PATH, or the auto-provisioned cache. Fall back to sc.exe if absent.
if (-not $NssmPath) {
    $cmd = Get-Command nssm -ErrorAction SilentlyContinue
    $NssmPath = if ($cmd) { $cmd.Source } else { Join-Path $DataDir "bin\nssm.exe" }
}
$haveNssm = Test-Path $NssmPath

Write-Host "Stopping '$ServiceName'..."
if ($haveNssm) { try { & $NssmPath stop $ServiceName 2>&1 | Out-Null } catch { } }
else { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }

Write-Host "Removing '$ServiceName'..."
if ($haveNssm) {
    & $NssmPath remove $ServiceName confirm
    if ($LASTEXITCODE -ne 0) { throw "nssm remove failed (exit $LASTEXITCODE)" }
} else {
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed (exit $LASTEXITCODE)" }
}

Write-Host "Removed '$ServiceName'. Logs and the message store were left in place." -ForegroundColor Green
