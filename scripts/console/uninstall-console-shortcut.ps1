<#
.SYNOPSIS
    Remove the MessageFoundry admin-console shortcuts created by install-console-shortcut.ps1.

.DESCRIPTION
    Deletes the Desktop + Start-Menu .lnk shortcuts. Per-user by default; -AllUsers removes the
    machine-wide shortcuts (requires an elevated prompt). The installed package is left untouched.

.EXAMPLE
    .\uninstall-console-shortcut.ps1
    .\uninstall-console-shortcut.ps1 -AllUsers          # run elevated
#>
[CmdletBinding()]
param(
    [string]$Name = "MessageFoundry Console",
    [switch]$AllUsers
)

$ErrorActionPreference = "Stop"

if ($AllUsers) {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "-AllUsers removes machine-wide shortcuts and requires an elevated (Administrator) PowerShell."
    }
    $dirs = @(
        [Environment]::GetFolderPath('CommonDesktopDirectory'),
        [Environment]::GetFolderPath('CommonPrograms')
    )
} else {
    $dirs = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('Programs')
    )
}

$removed = 0
foreach ($dir in $dirs) {
    $lnk = Join-Path $dir "$Name.lnk"
    if (Test-Path $lnk) {
        Remove-Item $lnk -Force
        Write-Host "Removed $lnk" -ForegroundColor Green
        $removed++
    }
}
if ($removed -eq 0) { Write-Host "No '$Name' shortcuts found - nothing to do." }
