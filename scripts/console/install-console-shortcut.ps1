<#
.SYNOPSIS
    Create Desktop + Start-Menu shortcuts that launch the MessageFoundry admin console.

.DESCRIPTION
    Drops .lnk shortcuts pointing at the windowed launcher (messagefoundry-console.exe, the
    [project.gui-scripts] entry — no flashing console window) so operators open the console by
    double-clicking an icon instead of typing a command. The shortcut carries the MessageFoundry
    badge (messagefoundry/console/resources/app.ico).

    The console talks to a running engine (default http://127.0.0.1:8765 — typically the boot-start
    NSSM service, see docs/SERVICE.md) and prompts for sign-in, so no arguments are needed in the
    common case; pass -Url for a non-default engine.

    Per-user by default (no elevation). -AllUsers writes machine-wide shortcuts and needs an
    elevated (Administrator) prompt.

.EXAMPLE
    .\install-console-shortcut.ps1
    .\install-console-shortcut.ps1 -Url https://engine.internal:8765
    .\install-console-shortcut.ps1 -AllUsers          # run elevated
#>
[CmdletBinding()]
param(
    # Path to messagefoundry-console.exe. Auto-detected when omitted: the repo's .venv first, then PATH.
    [string]$ConsoleExe,
    # Engine API base URL. Only baked into the shortcut when it differs from the localhost default.
    [string]$Url,
    # Override the shortcut icon (.ico / exe). Defaults to the badge shipped with the package.
    [string]$IconPath,
    [string]$Name = "MessageFoundry Console",
    # Machine-wide shortcuts (Public Desktop + All-Users Start Menu). Requires elevation.
    [switch]$AllUsers,
    [switch]$NoDesktop,
    [switch]$NoStartMenu
)

$ErrorActionPreference = "Stop"

# Repo root is two levels up from this script (scripts\console\).
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Resolve-ConsoleExe {
    param([string]$Provided, [string]$RepoRoot)
    if ($Provided) {
        if (-not (Test-Path $Provided)) { throw "Console executable not found at: $Provided" }
        return (Resolve-Path $Provided).Path
    }
    $repoVenv = Join-Path $RepoRoot ".venv\Scripts\messagefoundry-console.exe"
    if (Test-Path $repoVenv) { return $repoVenv }
    $onPath = Get-Command messagefoundry-console -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw ("messagefoundry-console.exe not found. Install the console first " +
        "(pip install `"messagefoundry[console]`") in the engine venv, or pass -ConsoleExe.")
}

function Resolve-IconPath {
    <#
      Find the shipped badge. Ask the venv's own interpreter where the packaged resource lives (works
      for a normal pip install into site-packages); fall back to the repo copy, then to the exe itself
      (valid target, just a generic icon) so a missing .ico never blocks shortcut creation.
    #>
    param([string]$Provided, [string]$ConsoleExe, [string]$RepoRoot)
    if ($Provided) {
        if (-not (Test-Path $Provided)) { throw "Icon not found at: $Provided" }
        return (Resolve-Path $Provided).Path
    }
    $python = Join-Path (Split-Path $ConsoleExe) "python.exe"
    if (Test-Path $python) {
        try {
            $code = "from importlib.resources import files; print(files('messagefoundry.console')/'resources'/'app.ico')"
            $found = (& $python -c $code 2>$null | Select-Object -First 1)
            if ($found -and (Test-Path $found.Trim())) { return (Resolve-Path $found.Trim()).Path }
        } catch { }  # fall through to the repo copy
    }
    $repoIcon = Join-Path $RepoRoot "messagefoundry\console\resources\app.ico"
    if (Test-Path $repoIcon) { return (Resolve-Path $repoIcon).Path }
    return $ConsoleExe  # last resort: the exe's own (generic) icon
}

# --- preflight ---------------------------------------------------------------

if ($AllUsers) {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "-AllUsers writes machine-wide shortcuts and requires an elevated (Administrator) PowerShell."
    }
}

$ConsoleExe = Resolve-ConsoleExe -Provided $ConsoleExe -RepoRoot $RepoRoot
$IconPath   = Resolve-IconPath -Provided $IconPath -ConsoleExe $ConsoleExe -RepoRoot $RepoRoot
$WorkDir    = Split-Path $ConsoleExe

# Only carry --url when it isn't the localhost default the console already uses.
$Arguments = ""
if ($Url -and $Url -ne "http://127.0.0.1:8765") { $Arguments = "--url `"$Url`"" }

# --- create ------------------------------------------------------------------

function New-ConsoleShortcut {
    param([Parameter(Mandatory)][string]$Dir)
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
    $lnk = Join-Path $Dir "$Name.lnk"
    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($lnk)
    $shortcut.TargetPath = $ConsoleExe
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $WorkDir
    $shortcut.IconLocation = "$IconPath,0"
    $shortcut.Description = "MessageFoundry admin console"
    $shortcut.Save()
    [Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) | Out-Null
    Write-Host "  $lnk" -ForegroundColor Green
    return $lnk
}

if ($AllUsers) {
    $desktop   = [Environment]::GetFolderPath('CommonDesktopDirectory')
    $startMenu = [Environment]::GetFolderPath('CommonPrograms')
} else {
    $desktop   = [Environment]::GetFolderPath('Desktop')
    $startMenu = [Environment]::GetFolderPath('Programs')
}

Write-Host "Creating MessageFoundry Console shortcut(s):"
Write-Host "  Target : $ConsoleExe $Arguments"
Write-Host "  Icon   : $IconPath"
if (-not $NoDesktop)   { New-ConsoleShortcut -Dir $desktop | Out-Null }
if (-not $NoStartMenu) { New-ConsoleShortcut -Dir $startMenu | Out-Null }

Write-Host ""
Write-Host "Done. Double-click the icon to open the console (it connects to the engine and prompts for sign-in)." -ForegroundColor Green
Write-Host "Remove with: .\uninstall-console-shortcut.ps1$(if ($AllUsers) { ' -AllUsers' })"
