<#
.SYNOPSIS
    Install the cross-session coordination hooks so they load in EVERY worktree, not just some.

.DESCRIPTION
    THE PROBLEM THIS FIXES. The coordination banner (session-context.ps1) is wired only in the
    PROJECT settings file, `<worktree>/.claude/settings.json` -- and `/.claude/` is GITIGNORED
    (.gitignore:142), so git cannot deliver it to a new worktree. Worktrees the Claude Code harness
    creates under `.claude/worktrees/` get a copy; worktrees `new.ps1` creates as `<repo>-<name>`
    siblings DO NOT. Measured 2026-07-29: 5 of 9 worktrees had no project settings, and a live VS Code
    session was working in one of them with zero coordination context -- it could not see the other
    four sessions, and they could not see it.

    That is fatal to the whole idea. You cannot force sessions to coordinate when the mechanism does
    not load for half of them, and the half it misses is invisible rather than obviously broken.

    THE FIX: wire the hooks at USER level (~/.claude/settings.json), which is per-machine and loads in
    every worktree regardless of how it was created -- the same place the worktree gate already lives.

    NO INSTALLED COPY. Each hook is a one-line shim that locates the script in a checkout and runs it,
    so there is nothing to go stale: after a `git pull` the hook is current everywhere, immediately.
    This is deliberate -- the worktree gate's installer copies its script, and running it from a stale
    checkout has already silently downgraded the live gate once.

    THE SHIM RESOLVES THE PRIMARY CHECKOUT, not the calling worktree. Coordination is infrastructure
    and must be uniform across sessions. Measured 2026-07-29: a worktree sitting on a branch that
    predated the coordination merge had none of these scripts, so a cwd-resolved shim found nothing
    and exited silently -- that session got no banner and no gate, and nothing reported the absence.
    The primary tracks main, so every session runs the same current code whatever branch it is on.

    WHAT GETS WIRED
      SessionStart                          -> scripts/worktree/session-context.ps1  (who is live, what they build)
      PreToolUse Edit|Write|MultiEdit|Notebook -> scripts/hooks/collision_gate.ps1   (refuse a file a live session is changing)

    Idempotent: re-running replaces our own entries and leaves every other hook untouched.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Status,
    [switch]$Uninstall,
    # Settings file to modify. Tests point this at a fixture instead of the real user settings.
    [string]$SettingsPath = (Join-Path $env:USERPROFILE ".claude\settings.json")
)

$ErrorActionPreference = "Stop"

# Marker so we can find and replace exactly our own entries on a re-install, without disturbing hooks
# another tool (or another session) added to the same file.
$MARKER = "mefor-coord"

# The shim. No installed copy: it locates the script in a checkout and runs it, so a `git pull` updates
# the hook everywhere with nothing to fall stale. Silent and exit-0 outside a repo, because this file is
# user-global and runs in every unrelated project on the machine.
#
# IT RESOLVES THE PRIMARY CHECKOUT, NOT THE CURRENT WORKTREE, and that order matters. Coordination is
# INFRASTRUCTURE and has to be uniform: two sessions running different versions of the collision
# protocol is the drift the shared liveness fence exists to prevent. Measured 2026-07-29: a worktree
# sitting on a branch that predated the coordination merge had none of the scripts, so a cwd-resolved
# shim found nothing and exited silently -- the session got no banner and no gate, and nothing said so.
# The primary tracks main, so every session runs the same current code whatever its own branch is.
# The current worktree is kept only as a fallback, for a layout where the primary is unavailable.
function New-ShimCommand([string]$RelativeScript) {
    return (
        "# $MARKER`n" +
        '$c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null); ' +
        'if ($LASTEXITCODE -eq 0 -and $c) { ' +
        '$bases = @((Split-Path $c.Trim() -Parent), (& git rev-parse --path-format=absolute --show-toplevel 2>$null)); ' +
        'foreach ($b in $bases) { ' +
        'if (-not $b) { continue } ' +
        "`$s = Join-Path `$b.Trim() '$RelativeScript'; " +
        'if (Test-Path -LiteralPath $s) { & $s; break } } }'
    )
}

$WIRING = @(
    @{ Event = "SessionStart"; Matcher = $null; Script = "scripts/worktree/session-context.ps1"; Timeout = 30; Msg = "Session coordination" }
    @{ Event = "PreToolUse"; Matcher = "Edit|Write|MultiEdit|NotebookEdit"; Script = "scripts/hooks/collision_gate.ps1"; Timeout = 20; Msg = "Checking for a colliding session" }
)

function Read-Settings {
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $SettingsPath -Raw
    if (-not $raw.Trim()) { return [ordered]@{} }
    # Fail loudly rather than overwrite: a settings file we cannot parse is one we must not rewrite,
    # because a bad write silently disables EVERY setting in it.
    return ($raw | ConvertFrom-Json -AsHashtable)
}

function Test-IsOurs([hashtable]$Entry) {
    foreach ($h in @($Entry.hooks)) { if ([string]$h.command -match [regex]::Escape($MARKER)) { return $true } }
    return $false
}

$settings = Read-Settings
if (-not $settings.hooks) { $settings.hooks = [ordered]@{} }

if ($Status) {
    Write-Host ""
    Write-Host "Coordination hooks in $SettingsPath"
    $any = $false
    foreach ($w in $WIRING) {
        $groups = @($settings.hooks[$w.Event])
        $ours = @($groups | Where-Object { $_ -and (Test-IsOurs $_) })
        $state = if ($ours.Count -gt 0) { "INSTALLED" } else { "missing" }
        if ($ours.Count -gt 0) { $any = $true }
        Write-Host ("  {0,-12} {1,-34} {2}" -f $w.Event, $w.Script, $state)
    }
    Write-Host ""
    if (-not $any) { Write-Host "  Not installed. Run without -Status to wire it up." -ForegroundColor Yellow }
    exit 0
}

# Strip our entries first -- this is both the uninstall path and the idempotency of re-install.
foreach ($w in $WIRING) {
    if ($settings.hooks[$w.Event]) {
        $kept = @(@($settings.hooks[$w.Event]) | Where-Object { $_ -and -not (Test-IsOurs $_) })
        if ($kept.Count -gt 0) { $settings.hooks[$w.Event] = $kept } else { $settings.hooks.Remove($w.Event) }
    }
}

if (-not $Uninstall) {
    foreach ($w in $WIRING) {
        $entry = [ordered]@{}
        if ($w.Matcher) { $entry.matcher = $w.Matcher }
        $entry.hooks = @(
            [ordered]@{
                type          = "command"
                command       = (New-ShimCommand $w.Script)
                shell         = "powershell"
                timeout       = $w.Timeout
                statusMessage = $w.Msg
            }
        )
        $existing = @($settings.hooks[$w.Event])
        $settings.hooks[$w.Event] = @($existing | Where-Object { $_ }) + @($entry)
    }
}

$backup = "$SettingsPath.bak-coord"
if ($PSCmdlet.ShouldProcess($SettingsPath, $(if ($Uninstall) { "remove coordination hooks" } else { "install coordination hooks" }))) {
    if (Test-Path -LiteralPath $SettingsPath) { Copy-Item -LiteralPath $SettingsPath -Destination $backup -Force }
    $json = $settings | ConvertTo-Json -Depth 12
    # Validate what we are about to write BEFORE replacing the file. A malformed settings.json does not
    # error at startup -- it silently disables every setting in it, which is the worst failure mode here.
    try { $null = $json | ConvertFrom-Json } catch { throw "Refusing to write: generated settings JSON is invalid. $_" }
    Set-Content -LiteralPath $SettingsPath -Value $json -Encoding UTF8

    Write-Host ""
    if ($Uninstall) { Write-Host "Coordination hooks REMOVED from $SettingsPath" -ForegroundColor Yellow }
    else {
        Write-Host "Coordination hooks INSTALLED (user level -- loads in every worktree)" -ForegroundColor Green
        foreach ($w in $WIRING) { Write-Host ("  {0,-12} -> {1}" -f $w.Event, $w.Script) }
        Write-Host ""
        Write-Host "  Takes effect in NEWLY STARTED sessions; existing ones keep the config they booted with."
    }
    Write-Host "  backup: $backup"
    Write-Host ""
}
