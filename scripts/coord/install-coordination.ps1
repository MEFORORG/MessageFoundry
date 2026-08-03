<#
.SYNOPSIS
    Install the cross-session coordination hooks so they load in EVERY worktree, not just some.

.DESCRIPTION
    THE PROBLEM THIS FIXES. The coordination banner (session-context.ps1) is wired only in the
    PROJECT settings file, `<worktree>/.claude/settings.json` -- and `/.claude/` is GITIGNORED
    (.gitignore:148), so git cannot deliver it to a new worktree. Worktrees the Claude Code harness
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
      UserPromptSubmit                      -> scripts/hooks/announce-session.ps1    (tell the peers you exist, and what you intend)

    Idempotent: re-running replaces our own entries and leaves every other hook untouched.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Uninstall
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Only UserPromptSubmit -Uninstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Status,
    [switch]$Uninstall,
    # Settings file to modify. Tests point this at a fixture instead of the real user settings.
    [string]$SettingsPath = (Join-Path $env:USERPROFILE ".claude\settings.json"),
    # Limit the operation to these events (install, uninstall and -Status alike). Announce lives on its
    # own event, so `-Only UserPromptSubmit -Uninstall` removes it WITHOUT disarming the collision gate
    # or the SessionStart banner. Without this the only 2am remedy is a hand-edit of the user settings.
    [string[]]$Only,
    [string[]]$Except
)

$ErrorActionPreference = "Stop"

# Marker so we can find and replace exactly our own entries on a re-install, without disturbing hooks
# another tool (or another session) added to the same file.
$MARKER = "mefor-coord"

# A SEPARATE marker for the announce hook, deliberately. Two reasons; the second is the durable one:
#  - Test-IsOurs is a SUBSTRING regex match, so any marker CONTAINING "mefor-coord" (e.g.
#    "mefor-coord-announce") would be stripped by every managed event's loop. "mefor-announce"
#    contains neither string, in either direction.
#  - The blast radii differ. A SessionStart/PreToolUse failure degrades coordination; a
#    UserPromptSubmit failure can block the user's prompt outright. Being able to remove announce
#    (-Only UserPromptSubmit -Uninstall) without disarming the collision gate is worth one literal.
# It is also NOT "mefor-web-announce": the messagefoundry-website repo's live entry sits in this same
# user settings file (verified), and neither string contains the other, so neither installer can
# delete the other's hook.
$ANNOUNCE_MARKER = "mefor-announce"

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
function New-ShimCommand([string]$RelativeScript, [string]$Marker = $MARKER) {
    return (
        "# $Marker`n" +
        '$c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null); ' +
        'if ($LASTEXITCODE -eq 0 -and $c) { ' +
        '$bases = @((Split-Path $c.Trim() -Parent), (& git rev-parse --path-format=absolute --show-toplevel 2>$null)); ' +
        'foreach ($b in $bases) { ' +
        'if (-not $b) { continue } ' +
        "`$s = Join-Path `$b.Trim() '$RelativeScript'; " +
        'if (Test-Path -LiteralPath $s) { & $s; break } } }'
    )
}

# The announce shim differs from the shared one in exactly two ways, and it is a SEPARATE builder rather
# than a flag on New-ShimCommand for a mechanical reason: it appends `-CommonDir $c`, and
# session-context.ps1 / collision_gate.ps1 would ERROR on an unexpected parameter.
#
# WHY THE MISSING-SCRIPT NOTICE EXISTS. Every receipt, marker and visible line the hook writes lives
# INSIDE the script -- strictly downstream of the resolution failure that IS the historical bug.
# Measured 2026-08-01 from a worktree: BOTH probe bases returned False for BOTH candidate paths, stdout
# was empty, and nothing was written anywhere. That is byte-identical to a healthy hook with no peers,
# which is how a wired-but-resolving-nothing hook survived for weeks. This notice is the ONE surface
# that still resolves when the script does not.
#
# WHY IT IS GATED ON presence.ps1. This entry is user-global and fires in every unrelated project on the
# machine. The $mf probe means the notice appears ONLY in a checkout that is recognisably MessageFoundry,
# so the mandatory silent-outside-this-repo guarantee survives.
function New-AnnounceShimCommand {
    $notice = "[announce] scripts/hooks/announce-session.ps1 is missing from this checkout -- the announce hook is wired but resolving nothing. See docs/WORKTREES.md, ""Announcing yourself""."
    return (
        "# $ANNOUNCE_MARKER`n" +
        '$c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null); ' +
        'if ($LASTEXITCODE -eq 0 -and $c) { $c = $c.Trim(); ' +
        '$bases = @((Split-Path $c -Parent), (& git rev-parse --path-format=absolute --show-toplevel 2>$null)); ' +
        '$hit = $false; $mf = $false; ' +
        'foreach ($b in $bases) { if (-not $b) { continue } $b = $b.Trim(); ' +
        'if (Test-Path -LiteralPath (Join-Path $b ''scripts/coord/presence.ps1'')) { $mf = $true } ' +
        '$s = Join-Path $b ''scripts/hooks/announce-session.ps1''; ' +
        'if (Test-Path -LiteralPath $s) { & $s -CommonDir $c; $hit = $true; break } } ' +
        'if (-not $hit -and $mf) { Write-Output ' + "'$notice'" + ' } }'
    )
}

# Timeout 15 on the announce row is the hook's ONLY time bound -- the peer lookup runs in-process by
# design -- so it must comfortably exceed presence.ps1's MEASURED ~1.0 s while staying short enough that
# a hang is not felt as a hang at prompt submit. UserPromptSubmit takes no matcher.
$WIRING = @(
    @{ Event = "SessionStart"; Matcher = $null; Script = "scripts/worktree/session-context.ps1"; Timeout = 30; Msg = "Session coordination"; Marker = $MARKER; Shim = "std" }
    @{ Event = "PreToolUse"; Matcher = "Edit|Write|MultiEdit|NotebookEdit"; Script = "scripts/hooks/collision_gate.ps1"; Timeout = 20; Msg = "Checking for a colliding session"; Marker = $MARKER; Shim = "std" }
    @{ Event = "UserPromptSubmit"; Matcher = $null; Script = "scripts/hooks/announce-session.ps1"; Timeout = 15; Msg = "Announcing to sessions in this repo"; Marker = $ANNOUNCE_MARKER; Shim = "announce" }
)

if ($Only) { $WIRING = @($WIRING | Where-Object { $Only -contains $_.Event }) }
if ($Except) { $WIRING = @($WIRING | Where-Object { $Except -notcontains $_.Event }) }
if (-not $WIRING) { Write-Host "No wiring rows selected."; exit 0 }

function Read-Settings {
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $SettingsPath -Raw
    if (-not $raw.Trim()) { return [ordered]@{} }
    # Fail loudly rather than overwrite: a settings file we cannot parse is one we must not rewrite,
    # because a bad write silently disables EVERY setting in it.
    return ($raw | ConvertFrom-Json -AsHashtable)
}

function Test-IsOurs([hashtable]$Entry, [string]$Marker = $MARKER) {
    foreach ($h in @($Entry.hooks)) { if ([string]$h.command -match [regex]::Escape($Marker)) { return $true } }
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
        $ours = @($groups | Where-Object { $_ -and (Test-IsOurs $_ $w.Marker) })
        $state = if ($ours.Count -gt 0) { "INSTALLED" } else { "missing" }
        if ($ours.Count -gt 0) { $any = $true }
        Write-Host ("  {0,-16} {1,-40} {2}" -f $w.Event, $w.Script, $state)
    }
    Write-Host ""
    if (-not $any) { Write-Host "  Not installed. Run without -Status to wire it up." -ForegroundColor Yellow }
    exit 0
}

# Strip our entries first -- this is both the uninstall path and the idempotency of re-install.
foreach ($w in $WIRING) {
    if ($settings.hooks[$w.Event]) {
        $kept = @(@($settings.hooks[$w.Event]) | Where-Object { $_ -and -not (Test-IsOurs $_ $w.Marker) })
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
                command       = $(if ($w.Shim -eq "announce") { New-AnnounceShimCommand } else { New-ShimCommand $w.Script $w.Marker })
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
        foreach ($w in $WIRING) { Write-Host ("  {0,-16} -> {1}" -f $w.Event, $w.Script) }
        Write-Host ""
        Write-Host "  Takes effect in NEWLY STARTED sessions; existing ones keep the config they booted with."
    }
    Write-Host "  backup: $backup"
    Write-Host ""
}
