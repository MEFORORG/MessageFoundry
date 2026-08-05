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
    # Settings file(s) to modify. Tests point this at a fixture instead of the real user settings.
    #
    # DEFAULT IS EVERY CONFIG ROOT, NOT JUST ~/.claude, AND THAT CHANGE FIXES A MEASURED HOLE.
    # This script's own rationale used to be that user level "is per-machine and loads in every
    # worktree". That premise is false on a machine with more than one login: a config root owns its
    # OWN settings.json, and a session reads the one belonging to the root it authenticated against.
    # Measured 2026-08-05: five roots existed (~/.claude plus .claude-account-1..4); the coordination
    # hooks were present in ONE of them; MessageFoundry sessions had really run under accounts 1, 2 and
    # 3 (transcript directories under each); and two multi-megabyte transcripts from accounts 1 and 2
    # contained ZERO announce firings. Those sessions ran with no banner, no collision gate and no
    # announce, and nothing reported the absence.
    #
    # This matters most for the surface the mail channel exists to reach: the VS Code extension
    # launches under its own login, and on this host the live VS Code sessions were on account-4 while
    # the Desktop sessions were on the default root. Wiring only ~/.claude would leave the delivery hook
    # absent from exactly the sessions that cannot be reached any other way.
    #
    # scripts/worktree/install-gate.ps1 already loops the roots this way; this is that precedent applied
    # to the coordination hooks.
    [string[]]$SettingsPath,
    # Limit the operation to these events (install, uninstall and -Status alike). Announce lives on its
    # own event, so `-Only UserPromptSubmit -Uninstall` removes it WITHOUT disarming the collision gate
    # or the SessionStart banner. Without this the only 2am remedy is a hand-edit of the user settings.
    [string[]]$Only,
    [string[]]$Except
)

$ErrorActionPreference = "Stop"

# Every config root that should carry the coordination hooks.
#
# THE DISCRIMINATOR IS A REGEX ON THE NAME, NOT A GLOB, AND NOT "HAS A settings.json".
# Measured on this host: `~/.claude-account-2.lock` is a DIRECTORY, not a lock file, and it contains a
# settings.json of its own. A `.claude-account-*` glob adopts it; so does any "looks like a config root
# because it has settings" test. Writing hooks into a stale artifact is invisible until someone wonders
# why a root they never use keeps reappearing. `Get-ClaudeConfigRoots` (session-registry.ps1) filters on
# a `sessions/` subdir instead, which is right for READING a roster but wrong here: a root that exists
# but has not run a session yet has no sessions/ and still needs wiring, because the first session it
# runs is exactly the one that would come up uncoordinated.
function Get-CoordSettingsPaths {
    $home_ = $env:USERPROFILE
    $roots = @(
        Get-ChildItem -LiteralPath $home_ -Directory -Filter ".claude*" -Force -EA SilentlyContinue |
            Where-Object { $_.Name -match '^\.claude$|^\.claude-account-\d+$' } |
            ForEach-Object { $_.FullName }
    )
    if ($roots.Count -eq 0) { $roots = @((Join-Path $home_ ".claude")) }
    return @($roots | ForEach-Object { Join-Path $_ "settings.json" })
}

if (-not $SettingsPath -or $SettingsPath.Count -eq 0) { $SettingsPath = Get-CoordSettingsPaths }

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

# A THIRD marker for the async mail drain. Chosen so that NO marker is a substring of another in either
# direction -- Test-IsOurs is a substring match, so "mefor-mail" and a hypothetical "mefor-mail-urgent"
# would strip each other and the second one to be installed would silently delete the first. Check any
# future marker against all three before adding it.
#   mefor-coord / mefor-announce / mefor-mail   -- pairwise non-containing.
$MAIL_MARKER = "mefor-mail"

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
    # The async mail drain, on TWO events and deliberately not on PreToolUse.
    #   SessionStart -- mail that was waiting before you arrived.
    #   Stop         -- mail that landed during the turn. The docs are explicit that injecting at Stop
    #                   resumes rather than ends the conversation, so the session can act on it.
    # Measured on this repo's recent transcripts: 19.0 tool calls per turn at the mean. A PreToolUse
    # matcher would pay the ~366ms spawn ~19 times per turn for the same practical latency, which is
    # exactly the standing tax that keeps steer-inject opt-in. Stop pays it once.
    @{ Event = "SessionStart"; Matcher = $null; Script = "scripts/hooks/mail-drain.ps1"; Timeout = 20; Msg = "Checking session mail"; Marker = $MAIL_MARKER; Shim = "std" }
    @{ Event = "Stop"; Matcher = $null; Script = "scripts/hooks/mail-drain.ps1"; Timeout = 20; Msg = "Checking session mail"; Marker = $MAIL_MARKER; Shim = "std" }
)

if ($Only) { $WIRING = @($WIRING | Where-Object { $Only -contains $_.Event }) }
if ($Except) { $WIRING = @($WIRING | Where-Object { $Except -notcontains $_.Event }) }
if (-not $WIRING) { Write-Host "No wiring rows selected."; exit 0 }

function Read-Settings([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $Path -Raw
    if (-not $raw.Trim()) { return [ordered]@{} }
    # Fail loudly rather than overwrite: a settings file we cannot parse is one we must not rewrite,
    # because a bad write silently disables EVERY setting in it.
    return ($raw | ConvertFrom-Json -AsHashtable)
}

function Test-IsOurs([hashtable]$Entry, [string]$Marker = $MARKER) {
    foreach ($h in @($Entry.hooks)) { if ([string]$h.command -match [regex]::Escape($Marker)) { return $true } }
    return $false
}

# --- Status: report EVERY root, and report the ones with nothing as loudly as the ones with something.
# A per-root breakdown is the point. A single aggregated "INSTALLED" is what let a four-root hole sit
# unnoticed: the root you happen to be running under says yes, and nothing asks about the others.
if ($Status) {
    Write-Host ""
    Write-Host "Coordination hooks, as of $([DateTime]::UtcNow.ToString('o'))"
    Write-Host "Roots examined: $($SettingsPath.Count)"
    foreach ($p in $SettingsPath) {
        $s = $null
        try { $s = Read-Settings $p } catch {
            Write-Host ""
            Write-Host "  $p" -ForegroundColor Yellow
            Write-Host "    UNREADABLE -- cannot report on this root: $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }
        if (-not $s.hooks) { $s.hooks = [ordered]@{} }
        Write-Host ""
        Write-Host "  $p"
        foreach ($w in $WIRING) {
            $ours = @(@($s.hooks[$w.Event]) | Where-Object { $_ -and (Test-IsOurs $_ $w.Marker) })
            $state = if ($ours.Count -gt 0) { "INSTALLED" } else { "MISSING" }
            Write-Host ("    {0,-16} {1,-38} {2}" -f $w.Event, $w.Script, $state)
        }
    }
    Write-Host ""
    exit 0
}

# --- Install / uninstall, once per root ----------------------------------------------------------
# One root failing must not stop the others. A throw part-way through used to leave the machine in a
# state nobody wrote down: some roots wired, some not, and no record of which.
$failed = @()
foreach ($path in $SettingsPath) {
    try {
        $settings = Read-Settings $path
        if (-not $settings.hooks) { $settings.hooks = [ordered]@{} }

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

        $backup = "$path.bak-coord"
        if ($PSCmdlet.ShouldProcess($path, $(if ($Uninstall) { "remove coordination hooks" } else { "install coordination hooks" }))) {
            if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $backup -Force }
            $json = $settings | ConvertTo-Json -Depth 12
            # Validate what we are about to write BEFORE replacing the file. A malformed settings.json
            # does not error at startup -- it silently disables every setting in it, which is the worst
            # failure mode here, and it is worst of all in a root we cannot test by starting a session.
            try { $null = $json | ConvertFrom-Json } catch { throw "generated settings JSON is invalid: $_" }
            Set-Content -LiteralPath $path -Value $json -Encoding UTF8
            Write-Host ("  {0}  {1}" -f $(if ($Uninstall) { "REMOVED " } else { "INSTALLED" }), $path)
        }
    }
    catch {
        $failed += [pscustomobject]@{ Path = $path; Error = $_.Exception.Message }
        Write-Host ("  FAILED    {0}  -- {1}" -f $path, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host ("Roots examined: {0}   succeeded: {1}   failed: {2}   as of {3}" -f `
        $SettingsPath.Count, ($SettingsPath.Count - $failed.Count), $failed.Count, [DateTime]::UtcNow.ToString('o'))
if (-not $Uninstall) {
    foreach ($w in $WIRING) { Write-Host ("  {0,-16} -> {1}" -f $w.Event, $w.Script) }
    Write-Host ""
    Write-Host "  Takes effect in NEWLY STARTED sessions; existing ones keep the config they booted with."
    Write-Host "  A root listed above is a root whose settings FILE now carries the entry. That is not the"
    Write-Host "  same as a hook that FIRED -- confirm with a session started under that login."
}
Write-Host ""
if ($failed.Count -gt 0) { exit 1 }
