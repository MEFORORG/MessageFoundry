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

    NO INSTALLED COPY OF THE SCRIPT. Each hook is a one-line shim that locates the script in a checkout
    and runs it, so the SCRIPT is current everywhere the moment a `git pull` lands -- there is no second
    copy of it to fall behind. This is deliberate: the worktree gate's installer copies its script, and
    running it from a stale checkout has already silently downgraded the live gate once.

    THE SHIM BODY IS A COPY, THOUGH, AND IT DOES GO STALE. This header used to say "there is nothing to
    go stale", which is false about the one thing this file writes: the shim TEXT lands in settings.json,
    so a root wired by an older checkout keeps the older shim until this installer is re-run -- and a
    marker-only check calls that INSTALLED. Measured 2026-08-15 against a fixture: a seat row hand-
    reverted to its pre-fix body (no trailing `exit 0`) reported INSTALLED while that same wired command
    answered rc=1 outside a repo, and a row whose whole body was `# mefor-mail` + `Write-Output 42`
    reported INSTALLED too. -Status therefore COMPARES each wired command against the command THIS
    checkout generates and reports STALE when they differ -- a verdict measured at the moment you ask,
    not a label recorded at some earlier install, so it is still right for a reader who arrives days
    later. A stale row also sets exit code 3, so the divergence reaches a script and not only a reader.

    THE SHIM RESOLVES THE PRIMARY CHECKOUT, not the calling worktree. Coordination is infrastructure
    and must be uniform across sessions. Measured 2026-07-29: a worktree sitting on a branch that
    predated the coordination merge had none of these scripts, so a cwd-resolved shim found nothing
    and exited silently -- that session got no banner and no gate, and nothing reported the absence.
    The primary tracks main, so every session runs the same current code whatever branch it is on.

    WHAT GETS WIRED: the $WIRING table below is the source of record, and -Status prints it per config
    root. It is deliberately NOT restated here. This header used to list three rows while the table
    carried seven, so an operator reading the header could not learn that ONE event, Stop, carries
    three independent hooks -- and that gap is exactly what made the seat marker's removal recipe wrong
    (see $SEAT_MARKER).

    Idempotent: re-running replaces our own entries and leaves every other hook untouched.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Uninstall
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Only UserPromptSubmit -Uninstall
    # ONE row of a multi-row event -- -Only cannot express this, because it selects the EVENT:
    pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Script seat-record -Uninstall
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
    [string[]]$Except,
    # Limit to the rows whose Script matches. -Only filters by EVENT, and an event can carry more than
    # one row: SessionStart carries BOTH the coordination banner and the mail drain. So
    # `-Only SessionStart` silently installs the banner too, which is a different hook with a different
    # blast radius, and there was no way to ask for one tier of one event.
    #
    # That matters because wiring this channel ONE TIER AT A TIME is the deliberate pattern -- the mail
    # drain went live on Stop alone while SessionStart stayed out, for a measured reason (see
    # docs/SESSION-MAIL.md). A switch that cannot express the thing you are actually doing pushes you
    # toward a hand-edit of the user settings file, which is exactly what this script exists to avoid.
    #
    # Substring match, because the rows carry repo-relative paths and 'mail-drain' is what an operator
    # actually types. It composes with -Only and -Except rather than replacing them.
    [string[]]$Script)

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

# A FOURTH marker, for the URGENT mail tier (scripts/hooks/mail-watch.ps1). The comment above names
# "mefor-mail-urgent" as the exact mistake to avoid -- it CONTAINS "mefor-mail", so installing it would
# make Test-IsOurs strip the drain's row and the second installer to run would silently disarm the
# first. "mefor-wake" is contained by none of the other three and contains none of them:
#   mefor-coord / mefor-announce / mefor-mail / mefor-wake   -- pairwise non-containing, checked.
$WAKE_MARKER = "mefor-wake"

# A FIFTH marker, for the seat recorder. Same pairwise rule, re-checked rather than assumed:
#   mefor-coord / mefor-announce / mefor-mail / mefor-wake / mefor-seat
# No one of the five contains another in either direction, so no installer can strip a sibling's row.
# Its own blast radius is small by design -- a Stop hook that fails records nothing that turn and
# costs the session nothing -- and a separate marker is what makes this row independently removable.
#
# THE REMOVAL RECIPE IS `-Script seat-record -Uninstall`. It is NOT `-Only Stop -Uninstall`, which is
# what this comment used to say -- wrong in the one place a 2am operator looks for the remedy. -Only
# selects an EVENT (the -Script parameter above states that rule in full), and Stop carries THREE
# unrelated rows. Measured 2026-08-14 against a fixture settings.json: `-Only Stop -Uninstall` removed
# mefor-mail, mefor-seat AND mefor-wake -- the async mail drain and the whole urgent-mail push tier
# went with the recorder -- while `-Script seat-record -Uninstall` on the same fixture removed
# mefor-seat alone and left the other two standing.
$SEAT_MARKER = "mefor-seat"

# ==================================================================================================
# THE EXIT RULE, SHARED BY EVERY BUILDER BELOW. Stated once here; the other builders point at it
# rather than restating it, and the ONE deliberate exception (the wake row) states only its own half.
#
# EVERY SHIM ENDS WITH A TRAILING `exit 0`, AND SO MUST ANY BUILDER ADDED LATER. Outside a git repo the
# `if ($LASTEXITCODE -eq 0 -and $c)` guard is false, nothing in the body runs, and the last thing the
# shim executed is a FAILED `git rev-parse` -- so `pwsh -Command <shim>` exits 1 with an EMPTY stderr,
# git's message having been eaten by `2>$null`. These entries are user-global and fire in every
# unrelated project on the machine, and one of them is on Stop, at every turn end. The cost is not the
# exit code itself -- it is that a channel crying wolf in every non-checkout folder on the box trains
# the reader to skip it, including the turn it finally carries a missing-script notice.
#
# MEASURED 2026-08-15, one run, one non-git cwd, each installed command run as `pwsh -NoProfile
# -Command <command>`; control in the same run: `git rev-parse --git-common-dir` there exits 128.
#   BEFORE: coord@SessionStart 1, coord@PreToolUse 1, mail@SessionStart 1, mail@Stop 1,
#           announce@UserPromptSubmit 1, seat@Stop 0, wake@Stop 0.    AFTER: all seven 0.
# The suffix had been applied to the SEAT builder alone, so five of the seven rows still cried wolf --
# including the mail drain, which shares Stop with the row that got the fix.
#
# WHAT THE SUFFIX GUARANTEES IS NARROWER THAN "THIS SHIM ALWAYS EXITS 0", AND THE NARROW FORM IS THE
# ONE TO QUOTE. `exit 0` is the last STATEMENT, so it is reached only if control gets there. A
# TERMINATING error inside the body unwinds straight past it: measured in the same lab, a shim whose
# resolved target runs `$ErrorActionPreference='Stop'; throw` answers rc=1 WITH the suffix in place,
# under pwsh 7 and under Windows PowerShell 5.1 alike. So the guarantee is exactly this -- THE SHIM
# DOES NOT REPORT A FAILURE OF ITS OWN PLUMBING, meaning the `git rev-parse` that fails outside a repo,
# which is the one that fires constantly. A real fault inside a target still surfaces.
#
# THE RUNNER IS PART OF THAT MEASUREMENT, so never quote the exit codes without it. Under `powershell`
# (Windows PowerShell 5.1 -- the literal string in each row's `shell` key) the non-git case answered 0
# even BEFORE the suffix, because 5.1 does not map a failed native command onto the process exit code
# the way pwsh 7 does. The suffix costs nothing there and fixes pwsh 7, which is what a hand-run or a
# pwsh-configured harness uses.
#
# BLANKET `exit 0` HERE AND ON THE ANNOUNCE BUILDER; ONLY New-WakeShimCommand FORWARDS. For the wake
# row the exit code IS the payload -- a rewake fires on 2 and only on 2. Every other wired target
# disclaims it: grepped 2026-08-15, collision_gate.ps1, session-context.ps1, mail-drain.ps1,
# announce-session.ps1 and seat-record.ps1 contain no `exit` other than `exit 0` on any path.
# collision_gate.ps1 fails OPEN by design and denies through JSON on stdout rather than an exit code,
# and a UserPromptSubmit failure can block the user's prompt outright. Nothing is lost by swallowing
# either: measured, the un-suffixed shared shim answered rc=1 for a target that exited 3, so it never
# forwarded a code faithfully to begin with -- it only ever turned "something happened" into "failed".
# ==================================================================================================

# The shim. No installed copy of the SCRIPT: it locates the script in a checkout and runs it, so a
# `git pull` updates the hook everywhere with nothing to fall stale. The shim TEXT is a copy and CAN
# fall stale -- see the header, and -Status, which measures exactly that.
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
        'if (Test-Path -LiteralPath $s) { & $s; break } } }' + "`n" +
        'exit 0'
    )
}

# The WAKE shim, for the asyncRewake tier. It differs from the shared shim in exactly one way, and that
# one way is the whole reason it is a separate builder: IT PROPAGATES THE SCRIPT'S EXIT CODE.
#
# WHY THAT IS LOAD-BEARING RATHER THAN TIDY. A rewake fires on exit code 2 and ONLY on exit code 2. The
# shared shim ends `& $s; break`, which runs the script and then lets the hook process exit 0 -- so a
# watcher that found mail and exited 2 is reported as a clean no-op and its payload is DISCARDED. The
# failure is completely silent from the session's side: the hook ran, the output was captured, nothing
# arrived. scripts/hooks/mail-watch.ps1 records that this cost a full debug cycle to find, and states
# that the installer is the component responsible for emitting the suffix. This is that emission.
#
# `exit $LASTEXITCODE` sits INSIDE the Test-Path branch, immediately after the call, rather than at the
# end of the command. Outside a repo, or with no checkout carrying the script, nothing ran and there is
# no exit code to forward -- so the fall-through `exit 0` is reached instead. Forwarding an unset or
# stale $LASTEXITCODE from a hook that never ran is how a rewake fires on a session with no mail.
function New-WakeShimCommand([string]$RelativeScript, [string]$Marker = $WAKE_MARKER) {
    return (
        "# $Marker`n" +
        '$c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null); ' +
        'if ($LASTEXITCODE -eq 0 -and $c) { ' +
        '$bases = @((Split-Path $c.Trim() -Parent), (& git rev-parse --path-format=absolute --show-toplevel 2>$null)); ' +
        'foreach ($b in $bases) { ' +
        'if (-not $b) { continue } ' +
        "`$s = Join-Path `$b.Trim() '$RelativeScript'; " +
        'if (Test-Path -LiteralPath $s) { & $s; exit $LASTEXITCODE } } }' + "`n" +
        'exit 0'
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
        'if (-not $hit -and $mf) { Write-Output ' + "'$notice'" + ' } }' + "`n" +
        'exit 0'
    )
}

# The SEAT shim. Deliberately NOT Shim='std', and the reason is the defect this whole layer is built
# to expose. The std shim is Test-Path-then-run: when the script is absent it produces ZERO BYTES and
# exits 0, which is byte-identical to a healthy hook that had nothing to do. install-coordination.ps1
# already records that exact class -- "byte-identical to a healthy hook with no peers, which is how a
# wired-but-resolving-nothing hook survived for weeks".
#
# THAT MATTERS MORE HERE THAN ANYWHERE ELSE. The shim resolves against the PRIMARY checkout's working
# tree, which tracks main and is routinely behind it. Until this commit lands on main, every seat's
# recorder resolves nothing -- and with the std shim the fleet would look quiet and healthy while
# recording nothing at all, in every session, with every settings.json reporting green.
#
# $mf gates the notice on "this is a MessageFoundry checkout": this file is user-global and runs in
# every unrelated project on the machine, and a notice about a missing MEFOR script in someone's
# unrelated repo is noise, not a signal.
#
# IT ENDS WITH A BLANKET `exit 0` -- the shared exit rule above, which every builder now follows. What
# is specific to THIS row is why the blanket form rather than the wake row's `exit $LASTEXITCODE`:
# scripts/hooks/seat-record.ps1 states "THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 unconditionally"
# and reports trouble through seats/.writer-errors.txt and a stdout notice instead, so there is no exit
# code here worth forwarding. Measured against a target rigged to exit 3: this shim answered 0 before
# the suffix and answers 0 after it, while the wake builder answered 3 on the same target in the same
# run -- which is what establishes that the measurement could see a non-zero exit at all.
function New-SeatShimCommand {
    $notice = "[seat] scripts/hooks/seat-record.ps1 is missing from this checkout -- the seat recorder is wired but resolving nothing, so this session is NOT being recorded and a cold start would not see it."
    return (
        "# $SEAT_MARKER`n" +
        '$c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null); ' +
        'if ($LASTEXITCODE -eq 0 -and $c) { $c = $c.Trim(); ' +
        '$bases = @((Split-Path $c -Parent), (& git rev-parse --path-format=absolute --show-toplevel 2>$null)); ' +
        '$hit = $false; $mf = $false; ' +
        'foreach ($b in $bases) { if (-not $b) { continue } $b = $b.Trim(); ' +
        'if (Test-Path -LiteralPath (Join-Path $b ''scripts/coord/presence.ps1'')) { $mf = $true } ' +
        '$s = Join-Path $b ''scripts/hooks/seat-record.ps1''; ' +
        'if (Test-Path -LiteralPath $s) { & $s; $hit = $true; break } } ' +
        'if (-not $hit -and $mf) { Write-Output ' + "'$notice'" + ' } }' + "`n" +
        'exit 0'
    )
}

# ONE resolution of "which builder does this row use", called by BOTH the install path and -Status.
#
# IT IS A FUNCTION AND NOT A SWITCH IN TWO PLACES FOR A REASON THAT IS THE WHOLE POINT OF THE -Status
# PARITY CHECK. If -Status carried its own copy of the switch, the two could drift -- and a drift here
# is invisible in the worst way: -Status would compare each wired row against a command that nothing
# installs, so every root would read STALE while every root was in fact current, or the reverse. The
# comparison is only worth anything if the expectation comes from the same code that does the writing.
function Get-ShimCommand([hashtable]$Row) {
    switch ($Row.Shim) {
        "announce" { return (New-AnnounceShimCommand) }
        "seat" { return (New-SeatShimCommand) }
        "wake" { return (New-WakeShimCommand $Row.Script $Row.Marker) }
        default { return (New-ShimCommand $Row.Script $Row.Marker) }
    }
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
    # Stop, not UserPromptSubmit: the recorder is exercised at ACCOUNT-SWITCH frequency (days), so a
    # per-prompt spawn would be a standing tax for a rare path. Timeout 25 covers seat.ps1's git calls
    # -- roughly ten cheap plumbing commands plus a `stash create` -- with room on a loaded box.
    @{ Event = "Stop"; Matcher = $null; Script = "scripts/hooks/seat-record.ps1"; Timeout = 25; Msg = "Recording this seat's episode"; Marker = $SEAT_MARKER; Shim = "seat" }

    # The URGENT tier: mail-watch.ps1, armed at Stop, which is the moment the session goes IDLE.
    #
    # WHY Stop AND NOT SessionStart. The drain above already covers arrival-before-you-got-here. The gap
    # this closes is mail landing while a session sits at a prompt with nobody typing -- measured, the
    # drain's next delivery point is the END of the session's NEXT turn, so mail waits for a human to
    # interact before it is shown. Arming at Stop puts the watcher live exactly across the idle window.
    #
    # THE TWO FLAGS ARE BOTH REQUIRED AND FOR DIFFERENT REASONS. `asyncRewake` is what injects the
    # output on exit 2. `async` must be set ALONGSIDE it rather than relied on as implied: the binary
    # gates backgrounding on `isInteractive || hasStreamingInput`, so in a non-interactive run
    # (claude -p) asyncRewake alone falls through to the SYNCHRONOUS path and this watcher would block
    # the session for its full timeout. Setting async forces the background branch unconditionally.
    #
    # TIMEOUT 1200 AGAINST THE SCRIPT'S OWN 900s WAIT. The script requires its wait to stay comfortably
    # under the hook timeout, because a watcher killed at timeout is indistinguishable from one that
    # found nothing. 300s of headroom, not a round number chosen to look tidy.
    #
    # ONE-SHOT, STATED RATHER THAN PAPERED OVER: the rewake belongs to the process Claude Code spawned
    # and is tracked by hook id, so the watcher cannot re-arm itself. Each Stop arms one. After a
    # delivery the session falls back to the drain until its next turn boundary.
    @{ Event = "Stop"; Matcher = $null; Script = "scripts/hooks/mail-watch.ps1"; Timeout = 1200; Msg = "Watching for urgent mail"; Marker = $WAKE_MARKER; Shim = "wake"; Async = $true }
)

# The unfiltered table, kept so a filter that matches nothing can tell the operator what DOES exist.
# Naming the real events and scripts turns a dead end into a correction; without it the message can
# only say that nothing matched, which is the same information the exit code already carries.
$WIRING_ALL = $WIRING

# SPLIT ON COMMAS, BECAUSE `pwsh -File` HANDS EVERY ARGUMENT OVER AS A STRING. The documented
# invocation in .EXAMPLE is the -File form, and it binds a multi-value switch as ONE element:
# `-Only PreToolUse,UserPromptSubmit` arrives as the single string "PreToolUse,UserPromptSubmit",
# `-contains` then matches nothing, and the run selected zero rows while reporting success. Measured
# 2026-08-06 -- it printed "No wiring rows selected" and exited 0, which reads as "done". Splitting
# here makes the documented form mean what it looks like it means; passing a real array in-process
# still works, because splitting a single-element array on a character it does not contain is a no-op.
# Only the identifier-shaped switches are split. -SettingsPath is NOT: a Windows path may legally
# contain a comma, and silently cutting one in half would be a worse bug than the one being fixed.
function Split-Csv([string[]]$Values) {
    if (-not $Values) { return @() }
    return @($Values | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
$Only = Split-Csv $Only
$Except = Split-Csv $Except
$Script = Split-Csv $Script

if ($Only) { $WIRING = @($WIRING | Where-Object { $Only -contains $_.Event }) }
if ($Except) { $WIRING = @($WIRING | Where-Object { $Except -notcontains $_.Event }) }
if ($Script) {
    $WIRING = @($WIRING | Where-Object {
            $row = $_
            @($Script | Where-Object { $row.Script -like "*$_*" }).Count -gt 0
        })
}
# NONZERO, NOT exit 0. A filter that matches nothing is a user error -- a misspelled event, a -Script
# that hits no row -- and exiting 0 made it indistinguishable from a successful install. That is the
# silent-no-op shape this script exists to report on rather than commit: the operator sees a clean
# exit and believes the roots were wired. Naming what was asked for is the difference between "there
# was nothing to do" and "you asked for something that does not exist".
if (-not $WIRING) {
    $asked = @()
    if ($Only) { $asked += "-Only $($Only -join ',')" }
    if ($Except) { $asked += "-Except $($Except -join ',')" }
    if ($Script) { $asked += "-Script $($Script -join ',')" }
    Write-Host ""
    Write-Host "NO WIRING ROWS MATCHED $($asked -join ' ') -- nothing was examined and nothing was written." -ForegroundColor Yellow
    Write-Host "  Known events : $((($WIRING_ALL | ForEach-Object { $_.Event }) | Sort-Object -Unique) -join ', ')"
    Write-Host "  Known scripts: $((($WIRING_ALL | ForEach-Object { $_.Script }) | Sort-Object -Unique) -join ', ')"
    Write-Host ""
    exit 2
}

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
#
# INSTALLED IS A MEASUREMENT, NOT A LABEL. It used to be "a row carrying our marker exists", which is a
# claim about something somebody wrote at some earlier install -- and the marker is the one part of the
# shim that never changes. So a row wired by an older checkout, or hand-edited, or reduced to the marker
# plus a `Write-Output`, all read INSTALLED. That is how a fleet ends up half-wired with nothing saying
# so, and it is worst for the payload this file actually delivers, which is shim TEXT copied into
# settings.json. Each row is now compared against what THIS checkout generates for it (Get-ShimCommand,
# the same call the install path makes) and reported as one of:
#   MISSING   -- no row carries the marker on that event.
#   INSTALLED -- every row carrying the marker is byte-identical to what this checkout would write.
#   STALE     -- the marker is there and the command is not ours-as-of-now. Re-run the installer.
# The comparison re-derives the expectation from the working tree at the moment you ask, so it is still
# correct for a reader who runs it days after the install -- there is no recorded verdict to age out.
#
# scripts/coord/install-git-hooks.ps1 already had this parity check for the payloads it copies, and
# tests/test_installed_coord_hooks.py records the same "reported INSTALLED over a payload that was in
# fact stale" measurement against it. This is that check, on this side.
if ($Status) {
    Write-Host ""
    Write-Host "Coordination hooks, as of $([DateTime]::UtcNow.ToString('o'))"
    Write-Host "Roots examined: $($SettingsPath.Count)"
    $staleRows = @()
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
            $expected = Get-ShimCommand $w
            $wired = @()
            foreach ($entry in @($s.hooks[$w.Event])) {
                if (-not $entry) { continue }
                foreach ($h in @($entry.hooks)) {
                    $cmd = [string]$h.command
                    if ($cmd -match [regex]::Escape($w.Marker)) { $wired += $cmd }
                }
            }
            $current = @($wired | Where-Object { $_ -eq $expected }).Count
            $state =
            if ($wired.Count -eq 0) { "MISSING" }
            elseif ($current -eq $wired.Count) { if ($wired.Count -eq 1) { "INSTALLED" } else { "INSTALLED ($($wired.Count) COPIES)" } }
            elseif ($current -eq 0) { "STALE" }
            else { "STALE ($current of $($wired.Count) current)" }
            Write-Host ("    {0,-16} {1,-38} {2}" -f $w.Event, $w.Script, $state)
            if ($state.StartsWith("STALE")) {
                $staleRows += ("{0}  {1}  {2}" -f $p, $w.Event, $w.Script)
                Write-Host "      wired, but the command is NOT what this checkout generates" -ForegroundColor Yellow
            }
        }
    }
    Write-Host ""
    if ($staleRows.Count -gt 0) {
        Write-Host ("STALE: {0} wired row(s) carry a command this checkout no longer generates." -f $staleRows.Count) -ForegroundColor Yellow
        foreach ($r in $staleRows) { Write-Host "      $r" }
        Write-Host "  A marker-only check calls these INSTALLED, and they run the OLD shim until refreshed."
        Write-Host "  Re-run this installer with no arguments to rewrite them from this checkout."
        Write-Host ""
        # Exit 3, distinct from 2 (a filter that matched nothing) and 1 (a root that failed to write),
        # so a caller can tell "wired but stale" from the other two without parsing this text.
        exit 3
    }
    exit 0
}

# --- Name the rows BEFORE removing them ----------------------------------------------------------
# A REMOVAL THAT TAKES MORE THAN THE OPERATOR NAMED HAS TO SAY SO, BEFORE IT WRITES. -Only selects an
# EVENT, and Stop carries three independent hooks -- the mail drain, the seat recorder and the urgent-
# mail watcher -- so `-Only Stop -Uninstall` disarms two controls nobody mentioned. Measured
# 2026-08-14 on a fixture settings.json: all three markers went, and the entire receipt was
# "REMOVED <path>" plus a root count, naming none of them. The operator's natural check afterwards,
# `-Status -Only Stop`, then shows three rows MISSING, which reads as success to someone who asked for
# a removal.
#
# This is the CLASS fix rather than the instance: it also keeps the two -Only recipes elsewhere in this
# file honest. They are true today only because their event happens to carry one row, and nothing
# enforces that -- the day either event gains a sibling, this block starts naming what would go.
if ($Uninstall) {
    $markers = @($WIRING | ForEach-Object { $_.Marker } | Sort-Object -Unique)
    if ($markers.Count -gt 1) {
        Write-Host ""
        Write-Host ("REMOVING {0} ROW(S) ACROSS {1} INDEPENDENT HOOKS -- named here BEFORE anything is written:" -f $WIRING.Count, $markers.Count) -ForegroundColor Yellow
        foreach ($w in $WIRING) { Write-Host ("    {0,-16} {1,-38} {2}" -f $w.Event, $w.Script, $w.Marker) }
        Write-Host "  If you meant ONE of these, -Script <part of the script path> selects a single row; -Only cannot."
        Write-Host "  That list is what this run SELECTED, read off the wiring table before looking at any root."
        Write-Host "  What it actually took is counted per root below, and the two differ whenever a row is absent."
        Write-Host ""
    }
}

# --- Install / uninstall, once per root ----------------------------------------------------------
# One root failing must not stop the others. A throw part-way through used to leave the machine in a
# state nobody wrote down: some roots wired, some not, and no record of which.
#
# EVERY ROOT GETS EXACTLY ONE OUTCOME LINE, AND THE WORD ON IT IS EARNED. Before this, a root the
# operator PREVIEWED (-WhatIf) or DECLINED (-Confirm answered No) printed nothing at all, so the sole
# difference between a preview and a real removal was the ABSENCE of a line -- while the trailing prose
# still said rows had been removed. An absence is not a receipt; it is the reader being asked to notice
# something that was not printed.
$failed = @()
$wroteRoots = @()
$previewRoots = @()
# MEASURED, per selected row: how many entries the strip loop actually dropped. Kept in TWO
# accumulators because a preview measures the same thing and changes nothing on disk, and a receipt
# that adds the two together is back to claiming a removal that did not happen.
$removedWritten = [int[]]::new($WIRING.Count)
$removedPreview = [int[]]::new($WIRING.Count)
foreach ($path in $SettingsPath) {
    try {
        $settings = Read-Settings $path
        if (-not $settings.hooks) { $settings.hooks = [ordered]@{} }

        # Strip our entries first -- this is both the uninstall path and the idempotency of re-install.
        #
        # COUNT WHAT COMES OUT. The loop used to keep only $kept and discard the removed set, so there
        # was no number anywhere for "how many rows did this actually take" -- and the receipt filled
        # the gap from the static $WIRING table instead. Measured 2026-08-15 on a fixture whose only
        # hook was a foreign row: `-Only Stop -Uninstall` removed nothing and still printed the full
        # three-row inventory under "REMOVED", byte-comparable to the run where three rows really went.
        $rootRemoved = [int[]]::new($WIRING.Count)
        for ($i = 0; $i -lt $WIRING.Count; $i++) {
            $w = $WIRING[$i]
            if ($settings.hooks[$w.Event]) {
                $present = @(@($settings.hooks[$w.Event]) | Where-Object { $_ })
                $kept = @($present | Where-Object { -not (Test-IsOurs $_ $w.Marker) })
                $rootRemoved[$i] = $present.Count - $kept.Count
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
                        command       = (Get-ShimCommand $w)
                        shell         = "powershell"
                        timeout       = $w.Timeout
                        statusMessage = $w.Msg
                    }
                )
                # The async/rewake pair is emitted ONLY for rows that ask for it, so every existing row
                # keeps its exact previous shape and a re-install is a no-op for them. Adding the keys
                # unconditionally would rewrite four hooks that have no business being backgrounded --
                # a PreToolUse gate that returns asynchronously is a gate that does not gate.
                if ($w.Async) {
                    $entry.hooks[0].async = $true
                    $entry.hooks[0].asyncRewake = $true
                }
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
            $wroteRoots += $path
            for ($i = 0; $i -lt $WIRING.Count; $i++) { $removedWritten[$i] += $rootRemoved[$i] }
            if ($Uninstall) {
                Write-Host ("  REMOVED   {0} row(s)  {1}" -f (($rootRemoved | Measure-Object -Sum).Sum), $path)
            }
            else { Write-Host ("  INSTALLED {0}" -f $path) }
        }
        else {
            # ShouldProcess said no: -WhatIf, or a -Confirm the operator declined. NOTHING was written
            # to this root, and saying so here is the whole fix -- PowerShell's own "What if:" line is
            # about the intent, not about what the file now holds.
            $previewRoots += $path
            for ($i = 0; $i -lt $WIRING.Count; $i++) { $removedPreview[$i] += $rootRemoved[$i] }
            if ($Uninstall) {
                Write-Host ("  PREVIEW   {0} row(s) of ours are present and would go -- NOTHING WRITTEN  {1}" -f (($rootRemoved | Measure-Object -Sum).Sum), $path) -ForegroundColor Yellow
            }
            else { Write-Host ("  PREVIEW   NOTHING WRITTEN  {0}" -f $path) -ForegroundColor Yellow }
        }
    }
    catch {
        $failed += [pscustomobject]@{ Path = $path; Error = $_.Exception.Message }
        Write-Host ("  FAILED    {0}  -- {1}" -f $path, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ""
# "succeeded" USED TO COUNT A PREVIEW AS A SUCCESS, which is the same lie one level up: a -WhatIf run
# over five roots reported five successes and wrote nothing. The three counters below are disjoint and
# each names what happened to the file.
Write-Host ("Roots examined: {0}   written: {1}   previewed (NOTHING WRITTEN): {2}   failed: {3}   as of {4}" -f `
        $SettingsPath.Count, $wroteRoots.Count, $previewRoots.Count, $failed.Count, [DateTime]::UtcNow.ToString('o'))
# THE ROW INVENTORY IS PRINTED ON BOTH PATHS, AND ON THE UNINSTALL PATH IT CARRIES A MEASURED COUNT.
# It used to be gated on `-not $Uninstall`, so a removal reported only that something had been removed
# and from how many roots -- never WHICH rows. Printing the rows closed that half and left the other
# open: the rows came from the static $WIRING table, so the receipt was identical whether the run took
# three rows, one, or none, and identical again under -WhatIf where it takes none by construction.
# Every number below is counted by the strip loop above, against each file as this run read it.
foreach ($i in 0..($WIRING.Count - 1)) {
    $w = $WIRING[$i]
    $tail = ""
    if ($Uninstall) {
        if ($wroteRoots.Count -gt 0) {
            $tail = "  removed {0}" -f $removedWritten[$i]
            if ($removedPreview[$i] -gt 0) { $tail += ("   (+{0} matched in a root nothing was written to)" -f $removedPreview[$i]) }
        }
        else { $tail = "  would remove {0}" -f $removedPreview[$i] }
    }
    Write-Host ("  {0,-16} -> {1,-38} [{2}]{3}" -f $w.Event, $w.Script, $w.Marker, $tail)
}
Write-Host ""
if ($Uninstall) {
    if ($wroteRoots.Count -gt 0) {
        Write-Host "  Those counts are MEASURED: each is the number of entries this run actually dropped from"
        Write-Host "  the roots it wrote. A row showing 0 was examined and was not there -- which is the case"
        Write-Host "  this receipt could not previously distinguish from a removal. Any hook not listed was"
        Write-Host "  left alone."
        Write-Host "  Takes effect in NEWLY STARTED sessions; existing ones keep the config they booted with."
    }
    if ($previewRoots.Count -gt 0) {
        Write-Host ("  {0} of {1} root(s) were a PREVIEW (-WhatIf, or a -Confirm you declined). NOTHING was" -f $previewRoots.Count, $SettingsPath.Count) -ForegroundColor Yellow
        Write-Host "  written there and every hook is still wired exactly as it was. Their counts above are"
        Write-Host "  what a real run would have dropped, measured against the file as it stands now."
    }
}
else {
    if ($wroteRoots.Count -gt 0) {
        Write-Host "  Takes effect in NEWLY STARTED sessions; existing ones keep the config they booted with."
        Write-Host "  A root marked INSTALLED above is a root whose settings FILE now carries the entry. That is"
        Write-Host "  not the same as a hook that FIRED -- confirm with a session started under that login."
    }
    if ($previewRoots.Count -gt 0) {
        Write-Host ("  {0} of {1} root(s) were a PREVIEW (-WhatIf, or a -Confirm you declined). NOTHING was" -f $previewRoots.Count, $SettingsPath.Count) -ForegroundColor Yellow
        Write-Host "  written there. The rows above are what a real run WOULD write, not what any file carries."
    }
}
Write-Host ""
if ($failed.Count -gt 0) { exit 1 }
