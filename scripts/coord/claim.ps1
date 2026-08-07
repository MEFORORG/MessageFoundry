<#
.SYNOPSIS
    Claim a piece of WORK, atomically, so two concurrent sessions cannot build the same thing twice.

.DESCRIPTION
    `alloc.ps1` stops two sessions taking the same ADR/BACKLOG *number*. This stops them doing the same
    *work* -- a different failure, and one that has cost real rework here. On 2026-07-24 three sessions
    independently fixed the same npm advisory; two of the three PRs were closed as duplicates, and the one
    that merged had NOT tested the failure mode the others found, so it put a latent break on main.

    A claim is a free-text KEY, deliberately not just a backlog number:

        claim.ps1 -Take 105                          # a numbered backlog item
        claim.ps1 -Take npm-audit-brace-expansion    # ad-hoc work that has no number

    The number form is what the commit-msg gate enforces (see scripts/hooks/claim_check.py). The free-text
    form is what catches the case that actually bit us -- unnumbered work nobody thought to coordinate.

    Same test-and-set as alloc.ps1, for the same reason: it claims by EXCLUSIVELY CREATING
    <git-common-dir>/mefor-coord/claims/<key>.json, an atomic NTFS operation. A read-modify-write on a
    shared list is not an option (PowerShell was measured silently losing 4 of 8 concurrent writes).

    Claims are ADVISORY for free-text keys and ENFORCED for numbered ones. Neither can stop a session that
    refuses to look; what they buy is that the collision becomes visible BEFORE the work, not after.

    Releasing is manual and claims do NOT expire: an abandoned claim is a stale note, whereas an
    auto-expiring one silently re-opens the race it exists to prevent. `-List` reports each holder's
    LIVENESS -- worktree gone, or hours since its last commit -- not the claim's age. Age was the
    original signal and it was actively misleading: a 21h claim whose holder had committed two minutes
    earlier was labelled STALE and recommended for release.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\claim.ps1 -Take 105 -Note "corepoint xml importer"
    pwsh -NoProfile -File scripts\coord\claim.ps1 -List
    pwsh -NoProfile -File scripts\coord\claim.ps1 -Release 105
#>
[CmdletBinding()]
param(
    # Claim this key for THIS worktree. Idempotent: re-taking a key you already hold refreshes its note
    # and branch in place (never dropping the claim), rather than failing.
    [string]$Take,
    # Release a claim this worktree holds.
    [string]$Release,
    # Show every active claim (default when no other switch is given).
    [switch]$List,
    # What the work is -- recorded so a sibling session sees WHY the key is taken.
    [string]$Note,
    # Release a claim held by ANOTHER worktree (for a session that died without releasing).
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Anchored on the SCRIPT, not the current directory -- the reasoning is written out once, at the head of
# alloc.ps1 (BACKLOG #1060). It applies here identically and was found here by inspection rather than by
# a second reproduction: this file recorded `worktree = $repo` from the same unanchored call, so an
# absolute `-File` invocation from another worktree took the claim in the caller's name. A claim is
# advisory for free-text keys and ENFORCED for numbered ones by scripts/hooks/claim_check.py, which reads
# the repo from cwd correctly because it runs as a commit hook -- cwd IS the committing worktree there.
# Hook right, tool wrong, and only the tool can be invoked from somewhere else.
$repo = (& git -C $PSScriptRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
if (-not $repo) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }
$repo = $repo.Trim()
$common = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
$claims = Join-Path $common "mefor-coord/claims"
New-Item -ItemType Directory -Force -Path $claims | Out-Null

# A key is free text but becomes a FILENAME, so fold it to a safe, case-insensitive form. The original is
# kept inside the json so `-List` can show what the human actually typed.
function ConvertTo-KeyFile([string]$Key) {
    $safe = ($Key.Trim().ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim('-')
    if (-not $safe) { throw "Key '$Key' reduces to nothing usable -- pick something with letters or digits." }
    $safe
}

# ConvertFrom-Json SILENTLY COERCES an ISO-8601 string into a [datetime], so `[string]$c.claimed` does
# not give you back what was written -- it gives the local short form ("08/01/2026 23:17:46"), losing
# the sub-second precision and the UTC offset. Writing that back would quietly downgrade the stamp on
# every refresh, and it would still parse, so nothing would ever complain. Round-trip it instead.
function ConvertTo-Stamp($Value) {
    if ($Value -is [datetime]) { return $Value.ToString("o") }
    if ($Value -is [datetimeoffset]) { return $Value.ToString("o") }
    return [string]$Value
}

function Get-Mine([string]$Path) {
    $c = Get-Content $Path -Raw | ConvertFrom-Json
    $held = ($c.worktree -replace '\\', '/').TrimEnd('/')
    $me = ($repo -replace '\\', '/').TrimEnd('/')
    [pscustomobject]@{ Claim = $c; IsMine = ($held -ieq $me) }
}

# ONE liveness rule, three call sites (BACKLOG #345 Half B).
#
# `-List` learned this first, and that was the wrong half to fix alone: -List is where you BROWSE, and
# `-Take`/`-Release` are where you are STOPPED. Both blocking paths printed the same "held by another
# worktree" block whether the holder had been deleted, had died, or was committing that minute -- and
# `-Release` went further and RECOMMENDED `-Force` ("If that session is gone...") on a holder it had
# never looked at. Advice that cannot distinguish the two cases is advice to guess, and the guess that
# frees a live session's key causes the duplicate build this whole registry exists to prevent.
#
# Reports only what it can PROVE. A vanished directory is a fact and the one state safe to act on
# unasked. Everything else is 'unknown' or a quiet-hours count -- never "probably fine": a session can
# be alive and simply not committing, so silence is not evidence of death.
function Get-HolderLiveness([string]$HeldPath) {
    try {
        if (-not (Test-Path -LiteralPath $HeldPath)) {
            return [pscustomobject]@{ State = 'gone'; QuietHours = $null }
        }
        $ct = & git -C $HeldPath log -1 --format=%ct 2>$null
        if ($ct) {
            $quiet = [int]((Get-Date) - [System.DateTimeOffset]::FromUnixTimeSeconds([long]$ct).LocalDateTime).TotalHours
            return [pscustomobject]@{ State = 'present'; QuietHours = $quiet }
        }
        # Present on disk but no commit to date it by -- a brand-new worktree looks exactly like this.
        return [pscustomobject]@{ State = 'unknown'; QuietHours = $null }
    }
    catch {
        # Say so rather than returning 'gone'. A failed probe that reported death would turn an
        # unreadable path into a licence to release someone's live claim.
        return [pscustomobject]@{ State = 'failed'; QuietHours = $null }
    }
}

function Show-List {
    $files = @(Get-ChildItem $claims -Filter *.json -EA SilentlyContinue | Sort-Object Name)
    if (-not $files) { Write-Host "No active claims."; return }
    $me = ($repo -replace '\\', '/').TrimEnd('/')
    Write-Host ""
    Write-Host "Active work claims ($($files.Count)):"
    foreach ($f in $files) {
        $c = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $held = ($c.worktree -replace '\\', '/').TrimEnd('/')
        $mine = if ($held -ieq $me) { "  <-- THIS worktree" } else { "" }
        # LIVENESS, not age. This used to print "[STALE ~Nh -- release it if that session is gone]" once
        # a claim was 12h old, which measures how long the WORK has run and says nothing about whether
        # anyone is still doing it. Measured 2026-07-31: a claim reported STALE ~21h whose holder had
        # committed TWO MINUTES earlier. Releasing on that advice frees the key for a second session to
        # start building what someone is mid-flight on -- the exact duplicate-build this registry exists
        # to prevent, arrived at by following the tool's own recommendation. A long claim is the normal
        # shape of long work; report what the HOLDER is doing and let the operator decide.
        $age = ""
        try {
            $hrs = [int]((Get-Date) - [datetime]::Parse($c.claimed)).TotalHours
            # Shared with -Take and -Release, so all three surfaces answer "is the holder there?" the
            # same way. They used to disagree: this one probed, the other two did not probe at all.
            $live = Get-HolderLiveness $held
            switch ($live.State) {
                'gone'    { $age = "  [HOLDER GONE -- worktree no longer exists; release with -Force]" }
                'present' {
                    $age = "  [held ${hrs}h; holder last committed $($live.QuietHours)h ago]"
                    if ($live.QuietHours -ge 12) { $age += " -- QUIET, confirm with the holder before releasing" }
                }
                default   { $age = "  [held ${hrs}h; holder liveness UNKNOWN -- confirm before releasing]" }
            }
        } catch {
            # Say so. An empty annotation reads as "nothing notable about this claim", which is the same
            # silent-instrument failure the age signal had: accurate about what it measured, mute about
            # what it could not. A claim whose liveness could not be determined must not look routine.
            $age = "  [liveness check FAILED -- treat as unknown, confirm before releasing]"
        }
        Write-Host ("  {0,-34} {1}" -f $c.key, $c.note)
        Write-Host ("      held by {0} [{1}]{2}{3}" -f $held, $c.branch, $mine, $age)
    }
    Write-Host ""
}

if ($Release) {
    $file = Join-Path $claims ((ConvertTo-KeyFile $Release) + ".json")
    if (-not (Test-Path $file)) { Write-Host "No claim on '$Release' -- nothing to release."; exit 0 }
    $info = Get-Mine $file
    if (-not $info.IsMine -and -not $Force) {
        Write-Host ""
        Write-Host "REFUSING to release '$Release': it is held by another worktree." -ForegroundColor Yellow
        Write-Host "  held by: $($info.Claim.worktree) [$($info.Claim.branch)]"
        Write-Host "  since  : $($info.Claim.claimed)"
        Write-Host "  note   : $($info.Claim.note)"
        # DO NOT recommend -Force without looking. This line used to read "If that session is gone,
        # re-run with -Force" unconditionally -- an instruction to guess, printed at exactly the moment
        # the operator is deciding whether to take someone else's key. Now the recommendation is only
        # made in the one state that can be proven, and the live case says the opposite.
        $live = Get-HolderLiveness $info.Claim.worktree
        Write-Host ""
        switch ($live.State) {
            'gone' {
                Write-Host "  HOLDER GONE -- that worktree no longer exists on disk." -ForegroundColor Green
                Write-Host "  Safe to take over:  claim.ps1 -Release $Release -Force"
            }
            'present' {
                Write-Host "  HOLDER IS STILL THERE -- that worktree exists and last committed $($live.QuietHours)h ago." -ForegroundColor Red
                Write-Host "  Do NOT -Force it on the strength of a quiet period: a session can be alive and"
                Write-Host "  simply not committing. Ask that session first -- releasing a live claim is how two"
                Write-Host "  sessions end up building the same thing."
            }
            default {
                Write-Host "  HOLDER LIVENESS UNKNOWN -- the worktree exists but could not be dated." -ForegroundColor Yellow
                Write-Host "  Confirm with that session before using -Force."
            }
        }
        exit 1
    }
    Remove-Item -LiteralPath $file -Force
    Write-Host "Released claim on '$Release'." -ForegroundColor Green
    exit 0
}

if (-not $Take) { Show-List; exit 0 }
if ($List) { Show-List; exit 0 }

$safe = ConvertTo-KeyFile $Take
$file = Join-Path $claims "$safe.json"

$branch = & git -C $repo branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git -C $repo rev-parse --short HEAD) }
$branch = $branch.Trim()

try {
    # ATOMIC test-and-set -- identical to alloc.ps1. 'CreateNew' + FileShare::None throws IOException if a
    # sibling session got here first, and that throw IS the mutual exclusion.
    $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
} catch [System.IO.IOException] {
    $info = Get-Mine $file
    if ($info.IsMine) {
        # Re-taking your own claim is not an error: a session should be able to re-assert freely. It was
        # also, until now, not a REFRESH -- despite the -Take parameter documenting one. A new -Note was
        # accepted, reported as success, and silently discarded.
        #
        # That is worse than an outright failure, because the note is the one field written deliberately
        # to say what a session is doing, and announce-session.ps1 broadcasts it to every session that
        # joins the repo, telling them to prefer it over the worktree name. Measured 2026-08-02: the
        # 'announce-hook' claim still read "NO PR OPENED -- honouring the #119 merge freeze" to every
        # joining session hours after both #133 and #119 had merged. A stale note broadcast as current
        # intent is a coordination fault, not a cosmetic one -- and the documented workaround (-Release
        # then -Take) drops the claim in between, re-opening the race the claim exists to close.
        if ($Note) {
            $updated = [ordered]@{
                # $Take, not the stored key: ConvertFrom-Json date-coerces any ISO-8601-SHAPED string,
                # and a key is free text, so a key like "2026-08-01T00:00:00" would come back through
                # [string] as "08/01/2026 00:00:00" -- a record naming a key nobody typed and -Release
                # cannot be spelled to match. $Take is the caller's current spelling of the same key,
                # and it folds to the same filename, which is the real identity.
                key      = $Take
                note     = $Note
                # Refresh the branch too: a worktree can have switched branches since the claim was made,
                # and a claim naming a branch nobody is on is another confidently-wrong coordination fact.
                branch   = $branch
                worktree = [string]$info.Claim.worktree
                # `claimed` is the identity of the claim and never moves; `refreshed` is what tells a
                # reader how old the NOTE is, which is the question a stale note makes urgent.
                claimed   = ConvertTo-Stamp $info.Claim.claimed
                refreshed = (Get-Date).ToString("o")
            } | ConvertTo-Json -Compress
            # Write-then-replace, not a truncating in-place write. A torn claim file does not fail loudly:
            # scripts/hooks/claim_check.py swallows a parse error into "not claimed", which would disable
            # the enforced gate for that key -- so a crash mid-write must leave the OLD file intact.
            $tmp = "$file.$PID.tmp"
            # UTF8 WITHOUT a BOM, for that same reader: a BOM makes json.loads raise.
            [System.IO.File]::WriteAllBytes($tmp, [System.Text.Encoding]::UTF8.GetBytes($updated))

            # [IO.File]::Move(.., overwrite) AND NOT `Move-Item -Force`. THE CLAIM FILE'S EXISTENCE *IS*
            # THE LOCK -- the take path above is an exclusive CreateNew, so any instant in which the name
            # does not exist is an instant another worktree can claim a key we hold. `Move-Item -Force`
            # is delete-then-rename and opens exactly that window: measured on this box, 400 moves left
            # the destination absent on 2,559 of 154,506 polls. The same harness over [IO.File]::Move
            # with overwrite -- which is MoveFileEx(MOVEFILE_REPLACE_EXISTING), atomic on NTFS -- polled
            # 134,581 times and never once saw the name missing.
            #
            # It can fail transiently instead (a scanner or an editor holding the destination without
            # FILE_SHARE_DELETE); the same harness saw 13.5% under back-to-back churn, which is nothing
            # like one refresh per invocation but is cheap to absorb. Failing is the SAFE direction: the
            # old note survives and the claim stays ours. Losing the lock is not.
            #
            # The catch is deliberately UNTYPED. PowerShell wraps an exception thrown by a .NET METHOD in
            # a MethodInvocationException, so `catch [System.IO.IOException]` around this call never
            # matches -- the failure escapes to $ErrorActionPreference = "Stop", the cleanup below never
            # runs, and the temp file is orphaned in the claim registry. (Written typed first; the
            # orphaned-temp assertion is what caught it.) Every failure here has the same right answer
            # anyway: leave the old note, keep the claim, say so.
            $moved = $false
            foreach ($attempt in 1..5) {
                try { [System.IO.File]::Move($tmp, $file, $true); $moved = $true; break }
                catch { Start-Sleep -Milliseconds (20 * $attempt) }
            }
            if (-not $moved) {
                # Never orphan the temp: this directory is the claim registry, and a k.json.<pid>.tmp
                # nothing ever removes accumulates in it for the life of the repo.
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Write-Host ""
                Write-Host "Could NOT refresh the note on '$Take' -- the file was locked by another process." -ForegroundColor Yellow
                Write-Host "  Your claim is UNCHANGED and still yours; only the note was not updated."
                Write-Host "  Retry in a moment. Do NOT -Release: that would drop a claim you still hold."
                exit 1
            }
            Write-Host ""
            Write-Host "REFRESHED '$Take' (held since $($info.Claim.claimed))." -ForegroundColor Green
            Write-Host "  note : $Note"
            exit 0
        }
        Write-Host "You already hold '$Take' (claimed $($info.Claim.claimed))." -ForegroundColor Green
        Write-Host "  note : $($info.Claim.note)"
        Write-Host "  (pass -Note to update it -- it is what other sessions are shown.)"
        exit 0
    }
    Write-Host ""
    Write-Host "BLOCKED: '$Take' is already claimed by another session." -ForegroundColor Red
    Write-Host "  held by: $($info.Claim.worktree) [$($info.Claim.branch)]"
    Write-Host "  since  : $($info.Claim.claimed)"
    Write-Host "  note   : $($info.Claim.note)"
    # THE BLOCKING PATH IS WHERE THIS MATTERS MOST. -List is where you browse; this is where a session
    # is stopped and has to decide between waiting, picking other work, and taking the key. It used to
    # offer -Force as a flat third option with no way to tell a dead holder from a live one, so the
    # cheapest way past the gate was also the one that causes the duplicate build it exists to prevent.
    $live = Get-HolderLiveness $info.Claim.worktree
    Write-Host ""
    switch ($live.State) {
        'gone' {
            Write-Host "  HOLDER GONE -- that worktree no longer exists on disk, so nobody is building this." -ForegroundColor Green
            Write-Host "  Take it over with:"
            Write-Host "      pwsh -NoProfile -File scripts\coord\claim.ps1 -Release $Take -Force"
            Write-Host "      pwsh -NoProfile -File scripts\coord\claim.ps1 -Take $Take -Note ""<what>"""
        }
        'present' {
            Write-Host "  HOLDER IS STILL THERE -- that worktree exists and last committed $($live.QuietHours)h ago." -ForegroundColor Red
            Write-Host "  Do NOT build it in parallel -- that is the duplicate-work this gate exists to stop,"
            Write-Host "  and do NOT -Force it: quiet is not dead. Coordinate with that session or pick"
            Write-Host "  different work. Its note above says what it is doing."
        }
        default {
            Write-Host "  HOLDER LIVENESS UNKNOWN -- the worktree exists but could not be dated." -ForegroundColor Yellow
            Write-Host "  Treat it as live: coordinate with that session before -Force."
        }
    }
    exit 1
}
try {
    $claim = [ordered]@{
        key      = $Take
        note     = if ($Note) { $Note } else { "(no note)" }
        branch   = $branch
        worktree = $repo
        claimed  = (Get-Date).ToString("o")
    } | ConvertTo-Json -Compress
    # UTF8 WITHOUT a BOM: the python-side gate reads this with encoding="utf-8", and a BOM makes
    # json.loads raise -- which would be swallowed into "not claimed" and silently disable the gate.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($claim)
    $fs.Write($bytes, 0, $bytes.Length)
} finally {
    $fs.Dispose()
}

Write-Host ""
Write-Host "CLAIMED '$Take'" -ForegroundColor Green
Write-Host "  by   : $repo [$branch]"
Write-Host "  note : $(if ($Note) { $Note } else { '(no note)' })"
Write-Host "  release when done:  pwsh -NoProfile -File scripts\coord\claim.ps1 -Release $Take"

# Same note alloc.ps1 prints, for the same reason (BACKLOG #1060): anchoring is correct but surprising,
# and a claim recorded to a worktree the caller is not standing in otherwise surfaces only as a refused
# commit later. Silent on the ordinary same-tree invocation.
$cwdTop = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
if ($cwdTop) {
    $a = ($cwdTop.Trim() -replace '\\', '/').TrimEnd('/')
    $b = ($repo -replace '\\', '/').TrimEnd('/')
    if ($a -ine $b) {
        Write-Host "  NOTE: your shell is in $a, but this script lives in $b, so the claim is" -ForegroundColor Yellow
        Write-Host "        recorded to $b. -Release must be run against that same worktree." -ForegroundColor Yellow
    }
}
exit 0
