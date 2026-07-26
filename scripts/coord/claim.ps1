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
    auto-expiring one silently re-opens the race it exists to prevent. `-List` flags anything older than
    12h so stale ones are obvious.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\claim.ps1 -Take 105 -Note "corepoint xml importer"
    pwsh -NoProfile -File scripts\coord\claim.ps1 -List
    pwsh -NoProfile -File scripts\coord\claim.ps1 -Release 105
#>
[CmdletBinding()]
param(
    # Claim this key for THIS worktree. Idempotent: re-taking your own claim just refreshes the note.
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

$repo = (& git rev-parse --path-format=absolute --show-toplevel).Trim()
if (-not $repo) { throw "Not inside a git repository." }
$common = (& git rev-parse --path-format=absolute --git-common-dir).Trim()
$claims = Join-Path $common "mefor-coord/claims"
New-Item -ItemType Directory -Force -Path $claims | Out-Null

# A key is free text but becomes a FILENAME, so fold it to a safe, case-insensitive form. The original is
# kept inside the json so `-List` can show what the human actually typed.
function ConvertTo-KeyFile([string]$Key) {
    $safe = ($Key.Trim().ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim('-')
    if (-not $safe) { throw "Key '$Key' reduces to nothing usable -- pick something with letters or digits." }
    $safe
}

function Get-Mine([string]$Path) {
    $c = Get-Content $Path -Raw | ConvertFrom-Json
    $held = ($c.worktree -replace '\\', '/').TrimEnd('/')
    $me = ($repo -replace '\\', '/').TrimEnd('/')
    [pscustomobject]@{ Claim = $c; IsMine = ($held -ieq $me) }
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
        $age = ""
        try {
            $hrs = ((Get-Date) - [datetime]::Parse($c.claimed)).TotalHours
            if ($hrs -ge 12) { $age = "  [STALE ~$([int]$hrs)h -- release it if that session is gone]" }
        } catch { }
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
        Write-Host ""
        Write-Host "If that session is gone, re-run with -Force."
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

$branch = & git branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git rev-parse --short HEAD) }
$branch = $branch.Trim()

try {
    # ATOMIC test-and-set -- identical to alloc.ps1. 'CreateNew' + FileShare::None throws IOException if a
    # sibling session got here first, and that throw IS the mutual exclusion.
    $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
} catch [System.IO.IOException] {
    $info = Get-Mine $file
    if ($info.IsMine) {
        # Re-taking your own claim is a no-op, not an error: a session should be able to re-assert freely.
        Write-Host "You already hold '$Take' (claimed $($info.Claim.claimed))." -ForegroundColor Green
        exit 0
    }
    Write-Host ""
    Write-Host "BLOCKED: '$Take' is already claimed by another session." -ForegroundColor Red
    Write-Host "  held by: $($info.Claim.worktree) [$($info.Claim.branch)]"
    Write-Host "  since  : $($info.Claim.claimed)"
    Write-Host "  note   : $($info.Claim.note)"
    Write-Host ""
    Write-Host "Do NOT build it in parallel -- that is the duplicate-work this gate exists to stop."
    Write-Host "Coordinate with that session, pick different work, or if it is dead:"
    Write-Host "    pwsh -NoProfile -File scripts\coord\claim.ps1 -Release $Take -Force"
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
exit 0
