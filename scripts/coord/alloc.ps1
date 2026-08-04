<#
.SYNOPSIS
    Allocate the next free ADR or BACKLOG number, atomically, so two concurrent sessions can never take
    the same one.

.DESCRIPTION
    NEVER grep for `max + 1`. Two sessions that both grep pick the SAME number, create DIFFERENTLY-named
    files, merge CLEAN, and silently corrupt the ledger. That has happened three times here (d1d0a5a #574,
    5b7d046 #598, 9f3483d) and it is invisible to git, to a file lock, and to `git merge-tree`.

    This is a test-and-set, not a read-modify-write. It claims the number by EXCLUSIVELY CREATING
    <git-common-dir>/mefor-coord/alloc/<kind>/<number>.json -- an atomic NTFS operation. If a sibling
    session already holds it, the create throws and we move to the next number. (A read-modify-write on a
    shared list is not an option: PowerShell was MEASURED silently losing 4 of 8 concurrent writes to one
    shared file.)

    The registry lives beside the SHARED object store, so every worktree of this repo sees the same
    allocations, and a different clone automatically gets its own registry.

    The floor is the max over: the numbers on origin/main, the numbers on EVERY local and remote ref, and
    every existing allocation. The all-refs term closes the "registry wiped -> re-issue a number that only
    exists on an unpushed branch" hole. It costs about a second, once per ADR -- not per edit.

    Numbers are never reclaimed. An abandoned branch holds its number forever and the sequence develops
    holes. That is deliberate: holes are free, collisions are not.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "Worktree gate"
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog -Title "Ledger allocator"
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -List
#>
[CmdletBinding()]
param(
    [ValidateSet("adr", "backlog")]
    [string]$Kind = "adr",
    [string]$Title,
    # Show what this worktree currently holds, and exit.
    [switch]$List,
    # Print the computed floor and the paths it swept, then exit WITHOUT allocating.
    #
    # Allocation is a one-way door -- claims are never released ("holes are free, collisions are not")
    # -- so before this switch the only way to find out what the floor could see was to spend a number
    # on the question. That makes the floor's own correctness the one property nobody re-tests, which
    # is how it went a whole release reading two refs while its header promised all of them. A gate
    # that cannot be inspected without altering the thing it guards will not be inspected.
    [switch]$ShowFloor
)

$ErrorActionPreference = "Stop"

$repo = (& git rev-parse --path-format=absolute --show-toplevel).Trim()
if (-not $repo) { throw "Not inside a git repository." }
$common = (& git rev-parse --path-format=absolute --git-common-dir).Trim()
$allocRoot = Join-Path $common "mefor-coord/alloc"
$alloc = Join-Path $allocRoot $Kind
New-Item -ItemType Directory -Force -Path $alloc | Out-Null

if ($List) {
    foreach ($k in @("adr", "backlog")) {
        $dir = Join-Path $allocRoot $k
        $mine = @(Get-ChildItem $dir -Filter *.json -EA SilentlyContinue | ForEach-Object {
                $c = Get-Content $_.FullName -Raw | ConvertFrom-Json
                if (($c.worktree -replace '\\', '/').TrimEnd('/') -ieq ($repo -replace '\\', '/').TrimEnd('/')) { $c }
            })
        Write-Host "$k allocated to this worktree: $(if ($mine) { ($mine.number -join ', ') } else { '(none)' })"
    }
    return
}

# -ShowFloor allocates nothing, so there is no claim for a title to be recorded against.
if (-not $Title -and -not $ShowFloor) { throw "-Title is required (it is recorded with the claim, so a sibling session can see what the number is for)." }

# `git branch --show-current` prints NOTHING on a detached HEAD, so `& git ...` yields $null (not "")
# -- calling .Trim() on it here threw *before* the detached-HEAD fallback below could run. Null-check first.
$branch = & git branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git rev-parse --short HEAD) }
$branch = $branch.Trim()

# FLOOR = max over (origin/main) U (every local + remote ref) U (existing allocations).
function Get-Floor {
    # -Peek computes the floor WITHOUT advancing the high-water ratchet. The ratchet is a one-way
    # door, so an inspection that moves it is not an inspection -- and the first run of -ShowFloor
    # against a deliberately planted number proved it, ratcheting this clone from 316 to a fabricated
    # 990 that no later run could undo. Reading a value must not be able to corrupt it.
    param([switch]$Peek)

    $seen = [System.Collections.Generic.List[int]]::new()
    $seen.Add(0)

    if ($Kind -eq "adr") {
        $refs = @("origin/main") + @(& git for-each-ref --format='%(refname)' refs/heads refs/remotes)
        foreach ($ref in ($refs | Select-Object -Unique)) {
            $names = & git ls-tree --name-only $ref docs/adr/ 2>$null
            foreach ($n in $names) {
                if ($n -match 'docs/adr/(\d{4})-') { $seen.Add([int]$Matches[1]) }
            }
        }
    } else {
        # BACKLOG.md is ONE BIG FILE, so the floor needs its CONTENT, not a filename listing -- but it
        # still needs EVERY ref, exactly like the adr branch above and exactly as this function's own
        # header comment promises. Reading only origin/main + HEAD is what re-issued #240-#247 on
        # 2026-07-30 over numbers ADR 0115 and seven amended ADRs already cite: the items holding
        # those numbers live on refs the published branch does not carry, so they were invisible here
        # and the allocator handed the numbers out as free. A number that exists on ANY ref is taken.
        #
        # Batched deliberately: ~550 refs share ~190 distinct BACKLOG.md blobs, and a `git show` per
        # ref costs ~34s on Windows (one process each). Two `git cat-file` processes do it in ~3s.
        # THE NUMBER SPACE SPANS TWO PATHS. Retiring an item MOVES it verbatim out of docs/BACKLOG.md
        # and into docs/archive/backlog/BACKLOG-CLOSED.md. Sweeping only the published file would make
        # every archived number invisible here and free to re-issue -- the #240-#247 shape again, just
        # sourced from a different blind spot. A number that exists in EITHER file, on ANY ref, is taken.
        #
        # The archive is ONE file with a FIXED name on purpose: `cat-file --batch-check` takes a spec
        # list and cannot glob a directory, so a per-ref `git ls-tree -r` would be needed to discover
        # archive filenames -- one process per ref, the ~34s cost the batching below exists to avoid.
        # A fixed second spec keeps the sweep at two processes. Splitting the archive into several
        # files means adding each one here; an archive file not listed here is not policed.
        $backlogPaths = @("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md")

        $refs = @("origin/main", "HEAD") + @(& git for-each-ref --format='%(refname)' refs/heads refs/remotes)
        $specs = foreach ($r in ($refs | Select-Object -Unique)) {
            foreach ($p in $backlogPaths) { "${r}:${p}" }
        }

        $oids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($line in ($specs -join "`n" | & git cat-file --batch-check='%(objectname) %(objecttype)' 2>$null)) {
            $p = "$line".Split(' ')
            if ($p.Count -ge 2 -and $p[1] -eq 'blob') { [void]$oids.Add($p[0]) }
        }

        # MULTILINE IS LOAD-BEARING, and its absence was a silent hole. `[regex]'^...'` anchors at the
        # start of the STRING, not of each line. The all-refs term below feeds it one line at a time
        # (cat-file output through the pipeline), so it matched there and looked correct -- but the
        # working-tree term feeds it `Get-Content -Raw`, one string starting "# Backlog", where `^`
        # could never match. Measured on this tree: 0 of 277 headings found without Multiline, 277
        # with. So the term that exists to catch a number written but committed NOWHERE has been
        # finding nothing since it was written, and the all-refs term hid it by covering every number
        # that had been committed somewhere -- i.e. every case except the one this term is for.
        $rx = [regex]::new('^#{2,3} (\d+)\.', [System.Text.RegularExpressions.RegexOptions]::Multiline)
        if ($oids.Count -gt 0) {
            foreach ($line in (($oids -join "`n") | & git cat-file --batch 2>$null)) {
                $m = $rx.Match("$line")
                if ($m.Success) { $seen.Add([int]$m.Groups[1].Value) }
            }
        }
        # Working-tree term: catches a number written to a file but committed nowhere. Both paths, for
        # the same reason -- an item drafted straight into the archive is still a claim on its number.
        foreach ($p in $backlogPaths) {
            $wip = Join-Path $repo $p
            if (Test-Path $wip) {
                foreach ($m in $rx.Matches((Get-Content $wip -Raw))) { $seen.Add([int]$m.Groups[1].Value) }
            }
        }
    }

    foreach ($f in (Get-ChildItem $alloc -Filter *.json -EA SilentlyContinue)) {
        $n = 0
        if ([int]::TryParse($f.BaseName, [ref]$n)) { $seen.Add($n) }
    }

    # HIGH-WATER RATCHET -- the floor may rise but must never fall.
    #
    # Every other term above is derived from refs that a routine cleanup can remove. Measured on this
    # clone: the backlog floor is 314 counting all refs, but only 252 counting `refs/remotes/origin`
    # and local heads -- the missing 62 live on remote-tracking refs for a remote that `git remote -v`
    # no longer lists. Drop those and the floor silently reverts to the pre-fix value and the allocator
    # resumes issuing numbers that are already used, with no error and no signal. That is the exact bug
    # this function was fixed for, so leaving its correctness dependent on nobody tidying refs is not
    # good enough: persist the high-water mark and never go below it.
    #
    # SAFE:      `git fetch origin --prune` -- prunes only refs/remotes/origin/*, which is not where the
    #            high numbers live. It is also what you SHOULD run before allocating.
    # DANGEROUS: `git remote prune <name>` / `git remote remove <name>` for a non-origin remote,
    #            deleting refs/<vault-ish>/*, or an aggressive `gc` / `reflog expire` that drops
    #            unreachable objects. Those are what this ratchet defends against.
    $watermark = Join-Path $alloc ".floor-highwater"
    $computed = [int](($seen | Measure-Object -Maximum).Maximum)
    $previous = 0
    if (Test-Path $watermark) { [void][int]::TryParse((Get-Content $watermark -Raw).Trim(), [ref]$previous) }

    if ($previous -gt $computed) {
        Write-Host "NOTE: computed $Kind floor $computed is BELOW the recorded high-water $previous." -ForegroundColor Yellow
        Write-Host "      Using $previous. Refs that carried the higher numbers are missing from this clone;" -ForegroundColor Yellow
        Write-Host "      re-fetch them before trusting any number-space reasoning here." -ForegroundColor Yellow
    }
    $floor = [Math]::Max($computed, $previous)
    if ($floor -gt $previous -and -not $Peek) { Set-Content -Path $watermark -Value $floor -Encoding ASCII }
    # Measure-Object hands back a [double]; the 'D4' format specifier is integer-only and throws on one.
    [int]$floor
}

# THE FLOOR IS DEFINED ONCE, IN THE GATE, AND READ HERE.
#
# Two integers that must agree is the next place this rots: the allocator would go on emitting numbers
# the gate refuses, and the tool would be sending people straight into a blocked commit while insisting
# it had given them a valid number. So parse it out of ledger_check.py rather than restating it, and
# REFUSE to allocate a backlog number if it cannot be read -- guessing a floor the gate will not honour
# is the failure this whole partition exists to prevent, reintroduced by its own tooling.
$gateFile = Join-Path $repo "scripts/hooks/ledger_check.py"
$PublicBacklogFloor = $null
if (Test-Path $gateFile) {
    # The optional `(?::[^=]+)?` tolerates a type annotation. `PUBLIC_BACKLOG_FLOOR: Final[int] = 1000`
    # is idiomatic in a mypy-strict codebase and would otherwise fail to match -- silently disarming
    # every backlog allocation as the result of an ordinary tidy-up. tests/test_ledger_check.py pins
    # this contract so the break lands in CI on whoever edits the constant, not on a session days later.
    $m = [regex]::Match((Get-Content $gateFile -Raw), '(?m)^PUBLIC_BACKLOG_FLOOR\s*(?::[^=]+)?=\s*(\d+)')
    if ($m.Success) { $PublicBacklogFloor = [int]$m.Groups[1].Value }
}

$observed = Get-Floor -Peek:$ShowFloor

if ($ShowFloor) {
    # Name the SOURCES, not just the number. "Which files did this sweep actually read" is the
    # question every silent-narrowing bug turns on, and a bare integer cannot answer it -- a floor of
    # 353 looks identical whether it swept one path or two.
    Write-Host "kind     : $Kind"
    Write-Host "floor    : $observed"
    if ($Kind -eq "backlog") {
        Write-Host "paths    : docs/BACKLOG.md, docs/archive/backlog/BACKLOG-CLOSED.md"
        Write-Host "next     : $([Math]::Max($observed, $PublicBacklogFloor - 1) + 1)  (clamped to >= $PublicBacklogFloor)"
    } else {
        Write-Host "paths    : docs/adr/NNNN-*.md (filenames, all refs)"
        Write-Host "next     : $($observed + 1)"
    }
    Write-Host "watermark: $(Join-Path $alloc '.floor-highwater')"
    Write-Host ""
    Write-Host "Read-only: nothing was allocated." -ForegroundColor DarkGray
    return
}

if ($Kind -eq "backlog") {
    if ($null -eq $PublicBacklogFloor) {
        throw "Could not read PUBLIC_BACKLOG_FLOOR from $gateFile. Refusing to allocate a backlog number rather than guess a floor the gate will not honour."
    }

    # THE RESIDUAL DETECTOR, ON APPROACH RATHER THAN ARRIVAL.
    #
    # The partition binds only the PUBLIC side; nothing can stop the maintainer-internal sequence
    # allocating past the boundary, and CI cannot see it -- a public runner checks out origin only. But
    # THIS machine can: Get-Floor already swept every ref, internal ones included. So the one place the
    # breach is observable is here, at allocation time.
    #
    # Warning only on ARRIVAL would fire exactly when it is too late -- at that point the next internal
    # allocation already collides and there is no room to move. A check that fires only on collision has
    # the same practical value as no check for every moment until the collision. So: warn at 90% of the
    # boundary, with hundreds of numbers of runway left, and REFUSE at the boundary itself.
    $warnAt = [int]($PublicBacklogFloor * 0.9)
    if ($observed -ge $PublicBacklogFloor) {
        throw @"
REFUSING TO ALLOCATE. The all-refs backlog maximum ($observed) has reached the public floor ($PublicBacklogFloor).
The partition assumes the maintainer-internal sequence stays BELOW that boundary, and it no longer does
-- so the next number this would hand out is not safe to use. Raise PUBLIC_BACKLOG_FLOOR in
scripts/hooks/ledger_check.py (the allocator reads it from there), and say so in the PR.
"@
    }
    elseif ($observed -ge $warnAt) {
        Write-Host ""
        Write-Host "WARNING: the all-refs backlog maximum ($observed) is approaching the public floor ($PublicBacklogFloor)." -ForegroundColor Yellow
        Write-Host "         Still safe -- but the partition's headroom is running out, and at the boundary" -ForegroundColor Yellow
        Write-Host "         this script will refuse to allocate. Plan to raise PUBLIC_BACKLOG_FLOOR in" -ForegroundColor Yellow
        Write-Host "         scripts/hooks/ledger_check.py before that happens, not after." -ForegroundColor Yellow
        Write-Host ""
    }
    $start = [Math]::Max($observed, $PublicBacklogFloor - 1) + 1
}
else {
    $start = $observed + 1
}
for ($i = $start; $i -lt $start + 500; $i++) {
    $name = if ($Kind -eq "adr") { "{0:D4}" -f $i } else { "$i" }
    $file = Join-Path $alloc "$name.json"
    try {
        # ATOMIC test-and-set. 'CreateNew' + FileShare::None throws IOException if a sibling got here
        # first -- that throw IS the mutual exclusion.
        $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        continue    # taken by a sibling session; try the next number
    }
    try {
        $claim = [ordered]@{
            number   = $name
            kind     = $Kind
            title    = $Title
            branch   = $branch
            worktree = $repo
            claimed  = (Get-Date).ToString("o")
        } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($claim)
        $fs.Write($bytes, 0, $bytes.Length)
    } finally {
        $fs.Dispose()
    }

    Write-Host ""
    if ($Kind -eq "adr") {
        $slug = ($Title.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        Write-Host "ALLOCATED ADR $name" -ForegroundColor Green
        Write-Host "  file  : docs/adr/$name-$slug.md"
        Write-Host "  index : add its row to docs/adr/README.md in the SAME commit (the gate checks)."
    } else {
        Write-Host "ALLOCATED BACKLOG #$name" -ForegroundColor Green
        Write-Host "  heading : ## $name. $Title"
        Write-Host "  file    : docs/BACKLOG.md"
    }
    Write-Host "  claimed by: $repo [$branch]"
    exit 0
}

throw "No free $Kind number found in 500 tries starting at $start -- the registry looks wrong."
