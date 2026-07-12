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
    [switch]$List
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

if (-not $Title) { throw "-Title is required (it is recorded with the claim, so a sibling session can see what the number is for)." }

# `git branch --show-current` prints NOTHING on a detached HEAD, so `& git ...` yields $null (not "")
# -- calling .Trim() on it here threw *before* the detached-HEAD fallback below could run. Null-check first.
$branch = & git branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git rev-parse --short HEAD) }
$branch = $branch.Trim()

# FLOOR = max over (origin/main) U (every local + remote ref) U (existing allocations).
function Get-Floor {
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
        # BACKLOG.md is one big file: read it from origin/main and from this worktree's HEAD + index.
        $texts = @(
            (& git show "origin/main:docs/BACKLOG.md" 2>$null) -join "`n"
            (& git show "HEAD:docs/BACKLOG.md" 2>$null) -join "`n"
        )
        $wip = Join-Path $repo "docs/BACKLOG.md"
        if (Test-Path $wip) { $texts += (Get-Content $wip -Raw) }
        foreach ($t in $texts) {
            foreach ($m in [regex]::Matches($t, '(?m)^#{2,3} (\d+)\.')) { $seen.Add([int]$m.Groups[1].Value) }
        }
    }

    foreach ($f in (Get-ChildItem $alloc -Filter *.json -EA SilentlyContinue)) {
        $n = 0
        if ([int]::TryParse($f.BaseName, [ref]$n)) { $seen.Add($n) }
    }
    # Measure-Object hands back a [double]; the 'D4' format specifier is integer-only and throws on one.
    [int](($seen | Measure-Object -Maximum).Maximum)
}

$start = (Get-Floor) + 1
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
