<#
.SYNOPSIS
    Create an isolated git worktree (+ its own .venv) for a parallel MessageFoundry build session.

.DESCRIPTION
    Two parallel efforts (e.g. two Claude Code chats) can't safely build in the same working tree --
    one's branch switch / edits clobber the other. This adds a git worktree as a SIBLING directory
    (<repo>-<Name>) on its own branch, then bootstraps that worktree's own Python virtualenv so its
    tests/tools run against its own checkout. The worktree shares the same .git/history/remote, so
    the normal branch -> PR -> merge flow is unchanged.

    Run from anywhere (it locates the repo via this script's path). See docs/WORKTREES.md.

    The base is fetched first and defaults to `origin/main` (the freshest remote tip), so a new
    worktree never seeds itself from a stale local `main`. Override with -Base; if you point it at a
    local branch that lags its upstream you get a loud warning.

.EXAMPLE
    .\new.ps1 -Name alerts
    .\new.ps1 -Name sqltuning -Base feature/sql-tuning -Sqlserver -Ide
    .\new.ps1 -Name quicklook -NoInstall
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Name,
    # Branch the new worktree off this ref. Default = the fetched `origin/main` so a stale local
    # `main` can't seed it (the classic trap this script kept hitting).
    [string]$Base = "origin/main",
    [string]$Python = "python",
    [switch]$Sqlserver,   # also install the [sqlserver] extra
    [switch]$Ide,         # also run `npm install` for the VS Code extension
    [switch]$NoInstall    # create the worktree only; skip the venv bootstrap
)

$ErrorActionPreference = "Stop"

# Repo root is two levels up from scripts\worktree\.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Parent = Split-Path $RepoRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf
$WorktreePath = Join-Path $Parent "$RepoName-$Name"

if (Test-Path $WorktreePath) { throw "Worktree path already exists: $WorktreePath" }

# Refresh remote-tracking refs FIRST so the base is current. The classic trap is branching a new
# worktree off a LOCAL `main` that quietly lags `origin/main` -- every parallel session then starts
# from stale code. Defaulting -Base to `origin/main` (the freshly fetched remote tip) avoids it. A
# fetch failure (offline) is a loud warning, not fatal -- you can still branch off whatever you have.
Write-Host "Fetching origin so the base is current..."
& git -C $RepoRoot fetch origin --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Warning "git fetch origin failed (offline?). Proceeding with possibly-stale refs."
}

# Reuse an existing branch if it's there, else create it from -Base.
$branchExists = & git -C $RepoRoot branch --list $Name
Write-Host "Creating worktree '$WorktreePath' on branch '$Name'..."

# SERIALIZED ACROSS SESSIONS. `git worktree add -b <name> <base>` writes .git/config (the new
# branch's upstream), and concurrent adds race .git/config.lock. Reported and reproduced on Windows:
# parallel adds against one common .git fail with "could not lock config file .git/config: File
# exists" / "unable to write upstream branch configuration", leaving ORPHANED branches behind and
# callers that never run. Several worktrees already share this .git, so this is a live hazard, not a
# theoretical one. 90s is generous for an operation that takes seconds -- if we wait that long,
# something is genuinely wrong and the throw is the right outcome.
. "$PSScriptRoot\..\coord\lock.ps1"
$addLock = Enter-CoordLock -Name "worktree-add" -TimeoutSeconds 90 -Repo $RepoRoot
try {
if ($branchExists) {
    & git -C $RepoRoot worktree add $WorktreePath $Name
} else {
    # Guard the stale-base trap when -Base names a LOCAL branch that lags its upstream (e.g. an
    # explicit `-Base main` while origin/main has moved on). A remote-tracking base like origin/main
    # has no @{upstream}, so this check simply no-ops for the default.
    $baseUpstream = & git -C $RepoRoot rev-parse --abbrev-ref --symbolic-full-name ("$Base" + '@{upstream}') 2>$null
    if ($LASTEXITCODE -eq 0 -and $baseUpstream) {
        $behind = & git -C $RepoRoot rev-list --count "$Base..$baseUpstream" 2>$null
        if ($LASTEXITCODE -eq 0 -and $behind -and [int]$behind -gt 0) {
            Write-Warning ("Base '$Base' is $behind commit(s) behind its upstream '$baseUpstream' -- " +
                "the new worktree will start from stale code. Update '$Base' first, or use " +
                "-Base $baseUpstream (the default).")
        }
    }
    & git -C $RepoRoot worktree add $WorktreePath -b $Name $Base
}
} finally { Exit-CoordLock $addLock }
if ($LASTEXITCODE -ne 0) { throw "git worktree add failed (exit $LASTEXITCODE)" }

# Record this worktree's HOME branch in its PRIVATE git dir (<repo>/.git/worktrees/<id>/), so the
# SessionStart drift-detector in worktree-selfheal.ps1 can notice if the worktree is later SWITCHED onto
# another branch -- the worktree-hijack (docs/WORKTREES.md). Not the working tree and not shared config:
# it is per-worktree and untracked. Best-effort -- a failure here never blocks worktree creation.
try {
    $gitDir = "$(& git -C $WorktreePath rev-parse --absolute-git-dir 2>$null)".Trim()
    if ($gitDir) { Set-Content -LiteralPath (Join-Path $gitDir 'mefor-home-branch') -Value $Name -Encoding utf8 }
} catch { }

# The forbidden-content gate's token list is git-ignored, so `git worktree add` cannot deliver it and a
# fresh worktree starts unable to commit AT ALL -- the pre-commit hook passes --require-tokens and fails
# closed. Carry the source checkout's copy across if it has one; otherwise say so here, because the
# symptom is a hard commit block whose message does not mention worktrees. Best-effort: never block
# worktree creation. MEFOR_FORBIDDEN_TOKENS, if set, already covers every checkout on the machine.
try {
    $tokenRel = 'scripts/security/scan-tokens.local.txt'
    $srcToken = Join-Path $RepoRoot $tokenRel
    if (Test-Path -LiteralPath $srcToken) {
        Copy-Item -LiteralPath $srcToken -Destination (Join-Path $WorktreePath $tokenRel) -Force
        Write-Host "Leak-gate token list copied into the worktree." -ForegroundColor DarkGray
    }
    elseif (-not $env:MEFOR_FORBIDDEN_TOKENS) {
        Write-Host "NOTE: no leak-gate token source found - commits here will fail closed." -ForegroundColor Yellow
        Write-Host "      Fix once: pwsh -NoProfile -File scripts\dev\setup-leak-gate.ps1 -From <path>" -ForegroundColor Yellow
    }
} catch { }

function Show-NextSteps {
    Write-Host ""
    Write-Host "Worktree ready: $WorktreePath (branch '$Name')" -ForegroundColor Green
    Write-Host "Next steps:"
    Write-Host "  cd `"$WorktreePath`""
    if (-not $NoInstall) {
        Write-Host "  .\.venv\Scripts\Activate.ps1        # use this worktree's env"
    }
    if ($Ide) {
        Write-Host "  code --extensionDevelopmentPath=`"$WorktreePath\ide`" `"$WorktreePath\mefor.code-workspace`""
    }
    Write-Host "  # ... build/commit/push on branch '$Name'; open a PR as usual."
    Write-Host "  # When done (run from the MAIN checkout): scripts\worktree\remove.ps1 -Name $Name"
}

if ($NoInstall) {
    Write-Host "Skipped env bootstrap (-NoInstall). Create a venv before running tests."
    Show-NextSteps
    return
}

# --- bootstrap the worktree's own virtualenv ---------------------------------
# Per-worktree venv so the worktree's tests/tools resolve its OWN checkout (a shared venv with an
# editable install would import whichever checkout it was installed from).
$venv = Join-Path $WorktreePath ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"
$extras = if ($Sqlserver) { "dev,harness,sqlserver" } else { "dev,harness" }

Write-Host "Creating virtualenv + installing .[$extras] (this can take a minute)..."
& $Python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw "venv creation failed (is '$Python' on PATH?)" }
& $venvPy -m pip install --upgrade pip | Out-Null

Push-Location $WorktreePath
try {
    & $venvPy -m pip install -e ".[$extras]"
    if ($LASTEXITCODE -ne 0) { throw "pip install -e .[$extras] failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

if ($Ide) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($npm) {
        Write-Host "Installing IDE extension dependencies (npm)..."
        & npm --prefix (Join-Path $WorktreePath "ide") install
        if ($LASTEXITCODE -ne 0) { Write-Warning "npm install failed; set up ide/ manually." }
    } else {
        Write-Warning "npm not found on PATH; skipped IDE dependency install."
    }
}

Show-NextSteps
