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

    -Name is the DIRECTORY component and cannot contain '/'; -Branch is the git ref and can. -Branch
    defaults to -Name, which is the ordinary case.

.EXAMPLE
    .\new.ps1 -Name alerts
    .\new.ps1 -Name sqltuning -Base feature/sql-tuning -Sqlserver -Ide
    .\new.ps1 -Name quicklook -NoInstall
    .\new.ps1 -Name my-task -Branch claude/my-task    # reuse a namespaced branch ('/' is not legal in -Name)
#>
[CmdletBinding()]
param(
    # The worktree DIRECTORY component: the sibling created is <repo-parent>\<repo-name>-<Name>. This
    # pattern is LOAD-BEARING and is not about branch names -- a '/' here would silently create a
    # NESTED directory instead of the intended sibling. The branch is -Branch.
    #
    # \A..\z, not ^..$: .NET's '$' also matches before a FINAL NEWLINE, so the old spelling accepted
    # "abc<newline>" and let it through into a directory name. The same literal appears in remove.ps1,
    # spawn.ps1 and rescue.ps1 -- keep all four identical.
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('\A[A-Za-z0-9._-]+\z')]
    [string]$Name,
    # The git BRANCH to reuse or create. Defaults to -Name, so spawn.ps1, rescue.ps1 and every
    # documented invocation are unchanged. It exists because a real refname can carry a '/' and -Name
    # never can, and the worktree gate's rule-3b remediation has to hand one back. Validated as a
    # REFNAME by git itself in the body, not by a character class -- refname grammar is git's to define.
    [string]$Branch,
    # Branch the new worktree off this ref. Default = the fetched `origin/main` so a stale local
    # `main` can't seed it (the classic trap this script kept hitting).
    [Parameter(Position = 1)]
    [string]$Base = "origin/main",
    [string]$Python = "python",
    [switch]$Sqlserver,   # also install the [sqlserver] extra
    [switch]$Ide,         # also run `npm install` for the VS Code extension
    [switch]$NoInstall    # create the worktree only; skip the venv bootstrap
)

$ErrorActionPreference = "Stop"

# -Branch defaults to -Name: these two roles were ONE parameter until the worktree gate needed to hand
# back a real slash-bearing ref (scripts\hooks\worktree_gate.ps1 rule 3b). Defaulting keeps spawn.ps1,
# rescue.ps1 and every documented invocation byte-identical.
if (-not $Branch) { $Branch = $Name }

# Ask GIT whether this is a legal branch name rather than inventing a second grammar -- a hand-rolled
# pattern here is precisely the mistake this parameter exists to undo. check-ref-format rejects a space,
# '..', a '.lock' suffix, '*', '\', a leading '.', and a leading or trailing '/', but ACCEPTS a leading
# '-', which git's own argument parser would then read as a FLAG. That one case is refused separately.
# (Forbidding '*' is also why `git branch --list $Branch` below stays an exact existence probe, not a glob.)
if ($Branch.StartsWith('-')) { throw "-Branch may not start with '-': '$Branch'" }
& git check-ref-format ("refs/heads/" + $Branch)
if ($LASTEXITCODE -ne 0) { throw "-Branch is not a valid git branch name: '$Branch'" }

# Repo root is two levels up from scripts\worktree\.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Parent = Split-Path $RepoRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf
$WorktreePath = Join-Path $Parent "$RepoName-$Name"

# ASSERT what the ValidatePattern only IMPLIES: one path component, directly under the repo's parent.
# A proxy can be relaxed by someone who does not know what it was standing in for -- and this one
# already admitted more than it looked like it did (see the anchor note in the param block).
if ((Split-Path $WorktreePath -Parent) -ne $Parent) {
    throw "internal: -Name '$Name' did not derive a direct child of '$Parent' (got '$WorktreePath')."
}

# Structurally, two branches can slug to one directory ('claude/foo' and 'claude-foo'). Refuse loudly
# rather than auto-suffixing, which would make the directory name unpredictable across runs.
if (Test-Path $WorktreePath) {
    throw ("Worktree path already exists: $WorktreePath  (if it is yours, just work in it; otherwise " +
           "pass a different -Name -- -Name is only the DIRECTORY, so a worktree for branch '$Branch' " +
           "can use any free name)")
}

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
# Probe the BRANCH, not the directory name. With a sanitized -Name here the probe would come back empty
# and the -b path below would silently cut a BRAND-NEW branch off origin/main while the gate's deny text
# says the branch already exists and is being reused -- a quiet wrong success, worse than a loud failure.
$branchExists = & git -C $RepoRoot branch --list $Branch
Write-Host "Creating worktree '$WorktreePath' on branch '$Branch'..."

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
    & git -C $RepoRoot worktree add $WorktreePath $Branch
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
    & git -C $RepoRoot worktree add $WorktreePath -b $Branch $Base
}
} finally { Exit-CoordLock $addLock }
if ($LASTEXITCODE -ne 0) { throw "git worktree add failed (exit $LASTEXITCODE)" }

# Record this worktree's HOME branch in its PRIVATE git dir (<repo>/.git/worktrees/<id>/), so the
# SessionStart drift-detector in worktree-selfheal.ps1 can notice if the worktree is later SWITCHED onto
# another branch -- the worktree-hijack (docs/WORKTREES.md). Not the working tree and not shared config:
# it is per-worktree and untracked. Best-effort -- a failure here never blocks worktree creation.
try {
    $gitDir = "$(& git -C $WorktreePath rev-parse --absolute-git-dir 2>$null)".Trim()
    # The BRANCH, not -Name: worktree-selfheal.ps1 compares this against the worktree's actual HEAD, so
    # a directory slug here would mismatch BY CONSTRUCTION and fire a false hijack warning forever,
    # whose printed remedy would name a branch that does not exist.
    if ($gitDir) { Set-Content -LiteralPath (Join-Path $gitDir 'mefor-home-branch') -Value $Branch -Encoding utf8 }
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
    Write-Host "Worktree ready: $WorktreePath (branch '$Branch')" -ForegroundColor Green
    Write-Host "Next steps:"
    Write-Host "  cd `"$WorktreePath`""
    if (-not $NoInstall) {
        Write-Host "  .\.venv\Scripts\Activate.ps1        # use this worktree's env"
    }
    if ($Ide) {
        Write-Host "  code --extensionDevelopmentPath=`"$WorktreePath\ide`" `"$WorktreePath\mefor.code-workspace`""
    }
    Write-Host "  # ... build/commit/push on branch '$Branch'; open a PR as usual."
    # THE CLEANUP ADVICE NAMES $RepoRoot, NOT "the MAIN checkout" (BACKLOG #1078). This script anchors
    # on $PSScriptRoot, so run from a linked worktree it creates the new tree beside ITSELF -- and
    # remove.ps1 anchors on its own location too, so the MAIN checkout's copy would derive
    # <main-parent>\<main-leaf>-$Name, a path that does not exist, and throw "No such worktree". The
    # anchoring is correct (#1060); the sentence was not. Both forms below carry the root explicitly,
    # so they work from any cwd. -Name here is the DIRECTORY, which is what remove.ps1 takes --
    # correct even when it differs from the branch.
    #
    # EXTRACTION CONTRACT: a line beginning "  #   " (hash, THREE spaces) is a command meant to be run
    # verbatim; "  # " (hash, one space) is prose. tests/test_worktree_new_cleanup_advice.py extracts
    # the former and EXECUTES it against a synthetic repo, because advice that is only read is advice
    # nothing checks. Keep the two shapes distinct.
    Write-Host "  # When done, from any directory OUTSIDE the worktree, either of:"
    Write-Host "  #   pwsh -NoProfile -File `"$RepoRoot\scripts\worktree\remove.ps1`" -Name $Name"
    Write-Host "  #   git -C `"$RepoRoot`" worktree remove --force `"$WorktreePath`""
    # --force because the untracked .venv makes git consider the worktree non-empty. The first form is
    # the one to reach for: it refuses on uncommitted TRACKED changes, which the bare git call does not.
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
    # --constraint constraints.lock, exactly as EVERY install in ci.yml does. constraints.lock is the
    # HASHLESS export of uv.lock kept in sync by the DEP-1 gate; without it pip RE-RESOLVES inside
    # pyproject's ranges and a fresh worktree gets whatever PyPI serves today.
    #
    # Not hypothetical: a worktree created 2026-07-29 came up with ruff 0.16.0 while constraints.lock
    # pinned 0.15.22. That worktree then reported ~829 findings CI does not have — and because the
    # ruff pre-commit hook runs `ruff check --fix`, it REWROTE files to match, stripping `# noqa`
    # directives the pinned ruff still wants. A venv that lints differently from CI does not merely
    # mislead; it edits your source on commit.
    #
    # This is the same reasoning as the DEP-1 `--require-hashes` install, one rung down: CI proves the
    # lock installs, this makes a developer's environment agree with it.
    & $venvPy -m pip install --constraint constraints.lock -e ".[$extras]"
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
