# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Bootstrap a checkout's own .venv, installing exactly what CI's test leg installs. Idempotent.

.DESCRIPTION
    Split out of new.ps1 (which still calls it) so that a worktree the HARNESS created can be given
    the same environment. Claude Code's own `--worktree`, the desktop app and `isolation: worktree`
    subagents all create worktrees and install nothing into them; only new.ps1 ever bootstrapped one,
    and it can only bootstrap the siblings it makes. That population had no route to a locked venv.

    WHY THAT MATTERED ENOUGH TO SPLIT: without a venv, `pytest` does not run slowly against the wrong
    interpreter -- it dies at import. A worker there cannot run the checks its brief requires before
    committing, so the first real signal arrives in CI after its process is gone. That is a SILENT
    failure, and it is worse than a loud one. The counts, and the entry-point rule this enables, are
    in docs/WORKTREES.md section "Start the session in the worktree" -- stated once, there.

    IDEMPOTENT ON PURPOSE. A session cannot know whether its worktree already has an environment, so
    this is safe to run unconditionally at the start of one: with a usable interpreter already
    present it prints one line and returns, touching nothing. Nothing here removes a directory --
    to rebuild an environment, delete .venv yourself first.

    THIS FILE OWNS THE INSTALL LINE, and two tests read it here: the extras must equal ci.yml's test
    leg (tests/test_worktree_venv_extras_parity.py) and the install must pin --constraint
    constraints.lock (tests/test_worktree_venv_constraint.py). Keeping ONE declaration is the point;
    a copy in each script is the drift those tests exist to catch.

.EXAMPLE
    .\ensure-venv.ps1                      # bootstrap the worktree you are standing in
    .\ensure-venv.ps1 -Path C:\src\mf-x    # bootstrap a named one
    .\ensure-venv.ps1 -Sqlserver           # also install the [sqlserver] extra
#>
[CmdletBinding()]
param(
    # The checkout to bootstrap. Defaults to the current directory, which is the ordinary case: a
    # session runs this in its own worktree. Resolved to the checkout ROOT via git, so running it
    # from a subdirectory does the right thing instead of creating a stray .venv there.
    [string]$Path = $PWD.Path,
    [string]$Python = "python",
    [switch]$Sqlserver   # also install the [sqlserver] extra
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) { throw "No such path: $Path" }

# Ask GIT for the checkout root rather than walking parents ourselves. A worktree's root is not
# derivable from the path shape -- that is the whole reason the two layouts diverged -- and this
# resolves a linked worktree, a nested one and the primary identically.
$root = & git -C $Path rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -ne 0 -or -not $root) { throw "Not a git checkout: $Path" }
$root = (Resolve-Path -LiteralPath ($root.Trim())).Path

# Refuse a checkout that is not this project. Without this, a mistyped -Path silently builds a venv
# and installs an unrelated package tree into it, and the failure surfaces much later as an import
# error nobody connects back to here.
if (-not (Test-Path -LiteralPath (Join-Path $root 'pyproject.toml'))) {
    throw "Not a MessageFoundry checkout (no pyproject.toml): $root"
}

$venv = Join-Path $root ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"

if (Test-Path -LiteralPath $venvPy) {
    Write-Host "venv already present, nothing to do: $venvPy" -ForegroundColor Green
    return
}

# EXTRAS MUST MATCH ci.yml's TEST LEG, and the reason is a FALSE GREEN rather than convenience
# (BACKLOG #1335). A lane installing fewer extras COLLECTS FEWER TESTS: the extras-gated suites skip
# at MODULE scope, so a large number of absent tests collapses into a handful of skip lines and the
# lane reads green over a tree it never ran. `testpaths` also collects the web console suite, which
# needs the console package installed -- without it that whole suite is silently absent.
#
# KEPT IN SYNC BY A TEST, NOT BY CARE: tests/test_worktree_venv_extras_parity.py fails if this line
# and ci.yml's install line drift. Same remedy tests/test_lint_scope_parity.py already applies to
# ruff and bandit, whose scopes were written twice and drifted until a test held them together.
$extras = if ($Sqlserver) { "dev,harness,fhir,dicom,x12,xml,webauthn,vault,sqlserver" } else { "dev,harness,fhir,dicom,x12,xml,webauthn,vault" }

Write-Host "Creating virtualenv + installing .[$extras] in $root (this can take a minute)..."
& $Python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw "venv creation failed (is '$Python' on PATH?)" }
& $venvPy -m pip install --upgrade pip | Out-Null

Push-Location $root
try {
    # --constraint constraints.lock, exactly as EVERY install in ci.yml does. constraints.lock is the
    # HASHLESS export of uv.lock kept in sync by the DEP-1 gate; without it pip RE-RESOLVES inside
    # pyproject's ranges and a fresh worktree gets whatever PyPI serves today.
    #
    # Not hypothetical: a worktree created 2026-07-29 came up with ruff 0.16.0 while constraints.lock
    # pinned 0.15.22. That worktree then reported ~829 findings CI does not have -- and `ruff check
    # --fix` REWROTE files to match, stripping `# noqa` directives the pinned ruff still wants. A venv
    # that lints differently from CI does not merely mislead; it edits your source.
    #
    # NARROWED 2026-08-18. That `--fix` WAS the pre-commit hook at the time -- `language: system`, so
    # it ran whatever ruff the shell's PATH offered -- which is what made the rewrite land on commit,
    # unasked. The ruff hooks now install their own pinned ruff (see .pre-commit-config.yaml's ruff
    # block), so a commit still rewrites source -- `ruff-format` writes and `ruff-check` keeps
    # `args: [--fix]` -- but it is the PINNED ruff doing it, which agrees with CI. What THIS venv's
    # ruff still drives is the hand run: CLAUDE.md section 7's bare `ruff format .` writes with
    # whatever ruff this venv resolved. The flag below is not thereby less needed -- nothing in
    # .pre-commit-config.yaml pins mypy or pytest, so a freely re-resolved venv still moves at least
    # those two off CI.
    #
    # This is the same reasoning as the DEP-1 `--require-hashes` install, one rung down: CI proves the
    # lock installs, this makes a developer's environment agree with it.
    & $venvPy -m pip install --constraint constraints.lock -e ".[$extras]" -e packaging/messagefoundry-webconsole
    if ($LASTEXITCODE -ne 0) { throw "pip install -e .[$extras] + webconsole failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "venv ready: $venvPy" -ForegroundColor Green
