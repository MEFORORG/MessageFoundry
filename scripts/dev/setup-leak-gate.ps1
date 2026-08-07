<#
.SYNOPSIS
    Configure the forbidden-content (customer/PHI leak) gate for THIS checkout, then prove it can see.

.DESCRIPTION
    The gate's token list is private and git-ignored, so it does NOT travel with a clone or a
    `git worktree add`. Every fresh checkout therefore starts with no token source, and the
    pre-commit hook -- which passes --require-tokens deliberately -- fails closed on every commit.
    That is correct behaviour with an undocumented bootstrap; this script is the bootstrap.

    Choose ONE:

      -From <path>   Install the REAL token list (maintainers). The file is copied to the
                     git-ignored scripts/security/scan-tokens.local.txt.
      -Synthetic     Copy the committed synthetic template (outside contributors, who cannot have
                     the real list). The gate then runs, but is BLIND to real customer tokens --
                     the scanner announces this on every run, and CI remains authoritative.
      (no switch)    Report the current state only; change nothing.

    WHY THE VERIFY STEP IS NOT OPTIONAL. A green gate is evidence only if you confirmed it can see
    the class it is meant to catch. This repo has repeatedly hit gates that were green because they
    never ran, or ran with nothing loaded. So this script always finishes by invoking the scanner and
    printing the per-section detector counts, and exits non-zero if the sections are empty.

.EXAMPLE
    pwsh -NoProfile -File scripts/dev/setup-leak-gate.ps1 -From C:\path\to\tokens.txt
.EXAMPLE
    pwsh -NoProfile -File scripts/dev/setup-leak-gate.ps1 -Synthetic
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Real', Mandatory)][string]$From,
    [Parameter(ParameterSetName = 'Synthetic', Mandatory)][switch]$Synthetic
)

$ErrorActionPreference = 'Stop'

# Repo root = parent of scripts\ = parent of this script's dir (scripts\dev). Same form postgres.ps1 and
# sqlserver.ps1 in this directory already use.
#
# NOT `git rev-parse --show-toplevel`: that resolves against the CURRENT DIRECTORY, not against the path
# this script was handed. Invoked by absolute -File path from another worktree -- the ordinary shape on a
# clone carrying dozens of them -- it armed the CALLER's checkout and printed CONFIGURED about that one,
# while the checkout the operator named kept no token source and went on failing closed (BACKLOG #1063).
# An absolute -File invocation is naming the checkout to act on; it must not then consult a different one.
# -From names the token SOURCE, not the checkout, so it never covered this.
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$secDir  = Join-Path $repo 'scripts/security'
# ASSERT what the derivation only IMPLIES. Discovering a wrong root later, as a confusing scanner
# failure, is how this class stays invisible; new.ps1 takes the same posture after deriving its path.
if (-not (Test-Path -LiteralPath $secDir)) {
    throw "Derived repo root has no scripts/security -- this script must live in <repo>/scripts/dev/: $repo"
}
$local   = Join-Path $secDir 'scan-tokens.local.txt'
$example = Join-Path $secDir 'scan-tokens.local.txt.example'
$scanner = Join-Path $secDir 'scan_forbidden.py'

if ($PSCmdlet.ParameterSetName -eq 'Real') {
    if (-not (Test-Path -LiteralPath $From)) { throw "No such token file: $From" }
    Copy-Item -LiteralPath $From -Destination $local -Force
    Write-Host "Installed the real token list -> scripts/security/scan-tokens.local.txt" -ForegroundColor Green
}
elseif ($PSCmdlet.ParameterSetName -eq 'Synthetic') {
    Copy-Item -LiteralPath $example -Destination $local -Force
    Write-Host "Installed the SYNTHETIC template -> scripts/security/scan-tokens.local.txt" -ForegroundColor Yellow
    Write-Host "  This gate cannot see real customer tokens. CI runs the real set on your PR." -ForegroundColor Yellow
}

# Printed for BOTH installs, not just the synthetic one. Either list arms the site-code detectors, and
# with the REAL list a placeholder built from a listed prefix is an actual disclosure rather than a
# false positive -- so the maintainer arm is the one that needs this more, not less.
if ($PSCmdlet.ParameterSetName -ne 'Status') {
    Write-Host "  Writing a placeholder site code? Use a NON-NUMERIC stand-in (SITEA, or <site>) -- one built from a prefix in the installed list is a hit here." -ForegroundColor Yellow
}

# The token file must never become committable. Verify rather than assume -- this is the one mistake
# that would publish the very list the gate protects.
if (Test-Path -LiteralPath $local) {
    $ignored = & git -C $repo check-ignore -- 'scripts/security/scan-tokens.local.txt' 2>$null
    if (-not $ignored) {
        Remove-Item -LiteralPath $local -Force
        throw 'scan-tokens.local.txt is NOT git-ignored in this checkout. Removed it rather than risk committing the token list.'
    }
}

# --- verify: what can the gate actually SEE? -------------------------------------------------------
$py = if (Test-Path (Join-Path $repo '.venv/Scripts/python.exe')) { Join-Path $repo '.venv/Scripts/python.exe' } else { 'python' }
Write-Host ''
Write-Host 'Verifying the gate can see:' -ForegroundColor Cyan
$out = & $py $scanner --require-tokens 2>&1
$loaded = $out | Where-Object { $_ -match 'loaded names=' } | Select-Object -First 1
if (-not $loaded) { Write-Host ($out | Select-Object -Last 5); throw 'Scanner produced no detector-count line.' }
Write-Host "  $loaded"

if ($loaded -match 'STRUCTURAL-ONLY') {
    Write-Host ''
    Write-Host 'NOT CONFIGURED — the pre-commit hook will fail closed on every commit.' -ForegroundColor Red
    Write-Host '  Maintainers: -From <path to the real list>     Contributors: -Synthetic'
    exit 1
}
if ($loaded -match 'SYNTHETIC') {
    Write-Host ''
    Write-Host 'CONFIGURED (synthetic). Real customer tokens are NOT detected locally.' -ForegroundColor Yellow
    Write-Host '  It also flags the fictional customer/partner names this project uses in its own docs, so a hit here is not by itself a leak. CI is authoritative.' -ForegroundColor Yellow
    exit 0
}
Write-Host ''
Write-Host 'CONFIGURED with the real token set.' -ForegroundColor Green
exit 0
