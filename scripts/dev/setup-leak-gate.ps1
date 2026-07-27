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
$repo = (& git rev-parse --show-toplevel 2>$null)
if (-not $repo) { throw 'Not inside a git checkout.' }
$secDir  = Join-Path $repo 'scripts/security'
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
    Write-Host 'CONFIGURED (synthetic). Commits will pass; real customer tokens are NOT detected locally.' -ForegroundColor Yellow
    exit 0
}
Write-Host ''
Write-Host 'CONFIGURED with the real token set.' -ForegroundColor Green
exit 0
