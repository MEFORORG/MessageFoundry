# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

    IT ALSO NAMES THE SOURCE THOSE COUNTS CAME FROM, and says so when the environment overrode the
    file just written (BACKLOG #1080). MEFOR_FORBIDDEN_TOKENS wins over
    scripts/security/scan-tokens.local.txt, so -Synthetic could install the template and then report
    the REAL set as configured -- two true lines that together read as a contradiction. Counts without
    a provenance leave exactly the ambiguity this step exists to close. Two consequences worth knowing:
    an inline (non-path) MEFOR_FORBIDDEN_TOKENS value is named but never PRINTED, because that value
    is the token list; and the scanner's exit code is now propagated, so a refusal is reported as
    VERIFY FAILED instead of coming back out as CONFIGURED.

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

# Every git call this script makes, its own and the scanner's, must answer about $repo. An inherited
# location variable -- exported by a hook, or left behind in the operator's shell -- outranks both -C
# and the current directory, so the scan would list another repository's tracked files (or another
# index), and check-ignore would read another repository's exclude rules, each reported as this
# checkout's. The list is the location set scripts/worktree/worktree-gates.ps1 refuses
# ($GIT_REDIRECT_NAMES); keep the two in step. Each call runs with them dropped, and they are
# restored afterwards so a caller that dot-sources or invokes this in-process keeps its environment.
$gitRedirects = 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE'
function Invoke-WithoutGitRedirect([scriptblock]$Body) {
    $saved = @{}
    foreach ($name in $gitRedirects) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name)
        # Remove-Item, not SetEnvironmentVariable($name, $null): PowerShell binds that $null to the
        # [string] parameter as '', and git then reads GIT_DIR='' as a (missing) repository.
        Remove-Item -LiteralPath "Env:$name" -ErrorAction Ignore
    }
    try { & $Body }
    finally {
        foreach ($name in $gitRedirects) {
            if ($null -ne $saved[$name]) { Set-Item -LiteralPath "Env:$name" -Value $saved[$name] }
        }
    }
}

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
    $ignored = Invoke-WithoutGitRedirect { & git -C $repo check-ignore -- 'scripts/security/scan-tokens.local.txt' 2>$null }
    if (-not $ignored) {
        Remove-Item -LiteralPath $local -Force
        throw 'scan-tokens.local.txt is NOT git-ignored in this checkout. Removed it rather than risk committing the token list.'
    }
}

# --- which source will the scanner ACTUALLY load from? ---------------------------------------------
# The verify step below reports the LOADED token set. Reporting only that is what let -Synthetic print
# "Installed the SYNTHETIC template" and then, three lines later, "CONFIGURED with the real token set"
# (BACKLOG #1080). Both were true -- the file was installed, and MEFOR_FORBIDDEN_TOKENS won over it --
# but nothing said the environment had OVERRIDDEN what had just been written, so the pair read as a
# contradiction or, worse, as confirmation that a synthetic install had produced a real-token gate.
#
# PRECEDENCE IS DEFINED BY scan_forbidden._resolve_token_text, NOT HERE. This is a second expression of
# it and would drift silently, so tests/test_setup_leak_gate_reports_source.py measures every branch
# below against the scanner's own detector counts in the SAME run rather than trusting either alone.
$envTokens = [Environment]::GetEnvironmentVariable('MEFOR_FORBIDDEN_TOKENS')
$envEmpty = $false
if ($null -ne $envTokens) {
    $trimmed = $envTokens.Trim()
    if (-not $trimmed) {
        # An explicitly-EMPTY value means "no source" and does NOT fall back to the file. Worth naming,
        # because in this one state installing a token list changes nothing and the ordinary advice
        # ("-From <path>" / "-Synthetic") sends the operator round the same loop indefinitely.
        $envEmpty = $true
        $source = 'NONE -- MEFOR_FORBIDDEN_TOKENS is set but EMPTY, which the scanner reads as "no source" (it does NOT fall back to the file)'
    }
    else {
        # Probed APPROXIMATELY as the scanner probes it, with Python's Path(value).is_file() from $repo,
        # where both the verify step below and the pre-commit hook run it (BACKLOG #5467): a relative
        # path is relative to the checkout, and no `~` or PSDrive is expanded, as Test-Path would. NOT
        # identical: a trailing separator, a drive- or root-relative Windows form, and a POSIX `..`
        # through a symlink can resolve differently here, so in those cases the label below can
        # disagree with what the scanner loaded. The counts line is the scanner's own answer.
        $tokenPath = $null
        try { $tokenPath = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, $trimmed)) } catch { $tokenPath = $null }
        if ($tokenPath -and [IO.File]::Exists($tokenPath)) { $source = "MEFOR_FORBIDDEN_TOKENS -> $tokenPath" }
        # NEVER echo the value. A non-path value IS the token list, carried inline; naming the variable
        # is the whole diagnostic, and printing its content would publish exactly what this protects
        # into whatever log the operator happened to be capturing.
        else { $source = 'MEFOR_FORBIDDEN_TOKENS (inline token content -- value deliberately not printed)' }
    }
    $fromFile = $false
}
elseif (Test-Path -LiteralPath $local) {
    $source = 'scripts/security/scan-tokens.local.txt'
    $fromFile = $true
}
else {
    $source = 'NONE -- no MEFOR_FORBIDDEN_TOKENS, and scripts/security/scan-tokens.local.txt is absent'
    $fromFile = $false
}

# --- verify: what can the gate actually SEE? -------------------------------------------------------
# The checkout's own venv, in this platform's layout: Scripts\python.exe on Windows, bin/python on
# POSIX (BACKLOG #5467). Only the platform's own layout is probed, since a POSIX venv's interpreter
# cannot be launched on Windows. Without one it falls back to whatever `python` PATH offers.
# [Environment]::OSVersion rather than $IsWindows, which Windows PowerShell 5.1 does not define
# (scripts/worktree/ensure-venv.ps1 takes the same form).
$onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$venvPy = Join-Path $repo $(if ($onWindows) { '.venv/Scripts/python.exe' } else { '.venv/bin/python' })
$py = if (Test-Path -LiteralPath $venvPy -PathType Leaf) { $venvPy } else { 'python' }
Write-Host ''
Write-Host 'Verifying the gate can see:' -ForegroundColor Cyan
# Run FROM the derived repo root (BACKLOG #5467). With no path argument the scanner lists the tracked
# files of its CURRENT DIRECTORY (scan_forbidden._git_tracked), while its token list is anchored on its
# own location. Run from the caller's directory, the verify step scanned the CALLER's checkout with this
# checkout's tokens -- and outside any git directory it failed outright -- which is the same
# wrong-checkout class the $repo derivation above closes for the install (BACKLOG #1063).
Push-Location -LiteralPath $repo
try {
    $scan = Invoke-WithoutGitRedirect {
        $scanOut = & $py $scanner --require-tokens 2>&1
        # Captured on the very next line, before any other native call can overwrite it. The scanner's
        # verdict used to be discarded entirely, so a refusal came back out of here as CONFIGURED and
        # exit 0 -- which contradicts this file's own header promise to "exit non-zero if the sections
        # are empty".
        [pscustomobject]@{ Out = $scanOut; Exit = $LASTEXITCODE }
    }
    $out = $scan.Out
    $scanExit = $scan.Exit
}
finally {
    Pop-Location
}
$loaded = $out | Where-Object { $_ -match 'loaded names=' } | Select-Object -First 1
if (-not $loaded) { Write-Host ($out | Select-Object -Last 5); throw 'Scanner produced no detector-count line.' }
Write-Host "  $loaded"
Write-Host "  token source: $source"
if ($PSCmdlet.ParameterSetName -ne 'Status' -and -not $fromFile) {
    Write-Host '  OVERRIDDEN: the file this run just installed is NOT what the gate loaded -- MEFOR_FORBIDDEN_TOKENS takes precedence over scripts/security/scan-tokens.local.txt.' -ForegroundColor Yellow
    Write-Host '              Unset that variable to use the file you just installed.' -ForegroundColor Yellow
}

if ($loaded -match 'STRUCTURAL-ONLY') {
    Write-Host ''
    Write-Host 'NOT CONFIGURED -- the pre-commit hook will fail closed on every commit.' -ForegroundColor Red
    if ($envEmpty) {
        Write-Host '  CAUSE: MEFOR_FORBIDDEN_TOKENS is set to an EMPTY value, which the scanner reads as "no source".' -ForegroundColor Red
        Write-Host '  Installing a token list will NOT fix this -- unset that variable first.' -ForegroundColor Red
    }
    else {
        Write-Host '  Maintainers: -From <path to the real list>     Contributors: -Synthetic'
    }
    exit 1
}
if ($scanExit -ne 0) {
    Write-Host ''
    Write-Host "VERIFY FAILED -- a token source is loaded but the scanner EXITED $scanExit." -ForegroundColor Red
    Write-Host "  token source: $source"
    # Its output is NOT reprinted here: a hit line can quote matched content, and copying that into a
    # terminal scrollback, a ticket or a CI log is the disclosure this whole gate exists to prevent.
    Write-Host "  Re-run the scanner yourself, from $repo, to see why, and do not paste its output anywhere:" -ForegroundColor Red
    Write-Host "      $py scripts/security/scan_forbidden.py --require-tokens"
    exit $scanExit
}
if ($loaded -match 'SYNTHETIC') {
    Write-Host ''
    Write-Host "CONFIGURED (synthetic), loaded from: $source. Real customer tokens are NOT detected locally." -ForegroundColor Yellow
    Write-Host '  It also flags the fictional customer/partner names this project uses in its own docs, so a hit here is not by itself a leak. CI is authoritative.' -ForegroundColor Yellow
    exit 0
}
Write-Host ''
Write-Host "CONFIGURED with the real token set, loaded from: $source." -ForegroundColor Green
exit 0
