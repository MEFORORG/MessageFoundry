# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Install the CLAIM gate (commit-msg) in the SHARED .git/hooks — one copy governs every worktree at
    once. The LEDGER gate is no longer installed here; it runs via .pre-commit-config.yaml.

.DESCRIPTION
    `.git/hooks` lives in the COMMON git directory, which every linked worktree shares. So a single file
    there:

      * reaches ALL worktrees the instant it is written -- no branch, no merge, no propagation lag (a
        hook committed to a branch protects nothing until every other worktree merges it);
      * survives a branch switch in any of them (it sits outside every working tree); and
      * sees EVERY write route -- the Edit tool, a shell redirect, Set-Content, python -c, VS Code, a
        subagent -- because it inspects the TREE at commit time, not a tool call.

    That last property is why this exists alongside the worktree gate (scripts/hooks/worktree_gate.ps1):
    the worktree gate inspects tool arguments, so a file written by a shell command is invisible to it.
    This is that backstop.

    WHY THE LEDGER GATE MOVED OUT OF HERE (2026-07-27). It used to be installed as a standalone
    .git/hooks/pre-commit. Two tools cannot both own that file: this script refused to overwrite a
    foreign hook, and `pre-commit install` responded by renaming ours to pre-commit.legacy and calling
    it from its own shim. That works on POSIX and FAILS ON WINDOWS -- pre-commit invokes the legacy hook
    from a Python subprocess, which cannot resolve `#!/bin/sh`:

        ExecutableNotFoundError: Executable `/bin/sh` not found

    Measured: every commit in the repo was blocked until the shim was uninstalled. Note that
    pre-commit.legacy EXISTING did not indicate success -- only a real commit did. The ledger gate is
    therefore a `local` hook in .pre-commit-config.yaml (id: ledger-gate) and pre-commit owns the file
    alone. Running this script now MIGRATES an old install by removing our standalone hook.

    TRADE-OFF, stated because it is real: the ledger gate's availability is now coupled to pre-commit
    being installed. This script warns loudly when it is not. The claim gate stays a commit-msg hook --
    only commit-msg receives the message file, so it cannot move.

    ledger_check.py is stdlib-only and imports nothing from messagefoundry, so it still runs in a
    worktree with no project .venv.

    Run from a plain terminal. `git commit --no-verify` bypasses both -- that is a guardrail, not a
    security boundary, and the --ci leg is the backstop for exactly that.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1
    pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Status
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$common = (& git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir).Trim()
if (-not $common) { throw "Not inside a git repository." }

$hooksPath = (& git -C $RepoRoot config --get core.hooksPath)
if ($hooksPath) {
    $hooksDir = if ([System.IO.Path]::IsPathRooted($hooksPath)) { $hooksPath } else { Join-Path $RepoRoot $hooksPath }
} else {
    $hooksDir = Join-Path $common "hooks"
}
$preCommit = Join-Path $hooksDir "pre-commit"
$marker = "MessageFoundry ledger gate"
# BACKLOG #309: the claim gate must be a COMMIT-MSG hook, not pre-commit -- pre-commit never receives the
# commit message, so a claim check bolted onto it would look installed and silently never fire.
$commitMsg = Join-Path $hooksDir "commit-msg"
$claimMarker = "MessageFoundry claim gate"
$prePush = Join-Path $hooksDir "pre-push"
$pushMarker = "MessageFoundry push guard"
# The durability hook is a POST-commit hook, and it must be: it needs a commit to exist before it can
# push one. It is also the only hook here installed VERBATIM rather than as a shim -- it has no Python
# payload to locate, so there is nothing for a shim to resolve.
$postCommit = Join-Path $hooksDir "post-commit"
$durabilityMarker = "MessageFoundry durability hook"

# The .py PAYLOADS the install path below Copy-Items into $hooksDir, listed for -Status to audit. The
# install path still names its own file per section, because each carries its own why -- so a THIRD
# payload has to be added in both places. tests/test_installed_coord_hooks.py reads this list out of
# this script rather than carrying its own copy, so at least the test cannot fall behind it.
$payloads = @("claim_check.py", "push_guard.py")

function Get-HookPayloadHash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    # A CONTENT hash, not a byte hash, and byte-for-byte the SAME fold as scripts\worktree\
    # install-gate.ps1's Get-GateHash and tests\test_gate_installed_parity.py's content_hash. Three
    # instruments that fold differently would disagree about one file, which is the same defect one
    # level up; the reasoning for folding at all is stated once, in Get-GateHash. Short version: the
    # install below is a Copy-Item, which translates nothing, so the installed copy carries whatever
    # line endings the checkout that installed it had -- raw bytes answer "are these the same bytes",
    # which is a different question from the one asked here.
    #
    # Folded on BYTES (drop the CR of each CRLF pair) rather than by decoding to text: the payload need
    # not be valid UTF-8, and a decode/re-encode round trip could move a BOM or a lone high byte and
    # change the digest for a reason that has nothing to do with content.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $out = [System.Collections.Generic.List[byte]]::new($bytes.Length)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 13 -and ($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
        $out.Add($bytes[$i])
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        (($sha.ComputeHash($out.ToArray()) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
    } finally {
        $sha.Dispose()
    }
}

if ($Status) {
    $stale = (Test-Path $preCommit) -and ((Get-Content $preCommit -Raw -EA SilentlyContinue) -match [regex]::Escape($marker))
    $claimInstalled = (Test-Path $commitMsg) -and ((Get-Content $commitMsg -Raw -EA SilentlyContinue) -match [regex]::Escape($claimMarker))
    # The ledger gate is a pre-commit hook now, so "is it armed" means "did pre-commit install its
    # shim" -- reporting on OUR marker would say 'not installed' for a perfectly healthy setup.
    $pcShim = (Test-Path $preCommit) -and ((Get-Content $preCommit -Raw -EA SilentlyContinue) -match 'File generated by pre-commit')
    Write-Host "hooks dir  : $hooksDir"

    # WHERE WORK CLAIMS LIVE, which is not always this repository (BACKLOG #1346). The commit-msg gate
    # below refuses a code-touching commit whose SUBJECT cites a ledger number unless a claim for THIS
    # tree exists in that registry -- so an operator reading a refusal needs to know which directory the
    # gate actually opened. Nothing anywhere said, and that silence is most of why the split between the
    # tool's registry and the gate's went unnoticed: a refusal against a registry in another repository
    # is indistinguishable, from the outside, from an item nobody has claimed.
    $claimsRoot = (& git -C $RepoRoot config --get mefor.claimsRoot)
    if ($claimsRoot) {
        $claimsRoot = $claimsRoot.Trim()
        $rootTop = (& git -C $claimsRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
        if ($rootTop) {
            $rootCommon = (& git -C $rootTop.Trim() rev-parse --path-format=absolute --git-common-dir).Trim()
            Write-Host "claims     : $(Join-Path $rootCommon 'mefor-coord/claims')"
            Write-Host "             ^ SHARED -- mefor.claimsRoot points at $($rootTop.Trim())"
        }
        else {
            Write-Host "claims     : UNRESOLVABLE -- mefor.claimsRoot names '$claimsRoot'," -ForegroundColor Red
            Write-Host "             which is not a git repository. The claim gate FAILS CLOSED on this," -ForegroundColor Red
            Write-Host "             so every code-touching commit citing a ledger number is refused" -ForegroundColor Red
            Write-Host "             until it is corrected or unset:" -ForegroundColor Red
            Write-Host "                 git -C $RepoRoot config --unset mefor.claimsRoot" -ForegroundColor Red
        }
    }
    else {
        Write-Host "claims     : $(Join-Path $common 'mefor-coord/claims')  (this repository's own)"
    }
    Write-Host "commit-msg : $(if ($claimInstalled) { 'INSTALLED (claim gate)' } elseif (Test-Path $commitMsg) { 'present, but NOT ours' } else { 'not installed' })"
    Write-Host "pre-commit : $(if ($pcShim) { 'pre-commit framework (carries the ledger gate + leak gate)' } elseif ($stale) { 'STALE standalone ledger hook -- re-run this script to migrate' } elseif (Test-Path $preCommit) { 'present, but NOT ours' } else { 'NOT INSTALLED -- run: pre-commit install' })"
    if ($stale) {
        Write-Host "             ^ a leftover standalone hook will make `pre-commit install` chain to" -ForegroundColor Yellow
        Write-Host "               pre-commit.legacy, which FAILS on Windows and blocks every commit." -ForegroundColor Yellow
    }
    $pushInstalled = (Test-Path $prePush) -and ((Get-Content $prePush -Raw -EA SilentlyContinue) -match [regex]::Escape($pushMarker))
    Write-Host "pre-push   : $(if ($pushInstalled) { 'INSTALLED (push guard)' } elseif (Test-Path $prePush) { 'present, but NOT ours' } else { 'NOT INSTALLED' })"

    # The durability hook reports on TWO axes, because installed and armed are different states and
    # only one of them protects anything. An installed hook with no nominated remote is a no-op by
    # design (fail-safe by absence), and reporting it as INSTALLED alone would be the same
    # manufactured confidence the check in scripts/coord/unbacked_check.ps1 exists to avoid.
    $durInstalled = (Test-Path $postCommit) -and ((Get-Content $postCommit -Raw -EA SilentlyContinue) -match [regex]::Escape($durabilityMarker))
    $durRemote = (& git -C $RepoRoot config --get mefor.durabilityRemote)
    Write-Host "post-commit: $(if ($durInstalled) { 'INSTALLED (durability hook)' } elseif (Test-Path $postCommit) { 'present, but NOT ours' } else { 'NOT INSTALLED' })"
    if ($durInstalled -and -not $durRemote) {
        Write-Host "             ^ INSTALLED BUT NOT ARMED. mefor.durabilityRemote is unset, so the hook" -ForegroundColor Yellow
        Write-Host "               exits 0 without pushing. Nothing is being made durable. Arm it with:" -ForegroundColor Yellow
        Write-Host "                 git config mefor.durabilityRemote <private-remote>" -ForegroundColor Yellow
        Write-Host "               Confirm the remote is PRIVATE first: gh repo view <owner>/<repo> --json visibility" -ForegroundColor Yellow
    } elseif ($durInstalled -and $durRemote) {
        $durUrl = (& git -C $RepoRoot remote get-url $durRemote 2>$null)
        if (-not $durUrl) {
            Write-Host "             ^ ARMED at remote '$durRemote', which DOES NOT EXIST in this repo." -ForegroundColor Red
            Write-Host "               The hook exits 0 silently, so this looks identical to working." -ForegroundColor Red
        } elseif ($durUrl -match 'MEFORORG/MessageFoundry') {
            Write-Host "             ^ POINTED AT THE PUBLIC CANONICAL REPO. The hook refuses this target," -ForegroundColor Red
            Write-Host "               so nothing is being made durable AND nothing is being published." -ForegroundColor Red
        } else {
            Write-Host "             ^ armed -> $durRemote ($durUrl)"
            Write-Host "               Visibility is NOT verified here -- git cannot see it. Confirm once:"
            Write-Host "                 gh repo view <owner>/<repo> --json visibility"
        }
    }

    # PAYLOAD parity. Everything above this point tests a marker in a SHIM -- for commit-msg/pre-push
    # the marker this script writes, for pre-commit that tool's own "File generated by pre-commit"
    # (a file this script deliberately never writes; see the DIAGNOSE-never-write note below). Either
    # way it answers "is a hook of the right shape present" and NOT "is the .py that hook execs the
    # one in this checkout".
    # The shims are here-strings that change once in months, so they keep reading INSTALLED across an
    # arbitrarily old payload -- and the payload is where every rule the gate enforces actually lives.
    # Measured 2026-08-04: the installed push_guard.py hashed d4a57428cb2c against a committed source of
    # 82f4adbfde30 -- a whole class of drift with no instrument pointed at it. (Digests, not byte counts:
    # a size delta is itself a function of line endings, the very thing being folded out.) It matters
    # more here than for a per-worktree file because .git/hooks lives in the COMMON git dir: one stale
    # copy governs EVERY worktree at once, and the source-side tests keep passing while it does.
    # tests/test_installed_coord_hooks.py asserts the same parity from the pytest side.
    #
    # Both payloads are reported every run, never just the offender: the install path copies both, so
    # "re-install to fix this one" is the wrong mental model of what re-running does.
    $shortSha = { param($h) if ($h) { $h.Substring(0, 12).ToLowerInvariant() } else { "(absent)" } }
    foreach ($payload in $payloads) {
        $srcPy = Join-Path $RepoRoot "scripts\hooks\$payload"
        $dstPy = Join-Path $hooksDir $payload
        $iSha = Get-HookPayloadHash $dstPy
        $sSha = Get-HookPayloadHash $srcPy
        Write-Host "payload    : $payload  installed $(& $shortSha $iSha) / source $(& $shortSha $sSha)"
        if (-not $iSha) {
            Write-Host "             ^ NOT INSTALLED at $dstPy." -ForegroundColor Yellow
            Write-Host "               If the matching hook above reads INSTALLED, its shim execs this missing" -ForegroundColor Yellow
            Write-Host "               file; where python resolves it exits nonzero and fails closed, blocking" -ForegroundColor Yellow
            Write-Host "               every worktree. Where python does NOT resolve the shim now refuses too" -ForegroundColor Yellow
            Write-Host "               (it used to exit 0 and let the push through unchecked)." -ForegroundColor Yellow
        } elseif (-not $sSha) {
            Write-Host "             ^ no source at $srcPy -- the installed copy cannot be judged." -ForegroundColor Yellow
        } elseif ($iSha -eq $sSha) {
            Write-Host "             ^ IN SYNC -- identical CONTENT (line endings are folded out, not compared)."
        } else {
            Write-Host "             ^ *** STALE *** the payload that RUNS differs in CONTENT from this checkout's." -ForegroundColor Red
            Write-Host "               CRLF vs LF cannot produce this. Until the installed copy is replaced," -ForegroundColor Red
            Write-Host "               changes made to the source have no effect. Only" -ForegroundColor Red
            Write-Host "               tests/test_installed_coord_hooks.py notices; source-side tests stay green." -ForegroundColor Red
            Write-Host "               WORK OUT WHICH COPY IS OLDER FIRST. Re-installing from a checkout older" -ForegroundColor Yellow
            Write-Host "               than the installed hook downgrades it for every worktree on this box:" -ForegroundColor Yellow
            Write-Host "                 git log --oneline -5 -- scripts/hooks/$payload"
            Write-Host "               Only once THIS checkout is confirmed newer, from a PLAIN terminal:" -ForegroundColor Yellow
            Write-Host "                 pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1"
        }
    }
    # Report WHERE the shim's interpreter points. This script does not (and must not) rewrite that file
    # -- see the "DIAGNOSE, never write" note below -- so this is a diagnostic with a remedy, not a
    # pending action. It matters because the path is baked in at `pre-commit install` time and can name
    # a worktree that no longer exists, which fails every commit in every worktree at once.
    #
    # (?m) so ^ anchors per LINE: Get-Content -Raw yields ONE string, and piping that to Select-String
    # with a ^ anchor silently matches nothing -- the diagnostic would just vanish (it did).
    if ($pcShim -and ((Get-Content $preCommit -Raw -EA SilentlyContinue) -match "(?m)^INSTALL_PYTHON='(.+)'\s*$")) {
        $pinnedPy = $Matches[1]
        # The PRIMARY checkout is the only non-disposable one: it owns the common git dir, so it cannot
        # be `git worktree remove`d. Anything else -- a sibling clone-style worktree like
        # MessageFoundry-ledger just as much as one under .claude/worktrees/ -- can vanish. Testing for
        # a `.claude\worktrees\` path missed exactly that case, so derive the primary from $common
        # instead of pattern-matching a layout convention.
        $primaryRoot = (Split-Path -Parent $common)
        # EXACT match against the primary's own venv, not a path-prefix test. Three traps, all hit while
        # writing this:
        #   * `"...\MessageFoundry-ledger\...".StartsWith("...\MessageFoundry")` is TRUE, so a bare
        #     prefix test reports a SIBLING worktree as the primary.
        #   * git returns the common dir with FORWARD slashes (C:/Users/...) while INSTALL_PYTHON uses
        #     backslashes, so an un-normalised compare never matches at all.
        #   * even a boundary-correct prefix test is wrong here: a worktree under
        #     `<primary>\.claude\worktrees\<name>` is INSIDE the primary's path and is still removable.
        #     Only the primary's own `.venv` is non-removable, so compare against exactly that.
        $normPinned = [System.IO.Path]::GetFullPath($pinnedPy)
        $primaryVenvPys = @(
            (Join-Path $primaryRoot ".venv\Scripts\python.exe"),
            (Join-Path $primaryRoot ".venv/bin/python")
        ) | ForEach-Object { [System.IO.Path]::GetFullPath($_) }
        if (-not (Test-Path $pinnedPy)) {
            Write-Host "  interp   : $pinnedPy" -ForegroundColor Red
            Write-Host "             ^ DOES NOT EXIST. Commits now depend on ``pre-commit`` being on PATH," -ForegroundColor Red
            Write-Host "               and on a bare PATH it is not. Fix: run ``pre-commit install`` from" -ForegroundColor Red
            Write-Host "               $primaryRoot" -ForegroundColor Red
        } elseif ($primaryVenvPys -notcontains $normPinned) {
            Write-Host "  interp   : $pinnedPy" -ForegroundColor Yellow
            Write-Host "             ^ NOT the primary checkout, so that worktree is removable. If it goes," -ForegroundColor Yellow
            Write-Host "               every commit in all $(@(& git -C $RepoRoot worktree list).Count) worktrees fails at once (it fails closed)." -ForegroundColor Yellow
            Write-Host "               Re-anchor: run ``pre-commit install`` from $primaryRoot" -ForegroundColor Yellow
        } else {
            Write-Host "  interp   : $pinnedPy (primary checkout -- not removable)"
        }
    }
    # A worktree whose ruff drifts off constraints.lock lints with a DIFFERENT linter than CI, so the
    # `ruff check .` / `ruff format --check .` pass CONTRIBUTING.md asks for before a push answers a
    # question CI will answer differently. Compare rather than assume.
    #
    # NARROWED 2026-08-18. This used to add "and its `ruff check --fix` hook rewrites files
    # accordingly", which held while the ruff hooks were `language: system` and ran whatever ruff was
    # on PATH. They now come from the pre-commit-managed astral-sh/ruff-pre-commit repo at a pinned
    # rev, so the commit-time hook runs its OWN ruff and a divergent .venv can no longer edit source
    # on commit. What survives is the read-only half -- a local verdict CI does not share -- plus a
    # hand-run `ruff check --fix`, which still rewrites files. That is why this check stays.
    $wantRuff = (Select-String -Path (Join-Path $RepoRoot "constraints.lock") -Pattern '^ruff==(\S+)' -EA SilentlyContinue)
    if ($wantRuff) {
        $want = $wantRuff.Matches[0].Groups[1].Value
        $ruffExe = Join-Path $RepoRoot ".venv\Scripts\ruff.exe"
        if (-not (Test-Path $ruffExe)) { $ruffExe = Join-Path $RepoRoot ".venv/bin/ruff" }
        if (Test-Path $ruffExe) {
            $have = ((& $ruffExe --version) -split '\s+')[1]
            if ($have -eq $want) {
                Write-Host "ruff       : $have (matches constraints.lock)"
            } else {
                Write-Host "ruff       : $have but constraints.lock pins $want -- THIS WORKTREE LINTS DIFFERENTLY THAN CI" -ForegroundColor Red
                Write-Host "             Fix: .venv\Scripts\python.exe -m pip install `"ruff==$want`"" -ForegroundColor Red
            }
        } else {
            Write-Host "ruff       : not installed in this worktree's .venv (constraints.lock pins $want)" -ForegroundColor Yellow
        }
    }
    Write-Host "worktrees  : $(@(& git -C $RepoRoot worktree list).Count) share these hooks"
    return
}

if ($Uninstall) {
    $removed = $false
    if ((Test-Path $preCommit) -and ((Get-Content $preCommit -Raw) -match [regex]::Escape($marker))) {
        Remove-Item -LiteralPath $preCommit -Force
        Write-Host "Ledger pre-commit hook REMOVED." -ForegroundColor Yellow
        $removed = $true
    }
    if ((Test-Path $commitMsg) -and ((Get-Content $commitMsg -Raw) -match [regex]::Escape($claimMarker))) {
        Remove-Item -LiteralPath $commitMsg -Force
        Write-Host "Claim commit-msg hook REMOVED." -ForegroundColor Yellow
        $removed = $true
    }
    if ((Test-Path $prePush) -and ((Get-Content $prePush -Raw) -match [regex]::Escape($pushMarker))) {
        Remove-Item -LiteralPath $prePush -Force
        Write-Host "Push guard pre-push hook REMOVED." -ForegroundColor Yellow
        $removed = $true
    }
    if ((Test-Path $postCommit) -and ((Get-Content $postCommit -Raw) -match [regex]::Escape($durabilityMarker))) {
        Remove-Item -LiteralPath $postCommit -Force
        Write-Host "Durability post-commit hook REMOVED. New commits are single-copy again until pushed." -ForegroundColor Yellow
        $removed = $true
    }
    if (-not $removed) { Write-Host "Nothing to remove (no MessageFoundry hooks installed)." }
    return
}

if ((Test-Path $commitMsg) -and ((Get-Content $commitMsg -Raw) -notmatch [regex]::Escape($claimMarker))) {
    throw "A commit-msg hook that is not ours already exists at $commitMsg. Refusing to overwrite it -- merge them by hand."
}
if ((Test-Path $prePush) -and ((Get-Content $prePush -Raw) -notmatch [regex]::Escape($pushMarker))) {
    throw "A pre-push hook that is not ours already exists at $prePush. Refusing to overwrite it -- merge them by hand."
}
if ((Test-Path $postCommit) -and ((Get-Content $postCommit -Raw) -notmatch [regex]::Escape($durabilityMarker))) {
    throw "A post-commit hook that is not ours already exists at $postCommit. Refusing to overwrite it -- merge them by hand."
}

New-Item -ItemType Directory -Force -Path $hooksDir | Out-Null

# --- MIGRATION: retire our OWN old pre-commit hook -------------------------------------------------
# The ledger gate used to be installed here as a standalone .git/hooks/pre-commit. It now runs as a
# `local` hook inside .pre-commit-config.yaml instead. Leaving the old copy in place is NOT harmless:
# `pre-commit install` would find a foreign hook, move it to pre-commit.legacy and call it from its own
# shim -- which fails on Windows (see the note below) and blocks EVERY commit. Remove ours; never touch
# a hook that is not ours.
if ((Test-Path $preCommit) -and ((Get-Content $preCommit -Raw -EA SilentlyContinue) -match [regex]::Escape($marker))) {
    Remove-Item -LiteralPath $preCommit -Force
    $legacy = "$preCommit.legacy"
    if ((Test-Path $legacy) -and ((Get-Content $legacy -Raw -EA SilentlyContinue) -match [regex]::Escape($marker))) {
        Remove-Item -LiteralPath $legacy -Force
    }
    Write-Host "Migrated: the standalone ledger pre-commit hook was REMOVED." -ForegroundColor Yellow
    Write-Host "          The ledger gate now runs via .pre-commit-config.yaml (id: ledger-gate)." -ForegroundColor Yellow
}
Remove-Item -LiteralPath (Join-Path $hooksDir "ledger_check.py") -Force -EA SilentlyContinue

# --- claim gate (BACKLOG #309) -------------------------------------------------------------------
# A commit-msg hook, because only commit-msg is handed the message file (as $1). The claim gate keys off
# the SUBJECT declaring `BACKLOG #N`, so on pre-commit it would have nothing to read.
Copy-Item (Join-Path $RepoRoot "scripts\hooks\claim_check.py") (Join-Path $hooksDir "claim_check.py") -Force

$claimHook = @'
#!/bin/sh
# MessageFoundry claim gate -- INSTALLED COPY. Source: scripts/hooks/claim_check.py
# commit-msg (NOT pre-commit): only this hook receives the message file, and the gate reads the subject.
# Re-install after changing the source:  pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1
HOOK_DIR=$(dirname "$0")
PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "MessageFoundry: neither python nor python3 resolves, so the claim gate cannot run." >&2
  echo "REFUSING this commit rather than allowing it unchecked -- a gate that cannot run" >&2
  echo "must not report success. Fix PATH so python resolves, then commit again." >&2
  echo "To commit without the gate, deliberately:  git commit --no-verify" >&2
  exit 1
fi
exec "$PY" "$HOOK_DIR/claim_check.py" "$1"
'@ -replace "`r`n", "`n"

[System.IO.File]::WriteAllText($commitMsg, $claimHook, (New-Object System.Text.UTF8Encoding $false))

# --- push guard ------------------------------------------------------------------------------------
# Since the MEFORORG cutover this repo IS the published artifact -- a push to main is publication, with
# no publish step left to catch anything. Server-side protection requires a PR and the checks listed
# in .github/required-contexts.txt -- never a count written down here, which has gone stale before --
# but enforce_admins is false, so the owner bypasses all of it and VS Code's Sync button does not
# distinguish main from a feature branch. This restores the class of protection the old mirror clone's
# Gate-Provenance pre-push hook provided before it was quarantined at cutover.
Copy-Item (Join-Path $RepoRoot "scripts\hooks\push_guard.py") (Join-Path $hooksDir "push_guard.py") -Force

$pushHook = @'
#!/bin/sh
# MessageFoundry push guard -- INSTALLED COPY. Source: scripts/hooks/push_guard.py
# Refuses a DIRECT push (or delete) of a protected branch. git feeds the refs on stdin.
# Re-install after changing the source:  pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1
HOOK_DIR=$(dirname "$0")
PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "MessageFoundry: neither python nor python3 resolves, so the push guard cannot run." >&2
  echo "REFUSING this push rather than allowing it unchecked -- a guard that cannot run" >&2
  echo "must not report success. This repo IS the published artifact: a push to main is" >&2
  echo "publication, and nothing downstream would catch it." >&2
  echo "Fix PATH so python resolves, then push again." >&2
  echo "To push without the guard, deliberately:  git push --no-verify" >&2
  exit 1
fi
exec "$PY" "$HOOK_DIR/push_guard.py" "$@"
'@ -replace "`r`n", "`n"

[System.IO.File]::WriteAllText($prePush, $pushHook, (New-Object System.Text.UTF8Encoding $false))

# --- durability hook -------------------------------------------------------------------------------
# The gates above stop the WRONG thing happening. This one stops the RIGHT thing being lost.
#
# Measured on this machine 2026-08-16: 802 commits across 239 branches existed on no remote at all,
# the oldest 17 days old, and nothing had reported it -- because a session may commit on its own
# judgment but may not push, `origin` being the published artifact. Work therefore accumulates in one
# checkout, and a session that stops at a usage cap takes the only copy with it. A worktree deleted in
# that state loses the commits AND the coordination record naming what they were for.
#
# A tag under rescue/auto/ on a PRIVATE remote breaks that coupling: durability without review and
# without disclosure, so it needs no approval -- which matters because the sessions that most need it
# are the ones that cannot stop and ask.
#
# Installed VERBATIM, not via a shim. Every other hook here execs a .py and needs a shim to find an
# interpreter; this one is already /bin/sh and has no payload, so a shim would add a failure mode
# (see the INSTALL_PYTHON note below for what that costs) and buy nothing.
#
# FAIL-SAFE BY ABSENCE: with mefor.durabilityRemote unset the hook exits 0 without pushing, so
# installing it here can never make a fresh clone, a CI checkout or a fork push anywhere. Arming is a
# separate, deliberate, per-repository act. -Status reports installed and armed as two different
# things, because only one of them protects anything.
Copy-Item (Join-Path $RepoRoot "scripts\hooks\durability_push.sh") $postCommit -Force

# --- pre-commit's generated shim: DIAGNOSE, never write -------------------------------------------
# This script deliberately does NOT touch .git/hooks/pre-commit. pre-commit owns that file alone, and
# tests/test_ledger_check.py::test_the_installer_no_longer_writes_a_pre_commit_hook enforces it,
# because two tools contending for it once blocked EVERY commit in the repo on Windows (see the
# header). A patch here would also be futile: `pre-commit install` rewrites the file from its template,
# so anything spliced in is erased the next time anyone runs it.
#
# Two real problems with the generated shim in a multi-worktree checkout. The first is LIVE and is
# reported by -Status; the second is FIXED, and is kept here because the fix is undone by writing one
# new hook, and because this is the text somebody reads while a hook is red at them:
#
#   1. INSTALL_PYTHON is hardcoded to whichever checkout last ran `pre-commit install` -- here it was
#      MessageFoundry-ledger's .venv, a DISPOSABLE worktree. Delete that worktree and the fallback
#      `command -v pre-commit` finds nothing on a bare PATH, so every commit in every worktree exits 1.
#      Fails closed, but blocks every session at once.
#      REMEDY: run `pre-commit install` from the PRIMARY checkout, whose .venv is not disposable. That
#      is pre-commit's own mechanism for repointing it -- no third-party edit to its file.
#
#   2. RETIRED 2026-08-18 -- recorded so it is not rewritten under a new hook id. The two ruff hooks
#      were `language: system`, on the reasoning that sharing one installed ruff with CI made a
#      version disagreement impossible. The reasoning was sound and the mechanism was not:
#      `language: system` resolves `entry:` as a bare program name on PATH, `ruff` is on no ambient
#      PATH here, and this shim execs a venv's python.exe DIRECTLY -- which does not put that venv's
#      Scripts on PATH. Measured from a bare PATH: `ruff` not found, in the primary checkout too.
#      The remedy this file used to print was "commit from a shell with the worktree's .venv
#      activated", which is not available to an agent session at all -- shell state does not survive
#      between tool calls -- so the apparent remedy was `--no-verify`, and that drops the ledger gate
#      and the leak gate along with ruff. The ruff hooks now come from the pre-commit-managed
#      astral-sh/ruff-pre-commit repo at a pinned rev and need no venv; the hooks still on
#      `language: system` name only `python`, which the Windows Python Manager shim puts on the
#      ambient PATH, and tests/test_lint_scope_parity.py reds on a `language: system` entry naming
#      anything else. Note bandit was never in this set -- it is a hosted PyCQA/bandit hook.
#
# VERSION DRIFT IS A DIFFERENT PROBLEM FROM (2) AND IS STILL LIVE, which is what -Status checks: a
# worktree whose ruff disagrees with constraints.lock lints with a DIFFERENT linter than CI. Measured
# 2026-07-29: one worktree carried ruff 0.16.0 against pyproject's `<0.16` cap (installed standalone,
# so nothing capped it), producing ~829 findings CI does not have, and stripping `# noqa` directives
# the pinned 0.15.22 still wants -- through `ruff check --fix`, which at that time was ALSO the commit
# hook, so a divergent venv rewrote source on commit. That commit-time half died with the move above.
# The read-only half did not: CONTRIBUTING.md tells a developer to run ruff by hand before pushing,
# and that run is the venv's.

# Git for Windows does not need the exec bit, but a WSL/Linux checkout of the same repo would.
if ($IsLinux -or $IsMacOS) { & chmod +x $commitMsg; & chmod +x $prePush; & chmod +x $postCommit }

Write-Host ""
Write-Host "MessageFoundry hooks INSTALLED." -ForegroundColor Green
Write-Host "  commit-msg : $commitMsg"
Write-Host "               $(Join-Path $hooksDir 'claim_check.py')   (claim gate, BACKLOG #309)"
Write-Host "  pre-push   : $prePush"
Write-Host "               $(Join-Path $hooksDir 'push_guard.py')    (refuses a direct push to main)"
Write-Host "  post-commit: $postCommit  (durability hook)"
Write-Host "  governs    : all $(@(& git -C $RepoRoot worktree list).Count) worktree(s) of this repo, immediately"
Write-Host ""

# ARMING IS SEPARATE FROM INSTALLING, and saying so here is the point: an operator who reads
# "INSTALLED" and stops has protected nothing. The hook is deliberately inert until a remote is
# nominated, so the install path must state the second step rather than imply one was enough.
$armedRemote = (& git -C $RepoRoot config --get mefor.durabilityRemote)
if ($armedRemote) {
    Write-Host "Durability : ARMED -> $armedRemote" -ForegroundColor Green
    # The <repo> segment is load-bearing and MUST stay in this message. It was added because
    # refs/tags/rescue/auto/main collided between the engine and the vault, which push to one
    # remote; the bare shape this line used to print still resolves, to that contested fossil. So
    # an operator who built a query from the old wording got a CONFIDENT HIT at a commit belonging
    # to neither repository and concluded their work was backed up. Keep this in step with
    # scripts/hooks/durability_push.sh:122 and :126 -- the two lines that assign $TAG.
    Write-Host "             Every commit now also lands as refs/tags/rescue/auto/<repo>/<branch>"
    Write-Host "             there, or refs/tags/rescue/auto/<repo>/detached/<sha> off a branch."
} else {
    Write-Host "!! DURABILITY HOOK IS INSTALLED BUT NOT ARMED." -ForegroundColor Yellow
    Write-Host "   mefor.durabilityRemote is unset, so it exits 0 without pushing and nothing is" -ForegroundColor Yellow
    Write-Host "   being made durable. Measured 2026-08-16 before this existed: 802 commits on 239" -ForegroundColor Yellow
    Write-Host "   branches existed on no remote at all. Arm it with:" -ForegroundColor Yellow
    Write-Host "       git config mefor.durabilityRemote <private-remote>" -ForegroundColor Yellow
    Write-Host "   CONFIRM THE REMOTE IS PRIVATE FIRST -- git cannot see visibility and neither can" -ForegroundColor Yellow
    Write-Host "   this script. A public remote turns durability into unreviewed publication:" -ForegroundColor Yellow
    Write-Host "       gh repo view <owner>/<repo> --json visibility" -ForegroundColor Yellow
    Write-Host ""
}
Write-Host "Audit what is unbacked at any time (per REF, not per HEAD -- the distinction matters):"
Write-Host "    pwsh -NoProfile -File scripts\coord\unbacked_check.ps1"
Write-Host ""

# The ledger gate now rides on pre-commit. If pre-commit is not installed, say so LOUDLY -- a gate that
# is simply absent looks identical to one that passed.
$pcInstalled = (Test-Path $preCommit) -and ((Get-Content $preCommit -Raw -EA SilentlyContinue) -match 'File generated by pre-commit')
if ($pcInstalled) {
    Write-Host "Ledger gate: ARMED via .pre-commit-config.yaml (id: ledger-gate)." -ForegroundColor Green
} else {
    Write-Host "!! LEDGER GATE IS NOT ARMED." -ForegroundColor Red
    Write-Host "   It runs as a pre-commit hook now, and pre-commit is not installed in this repo." -ForegroundColor Red
    Write-Host "   Nothing is stopping two sessions colliding on an ADR/BACKLOG number. Fix with:" -ForegroundColor Red
    Write-Host "       pip install pre-commit" -ForegroundColor Red
    Write-Host "       pre-commit install" -ForegroundColor Red
    Write-Host ""
}
Write-Host "Ledger gate: blocks a commit that reuses an ADR/BACKLOG number, or adds an ADR with no index row."
Write-Host "Claim gate : blocks a CODE commit whose subject says 'BACKLOG #N' unless THIS worktree claims N,"
Write-Host "             so two sessions cannot build the same item in parallel. Docs-only commits pass."
Write-Host ""
Write-Host "Allocate numbers with:  pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title `"<title>`""
Write-Host "Claim work with:        pwsh -NoProfile -File scripts\coord\claim.ps1 -Take <key> -Note `"<what>`""
Write-Host "See who holds what:     pwsh -NoProfile -File scripts\coord\claim.ps1 -List"
Write-Host "Remove with:            pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Uninstall"
