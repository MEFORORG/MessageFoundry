# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Do the coordination hooks that are WIRED actually resolve to a script that exists?

The coordination hooks wired in ``settings.json`` are not installed copies. Each is an inline command
in ``~/.claude/settings.json`` that locates its script in a working tree at every invocation, primary
checkout first::

    $bases = @((Split-Path <git-common-dir> -Parent), <toplevel>)
    foreach ($b in $bases) { $s = Join-Path $b '<relative script>'; if (Test-Path $s) { & $s; break } }

That has a failure mode nothing was watching: **if neither base yields the file, ``Test-Path`` fails, the
loop ends, nothing runs, and the tool call proceeds with no hook and no signal.** "The hook is
uninstalled" and "the hook ran and permitted this" are indistinguishable from outside.

It is not hypothetical. A ``UserPromptSubmit`` entry belonging to a *different* repo sat in this same
settings file probing a script that exists only in that repo -- wired, firing, resolving nothing, exiting
0 -- for weeks, and nothing reported it.

The risk composes badly for ``collision_gate.ps1`` specifically, which (a) fails OPEN on any error,
(b) now denies less by design after the dirty-vs-committed split, and (c) silently no-ops when
unresolvable. Each is individually defensible; together the realistic bad day is *the gate was never
running and nobody noticed*. This module is the assertion that closes (c).

``test_gate_installed_parity.py`` does the equivalent job for ``worktree_gate.ps1``, which DOES install a
copy and so can drift in the opposite direction. These are different mechanisms with opposite postures --
the worktree gate fails closed, these fail open -- so they need separate checks.

SECOND MECHANISM, SAME FILE: the shared ``.git/hooks`` payloads. ``scripts/coord/install-git-hooks.ps1``
wires no shim into settings.json -- it ``Copy-Item``s ``claim_check.py`` and ``push_guard.py`` into the
COMMON git dir, where a single copy governs every worktree of this repo at once. Those ARE installed
copies, so they drift the worktree gate's way: an edit to the source has no effect until someone
re-installs, and a check deleted from the source keeps firing until then. What kept it invisible is
narrower than "nobody looked" -- the installer's ``-Status`` did look, at a marker in the *generated
shim*, a here-string that changes about once in months. It reported INSTALLED over a payload that was in
fact stale (measured 2026-08-04; the digests are in that script's own comment, stated once there).
The tests in the second half of this module are modelled on
``test_gate_installed_parity.py::test_the_installed_gate_matches_the_committed_source`` and use the same
comparison basis; ``-Status`` now reports the same parity from the PowerShell side.

LOCAL-MACHINE TESTS. CI has no user settings, so these skip there, and that is honest: an unresolvable
shim is a developer-box condition, not a repository one. **What CI therefore does not guard is exactly
this property.** Following ``test_gate_installed_parity.py`` verbatim, every test PRINTS what it scanned
BEFORE it can skip -- the repo's pytest config carries no ``-rs``, so a skip would otherwise render as a
bare dot with its reason invisible.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from _bash_resolver import bash_sees, require_bash

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "coord" / "install-coordination.ps1"

# Parsed from the installer rather than hardcoded: a test carrying its own copy of a marker cannot
# notice the code drifting away from it, which is the failure it exists to catch.
_SRC = INSTALLER.read_text(encoding="utf-8")
MARKERS = re.findall(r"\$(?:ANNOUNCE_)?MARKER\s*=\s*\"([^\"]+)\"", _SRC)


def _settings_files() -> list[Path]:
    """Every user-scope settings file that could carry a wired hook."""
    return sorted(
        p for d in Path.home().glob(".claude*") if d.is_dir() for p in d.glob("settings*.json")
    )


def _shim_bases() -> list[Path]:
    """The SAME two bases the shim resolves, computed the same way, in the same order."""
    bases: list[Path] = []
    common = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if common:
        bases.append(Path(common).parent)
    top = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--path-format=absolute", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if top:
        bases.append(Path(top))
    return bases


def _wired_entries() -> list[tuple[Path, str, str]]:
    """(settings file, event, relative script path) for every entry carrying one of our markers."""
    found: list[tuple[Path, str, str]] = []
    for f in _settings_files():
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        for event, groups in (data.get("hooks") or {}).items():
            for g in groups or []:
                for h in g.get("hooks") or []:
                    cmd = str(h.get("command") or "")
                    if not any(m in cmd for m in MARKERS):
                        continue
                    for rel in re.findall(r"'([^']*scripts/[^']*\.ps1)'", cmd):
                        found.append((f, event, rel))
    return found


def test_every_wired_coordination_hook_resolves_to_a_script_that_exists() -> None:
    """The anti-silent-off assertion: a wired hook whose script cannot be found does nothing, quietly."""
    bases = _shim_bases()
    print(f"markers parsed from installer: {MARKERS}")
    print(f"settings files scanned: {[str(p) for p in _settings_files()] or 'NONE'}")
    print(f"shim bases (primary first): {[str(b) for b in bases]}")

    entries = _wired_entries()
    for f, event, rel in entries:
        print(f"  wired: {event} -> {rel}   (from {f.name})")
    if not entries:
        pytest.skip(
            "no coordination hooks wired in any user settings file on this box (printed above)"
        )

    unresolved = []
    for _f, event, rel in entries:
        hits = [b / rel for b in bases if (b / rel).is_file()]
        print(f"  resolve {event} {rel}: {[str(h) for h in hits] or 'NONE OF THE BASES'}")
        if not hits:
            unresolved.append((event, rel))
    assert not unresolved, (
        f"wired but unresolvable -- these hooks run, find nothing and exit 0 silently: {unresolved}"
    )


def test_the_resolution_check_can_detect_a_missing_script() -> None:
    """NEGATIVE CONTROL for the test above, which would otherwise be vacuously green.

    The assertion is "every wired script resolves against one of the shim's bases". If the resolution
    predicate were broken open -- an empty base list, a truthy default, a swallowed exception -- it would
    pass no matter what was wired, and this whole module would be decoration. The real hooks cannot be
    unwired to prove otherwise (the primary checkout is shared with live sessions and must not be
    disturbed), so the predicate is exercised directly against a path known not to exist.
    """
    bases = _shim_bases()
    assert bases, "no shim bases resolved -- the check would be vacuous"
    bogus = "scripts/hooks/definitely-not-a-real-hook.ps1"
    hits = [b / bogus for b in bases if (b / bogus).is_file()]
    print(f"negative control {bogus} against {len(bases)} base(s): {hits or 'no hits (correct)'}")
    assert not hits, "the resolution predicate reports a hit for a script that does not exist"


def test_report_any_foreign_hook_entry_that_resolves_nothing_here() -> None:
    """INFORMATIONAL, never a failure. Other repos install user-scope hooks into this same file.

    A foreign entry that resolves nothing in THIS checkout is not ours to delete -- but it is worth
    naming, because it is indistinguishable from a working hook and one such entry went unnoticed for
    weeks. Report it; leave it alone.
    """
    bases = _shim_bases()
    scanned = _settings_files()
    print(f"settings files scanned: {[str(p) for p in scanned] or 'NONE'}")
    if not scanned:
        pytest.skip("no user settings files on this box (printed above)")

    for f in scanned:
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            print(f"  {f}: UNPARSEABLE")
            continue
        for event, groups in (data.get("hooks") or {}).items():
            for g in groups or []:
                for h in g.get("hooks") or []:
                    cmd = str(h.get("command") or "")
                    if any(m in cmd for m in MARKERS):
                        continue  # ours; the test above asserts on it
                    for rel in re.findall(r"'([^']*scripts/[^']*\.ps1)'", cmd):
                        resolves = any((b / rel).is_file() for b in bases)
                        marker = re.match(r"#\s*([\w-]+)", cmd)
                        who = marker.group(1) if marker else "unmarked"
                        print(
                            f"  FOREIGN {event} [{who}] -> {rel}: "
                            f"{'resolves here' if resolves else 'RESOLVES NOTHING HERE'}"
                        )


# --------------------------------------------------------------------------------------------------
# The shared .git/hooks payloads -- the second mechanism described in the module docstring. Everything
# above watches hooks that resolve their script at run time and can fail open; everything below watches
# hooks that run from a COPY and can therefore be silently out of date.

HOOK_INSTALLER = ROOT / "scripts" / "coord" / "install-git-hooks.ps1"
HOOK_SOURCE_DIR = ROOT / "scripts" / "hooks"

# Parsed out of the installer for the same reason MARKERS is: a test carrying its own list of payloads
# cannot notice one being ADDED to the installer, and an unaudited payload is exactly the state this
# section exists to end.
#
# Line-anchored (``(?m)^\s*``) so a COMMENTED-OUT or illustrative `# $payloads = @(...)` cannot become
# the parametrize source -- ``re.search`` takes the first hit anywhere in the file, and a `#` prefix
# would otherwise satisfy it. That is the same defect this session fixed in
# test_gate_installed_parity.py's handled_tools, where a comment written in rule syntax was being
# credited as the rule; a raw text scan does not know what is code.
_PAYLOAD_DECL = re.search(
    r"(?m)^\s*\$payloads\s*=\s*@\(([^)]*)\)", HOOK_INSTALLER.read_text(encoding="utf-8")
)
PAYLOADS: list[str] = re.findall(r'"([^"]+)"', _PAYLOAD_DECL.group(1)) if _PAYLOAD_DECL else []


def content_hash(data: bytes) -> str:
    """SHA-256 of a payload's CONTENT: raw bytes with CRLF folded to LF.

    Deliberately the SAME basis as ``test_gate_installed_parity.content_hash`` and the byte loop in
    ``install-gate.ps1``'s ``Get-GateHash`` / ``install-git-hooks.ps1``'s ``Get-HookPayloadHash``. The
    reasoning and the measurements are stated once, in that first docstring; the consequence for these
    files is that the installer lays its copies down with ``Copy-Item``, which translates nothing, so an
    installed payload carries whatever line endings the checkout that installed it had. A byte-exact
    digest would answer "are these the same bytes", which is not the question. Folds that disagree would
    be that same defect one level up: if this one ever diverges from those two, the divergence IS the
    bug.

    Spelled out rather than imported from the gate module: there is no ``tests/__init__.py``, so
    ``import test_gate_installed_parity`` would bind this file's correctness to pytest's collection
    import mode. ``test_the_payload_parity_check_still_detects_a_content_difference`` is what keeps the
    copy honest.
    """
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _git(*args: str) -> str:
    """stdout of a git command run at ROOT, or "" if git failed or is unusable.

    Never raises: "git could not tell us where the hooks are" is a skip reason these tests must be able
    to PRINT, not an error that kills the module before it says what it scanned.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def installed_hooks_dir() -> Path | None:
    """Where git looks for hooks, resolved exactly as ``install-git-hooks.ps1`` resolves it.

    ``core.hooksPath`` wins when set (it is set on this box), otherwise ``<git-common-dir>/hooks``.
    Deriving it any other way would compare a directory git never consults and report parity for a copy
    that is not the one running -- and the obvious shortcut is worse than wrong, it is empty: in a linked
    worktree ``ROOT/.git`` is a FILE pointing at the common dir, so ``ROOT/.git/hooks`` never exists and
    every payload would read as "not installed".
    """
    configured = _git("config", "--get", "core.hooksPath")
    if configured:
        p = Path(configured)
        return p if p.is_absolute() else ROOT / configured
    common = _git("rev-parse", "--path-format=absolute", "--git-common-dir")
    return Path(common) / "hooks" if common else None


def payload_source_is_committed(name: str) -> bool:
    """Same posture as the gate parity test: assert only against a COMMITTED source.

    Mid-edit the installed copy is *supposed* to differ, and a check that goes red on every keystroke is
    one that gets deselected and then deleted.
    """
    rel = (HOOK_SOURCE_DIR / name).relative_to(ROOT).as_posix()
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", rel],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and not out.stdout.strip()


def test_the_payload_list_was_parsed_from_the_installer() -> None:
    """Guard the parametrize source. An empty list makes the parity test below collect to nothing and
    report as a skip -- no hook compared, no red, which is the ambiguity this whole module removes."""
    print(f"payloads parsed from {HOOK_INSTALLER.name}: {PAYLOADS or 'NONE'}")
    assert PAYLOADS, (
        f"no $payloads list parsed from {HOOK_INSTALLER} -- the parity test then parametrizes over an "
        f"empty set and pytest reports it as a SKIP, which reads like a pass"
    )
    missing = [n for n in PAYLOADS if not (HOOK_SOURCE_DIR / n).is_file()]
    assert not missing, (
        f"the installer lists payloads with no source in this checkout: {missing} -- installing would "
        f"fail, and until then those hooks run from whatever copy is already in place"
    )


@pytest.mark.parametrize("name", PAYLOADS)
def test_the_installed_coord_hook_matches_the_committed_source(name: str) -> None:
    """Is the .py the shared git hook EXECS the one in this checkout?

    Nothing asked this. ``install-git-hooks.ps1 -Status`` checked a marker in the generated shim, which
    is present whether the payload beside it is current or months old, so the answer it gave was to a
    different question. The hooks sit in the COMMON git dir, so one stale copy is stale for every
    worktree on the box at once, while the source-side tests stay green.
    """
    source = HOOK_SOURCE_DIR / name
    hooks_dir = installed_hooks_dir()
    installed = hooks_dir / name if hooks_dir else None
    # Announce the target BEFORE any skip, exactly as test_gate_installed_parity.py does: the repo's
    # pytest config carries no -rs, so a skip renders as a bare dot with its reason invisible, and
    # "nothing was compared" then looks identical to "the comparison passed".
    print(f"scanning: {installed or '(git named no hooks dir)'} vs {source}")
    if installed is None:
        pytest.skip("SKIP (nothing compared): git resolved no hooks directory from this checkout")
    if not installed.is_file():
        pytest.skip(
            f"SKIP (nothing compared): no {name} installed at {installed} -- these hooks are installed "
            f"per box by a human running the installer, and CI installs none"
        )
    if not payload_source_is_committed(name):
        pytest.skip(
            f"SKIP (nothing compared): scripts/hooks/{name} has uncommitted changes -- the installed "
            f"copy is SUPPOSED to differ mid-edit. Re-run after committing."
        )

    installed_bytes = installed.read_bytes()
    source_bytes = source.read_bytes()
    installed_hash = content_hash(installed_bytes)
    source_hash = content_hash(source_bytes)

    # Print both bases. The content hashes are what the assertion turns on; the raw byte digests and the
    # eol-only flag are diagnostics that keep "differs in content" and "differs in line endings"
    # distinguishable in the output, which is the distinction that was confused one level up.
    print(
        f"compared (content, CRLF folded): installed={installed_hash[:12]} source={source_hash[:12]}"
    )
    print(
        f"diagnostic raw bytes: installed={hashlib.sha256(installed_bytes).hexdigest()[:12]} "
        f"source={hashlib.sha256(source_bytes).hexdigest()[:12]} "
        f"line-endings-only difference={installed_bytes != source_bytes and installed_hash == source_hash}"
    )

    assert installed_hash == source_hash, (
        f"CONTENT DRIFT: the {name} that RUNS is not this checkout's.\n"
        f"  installed: {installed}  content={installed_hash[:12]}\n"
        f"  source   : {source}  content={source_hash[:12]}\n"
        f"Line endings are folded out of this comparison, so CRLF vs LF cannot account for it -- the two "
        f"differ in at least one byte of content. WHICH bytes, and whether the difference weakens the "
        f"hook or strengthens it, this test cannot say: diff them.\n"
        f"The hook runs from the shared .git/hooks, so the installed copy is what fires for every "
        f"worktree of this repo. Until it is replaced, edits to the source have no effect and the rest "
        f"of the suite still passes.\n"
        f"WORK OUT WHICH COPY IS OLDER FIRST. Re-installing from a checkout older than the installed "
        f"payload downgrades it for every worktree on this box:\n"
        f"    git log --oneline -5 -- scripts/hooks/{name}\n"
        f"Only once THIS checkout is confirmed the newer of the two, from a plain terminal:\n"
        f"    pwsh -NoProfile -File scripts\\coord\\install-git-hooks.ps1\n"
        f"That installer re-copies every payload it manages ({', '.join(PAYLOADS)}), not only this one; "
        f"its -Status reports them all."
    )


def test_the_payload_parity_check_still_detects_a_content_difference() -> None:
    """NEGATIVE CONTROL for the parity test above, and the price of folding line endings out of it.

    Folding is exactly the edit that can turn a false RED into a false GREEN -- a payload that is
    genuinely stale, reported in sync -- so prove the weakened predicate still detects what it exists to
    detect, and prove the tolerance is not vacuous while doing it.

    Exercised against the predicate on real source bytes, never by mutating the installed copy: that
    file lives in the common git dir and fires on every commit and push in every worktree on this box,
    so a test may not take it out from under a concurrent session. Same reasoning and same shape as
    ``test_the_resolution_check_can_detect_a_missing_script`` above.
    """
    body = (HOOK_SOURCE_DIR / "push_guard.py").read_bytes().replace(b"\r\n", b"\n")
    crlf = body.replace(b"\n", b"\r\n")

    # Guard the guard: identical encodings would make the tolerance assertion hold for a trivial reason
    # and prove nothing about folding.
    assert crlf != body, "the CRLF and LF encodings are identical -- this control would be vacuous"
    print(f"eol probes differ in bytes: LF={len(body)} CRLF={len(crlf)}")
    assert content_hash(crlf) == content_hash(body), (
        "re-encoding line endings changed the content hash -- the tolerance this section documents does "
        "not actually hold"
    )

    added = body + b"\ndef _mf_test_only_probe() -> None:\n    return None\n"
    assert content_hash(added) != content_hash(body), (
        "appending code did not change the content hash -- the parity check is decoration"
    )

    # The subtle end of the range: one character inside the constant that decides WHICH refs the guard
    # protects. A payload can stop protecting main without changing length, so a size check is not a
    # substitute for this.
    flipped = body.replace(b'"refs/heads/main"', b'"refs/heads/mail"', 1)
    assert flipped != body, (
        "probe edit matched nothing -- push_guard.py's PROTECTED set moved, fix this control"
    )
    assert content_hash(flipped) != content_hash(body), (
        "a one-character edit to the protected-ref list did not change the content hash"
    )
    print(
        "content differences still detected: code appended, and one character changed in PROTECTED"
    )


# --------------------------------------------------------------------------------------------------
# IS IT INSTALLED AT ALL? -- the gap every test above leaves open.
#
# The parity test asks "does the installed copy match source" and SKIPS when nothing is installed.
# That is the right posture for a parity question and the wrong one for the repo as a whole, because
# it makes the two states that matter most indistinguishable in the output: a box where the guard is
# installed and current, and a box where it was NEVER installed, both render as green. Measured
# 2026-08-05 by a four-lens audit of the push-guard chain: "no instrument anywhere asserts the push
# guard is INSTALLED; the one test that looks skips when it is absent". A guard nobody can prove is
# running is not a control, and prose that credits it with one is the false-premise defect CLAUDE.md
# section 11 names.
#
# So this section ASSERTS presence, and the discriminator is CI rather than the file's own absence:
#
#   * On CI there are genuinely no hooks -- the installer is run per box by a human, and no workflow
#     runs it. Failing there would be a false red on every job, so it skips, loudly, naming the marker
#     that made the call. That is the same honesty the module docstring already claims for the shim
#     tests: what CI does NOT guard is stated rather than implied by three green dots.
#   * OFF CI this is a working checkout, and an absent guard is exactly the condition worth failing
#     over. The remedy is one documented command and the failure text carries it.
#
# WHY AN ENV MARKER AND NOT "does the hooks dir look empty": the second infers intent from the very
# state under test, so it can only ever conclude that absence is normal -- which is the bug.
# --------------------------------------------------------------------------------------------------

# Shim filename -> the installer VARIABLE holding the marker it writes into that shim. Parsed rather
# than hardcoded for the reason MARKERS and PAYLOADS already are: a test carrying its own copy of a
# marker cannot notice the installer drifting away from it.
#
# `pre-commit` is deliberately NOT here. This installer never writes it -- the pre-commit framework
# does, and -Status looks for that tool's own "File generated by pre-commit" rather than for a marker
# of ours. Asserting our marker on it would fail on a perfectly healthy setup.
_SHIM_MARKER_VARS = {"pre-push": "pushMarker", "commit-msg": "claimMarker"}

_HOOK_SRC = HOOK_INSTALLER.read_text(encoding="utf-8")
SHIM_MARKERS: dict[str, str] = {}
for _shim, _var in _SHIM_MARKER_VARS.items():
    # Line-anchored so a marker quoted inside a comment cannot become the expected value -- the same
    # code-vs-prose trap _PAYLOAD_DECL is anchored against.
    _m = re.search(rf'(?m)^\s*\${_var}\s*=\s*"([^"]+)"', _HOOK_SRC)
    if _m:
        SHIM_MARKERS[_shim] = _m.group(1)


def ci_marker() -> str | None:
    """The environment variable proving this is CI, or ``None`` on a working checkout.

    GitHub Actions sets both unconditionally, so either is sufficient and checking both means a
    self-hosted or container leg that sets only the generic one still reads correctly. Returns the
    NAME=VALUE rather than a bool so the skip reason can say what made the call -- a bare "skipped on
    CI" is unfalsifiable from the log, and this suite's whole complaint is about unfalsifiable greens.
    """
    for var in ("GITHUB_ACTIONS", "CI"):
        val = os.environ.get(var)
        if val:
            return f"{var}={val}"
    return None


def test_the_shim_markers_were_parsed_from_the_installer() -> None:
    """Guard the expectation source. An empty SHIM_MARKERS makes the assertion below vacuous -- it
    would iterate nothing and pass on a box with no hooks at all, which is the exact defect it exists
    to close."""
    print(f"shim markers parsed from {HOOK_INSTALLER.name}: {SHIM_MARKERS or 'NONE'}")
    missing = sorted(set(_SHIM_MARKER_VARS) - set(SHIM_MARKERS))
    assert not missing, (
        f"no marker parsed from {HOOK_INSTALLER} for shim(s) {missing} -- the variables "
        f"{[_SHIM_MARKER_VARS[m] for m in missing]} were renamed or moved. Until this is fixed the "
        f"installed-hook assertion below silently stops checking those shims."
    )


def test_the_coordination_hooks_are_actually_installed() -> None:
    """Off CI, an absent shim or payload is a FAILURE rather than a skip.

    This is the assertion that makes every other check in this module mean something: parity against
    a copy that does not exist is not a weaker signal, it is no signal.
    """
    hooks_dir = installed_hooks_dir()
    marker = ci_marker()
    # Announce everything BEFORE any skip, as every test in this module does -- the repo's pytest
    # config carries no -rs, so a skip renders as a bare dot with its reason invisible.
    print(f"hooks dir: {hooks_dir or '(git named no hooks dir)'}")
    print(f"CI marker: {marker or 'none -- treating this as a working checkout'}")
    print(f"expecting shims {sorted(SHIM_MARKERS)} and payloads {PAYLOADS}")

    absent: list[str] = []
    if hooks_dir is None:
        absent.append("git resolved no hooks directory at all")
    else:
        for shim, expected in sorted(SHIM_MARKERS.items()):
            path = hooks_dir / shim
            if not path.is_file():
                absent.append(f"{shim}: NOT INSTALLED at {path}")
            elif expected not in path.read_text(encoding="utf-8", errors="replace"):
                # Present but foreign. The installer refuses to clobber a hook it does not recognise,
                # so this is a real state, and it is worse than absence: something IS wired here, and
                # it is not ours.
                absent.append(f"{shim}: present at {path} but carries no {expected!r} marker")
            else:
                print(f"  {shim}: INSTALLED ({expected})")
        for name in PAYLOADS:
            path = hooks_dir / name
            if not path.is_file():
                absent.append(f"{name}: NOT INSTALLED at {path}")
            else:
                print(f"  {name}: INSTALLED")

    if marker:
        pytest.skip(
            f"SKIP (nothing asserted): {marker} -- these hooks are installed per box by a human and "
            f"no workflow runs the installer, so absence on CI is expected, not drift. "
            f"State on this runner: {absent or 'all present'}"
        )

    assert not absent, (
        "COORDINATION HOOKS NOT INSTALLED in this checkout's hooks directory:\n  "
        + "\n  ".join(absent)
        + f"\nThe hooks live in the COMMON git dir ({hooks_dir}), so one install covers every "
        f"worktree of this repo at once -- and one absence leaves every worktree unguarded at once.\n"
        f"What is unguarded while this fails: pre-push refuses a direct push or delete of a protected "
        f"branch, and commit-msg is the claim gate. Neither inspects file CONTENT, so neither was ever "
        f"a leak gate -- do not read this passing as proof that anything scans what you push.\n"
        f"Fix, from a plain terminal:\n"
        f"    pwsh -NoProfile -File scripts\\coord\\install-git-hooks.ps1\n"
        f"Then confirm:\n"
        f"    pwsh -NoProfile -File scripts\\coord\\install-git-hooks.ps1 -Status\n"
        f"If this is a CI-like environment that sets neither GITHUB_ACTIONS nor CI, set one of them "
        f"rather than deleting this assertion."
    )


def test_the_installed_assertion_can_detect_an_absent_hook() -> None:
    """NEGATIVE CONTROL for the assertion above -- the whole reason it is worth having.

    An assertion about presence is trivially green on a box where everything is present, and would
    stay green if the predicate were broken open (a swallowed exception, a directory that always
    reports files, a membership test against the wrong path). That is precisely the failure mode this
    section was written to end, so it may not be taken on trust.

    Exercised against the predicate on a name known not to exist, never by removing a real hook: these
    files sit in the common git dir and fire on every commit and push in every worktree on this box,
    so a test may not take one out from under a concurrent session. Same reasoning and same shape as
    ``test_the_resolution_check_can_detect_a_missing_script``.
    """
    hooks_dir = installed_hooks_dir()
    print(f"probing: {hooks_dir}")
    assert hooks_dir is not None, "git resolved no hooks dir -- this control would be vacuous"

    bogus = hooks_dir / "definitely-not-a-real-hook"
    assert not bogus.is_file(), f"the probe name exists ({bogus}) -- pick another"
    print(f"absent-file probe {bogus.name}: correctly reports absent")

    # And prove the same predicate says YES to something that IS there, so "reports absent" is not
    # just a predicate that reports absent for everything. The installer's own source file is a
    # guaranteed-present target that no concurrent session can be running out from under us.
    assert HOOK_INSTALLER.is_file(), (
        "the presence predicate reports the installer source missing -- it answers 'absent' for "
        "everything, so the assertion above could never fail for a real reason"
    )
    print(f"present-file probe {HOOK_INSTALLER.name}: correctly reports present")

    # The marker check is the other half of the assertion and fails differently, so prove it too.
    assert SHIM_MARKERS, "no shim markers parsed -- the marker half of the assertion is vacuous"
    for shim, expected in sorted(SHIM_MARKERS.items()):
        assert expected not in "a file body that carries no marker at all", (
            f"the marker predicate matched {expected!r} in text that does not contain it ({shim})"
        )
    print(f"marker predicate rejects unmarked text for {sorted(SHIM_MARKERS)}")


# --------------------------------------------------------------------------------------------------
# WHAT HAPPENS WHEN THE GATE CANNOT RUN -- the fail-open the shims used to carry.
#
# Both shims resolved an interpreter and, finding none, printed "THE PUSH GUARD IS OFF for this push"
# (or the claim-gate equivalent) and EXITED 0. Git reads 0 as permission, so the one condition in
# which the guard is provably not evaluating anything was also the condition in which it waved
# everything through. That is the worst possible pairing: silent, and biased toward permitting.
#
# It was not theoretical on this box -- the only `python` on PATH is a per-user Microsoft Store
# app-execution alias, exactly the kind of entry that stops resolving after a profile or Store change.
#
# These are SOURCE-level tests of the generated shim text, so unlike everything above them they run on
# CI too: the property belongs to the installer, not to any box's installed copy.
# --------------------------------------------------------------------------------------------------

# The shims are PowerShell here-strings (@'...'@). Captured by variable name so a test can say WHICH
# shim it is asserting about, and so an added third shim is visible as a new key rather than silently
# unchecked.
HERE_STRINGS: dict[str, str] = dict(
    re.findall(r"\$(\w+)\s*=\s*@'\r?\n(.*?)\r?\n'@", _HOOK_SRC, re.DOTALL)
)
SHIM_VARS = ("claimHook", "pushHook")


def test_the_shim_bodies_were_parsed_from_the_installer() -> None:
    """Guard the source. An empty parse makes every assertion below vacuously green."""
    print(f"here-strings parsed from {HOOK_INSTALLER.name}: {sorted(HERE_STRINGS)}")
    missing = [v for v in SHIM_VARS if v not in HERE_STRINGS]
    assert not missing, (
        f"no here-string parsed for {missing} -- the shim variables were renamed or the quoting "
        f"changed, and the fail-closed assertions below would pass without reading any shim"
    )


@pytest.mark.parametrize("var", SHIM_VARS)
def test_the_shim_refuses_rather_than_permits_when_no_interpreter_resolves(var: str) -> None:
    """The no-interpreter branch must exit NONZERO and say how to proceed deliberately.

    Asserting on the branch rather than on the file as a whole: ``exit 0`` is a perfectly ordinary
    thing for a shell script to contain, so a blanket "no exit 0 anywhere" check would be both
    fragile and wrong. What matters is which code the ``command -v`` failure path reaches.
    """
    body = HERE_STRINGS[var]
    print(f"--- {var} ---\n{body}")

    lines = body.splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.startswith("if ! command -v")]
    assert len(starts) == 1, (
        f"{var}: expected exactly one interpreter-resolution branch, found {len(starts)}. The shim "
        f"changed shape and this assertion no longer knows which branch to read."
    )
    ends = [i for i, ln in enumerate(lines) if ln.strip() == "fi" and i > starts[0]]
    assert ends, f"{var}: the `if ! command -v` branch is never closed by `fi`"
    branch = lines[starts[0] : ends[0] + 1]
    print("branch under test:\n" + "\n".join(branch))

    exits = [ln.strip() for ln in branch if ln.strip().startswith("exit ")]
    assert exits == ["exit 1"], (
        f"{var}: the no-interpreter branch exits {exits or '(nothing)'}, not ['exit 1']. Exiting 0 "
        f"there tells git the gate PASSED at the one moment it provably did not run -- silent, and "
        f"biased toward permitting. If a deliberate bypass is wanted it belongs in an explicit "
        f"--no-verify, not in the failure path of interpreter resolution."
    )
    assert "--no-verify" in "\n".join(branch), (
        f"{var}: the refusal names no way forward. A fail-closed gate that does not say how to "
        f"proceed deliberately gets 'fixed' by deleting the gate."
    )


@pytest.mark.parametrize("var", SHIM_VARS)
def test_the_shim_actually_exits_nonzero_with_no_python_on_path(var: str, tmp_path: Path) -> None:
    """BEHAVIOURAL control for the text assertion above -- run the real shim body with an empty PATH.

    A text scan proves the source says ``exit 1``; it does not prove the branch is REACHED, which is
    the part that decides whether a push is refused. Run it: an empty PATH means ``command -v python``
    and ``command -v python3`` both fail, which is precisely the state the branch exists for.

    Run against a COPY in tmp_path, never against the installed hook -- that file fires on every push
    in every worktree on this box.
    """
    # `sh` is preferred -- the shim is POSIX and running it under a POSIX shell is the faithful
    # check -- but WHATEVER is found must be PROVED to see this process's files before it is trusted
    # (BACKLOG #1216). On Windows a PATH lookup can resolve an interpreter in a different filesystem
    # namespace: it is FOUND rather than absent, so a `which(...) is None` skip never fires and the
    # body fails for a reason unrelated to the shim. If the found shell is blind, fall back to the
    # probed resolver, which raises loudly rather than skipping.
    found = shutil.which("sh") or shutil.which("bash")
    sh = found if found and bash_sees(Path(found), tmp_path) else require_bash(tmp_path)
    print(f"POSIX shell: {sh} (namespace probe passed; which() offered {found or 'NONE'})")

    script = tmp_path / "shim"
    script.write_text(HERE_STRINGS[var].replace("\r\n", "\n"), encoding="utf-8", newline="")
    empty = tmp_path / "emptybin"
    empty.mkdir()

    # PATH is the whole experiment: point it at a directory with nothing in it so neither interpreter
    # resolves. SystemRoot is preserved because Windows process creation needs it (env var names are
    # case-insensitive on Windows, so the capitalised spelling reaches the same variable).
    env = {"PATH": str(empty)}
    if sysroot := os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = sysroot

    r = subprocess.run(
        [sh, str(script)], input="", capture_output=True, text=True, env=env, check=False
    )
    print(f"exit={r.returncode}\nstderr:\n{r.stderr}")
    assert r.returncode != 0, (
        f"{var}: with no interpreter on PATH the shim exited {r.returncode}, which git reads as "
        f"permission. The gate did not run and said everything was fine."
    )
    assert "REFUSING" in r.stderr, f"{var}: refused silently -- stderr does not say what happened"


# Shim variable -> the hook filename the installer writes it to. The parity test below needs the
# pairing; the here-string parse gives the body, and $prePush/$commitMsg give the destination.
_SHIM_FILES = {"claimHook": "commit-msg", "pushHook": "pre-push"}


@pytest.mark.parametrize("var", SHIM_VARS)
def test_the_installed_shim_matches_the_installer_here_string(var: str) -> None:
    """Is the SHIM that runs the one this checkout would install?

    The payload parity test covers the ``.py`` files and the marker check covers "a hook of ours is
    present". Neither reads the shim BODY -- so the interpreter-resolution branch, which is where the
    fail-open lived, had no instrument pointed at it at all. Fixing that branch in source therefore
    changed nothing on any box until someone re-ran the installer, and every check stayed green while
    the old shim kept exiting 0. That is the same "never installed reads as installed" defect one
    level over, so it gets the same treatment.

    Compared on CONTENT with CRLF folded, the same basis as :func:`content_hash` and the installer's
    ``Get-HookPayloadHash`` -- the installer writes the shim with LF explicitly, but a checkout's
    line endings still vary, and three instruments that fold differently about one file is itself the
    bug this repo has already been bitten by.
    """
    hooks_dir = installed_hooks_dir()
    shim = _SHIM_FILES[var]
    installed = hooks_dir / shim if hooks_dir else None
    marker = ci_marker()
    print(f"scanning: {installed or '(git named no hooks dir)'} vs {HOOK_INSTALLER.name}:${var}")
    print(f"CI marker: {marker or 'none -- treating this as a working checkout'}")

    if marker:
        pytest.skip(f"SKIP (nothing compared): {marker} -- CI installs no hooks")
    if installed is None:
        pytest.skip("SKIP (nothing compared): git resolved no hooks directory from this checkout")
    if not installed.is_file():
        pytest.skip(
            f"SKIP (nothing compared): no {shim} installed -- "
            f"test_the_coordination_hooks_are_actually_installed is the assertion for that, and it "
            f"fails off CI, so this skip cannot hide an absent hook"
        )

    expected = content_hash(HERE_STRINGS[var].encode("utf-8"))
    actual = content_hash(installed.read_bytes())
    print(f"compared (content, CRLF folded): installed={actual[:12]} generator={expected[:12]}")

    assert actual == expected, (
        f"SHIM DRIFT: the {shim} that RUNS is not what this checkout's installer generates.\n"
        f"  installed: {installed}  content={actual[:12]}\n"
        f"  generator: {HOOK_INSTALLER}  ${var}  content={expected[:12]}\n"
        f"The shim is what decides whether the gate runs AT ALL -- it resolves the interpreter and, "
        f"historically, exited 0 when it found none. An out-of-date shim can therefore be waving "
        f"pushes through while every payload-parity and marker check in this file reports green.\n"
        f"The hooks live in the COMMON git dir, so this one file governs every worktree on the box.\n"
        f"WORK OUT WHICH COPY IS OLDER FIRST -- installing from a checkout older than the installed "
        f"shim downgrades it for every worktree here:\n"
        f"    git log --oneline -5 -- scripts/coord/install-git-hooks.ps1\n"
        f"Only once THIS checkout is confirmed the newer of the two, from a plain terminal:\n"
        f"    pwsh -NoProfile -File scripts\\coord\\install-git-hooks.ps1"
    )
