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
import re
import subprocess
from pathlib import Path

import pytest

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
