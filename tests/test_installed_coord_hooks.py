# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

THIRD MECHANISM, SAME FILE, added for BACKLOG #1463: the VERBATIM hooks. ``install-git-hooks.ps1``
also ``Copy-Item``s ``durability_push.sh`` into that same common git dir, but under TWO names -- as
``post-commit`` and as ``post-merge``. There is no shim and no payload: the installed file IS the
hook. It is therefore outside ``$payloads`` by design, which is exactly why the section above never
looked at it and never reported that it had not looked. The installer now declares the mapping, this
module parses it out of the installer, and ``-Status`` reads the same declaration.

**THE VERBATIM HALF IS SCOPED TO THIS CHECKOUT, and saying so is the point of this paragraph.** The
fourth mechanism below sweeps every governed root for its PAYLOAD parity; nothing sweeps them for
verbatim parity, so a second governed checkout that installs verbatim hooks of its own is not covered
here. ``audit_verbatim_hooks`` is root-parameterised and ready for that sweep, and the extension is a
one-line call -- it is left undone deliberately rather than overlooked, because that sweep's test is
red for an unrelated reason (BACKLOG #1376) and a second finding threaded into it would be read as
part of that one. Do not infer coverage from the function being parameterised.

FOURTH MECHANISM, SAME FILE, added for BACKLOG #1376: the OTHER governed roots. Everything above roots
its git-hook half at THIS repository, so it answers the question for one checkout and says nothing about
any other. The worktree gate's machine allowlist
(``~/.claude/hooks/worktree-gate.repos.txt``) names more than one primary checkout, and a second
checkout that also ships ``scripts/coord/install-git-hooks.ps1`` installs its own payloads into its own
common git dir, where the same silent-staleness applies and no instrument was watching at all. Measured
2026-09-03 on the reference box: the allowlist named two roots, and the second one carried an installed
``claim_check.py`` that nothing in either checkout compared against anything.

**THE COMPARISON IS PER-ROOT AND SELF-REFERENTIAL, AND AN OWNER RULING NOW REQUIRES IT.** Each root's
installed payload is judged against THAT ROOT's own committed ``scripts/hooks/`` source, using THAT
ROOT's own installer to say which payloads it manages. No copy is ever compared across roots.

The question this shape was built to avoid deciding was *which checkout's copy of a shared governance
script is authoritative when two of them disagree*. **The owner ruled on 2026-09-03 (BACKLOG #1376):
each repository owns its own copy, and there is no cross-repo authority.** So the question does not
arise, and a test comparing one root's installed file against another root's source would do worse than
decide it silently -- it would assert an authority relationship the ruling says does not exist. This one
only asserts that whatever a root committed is what that root runs.

LOCAL-MACHINE TESTS. CI has no user settings and no allowlist, so these skip there, and that is honest:
an unresolvable shim is a developer-box condition, not a repository one. **What CI therefore does not
guard is exactly this property.** Following ``test_gate_installed_parity.py`` verbatim, every test PRINTS
what it scanned BEFORE it can skip -- the repo's pytest config carries no ``-rs``, so a skip would
otherwise render as a bare dot with its reason invisible.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from _bash_resolver import bash_preserves_path_order, bash_sees, require_bash

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
def payloads_declared_by(root: Path) -> list[str]:
    """The payload names ``root``'s OWN ``install-git-hooks.ps1`` says it manages, or [] if it has none.

    Parameterised by root so a second governed checkout is audited against its own installer rather than
    this one's. Two checkouts may legitimately manage different payload sets, and reading this list off
    the wrong installer would report a phantom missing payload in one direction and skip a real one in
    the other.

    Recognises ONE declaration shape and deliberately guesses at no other. An installer written
    differently returns [], which ``audit_governed_root`` reports as UNAUDITABLE rather than as clean --
    the honest answer. Widening this to infer payloads from, say, a ``Copy-Item`` scan would produce a
    confident payload list for a file nobody has read, and a wrong list reports parity over the wrong
    files, which is worse than reporting nothing.
    """
    try:
        src = (root / "scripts" / "coord" / "install-git-hooks.ps1").read_text(encoding="utf-8")
    except OSError:
        return []
    decl = re.search(r"(?m)^\s*\$payloads\s*=\s*@\(([^)]*)\)", src)
    return re.findall(r'"([^"]+)"', decl.group(1)) if decl else []


PAYLOADS: list[str] = payloads_declared_by(ROOT)


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


def _git_at(root: Path, *args: str) -> str:
    """stdout of a git command run at ``root``, or "" if git failed or is unusable.

    Never raises: "git could not tell us where the hooks are" is a skip reason these tests must be able
    to PRINT, not an error that kills the module before it says what it scanned.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def hooks_dir_for(root: Path) -> Path | None:
    """Where git looks for ``root``'s hooks, resolved exactly as ``install-git-hooks.ps1`` resolves it.

    ``core.hooksPath`` wins when set, otherwise ``<git-common-dir>/hooks``. Deriving it any other way
    would compare a directory git never consults and report parity for a copy that is not the one
    running -- and the obvious shortcut is worse than wrong, it is empty: in a linked worktree
    ``root/.git`` is a FILE pointing at the common dir, so ``root/.git/hooks`` never exists and every
    payload would read as "not installed".
    """
    configured = _git_at(root, "config", "--get", "core.hooksPath")
    if configured:
        p = Path(configured)
        return p if p.is_absolute() else root / configured
    common = _git_at(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
    return Path(common) / "hooks" if common else None


def installed_hooks_dir() -> Path | None:
    """``hooks_dir_for`` bound to this checkout."""
    return hooks_dir_for(ROOT)


def source_is_committed_in(root: Path, name: str) -> bool:
    """Same posture as the gate parity test: assert only against a COMMITTED source.

    Mid-edit the installed copy is *supposed* to differ, and a check that goes red on every keystroke is
    one that gets deselected and then deleted.
    """
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", f"scripts/hooks/{name}"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and not out.stdout.strip()


def payload_source_is_committed(name: str) -> bool:
    """``source_is_committed_in`` bound to this checkout."""
    return source_is_committed_in(ROOT, name)


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
# THE VERBATIM HOOKS -- BACKLOG #1463. Everything above this point audits a .py PAYLOAD that a
# generated shim execs. A verbatim hook is not that shape: install-git-hooks.ps1 Copy-Items
# scripts/hooks/durability_push.sh straight into the common git dir, so the installed file IS the
# hook and nothing regenerates around it.
#
# So it drifts the same way a payload does and was audited by nothing on this side. ``$payloads``
# deliberately excludes it -- the installer's own comment says so -- and ``PAYLOADS`` is parsed from
# that list, which means the parity test above never looked at it and never said it had not looked.
#
# ONE SOURCE, MORE THAN ONE INSTALLED NAME, and the second name is where this actually bit. Measured
# 2026-09-19 in the engine clone: ``.git/hooks/post-merge`` was byte-identical to the VAULT clone's
# copy of durability_push.sh and three weeks older than the ``post-commit`` beside it, carrying a
# matcher that refused this clone's PRIVATE remote. It ran on every ``git pull`` for three weeks
# while -Status printed INSTALLED for it and nothing compared its bytes to anything. That is why the
# declaration maps a source to a LIST: an audit that checked one name per source would have gone
# green across exactly that condition.
#
# ``install-git-hooks.ps1 -Status`` reports the same parity from the PowerShell side and reads the
# same declaration, so the two cannot drift apart into disagreeing about which names exist.

# The block terminator is the brace at the OPENER'S OWN INDENT (``^\1\}``), never the first
# ``^\s*\}`` anywhere below. Any-brace termination ends the block early at a NESTED hashtable's
# closer, and every entry past it then vanishes into a map that is still non-empty -- so no
# UNAUDITABLE, no red, and a silently short list. Losing a NAME is the orphan defect #1463 exists to
# close, so the parser must not be able to lose one quietly.
VERBATIM_DECL = re.compile(
    r"(?m)^([ \t]*)\$verbatimHooks\s*=\s*@\{[ \t]*\r?\n(.*?)^\1\}[ \t]*$", re.S
)
#: An entry this parser can read. Both PowerShell quote styles, because both are legal and a parser
#: that silently skipped one would drop a real entry.
VERBATIM_ENTRY = re.compile(r"""(?m)^[ \t]*(['"])([^'"]+)\1\s*=\s*@\(([^)]*)\)""")
#: Anything that LOOKS like an entry line, read only to count. See the mismatch guard below.
VERBATIM_CANDIDATE = re.compile(r"""(?m)^[ \t]*['"][^'"]*['"][ \t]*=""")
VERBATIM_NAME = re.compile(r"""(['"])([^'"]+)\1""")


def verbatim_hooks_declared_by(root: Path) -> dict[str, list[str]]:
    """``root``'s own installer's map of verbatim SOURCE -> every installed name, or {} if unreadable.

    Parameterised by root for the same reason ``payloads_declared_by`` is, and recognising ONE
    declaration shape for the same reason: an installer written differently returns {}, which
    ``audit_verbatim_hooks`` reports as UNAUDITABLE rather than as clean. Inferring the map from, say,
    a ``Copy-Item`` scan would produce a confident answer for a file nobody has read, and a wrong map
    audits the wrong pair of files -- which reads as agreement.

    Line-anchored twice over (``(?m)^[ \\t]*``), on the opener AND on each entry, so neither a
    commented-out ``# $verbatimHooks = @{`` nor a commented-out ``# "x.sh" = @("y")`` inside a live
    block can be credited. ``re.search`` takes the first hit anywhere in a file and a ``#`` prefix
    would otherwise satisfy an unanchored pattern -- the defect already fixed in
    ``payloads_declared_by`` and in ``test_gate_installed_parity.py``'s ``handled_tools``.

    **PARTIAL IS WORSE THAN NOTHING HERE, so a shape this parser half-reads returns {}.** An empty
    map is loud: it reports UNAUDITABLE. A map that parsed three entries out of four, or two names
    out of three, is quiet -- it reports confident parity over the subset it managed to read while
    the entry it dropped is audited by nothing. That dropped name is the 2026-09-19 orphan exactly.
    So every line inside the block that LOOKS like an entry must be one this parser actually read;
    a count mismatch means some declaration shape here is unreadable, and the honest answer to that
    is the same {} as for an unrecognised opener.
    """
    try:
        src = (root / "scripts" / "coord" / "install-git-hooks.ps1").read_text(encoding="utf-8")
    except OSError:
        return {}
    block = VERBATIM_DECL.search(src)
    if not block:
        return {}
    body = block.group(2)
    out: dict[str, list[str]] = {}
    for _q, source, names in VERBATIM_ENTRY.findall(body):
        installed = [n for _nq, n in VERBATIM_NAME.findall(names)]
        if installed:
            out[source] = installed
    if len(out) != len(VERBATIM_CANDIDATE.findall(body)):
        return {}
    return out


VERBATIM: dict[str, list[str]] = verbatim_hooks_declared_by(ROOT)


def audit_verbatim_hooks(root: Path, hooks_dir: Path | None) -> tuple[list[str], list[str]]:
    """Does ``root`` run the verbatim hooks ``root`` itself committed? Returns (findings, notes).

    Same contract and same carve-outs as ``audit_governed_root``: findings are the assertion, notes
    print either way so a run that compared nothing says so instead of looking like a run that
    compared everything and agreed. A root is only ever measured against its own installer and its
    own sources.

    An installer that is PRESENT but declares nothing this parser can read is a FINDING, not a note.
    An empty map skips every loop body below and reports clean, which is indistinguishable from a
    root with nothing wrong -- the same silent-vacuity defect ``audit_governed_root`` reports as
    UNAUDITABLE, arriving here the moment a second checkout's installer is written a little
    differently.

    Not findings, because each is a normal state rather than drift: a root that ships no installer is
    not running this machinery; git declining to name a hooks directory is a broken-git condition the
    caller cannot act on; an installed copy that is simply absent means nobody has run that root's
    installer on this box, which is a human step CI never performs; and an uncommitted source is
    SUPPOSED to differ mid-edit.
    """
    findings: list[str] = []
    notes: list[str] = []

    installer = root / "scripts" / "coord" / "install-git-hooks.ps1"
    if not installer.is_file():
        notes.append(f"  {root}: no scripts/coord/install-git-hooks.ps1 -- not governed by this")
        return findings, notes

    declared = verbatim_hooks_declared_by(root)
    if not declared:
        findings.append(
            f"{root}: UNAUDITABLE. Its install-git-hooks.ps1 is present but declares no "
            f"$verbatimHooks map this parser can read, so NOTHING about the hooks it installs "
            f"VERBATIM was compared -- and an empty map reads exactly like agreement. A verbatim "
            f"hook IS the installed file, so an unaudited one runs whatever bytes it was given "
            f"whenever it was given them, for every worktree of that clone at once. REMEDY: either "
            f"that root's installer gains the $verbatimHooks declaration this one has, or "
            f"verbatim_hooks_declared_by learns that installer's shape. Do not guess a map for a "
            f"shape nobody has read: a wrong map reports confident parity over the wrong files"
        )
        return findings, notes

    if hooks_dir is None:
        notes.append(f"  {root}: git named no hooks directory -- nothing compared")
        return findings, notes

    notes.append(f"  {root}: verbatim={declared} hooks_dir={hooks_dir}")
    for source_name, installed_names in sorted(declared.items()):
        source = root / "scripts" / "hooks" / source_name
        if not source.is_file():
            findings.append(
                f"{root}: its installer declares {source_name}, which has no source at "
                f"scripts/hooks/{source_name} -- installing there would fail, and until then those "
                f"hooks run from whatever copies are already in place. REMEDY: reconcile that root's "
                f"installer with that root's sources"
            )
            continue
        committed = source_is_committed_in(root, source_name)
        source_hash = content_hash(source.read_bytes())
        for name in installed_names:
            installed = hooks_dir / name
            if not installed.is_file():
                notes.append(f"    {name} <- {source_name}: not installed -- nothing compared")
                continue
            if not committed:
                notes.append(
                    f"    {name} <- {source_name}: source uncommitted there -- nothing compared"
                )
                continue
            installed_hash = content_hash(installed.read_bytes())
            notes.append(
                f"    {name} <- {source_name}: installed={installed_hash[:12]} "
                f"source={source_hash[:12]} "
                f"{'match' if installed_hash == source_hash else 'DIFFER'}"
            )
            if installed_hash != source_hash:
                findings.append(
                    f"{root}: CONTENT DRIFT. .git/hooks/{name} is installed VERBATIM from "
                    f"scripts/hooks/{source_name}, and the copy that RUNS is not the one this "
                    f"checkout committed (installed={installed_hash[:12]} at {installed}, "
                    f"source={source_hash[:12]}). Line endings are folded out of this comparison, so "
                    f"CRLF vs LF cannot account for it -- they differ in content. There is no shim "
                    f"here: the installed file IS the hook, so every rule in it is whatever it was "
                    f"when it was installed, for every worktree of this clone at once. WORK OUT "
                    f"WHICH COPY IS OLDER FIRST -- re-installing from the older side downgrades the "
                    f"hook everywhere:\n"
                    f"    git -C {root} log --oneline -5 -- scripts/hooks/{source_name}\n"
                    f"Only once that checkout is the newer of the two, from a plain terminal in it:\n"
                    f"    pwsh -NoProfile -File scripts\\coord\\install-git-hooks.ps1"
                )
    return findings, notes


def test_the_verbatim_hook_map_was_parsed_from_the_installer() -> None:
    """Guard the source of every check below, the way ``test_the_payload_list_was_parsed_from_the_installer``
    guards ``PAYLOADS``.

    An empty map makes ``audit_verbatim_hooks`` report UNAUDITABLE rather than clean, so it cannot go
    silently green -- but it would go red with a message about a parser rather than about a hook,
    which sends the reader to the wrong file. Say here, once, that the declaration is the thing that
    moved.
    """
    print(f"verbatim hooks parsed from {HOOK_INSTALLER.name}: {VERBATIM or 'NONE'}")
    assert VERBATIM, (
        f"no $verbatimHooks map parsed from {HOOK_INSTALLER} -- either the declaration was removed or "
        f"its shape moved away from verbatim_hooks_declared_by"
    )
    missing = [s for s in VERBATIM if not (HOOK_SOURCE_DIR / s).is_file()]
    assert not missing, (
        f"the installer declares verbatim hooks with no source in this checkout: {missing} -- "
        f"installing would fail, and until then those hooks run from whatever copies are in place"
    )
    # The list half of the declaration is the part BACKLOG #1463 turned on, so pin that the known
    # two-name source still declares both. A map that quietly lost post-merge would restore the
    # 2026-09-19 blind spot with every test here still green.
    #
    # A FLOOR, not an equality, and the difference is which reds are true ones. Both names must be
    # there; a THIRD name added later (post-rewrite, say) is a correct extension and must not red
    # this, and neither must a reordering, which means nothing. An exact pin would report both as
    # failures, and a red nobody believes is a red nobody reads.
    assert set(VERBATIM.get("durability_push.sh") or []) >= {"post-commit", "post-merge"}, (
        f"durability_push.sh is installed under BOTH post-commit and post-merge -- a map naming "
        f"fewer leaves an entire class of commit audited by nothing: "
        f"{VERBATIM.get('durability_push.sh')}"
    )


def test_this_checkout_runs_the_verbatim_hooks_it_committed() -> None:
    """BACKLOG #1463: nothing checked that a verbatim-installed git hook matches its source.

    The payload parity test above answers this for the .py hooks a shim execs. This one answers it for
    the hooks that ARE the installed file, which is the harder case: a payload at least has a shim
    whose marker someone was looking at, while a verbatim hook has nothing beside it to look at.

    LOCAL-MACHINE TEST, for the same reason as every parity test in this module: these hooks are
    installed per box by a human running the installer, and CI installs none. The notes print before
    any assertion so a run that compared nothing says so.
    """
    hooks_dir = installed_hooks_dir()
    findings, notes = audit_verbatim_hooks(ROOT, hooks_dir)
    print(f"hooks dir: {hooks_dir or '(git named none)'}")
    for line in notes:
        print(line)
    assert not findings, "\n".join(findings)


def test_the_verbatim_audit_detects_a_copy_that_was_not_committed_here(tmp_path: Path) -> None:
    """ANTI-VACUITY CONTROL, with the untouched baseline beside it.

    An audit that reported nothing whatever it was pointed at would pass on every box forever and
    read as coverage. The drifted case ALONE proves less than it looks: it cannot rule out an audit
    that finds a problem everywhere, so the clean root is not decoration, it is the half that makes
    the other half mean something.

    The clean root's installed copy is written in CRLF against an LF source, which pins that the eol
    fold still holds here -- otherwise a re-encoding could masquerade as content drift, and the first
    red this check ever produced would be a false one.

    Both roots are constructed under ``tmp_path`` and neither is a real checkout. The verbatim hooks
    on this box fire on every commit, merge and pull in every worktree of their clone; a test may not
    take one out from under a concurrent session.

    **AND THE FIXTURE NAMES ARE LIVE HOOK NAMES, which is why the containment is asserted rather than
    assumed.** ``hooks_dir_for`` honours ``core.hooksPath``, and that setting reads the global
    cascade: on a box where an operator has set it to an absolute path, both fixtures would resolve to
    that one real directory and this test would write ``post-commit`` and ``post-merge`` into it --
    files git then EXECUTES. ``_seed_verbatim_root`` pins the fixture's own ``core.hooksPath`` in its
    LOCAL config, which wins, and the assertions below refuse to write anywhere outside ``tmp_path``.
    The older governed-root control has the same shape and gets away without this because the file it
    writes is ``claim_check.py``, which git never invokes.
    """
    committed = b"#!/bin/sh\n# MessageFoundry durability hook\nexit 0\n"

    clean = tmp_path / "Clean"
    clean.mkdir()
    _seed_verbatim_root(clean, {"durability_push.sh": ["post-commit", "post-merge"]}, committed)
    clean_hooks = hooks_dir_for(clean)
    assert clean_hooks is not None, "the fixture root resolved no hooks dir -- control is vacuous"
    assert tmp_path in clean_hooks.parents, (
        f"the fixture's hooks dir resolved OUTSIDE tmp_path ({clean_hooks}) -- writing live hook "
        f"names there would plant executable hooks in a real directory"
    )
    for name in ("post-commit", "post-merge"):
        (clean_hooks / name).write_bytes(committed.replace(b"\n", b"\r\n"))

    # Drift ONLY the second installed name. A source installed twice is where this class of defect
    # actually lived, and an audit that stopped at the first name would report this root clean --
    # which is precisely the 2026-09-19 orphan post-merge, reconstructed.
    drifted = tmp_path / "Drifted"
    drifted.mkdir()
    _seed_verbatim_root(drifted, {"durability_push.sh": ["post-commit", "post-merge"]}, committed)
    drifted_hooks = hooks_dir_for(drifted)
    assert drifted_hooks is not None, "the fixture root resolved no hooks dir -- control is vacuous"
    assert tmp_path in drifted_hooks.parents, (
        f"the fixture's hooks dir resolved OUTSIDE tmp_path ({drifted_hooks}) -- writing live hook "
        f"names there would plant executable hooks in a real directory"
    )
    assert drifted_hooks != clean_hooks, (
        "both fixture roots resolved to ONE hooks directory, so the clean baseline and the drifted "
        "case are writing over each other and neither measures what it claims to"
    )
    (drifted_hooks / "post-commit").write_bytes(committed)
    (drifted_hooks / "post-merge").write_bytes(committed + b"# installed three weeks earlier\n")

    clean_findings, clean_notes = audit_verbatim_hooks(clean, clean_hooks)
    drift_findings, drift_notes = audit_verbatim_hooks(drifted, drifted_hooks)
    for line in (*clean_notes, *drift_notes):
        print(line)

    assert not clean_findings, (
        f"the audit reported drift for a root whose installed copies match its committed source, "
        f"differing only in line endings: {clean_findings}"
    )
    assert drift_findings, (
        "the audit found nothing for a root whose SECOND installed name differs in content from the "
        "source that root committed -- it cannot detect the condition it exists to detect"
    )
    assert "post-merge" in drift_findings[0] and "durability_push.sh" in drift_findings[0], (
        f"the finding names neither the installed hook nor its source, so a reader cannot act on it: "
        f"{drift_findings[0]}"
    )
    assert not any("post-commit" in f for f in drift_findings), (
        f"the audit reported the matching post-commit as drifted too, so it is not comparing "
        f"per installed name: {drift_findings}"
    )


def test_the_verbatim_audit_reports_an_installer_whose_map_it_cannot_read(tmp_path: Path) -> None:
    """The other way this audit goes silently vacuous: an installer it cannot parse.

    An unreadable ``$verbatimHooks`` yields an empty map, every loop body is skipped, and the root
    reports clean -- indistinguishable from a root with nothing wrong. Modelled on
    ``test_the_governed_root_audit_reports_an_installer_whose_payload_list_it_cannot_read``, which
    exists because the same hole opened one level up.
    """
    root = tmp_path / "Unparseable"
    root.mkdir()
    _seed_verbatim_root(root, {"durability_push.sh": ["post-commit"]}, b"#!/bin/sh\nexit 0\n")
    (root / "scripts" / "coord" / "install-git-hooks.ps1").write_text(
        "# an installer this parser cannot read\n$verbatim = @{ 'durability_push.sh' = 'post-commit' }\n",
        encoding="utf-8",
    )

    findings, notes = audit_verbatim_hooks(root, hooks_dir_for(root))
    for line in notes:
        print(line)
    assert findings and "UNAUDITABLE" in findings[0], (
        f"a root whose installer cannot be parsed reported clean: {findings}"
    )
    assert "$verbatimHooks" in findings[0], (
        f"the finding does not name what could not be read, so a reader cannot act on it: "
        f"{findings[0]}"
    )


def test_the_verbatim_declaration_parser_refuses_a_commented_out_map(tmp_path: Path) -> None:
    """Line-anchoring is the whole of what keeps a COMMENT from being read as a declaration.

    Two shapes, because the parser anchors twice and only the pair exercises both anchors: a fully
    commented-out block, and a live block with one entry commented out. The second is the one a
    reader is most likely to write -- disabling a hook by prefixing its line -- and an unanchored
    entry pattern would go on auditing it.

    A positive control sits beside them, because a parser that returned {} for EVERYTHING would pass
    both negative assertions while reporting every installer on the box UNAUDITABLE.
    """
    live = tmp_path / "Live"
    (live / "scripts" / "coord").mkdir(parents=True)
    installer = live / "scripts" / "coord" / "install-git-hooks.ps1"

    installer.write_text(
        '# $verbatimHooks = @{\n#     "durability_push.sh" = @("post-commit", "post-merge")\n# }\n',
        encoding="utf-8",
    )
    print(f"fully commented out -> {verbatim_hooks_declared_by(live)}")
    assert verbatim_hooks_declared_by(live) == {}, (
        "a commented-out declaration was credited as the real one -- the opener is not line-anchored"
    )

    installer.write_text(
        '$verbatimHooks = @{\n    "durability_push.sh" = @("post-commit")\n'
        '#    "retired_hook.sh" = @("pre-rebase")\n}\n',
        encoding="utf-8",
    )
    partial = verbatim_hooks_declared_by(live)
    print(f"one entry commented out -> {partial}")
    assert partial == {"durability_push.sh": ["post-commit"]}, (
        f"a commented-out ENTRY inside a live block was credited: {partial}"
    )

    installer.write_text(
        '$verbatimHooks = @{\n    "durability_push.sh" = @("post-commit", "post-merge")\n}\n',
        encoding="utf-8",
    )
    positive = verbatim_hooks_declared_by(live)
    print(f"positive control -> {positive}")
    assert positive == {"durability_push.sh": ["post-commit", "post-merge"]}, (
        f"the parser failed to read a well-formed declaration, so the two assertions above prove "
        f"nothing about anchoring: {positive}"
    )


def test_a_declaration_this_parser_half_reads_returns_nothing_rather_than_a_short_list(
    tmp_path: Path,
) -> None:
    """A PARTIAL read is the dangerous one, because it is the quiet one.

    An empty map is loud: ``audit_verbatim_hooks`` reports UNAUDITABLE. A map that read three entries
    out of four, or two names out of three, is silent -- it reports confident parity over the subset
    and the entry it dropped is compared to nothing. A dropped installed NAME is the 2026-09-19
    orphan exactly, so the parser has to be unable to drop one without saying so.

    Each shape below is one this parser genuinely cannot read. The assertion is that every one yields
    {} rather than a short list; the two positive controls at the end are what stop a parser broken
    to always-{} from passing this whole test.
    """
    root = tmp_path / "Shapes"
    (root / "scripts" / "coord").mkdir(parents=True)
    installer = root / "scripts" / "coord" / "install-git-hooks.ps1"

    half_read = {
        "nested hashtable closes the block early": "$verbatimHooks = @{\n"
        '    "a.sh" = @("x")\n    "b.sh" = @{ k = 1 }\n    "c.sh" = @("y")\n}\n',
        "a value that is not an array": "$verbatimHooks = @{\n"
        '    "a.sh" = @("x")\n    "b.sh" = "post-commit"\n}\n',
        "an entry declaring no names at all": "$verbatimHooks = @{\n"
        '    "a.sh" = @("x")\n    "b.sh" = @()\n}\n',
    }
    for label, text in half_read.items():
        installer.write_text(text, encoding="utf-8")
        got = verbatim_hooks_declared_by(root)
        print(f"{label} -> {got}")
        assert got == {}, (
            f"the parser returned a SHORT list for a declaration it can only half read ({label}): "
            f"{got}. A short list reads as agreement over the entries it dropped"
        )

    # Both PowerShell quote styles are legal, and a parser that silently skipped one would drop a
    # real entry -- the same defect from the other direction. These must PARSE, not return {}.
    installer.write_text(
        "$verbatimHooks = @{\n    'a.sh' = @('post-commit', \"post-merge\")\n}\n", encoding="utf-8"
    )
    quoted = verbatim_hooks_declared_by(root)
    print(f"mixed quote styles -> {quoted}")
    assert quoted == {"a.sh": ["post-commit", "post-merge"]}, (
        f"a legal single-quoted declaration was dropped or half-read: {quoted}"
    )

    installer.write_text(
        '$verbatimHooks = @{\n    "a.sh" = @("x")\n    "b.sh" = @("y", "z")\n}\n', encoding="utf-8"
    )
    two = verbatim_hooks_declared_by(root)
    print(f"two well-formed entries -> {two}")
    assert two == {"a.sh": ["x"], "b.sh": ["y", "z"]}, (
        f"the parser failed on two well-formed entries, so every {{}} above proves nothing about "
        f"the guard and only that the parser is broken: {two}"
    )


def _seed_verbatim_root(root: Path, verbatim: dict[str, list[str]], body: bytes) -> None:
    """A throwaway checkout shaped like a governed root, declaring verbatim hooks instead of payloads.

    Sibling of ``_seed_governed_root`` below rather than a parameter on it: that one seeds a
    ``$payloads`` installer, and folding both shapes into one helper would let a test that meant to
    exercise one declaration silently exercise the other.
    """
    (root / "scripts" / "coord").mkdir(parents=True)
    (root / "scripts" / "hooks").mkdir(parents=True)
    entries = "\n".join(
        f'    "{source}" = @({", ".join(f'"{n}"' for n in names)})'
        for source, names in verbatim.items()
    )
    (root / "scripts" / "coord" / "install-git-hooks.ps1").write_text(
        f"# fixture installer\n$verbatimHooks = @{{\n{entries}\n}}\n", encoding="utf-8"
    )
    for source in verbatim:
        (root / "scripts" / "hooks" / source).write_bytes(body)
    for args in (
        ("init", "-q"),
        ("config", "user.email", "t@example.invalid"),
        ("config", "user.name", "T"),
        # PIN THE FIXTURE'S OWN HOOKS DIRECTORY IN LOCAL CONFIG, which beats the global cascade.
        # hooks_dir_for honours core.hooksPath, so on a box where an operator has set it globally to
        # an absolute path every fixture would otherwise resolve to that one real directory -- and
        # the caller writes LIVE hook names, files git executes. Local config makes the containment
        # a property of the fixture rather than of the box it runs on.
        ("config", "core.hooksPath", str(root / ".git" / "hooks")),
        ("add", "--", "scripts"),
        ("commit", "-q", "-m", "seed"),
    ):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
    (root / ".git" / "hooks").mkdir(parents=True, exist_ok=True)


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


def _posix_shell(tmp_path: Path) -> str:
    """The interpreter the empty-PATH experiment below runs under, PINNED ON PROOF NOT ON A NAME.

    ``sh`` is preferred -- the shim is POSIX and running it under a POSIX shell is the faithful check
    -- but WHATEVER is found must be PROVED before it is trusted (BACKLOG #1216). On Windows a PATH
    lookup can resolve an interpreter in a different filesystem namespace: it is FOUND rather than
    absent, so a ``which(...) is None`` skip never fires and the body fails for a reason unrelated to
    the shim. If the found shell fails a probe, fall back to the shared resolver, which raises loudly
    rather than skipping.

    BOTH probes, matching ``require_bash``, and PATH order is the load-bearing one HERE SPECIFICALLY
    (BACKLOG #1272). The experiment below sets ``env = {"PATH": str(empty)}`` and nothing else, so
    PATH is its ONLY variable -- and Git for Windows' ``bin/sh.exe`` wrapper rewrites PATH to put
    ``/mingw64/bin`` first, refilling the directory the test just emptied. ``bash_sees`` passes it,
    because the filesystem namespace is fine and PATH order is an orthogonal dimension. The
    assertions would then hold for a reason unrelated to the shim.
    """
    found = shutil.which("sh") or shutil.which("bash")
    if (
        found
        and bash_sees(Path(found), tmp_path)
        and bash_preserves_path_order(Path(found), tmp_path)
    ):
        return found
    return require_bash(tmp_path)


@pytest.mark.parametrize("var", SHIM_VARS)
def test_the_shim_actually_exits_nonzero_with_no_python_on_path(var: str, tmp_path: Path) -> None:
    """BEHAVIOURAL control for the text assertion above -- run the real shim body with an empty PATH.

    A text scan proves the source says ``exit 1``; it does not prove the branch is REACHED, which is
    the part that decides whether a push is refused. Run it: an empty PATH means ``command -v python``
    and ``command -v python3`` both fail, which is precisely the state the branch exists for.

    Run against a COPY in tmp_path, never against the installed hook -- that file fires on every push
    in every worktree on this box.
    """
    sh = _posix_shell(tmp_path)
    print(f"POSIX shell: {sh}")

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


def test_the_shell_selection_consults_both_probes_not_only_the_namespace_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PATH ORDER is the load-bearing dimension HERE SPECIFICALLY, and one probe cannot see it.

    The experiment above sets ``env = {"PATH": str(empty)}`` and nothing else -- PATH is its only
    variable. Git for Windows' ``bin/bash.exe`` (and the ``bin/sh.exe`` beside it) is the MINGW64
    wrapper: it REWRITES the inherited PATH so ``/mingw64/bin`` leads. MEASURED on this box, same
    shim, one variable::

        Git/bin/sh.exe      sees=True  order=False  PATH head -> /mingw64/bin
        Git/usr/bin/sh.exe  sees=True  order=True   PATH head -> <the empty dir>

    A shell that refills the directory the test emptied DESTROYS the experiment while every assertion
    still passes -- it passes today only because nothing in ``mingw64/bin`` happens to be named
    ``python``, which is a property of Git's packaging, not of the shim. ``bash_sees`` cannot catch it
    and that is not a gap in that probe: it asks about the FILESYSTEM NAMESPACE, and both binaries
    share ours. The dimensions are orthogonal, so the site must consult BOTH, exactly as
    ``require_bash`` does.

    Forced rather than waited for. ``which("sh")`` resolves ``usr/bin`` on this box, so the hole is
    LATENT here and fires wherever PATH orders ``Git/bin`` first -- a test that only ran the real
    lookup would be green on this machine for a reason unrelated to the code. So ``which`` is pointed
    at an interpreter that is real, runs, and is not a shell, and the namespace probe is mutated OPEN
    the way ``test_bash_resolver`` establishes: with the first probe answering yes to everything, only
    a genuinely consulted second probe can still reject. No skip and no Git-for-Windows needed, so
    this control is alive on every platform the suite runs on.
    """
    real_which = shutil.which

    def fake_which(cmd: str, mode: int = os.F_OK | os.X_OK, path: str | None = None) -> str | None:
        # Narrow on purpose: `bash_candidates` calls which("git") to anchor itself, and hijacking
        # that would break the fall-back this test is asserting reaches.
        if cmd == "sh":
            return sys.executable
        return real_which(cmd, mode, path)

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(sys.modules[__name__], "bash_sees", lambda *a, **k: True)

    chosen = _posix_shell(tmp_path)
    assert chosen != sys.executable, (
        f"the selection returned {chosen}, an interpreter `require_bash` rejects. It was accepted on "
        "the strength of one probe, so a shell that rewrites PATH is accepted the same way -- and "
        "PATH is the only variable this module's empty-PATH experiment has."
    )
    assert bash_preserves_path_order(Path(chosen), tmp_path), (
        f"the selected shell ({chosen}) rewrites PATH, so the empty directory the experiment points "
        "PATH at is refilled before the shim runs and the assertions hold for the wrong reason"
    )


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


# --------------------------------------------------------------------------------------------------
# The OTHER governed roots -- the fourth mechanism described in the module docstring (BACKLOG #1376).
# Everything above roots its git-hook half at THIS repository. A second primary checkout on the same
# box that also ships install-git-hooks.ps1 installs its own payloads into its own common git dir, and
# nothing anywhere compared them. Read the comparison rule in the docstring before editing anything
# here: every check below is PER-ROOT and SELF-REFERENTIAL, and an owner ruling requires it to stay
# that way -- ruled 2026-09-03 (BACKLOG #1376), each repository owns its own copy of a shared
# governance script and there is no cross-repo authority.

# The worktree gate's machine allowlist, resolved the way scripts/hooks/worktree_gate.ps1's $ReposFile
# default resolves it: USERPROFILE first, the user-profile folder otherwise. Not a repository file --
# it names checkouts, so it cannot live in one of them, and that is why CI has none and these skip
# there. tests/test_worktree_gate_default_reposfile.py pins the gate's half of this path.
GATE_REPOS_FILE = (
    Path(os.environ.get("USERPROFILE") or Path.home())
    / ".claude"
    / "hooks"
    / "worktree-gate.repos.txt"
)


def read_governed_roots(repos_file: Path) -> list[Path]:
    """The primary checkouts named by the allowlist: one path per line, ``#`` comments and blanks out.

    Returns [] for an absent or unreadable file rather than raising. An absent allowlist means the gate
    is off everywhere -- the documented kill switch -- so there is no governed set to audit, and that is
    a skip these tests must be able to print.
    """
    try:
        text = repos_file.read_text(encoding="utf-8-sig")
    except OSError:
        return []
    return [
        Path(s) for s in (line.strip() for line in text.splitlines()) if s and not s.startswith("#")
    ]


def _key(path: Path) -> str:
    """A comparable spelling of a path, for asking whether two roots share one hooks directory."""
    return os.path.normcase(os.path.normpath(str(path)))


def audit_governed_root(root: Path, hooks_dir: Path | None) -> tuple[list[str], list[str]]:
    """Does ``root`` run the hook payloads ``root`` itself committed? Returns (findings, notes).

    Findings are the assertion; notes are printed either way so a run that compared nothing says so
    rather than looking like a run that compared everything and agreed. A root is only ever measured
    against its own installer and its own source -- see the module docstring.

    ``hooks_dir`` is passed in rather than resolved here because the caller has already resolved it to
    decide whether this root is the one the tests above already cover. Resolving it twice would be two
    git reads that could, in principle, disagree -- and then the directory reported would not be the
    directory compared.

    Four conditions are deliberately NOT findings, because each is a normal state rather than drift:
    a root that ships no install-git-hooks.ps1 is not running this machinery at all; git declining to
    name a hooks directory is a broken-git condition the caller cannot act on; a payload with no
    installed copy just means nobody has run that root's installer on this box, which is a human step
    CI never performs; and an uncommitted source is SUPPOSED to differ mid-edit.
    """
    findings: list[str] = []
    notes: list[str] = []

    installer = root / "scripts" / "coord" / "install-git-hooks.ps1"
    if not installer.is_file():
        notes.append(f"  {root}: no scripts/coord/install-git-hooks.ps1 -- not governed by this")
        return findings, notes

    payloads = payloads_declared_by(root)
    if not payloads:
        findings.append(
            f"{root}: UNAUDITABLE. Its install-git-hooks.ps1 is present but declares no $payloads list "
            f"this parser can read, so NOTHING about what that root runs was compared -- and an empty "
            f"payload list reads exactly like agreement, which is the state BACKLOG #1376 filed. "
            f"REMEDY: either that root's installer gains the $payloads declaration this one has, or "
            f"payloads_declared_by learns that installer's shape. The owner ruled on 2026-09-03 that "
            f"each repository owns its own copy and there is no cross-repo authority, so BOTH repairs "
            f"keep this audit self-referential and the ruling picks NEITHER -- choosing between them "
            f"is an ordinary engineering call, tracked in #1376. Do not guess a payload list for a "
            f"shape nobody has read, because a wrong guess reports confident parity over the wrong "
            f"files"
        )
        return findings, notes

    if hooks_dir is None:
        notes.append(f"  {root}: git named no hooks directory -- nothing compared")
        return findings, notes

    notes.append(f"  {root}: payloads={payloads} hooks_dir={hooks_dir}")
    for name in payloads:
        source = root / "scripts" / "hooks" / name
        installed = hooks_dir / name
        if not source.is_file():
            findings.append(
                f"{root}: its installer lists {name}, which has no source at scripts/hooks/{name} -- "
                f"installing there would fail, and until then that hook runs from whatever copy is "
                f"already in place. REMEDY: reconcile that root's installer with that root's sources"
            )
            continue
        if not installed.is_file():
            notes.append(f"    {name}: not installed at {installed} -- nothing compared")
            continue
        if not source_is_committed_in(root, name):
            notes.append(f"    {name}: source is uncommitted there -- nothing compared")
            continue
        installed_hash = content_hash(installed.read_bytes())
        source_hash = content_hash(source.read_bytes())
        notes.append(
            f"    {name}: installed={installed_hash[:12]} source={source_hash[:12]} "
            f"{'match' if installed_hash == source_hash else 'DIFFER'}"
        )
        if installed_hash != source_hash:
            findings.append(
                f"{root}: CONTENT DRIFT. The {name} that RUNS there is not the one that checkout "
                f"committed (installed={installed_hash[:12]} at {installed}, "
                f"source={source_hash[:12]}). Line endings are folded out of this comparison, so they "
                f"differ in content. REMEDY: work out which copy is older FIRST -- "
                f"`git -C {root} log --oneline -5 -- scripts/hooks/{name}` -- then, only if that "
                f"checkout is the newer of the two, run its own installer from a plain terminal IN "
                f"THAT ROOT. Re-installing from the older side downgrades the hook for every worktree "
                f"of that repository"
            )
    return findings, notes


def test_every_governed_root_runs_the_hook_payloads_its_own_checkout_committed() -> None:
    """BACKLOG #1376. A second governed checkout's per-repo hooks were covered by nothing at all.

    ``test_the_installed_coord_hook_matches_the_committed_source`` above roots at THIS repository, so it
    would go red for this checkout's hooks and stay green while another governed root ran a payload
    months out of date. ``test_gate_installed_parity.py`` does not cover the difference either: the
    worktree gate installs ONE shared copy under ``~/.claude/hooks`` for the whole box, while these
    payloads are installed per repository into each root's own common git dir.

    Reports, and never decides, which copy is right. Each root is measured against its own committed
    source only.
    """
    roots = read_governed_roots(GATE_REPOS_FILE)
    print(f"allowlist: {GATE_REPOS_FILE}")
    print(f"governed roots: {[str(r) for r in roots] or 'NONE'}")
    if not roots:
        pytest.skip(
            "SKIP (nothing compared): no worktree-gate allowlist on this box, so no governed set "
            "(printed above). CI has none by construction"
        )

    # Do not report this checkout's own hooks directory twice: the parametrized test above already
    # asserts on it, against THIS worktree's source rather than the primary's, and two verdicts on one
    # directory from two different sources is the ambiguity the module exists to remove.
    already = hooks_dir_for(ROOT)
    already_key = _key(already) if already else None

    findings: list[str] = []
    for root in roots:
        if not root.is_dir():
            print(f"  {root}: allowlisted but not present on this box -- nothing compared")
            continue
        hooks_dir = hooks_dir_for(root)
        if hooks_dir is not None and already_key is not None and _key(hooks_dir) == already_key:
            print(f"  {root}: shares this checkout's hooks dir -- covered by the test above")
            continue
        root_findings, notes = audit_governed_root(root, hooks_dir)
        for line in notes:
            print(line)
        findings.extend(root_findings)

    assert not findings, (
        "A CHECKOUT ON THE WORKTREE GATE'S ALLOWLIST IS NOT KNOWN TO RUN WHAT IT COMMITTED. Each "
        "finding carries its own remedy; read the one that fired, they are not the same repair:\n\n"
        + "\n\n".join(f"  * {f}" for f in findings)
        + "\n\nEvery root above was measured ONLY against its own installer and its own committed "
        "scripts/hooks/ source. Nothing here compares one checkout's copy against another's, and no "
        "finding above says which checkout's copy of a shared script is authoritative. The owner "
        "ruled on 2026-09-03 that none of them is: each repository owns its own copy and there is no "
        "cross-repo authority (BACKLOG #1376). A cross-root comparison would assert a relationship "
        "the ruling says does not exist, so do not add one here.\n"
        "This is a developer-box condition, not a repository one: it is fixed by an operator action in "
        "the root that is named, not by an edit here. Do not delete or deselect this test to get a "
        "green -- that restores the exact blindness #1376 was filed for."
    )


def _seed_governed_root(root: Path, payloads: list[str], body: bytes) -> None:
    """A throwaway checkout shaped like a governed root: an installer, committed sources, a hooks dir."""
    (root / "scripts" / "coord").mkdir(parents=True)
    (root / "scripts" / "hooks").mkdir(parents=True)
    decl = ", ".join(f'"{p}"' for p in payloads)
    (root / "scripts" / "coord" / "install-git-hooks.ps1").write_text(
        f"# fixture installer\n$payloads = @({decl})\n", encoding="utf-8"
    )
    for name in payloads:
        (root / "scripts" / "hooks" / name).write_bytes(body)
    for args in (
        ("init", "-q"),
        ("config", "user.email", "t@example.invalid"),
        ("config", "user.name", "T"),
        ("add", "--", "scripts"),
        ("commit", "-q", "-m", "seed"),
    ):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def test_the_governed_root_audit_detects_a_root_running_something_it_did_not_commit(
    tmp_path: Path,
) -> None:
    """ANTI-VACUITY CONTROL, with the untouched baseline beside it.

    A per-root audit that reported nothing no matter what it was pointed at would pass on this box
    forever and read as coverage -- which is the exact state BACKLOG #1376 filed. So drive the audit
    against a constructed root in BOTH conditions: one whose installed payload matches its committed
    source, and one whose does not. Only the pair proves the predicate can tell them apart; the drifted
    case alone cannot rule out an audit that finds a problem everywhere.

    Built in tmp_path and never against a real root. The installed payloads on this box fire on every
    commit and push in every worktree of their repository, and the machine allowlist is the worktree
    gate's kill switch -- a test may not take either out from under a concurrent session.
    """
    committed = b"#!/usr/bin/env python3\nprint('the committed payload')\n"

    clean = tmp_path / "Clean"
    clean.mkdir()
    _seed_governed_root(clean, ["claim_check.py"], committed)
    clean_hooks = hooks_dir_for(clean)
    assert clean_hooks is not None, "the fixture root resolved no hooks dir -- control is vacuous"
    (clean_hooks / "claim_check.py").write_bytes(committed.replace(b"\n", b"\r\n"))

    drifted = tmp_path / "Drifted"
    drifted.mkdir()
    _seed_governed_root(drifted, ["claim_check.py"], committed)
    drifted_hooks = hooks_dir_for(drifted)
    assert drifted_hooks is not None, "the fixture root resolved no hooks dir -- control is vacuous"
    (drifted_hooks / "claim_check.py").write_bytes(committed + b"print('installed months ago')\n")

    clean_findings, clean_notes = audit_governed_root(clean, clean_hooks)
    drift_findings, drift_notes = audit_governed_root(drifted, drifted_hooks)
    for line in (*clean_notes, *drift_notes):
        print(line)

    # The baseline first. Without it a finding on the drifted root proves only that the audit reports
    # something, not that it reports drift -- and the CRLF copy also pins that the eol fold still holds
    # here, so a re-encoding cannot masquerade as content drift one root over.
    assert not clean_findings, (
        f"the audit reported drift for a root whose installed payload matches its committed source, "
        f"differing only in line endings: {clean_findings}"
    )
    assert drift_findings, (
        "the audit found nothing for a root whose installed payload differs in content from the source "
        "that root committed -- it cannot detect the condition it exists to detect"
    )
    assert str(drifted) in drift_findings[0] and "claim_check.py" in drift_findings[0], (
        f"the finding names neither the root nor the payload, so a reader cannot act on it: "
        f"{drift_findings[0]}"
    )


def test_the_governed_root_audit_reports_an_installer_whose_payload_list_it_cannot_read(
    tmp_path: Path,
) -> None:
    """The other way this audit goes silently vacuous: an installer it cannot parse.

    An unparseable ``$payloads`` yields an empty list, every payload loop body is skipped, and the root
    reports clean -- indistinguishable from a root with nothing wrong. That is the same defect
    ``test_the_payload_list_was_parsed_from_the_installer`` guards one level up, and it arrives here for
    free the moment a second checkout's installer is written a little differently.
    """
    root = tmp_path / "Unparseable"
    root.mkdir()
    _seed_governed_root(root, ["claim_check.py"], b"x\n")
    (root / "scripts" / "coord" / "install-git-hooks.ps1").write_text(
        "# an installer this parser cannot read\n$hookPayloads = @('claim_check.py')\n",
        encoding="utf-8",
    )

    findings, notes = audit_governed_root(root, hooks_dir_for(root))
    for line in notes:
        print(line)
    assert findings and "UNAUDITABLE" in findings[0], (
        f"a governed root whose installer cannot be parsed reported clean: {findings}"
    )
    assert "$payloads" in findings[0], (
        f"the finding does not name what could not be read, so a reader cannot act on it: {findings[0]}"
    )


def test_the_allowlist_reader_skips_comments_and_blanks_and_keeps_paths(tmp_path: Path) -> None:
    """The allowlist's real shape carries a comment header, and a reader that kept it would audit a
    root named ``# Primary checkouts governed by...`` -- which is not a directory, so the report would
    carry a line nobody can act on.

    The kept lines are compared WHOLE, never by ``Path.name``. This allowlist is a Windows file -- it
    resolves under ``USERPROFILE`` and its lines are drive-letter paths -- but the reader is ordinary
    ``pathlib``, and a backslash is not a separator on POSIX. Measured on both: the two lines below
    parse as two paths either way, and the leaf of the first is ``Alpha`` on Windows and the ENTIRE
    line on Linux, so a ``.name`` assertion means two different things for one input and reds the
    Linux leg. The whole spelling pins more of each line than the leaf did and reads the same on both.
    """
    kept = ["C:\\Users\\X\\Code\\Alpha", "C:\\Users\\X\\Code\\Beta"]
    f = tmp_path / "repos.txt"
    f.write_text(f"# a comment header\n\n{kept[0]}\n   \n{kept[1]}\n", encoding="utf-8")
    roots = read_governed_roots(f)
    print(f"parsed: {[str(r) for r in roots]}")
    assert [str(r) for r in roots] == kept, (
        "the reader must drop the comment header and both blank-ish lines and keep every remaining "
        "line exactly as written"
    )
    assert read_governed_roots(tmp_path / "absent.txt") == [], (
        "an absent allowlist is the documented kill switch and must read as an empty governed set"
    )


# ----------------------------------------------- a remediation must name a flag that exists


INSTALLER_PS1 = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "install-git-hooks.ps1"


def _declared_switches(text: str) -> set[str]:
    """The parameter names the script's own `param(...)` block declares."""
    block = re.search(r"^param\(\s*(.*?)^\)", text, re.S | re.M)
    assert block, "install-git-hooks.ps1 has no param block -- the probe, not the script, is broken"
    return {"-" + name for name in re.findall(r"\$(\w+)", block.group(1))}


def _reissue_instructions(text: str) -> list[tuple[str, set[str]]]:
    """Every `Write-Host` line that tells a reader to RE-RUN THIS SCRIPT, with the flags it names.

    Scoped to re-run instructions on purpose. This file's output also quotes flags belonging to
    `alloc.ps1` and `claim.ps1` (`-Kind`, `-Take`, `-Note`, `-Title`, `-List`), and those are not
    this script's to declare. A probe that graded them would be red on correct text.
    """
    out = []
    for line in re.findall(r'Write-Host "([^"]*)"', text):
        if "Re-run" not in line:
            continue
        named = set(re.findall(r"(?<![\w-])(-[A-Z][A-Za-z]+)", line))
        # pwsh's own flags appear when the line spells a full command.
        named -= {"-NoProfile", "-File", "-Command", "-NonInteractive"}
        out.append((line, named))
    return out


def test_every_re_run_instruction_names_a_real_parameter() -> None:
    """`-Status` told a reader to "Re-run with -Arm." for a script that has no such parameter.

    Following it returns `A parameter cannot be found that matches parameter name 'Arm'`, which
    reads as a broken tool rather than as a wrong instruction -- so the reader stops, and the stale
    hook the message was warning about stays installed. Measured 2026-09-20: the box's `post-merge`
    was three weeks older than the `post-commit` beside it and refused the PRIVATE vault as though
    it were the public repository, and this string is what stood between the warning and the fix.
    """
    text = INSTALLER_PS1.read_text(encoding="utf-8")
    declared = _declared_switches(text)
    instructions = _reissue_instructions(text)
    assert instructions, "found no re-run instructions at all -- the probe stopped working"
    bad = [(line, sorted(named - declared)) for line, named in instructions if named - declared]
    assert not bad, (
        "a re-run instruction names a flag this script does not declare "
        f"(declared: {sorted(declared)}):\n"
        + "".join(f"  {flags} in: {line.strip()}\n" for line, flags in bad)
    )


def test_the_re_run_probe_can_fail() -> None:
    """The anti-vacuity arm. A probe that finds no instructions would pass the test above silently."""
    declared = _declared_switches(INSTALLER_PS1.read_text(encoding="utf-8"))
    planted = 'Write-Host "               Re-run with -Arm." -ForegroundColor Yellow'
    found = _reissue_instructions(planted)
    assert found, "the probe did not see a re-run instruction it was handed"
    assert found[0][1] - declared == {"-Arm"}, found
