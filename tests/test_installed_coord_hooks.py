# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Do the coordination hooks that are WIRED actually resolve to a script that exists?

The coordination hooks are not installed copies. Each is an inline command in ``~/.claude/settings.json``
that locates its script in a working tree at every invocation, primary checkout first::

    $bases = @((Split-Path <git-common-dir> -Parent), <toplevel>)
    foreach ($b in $bases) { $s = Join-Path $b '<relative script>'; if (Test-Path $s) { & $s; break } }

That has a failure mode nothing was watching: **if neither base yields the file, ``Test-Path`` fails, the
loop ends, nothing runs, and the tool call proceeds with no hook and no signal.** "The hook is
uninstalled" and "the hook ran and permitted this" are indistinguishable from outside.

It is not hypothetical. A ``UserPromptSubmit`` entry belonging to a *different* repo sat in this same
settings file probing a script that exists only in that repo — wired, firing, resolving nothing, exiting
0 — for weeks, and nothing reported it.

The risk composes badly for ``collision_gate.ps1`` specifically, which (a) fails OPEN on any error,
(b) now denies less by design after the dirty-vs-committed split, and (c) silently no-ops when
unresolvable. Each is individually defensible; together the realistic bad day is *the gate was never
running and nobody noticed*. This module is the assertion that closes (c).

``test_gate_installed_parity.py`` does the equivalent job for ``worktree_gate.ps1``, which DOES install a
copy and so can drift in the opposite direction. These are different mechanisms with opposite postures --
the worktree gate fails closed, these fail open -- so they need separate checks.

LOCAL-MACHINE TESTS. CI has no user settings, so these skip there, and that is honest: an unresolvable
shim is a developer-box condition, not a repository one. **What CI therefore does not guard is exactly
this property.** Following ``test_gate_installed_parity.py`` verbatim, every test PRINTS what it scanned
BEFORE it can skip -- the repo's pytest config carries no ``-rs``, so a skip would otherwise render as a
bare dot with its reason invisible.
"""

from __future__ import annotations

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
