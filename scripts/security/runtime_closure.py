#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rewrite ``security/runtime-closure-core.txt`` from the DEP-1 core lock (BACKLOG #1812).

The closure file is the denominator for ``docs/RISKY-COMPONENTS.md``. Its pin lines are a copy of
``docker/locks/requirements-core.lock``, one ``name==version`` per package, sorted, with markers and
hashes dropped. ``tests/test_risky_component_designation.py`` holds the copy to the lock, and uses
this module to do it, so the gate and the regenerator read the lock the same way.

STANDARD LIBRARY ONLY. ``.github/workflows/dependabot-lock-resync.yml`` runs this with the runner's
``python3`` right after it re-exports the core lock, and that job installs nothing on purpose (read
its SECURITY MODEL block). A third-party import here would fail there and leave every Dependabot PR
red. ``tests/test_dep1_lock_resync_lockstep.py`` enforces the rule.

Run from anywhere; paths resolve from this file:

    python scripts/security/runtime_closure.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLOSURE = ROOT / "security" / "runtime-closure-core.txt"
CORE_LOCK = ROOT / "docker" / "locks" / "requirements-core.lock"

#: A plain pin at the start of a lock line: a PEP 508 name, ``==`` but never ``===``, then a version
#: made only of PEP 440 characters, ended by whitespace, a marker, a line continuation or the line
#: end. So ``foo==1.*`` and ``foo==1.0,<2`` do not match.
_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)(?=[\s;\\]|$)"
)


class LockFormatError(ValueError):
    """A lock line this parser cannot read, or a closure it cannot record as one version per name."""


def canonical_name(name: str) -> str:
    """The PEP 503 normalized name, the form ``packaging.utils.canonicalize_name`` returns."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def lock_versions(path: Path, *, strict: bool = False) -> dict[str, list[str]]:
    """Name to every version an exported lock pins for it, in file order.

    A pin line reads ``name==version ; marker \\`` and the hash lines under it are indented. A list,
    because an export writes one line per marker fork. Each caller decides which names must be
    unambiguous, so a fork in a package it never reads is not its failure.

    With ``strict``, a top-level line that is not a plain ``name==version`` pin raises. A URL, extras
    or ``===`` requirement would otherwise vanish from the parsed set, and so from the denominator,
    with nothing reporting it. The name is matched from the start of the line, so an ``==`` inside
    a marker on a URL requirement is not read as a pin.
    """
    pins: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith((" ", "#")):
            continue
        pin = _PIN.match(line)
        if pin is None:
            if strict:
                raise LockFormatError(
                    f"{path.name} has a requirement this parser cannot read: {line!r}"
                )
            continue
        pins.setdefault(canonical_name(pin["name"]), []).append(pin["version"])
    return pins


def core_lock_pins(path: Path = CORE_LOCK) -> dict[str, str]:
    """Name to version for the core closure, read from the DEP-1 core lock."""
    pins: dict[str, str] = {}
    for name, versions in lock_versions(path, strict=True).items():
        if len(set(versions)) != 1:
            raise LockFormatError(
                f"{path.name} pins {name} at {versions}, a per-platform fork. The closure file "
                "records one version per name, so it cannot say which one a default install takes."
            )
        pins[name] = versions[0]
    return pins


def expected_closure_lines(core: dict[str, str]) -> list[str]:
    """The closure file's pin lines as the core lock says they must read: sorted ``name==version``."""
    return [f"{name}=={version}" for name, version in sorted(core.items())]


def closure_lines(text: str) -> list[str]:
    """The closure file's pin lines, stripped, in file order. Comments and blanks are skipped."""
    return [s for s in (raw.strip() for raw in text.splitlines()) if s and not s.startswith("#")]


def render_closure(current: str, core: dict[str, str]) -> str:
    """The closure file's text with its pin lines replaced by the core lock's.

    Keeps the leading comment block and drops everything after it, so a comment placed between
    pins is lost. The file's contract is header, then pins.
    """
    header: list[str] = []
    for raw in current.splitlines():
        if raw.strip() and not raw.lstrip().startswith("#"):
            break
        header.append(raw)
    return "\n".join([*header, *expected_closure_lines(core)]) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--closure", type=Path, default=CLOSURE, help="the file to rewrite")
    parser.add_argument("--core-lock", type=Path, default=CORE_LOCK, help="the lock to copy")
    args = parser.parse_args(argv)
    core = core_lock_pins(args.core_lock)
    closure: Path = args.closure
    current = closure.read_text(encoding="utf-8")
    new = render_closure(current, core)
    if new == current:
        print(f"{closure.name} already matches {args.core_lock.name} ({len(core)} pins)")
        return 0
    # Bytes, so a Windows run writes LF like the tracked file.
    closure.write_bytes(new.encode("utf-8"))
    print(f"wrote {len(core)} pins to {closure.name} from {args.core_lock.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
