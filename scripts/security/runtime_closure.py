#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rewrite the ``security/runtime-closure-*.txt`` files from their DEP-1 locks (BACKLOG #1812, #1955).

Each closure file is a denominator for ``docs/RISKY-COMPONENTS.md``. Its pin lines are a copy of one
exported lock, one ``name==version`` per package, sorted, with markers and hashes dropped:

* ``security/runtime-closure-core.txt`` copies ``docker/locks/requirements-core.lock``;
* ``security/runtime-closure-sqlserver.txt`` copies ``docker/locks/requirements-sqlserver.lock``.

``tests/test_risky_component_designation.py`` holds each copy to its lock, and uses this module to
do it, so the gate and the regenerator read a lock the same way.

STANDARD LIBRARY ONLY. ``.github/workflows/dependabot-lock-resync.yml`` runs this with the runner's
``python3`` right after it re-exports the locks, and that job installs nothing on purpose (read
its SECURITY MODEL block). A third-party import here would fail there and leave every Dependabot PR
red. ``tests/test_dep1_lock_resync_lockstep.py`` checks the imports. That check runs on this
project's newer Python, so it misses at least a module or API newer than the runner's python3.

Run from anywhere; paths resolve from this file. With no arguments it rewrites every pair; the
resync workflow relies on that. ``--closure`` and ``--lock`` together rewrite one other pair:

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
SQLSERVER_CLOSURE = ROOT / "security" / "runtime-closure-sqlserver.txt"
SQLSERVER_LOCK = ROOT / "docker" / "locks" / "requirements-sqlserver.lock"

#: Each closure file and the lock it copies. A run with no arguments rewrites all of them, which is
#: what the Dependabot lock-resync workflow relies on.
PAIRS: tuple[tuple[Path, Path], ...] = (
    (CLOSURE, CORE_LOCK),
    (SQLSERVER_CLOSURE, SQLSERVER_LOCK),
)

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


def lock_pins(path: Path = CORE_LOCK) -> dict[str, str]:
    """Name to version for one closure, read from its DEP-1 lock. A per-platform fork raises."""
    pins: dict[str, str] = {}
    for name, versions in lock_versions(path, strict=True).items():
        if len(set(versions)) != 1:
            raise LockFormatError(
                f"{path.name} pins {name} at {versions}, a per-platform fork. The closure file "
                "records one version per name, so it cannot say which one a default install takes."
            )
        pins[name] = versions[0]
    return pins


def expected_closure_lines(pins: dict[str, str]) -> list[str]:
    """A closure file's pin lines as its lock says they must read: sorted ``name==version``."""
    return [f"{name}=={version}" for name, version in sorted(pins.items())]


def closure_lines(text: str) -> list[str]:
    """The closure file's pin lines, stripped, in file order. Comments and blanks are skipped."""
    return [s for s in (raw.strip() for raw in text.splitlines()) if s and not s.startswith("#")]


def render_closure(current: str, pins: dict[str, str]) -> str:
    """A closure file's text with its pin lines replaced by its lock's.

    Keeps the leading comment block and drops everything after it, so a comment placed between
    pins is lost. The file's contract is header, then pins.
    """
    header: list[str] = []
    for raw in current.splitlines():
        if raw.strip() and not raw.lstrip().startswith("#"):
            break
        header.append(raw)
    return "\n".join([*header, *expected_closure_lines(pins)]) + "\n"


def selected_pairs(closure: Path | None, lock: Path | None) -> tuple[tuple[Path, Path], ...]:
    """The pairs one run rewrites: every pair with no arguments, else the one pair named.

    One pair needs both sides named. Defaulting the unnamed side would pair a file with the wrong
    lock: ``--lock`` naming the sqlserver lock alone would write its pins into the core file.
    """
    if closure is None and lock is None:
        return PAIRS
    if closure is None or lock is None:
        raise ValueError("--closure and --lock go together; name both, or neither for every pair")
    return ((closure, lock),)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--closure", type=Path, default=None, help="rewrite only this file")
    parser.add_argument("--lock", type=Path, default=None, help="copy only this lock")
    args = parser.parse_args(argv)
    try:
        pairs = selected_pairs(args.closure, args.lock)
    except ValueError as exc:
        parser.error(str(exc))
    # Every lock and every closure is read before anything is written, so a fork in one lock, or a
    # missing closure file, leaves every file as it was rather than rewriting some of them.
    planned = [(c, lk, lock_pins(lk), c.read_text(encoding="utf-8")) for c, lk in pairs]
    for closure, lock, pins, current in planned:
        new = render_closure(current, pins)
        if new == current:
            print(f"{closure.name} already matches {lock.name} ({len(pins)} pins)")
            continue
        # Bytes, so a Windows run writes LF like the tracked file.
        closure.write_bytes(new.encode("utf-8"))
        print(f"wrote {len(pins)} pins to {closure.name} from {lock.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
