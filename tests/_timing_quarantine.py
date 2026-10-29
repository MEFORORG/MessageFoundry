# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one Python reader of ``tests/timing_quarantine.txt`` (ci.yml's job also reads it in shell).

``tests/conftest.py`` applies the ``timing_quarantine`` marker from it, and
``tests/test_timing_quarantine.py`` pins it against the tree and against ci.yml. Both import this
module, so the hook that moves tests off the engine legs and the check that pins the list cannot
read the file differently.

Each entry line is a node id, whitespace, and a one-line reason that names its row as ``#<n>``.
A node id is ``tests/<file>.py::<function>``, or ``::<Class>::<method>``, with no parameter
suffix: a parametrized test is quarantined whole.

A MISSING OR MALFORMED FILE RAISES, for the reason the tooling partition block in
tests/conftest.py gives: a reader that quietly marks nothing keeps the engine legs' selection
looking right while the quarantine job selects zero tests.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

QUARANTINE = Path(__file__).resolve().parent / "timing_quarantine.txt"

_LINE = re.compile(
    r"(?P<node>tests/test_[A-Za-z0-9_]+\.py(?:::[A-Za-z_][A-Za-z0-9_]*)+)\s+(?P<reason>\S.*)"
)
_ROW = re.compile(r"#\d+\b")


@dataclass(frozen=True)
class Entry:
    """One quarantined test."""

    node_id: str
    reason: str
    line: int

    @property
    def path(self) -> str:
        """The test file, as ``tests/<name>.py``."""
        return self.node_id.split("::", 1)[0]

    @property
    def qualname(self) -> tuple[str, ...]:
        """The parts after the file: ``(function,)`` or ``(Class, method)``."""
        return tuple(self.node_id.split("::")[1:])


def entries_from(text: str) -> list[Entry]:
    """The entries in ``text``, in order, with blanks and ``#`` comments dropped.

    Raises ``ValueError`` on a line that is not a node id plus a reason, on a reason that names no
    ``#<n>`` row, and on a node id listed twice.
    """
    kept: list[Entry] = []
    seen: set[str] = set()
    for number, physical in enumerate(text.split("\n"), start=1):
        # A byte-order mark an editor put in front of the first line is not part of it.
        line = physical.removeprefix("\ufeff") if number == 1 else physical
        line = line.removesuffix("\r").strip()
        if not line or line.startswith("#"):
            continue
        found = _LINE.fullmatch(line)
        if not found:
            raise ValueError(
                f"{QUARANTINE.name} line {number} is {line!r}: an entry is "
                "`tests/test_<name>.py::<test> <reason naming #<row>>`"
            )
        node, reason = found.group("node"), found.group("reason")
        if not _ROW.search(reason):
            raise ValueError(
                f"{QUARANTINE.name} line {number}: the reason for {node} names no #<row>, so "
                "nothing says which row owns fixing its timing dependence"
            )
        if node in seen:
            raise ValueError(f"{QUARANTINE.name} line {number}: {node} is listed twice")
        seen.add(node)
        kept.append(Entry(node, reason, number))
    return kept


def entries() -> list[Entry]:
    """``entries_from`` over the real file."""
    return entries_from(QUARANTINE.read_text(encoding="utf-8", newline=""))


def node_ids() -> frozenset[str]:
    """The quarantined node ids, as :func:`mark_quarantined` keys on them."""
    return frozenset(entry.node_id for entry in entries())


def key_of(path: Path, nodeid: str) -> str:
    """``tests/<file>.py::<test>`` for an item, parameter suffix dropped.

    Built from the file name rather than taken from ``nodeid`` whole, so the key does not depend on
    the rootdir pytest chose.
    """
    _, _, inner = nodeid.partition("::")
    return f"tests/{path.name}::{inner.partition('[')[0]}"


def mark_quarantined(items: Iterable[Any], tests_dir: Path) -> None:
    """Add the ``timing_quarantine`` marker to every listed item in ``tests_dir`` itself.

    Called from ``pytest_collection_modifyitems`` in tests/conftest.py. It lives here, not there,
    because tests/conftest.py must not be imported a second time (see
    tests/test_conftest_name_collision_guard.py), and the test of this hook needs to drive it.
    Scoped to files directly in ``tests_dir``, as the tooling partition is.
    """
    quarantined = (
        node_ids()
    )  # raises if the list is absent or malformed -- see the module docstring
    for item in items:
        path = getattr(item, "path", None)
        if (
            path is not None
            and path.parent == tests_dir
            and key_of(path, item.nodeid) in quarantined
        ):
            item.add_marker(pytest.mark.timing_quarantine)
