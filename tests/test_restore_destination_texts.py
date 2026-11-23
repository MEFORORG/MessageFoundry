# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The restore's never-overwrite texts say what the check refuses and give a safe remedy.

The early-adopter guide's *Restore an archive* paragraph and the ``restore --to`` help said a
leftover sidecar was refused with no limit, while a dangling sidecar link, a ``--to`` ending in a dot
or a space on Windows, and a ``--to`` holding ``:`` all passed. An earlier fix named two of those
limits and told the operator to clear the destination's sidecars by hand, which would delete the old
store's un-checkpointed WAL or hot journal. The check now refuses those cases
(``tests/test_cli_restore_dispatch.py`` pins each), and these tests pin the texts to match: what is
refused, what is not caught, and a remedy that moves the old store with its sidecars as one set.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from messagefoundry.__main__ import _build_parser

_GUIDE = Path(__file__).resolve().parents[1] / "docs" / "EARLY-ADOPTER-GUIDE.md"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _restore_paragraph() -> str:
    text = _GUIDE.read_text(encoding="utf-8")
    start = text.index("**Restore an archive.**")
    return _flat(text[start : text.index("\n\n", start)])


def _to_help() -> str:
    parser, _dispatch = _build_parser()
    subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    restore = subparsers.choices["restore"]
    action = next(a for a in restore._actions if "--to" in a.option_strings)
    return _flat(action.help or "")


def test_the_guide_says_what_is_refused_and_gives_the_safe_remedy() -> None:
    body = _restore_paragraph()
    for needle in (
        "already taken by a file, a directory or a link, a dangling link included",
        "reads those three sidecar names again just before it writes the store",
        "SQLite replays it over the verified pages on first open",
        "A sidecar created after that last read is not caught",
        "refuses at least a `--to` whose file name holds a `:`, and on Windows one ending in a dot or a space",
        "stop the engine, then move the old store aside together with its `-wal`, `-shm` and "
        "`-journal`, as one set",
    ):
        assert needle in body, needle
    for unsafe in ("clear the destination's sidecars", "by hand", "delete"):
        assert unsafe not in body, unsafe


def test_the_to_help_says_what_is_refused_and_gives_the_safe_remedy() -> None:
    text = _to_help()
    for needle in (
        "(a file, a directory or a link, a dangling one included), is refused",
        "the sidecar names are read again just before the write",
        "a name holding ':', and on Windows a name ending in a dot or a space",
        "stop the engine and move the old store aside with its -wal, -shm and -journal as one set",
    ):
        assert needle in text, needle
