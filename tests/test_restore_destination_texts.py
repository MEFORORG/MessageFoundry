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

import pytest

from messagefoundry.__main__ import _build_parser
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import _OVERWRITE_REFUSAL

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
    for unsafe in ("clear the destination's sidecars", "clear any `-wal`"):
        assert unsafe not in body, unsafe


def test_the_to_help_says_what_is_refused_and_gives_the_safe_remedy() -> None:
    text = _to_help()
    for needle in (
        "(a file, a directory or a link, a dangling one included), is refused",
        "the store and sidecar names are read again just before the write",
        "Not caught, at least: a sidecar created after that re-read",
        "Nor, at least on Windows, a taken -wal, -shm or -journal name, or a dangling link at the "
        "store name when the store is copied into place, on a share or drive that neither read could "
        "reach",
        "an unreachable share, which reads as free (at least WinError 53 and 67), or a drive letter "
        "that is gone (at least WinError 3 and 15)",
        "a dangling link planted at the store name after that re-read, which is followed",
        "a name holding ':', and on Windows a name ending in a dot or a space",
        "stop the engine and move the old store aside with its -wal, -shm and -journal as one set",
    ):
        assert needle in text, needle


def test_the_overwrite_refusal_gives_the_safe_remedy() -> None:
    # The refusal an operator actually reads names the taken path, which may be a sidecar alone.
    assert (
        "stop the engine and move the existing store aside with its -wal, -shm and -journal as one set"
        in _flat(_OVERWRITE_REFUSAL)
    )


@pytest.mark.parametrize(
    ("name", "own", "foreign"),
    [
        ("store.db::$DATA", "its file name holds a ':'", ("dot or a space", "device", "ends in")),
        ("store.db.", "its file name ends in a dot,", ("':'", "device")),
        ("store.db ", "its file name ends in a space,", ("':'", "device")),
        ("NUL", "would not open that name as a file of its own", ("':'", "ends in a")),
        ("..", "would not open that name as a file of its own", ("':'", "ends in a")),
    ],
)
def test_each_to_refusal_names_only_its_own_trigger(
    name: str, own: str, foreign: tuple[str, ...]
) -> None:
    # One text per trigger, chosen by name alone, so this runs on every host. The ':' text, the one
    # that fires on POSIX too, names only the ':' and scopes its sidecar reason to Windows and NTFS.
    text = dr_backup._rewritten_to_refusal(Path("dr") / name)
    assert own in text, text
    for other in foreign:
        assert other not in text, (other, text)


def test_the_colon_refusal_gives_its_cross_host_reason() -> None:
    text = _flat(dr_backup._COLON_TO_REFUSAL)
    assert "It is refused on every host, so one --to means the same everywhere" in text
    assert "on Windows, and on some NTFS volumes reached from other systems, a ':' names" in text


def test_the_fault_refusals_give_their_own_remedies() -> None:
    assert "check that this account can read its directory" in dr_backup._FAULT_REFUSAL
    invalid = _flat(dr_backup._INVALID_NAME_REFUSAL)
    assert "Windows refuses the path as invalid" in invalid
    assert "in its file name or in one of its directories; choose another --to path" in invalid
    assert "check that this account" not in invalid
