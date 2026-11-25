# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""owner_log.py creates its ledger without truncating (BACKLOG #7584) and never reads an
unparseable timestamp as fresh (BACKLOG #7585).

ensure() checked for the file and then opened it for write, so a second writer that lost the race
truncated the rows the first had just appended. age_minutes() returned -1.0 for a timestamp it
could not parse, and check compared that against the stale threshold, so a hand-appended row with
an odd timestamp read as younger than any threshold and its item was never flagged.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import os
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import IO, Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "owner_log.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_owner_log_create_age", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ol = _load()


def _rec(item: str, event: str, ts: str) -> dict[str, str]:
    return {
        "ts": ts,
        "item": item,
        "event": event,
        "actor": "manager",
        "counterparty": "owner",
        "summary": f"summary {item}",
        "ruling": "-",
        "blocks": "nothing",
        "target": "-",
    }


def test_ensure_never_truncates_a_ledger_that_appeared_after_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lost race, made deterministic: the existence probe says absent, but another writer has
    already created the file and appended a row. ensure() must leave that row in place."""
    ledger = tmp_path / "OWNER-ITEMS.md"
    ol.append(str(ledger), _rec("1", "request_sent", "2026-11-24T10:00:00Z"))
    before = ledger.read_bytes()
    monkeypatch.setattr(ol.os.path, "isfile", lambda _p: False)
    ol.ensure(str(ledger))
    monkeypatch.undo()
    assert ledger.read_bytes() == before


def test_a_row_appended_between_create_and_header_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second race window, made deterministic: another writer appends its row after ensure()
    has created the file but before the header is written. The header must not overwrite it."""
    ledger = tmp_path / "OWNER-ITEMS.md"
    real_fdopen = os.fdopen

    def fdopen_then_race(fd: int, mode: str) -> IO[Any]:
        fh = real_fdopen(fd, mode)
        with open(ledger, "ab") as other:
            other.write(b"| 2026-11-24T10:00:00Z | race | request_sent | b | - | s | - | - | - |\n")
        return fh

    monkeypatch.setattr(ol.os, "fdopen", fdopen_then_race)
    ol.ensure(str(ledger))
    monkeypatch.undo()
    assert [r["item"] for r in ol.read(str(ledger))] == ["race"]
    assert "\n".join(ol.HEADER) in ledger.read_text(encoding="utf-8")


def test_ensure_writes_the_header_once_on_a_new_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "sub" / "OWNER-ITEMS.md"
    ol.ensure(str(ledger))
    ol.ensure(str(ledger))
    assert ledger.read_text(encoding="utf-8") == "\n".join(ol.HEADER) + "\n"


def test_age_minutes_reads_a_good_stamp_and_refuses_a_bad_one() -> None:
    good = ol.age_minutes("2000-01-01T00:00:00Z")
    assert good is not None and good > 0
    assert ol.age_minutes("2026-11-24 10:00") is None
    assert ol.age_minutes("") is None
    assert ol.age_minutes("2999-01-01T00:00:00Z") is None, "a far-future stamp is not fresh"


def _stamp(offset_minutes: float) -> str:
    t = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_the_future_skew_boundary() -> None:
    assert ol.age_minutes(_stamp(2)) == 0.0, "within skew reads as just written"
    assert ol.age_minutes(_stamp(10)) is None, "beyond skew cannot be read as fresh"


@pytest.fixture
def check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Callable[[Path], tuple[int, str]]:
    def run(ledger: Path) -> tuple[int, str]:
        monkeypatch.setenv("MEFOR_OWNER_LOG", str(ledger))
        rc = ol.cmd_check(argparse.Namespace(stale_minutes=45.0))
        return rc, capsys.readouterr().out

    return run


@pytest.mark.parametrize("event", ["request_sent", "request_received", "presented", "answer_sent"])
def test_an_unreadable_stamp_on_an_open_item_fails_the_check(
    tmp_path: Path, check: Callable[[Path], tuple[int, str]], event: str
) -> None:
    ledger = tmp_path / "OWNER-ITEMS.md"
    ol.append(str(ledger), _rec("hand", event, "yesterday afternoon"))
    rc, out = check(ledger)
    assert rc == 1, out
    assert "UNREADABLE" in out and "hand" in out
    assert "yesterday afternoon" in out


def test_a_readable_fresh_item_still_passes_the_check(
    tmp_path: Path, check: Callable[[Path], tuple[int, str]]
) -> None:
    """Control: the same ledger shape with a parseable, current stamp stays green."""
    ledger = tmp_path / "OWNER-ITEMS.md"
    ol.append(str(ledger), _rec("fresh", "request_sent", ol.now()))
    rc, out = check(ledger)
    assert rc == 0, out
    assert "UNREADABLE" not in out


def test_an_unreadable_stamp_on_a_closed_item_does_not_fail_the_check(
    tmp_path: Path, check: Callable[[Path], tuple[int, str]]
) -> None:
    """A closed item's age is never read, so its stamp cannot make it need attention."""
    ledger = tmp_path / "OWNER-ITEMS.md"
    ol.append(str(ledger), _rec("done", "request_sent", "odd stamp"))
    ol.append(str(ledger), _rec("done", "declined", "odd stamp"))
    rc, out = check(ledger)
    assert rc == 0, out
