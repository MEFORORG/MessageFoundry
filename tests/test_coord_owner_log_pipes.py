# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""owner_log.py's reader must undo exactly the escape its writer applies (BACKLOG #5488).

cell() writes a pipe inside a cell as backslash-pipe. read() used to split every row on every pipe,
so a row whose summary or ruling held a pipe came back one cell too wide and was dropped: the item
then read as never logged, or its ruling as never delivered. These round-trip writer to reader, and
the control row with no pipe proves the reader is not simply dropping everything.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "owner_log.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_owner_log_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ol = _load()


def _rec(item: str, summary: str, ruling: str = "-") -> dict[str, str]:
    return {
        "ts": "2026-11-18T12:00:00Z",
        "item": item,
        "event": "answer_sent",
        "actor": "manager",
        "counterparty": "owner",
        "summary": summary,
        "ruling": ruling,
        "blocks": "nothing",
        "target": "-",
    }


@pytest.mark.parametrize(
    ("summary", "ruling"),
    [
        pytest.param("no pipes at all", "keep it", id="control-no-pipe"),
        pytest.param("choose a | b", "a", id="one-pipe"),
        pytest.param("|leading and trailing|", "x || y", id="edge-and-double-pipes"),
        pytest.param(r"a literal \| backslash-pipe", r"ends in a backslash \\", id="backslashes"),
        pytest.param("\\", r"\\|\\", id="backslash-only-and-mixed"),
    ],
)
def test_a_written_row_reads_back_identically(tmp_path: Path, summary: str, ruling: str) -> None:
    ledger = str(tmp_path / "OWNER-ITEMS.md")
    ol.append(ledger, _rec("5488", summary, ruling))
    rows = ol.read(ledger)
    assert len(rows) == 1, f"the row was dropped: {Path(ledger).read_text(encoding='utf-8')}"
    assert rows[0]["summary"] == summary
    assert rows[0]["ruling"] == ruling
    assert rows[0]["blocks"] == "nothing"
    assert rows[0]["target"] == "-"


def test_a_piped_row_does_not_hide_its_neighbours(tmp_path: Path) -> None:
    ledger = str(tmp_path / "OWNER-ITEMS.md")
    ol.append(ledger, _rec("1", "before"))
    ol.append(ledger, _rec("2", "a | b | c"))
    ol.append(ledger, _rec("3", "after"))
    assert [r["item"] for r in ol.read(ledger)] == ["1", "2", "3"]


def test_a_legacy_width_row_with_an_escaped_pipe_still_pads(tmp_path: Path) -> None:
    ledger = tmp_path / "OWNER-ITEMS.md"
    ol.ensure(str(ledger))
    legacy = ol.LEGACY_COLUMNS
    values = {c: ol.cell(_rec("9", "old | row")[c]) for c in legacy}
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write("| " + " | ".join(values[c] for c in legacy) + " |\n")
    rows = ol.read(str(ledger))
    assert len(rows) == 1
    assert rows[0]["summary"] == "old | row"
    assert rows[0]["target"] == "-"


def test_a_hand_written_row_without_a_closing_pipe_reads(tmp_path: Path) -> None:
    ledger = tmp_path / "OWNER-ITEMS.md"
    ol.ensure(str(ledger))
    row = "| " + " | ".join(ol.cell(_rec("8", "a | b")[c]) for c in ol.COLUMNS)
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(row + "\n")  # no closing separator
    rows = ol.read(str(ledger))
    assert len(rows) == 1
    assert rows[0]["summary"] == "a | b"
    assert rows[0]["target"] == "-"
