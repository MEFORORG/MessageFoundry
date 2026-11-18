# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The scorecard writer must never splice away an untouched cell (BACKLOG #5455).

`block_spans` found a cell's header with an exact-line pattern, so a `[[cell]]` header carrying
trailing whitespace, or spelled with TOML's permitted inner spaces, was not seen as a header at all.
The cell before it then owned the whole of that cell's text, and rewriting it replaced both. The
post-splice count check compared the parsed result against the SPAN count, which had already lost
the cell, so it agreed with the loss and the write went through.

The ids below are synthetic: no requirement set has a chapter 99.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "asvs"))

from scripts.asvs.apply import block_spans, main  # noqa: E402

_HEAD = """[scorecard]
asvs_version = "5.0.0"

"""

_FIRST = """[[cell]]
id = "99.1.1"
level = 1
verdict = "partial"
residual = "first synthetic cell"
last_verified = "2026-08-09"
verified_at = "1111111111111111111111111111111111111111"
reviewed_by = { reviewer = "fixture", ref = "unrecorded", date = "unrecorded" }
  [[cell.evidence]]
  path = "messagefoundry/m.py"
  line = 10
  expect = "alpha"
"""

_SECOND_BODY = """id = "99.1.2"
level = 1
verdict = "pass"
residual = "second synthetic cell, never in the payload"
last_verified = "2026-08-09"
verified_at = "2222222222222222222222222222222222222222"
reviewed_by = { reviewer = "fixture", ref = "unrecorded", date = "unrecorded" }
  [[cell.evidence]]
  path = "messagefoundry/m.py"
  line = 20
  expect = "beta"
"""

#: Header spellings TOML accepts that the exact-line pattern did not.
_PADDED_HEADERS = [
    pytest.param("[[cell]]  \n", id="trailing-spaces"),
    pytest.param("[[cell]]\t\n", id="trailing-tab"),
    pytest.param("[[ cell ]]\n", id="inner-spaces"),
    pytest.param("  [[cell]]\n", id="indented"),
    pytest.param("[[cell]]  # a note on the header\n", id="trailing-comment"),
]


def _payload(tmp_path: Path) -> Path:
    cell = {
        "id": "99.1.1",
        "level": 1,
        "verdict": "partial",
        "residual": "first synthetic cell, rewritten",
        "last_verified": "2026-08-10",
        "verified_at": "3333333333333333333333333333333333333333",
        "reviewed_by": {"reviewer": "test", "ref": "unrecorded", "date": "unrecorded"},
        "evidence": [{"path": "messagefoundry/m.py", "line": 11, "expect": "alpha"}],
    }
    p = tmp_path / "payload.json"
    p.write_text(json.dumps([cell]), encoding="utf-8")
    return p


def _record(tmp_path: Path, header: str) -> Path:
    p = tmp_path / "asvs-scorecard.toml"
    p.write_text(_HEAD + _FIRST + header + _SECOND_BODY, encoding="utf-8")
    # The fixture must be a record TOML itself reads as two cells, or the test proves nothing.
    assert len(tomllib.loads(p.read_text(encoding="utf-8"))["cell"]) == 2
    return p


@pytest.mark.parametrize("header", _PADDED_HEADERS)
def test_a_padded_header_still_starts_its_own_span(header: str) -> None:
    spans = block_spans(_HEAD + _FIRST + header + _SECOND_BODY)
    assert set(spans) == {"99.1.1", "99.1.2"}


@pytest.mark.parametrize("header", _PADDED_HEADERS)
def test_rewriting_the_cell_before_a_padded_header_keeps_the_next_cell(
    tmp_path: Path, header: str
) -> None:
    rec = _record(tmp_path, header)
    rc = main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"])
    cells = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    # Whatever the writer decided, the untouched cell is still in the record.
    assert "99.1.2" in cells
    assert cells["99.1.2"]["residual"] == "second synthetic cell, never in the payload"
    assert rc == 0
    assert cells["99.1.1"]["residual"] == "first synthetic cell, rewritten"


def test_a_header_the_span_reader_cannot_see_refuses_the_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE BACKSTOP, independent of how far the header pattern reaches.

    TOML also accepts a quoted table name, so `[["cell"]]` opens a cell too. The span reader does
    not take that spelling, and some other spelling will always be out of its reach, so the writer
    must notice that the record TOML parses holds a cell its spans do not, and refuse before it
    splices, rather than trust a count taken from the spans themselves.
    """
    rec = _record(tmp_path, '[["cell"]]\n')
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"])
    assert rc == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "REFUSING" in out
    assert "99.1.2" in out
