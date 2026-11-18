# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The scorecard writer must never splice away an untouched cell (BACKLOG #5455).

`block_spans` found a cell's header with an exact-line pattern, so a `[[cell]]` header carrying
trailing whitespace, or in another spelling TOML accepts, was not seen as a header at all.
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
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "asvs"))

from scripts.asvs import apply as apply_mod  # noqa: E402
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

#: Header spellings TOML accepts that the exact-line pattern did not, and the span reader now does.
_PADDED_HEADERS = [
    pytest.param("[[cell]]  \n", id="trailing-spaces"),
    pytest.param("[[cell]]\t\n", id="trailing-tab"),
    pytest.param("[[cell]]  # a note on the header\n", id="trailing-comment"),
]

#: Header spellings TOML accepts that the span reader still does not take. It matches an
#: unindented `[[cell]]` only, because anything looser also matches inside a multi-line string, so
#: these must be REFUSED rather than read.
_UNREAD_HEADERS = [
    pytest.param('[["cell"]]\n', id="quoted"),
    pytest.param("[[ cell ]]\n", id="inner-spaces"),
    pytest.param("  [[cell]]\n", id="indented"),
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


@pytest.mark.parametrize("header", _UNREAD_HEADERS)
def test_a_header_the_span_reader_cannot_see_refuses_the_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], header: str
) -> None:
    """THE BACKSTOP, independent of how far the header pattern reaches.

    Some spelling will always be out of the span reader's reach, so the writer must notice that the
    record TOML parses holds a cell its spans do not, and refuse before it splices, rather than
    trust a count taken from the spans themselves.
    """
    rec = _record(tmp_path, header)
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"])
    assert rc == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "REFUSING" in out
    assert "99.1.2" in out


def test_an_id_line_with_a_trailing_comment_is_still_read(tmp_path: Path) -> None:
    """The id pattern was exact-line too: a padded id stopped every write to the record."""
    body = _SECOND_BODY.replace('id = "99.1.2"\n', "id = '99.1.2'   # a note on the id\n")
    assert body != _SECOND_BODY
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 0
    cells = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert cells["99.1.2"]["residual"] == "second synthetic cell, never in the payload"


def test_a_table_inside_a_rewritten_span_refuses_the_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A non-cell table after the last cell sits inside that cell's span. Rewriting the cell
    deleted the table, and a check that compared only cells could not see it."""
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + '[extra]\nnote = "kept"\n', encoding="utf-8")
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"])
    assert rc == 1
    assert rec.read_bytes() == before
    assert "top-level key extra" in capsys.readouterr().out


def test_header_and_id_lines_inside_a_string_are_prose(tmp_path: Path) -> None:
    """A padded header and an id line quoted in a multi-line string are not structure. Taken as a
    header, the bogus block made every write to the record refuse."""
    body = _SECOND_BODY.replace(
        'residual = "second synthetic cell, never in the payload"\n',
        'residual = """quoted prose\n[[cell]]  \nid = "99.1.9"\nmore prose"""\n',
    )
    assert body != _SECOND_BODY
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 0
    cells = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert set(cells) == {"99.1.1", "99.1.2"}
    assert cells["99.1.2"]["residual"].startswith("quoted prose\n[[cell]]")


def test_an_indented_id_line_is_read(tmp_path: Path) -> None:
    body = _SECOND_BODY.replace('id = "99.1.2"\n', '  id = "99.1.2"\n')
    assert body != _SECOND_BODY
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 0
    cells = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert cells["99.1.2"]["residual"] == "second synthetic cell, never in the payload"


def test_an_id_the_span_reader_cannot_read_is_a_refusal_not_a_crash(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An escaped id is valid TOML the id pattern does not take. `main` refuses with rc 1."""
    body = _SECOND_BODY.replace('id = "99.1.2"\n', 'id = "99.1\\u002e2"\n')
    assert body != _SECOND_BODY
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    before = rec.read_bytes()
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    assert "has no id" in capsys.readouterr().out


def _span_to_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the first cell's span run to the end of the file while every id stays found: wrong
    boundaries that the pre-splice id check cannot see, so only the post-splice check can."""
    real = apply_mod.block_spans

    def wide(text: str) -> dict[str, tuple[int, int]]:
        spans = real(text)
        spans["99.1.1"] = (spans["99.1.1"][0], len(text))
        return spans

    monkeypatch.setattr(apply_mod, "block_spans", wide)


def test_the_post_splice_check_names_a_lost_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rec = _record(tmp_path, "[[cell]]\n")
    before = rec.read_bytes()
    _span_to_eof(monkeypatch)
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "the cell list" in out
    assert "99.1.2" in out


def test_the_post_splice_check_names_an_altered_untouched_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The cell list survives, so only the comparison of each untouched cell can see the change."""
    rec = _record(tmp_path, "[[cell]]\n")
    before = rec.read_bytes()
    _span_to_eof(monkeypatch)
    real_render = apply_mod.render
    altered = "[[cell]]\n" + _SECOND_BODY.replace("never in the payload", "altered")

    def render_and_alter(cell: dict[str, Any], live: dict[str, Any]) -> str:
        return real_render(cell, live) + altered

    monkeypatch.setattr(apply_mod, "render", render_and_alter)
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "untouched cell 99.1.2" in out
    assert "the cell list" not in out


def test_mixed_id_types_refuse_cleanly_not_with_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A TOML integer id beside a string id, both unseen by the span reader. Sorting the unseen
    ids without a key raised TypeError, a traceback where a refusal belongs."""
    int_cell = "  [[cell]]\n" + _SECOND_BODY.replace('id = "99.1.2"\n', "id = 7\n")
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + int_cell + "  [[cell]]\n" + _SECOND_BODY, encoding="utf-8")
    # The fixture must hold both id types, or the test proves nothing.
    ids = [c["id"] for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]]
    assert ids == ["99.1.1", 7, "99.1.2"]
    before = rec.read_bytes()
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "REFUSING" in out
    assert "99.1.2" in out


def test_the_unseen_header_hint_does_not_ask_for_an_unindented_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The span reader takes an indented id line, so a hint asking for an unindented one is false."""
    rec = _record(tmp_path, "  [[cell]]\n")
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    out = capsys.readouterr().out
    assert "unindented [[cell]]" in out
    assert "unindented id" not in out


def test_a_repeated_id_refuses_with_a_hint_about_the_repeat(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two blocks carrying one id is not an id-spelling problem, so the spelling hint was wrong."""
    # The same verdict as the payload, so no verdict guard refuses first.
    body = _SECOND_BODY.replace('id = "99.1.2"\n', 'id = "99.1.1"\n').replace(
        'verdict = "pass"', 'verdict = "partial"'
    )
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    before = rec.read_bytes()
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "two [[cell]] blocks carry id" in out
    assert "no escapes" not in out
    assert "distinct id" in out


def test_an_entry_id_does_not_stand_in_for_an_unreadable_cell_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The id search ran into the cell's evidence entries, so an entry's `id` keyed a cell whose
    own id was unreadable, and the refusal named a repeated id rather than the unreadable one."""
    body = _SECOND_BODY.replace('id = "99.1.2"\n', 'id = "99.1\\u002e2"\n').replace(
        '  path = "messagefoundry/m.py"\n  line = 20\n',
        '  id = "99.1.1"\n  path = "messagefoundry/m.py"\n  line = 20\n',
    )
    assert body.count("99.1.1") == 1
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    before = rec.read_bytes()
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "has no id" in out
    assert "two [[cell]] blocks" not in out


def test_a_write_that_a_later_run_could_not_read_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A literal-string id is read, but `render` writes it back escaped, which the span reader does
    not read. TOML reads the same id either way, so every other check passed, and the next run
    refused every write to the record."""
    lit_id = "99.1\\1"
    first = _FIRST.replace('id = "99.1.1"\n', f"id = '{lit_id}'\n")
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + first + "[[cell]]\n" + _SECOND_BODY, encoding="utf-8")
    assert tomllib.loads(rec.read_text(encoding="utf-8"))["cell"][0]["id"] == lit_id
    payload = _payload(tmp_path)
    cells = json.loads(payload.read_text(encoding="utf-8"))
    cells[0]["id"] = lit_id
    payload.write_text(json.dumps(cells), encoding="utf-8")
    before = rec.read_bytes()
    assert main([str(payload), "--scorecard", str(rec), "--apply"]) == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "a later run reads" in out
    assert "has no id" in out


def test_an_array_of_arrays_does_not_end_the_id_search(tmp_path: Path) -> None:
    """An element line of a multi-line array of arrays opens with `[` like a table header does.
    Taken as one, it ended the id search above an id written below it, and every write refused."""
    body = _SECOND_BODY.replace('id = "99.1.2"\n', "matrix = [\n  [1, 2],\n]\n").replace(
        "level = 1\n", 'level = 1\nid = "99.1.2"\n'
    )
    assert body.index("matrix") < body.index('id = "99.1.2"')
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(_HEAD + _FIRST + "[[cell]]\n" + body, encoding="utf-8")
    assert main([str(_payload(tmp_path)), "--scorecard", str(rec), "--apply"]) == 0
    cells = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert cells["99.1.2"]["matrix"] == [[1, 2]]
