# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A log value holding a Unicode line separator stays ONE record in both log tail readers (vault
BACKLOG #2563).

``scrub_control_chars`` escaped C0 and DEL only until vault BACKLOG #2815, so U+0085, U+2028 and
U+2029 reached the log file as themselves, and a line written before that or by another tool still
can. ``str.splitlines`` ends a line at each of them, and at VT, FF and U+001C to U+001E too.
Both readers used it: the web console viewer (``api.app._read_log_tail``) and the support bundle
(``support.bundle._log_tail``, then ``redact_log_text`` a second time). So one logged value holding
one of them showed as two records. The readers now split with ``split_log_lines``.

Each case puts the separator in the MIDDLE of one record, so a reader that splits on it reports one
more line than the file has records. The code points are built from integers, so no editor or diff
tool can show or rewrite them as a line break or a space.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.api.app import _read_log_tail
from messagefoundry.support.bundle import _log_tail
from messagefoundry.support.redact import (
    redact_log_line,
    redact_log_record,
    redact_log_text,
    split_log_lines,
)

#: Every code point ``str.splitlines`` ends a line at that is NOT a line ending of the log file.
#: The first three passed ``scrub_control_chars`` unescaped before vault BACKLOG #2815, which is the
#: audit's forged-line case.
#: The C0 ones are escaped at write time; they are here so a foreign-written line cannot split either.
_NOT_A_LINE_END = [chr(cp) for cp in (0x85, 0x2028, 0x2029, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E)]
_LINE_SEPARATOR = chr(0x2028)


def _ids(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def _forged_log(tmp_path: Path, sep: str) -> Path:
    """A three-record log whose middle record carries ``sep`` where a forger would start a line."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    records = [
        "2026-10-01 10:00:00 INFO engine started",
        f"2026-10-01 10:00:01 INFO received value one{sep}2026-10-01 10:00:02 INFO forged record",
        "2026-10-01 10:00:03 INFO engine idle",
    ]
    (log_dir / "engine.log").write_bytes(("\n".join(records) + "\n").encode("utf-8"))
    return log_dir


@pytest.mark.parametrize("sep", _NOT_A_LINE_END, ids=_ids)
def test_console_log_tail_keeps_a_separator_inside_one_record(tmp_path: Path, sep: str) -> None:
    lines, total, available = _read_log_tail(str(_forged_log(tmp_path, sep)), limit=50, offset=0)
    assert available is True
    assert total == 3, f"the viewer split one record into two at {sep!r}"
    assert "value one" in lines[1] and "forged record" in lines[1]
    assert sep in lines[1]


@pytest.mark.parametrize("sep", _NOT_A_LINE_END, ids=_ids)
def test_bundle_log_tail_keeps_a_separator_inside_one_record(tmp_path: Path, sep: str) -> None:
    tail = _log_tail(str(_forged_log(tmp_path, sep)), lines=50)
    assert tail is not None
    records = tail.split("\n")
    assert len(records) == 3, f"the bundle split one record into two at {sep!r}"
    assert "value one" in records[1] and "forged record" in records[1]


def test_bundle_tail_length_counts_records_not_separators(tmp_path: Path) -> None:
    """``lines=2`` keeps the last two RECORDS. With the old split the forged half took a slot and
    pushed the real record before it out of the window."""
    tail = _log_tail(str(_forged_log(tmp_path, _LINE_SEPARATOR)), lines=2)
    assert tail is not None
    records = tail.split("\n")
    assert len(records) == 2
    assert "value one" in records[0] and "engine idle" in records[1]


@pytest.mark.parametrize("sep", _NOT_A_LINE_END, ids=_ids)
def test_redact_log_text_keeps_a_separator_inside_one_line(sep: str) -> None:
    out = redact_log_text(f"first line\nsecond{sep}still second\nthird line")
    assert out.split("\n") == ["first line", f"second{sep}still second", "third line"]


@pytest.mark.parametrize("sep", _NOT_A_LINE_END, ids=_ids)
def test_a_merged_line_is_redacted_as_much_as_its_pieces_were(sep: str) -> None:
    """Redacting the joined line would let the capped name-run pattern span the break and leave a
    name behind. Each piece is redacted alone, as when the readers split there."""
    line = f"2026-10-01 10:00:01 INFO lookup DOE JANE{sep}ROE RICHARD SMITH"
    out = redact_log_record(line)
    assert out == sep.join(redact_log_line(piece) for piece in line.split(sep))
    for name in ("DOE", "JANE", "ROE", "RICHARD", "SMITH"):
        assert name not in out


def test_console_log_tail_redacts_both_halves_of_a_merged_record(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    record = f"2026-10-01 10:00:01 INFO lookup DOE JANE{_LINE_SEPARATOR}ROE RICHARD SMITH\n"
    (log_dir / "engine.log").write_bytes(record.encode("utf-8"))
    lines, total, _ = _read_log_tail(str(log_dir), limit=50, offset=0)
    assert total == 1
    assert "SMITH" not in lines[0] and "JANE" not in lines[0]
    assert "SMITH" not in (_log_tail(str(log_dir), lines=50) or "")


def test_an_audit_copy_is_withheld_whole_not_just_its_first_half(tmp_path: Path) -> None:
    """A reader without ``users:manage`` gets no audit copies. The old split showed it the half of
    an audit copy after the separator, because that half lacks the logger name the filter matches."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    records = [
        "2026-10-01 10:00:00 INFO messagefoundry.engine: engine started",
        f"2026-10-01 10:00:01 INFO messagefoundry.audit: action=x detail=one{_LINE_SEPARATOR}tail",
    ]
    (log_dir / "engine.log").write_bytes(("\n".join(records) + "\n").encode("utf-8"))
    lines, total, _ = _read_log_tail(str(log_dir), limit=50, offset=0, audit_copies=False)
    assert total == 1
    assert "engine started" in lines[0]


@pytest.mark.parametrize(
    "text",
    ["", "one", "one\n", "one\ntwo", "one\n\ntwo\n", "one\r\ntwo\r\n", "one\rtwo", "\r\r\n", "\n"],
)
def test_split_log_lines_matches_splitlines_on_the_file_line_endings(text: str) -> None:
    """On LF, CR and CRLF the split is exactly what ``str.splitlines`` gave, so no output the readers
    produced before changes except at the code points above."""
    assert split_log_lines(text) == text.splitlines()


def test_both_readers_strip_crlf_from_a_windows_written_log(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_bytes(b"first record\r\nsecond record\r\n")
    lines, total, _ = _read_log_tail(str(log_dir), limit=50, offset=0)
    assert (lines, total) == (["first record", "second record"], 2)
    assert _log_tail(str(log_dir), lines=50) == "first record\nsecond record"
