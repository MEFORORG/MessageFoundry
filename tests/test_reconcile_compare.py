# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-connection reconcile orchestration: key extraction, message loading, pairing + diff, reporting.

Pure + offline (no DB, no sockets). Covers: field_value on a message's own separators; load_messages from
a JSONL capture, a batch file, and a directory; reconcile pairing (identical, real mismatch normalized
against engine-non-determinism, MEFOR-only / Corepoint-only, unkeyed, duplicate keys); and the report.
"""

from __future__ import annotations

import errno
import inspect
import json
import logging
import os
import threading
from pathlib import Path

import pytest

from harness.bounded_file import read_capped
from harness.reconcile import compare as compare_mod
from harness.reconcile.__main__ import main as reconcile_main
from harness.reconcile.compare import (
    DEFAULT_MAX_LOAD_FILE_BYTES,
    LoadError,
    field_value,
    load_messages,
    reconcile,
)
from harness.reconcile.normalize import NormalizeRules
from harness.reconcile.report import render_json, render_text
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES


def _msg(control_id: str, *, name: str = "DOE^JANE", stamp: str = "20260101000000") -> str:
    # `stamp` rides ONLY MSH-7 (blanked by default as engine-non-deterministic); EVN-2 is pinned so a
    # stamp change doesn't masquerade as a real (un-blanked) difference.
    return (
        f"MSH|^~\\&|SEND|FAC|RECV|FAC|{stamp}||ADT^A05^ADT_A05|{control_id}|P|2.5.1\r"
        f"EVN|A05|20260101000000\rPID|1||MRN123^^^FAC||{name}\r"
    )


def test_field_value_reads_on_own_separators() -> None:
    assert field_value(_msg("CID1"), ("MSH", 10)) == "CID1"
    assert field_value(_msg("CID1"), ("MSH", 9)) == "ADT^A05^ADT_A05"
    assert field_value(_msg("CID1"), ("PID", 5)) == "DOE^JANE"
    assert field_value(_msg("CID1"), ("ZZZ", 2)) is None  # absent segment
    # MSH-1 is the separator, on the same field numbering the diff uses, never the segment id.
    assert field_value(_msg("CID1"), ("MSH", 1)) == "|"
    assert field_value(_msg("CID1"), ("PID", 0)) is None


def test_load_messages_jsonl_batch_and_dir(tmp_path: Path) -> None:
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_text(
        "\n".join(json.dumps({"control_id": c, "raw": _msg(c)}) for c in ("A", "B")),
        encoding="utf-8",
    )
    assert [field_value(m, ("MSH", 10)) for m in load_messages(jsonl)] == ["A", "B"]

    batch = tmp_path / "export.hl7"
    batch.write_text(_msg("A") + _msg("B") + _msg("C"), encoding="latin-1")
    assert [field_value(m, ("MSH", 10)) for m in load_messages(batch)] == ["A", "B", "C"]

    d = tmp_path / "exp"
    d.mkdir()
    (d / "1.hl7").write_text(_msg("A"), encoding="latin-1")
    (d / "2.hl7").write_text(_msg("B"), encoding="latin-1")
    assert sorted(field_value(m, ("MSH", 10)) or "" for m in load_messages(d)) == ["A", "B"]


def test_load_messages_refuses_a_file_over_the_cap_in_each_shape(tmp_path: Path) -> None:
    """ASVS 5.1.1: each input file is capped and refused before it is read whole -- a batch file, a
    JSONL capture, and one file in a directory. The default is a FILE bound, not the per-message cap:
    a capture holds many messages."""
    default = inspect.signature(load_messages).parameters["max_file_bytes"].default
    assert default == DEFAULT_MAX_LOAD_FILE_BYTES == 64 * DEFAULT_MAX_MESSAGE_BYTES
    one = _msg("A").encode("latin-1")
    batch = tmp_path / "export.hl7"
    batch.write_bytes(one * 2)
    assert len(load_messages(batch, max_file_bytes=len(one) * 2)) == 2  # at the cap: read
    with pytest.raises(LoadError, match=f"over the {len(one) * 2 - 1}-byte cap"):
        load_messages(batch, max_file_bytes=len(one) * 2 - 1)
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_text(json.dumps({"raw": _msg("A")}), encoding="utf-8")
    with pytest.raises(LoadError, match="over the 8-byte cap") as over:
        load_messages(jsonl, max_file_bytes=8)
    assert over.value.over_cap
    if hasattr(os, "mkfifo"):  # POSIX: a FIFO is refused unread, never blocked on
        os.mkfifo(tmp_path / "pipe.hl7")
        caught: list[BaseException] = []

        def load_fifo() -> None:
            try:
                load_messages(tmp_path / "pipe.hl7")
            except LoadError as exc:
                caught.append(exc)

        worker = threading.Thread(target=load_fifo, daemon=True)
        worker.start()
        worker.join(5.0)
        assert not worker.is_alive(), "blocked on a FIFO"
        assert len(caught) == 1 and "not a regular file" in str(caught[0])
        assert isinstance(caught[0], LoadError) and not caught[0].over_cap
    d = tmp_path / "exp"
    d.mkdir()
    (d / "1.hl7").write_bytes(one)
    (d / "2.hl7").write_bytes(one + one)
    with pytest.raises(LoadError, match="2.hl7"):
        load_messages(d, max_file_bytes=len(one) * 2)  # a TOTAL across the directory: 3 > 2
    assert len(load_messages(d, max_file_bytes=len(one) * 3)) == 3
    with pytest.raises(ValueError, match="positive"):
        load_messages(batch, max_file_bytes=0)


def test_compare_cli_reports_an_over_cap_input_and_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    batch = tmp_path / "export.hl7"
    batch.write_text(_msg("A"), encoding="latin-1")
    argv = ["compare", "--mefor", str(batch), "--corepoint", str(batch)]
    assert reconcile_main([*argv, "--max-file-bytes", "16"]) == 2
    err = capsys.readouterr().err
    assert "over the 16-byte cap" in err and "--max-file-bytes changes the cap" in err
    assert reconcile_main(argv) == 0  # the default cap reads it; the same pair is clean
    with pytest.raises(SystemExit):
        reconcile_main([*argv, "--max-file-bytes", "0"])
    missing = ["compare", "--mefor", str(tmp_path / "nope.hl7"), "--corepoint", str(batch)]
    assert reconcile_main(missing) == 2  # unreadable input is 2, never 1 ("outputs differ")
    assert "could not be read (FileNotFoundError)" in capsys.readouterr().err


@pytest.mark.parametrize(
    "line",
    ["[1, 2]", "5", '"MSH|^~\\\\&|"', "null", '{"raw": 5}', '{"control_id": "A"}', "[" * 100_000],
    ids=["list", "number", "string", "null", "raw-not-text", "no-raw", "nested-too-deep"],
)
def test_compare_cli_exits_two_on_a_jsonl_line_that_is_not_a_capture_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], line: str
) -> None:
    """A JSONL line that is not an object with a string ``raw`` is malformed input, exit 2, never 1
    ("the outputs differ"). A list or a number used to raise an uncaught TypeError, so the process
    exited 1; a line nested too deep raised RecursionError the same way."""
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_text(json.dumps({"raw": _msg("A")}) + "\n" + line + "\n", encoding="utf-8")
    batch = tmp_path / "export.hl7"
    batch.write_text(_msg("A"), encoding="latin-1")
    assert reconcile_main(["compare", "--mefor", str(jsonl), "--corepoint", str(batch)]) == 2
    err = capsys.readouterr().err
    assert "cap.jsonl: line 2 is not" in err and "MSH" not in err  # the line, never its content
    assert "--max-file-bytes" not in err  # not a cap problem, so no cap hint


@pytest.mark.parametrize(
    "line",
    [
        '["PID|SECRET"]',
        '{"raw": "PID|SECRET"',
        "[" * 100_000,
        '{"raw": "PID|SECRET", "n": ' + "1" * 5000 + "}",
    ],
    ids=["list", "bad", "deep", "int-over-digit-limit"],
)
def test_load_messages_names_the_jsonl_line_and_not_its_content(tmp_path: Path, line: str) -> None:
    """A library caller gets a LoadError (a ValueError) naming the FILE's line number, never the
    line's text; a JSONDecodeError alone would count its line within the one line, and a line
    nested too deep would escape as RecursionError."""
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_text(json.dumps({"raw": _msg("A")}) + "\n" + line + "\n", encoding="utf-8")
    with pytest.raises(LoadError, match="cap.jsonl: line 2 is not") as bad:
        load_messages(jsonl)
    assert "SECRET" not in str(bad.value) and not bad.value.over_cap
    # Nothing chained either: a JSONDecodeError holds the whole line in .doc, and from None would
    # still leave it on __context__ for a logger or crash reporter that walks the chain.
    assert bad.value.__cause__ is None and bad.value.__context__ is None


def test_load_messages_jsonl_keeps_a_record_holding_a_unicode_line_separator(
    tmp_path: Path,
) -> None:
    """The capture sink writes ensure_ascii=False, so a body decoded from latin-1 byte 0x85 carries a
    raw U+0085, which str.splitlines() treats as a line break. The loader splits on newlines only."""
    jsonl = tmp_path / "cap.jsonl"
    bodies = [
        _msg("A").replace("DOE^JANE", "DOE\x85JANE"),
        _msg("B").replace("DOE^JANE", "X\u2028Y"),
    ]
    jsonl.write_text(
        "\n".join(json.dumps({"raw": b}, ensure_ascii=False) for b in bodies) + "\n",
        encoding="utf-8",
    )
    assert load_messages(jsonl) == bodies


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks on this platform")
def test_load_messages_directory_mode_does_not_follow_a_symlink(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """In a directory, a symlink is skipped, not followed, as the File tab's watch pane skips one:
    the entries are another system's output, and a link could point at any file the operator can
    read. A symlinked DIRECTORY the operator names is still read; only entries inside it are judged."""
    outside = tmp_path / "outside.hl7"
    outside.write_text(_msg("OUTSIDE"), encoding="latin-1")
    d = tmp_path / "exp"
    d.mkdir()
    (d / "1.hl7").write_text(_msg("A"), encoding="latin-1")
    try:
        (d / "2.hl7").symlink_to(outside)
    except OSError:  # Windows without the symlink privilege
        pytest.skip("cannot create a symlink here")
    with caplog.at_level(logging.WARNING, logger="harness.reconcile.compare"):
        assert [field_value(m, ("MSH", 10)) for m in load_messages(d)] == ["A"]
    assert "skipped 1 entry" in caplog.text  # a skip is never silent: it hides a key
    linked = tmp_path / "linked"
    linked.symlink_to(d, target_is_directory=True)
    assert [field_value(m, ("MSH", 10)) for m in load_messages(linked)] == ["A"]


def test_load_messages_directory_refusal_names_the_total_not_a_file_cap(tmp_path: Path) -> None:
    """The directory budget is a total, so a refusal says the cap it names is what was left of that
    total, not a per-file cap the operator set; it still names the file's own size."""
    one = _msg("A").encode("latin-1")
    d = tmp_path / "exp"
    d.mkdir()
    (d / "1.hl7").write_bytes(one)
    (d / "2.hl7").write_bytes(one)
    total = len(one) * 2 - 1
    with pytest.raises(LoadError) as over:
        load_messages(d, max_file_bytes=total)
    text = str(over.value)
    assert "2.hl7" in text and over.value.over_cap
    assert f"{len(one)} bytes, over the {len(one) - 1}-byte cap" in text
    assert f"what was left of the {total}-byte total across its files" in text


def test_reconcile_identical_is_clean() -> None:
    # Same content, only the engine-non-deterministic MSH-7 stamp + MSH-10 differ → blanked → clean.
    mefor = [_msg("MEF1", stamp="20260101111111")]
    corepoint = [_msg("MEF1", stamp="20260101222222")]
    result = reconcile(mefor, corepoint, connection="IB_X", key=("PID", 5))
    assert result.clean and len(result.pairs) == 1 and not result.mismatched


def test_reconcile_surfaces_a_real_field_difference() -> None:
    mefor = [_msg("K1", name="DOE^JANE")]
    corepoint = [_msg("K1", name="DOE^JANET")]
    result = reconcile(mefor, corepoint, key=("MSH", 10))
    assert not result.clean
    [pair] = result.mismatched
    assert pair.key == "K1"
    diff_locs = {(d.segment, d.field_no) for d in pair.differences}
    assert ("PID", 5) in diff_locs


def test_reconcile_unmatched_and_unkeyed_and_dupes() -> None:
    mefor = [_msg("A"), _msg("B"), _msg("B"), "garbage-no-msh"]  # dup B, one unkeyed
    corepoint = [_msg("A"), _msg("C")]  # C only on corepoint; B only on mefor
    result = reconcile(mefor, corepoint, key=("MSH", 10))
    assert result.mefor_only == ["B"]
    assert result.corepoint_only == ["C"]
    assert result.duplicate_keys == ["B"]
    assert result.unkeyed_mefor == 1 and result.unkeyed_corepoint == 0
    assert not result.clean


def test_blank_rule_suppresses_a_known_nondeterministic_field() -> None:
    # A db_lookup-derived field legitimately differs; --blank it and the pair is clean.
    mefor = [_msg("K") + "ROL|1|AD|NPI111\r"]
    corepoint = [_msg("K") + "ROL|1|AD|NPI999\r"]
    assert not reconcile(mefor, corepoint, key=("MSH", 10)).clean
    rules = NormalizeRules().with_blanks(("ROL", 3))
    assert reconcile(mefor, corepoint, key=("MSH", 10), rules=rules).clean


def test_report_renders_text_and_json() -> None:
    result = reconcile(
        [_msg("K", name="A^B")], [_msg("K", name="A^C")], connection="IB_Y", key=("MSH", 10)
    )
    text = render_text(result)
    assert "IB_Y" in text and "DIFFERENCES" in text
    blob = render_json(result)
    assert blob["connection"] == "IB_Y" and blob["clean"] is False
    assert blob["counts"]["mismatched"] == 1 and blob["mismatches"][0]["key"] == "K"


def test_load_messages_directory_skips_an_entry_gone_before_its_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An entry removed between the listing and its read, as a writer's temp file can be, is skipped
    and counted, as the old ``is_file()`` pre-check skipped it; any other OSError still ends the
    load, so an unreadable file is never silently dropped. (A symlink swapped in after the lstat is
    the shared reader's to answer: see tests/test_harness_bounded_file.py.)"""
    d = tmp_path / "exp"
    d.mkdir()
    (d / "1.hl7").write_text(_msg("A"), encoding="latin-1")
    (d / "2.hl7").write_text(_msg("B"), encoding="latin-1")

    def gone(path: Path, cap: int, *, follow_symlinks: bool = True) -> tuple[bytes, str]:
        if path.name == "2.hl7":
            raise FileNotFoundError(errno.ENOENT, "gone")
        return read_capped(path, cap, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(compare_mod, "read_capped", gone)
    with caplog.at_level(logging.WARNING, logger="harness.reconcile.compare"):
        assert [field_value(m, ("MSH", 10)) for m in load_messages(d)] == ["A"]
    assert "skipped 1 entry that is not a regular file" in caplog.text

    def denied(path: Path, cap: int, *, follow_symlinks: bool = True) -> tuple[bytes, str]:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(compare_mod, "read_capped", denied)
    with pytest.raises(PermissionError):
        load_messages(d)


def test_load_messages_reads_a_jsonl_capture_inside_a_directory(tmp_path: Path) -> None:
    """A ``.jsonl`` file in a directory is a capture, not HL7: read as HL7 it split into nothing, so
    every key on the other side read as a one-sided difference with no warning."""
    d = tmp_path / "captures"
    d.mkdir()
    (d / "IB_X.jsonl").write_text(json.dumps({"raw": _msg("A")}) + "\n", encoding="utf-8")
    (d / "more.hl7").write_text(_msg("B"), encoding="latin-1")
    assert [field_value(m, ("MSH", 10)) for m in load_messages(d)] == ["A", "B"]


def test_load_messages_jsonl_takes_a_bom_and_any_line_break(tmp_path: Path) -> None:
    """A byte-order mark, as some Windows tools write, and CR-only or CRLF breaks, which
    str.splitlines() accepted, are all read; a line number still counts the file's lines."""
    records = [json.dumps({"raw": _msg(c)}) for c in ("A", "B", "C")]
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_bytes(("\ufeff" + records[0] + "\r" + records[1] + "\r\n" + records[2]).encode())
    assert [field_value(m, ("MSH", 10)) for m in load_messages(jsonl)] == ["A", "B", "C"]
    jsonl.write_bytes((records[0] + "\r\r\n" + "nope\n").encode())
    with pytest.raises(LoadError, match="line 3 is not valid JSON"):
        load_messages(jsonl)


def test_reconcile_is_not_clean_when_nothing_was_compared() -> None:
    """BACKLOG #5424: with no pair there is nothing the sign-off gate checked, so it cannot pass,
    whether both inputs were empty or every message was unkeyed on both sides."""
    assert not reconcile([], [], key=("MSH", 10)).clean
    assert not reconcile([_msg("")], [_msg("")], key=("MSH", 10)).clean
    # Keyed on both sides, nothing unkeyed, but no key in common: only the pair check fails it.
    disjoint = reconcile([_msg("A")], [_msg("B")], key=("MSH", 10))
    assert not disjoint.pairs and not disjoint.unkeyed_mefor and not disjoint.unkeyed_corepoint
    assert not disjoint.clean
    text = render_text(reconcile([], []))
    assert "nothing was compared" in text and "DIFFERENCES" in text


def test_reconcile_is_not_clean_with_a_duplicate_key_even_when_the_last_copies_match() -> None:
    """BACKLOG #5424: only the last copy of a duplicated key is compared, so an earlier copy that
    differs is never looked at, and a doubled output is itself a difference."""
    mefor = [_msg("A", name="DOE^JOHN"), _msg("A")]
    corepoint = [_msg("A")]
    result = reconcile(mefor, corepoint, key=("MSH", 10))
    assert result.duplicate_keys == ["A"] and not result.mismatched
    assert not result.clean
    assert "duplicate keys" in render_text(result)


def test_compare_cli_exits_non_zero_over_empty_inputs_and_duplicate_keys(tmp_path: Path) -> None:
    """BACKLOG #5422: the CLI exits on ``clean``, so zero compared messages or a duplicate key used
    to exit 0, a pass, on a gate meant for a per-connection sign-off."""
    empty = tmp_path / "empty.hl7"
    empty.write_bytes(b"")
    assert reconcile_main(["compare", "--mefor", str(empty), "--corepoint", str(empty)]) == 1
    doubled = tmp_path / "doubled.hl7"
    doubled.write_text(_msg("A") + _msg("A"), encoding="latin-1")
    once = tmp_path / "once.hl7"
    once.write_text(_msg("A"), encoding="latin-1")
    assert reconcile_main(["compare", "--mefor", str(doubled), "--corepoint", str(once)]) == 1
    assert reconcile_main(["compare", "--mefor", str(once), "--corepoint", str(once)]) == 0
    # Field 0 is the segment id: as a key it would pair nothing, so it is refused at parse time.
    with pytest.raises(SystemExit):
        reconcile_main(
            ["compare", "--mefor", str(once), "--corepoint", str(once), "--key", "PID-0"]
        )


def test_compare_cli_exits_two_when_the_report_cannot_be_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5422: an unwritable --report-json raised an uncaught OSError, so the process exited
    1, the code for "the outputs differ", on a pair that was clean."""
    once = tmp_path / "once.hl7"
    once.write_text(_msg("A"), encoding="latin-1")
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory", encoding="utf-8")
    argv = ["compare", "--mefor", str(once), "--corepoint", str(once)]
    assert reconcile_main([*argv, "--report-json", str(blocker / "sub" / "r.json")]) == 2
    assert "report could not be written" in capsys.readouterr().err
    assert reconcile_main([*argv, "--report-json", str(tmp_path / "out" / "r.json")]) == 0


def test_load_messages_batch_strips_a_utf8_bom_and_refuses_a_wide_one(tmp_path: Path) -> None:
    """BACKLOG #5423: an HL7 file was decoded as latin-1 with its byte-order mark kept, so the first
    message's line no longer began with ``MSH`` and the message was dropped. The mark is now dropped
    where it leads an ``MSH``, the file still read as latin-1 like the capture, so bytes compare as
    bytes; a UTF-16 or UTF-32 mark is refused, since latin-1 would read it as noise."""
    bom8 = b"\xef\xbb\xbf"
    batch = tmp_path / "export.hl7"
    batch.write_bytes(bom8 + (_msg("A") + _msg("B", name="M\u00dcLLER^J")).encode())
    msgs = load_messages(batch)
    assert [field_value(m, ("MSH", 10)) for m in msgs] == ["A", "B"]
    assert field_value(msgs[1], ("PID", 5)) == "M\u00dcLLER^J".encode().decode("latin-1")
    # Two BOM-led files concatenated into one, as `copy /b a+b` makes, are still two messages.
    batch.write_bytes(bom8 + _msg("A").encode() + bom8 + _msg("B").encode())
    assert [field_value(m, ("MSH", 10)) for m in load_messages(batch)] == ["A", "B"]
    for bom in (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff"):
        batch.write_bytes(bom + _msg("A").encode("utf-16-le"))
        with pytest.raises(LoadError, match="UTF-16 or UTF-32"):
            load_messages(batch)
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_bytes(b"\xff\xfe" + json.dumps({"raw": _msg("A")}).encode("utf-16-le"))
    with pytest.raises(LoadError, match="UTF-16 or UTF-32"):
        load_messages(jsonl)


def test_load_messages_batch_keeps_text_with_no_msh_line_as_an_unkeyed_entry(
    tmp_path: Path,
) -> None:
    """BACKLOG #5423: text before the first ``MSH`` line, or a file with none, was discarded, so it
    reached neither the pairing nor the unkeyed counts and the gate could pass without it."""
    batch = tmp_path / "export.hl7"
    batch.write_text("not a message\r" + _msg("A"), encoding="latin-1")
    msgs = load_messages(batch)
    assert len(msgs) == 2
    batch.write_text("PID|1||MRN\r", encoding="latin-1")
    assert load_messages(batch) == ["PID|1||MRN"]
    result = reconcile(load_messages(batch), [_msg("A")], key=("MSH", 10))
    assert result.unkeyed_mefor == 1 and not result.clean
    # Batch-protocol envelope headers hold no message, so they are not an unkeyed entry.
    batch.write_text("FHS|^~\\&|S\rBHS|^~\\&|S\r" + _msg("A"), encoding="latin-1")
    assert [field_value(m, ("MSH", 10)) for m in load_messages(batch)] == ["A"]
    # MLLP framing bytes and blank lines alone are not content.
    batch.write_bytes(b"\x0b" + _msg("A").encode() + b"\x1c\r\n\r\n")
    assert [field_value(m, ("MSH", 10)) for m in load_messages(batch)] == ["A"]
