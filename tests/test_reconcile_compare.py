# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-connection reconcile orchestration: key extraction, message loading, pairing + diff, reporting.

Pure + offline (no DB, no sockets). Covers: field_value on a message's own separators; load_messages from
a JSONL capture, a batch file, and a directory; reconcile pairing (identical, real mismatch normalized
against engine-non-determinism, MEFOR-only / Corepoint-only, unkeyed, duplicate keys); and the report.
"""

from __future__ import annotations

import inspect
import json
import os
import threading
from pathlib import Path

import pytest

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
    assert "could not be read" in err and "MSH" not in err  # by class only, never the content


def test_load_messages_names_the_jsonl_line_and_not_its_content(tmp_path: Path) -> None:
    jsonl = tmp_path / "cap.jsonl"
    jsonl.write_text(json.dumps({"raw": _msg("A")}) + "\n" + '["PID|SECRET"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 2 is not an object") as bad:
        load_messages(jsonl)
    assert "SECRET" not in str(bad.value) and not isinstance(bad.value, LoadError)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks on this platform")
def test_load_messages_directory_mode_does_not_follow_a_symlink(tmp_path: Path) -> None:
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
    assert [field_value(m, ("MSH", 10)) for m in load_messages(d)] == ["A"]
    linked = tmp_path / "linked"
    linked.symlink_to(d, target_is_directory=True)
    assert [field_value(m, ("MSH", 10)) for m in load_messages(linked)] == ["A"]


def test_load_messages_directory_refusal_names_the_total_not_a_file_cap(tmp_path: Path) -> None:
    """The directory budget is a total, so a refusal names what was left of it and the total, not
    "the N-byte cap" as though N were a per-file cap the operator had set."""
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
    assert f"over the {len(one) - 1} bytes left of the {total}-byte total cap" in text


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
