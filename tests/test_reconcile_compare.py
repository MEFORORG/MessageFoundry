# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection reconcile orchestration: key extraction, message loading, pairing + diff, reporting.

Pure + offline (no DB, no sockets). Covers: field_value on a message's own separators; load_messages from
a JSONL capture, a batch file, and a directory; reconcile pairing (identical, real mismatch normalized
against engine-non-determinism, MEFOR-only / Corepoint-only, unkeyed, duplicate keys); and the report.
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.reconcile.compare import field_value, load_messages, reconcile
from harness.reconcile.normalize import NormalizeRules
from harness.reconcile.report import render_json, render_text


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
    assert sorted(field_value(m, ("MSH", 10)) for m in load_messages(d)) == ["A", "B"]


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
