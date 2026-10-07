# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The IB_STEPS_ORU sample is written only in the typed action vocabulary (ADR 0076, ADR 0106).

It exists so the planned analyst editor (ADR 0208) has a feed it can edit end to end. These tests pin
the property that makes it useful: ``lens parse`` projects no ``code`` row from either file, and the
rows cover the parts of the vocabulary the sample is meant to show. They also run the feed: a
``check`` pass over ``samples/config`` and a dryrun of a synthetic ORU (no real PHI)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.wiring import Send, load_config
from messagefoundry.lens import CONTRACT_V2, parse_module, parse_source, rewrite_module
from messagefoundry.parsing.message import Message

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "config"
ROUTER = SAMPLES / "IB_STEPS_ORU_router.py"
HANDLER = SAMPLES / "IB_STEPS_ORU_handler.py"

# Synthetic: invented names and identifiers. MSH-4 is a full HD, so the lookup must key on MSH-4.1.
# OBX 1 has no producer (OBX-15) and OBX 2 has one.
ORU_R01 = (
    "MSH|^~\\&|LAB|ACME^LABNS^L|C|D|20260101120000||ORU^R01|STEPS1|P|2.5.1\r"
    "PID|1||100^^^H^MR~200^^^H^PI||  zztest^synthetic||19800101120000\r"
    "OBR|1|||CBC|||20260101113000\r"
    "OBX|1|NM|WBC||7.1|10*3/uL|||||F\r"
    "OBX|2|NM|HGB||13.9|g/dL|||||F||||OTHERLAB\r"
)


def _rows(module: Path) -> list[dict[str, Any]]:
    contracts = parse_module(module, contract=CONTRACT_V2)
    assert len(contracts) == 1, contracts
    rows: list[dict[str, Any]] = contracts[0]["rows"]
    return rows


@pytest.mark.parametrize("module", [ROUTER, HANDLER], ids=lambda p: p.name)
def test_no_code_rows(module: Path) -> None:
    rows = _rows(module)
    assert rows
    assert [r for r in rows if r["kind"] == "code"] == []
    # A control row the lens could not read is as locked as a code row.
    assert all(r["recognized"] for r in rows if r["kind"] == "control")


def test_control_detector_fires_on_hand_written_python(tmp_path: Path) -> None:
    # The zero above means something only if the same parse finds a code row when one is there.
    probe = tmp_path / "probe.py"
    probe.write_text(
        HANDLER.read_text(encoding="utf-8").replace(
            '    set_field(msg, "MSH-5", "EMR")\n',
            '    set_field(msg, "MSH-5", "EMR")\n    msg.set("MSH-6", helper(msg))  # hand-written\n'
            "    stamp = [x for x in msg.repetitions('PID-3')]\n",
        ),
        encoding="utf-8",
    )
    assert any(r["kind"] == "code" for r in _rows(probe))


def test_router_rows() -> None:
    rows = _rows(ROUTER)
    assert [r["kind"] for r in rows] == ["control", "route", "route"]
    assert rows[0]["label"] == "when field MSH-9.1"
    assert rows[1]["handlers"] == ["steps_oru_handler"]
    assert rows[2]["unrouted"] is True


def test_handler_covers_the_vocabulary() -> None:
    rows = _rows(HANDLER)
    actions = {r["action"] for r in rows if r["kind"] == "action"}
    assert {"set_field", "copy_field", "trim_field", "convert_case", "substring_field"} <= actions
    assert [r["call"] for r in rows if r["kind"] == "lookup"] == ["code_lookup"]
    assert [r["call"] for r in rows if r["kind"] == "diagnostic"] == ["log_note"]
    controls = [r for r in rows if r["kind"] == "control"]
    assert {r["control"] for r in controls} >= {"if", "for", "raise"}
    assert "for each OBX segment" in {r["label"] for r in controls}
    assert any(r["control"] == "for" and "repetitions" in r["test_src"] for r in controls)
    sends = [r for r in rows if r["kind"] == "send"]
    assert any(r.get("filtered") for r in sends)
    assert ["OB_STEPS_ORU_EMR", "OB_STEPS_ORU_ARCHIVE"] in [r["outbounds"] for r in sends]
    assert any(r["kind"] == "note" for r in rows)


@pytest.mark.parametrize("module", [ROUTER, HANDLER], ids=lambda p: p.name)
def test_every_editable_row_rewrites_byte_identically(module: Path) -> None:
    # An analyst editor that opens a row and saves it unchanged must not touch the file.
    original = module.read_bytes().decode("utf-8")
    editable = [r for r in _rows(module) if r["kind"] in {"action", "lookup", "send", "route"}]
    assert editable
    resent = 0
    for row in editable:
        edit = {"line_start": row["line_start"], "line_end": row["line_end"], "op": "set_params"}
        out = rewrite_module(module, {**edit, "params": {}}, contract=CONTRACT_V2)
        assert out == original, f"no-op rewrite of {row} changed the file"
        # An empty edit returns early, so also re-send each literal param at its current value: that
        # runs the splice itself.
        current = {k: row["params"][k] for k in row.get("literal_params", [])}
        if current:
            out = rewrite_module(module, {**edit, "params": current}, contract=CONTRACT_V2)
            assert out == original, f"re-sending {current} on {row} changed the file"
            resent += 1
    if module == HANDLER:
        assert resent >= 8


def test_an_analyst_edit_changes_one_row() -> None:
    row = next(r for r in _rows(HANDLER) if r.get("params") == {"path": "MSH-5", "value": "EMR"})
    edit = {"line_start": row["line_start"], "line_end": row["line_end"], "op": "set_params"}
    out = rewrite_module(HANDLER, {**edit, "params": {"value": "CHART"}}, contract=CONTRACT_V2)
    before = HANDLER.read_bytes().decode("utf-8").splitlines()
    after = out.splitlines()
    changed = [i + 1 for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b]
    assert changed == [row["line_start"]]
    rows = parse_source(out, module=HANDLER.name, contract=CONTRACT_V2)[0]["rows"]
    assert {"path": "MSH-5", "value": "CHART"} in [r.get("params") for r in rows]
    assert [r for r in rows if r["kind"] == "code"] == []


def test_feed_transforms_a_synthetic_result() -> None:
    reg = load_config(SAMPLES)
    assert reg.inbound["IB_STEPS_ORU"].router == "steps_oru_router"
    assert {"OB_STEPS_ORU_EMR", "OB_STEPS_ORU_ARCHIVE"} <= set(reg.outbound)

    msg = Message.parse(ORU_R01)
    assert reg.routers["steps_oru_router"](msg) == ["steps_oru_handler"]
    adt = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M2|P|2.5.1\r")
    assert reg.routers["steps_oru_router"](adt) == []

    sends = reg.handlers["steps_oru_handler"](msg)
    assert isinstance(sends, list) and all(isinstance(s, Send) for s in sends)
    assert [s.to for s in sends if isinstance(s, Send)] == [
        "OB_STEPS_ORU_EMR",
        "OB_STEPS_ORU_ARCHIVE",
    ]
    assert msg.field("MSH-4") == "ACMEHOSP^LABNS^L"  # code_lookup on MSH-4.1 only
    assert msg.field("MSH-5") == "EMR"
    assert msg.field("PID-5.1") == "ZZTEST"  # trimmed, then upper-cased
    assert msg.field("PID-8") == "U"  # the If branch filled the empty field
    assert msg.field("PID-2.1") == "100"  # copied from the first PID-3 identifier
    assert msg.field("PID-7") == "19800101"  # the birth date without its time
    assert msg.field("OBX-15", occurrence=1) == "MAINLAB"  # For Each filled the empty producer
    assert msg.field("OBX-15", occurrence=2) == "OTHERLAB"  # and left the set one alone


def test_handler_filters_and_raises() -> None:
    reg = load_config(SAMPLES)
    run = reg.handlers["steps_oru_handler"]
    # MSH-11 carries a processing mode in its second component; the filter reads MSH-11.1.
    training = Message.parse(ORU_R01.replace("|P|2.5.1", "|T^T|2.5.1"))
    assert run(training) == []
    # A training message is filtered before the PID-3 check, so it is not an error.
    training_no_id = Message.parse(
        ORU_R01.replace("|P|2.5.1", "|T|2.5.1").replace("100^^^H^MR~200^^^H^PI", "")
    )
    assert run(training_no_id) == []
    no_id = Message.parse(ORU_R01.replace("100^^^H^MR~200^^^H^PI", ""))
    with pytest.raises(ValueError, match="PID-3"):
        run(no_id)


@pytest.mark.parametrize(
    ("pid7", "expected"),
    [
        ("19800101120000", "19800101"),
        ("19800101120000-0500", "19800101"),
        ("19800101^D", "19800101^D"),
        ("1980", "1980"),
        ("198003", "198003"),
    ],
)
def test_birth_date_keeps_its_precision(pid7: str, expected: str) -> None:
    # Cutting the text never invents a month or day, and never fails on the degree-of-precision part.
    reg = load_config(SAMPLES)
    msg = Message.parse(ORU_R01.replace("||19800101120000", f"||{pid7}"))
    assert msg.field("PID-7") == pid7
    reg.handlers["steps_oru_handler"](msg)
    assert msg.field("PID-7") == expected


def test_check_passes_and_dryrun_delivers_twice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    msgs = tmp_path / "messages"
    msgs.mkdir()
    (msgs / "oru.hl7").write_bytes(ORU_R01.encode("utf-8"))

    assert main(["check", "--config", str(SAMPLES), "--no-lint", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True

    rc = main(
        [
            "dryrun",
            "--config",
            str(SAMPLES),
            "--inbound",
            "IB_STEPS_ORU",
            "--messages",
            str(msgs / "oru.hl7"),
            "--json",
            "--show-phi",
        ]
    )
    assert rc == 0
    results = json.loads(capsys.readouterr().out)
    assert len(results) == 1
    r = results[0]
    assert r["message_type"] == "ORU^R01"
    assert [d["to"] for d in r["deliveries"]] == ["OB_STEPS_ORU_EMR", "OB_STEPS_ORU_ARCHIVE"]
    assert all("|ACMEHOSP^LABNS^L|EMR|MAINHOSP|" in d["payload"] for d in r["deliveries"])
