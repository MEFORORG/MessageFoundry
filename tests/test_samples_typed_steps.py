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

# Synthetic: invented names and identifiers. OBX 1 has no result status (OBX-11), OBX 2 has one.
ORU_R01 = (
    "MSH|^~\\&|LAB|ACME|C|D|20260101120000||ORU^R01|STEPS1|P|2.5.1\r"
    "PID|1||100^^^H^MR~200^^^H^PI||  zztest^synthetic\r"
    "OBR|1|||CBC|||20260101113000\r"
    "OBX|1|NM|WBC||7.1|10*3/uL\r"
    "OBX|2|NM|HGB||13.9|g/dL|||||C\r"
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
    assert {"set_field", "copy_field", "trim_field", "convert_case", "format_date"} <= actions
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
    for row in editable:
        edit = {"line_start": row["line_start"], "line_end": row["line_end"], "op": "set_params"}
        out = rewrite_module(module, {**edit, "params": {}}, contract=CONTRACT_V2)
        assert out == original, f"no-op rewrite of {row} changed the file"


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
    assert msg.field("MSH-4") == "ACMEHOSP"  # code_lookup through facility_mnemonics
    assert msg.field("MSH-5") == "EMR"
    assert msg.field("PID-5.1") == "ZZTEST"  # trimmed, then upper-cased
    assert msg.field("PID-8") == "U"  # the If branch filled the empty field
    assert msg.field("OBR-22") == "202601011130"  # copied from OBR-7, then cut to minutes
    assert msg.field("OBX-11", occurrence=1) == "F"  # For Each filled the empty status
    assert msg.field("OBX-11", occurrence=2) == "C"  # and left the set one alone


def test_handler_filters_and_raises() -> None:
    reg = load_config(SAMPLES)
    run = reg.handlers["steps_oru_handler"]
    cancelled = Message.parse(
        ORU_R01.replace("OBR|1|||CBC|||20260101113000", "OBR|1|||CBC" + "|" * 21 + "X")
    )
    assert cancelled.field("OBR-25") == "X"
    assert run(cancelled) == []
    no_id = Message.parse(ORU_R01.replace("100^^^H^MR~200^^^H^PI", ""))
    with pytest.raises(ValueError, match="PID-3"):
        run(no_id)


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
    assert all("|ACMEHOSP|EMR|MAINHOSP|" in d["payload"] for d in r["deliveries"])
