# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5826: the results_relay porting template must edit each OBX through the parsed model.

The template used to rebuild every kept OBX by joining a fixed subset of its fields with the raw
delimiters. A feed copied from it would have emitted a decoded delimiter as live structure, dropped
OBX-3.4 onward, OBX-4, OBX-9, OBX-10 and OBX-12 onward, and re-inserted every OBX under the first OBR. These tests
pin the fixed shape, and the per-occurrence ``Message.delete_segments`` the fix rests on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.wiring import load_config
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import dry_run

RESULTS_RELAY = Path(__file__).resolve().parents[1] / "samples" / "results_relay"

_HEAD = "MSH|^~\\&|LABCO|LAB|EHR|HOSP|20260613130000||ORU^R01|MSG3|P|2.5.1\rOBR|1|ORD1\r"


def _relay(fixture: str) -> list[str]:
    return _relay_raw((RESULTS_RELAY / "messages" / fixture).read_text(encoding="utf-8"))


def _relay_raw(raw: str) -> list[str]:
    result = dry_run(load_config(RESULTS_RELAY), raw)
    assert [d.to for d in result.deliveries] == ["OB_EHR_ORU", "FILE-OUT_LABCO_ORU"]
    payload = result.deliveries[0].payload
    assert isinstance(payload, str)
    return [line for line in payload.split("\r") if line]


def test_two_orders_keep_every_obx_field_escape_and_order() -> None:
    segments = _relay("oru_two_orders.hl7")
    assert [line[:3] for line in segments] == ["MSH", "PID", "OBR", "OBX", "OBX", "OBR", "OBX"]
    assert segments[2].startswith("OBR|1|") and segments[5].startswith("OBR|2|")
    assert segments[3:5] + segments[6:] == [
        # OBX-3.4 to 3.6, OBX-4, OBX-10 and OBX-14/15 survive; only OBX-3.1 is remapped.
        r"OBX|1|NM|GLUC^Glucose^L^2345-7^Glucose^LN|1|95|mg/dL|70-110|N||A|F|||20260613121500|LAB01^Main Lab",
        # The escaped delimiters in OBX-3.2 and OBX-5 stay escaped; the cancelled K result is gone
        # and the Set ID closes the gap.
        r"OBX|2|ST|SOD^Sodium\T\Serum^L||see note\S\ref A|mmol/L|135-145|N|||F",
        # The second order keeps its own OBX, renumbered from 1 within that order.
        r"OBX|1|NM|HGB^Hemoglobin^L^718-7^Hemoglobin^LN|2|13.5|g/dL|12.0-16.0|N|||F|||20260613122000",
    ]


def test_a_cancelled_results_comments_go_with_it() -> None:
    segments = _relay_raw(
        _HEAD + "OBX|1|NM|GLU^Glucose^L||95||||||F\rNTE|1||glucose ok\r"
        "OBX|2|NM|K^Potassium^L||4.1||||||X\rNTE|1||hemolyzed\rNTE|2||recollect\r"
        "OBX|3|NM|NA^Sodium^L||140||||||F\rNTE|1||sodium ok"
    )
    assert segments[2:] == [
        "OBX|1|NM|GLUC^Glucose^L||95||||||F",
        "NTE|1||glucose ok",
        "OBX|2|NM|SOD^Sodium^L||140||||||F",
        "NTE|1||sodium ok",
    ]


def test_a_cancelled_results_participants_and_z_rows_go_with_it() -> None:
    segments = _relay_raw(
        _HEAD + "OBX|1|NM|GLU^Glucose^L||95||||||F\r"
        "OBX|2|NM|K^Potassium^L||4.1||||||X\rPRT|1|AD||RO\rZNT|1|x\rNTE|1||hemolyzed\r"
        "OBX|3|NM|NA^Sodium^L||140||||||F\rPRT|1|AD||RO"
    )
    assert segments[2:] == [
        "OBX|1|NM|GLUC^Glucose^L||95||||||F",
        "OBX|2|NM|SOD^Sodium^L||140||||||F",
        "PRT|1|AD||RO",
    ]


def test_a_fieldless_line_beside_a_dropped_result_fails_closed() -> None:
    # A bare "NTE" line is listed by segments() but numbered by no occurrence, so the handler
    # refuses the message rather than delete a note that belongs to another result.
    raw = (
        _HEAD + "NTE\rOBX|1|NM|GLU^Glucose^L||95||||||F\rNTE|1||keep\r"
        "OBX|2|NM|K^K^L||4||||||X\rNTE|1||drop\rOBX|3|NM|NA^Sodium^L||140||||||F\rNTE|1||keep 3"
    )
    result = dry_run(load_config(RESULTS_RELAY), raw)
    assert result.deliveries == []
    assert result.disposition.value == "error"


def test_an_unmapped_code_is_left_exactly_as_it_arrived() -> None:
    obx = r"OBX|1|ST|ZZ\H\Q&SUB^Other^L||x||||||F"
    assert _relay_raw(_HEAD + obx)[2:] == [obx]


def _msg() -> Message:
    return Message.parse(
        "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1\r"
        "OBR|1\rOBX|1|ST|A\rNTE|1||n\rOBX|2|ST|B\rOBX|3|ST|C"
    )


def test_delete_segments_occurrence_removes_only_that_segment() -> None:
    msg = _msg()
    assert msg.delete_segments("OBX", occurrence=2) == 1
    assert msg.segments() == ["MSH", "OBR", "OBX", "NTE", "OBX"]
    assert [msg.field("OBX-3", occurrence=i) for i in (1, 2)] == ["A", "C"]


def test_delete_segments_occurrence_absent_removes_nothing() -> None:
    msg = _msg()
    assert msg.delete_segments("OBX", occurrence=4) == 0
    assert msg.delete_segments("ZZZ", occurrence=1) == 0
    assert msg.count_segments("OBX") == 3


def test_delete_segments_occurrence_refusals() -> None:
    msg = _msg()
    with pytest.raises(ValueError, match="1-based"):
        msg.delete_segments("OBX", occurrence=0)
    with pytest.raises(ValueError, match="MSH"):
        msg.delete_segments("MSH", occurrence=1)


def test_delete_segments_occurrence_is_copy_on_write() -> None:
    msg = _msg()
    snapshot = msg.copy()
    msg.delete_segments("OBX", occurrence=1)
    assert snapshot.count_segments("OBX") == 3
    assert msg.count_segments("OBX") == 2


def test_delete_segments_occurrence_skips_a_fieldless_line_like_count_segments() -> None:
    # A bare "OBX" line is no occurrence (BACKLOG #5917), so occurrence 1 is the populated OBX.
    msg = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1\rOBX\rOBX|1|ST|A")
    assert msg.delete_segments("OBX", occurrence=1) == 1
    assert msg.segments() == ["MSH", "OBX"]
    assert msg.count_segments("OBX") == 0


def test_delete_segments_occurrence_reaches_a_leading_batch_header() -> None:
    # Index 0 is an FHS here, not MSH; the delete-all form removes it, so this form must too.
    msg = Message.parse("FHS|^~\\&|A\rBHS|^~\\&|A\rMSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1")
    assert msg.delete_segments("FHS", occurrence=1) == 1
    assert msg.segments()[0] == "BHS"
