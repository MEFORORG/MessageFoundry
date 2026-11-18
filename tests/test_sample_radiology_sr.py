# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The IB_RADIOLOGY_SR sample handler builds its ORU MSH through the parsed model (BACKLOG #5396).

StudyDate and SOPInstanceUID come from the sending modality, so a delimiter or line break in either
must stay data in MSH-7 and MSH-10 rather than add fields or segments downstream. Synthetic DICOM only."""

from __future__ import annotations

import functools
from pathlib import Path

import pytest

pytest.importorskip("pydicom")

from messagefoundry.config.wiring import Registry, Send, load_config  # noqa: E402
from messagefoundry.parsing import RawMessage  # noqa: E402
from messagefoundry.parsing.message import Message  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "config"


@functools.cache
def _registry() -> Registry:
    return load_config(SAMPLES)


def _oru(*, sop_instance_uid: str, study_date: str) -> Message:
    reg = _registry()
    part10 = make_sr_part10(sop_instance_uid=sop_instance_uid, study_date=study_date)
    raw = RawMessage.from_bytes(part10, "dicom")
    out = reg.handlers["sr_to_oru"](raw)
    assert isinstance(out, Send) and out.to == "OB_POWERSCRIBE"
    assert isinstance(out.message, str)
    return Message.parse(out.message)


def test_clean_values_land_in_msh() -> None:
    oru = _oru(sop_instance_uid="1.2.826.0.1.99.5396", study_date="20260620")
    assert oru.field("MSH-7") == "20260620"
    assert oru.field("MSH-9") == "ORU^R01"
    assert oru.field("MSH-10") == "1.2.826.0.1.99.5396"
    assert oru.field("MSH-11") == "P"
    assert oru.field("MSH-12") == "2.5.1"


# pydicom warns that these values break the DA and UI value rules: a peer can still send them.
@pytest.mark.filterwarnings("ignore:Invalid value for VR:UserWarning")
def test_delimiters_and_line_breaks_stay_data() -> None:
    oru = _oru(sop_instance_uid="1.2|EVIL^X~Y&Z", study_date="2026|06\rZZZ|1")
    # The message type, processing id and version keep their positions: nothing was split off.
    assert oru.field("MSH-9") == "ORU^R01"
    assert oru.field("MSH-11") == "P"
    assert oru.field("MSH-12") == "2.5.1"
    assert oru.field("MSH-7.1") == "2026|06 ZZZ|1"
    assert oru.field("MSH-10.1") == "1.2|EVIL^X~Y&Z"
    # No segment was injected: MSH, PID, OBR, then one OBX per measurement.
    assert oru.segments() == ["MSH", "PID", "OBR", "OBX", "OBX"]


@pytest.mark.filterwarnings("ignore:Invalid value for VR:UserWarning")
def test_mllp_frame_bytes_in_a_peer_uid_never_reach_the_wire() -> None:
    # 0x0B and 0x1C open and close an MLLP frame; set_data carries them as hex escapes.
    reg = _registry()
    part10 = make_sr_part10(sop_instance_uid="1.2\x1c3\x0b4", study_date="20260620")
    out = reg.handlers["sr_to_oru"](RawMessage.from_bytes(part10, "dicom"))
    assert isinstance(out, Send) and isinstance(out.message, str)
    assert "\x1c" not in out.message and "\x0b" not in out.message
    assert Message.parse(out.message).field("MSH-10.1") == "1.2\x1c3\x0b4"
