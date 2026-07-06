# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HL7 schema export (for IDE field-path autocomplete)."""

from __future__ import annotations

import pytest

from messagefoundry.hl7schema import hl7_schema


def _field(seg: dict, index: int) -> dict | None:
    return next((f for f in seg["fields"] if f["index"] == index), None)


def test_schema_has_core_segments_and_version() -> None:
    schema = hl7_schema()
    assert schema["version"] == "2.5.1"
    segs = schema["segments"]
    assert {"MSH", "PID", "PV1", "OBR", "ORC"} <= set(segs)


def test_msh_message_type_is_composite() -> None:
    msh = hl7_schema()["segments"]["MSH"]
    f9 = _field(msh, 9)  # MSH-9 Message Type (MSG: code / trigger / structure)
    assert f9 is not None
    assert f9["datatype"] == "MSG"
    assert len(f9["components"]) >= 2  # code, trigger event, (structure)


def test_pid_name_field_has_named_components() -> None:
    pid = hl7_schema()["segments"]["PID"]
    f5 = _field(pid, 5)  # PID-5 Patient Name (XPN) — composite
    assert f5 is not None
    assert len(f5["components"]) >= 2
    names = " ".join((c["name"] or "") for c in f5["components"]).upper()
    assert "GIVEN" in names  # component names are available even when the field name isn't


def test_leaf_field_has_a_name() -> None:
    pid = hl7_schema()["segments"]["PID"]
    f1 = _field(pid, 1)  # PID-1 Set ID (simple leaf) carries a long name
    assert f1 is not None and f1["name"] and "SET_ID" in f1["name"].upper()


def test_unsupported_version_raises() -> None:
    with pytest.raises(ValueError):
        hl7_schema("2.3")
