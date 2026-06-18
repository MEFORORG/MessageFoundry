# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Payload-agnostic ingress (ADR 0004): RawMessage, content_type routing, and the HL7 path intact."""

from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    build_inbound_connection,
    load_config,
)
from messagefoundry.parsing import Message, RawMessage
from messagefoundry.pipeline.dryrun import dry_run, route_message, route_only, transform_one

HL7 = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\r"


# --- RawMessage --------------------------------------------------------------


def test_rawmessage_accessors() -> None:
    rm = RawMessage('{"mrn": "1", "type": "obs"}', "json")
    assert rm.raw == '{"mrn": "1", "type": "obs"}'
    assert rm.text == rm.raw
    assert rm.content_type == "json"
    assert rm.json() == {"mrn": "1", "type": "obs"}
    assert rm.encode() == rm.raw  # symmetry with Message.encode() for a pass-through Send
    assert str(rm) == rm.raw


def test_rawmessage_bad_json_raises() -> None:
    with pytest.raises(_json.JSONDecodeError):
        RawMessage("not json", "json").json()


def test_message_content_type_symmetry() -> None:
    assert Message.content_type == "hl7v2"


# --- content_type routing (the shared dryrun/engine core) --------------------


def _json_registry() -> tuple[Registry, InboundConnection, list[type]]:
    reg = Registry()
    ic = InboundConnection(
        name="IB_JSON",
        spec=ConnectionSpec(ConnectorType.FILE, {}),
        router="r",
        content_type=ContentType.JSON,
    )
    reg.add_inbound(ic)
    reg.add_outbound(OutboundConnection(name="OUT", spec=ConnectionSpec(ConnectorType.FILE, {})))
    seen: list[type] = []

    def route(msg: Any) -> list[str]:
        seen.append(type(msg))
        return ["h"] if msg.json().get("type") == "obs" else []

    def handle(msg: Any) -> Send:
        return Send("OUT", _json.dumps({"mrn": msg.json()["mrn"]}))

    reg.add_router("r", route)
    reg.add_handler("h", handle)
    return reg, ic, seen


def test_router_and_handler_receive_rawmessage() -> None:
    reg, ic, seen = _json_registry()
    raw = '{"mrn": "100", "type": "obs"}'
    assert route_only(reg, ic, raw) == ["h"]
    assert seen == [RawMessage]  # the Router got a RawMessage, not an HL7 Message
    previews, state_ops = transform_one(reg, "h", raw, "json")
    assert len(previews) == 1 and previews[0].to == "OUT"
    assert _json.loads(previews[0].payload) == {"mrn": "100"}  # Handler returned a Send(str)
    assert state_ops == []


def test_route_message_non_hl7_filtered() -> None:
    reg, ic, _ = _json_registry()
    outcome = route_message(reg, ic, '{"mrn": "1", "type": "adt"}')  # type != obs → routed nowhere
    assert outcome.handlers == []


def test_dry_run_non_hl7() -> None:
    reg, ic, _ = _json_registry()
    result = dry_run(reg, '{"mrn": "7", "type": "obs"}', inbound="IB_JSON")
    assert result.message_type == "json"  # message_type carries the content_type for non-HL7
    assert result.control_id is None and result.summary is None  # no HL7-derived metadata
    assert result.handlers == ["h"]
    assert result.deliveries and _json.loads(result.deliveries[0].payload) == {"mrn": "7"}


def test_hl7_inbound_still_receives_message() -> None:
    # Back-compat: an inbound with the default content_type=HL7V2 routes a mutable HL7 Message.
    reg = Registry()
    ic = InboundConnection(
        name="IB_HL7", spec=ConnectionSpec(ConnectorType.MLLP, {"port": 0}), router="r"
    )
    reg.add_inbound(ic)
    seen: list[type] = []

    def route(msg: Any) -> list[str]:
        seen.append(type(msg))
        return []

    reg.add_router("r", route)
    route_only(reg, ic, HL7)
    assert seen == [Message]
    assert ic.content_type is ContentType.HL7V2


# --- inbound() declaration: content_type + the HL7-strict reject -------------


def test_inbound_content_type_loads(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File, ContentType\n"
        "inbound('IB', File(directory='in'), router='r', content_type=ContentType.JSON)\n"
        "outbound('OUT', File(directory='out'))\n"
        "@router('r')\n"
        "def r(m): return ['h']\n"
        "@handler('h')\n"
        "def h(m): return Send('OUT', m.raw)\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert reg.inbound["IB"].content_type is ContentType.JSON


def test_inbound_rejects_strict_on_non_hl7(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text(
        "from messagefoundry import inbound, router, File, ContentType\n"
        "inbound('IB', File(directory='in'), router='r', content_type=ContentType.JSON, strict=True)\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="strict"):
        load_config(tmp_path)


def test_inbound_content_type_string_is_coerced(tmp_path: Path) -> None:
    # Regression (#12): a code-first author may pass the bare string ("x12") instead of the enum
    # member. The boundary must coerce it to ContentType so it can't flow into the pipeline as a raw
    # str and blow up later as `'str' object has no attribute 'value'` deep in dry-run.
    (tmp_path / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File, ContentType\n"
        "inbound('IB', File(directory='in'), router='r', content_type='x12')\n"
        "outbound('OUT', File(directory='out'))\n"
        "@router('r')\n"
        "def r(m): return ['h']\n"
        "@handler('h')\n"
        "def h(m): return Send('OUT', m.raw)\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert reg.inbound["IB"].content_type is ContentType.X12  # coerced, not left a bare str
    # and it now dry-runs without the AttributeError the raw string used to cause:
    result = dry_run(reg, "ISA*00*~", inbound="IB")
    assert result.message_type == "x12"
    assert result.handlers == ["h"]


def test_inbound_invalid_content_type_string_fails_loud(tmp_path: Path) -> None:
    # An unrecognized content_type string fails loud at load (WiringError naming the connection +
    # allowed values), not silently nor with an opaque crash deeper in the pipeline.
    (tmp_path / "c.py").write_text(
        "from messagefoundry import inbound, router, File\n"
        "inbound('IB', File(directory='in'), router='r', content_type='yaml')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match=r"invalid content_type 'yaml'"):
        load_config(tmp_path)


def test_build_inbound_connection_coerces_content_type() -> None:
    # The shared core (used by both inbound() and the connections.toml loader) coerces a string and is
    # idempotent on an enum member — so both authoring surfaces enforce the same guard.
    spec = ConnectionSpec(ConnectorType.FILE, {})
    assert build_inbound_connection("IB", spec, router="r", content_type="json").content_type is (
        ContentType.JSON
    )
    assert (
        build_inbound_connection("IB", spec, router="r", content_type=ContentType.X12).content_type
        is ContentType.X12
    )
    with pytest.raises(WiringError, match="invalid content_type"):
        build_inbound_connection("IB", spec, router="r", content_type="nope")
