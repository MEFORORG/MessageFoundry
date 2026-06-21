# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HL7-core engine features exercised through Corepoint patterns (SYNTHETIC-TEST-PLAN §1.3).

Gap-filling tests (the recon confirmed the rest is already covered elsewhere):

* 1.3.1 codeset graceful-miss — the Corepoint ItemCodeLookup "no-write-on-miss" contract:
  ``code_set(...).get(key)`` maps on a hit and returns None on a miss, leaving the field unchanged.
* 1.3.2 MSH-driven separators + Unicode + base64 ED — a custom-delimiter ORU carrying a base64 PDF
  OBX-5 round-trips intact, and the escaper uses the message's OWN delimiters (Unicode passes through).
* 1.3.3 timestamp conversion purity — convert/to_zone are pure + idempotent.
* 1.3.4 build_ack contract — AR/CR codes, MSA-3 CR/LF sanitization (no segment injection),
  AckMode.NONE still builds a valid AA, and a custom inbound field separator propagates to the ACK.
* 1.3.5 fan-out finalizer (mixed outcome) — one message to two outbounds where one delivers (DONE)
  and the sibling dead-letters (DEAD) finalizes the message as ERROR (the finalizer waits for all).

Synthetic + PHI-free.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import pytest

from messagefoundry import code_set
from messagefoundry.config.code_sets import CodeSet, activated as codesets_activated
from messagefoundry.config.models import AckMode, ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.generators.documents import synthetic_pdf
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.timezone import convert_hl7_timestamp, to_zone
from messagefoundry.transports.mllp import build_ack

ADT = "MSH|^~\\&|SND|FAC|RCV|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


# --- 1.3.1 codeset graceful-miss (ItemCodeLookup no-write-on-miss) -----------------------------


def _simplify_pv1_2(msg: Message) -> None:
    """The Corepoint ItemCodeLookup pattern: map PV1-2 via a code set, but leave it unchanged on a miss."""
    original = msg.field("PV1-2") or ""
    simplified = code_set("pv1_class").get(original)
    if simplified is not None:  # a miss returns None → no write, original survives
        msg.set("PV1-2", simplified)


def test_codeset_hit_maps_and_miss_leaves_field_unchanged() -> None:
    cs = CodeSet("pv1_class", {"I": "IP", "E": "EP", "O": "OP"})
    with codesets_activated({"pv1_class": cs}):
        hit = Message.parse("MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|1|P|2.5.1\rPV1|1|I\r")
        _simplify_pv1_2(hit)
        assert hit.field("PV1-2") == "IP"  # mapped on a hit

        miss = Message.parse("MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|2|P|2.5.1\rPV1|1|XYZ\r")
        _simplify_pv1_2(miss)
        assert miss.field("PV1-2") == "XYZ"  # unchanged on a miss (no crash, no blank)


def test_codeset_get_miss_returns_none_subscript_raises() -> None:
    cs = CodeSet("pv1_class", {"I": "IP"})
    assert cs.get("nope") is None
    with pytest.raises(KeyError):
        _ = cs["nope"]


# --- 1.3.2 custom MSH separators + Unicode + base64 ED round-trip ------------------------------


def test_custom_separators_carry_base64_ed_and_unicode() -> None:
    pdf = synthetic_pdf(n_bytes=1024, seed="csep")
    b64 = base64.b64encode(pdf).decode("ascii")
    # Custom delimiters: field=!, component=@, repetition=#, escape=\, subcomponent=&  (MSH-2 = "@#\&").
    raw = (
        "MSH!@#\\&!SND!FAC!RCV!RF!20260101!!ORU@R01!M1!P!2.5.1\r"
        "PID!1!!100@@@H@MR!!Müller@Jürgen\r"
        f"OBX!1!ED!DOC@Encapsulated Document@L!!@application@pdf@Base64@{b64}\r"
    )
    msg = Message.parse(raw)

    # base64 ED data (OBX-5.5, components split on the custom '@') survives byte-identical.
    assert msg.field("OBX-5.5") == b64
    assert base64.b64decode(msg.field("OBX-5.5") or "") == pdf
    # Unicode passes through the message's own delimiters intact.
    assert msg.field("PID-5.1") == "Müller"

    # A write escapes only the message's OWN delimiters; Unicode + base64 alphabet survive a round-trip.
    msg.set("PID-5.1", "García!@#&X")  # contains every custom delimiter
    assert msg.field("PID-5.1") == "García!@#&X"
    reparsed = Message.parse(msg.encode())
    assert reparsed.field("PID-5.1") == "García!@#&X"
    assert reparsed.field("OBX-5.5") == b64  # the document is untouched by the unrelated edit


# --- 1.3.3 timestamp conversion purity / idempotency ------------------------------------------


def test_timestamp_conversion_is_pure_and_idempotent() -> None:
    ts = "20260115103000-0500"  # winter Eastern
    first = convert_hl7_timestamp(ts, "America/Chicago", from_tz="America/New_York")
    second = convert_hl7_timestamp(ts, "America/Chicago", from_tz="America/New_York")
    assert first == second  # pure: same input → same output

    in_zone = to_zone(ts, "America/Chicago")
    assert (
        to_zone(in_zone, "America/Chicago") == in_zone
    )  # re-expressing in the same zone is stable


# --- 1.3.4 build_ack contract -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "code", "expected"),
    [
        (AckMode.ORIGINAL, "AR", "AR"),
        (AckMode.ENHANCED, "AR", "CR"),
        (AckMode.ENHANCED, "AE", "CE"),
    ],
)
def test_build_ack_codes(mode: AckMode, code: str, expected: str) -> None:
    ack = Message.parse(build_ack(ADT, code=code, ack_mode=mode))
    assert ack.field("MSA-1") == expected
    assert ack.field("MSA-2") == "MSG1"  # echoes the original control id


def test_build_ack_sanitizes_msa3_no_segment_injection() -> None:
    # Attacker-influenced reject text with CR/LF must not inject a new segment into the ACK.
    ack_str = build_ack(ADT, code="AE", text="bad result\r\nPID|9|INJECTED")
    ack = Message.parse(ack_str)
    assert ack.segments() == ["MSH", "MSA"]  # exactly two segments — nothing injected
    assert "\rPID|9" not in ack_str


def test_build_ack_none_mode_still_builds_valid_aa() -> None:
    # build_ack itself never suppresses — NONE maps to the ORIGINAL codes (suppression is the runner's job).
    ack = Message.parse(build_ack(ADT, ack_mode=AckMode.NONE))
    assert ack.field("MSA-1") == "AA"


def test_build_ack_propagates_custom_field_separator() -> None:
    inbound = "MSH!@#\\&!SND!FAC!RCV!RF!20260101!!ADT@A01!CID9!P!2.5.1"
    ack_str = build_ack(inbound, code="AA")
    assert ack_str.startswith("MSH!")  # the ACK uses the inbound's own field separator
    ack = Message.parse(ack_str)
    assert ack.field("MSA-1") == "AA"
    assert ack.field("MSA-2") == "CID9"


# --- 1.3.5 fan-out finalizer with mixed per-destination outcomes ------------------------------


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


class _RejectingDestination:
    """A destination that always fails — paired with max_attempts=1 it dead-letters on the first try."""

    async def send(self, payload: str) -> None:
        raise RuntimeError("destination unavailable")

    async def aclose(self) -> None:
        return None


def _route(msg: Message) -> list[str]:
    return ["fan"]


def _fan(msg: Message) -> list[Send]:
    return [Send("OB_GOOD", msg), Send("OB_BAD", msg)]  # one message → two destinations


async def _until_status(
    store: MessageStore, status: str, *, channel_id: str = "file_in", timeout: float = 8.0
) -> list[dict[str, object]]:
    for _ in range(int(timeout / 0.02)):
        msgs = await store.list_messages(channel_id=channel_id, status=status)
        if msgs:
            return msgs
        await asyncio.sleep(0.02)
    raise AssertionError(f"no message reached {status} within {timeout}s")


async def test_fanout_mixed_outcome_finalizes_error(store: MessageStore, tmp_path: Path) -> None:
    inbox, good_dir, bad_dir = tmp_path / "in", tmp_path / "good", tmp_path / "bad"
    inbox.mkdir()
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "OB_GOOD",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(good_dir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB_BAD",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(bad_dir), "filename": "{MSH-10}.hl7"}
            ),
            retry=RetryPolicy(max_attempts=1, backoff_seconds=0.02),  # dead-letter on first failure
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", _route)
    reg.add_handler("fan", _fan)

    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    runner._destinations["OB_BAD"] = _RejectingDestination()  # make the sibling fail permanently
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        msgs = await _until_status(store, MessageStatus.ERROR.value)  # any DEAD sibling → ERROR
    finally:
        await runner.stop()

    mid = str(msgs[0]["id"])
    by_dest = {str(r["destination_name"]): str(r["status"]) for r in await store.outbox_for(mid)}
    assert by_dest["OB_GOOD"] == OutboxStatus.DONE.value  # the healthy sibling delivered
    assert by_dest["OB_BAD"] == OutboxStatus.DEAD.value  # the failing sibling dead-lettered
    assert list(good_dir.glob("*.hl7")), "the good destination should have written its file"
    assert not bad_dir.exists() or not list(
        bad_dir.glob("*.hl7")
    )  # nothing delivered to the bad one
