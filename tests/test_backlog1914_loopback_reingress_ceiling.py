# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1914: a Loopback re-ingress enforces the engine ingress ceiling for every payload type.

The external listeners refuse a non-HL7 body over the 16 MiB ceiling (SEC-017, CWE-770), and an HL7
body meets the same ceiling inside ``Peek.parse``. The loopback re-ingress worker ran ``Peek.parse``
only for an HL7 loopback and relayed every other type verbatim, so a captured reply of any size would
let an internal hop bypass the ceiling on first deployment. These tests drive the real re-ingress step
(``_process_response_item``) over synthetic bodies and read the child message it records.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Loopback, Registry, build_inbound_connection
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

CEILING = DEFAULT_MAX_MESSAGE_BYTES
LOOP = "IB_LOOP"


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = await MessageStore.open(tmp_path / "loopback_ceiling.db")
    yield s
    await s.close()


def _runner(store: MessageStore, content_type: ContentType) -> RegistryRunner:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(LOOP, Loopback(), router="route_loop", content_type=content_type)
    )
    reg.add_router("route_loop", lambda msg: [])
    return RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )


def _json_body(chars: int) -> str:
    """A synthetic JSON document exactly ``chars`` characters long."""
    frame = '{"k":""}'
    return '{"k":"' + "a" * (chars - len(frame)) + '"}'


async def _reingress(
    store: MessageStore, content_type: ContentType, body: str
) -> tuple[str, dict[str, Any]]:
    """Capture ``body`` as a reply owed to the loopback, run the re-ingress step once, and return the
    origin message id and the child message the step recorded."""
    origin = await store.enqueue_message(
        channel_id="IB_REAL", raw="MSH|q", deliveries=[("OB_X", "q")], now=100.0
    )
    item = (await store.claim_ready(destination_name="OB_X", now=100.0))[0]
    await store.complete_with_response(
        item.id, body=body, outcome="accepted", reingress_to=LOOP, now=101.0
    )
    work = await store.claim_next_fifo(LOOP, now=102.0, stage=Stage.RESPONSE.value)
    assert work is not None
    await _runner(store, content_type)._process_response_item(LOOP, work)
    child = await store.get_message(store._reingress_message_id(origin, "OB_X", 1, body))
    assert child is not None  # count-and-log: the child is recorded whichever way it went
    return origin, child


async def _loop_rows(store: MessageStore) -> list[str]:
    cur = await store._db.execute("SELECT status FROM messages WHERE channel_id=?", (LOOP,))
    return [r["status"] for r in await cur.fetchall()]


async def _ingress_depth(store: MessageStore) -> int:
    return (await store.pending_depth(LOOP, stage=Stage.INGRESS.value))[0]


@pytest.mark.parametrize(
    "content_type",
    [ContentType.JSON, ContentType.XML, ContentType.TEXT, ContentType.X12, ContentType.FHIR],
)
async def test_an_oversize_text_payload_is_refused_on_reingress(
    store: MessageStore, content_type: ContentType
) -> None:
    origin, child = await _reingress(store, content_type, _json_body(CEILING + 1))
    assert child["status"] == MessageStatus.ERROR.value
    assert child["error"] == f"ingress exceeds max size ({CEILING + 1} > {CEILING} bytes)"
    assert child["message_type"] == content_type.value
    # One ERROR row and no ingress work: the oversize body never reaches the router.
    assert await _loop_rows(store) == [MessageStatus.ERROR.value]
    assert await _ingress_depth(store) == 0
    # The origin's reply was handled, so the origin still finalizes.
    origin_row = await store.get_message(origin)
    assert origin_row is not None and origin_row["status"] == MessageStatus.PROCESSED.value


async def test_a_text_payload_at_the_ceiling_is_admitted(store: MessageStore) -> None:
    _, child = await _reingress(store, ContentType.JSON, _json_body(CEILING))
    assert child["status"] == MessageStatus.RECEIVED.value
    assert child["error"] is None
    assert await _ingress_depth(store) == 1


async def test_an_oversize_binary_payload_is_refused_on_its_raw_bytes(store: MessageStore) -> None:
    # A binary loopback measures the RAW bytes, as the listener does, not the base64 carriage.
    body = RawMessage.from_bytes(b"\x01" * (CEILING + 1), ContentType.BINARY.value).raw
    _, child = await _reingress(store, ContentType.BINARY, body)
    assert child["status"] == MessageStatus.ERROR.value
    assert child["error"] == f"ingress exceeds max size ({CEILING + 1} > {CEILING} bytes)"
    assert await _ingress_depth(store) == 0


@pytest.mark.parametrize("content_type", [ContentType.BINARY, ContentType.DICOM])
async def test_an_oversize_decoded_binary_reply_is_refused_on_its_length(
    store: MessageStore, content_type: ContentType
) -> None:
    # A capturing transport hands back decoded text, not carriage. It is held and routed as text,
    # so it is sized in characters, which never exceed the wire bytes the transport decoded.
    body = "é" * (CEILING + 1)
    _, child = await _reingress(store, content_type, body)
    assert child["status"] == MessageStatus.ERROR.value
    assert child["error"] == f"ingress exceeds max size ({CEILING + 1} > {CEILING} bytes)"
    assert await _ingress_depth(store) == 0


async def test_a_decoded_binary_reply_at_the_ceiling_is_admitted(store: MessageStore) -> None:
    # A lossy or multibyte decode must not be refused for bytes it never had on the wire.
    _, child = await _reingress(store, ContentType.BINARY, "�" * CEILING)
    assert child["status"] == MessageStatus.RECEIVED.value
    assert await _ingress_depth(store) == 1


# A payload length at which even canonical base64 would carry more than the ceiling.
_CARRIAGE_ENVELOPE = 4 * CEILING // 3 + 4


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param("!" * _CARRIAGE_ENVELOPE, id="corrupt"),
        pytest.param(" " * _CARRIAGE_ENVELOPE + "AAAA", id="whitespace-padded"),
    ],
)
async def test_a_noncanonical_carriage_is_refused_on_its_text_length(
    store: MessageStore, payload: str
) -> None:
    # Padding would decode to 3 bytes and corrupt base64 to none; neither has an honest byte count,
    # so a carriage longer than a ceiling-size one is refused on its text length.
    body = "mfb64:v1:" + payload
    _, child = await _reingress(store, ContentType.BINARY, body)
    assert child["status"] == MessageStatus.ERROR.value
    assert child["error"] == f"ingress exceeds max size ({len(body)} > {CEILING} bytes)"
    assert await _ingress_depth(store) == 0


async def test_a_binary_payload_at_the_ceiling_is_admitted(store: MessageStore) -> None:
    # The carriage string is about 4/3 the ceiling long; the raw bytes are exactly at it.
    body = RawMessage.from_bytes(b"\x01" * CEILING, ContentType.BINARY.value).raw
    assert len(body) > CEILING
    _, child = await _reingress(store, ContentType.BINARY, body)
    assert child["status"] == MessageStatus.RECEIVED.value
    assert await _ingress_depth(store) == 1


async def test_hl7_control_is_unchanged(store: MessageStore) -> None:
    reply = "MSH|^~\\&|P|F|R|RF|20260101||RSP^K11|R1|P|2.5.1\r"
    _, child = await _reingress(store, ContentType.HL7V2, reply)
    assert child["status"] == MessageStatus.RECEIVED.value
    assert child["control_id"] == "R1"
    assert await _ingress_depth(store) == 1


async def test_hl7_oversize_still_errors_through_the_peek(store: MessageStore) -> None:
    # The HL7 ceiling was already enforced by Peek.parse; its disposition and wording do not move.
    reply = "MSH|^~\\&|P|F|R|RF|20260101||RSP^K11|R1|P|2.5.1\rNTE|1||" + "a" * CEILING + "\r"
    _, child = await _reingress(store, ContentType.HL7V2, reply)
    assert child["status"] == MessageStatus.ERROR.value
    assert child["error"] == "re-ingress body failed HL7 peek"
    assert await _ingress_depth(store) == 0
