# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #4796 item 1: a refused loopback re-ingress is charged to the refused-body allowance.

The contract in ``tests/_reingress_refused_body_contract.py`` runs here on SQLite, keyless and keyed,
and from the gated SQL Server and Postgres suites. The unit tests below pin how
:meth:`RefusedBodyAllowance.bound_held` reads a body the engine already holds.

Synthetic bodies only; no real PHI.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.binary import decode as decode_carriage
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline.refused_body import (
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
    head_only_resubmit_refusal,
)
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher, verify_refused_body_digest
from tests._reingress_refused_body_contract import CASES

_KEYLESS = make_cipher(None)


@pytest.fixture(params=[False, True], ids=["keyless", "keyed"])
async def store(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[MessageStore]:
    cipher = make_cipher(generate_key()) if request.param else None
    s = await MessageStore.open(tmp_path / "reingress_refused.db", cipher=cipher)
    yield s
    await s.close()


@pytest.mark.parametrize("case", CASES)
async def test_reingress_refused_body_contract(store: MessageStore, case: Any) -> None:
    await case(store)


def _allowance(allowance_bytes: int, head_bytes: int = 256) -> RefusedBodyAllowance:
    # A frozen clock, so no refill between two charges can make a spent allowance read as unspent.
    return RefusedBodyAllowance(
        RefusedBodyPolicy(
            allowance_bytes=allowance_bytes, window_seconds=60.0, head_bytes=head_bytes
        ),
        clock=lambda: 1000.0,
    )


def _record(metadata: str) -> dict[str, Any]:
    return dict(json.loads(metadata)[METADATA_KEY])


def test_a_canonical_carriage_on_a_binary_loopback_is_described_by_the_bytes_it_carries() -> None:
    payload = bytes(range(256)) * 20  # 5120 bytes, NULs included
    body = RawMessage.from_bytes(payload, ContentType.BINARY.value).raw
    key = generate_key()
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.BINARY.value, "e", cipher=make_cipher(key)
    )
    record = _record(bounded.metadata)
    assert record["bytes"] == len(payload) and record["stored"] == "head"
    assert verify_refused_body_digest(make_cipher(key), payload, record["body_hmac"]) is True
    # The head is the carried bytes' head, as carriage that fits the head bound: never a cut of the
    # base64 text, never the carriage string wrapped a second time, and never a latin-1 view.
    assert is_marked(bounded.raw) and len(bounded.raw) <= 256
    assert decode_carriage(bounded.raw) == payload[: 3 * ((256 - len("mfb64:v1:")) // 4)]
    # A NUL-free binary head stays carriage too.
    high = RawMessage.from_bytes(b"\xff" * 5000, ContentType.BINARY.value).raw
    no_nul = _allowance(0).bound_held(
        "IB_LOOP", high, ContentType.BINARY.value, "e", cipher=_KEYLESS
    )
    assert is_marked(no_nul.raw) and set(decode_carriage(no_nul.raw)) == {0xFF}


def test_a_carriage_inside_the_allowance_is_stored_exactly_as_held() -> None:
    body = RawMessage.from_bytes(b"\x00\x01" * 2000, ContentType.BINARY.value).raw
    allowance = _allowance(len(body))
    bounded = allowance.bound_held("IB_LOOP", body, ContentType.BINARY.value, "e", cipher=_KEYLESS)
    assert bounded.raw == body and bounded.error == "e"
    assert _record(bounded.metadata)["stored"] == "whole"
    # It was charged the carriage it stores, so nothing of the allowance is left.
    assert not allowance.try_charge("IB_LOOP", 1)


def test_a_padded_carriage_is_charged_as_the_text_it_is() -> None:
    # A decoder strips whitespace, so this decodes to 3 bytes. Read as those bytes it would fit any
    # head and be stored whole for free; it is held as text, so it is charged and cut as text.
    body = "mfb64:v1:" + " " * 10_000 + "AAAA"
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.BINARY.value, "e", cipher=_KEYLESS
    )
    record = _record(bounded.metadata)
    assert record["bytes"] == len(body) and record["stored"] == "head"
    # Its head is re-made as carriage of the held text's first bytes, as a listener's would be.
    assert decode_carriage(bounded.raw) == body.encode()[:256]


def test_a_text_loopback_body_that_opens_with_the_marker_is_text() -> None:
    # Only a binary loopback carries bytes in carriage; on a text loopback the marker is just text.
    body = RawMessage.from_bytes(b"A" * 3000, ContentType.BINARY.value).raw
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.JSON.value, "e", cipher=_KEYLESS
    )
    record = _record(bounded.metadata)
    assert record["bytes"] == len(body.encode())
    assert decode_carriage(bounded.raw) == body.encode()[:256]


def test_a_multibyte_reply_is_charged_its_utf8() -> None:
    body = "é" * 1500  # 3000 UTF-8 bytes
    allowance = _allowance(2999)
    bounded = allowance.bound_held("IB_LOOP", body, ContentType.JSON.value, "e", cipher=_KEYLESS)
    assert _record(bounded.metadata) == {
        "bytes": 3000,
        "body_hmac": None,
        "stored": "head",
        "head_bytes": 256,
    }
    assert len(bounded.raw.encode()) <= 256 and body.startswith(bounded.raw)
    # Nothing was charged for the head, so a 2998-byte reply still fits the 2999.
    fits = allowance.bound_held("IB_LOOP", "é" * 1499, ContentType.JSON.value, "e", cipher=_KEYLESS)
    assert _record(fits.metadata)["stored"] == "whole"


def test_a_reply_no_longer_than_its_head_is_stored_whole_and_charges_nothing() -> None:
    allowance = _allowance(0)
    for _ in range(20):
        bounded = allowance.bound_held(
            "IB_LOOP", "x" * 256, ContentType.TEXT.value, "e", cipher=_KEYLESS
        )
        assert bounded.raw == "x" * 256 and _record(bounded.metadata)["stored"] == "whole"


def test_the_loopback_spends_its_own_allowance_not_a_listeners() -> None:
    allowance = _allowance(1000)
    spent = allowance.bound_held(
        "IB_LOOP", "y" * 1000, ContentType.TEXT.value, "e", cipher=_KEYLESS
    )
    assert _record(spent.metadata)["stored"] == "whole"
    assert allowance.try_charge("IB_LISTENER", 1000)
    assert not allowance.try_charge("IB_LOOP", 1)


def test_a_held_text_with_a_nul_keeps_its_characters_in_the_head() -> None:
    # The held text's UTF-8 is not received bytes, so its head must not be their latin-1 view.
    body = "café " * 100 + "\x00" + "tail"
    bounded = _allowance(0, head_bytes=16).bound_held(
        "IB_LOOP", body, ContentType.JSON.value, "e", cipher=_KEYLESS
    )
    assert bounded.raw == "café café caf"  # 15 UTF-8 bytes: cut before a split character
    # A NUL inside the head is stored as carriage of the text's own UTF-8.
    nul_head = _allowance(0, head_bytes=16).bound_held(
        "IB_LOOP", "café\x00" + "x" * 100, ContentType.JSON.value, "e", cipher=_KEYLESS
    )
    assert decode_carriage(nul_head.raw) == ("café\x00" + "x" * 10).encode()


def test_a_head_only_reingress_child_points_at_its_origin_without_naming_it() -> None:
    record = {"refused_body": {"bytes": 9000, "stored": "head", "head_bytes": 256}}
    lineage = {"correlation_id": "origin-1", "correlation_root_id": "root-1", "reingress_of_seq": 1}
    text = head_only_resubmit_refusal("child-1", json.dumps({**lineage, **record}))
    assert text is not None
    assert text.endswith(
        "; its whole reply was captured on its origin message's response; unless retention has"
        " erased it, a user scoped to that message who may view raw bodies can read it there"
    )
    # The origin may be outside the caller's scope, so neither lineage id is disclosed.
    assert "origin-1" not in text and "root-1" not in text
    # A re-ingress marker with no origin id keeps the sender remedy rather than point at nothing.
    orphan = head_only_resubmit_refusal("child-2", json.dumps({"reingress_of_seq": 1, **record}))
    assert orphan is not None and orphan.endswith("; have the sender send its own copy again")
    # A listener's head-only row keeps the sender remedy.
    listener = head_only_resubmit_refusal("row-1", json.dumps(record))
    assert listener is not None and listener.endswith("; have the sender send its own copy again")


def test_a_held_text_head_keeps_a_lone_surrogate() -> None:
    # A held body may carry a lone surrogate; the head is still a prefix of the held text.
    body = "ab\udc80c" + "d" * 1000
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.JSON.value, "e", cipher=_KEYLESS
    )
    assert body.startswith(bounded.raw) and len(bounded.raw) == 256 - 2


async def test_a_reply_holding_a_nul_is_refused_on_reingress(store: MessageStore) -> None:
    """BACKLOG #5616: a NUL inside a captured HL7 reply is refused, as a listener refuses one. Here
    and not in the shared contract, because a keyless server store cannot capture a NUL at all."""
    from messagefoundry.pipeline.ingress_guards import NUL_REJECTED_REASON
    from tests._reingress_refused_body_contract import REPLY, _assert_refused_by_a_guard

    body = REPLY.replace("MSA|AA|RB1", "MSA|AA|RB\x001")
    await _assert_refused_by_a_guard(store, ContentType.HL7V2, body, NUL_REJECTED_REASON, now=900.0)


def _loopback(content_type: ContentType) -> Any:
    from messagefoundry.config.wiring import Loopback, build_inbound_connection

    return build_inbound_connection("IB_LOOP_G", Loopback(), router="r", content_type=content_type)


def test_reingress_body_error_reads_the_listener_guards() -> None:
    """BACKLOG #5616: what ``reingress_body_error`` admits and refuses, beside the contract."""
    from messagefoundry.pipeline.ingress_guards import (
        MULTIPLE_MESSAGES_REJECTED_REASON,
        reingress_body_error,
    )

    hl7 = _loopback(ContentType.HL7V2)
    reply = "MSH|^~\\&|P|||||20260101||ACK^A01|R1|P|2.5.1\rMSA|AA|X1\r"
    assert reingress_body_error(hl7, reply) is None
    # A whole MLLP frame around the reply is tolerated, as the listener tolerates it (ADR 0205).
    assert reingress_body_error(hl7, "\x0b" + reply + "\x1c\r") is None
    # Two messages are refused whatever the line endings, as the listener normalizes them first.
    for eol in ("\r", "\n", "\r\n"):
        two = (reply + reply.replace("R1", "R2")).replace("\r", eol)
        assert reingress_body_error(hl7, two) == MULTIPLE_MESSAGES_REJECTED_REASON, repr(eol)
    # An empty or blank reply (a no_reply capture, ADR 0013) has nothing to sniff and is admitted.
    for ct in (ContentType.JSON, ContentType.FHIR, ContentType.XML, ContentType.X12):
        for blank in ("", " \r\n"):
            assert reingress_body_error(_loopback(ct), blank) is None, (ct, blank)
    assert reingress_body_error(_loopback(ContentType.DICOM), "") is None
    dicom = _loopback(ContentType.DICOM)
    not_dicom = RawMessage.from_bytes(b"%PDF-1.7 synthetic" * 60, ContentType.DICOM.value).raw
    refused = reingress_body_error(dicom, not_dicom)
    assert refused is not None and "'dicom'" in refused
    # Line-wrapped carriage is still sniffed: whitespace in its head is tolerated.
    wrapped = "mfb64:v1:" + base64.encodebytes(b"%PDF-1.7 synthetic" * 60).decode()
    assert reingress_body_error(dicom, wrapped) == refused
    # Decoded text a capturing transport hands a binary loopback is sniffed too.
    assert reingress_body_error(dicom, "<html>error</html>") == refused
    # Longer than the decoded sniff head, so only its head is decoded.
    part10 = b"\x00" * 128 + b"DICM" + b"\x02\x00" * 600
    assert (
        reingress_body_error(dicom, RawMessage.from_bytes(part10, ContentType.DICOM.value).raw)
        is None
    )
    # A carriage whose head does not decode fails closed, as the operator resend refuses it.
    for corrupt in ("mfb64:v1:@@@not-base64@@@", "mfb64:v1:", "mfb64:v1:QQ"):
        assert reingress_body_error(dicom, corrupt) == refused, corrupt
    # An opaque binary loopback has no signature, so nothing is refused there.
    assert reingress_body_error(_loopback(ContentType.BINARY), "mfb64:v1:@@@") is None


async def test_a_refused_hl7_reply_records_no_message_type(store: MessageStore) -> None:
    """BACKLOG #5616: a guard-refused HL7 reply has no message type, as a listener's refusal does,
    not the content type ``hl7v2``."""
    from messagefoundry.pipeline.ingress_guards import FRAME_BYTE_REJECTED_REASON
    from tests._reingress_refused_body_contract import (
        REPLY,
        _allowance,
        _reingress,
        _runner,
    )

    body = REPLY.replace("MSA|AA|RB1", "MSA|AA|RB1\x1c\rNTE|1||SYNTH")
    child = await _reingress(store, _runner(store, _allowance(10_000)), body, now=950.0)
    assert child["error"] == FRAME_BYTE_REJECTED_REASON
    assert child["message_type"] is None


async def test_a_reply_holding_the_document_marker_is_refused(store: MessageStore) -> None:
    """BACKLOG #5616: the document-marker refusal both listeners run on a parsed HL7 body also
    refuses a re-ingressed reply, which would otherwise dead-letter on every outbound."""
    from messagefoundry.parsing.binary import DOC_REF_MARKER
    from messagefoundry.pipeline.ingress_guards import DOC_REF_MARKER_REFUSED_REASON
    from tests._reingress_refused_body_contract import _assert_refused_by_a_guard
    from tests.test_sender_document_handle import _copy_in_nte_component

    body = _copy_in_nte_component("|", "^~\\/", DOC_REF_MARKER + "x")
    await _assert_refused_by_a_guard(
        store, ContentType.HL7V2, body, DOC_REF_MARKER_REFUSED_REASON, now=990.0
    )
    # The refusal keeps the parsed header fields, as a listener records them.
    from messagefoundry.pipeline.wiring_runner import _peek_for_loopback

    control_id, message_type, _, refusal = _peek_for_loopback(_loopback(ContentType.HL7V2), body)
    assert refusal == DOC_REF_MARKER_REFUSED_REASON
    assert control_id is not None and message_type is not None


def test_only_a_reply_no_store_can_bind_is_unstorable() -> None:
    """BACKLOG #5616: a lone surrogate anywhere in a reply makes it unstorable, and the reason names
    a position, never the character. ASCII and other encodable text is the control."""
    from messagefoundry.pipeline.wiring_runner import _unstorable_reply

    for body in ('{"a": "\udc80"}', '{"abcdefghij": "\udc80"}', "MSH|^~\\&|P\rNTE|1||\udfff\r"):
        reason = _unstorable_reply(body)
        assert reason is not None and "surrogates not allowed" in reason, repr(body)
        assert "\udc80" not in reason and "\udfff" not in reason
    for body in ("", '{"a": 1}', '{"a": "é中"}'):
        assert _unstorable_reply(body) is None, repr(body)


async def test_a_reply_no_store_can_hold_is_dead_lettered_and_the_lane_drains(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5616: a reply holding a lone surrogate is dead-lettered, its reference kept, and
    the next reply on the loopback lane still re-ingresses. Before the fix the guards' head sniff
    raised on it, and a refused child would have held it as its raw and raised in the handoff, so
    the worker re-pended the token at the lane's head on every pass.

    No store can capture such a reply, since the capture binds it too, so the body read is
    substituted for the bad token only."""
    from messagefoundry.store import OutboxStatus, Stage
    from messagefoundry.store.store import MessageStore as _Store
    from tests._reingress_refused_body_contract import DEST, LOOP, RAW, _allowance, _runner

    reply = '{"ack": "synthetic"}'

    async def capture(now: float) -> str:
        origin = await store.enqueue_message(
            channel_id="IB_REAL", raw=RAW, deliveries=[(DEST, "q")], now=now
        )
        [item] = await store.claim_ready(destination_name=DEST, now=now)
        await store.complete_with_response(
            item.id, body=reply, outcome="accepted", reingress_to=LOOP, now=now
        )
        return str(origin)

    bad, good = await capture(1.0), await capture(2.0)
    bad_token = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
    assert bad_token is not None and bad_token.message_id == bad
    real_read = store.response_body_for_work_row

    async def _read(row_id: str) -> str | None:
        held = await real_read(row_id)
        return '{"a": "\udc80"}' if row_id == bad_token.id else held

    monkeypatch.setattr(store, "response_body_for_work_row", _read)
    runner = _runner(store, _allowance(10_000), ContentType.JSON)
    await runner._process_response_item(LOOP, bad_token)  # the bad head must not raise
    cur = await store._db.execute("SELECT status, payload FROM queue WHERE id=?", (bad_token.id,))
    row = await cur.fetchone()
    assert row is not None and row["status"] == OutboxStatus.DEAD.value and row["payload"]
    dead = [e for e in await store.events_for(bad) if e["event"] == "dead"]
    assert [e for e in dead if "unstorable re-ingress reply" in str(e["detail"])]
    assert all("\udc80" not in str(e["detail"]) for e in dead)
    # The lane keeps draining: the next reply re-ingresses as a routed child.
    good_token = await store.claim_next_fifo(LOOP, now=4.0, stage=Stage.RESPONSE.value)
    assert good_token is not None and good_token.message_id == good
    await runner._process_response_item(LOOP, good_token)
    child = await store.get_message(_Store._reingress_message_id(good, DEST, 1, reply))
    assert child is not None and child["status"] == MessageStatus.RECEIVED.value
    assert child["raw"] == reply


async def test_a_faulting_content_guard_is_recorded_and_the_lane_drains(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5616: a content guard that raises anything but its own refusal is recorded as an
    ERROR child, with only the fault's type, so the next reply on the loopback lane still
    re-ingresses. Before the fix the fault escaped the re-ingress step, and the worker re-pended the
    token at the lane's head on every pass."""
    from messagefoundry.pipeline import wiring_runner
    from messagefoundry.pipeline.ingress_guards import reingress_body_error as real
    from tests._reingress_refused_body_contract import REPLY, _allowance, _reingress, _runner

    faulting = REPLY.replace("RSP1", "FLT1")

    def _guard(ic: Any, body: str) -> str | None:
        if body == faulting:
            raise ValueError("synthetic guard fault")
        return real(ic, body)

    monkeypatch.setattr(wiring_runner, "reingress_body_error", _guard)
    runner = _runner(store, _allowance(10_000))
    bad = await _reingress(store, runner, faulting, now=1100.0)
    assert bad["status"] == MessageStatus.ERROR.value
    assert bad["error"] == "ingress guard error: content check failed (ValueError)"
    assert bad["raw"] == faulting
    # The lane keeps draining: the next reply is admitted and routed as before.
    good = await _reingress(store, runner, REPLY, now=1110.0)
    assert good["status"] == MessageStatus.RECEIVED.value and good["raw"] == REPLY
