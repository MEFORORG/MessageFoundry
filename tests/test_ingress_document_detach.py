# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Ingress-side very-large-document detach (#149, ADR 0105 Phase 1a).

Phase 0 shipped the attachment substrate; Phase 1a WIRES it into ingress: an over-threshold streaming
inbound DETACHES each oversized OBX-5 ED base64 document VERBATIM (Approach B) into the substrate before
the ingress commit, leaving a small ``mfdoc:v1:ref:`` handle in the persisted skeleton. These tests cover:

* over-threshold → small skeleton (the handle in OBX-5.5, other segments intact) + a verbatim attachment
  (``read_attachment`` recovers the EXACT base64 bytes), refcount 1, ACK AA;
* below-threshold / no-threshold → BYTE-IDENTICAL to today (no detach, no attachment row);
* a bad-header message still NAKs SYNCHRONOUSLY on a streaming inbound (before any commit);
* over ``max_message_bytes`` is rejected (NAK AR + ERROR, no attachment);
* whole-body strict validation is downgraded to header-only over threshold;
* the ACK fires only AFTER the skeleton + incref commit (the row/refcount are durable when AA returns);
* content-address dedup (identical docs → one physical attachment, refcount N, no double-write);
* a crash before the skeleton commit leaves an orphan chunk the Phase-0 sweep reclaims, and a re-run
  re-derives identically (dedup on sha256);
* the streaming-detach in-flight budget + an unsupported backend both NAK (never accepted-and-dropped);
* the detached skeleton composes with ADR 0104 copy-on-Send (Message.copy carries the handle verbatim).

Mirrors ``test_nonhl7_ingress_size_cap.py`` (ingress via ``_handle_inbound``) + ``test_attachment_substrate.py``.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Validation
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.binary import (
    chunk_b64,
    is_doc_ref,
    iter_obx_documents,
    make_doc_ref,
    parse_doc_ref,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _big_b64(nbytes: int) -> str:
    """A big UNBROKEN base64 string standing in for a base64 PDF sitting in OBX-5.5."""
    return base64.b64encode(b"P" * nbytes).decode("ascii")


def _hl7_with_doc(b64: str, *, obx_type: str = "Application") -> str:
    """A minimal MDM^T02 carrying one OBX-5 ED Base64 document (``^type^PDF^Base64^<b64>``)."""
    return (
        "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JOHN\r"
        f"OBX|1|ED|PDF^Report||^{obx_type}^PDF^Base64^{b64}||||||F\r"
    )


def _registry(ic: InboundConnection) -> Registry:
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router(ic.router, lambda m: [])  # no-op router; ingress never routes here
    return reg


def _streaming_ic(
    *,
    threshold: int | None = 500,
    max_message_bytes: int | None = None,
    strict: bool = False,
    ack_mode: AckMode = AckMode.ORIGINAL,
) -> InboundConnection:
    return InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
        router="r",
        ack_mode=ack_mode,
        content_type=ContentType.HL7V2,
        validation=Validation(strict=strict),
        stream_threshold_bytes=threshold,
        max_message_bytes=max_message_bytes,
    )


async def _messages(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT status, error, raw, message_type FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _attachments(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT id, content_type, total_bytes, refcount FROM attachment")
    return [dict(r) for r in await cur.fetchall()]


async def _read_attachment(store: MessageStore, ref: str) -> str:
    return "".join([c async for c in store.read_attachment(ref)])


def _ack_code(ack: str | None) -> str | None:
    """The MSA-1 acknowledgement code (AA/AE/AR) from a framed HL7 ACK string, or None."""
    if ack is None:
        return None
    for seg in ack.replace("\n", "\r").split("\r"):
        if seg.startswith("MSA|"):
            return seg.split("|")[1]
    return None


# --- pure helpers -------------------------------------------------------------


def test_iter_obx_documents_yields_verbatim_and_content_type() -> None:
    b64 = _big_b64(64)
    msg = Message.parse(_hl7_with_doc(b64, obx_type="Application"))
    docs = list(iter_obx_documents(msg))
    assert docs == [(1, b64, "Application")]


def test_iter_obx_documents_skips_already_detached() -> None:
    # A skeleton whose OBX-5.5 already carries a ref handle yields nothing (re-scan is a no-op).
    ref = hashlib.sha256(b"x").hexdigest()
    handle = make_doc_ref(ref, "Application")
    msg = Message.parse(_hl7_with_doc(handle))
    assert list(iter_obx_documents(msg)) == []


def test_chunk_b64_concatenates_to_input() -> None:
    b64 = _big_b64(4000)
    assert "".join(chunk_b64(b64, 100)) == b64
    # Content address is invariant to chunk size (put_attachment hashes the concatenation).
    whole = hashlib.sha256(b64.encode("utf-8")).hexdigest()
    pieced = hashlib.sha256("".join(chunk_b64(b64, 7)).encode("utf-8")).hexdigest()
    assert whole == pieced


# --- over-threshold detach ----------------------------------------------------


async def test_over_threshold_detaches_verbatim(store: MessageStore) -> None:
    b64 = _big_b64(2000)  # ~2668 base64 chars, well over the 500-byte message threshold
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AA"
    msgs = await _messages(store)
    assert len(msgs) == 1
    assert msgs[0]["status"] == MessageStatus.RECEIVED.value
    skeleton = msgs[0]["raw"]
    # The skeleton is SMALL (the bulky base64 is gone) and other segments are intact.
    assert len(skeleton) < len(raw)
    assert "DOE^JOHN" in skeleton
    assert "EVN|T02" in skeleton
    assert b64 not in skeleton  # the document was lifted out

    # OBX-5.5 now holds a live ref handle whose content address is the sha256 of the verbatim base64.
    obx5_5 = Message.parse(skeleton).field("OBX-5.5")
    assert obx5_5 is not None and is_doc_ref(obx5_5)
    ref, content_type = parse_doc_ref(obx5_5)
    assert ref == hashlib.sha256(b64.encode("utf-8")).hexdigest()
    assert content_type == "Application"

    # The attachment holds the EXACT base64 bytes and is increffed once (kept alive by this skeleton).
    attaches = await _attachments(store)
    assert len(attaches) == 1
    assert attaches[0]["id"] == ref
    assert attaches[0]["refcount"] == 1
    assert await _read_attachment(store, ref) == b64


async def test_below_threshold_byte_identical(store: MessageStore) -> None:
    b64 = _big_b64(50)  # small; whole message stays under the 5000-byte threshold
    raw = _hl7_with_doc(b64)
    assert len(raw) < 5000
    ic = _streaming_ic(threshold=5000)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AA"
    msgs = await _messages(store)
    assert len(msgs) == 1
    assert msgs[0]["status"] == MessageStatus.RECEIVED.value
    assert msgs[0]["raw"] == raw  # BYTE-IDENTICAL: no detach, no re-encode
    assert await _attachments(store) == []  # no attachment row


async def test_no_threshold_byte_identical(store: MessageStore) -> None:
    b64 = _big_b64(4000)  # large, but streaming is OFF (threshold None) → no detach
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=None)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AA"
    msgs = await _messages(store)
    assert msgs[0]["raw"] == raw  # BYTE-IDENTICAL to today
    assert await _attachments(store) == []


# --- synchronous header NAK, cap, strict downgrade ----------------------------


async def test_bad_header_naks_synchronously(store: MessageStore) -> None:
    # A non-MSH body on a streaming inbound still NAKs AR synchronously BEFORE any commit — the header
    # parse runs first, unchanged, so a malformed header never reaches the detach/ingress.
    ic = _streaming_ic(threshold=10)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(
        ic, b"NOTHL7 this is not a message at all, definitely over ten bytes"
    )

    assert _ack_code(ack) == "AR"
    msgs = await _messages(store)
    assert len(msgs) == 1
    assert msgs[0]["status"] == MessageStatus.ERROR.value
    assert await _attachments(store) == []  # nothing detached


async def test_over_max_message_bytes_rejected(store: MessageStore) -> None:
    b64 = _big_b64(4000)
    raw = _hl7_with_doc(b64)
    # Cap below the body size but at/above the threshold: the body is admitted past the threshold gate
    # but rejected by the total cap (Peek.parse) → NAK AR + ERROR, before any detach.
    ic = _streaming_ic(threshold=500, max_message_bytes=1000)
    assert len(raw) > 1000
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    msgs = await _messages(store)
    assert msgs[0]["status"] == MessageStatus.ERROR.value
    assert "exceeds max size" in msgs[0]["error"]
    assert await _attachments(store) == []


async def test_strict_downgraded_to_header_only_over_threshold(
    store: MessageStore, monkeypatch
) -> None:
    # Over the streaming threshold, whole-body hl7apy validation is NOT invoked (header-only downgrade).
    calls: list[str] = []

    def _boom(text, *, expected_version=None):  # type: ignore[no-untyped-def]
        calls.append(text)
        raise AssertionError("whole-body validate must not run over the streaming threshold")

    monkeypatch.setattr(wiring_runner, "validate", _boom)

    b64 = _big_b64(2000)
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500, strict=True)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AA"  # RECEIVED, not blocked by strict validation
    assert calls == []  # validate never called
    assert (await _messages(store))[0]["status"] == MessageStatus.RECEIVED.value


async def test_strict_still_runs_below_threshold(store: MessageStore, monkeypatch) -> None:
    # Below threshold, full strict validation still runs (byte-identical to today) — the downgrade is
    # scoped to over-threshold bodies only.
    called: list[str] = []

    class _Result:
        ok = True
        errors: list[str] = []

    def _spy(text, *, expected_version=None):  # type: ignore[no-untyped-def]
        called.append(text)
        return _Result()

    monkeypatch.setattr(wiring_runner, "validate", _spy)

    raw = _hl7_with_doc(_big_b64(20))
    ic = _streaming_ic(threshold=100_000, strict=True)  # threshold far above → below-threshold path
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(ic, raw.encode("utf-8"))
    assert len(called) == 1  # whole-body validate DID run


# --- ACK-after-commit + dedup + crash safety ----------------------------------


async def test_ack_fires_after_skeleton_and_incref_commit(store: MessageStore) -> None:
    # When _handle_inbound returns the AA ACK, the RECEIVED skeleton row AND the attachment incref are
    # already durable (the ACK is built only after enqueue_ingress commits both) — count-and-log holds.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))
    assert _ack_code(ack) == "AA"

    # Durable at the moment the ACK is available: one RECEIVED row + one attachment at refcount 1.
    msgs = await _messages(store)
    assert len(msgs) == 1 and msgs[0]["status"] == MessageStatus.RECEIVED.value
    attaches = await _attachments(store)
    assert len(attaches) == 1 and attaches[0]["refcount"] == 1


async def test_identical_documents_dedup_no_double_write(store: MessageStore) -> None:
    # Two distinct messages carrying the SAME document → one physical attachment, refcount 2 (each
    # skeleton increfs it once), no double-write of the chunks — content-addressing (sha256).
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))
    await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))

    assert len(await _messages(store)) == 2
    attaches = await _attachments(store)
    assert len(attaches) == 1  # one physical copy
    assert attaches[0]["refcount"] == 2  # both skeletons reference it
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM attachment_chunk")
    assert dict(await cur.fetchone())["n"] == len(list(chunk_b64(b64)))  # chunks written once


async def test_crash_before_skeleton_commit_orphan_reclaimed_and_rerun_dedups(
    store: MessageStore,
) -> None:
    # Simulate a crash AFTER put_attachment (refcount 0) but BEFORE the skeleton commit: _detach_documents
    # stores the attachment, then the process dies before enqueue_ingress. No ACK was sent.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    skeleton, refs = await runner._detach_documents(ic, _hl7_with_doc(b64))
    assert len(refs) == 1
    ref = refs[0]
    attaches = await _attachments(store)
    assert len(attaches) == 1 and attaches[0]["refcount"] == 0  # orphan (never increffed)

    # The Phase-0 startup sweep reclaims the refcount-0 orphan so no PHI chunk is left at rest.
    reclaimed = await store.sweep_orphan_attachments()
    assert reclaimed == 1
    assert await _attachments(store) == []

    # The sender resends (no ACK) → a full re-run re-derives identically: same ref (dedup on sha256),
    # one attachment at refcount 1, verbatim bytes recovered, RECEIVED.
    ack = await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))
    assert _ack_code(ack) == "AA"
    attaches = await _attachments(store)
    assert len(attaches) == 1 and attaches[0]["id"] == ref and attaches[0]["refcount"] == 1
    assert await _read_attachment(store, ref) == b64


# --- DoS guards ---------------------------------------------------------------


async def test_in_flight_budget_exceeded_naks(store: MessageStore) -> None:
    b64 = _big_b64(2000)
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, stream_inflight_budget_bytes=10)  # far below the body size

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AE"  # detach refused (backpressure) → NAK AE
    msgs = await _messages(store)
    assert msgs[0]["status"] == MessageStatus.ERROR.value
    assert "streaming detach failed" in msgs[0]["error"]
    assert await _attachments(store) == []  # nothing written (budget checked before put_attachment)
    assert runner._stream_inflight_bytes == 0  # counter released


async def test_unsupported_backend_naks(store: MessageStore) -> None:
    # A streaming inbound against a backend without streaming support (SQL Server / Postgres in Phase 1a)
    # raises the not-supported error at detach → NAK AE + ERROR, never accepted-and-dropped.
    store.supports_streaming_attachments = False  # simulate a non-SQLite backend
    b64 = _big_b64(2000)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))

    assert _ack_code(ack) == "AE"
    assert (await _messages(store))[0]["status"] == MessageStatus.ERROR.value


# --- copy-on-Send composition (ADR 0104) --------------------------------------


async def test_skeleton_composes_with_copy_on_send(store: MessageStore) -> None:
    # The detached skeleton is a normal Message: Message.copy() carries the OBX-5.5 handle verbatim and
    # the message type/segments are intact, so ADR 0104 copy-on-Send snapshots operate on it unchanged.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store)
    await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))

    skeleton = (await _messages(store))[0]["raw"]
    msg = Message.parse(skeleton)
    handle = msg.field("OBX-5.5")
    copy = msg.copy()
    assert copy.field("OBX-5.5") == handle  # the handle survives the copy verbatim
    assert copy.message_type == "MDM^T02"
    # Mutating the copy does not disturb the original skeleton's handle (independent snapshots).
    copy.set("OBX-5.5", "changed")
    assert msg.field("OBX-5.5") == handle
