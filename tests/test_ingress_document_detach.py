# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import socket
from pathlib import Path

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    InboundConnection,
    Registry,
    build_inbound_connection,
)
from messagefoundry.parsing.binary import (
    DocRefError,
    InboundDocRefError,
    chunk_b64,
    is_doc_ref,
    iter_obx_documents,
    make_doc_ref,
    parse_doc_ref,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, StreamingAttachmentsUnsupported
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.receipt import RefusalKind
from tests.test_wiring_engine import _mllp_client, _until_message


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
    text = _hl7_with_doc(b64, obx_type="Application")
    msg = Message.parse(text)
    docs = list(iter_obx_documents(msg, received=text))
    assert docs == [(1, b64, "Application")]


def test_iter_obx_documents_refuses_a_received_handle() -> None:
    # The scan runs on the received body only, so a handle there is the sender's text, never a
    # document this engine detached: refused, not skipped as already detached (BACKLOG #5099).
    ref = hashlib.sha256(b"x").hexdigest()
    handle = make_doc_ref(ref, "Application")
    text = _hl7_with_doc(handle)
    msg = Message.parse(text)
    with pytest.raises(InboundDocRefError):
        list(iter_obx_documents(msg, received=text))


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
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AA"
    msgs = await _messages(store)
    assert msgs[0]["raw"] == raw  # BYTE-IDENTICAL to today
    assert await _attachments(store) == []


# --- ASVS 1.3.4/5.2.2: OBX-5.2 MIME-vs-magic downgrade at detach ---------------


async def test_detach_downgrades_mislabelled_mime_to_octet_stream(store: MessageStore) -> None:
    # OBX-5.2 is a sender-controlled MIME. A document declared image/png whose bytes are NOT PNG (a %PDF
    # here) is stored as application/octet-stream so the download route can never serve mislabelled
    # active-content as its claimed inert type. The verbatim bytes are still recovered unchanged.
    b64 = base64.b64encode(b"%PDF-1.7 " + b"P" * 2000).decode("ascii")  # PDF magic, not PNG
    raw = _hl7_with_doc(b64, obx_type="image/png")
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_registry(ic), store, egress=EgressSettings(deny_by_default=False))

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))
    assert _ack_code(ack) == "AA"

    attaches = await _attachments(store)
    assert len(attaches) == 1
    assert (
        attaches[0]["content_type"] == "application/octet-stream"
    )  # downgraded (magic contradicts)
    # The handle in the persisted skeleton carries the downgraded type too, and the bytes round-trip.
    ref = Message.parse((await _messages(store))[0]["raw"]).field("OBX-5.5")
    assert ref is not None
    _, ct = parse_doc_ref(ref)
    assert ct == "application/octet-stream"
    assert await _read_attachment(store, attaches[0]["id"]) == b64  # verbatim bytes unchanged


async def test_detach_keeps_matching_mime(store: MessageStore) -> None:
    # A declared MIME whose magic AGREES with the bytes is preserved (no false downgrade): real PNG bytes
    # under an image/png label stay image/png.
    png = b"\x89PNG\r\n\x1a\n" + b"P" * 2000
    b64 = base64.b64encode(png).decode("ascii")
    raw = _hl7_with_doc(b64, obx_type="image/png")
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_registry(ic), store, egress=EgressSettings(deny_by_default=False))

    await runner._handle_inbound(ic, raw.encode("utf-8"))
    attaches = await _attachments(store)
    assert len(attaches) == 1
    assert attaches[0]["content_type"] == "image/png"  # magic agrees → kept


# --- synchronous header NAK, cap, strict downgrade ----------------------------


async def test_bad_header_naks_synchronously(store: MessageStore) -> None:
    # A non-MSH body on a streaming inbound still NAKs AR synchronously BEFORE any commit — the header
    # parse runs first, unchanged, so a malformed header never reaches the detach/ingress.
    ic = _streaming_ic(threshold=10)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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

    def _boom(text, *, expected_version=None):
        calls.append(text)
        raise AssertionError("whole-body validate must not run over the streaming threshold")

    monkeypatch.setattr(wiring_runner, "validate", _boom)

    b64 = _big_b64(2000)
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500, strict=True)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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

    def _spy(text, *, expected_version=None):
        called.append(text)
        return _Result()

    monkeypatch.setattr(wiring_runner, "validate", _spy)

    raw = _hl7_with_doc(_big_b64(20))
    ic = _streaming_ic(threshold=100_000, strict=True)  # threshold far above → below-threshold path
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

    await runner._handle_inbound(ic, raw.encode("utf-8"))
    assert len(called) == 1  # whole-body validate DID run


# --- ACK-after-commit + dedup + crash safety ----------------------------------


async def test_ack_fires_after_skeleton_and_incref_commit(store: MessageStore) -> None:
    # When _handle_inbound returns the AA ACK, the RECEIVED skeleton row AND the attachment incref are
    # already durable (the ACK is built only after enqueue_ingress commits both) — count-and-log holds.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

    await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))
    await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))

    assert len(await _messages(store)) == 2
    attaches = await _attachments(store)
    assert len(attaches) == 1  # one physical copy
    assert attaches[0]["refcount"] == 2  # both skeletons reference it
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM attachment_chunk")
    row = await cur.fetchone()
    assert row is not None
    assert dict(row)["n"] == len(list(chunk_b64(b64)))  # chunks written once


async def test_crash_before_skeleton_commit_orphan_reclaimed_and_rerun_dedups(
    store: MessageStore,
) -> None:
    # Simulate a crash AFTER put_attachment (refcount 0) but BEFORE the skeleton commit: _detach_documents
    # stores the attachment, then the process dies before enqueue_ingress. No ACK was sent.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

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
    runner = RegistryRunner(
        reg, store, stream_inflight_budget_bytes=10, egress=EgressSettings(deny_by_default=False)
    )  # far below the body size

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    # Detach refused; the body alone is over the whole budget, so no re-send could fit: final, AR
    # (BACKLOG #5078). The budget held by concurrent detaches, AE, is the control further down.
    assert _ack_code(ack) == "AR"
    msgs = await _messages(store)
    assert msgs[0]["status"] == MessageStatus.ERROR.value
    assert "streaming detach failed" in msgs[0]["error"]
    assert await _attachments(store) == []  # nothing written (budget checked before put_attachment)
    assert runner._stream_inflight_bytes == 0  # counter released


async def test_unsupported_backend_naks(store: MessageStore) -> None:
    # A streaming inbound against a backend that does not advertise streaming support raises the
    # not-supported error at detach → NAK AR + ERROR (final: the same body fails the same way on every
    # re-send, BACKLOG #5078), never accepted-and-dropped. SQLite, SQL Server, AND
    # Postgres now all support streaming (each sets supports_streaming_attachments=True), so this forces the
    # flag OFF as a unit seam to exercise a legacy/opt-out backend — it no longer describes SS/PG.
    store.supports_streaming_attachments = (
        False  # force the opt-out seam (not a real backend today)
    )
    b64 = _big_b64(2000)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

    ack = await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))

    assert _ack_code(ack) == "AR"
    assert (await _messages(store))[0]["status"] == MessageStatus.ERROR.value


# --- copy-on-Send composition (ADR 0104) --------------------------------------


async def test_skeleton_composes_with_copy_on_send(store: MessageStore) -> None:
    # The detached skeleton is a normal Message: Message.copy() carries the OBX-5.5 handle verbatim and
    # the message type/segments are intact, so ADR 0104 copy-on-Send snapshots operate on it unchanged.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    reg = _registry(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
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


# --- unlimited aggregate budget: the opt-out says so at start (BACKLOG #1729) ---
#
# The POSITIVE-budget refusal above (test_in_flight_budget_exceeded_naks) was the only behavioural
# cover this guard had. The ZERO path — the SHIPPED default — had none, and zero is falsy, so
# `if budget and ...` in _detach_documents short-circuits the whole check. These pin both halves:
# that unlimited really is unlimited (a characterization pin, deliberately green on a pristine tree),
# and that binding a streaming listener in that state now says so out loud (new behaviour, red without
# the change). The default is NOT flipped — tests/test_threat_model_doc_drift.py pins it at 0 against
# a vault THREAT-MODEL.md row, and that coupling is the point of leaving it alone.


async def test_zero_budget_admits_a_detach_that_a_positive_budget_refuses(
    store: MessageStore,
) -> None:
    # CHARACTERIZATION PIN, NOT A FAIL-WITHOUT-THE-FIX TEST — it passes on a pristine tree by design.
    # It fixes the MEANING of the shipped default so a later "0 = auto" reading cannot land quietly:
    # the same body that a budget of 10 refuses (AR) is accepted (AA) at 0. Both arms are asserted in
    # ONE test against ONE body, so it cannot degrade into an assertion the zero arm alone satisfies.
    b64 = _big_b64(2000)
    raw = _hl7_with_doc(b64).encode("utf-8")
    ic = _streaming_ic(threshold=500)

    refused = RegistryRunner(
        _registry(ic),
        store,
        stream_inflight_budget_bytes=10,
        egress=EgressSettings(deny_by_default=False),
    )
    assert _ack_code(await refused._handle_inbound(ic, raw)) == "AR"

    unlimited = RegistryRunner(
        _registry(ic),
        store,
        stream_inflight_budget_bytes=0,
        egress=EgressSettings(deny_by_default=False),
    )
    assert _ack_code(await unlimited._handle_inbound(ic, raw)) == "AA"
    assert unlimited._stream_inflight_bytes == 0  # released, exactly as on the positive path
    # The detach really happened on the unlimited run (an attachment exists), so "AA" is not an
    # accidental pass from some earlier gate declining to reach the budget check at all.
    assert len(await _attachments(store)) == 1


def test_streaming_inbound_with_unlimited_budget_warns(caplog) -> None:
    ic = _streaming_ic(threshold=500, max_message_bytes=64 * 1024 * 1024)
    with caplog.at_level("WARNING", logger=wiring_runner.__name__):
        warned = wiring_runner.warn_unbudgeted_streaming_inbound(ic, budget=0)
    assert warned
    assert len(caplog.records) == 1
    text = caplog.records[0].getMessage()
    assert "IB_STREAM" in text  # names the connection an operator has to act on
    assert "stream_inflight_budget_bytes" in text  # and the setting that fixes it
    assert "67108864" in text  # and the single-body cap that still applies


def test_streaming_inbound_with_no_max_message_bytes_names_the_engine_ceiling(caplog) -> None:
    # max_message_bytes=None inherits the engine ingress ceiling. The warning must not print "None"
    # as if no single-body bound existed — that would overstate the exposure it is reporting.
    ic = _streaming_ic(threshold=500, max_message_bytes=None)
    with caplog.at_level("WARNING", logger=wiring_runner.__name__):
        assert wiring_runner.warn_unbudgeted_streaming_inbound(ic, budget=0)
    text = caplog.records[0].getMessage()
    assert "16 MiB" in text
    assert "None" not in text


def test_positive_budget_does_not_warn(caplog) -> None:
    ic = _streaming_ic(threshold=500)
    with caplog.at_level("WARNING", logger=wiring_runner.__name__):
        assert wiring_runner.warn_unbudgeted_streaming_inbound(ic, budget=1) is False
    assert caplog.records == []


def test_non_streaming_inbound_does_not_warn(caplog) -> None:
    # The stock shape: no stream_threshold_bytes, budget at its 0 default. The detach path is never
    # reached, so there is nothing for the budget to bound and nothing to say. A warning here would
    # fire on every stock instance, which is how a real signal gets tuned out.
    ic = _streaming_ic(threshold=None)
    with caplog.at_level("WARNING", logger=wiring_runner.__name__):
        assert wiring_runner.warn_unbudgeted_streaming_inbound(ic, budget=0) is False
    assert caplog.records == []


async def test_binding_a_streaming_listener_emits_the_warning(store: MessageStore, caplog) -> None:
    # ASSERT THE INSTRUMENT FIRED: the three tests above exercise the function in isolation, which
    # proves nothing about whether the engine ever calls it. This drives a REAL listener bind through
    # RegistryRunner.start() and reads the log, with a non-streaming sibling on the same run as the
    # in-test control — so a warning that fired for everything, or for nothing, both fail here.
    def free_port() -> int:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])
        finally:
            s.close()

    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB_STREAMS", MLLP(port=free_port()), router="r", stream_threshold_bytes=500
        )
    )
    reg.add_inbound(build_inbound_connection("IB_PLAIN", MLLP(port=free_port()), router="r"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )  # stream_inflight_budget_bytes=0 default

    with caplog.at_level("WARNING", logger=wiring_runner.__name__):
        await runner.start()
        try:
            assert runner.inbound_running("IB_STREAMS")
            assert runner.inbound_running("IB_PLAIN")
        finally:
            await runner.stop()

    budget_lines = [
        m for m in (r.getMessage() for r in caplog.records) if "stream_inflight_budget_bytes" in m
    ]
    assert len(budget_lines) == 1  # exactly the streaming one, not its plain sibling
    assert "IB_STREAMS" in budget_lines[0]
    assert "IB_PLAIN" not in budget_lines[0]


# --- an HL7 escape in a document's OBX-5.5 (vault BACKLOG #2809) ---------------------------------
# Message.field decodes `\X0D\` to a real CR, so the detach would store a value that is not the
# sender's bytes, and Message.set refuses a CR at every later re-attach. Base64 needs no escape, so the
# detach refuses the message before the ACK instead.


def _escaped_b64(escape: str = "\\X0D\\") -> str:
    b64 = _big_b64(2000)
    return b64[:100] + escape + b64[100:]


@pytest.mark.parametrize("escape", ["\\X0D\\", "\\E\\"])
async def test_an_escape_in_obx_5_5_is_refused_at_detach_with_an_error_row_and_ar(
    store: MessageStore, escape: str
) -> None:
    raw = _hl7_with_doc(_escaped_b64(escape))
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_registry(ic), store, egress=EgressSettings(deny_by_default=False))

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    assert ack is not None and "escaped document in OBX-5.5" in ack
    msgs = await _messages(store)
    assert [m["status"] for m in msgs] == [MessageStatus.ERROR.value]
    assert "streaming detach failed" in msgs[0]["error"]
    assert "escape sequence" in msgs[0]["error"]
    assert await _attachments(store) == []  # nothing was detached, so nothing can fail re-attach


async def test_the_http_listener_refuses_an_escape_in_obx_5_5_too(store: MessageStore) -> None:
    raw = _hl7_with_doc(_escaped_b64())
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_registry(ic), store, egress=EgressSettings(deny_by_default=False))

    receipt = await runner._handle_inbound_http(ic, raw.encode("utf-8"))

    # Permanent, as the MLLP path's AR: the same bytes fail the same way on every re-send.
    assert receipt.refusal is RefusalKind.PERMANENT
    msgs = await _messages(store)
    assert [m["status"] for m in msgs] == [MessageStatus.ERROR.value]
    cur = await store._db.execute("SELECT id FROM messages")
    assert [r["id"] for r in await cur.fetchall()] == [receipt.message_id]
    assert "escape sequence" in msgs[0]["error"]
    assert await _attachments(store) == []


async def test_an_escape_in_a_later_document_stores_none_of_the_earlier_ones(
    store: MessageStore,
) -> None:
    """Every document is checked before the first is stored, so a refusal leaves no orphaned
    attachment behind for a clean document that came ahead of the escaped one."""
    clean = f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{_big_b64(2000)}||||||F\r"
    raw = _hl7_with_doc(_escaped_b64()).replace("OBX|1|", clean + "OBX|2|")
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_registry(ic), store, egress=EgressSettings(deny_by_default=False))

    assert _ack_code(await runner._handle_inbound(ic, raw.encode("utf-8"))) == "AR"

    assert await _attachments(store) == []
    cur = await store._db.execute("SELECT COUNT(*) FROM attachment_chunk")
    row = await cur.fetchone()
    assert row is not None and row[0] == 0


async def test_clean_base64_still_detaches_and_rehydrates_verbatim(store: MessageStore) -> None:
    """The control for the refusal above: the same message with clean base64 round-trips."""
    b64 = _big_b64(2000)
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_registry(ic), store, egress=EgressSettings(deny_by_default=False))

    assert _ack_code(await runner._handle_inbound(ic, raw.encode("utf-8"))) == "AA"

    cur = await store._db.execute("SELECT id, raw FROM messages")
    row = dict(await cur.fetchone() or {})
    hydrated = await runner._hydrate_payload(row["raw"], row["id"])
    assert Message.parse(hydrated).field("OBX-5.5") == b64


def test_an_escape_outside_obx_5_5_does_not_refuse_the_document() -> None:
    """The check reads OBX-5.5 alone: an escape in another component of OBX-5 is the sender's
    ordinary HL7 and leaves the document detachable."""
    b64 = _big_b64(300)
    text = _hl7_with_doc(b64, obx_type="App\\T\\lication")
    msg = Message.parse(text)
    assert [(occ, doc) for occ, doc, _ct in iter_obx_documents(msg, received=text)] == [(1, b64)]


# --- MLLP detach refusals take the receipt path's class (BACKLOG #5078) ---------------------------
#
# Owner ruling of 2026-11-03 (decision log d20261104T032854299-7235a9, stamped in UTC): MLLP follows
# the engine convention, AR for a refusal the engine treats as final and AE for one a re-send may
# clear. The receipt path classes a body alone over the whole budget OVERSIZE and an unsupported
# backend or a malformed handle PERMANENT, so each answers AR on MLLP; only a budget held by
# concurrent detaches is TEMPORARY, AE. Each case is sent by the engine's own MLLP outbound to the
# engine's own streaming listener, so the class is the one the real MLLPDestination reads.


async def _bad_handle_put_attachment(chunks: object, content_type: str) -> str:
    """A put_attachment that returns a content address make_doc_ref refuses, so the detach raises
    DocRefError after the store call (the only way that refusal reaches the detach arm)."""
    return "not-a-sha256"


async def _send_streaming_end_to_end(
    store: MessageStore, *, budget: int = 0, busy: int = 0
) -> tuple[NegativeAckError, RegistryRunner]:
    """Send one over-threshold MDM from the engine's own MLLP outbound to a running streaming MLLP
    inbound and return the NAK the outbound raised, once the listener has recorded the ERROR row.
    ``busy`` stands in for detaches already in flight on the runner's stream budget."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "mllp_in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
            content_type=ContentType.HL7V2,
            stream_threshold_bytes=500,
        )
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        stream_inflight_budget_bytes=budget,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    runner._stream_inflight_bytes = busy
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        with pytest.raises(NegativeAckError) as raised:
            await _mllp_client(port).send(_hl7_with_doc(_big_b64(2000)))
        await _until_message(store, MessageStatus.ERROR.value, channel_id="mllp_in")
    finally:
        await runner.stop()
    return raised.value, runner


def _refusal_for(case: str) -> Exception:
    """One instance of the refusal each case raises, for the classification both listeners share."""
    if case == "alone_over_budget":
        return wiring_runner._StreamBudgetExceeded("over", alone=True)
    if case == "unsupported_backend":
        return StreamingAttachmentsUnsupported("no streaming")
    return DocRefError("malformed")


@pytest.mark.parametrize(
    ("case", "receipt_kind"),
    [
        ("alone_over_budget", RefusalKind.OVERSIZE),
        ("unsupported_backend", RefusalKind.PERMANENT),
        ("malformed_handle", RefusalKind.PERMANENT),
    ],
)
async def test_a_final_detach_refusal_is_ar_to_the_engines_mllp_outbound(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, case: str, receipt_kind: RefusalKind
) -> None:
    """Mutation: answer every non-escape detach refusal AE again, as before the ruling. Red: the
    outbound's NAK is code AE and not permanent, for each of the three."""
    budget = 0
    if case == "alone_over_budget":
        budget = 10  # the body alone is far over it, so no re-send could ever fit
    elif case == "unsupported_backend":
        store.supports_streaming_attachments = False
    else:
        monkeypatch.setattr(store, "put_attachment", _bad_handle_put_attachment)

    nak, _ = await _send_streaming_end_to_end(store, budget=budget)

    assert nak.code == "AR"
    assert nak.permanent is True
    msgs = await _messages(store)
    assert [m["status"] for m in msgs] == [MessageStatus.ERROR.value]
    assert "streaming detach failed" in msgs[0]["error"]
    # The receipt path classes the same refusal by the same function, so the two cannot split.
    assert wiring_runner._detach_refusal_kind(_refusal_for(case)) is receipt_kind


async def test_control_a_budget_held_by_concurrent_detaches_is_ae_to_the_engines_mllp_outbound(
    store: MessageStore,
) -> None:
    """Control: the same path with a budget the body fits once the concurrent detaches finish. That
    refusal is TEMPORARY on the receipt path, so MLLP answers AE and the outbound retries it; the AR
    above is the final refusals' own class, not every detach refusal's. Mutation: answer every
    detach refusal AR. Red: AR here."""
    nak, runner = await _send_streaming_end_to_end(store, budget=1_000_000, busy=999_000)

    assert nak.code == "AE"
    assert nak.permanent is False
    msgs = await _messages(store)
    assert "(backpressure)" in msgs[0]["error"]
    assert runner._stream_inflight_bytes == 999_000  # the refusal reserved nothing
    assert (
        wiring_runner._detach_refusal_kind(wiring_runner._StreamBudgetExceeded("busy", alone=False))
        is RefusalKind.TEMPORARY
    )
