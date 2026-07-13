# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Delivery-side very-large-document re-attach (#149, ADR 0105 Phase 1b).

Phase 1a detaches an oversized OBX-5 document at ingress (skeleton + ``mfdoc:v1:ref:`` handle + a
content-addressed attachment); Phase 1b makes that skeleton DELIVERABLE — at the terminal egress the
handle is re-attached VERBATIM (Approach B: the exact stored base64 spliced back into OBX-5.5, no
decode/re-encode) and the full frame streams inline. These tests cover:

* the two owner end-to-end round-trips: Shape A (doc present at ingress → detach → pass-through →
  delivery hydrates → delivered OBX-5.5 is byte-identical to the original base64) and Shape B (a File
  binary PDF → a Handler base64s + builds an MDM → delivered OBX-5.5 decodes back to the exact PDF);
* fail-loud: a missing / GC'd attachment turns the delivery into a retryable ERROR — a handle is NEVER
  sent to the connector (that would deliver ``mfdoc:v1:ref:…`` into a partner's OBX-5.5 = corruption);
* at-least-once retry re-hydrates the IDENTICAL frame (pure read off the immutable attachment);
* fan-out: two outbounds each deliver the full verbatim doc and the shared attachment's refcount is
  UNCHANGED (delivery never decrefs);
* below-threshold / no-handle delivery is BYTE-IDENTICAL (a single substring check, no store read);
* the batch path hydrates every member;
* ``reattach_documents_in_hl7`` pure-unit round-trip + fail-loud (mirrors the strip helper tests).

Mirrors ``test_ingress_document_detach.py`` + ``test_delivery_phase_timing.py`` + ``test_outbound_batch.py``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import BatchConfig, ContentType, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.binary import (
    DOC_REF_MARKER,
    DocRefError,
    chunk_b64,
    extract_obx_document,
    make_doc_ref,
    reattach_documents_in_hl7,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.transports.base import DeliveryError

DEST = "OB_EPIC"
DEST2 = "OB_EPIC_2"


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "reattach.db")
    yield s
    await s.close()


def _big_b64(nbytes: int) -> str:
    """A big UNBROKEN base64 string standing in for a base64 PDF sitting in OBX-5.5."""
    return base64.b64encode(b"P" * nbytes).decode("ascii")


def _hl7_with_value(obx5_5: str, *, obx_type: str = "Application") -> str:
    """A minimal MDM^T02 whose single OBX-5.5 is ``obx5_5`` (a verbatim base64 doc, or a ref handle —
    the OBX-5.4 Base64 marker is retained exactly as the ingress detach leaves it)."""
    return (
        "MSH|^~\\&|APP|FAC|EPIC|EPICF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JOHN\r"
        f"OBX|1|ED|PDF^Report||^{obx_type}^PDF^Base64^{obx5_5}||||||F\r"
    )


async def _store_doc(store: MessageStore, b64: str, content_type: str = "application/pdf") -> str:
    """Put a verbatim base64 document into the attachment substrate + take one live reference (as the
    ingress two-object commit would), returning its content-address ref."""
    ref = await store.put_attachment(chunk_b64(b64), content_type)
    await store.attachment_incref(ref)
    return ref


async def _refcount(store: MessageStore, ref: str) -> int | None:
    cur = await store._db.execute("SELECT refcount FROM attachment WHERE id=?", (ref,))
    row = await cur.fetchone()
    return None if row is None else int(dict(row)["refcount"])


def _obx5_5(hl7: str) -> str | None:
    return Message.parse(hl7).field("OBX-5.5")


async def _until(pred, *, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


class _Collector:
    """A non-capturing outbound (returns None → mark_done). Records each delivered payload verbatim."""

    def __init__(self, fail_times: int = 0) -> None:
        self.deliveries: list[str] = []
        self._fail_times = fail_times

    async def send(self, payload: str) -> None:
        if self._fail_times > 0:
            self._fail_times -= 1
            raise DeliveryError("partner unreachable (transient)")
        self.deliveries.append(payload)
        return None

    async def aclose(self) -> None:
        return None


# --- pure unit: reattach_documents_in_hl7 (mirrors the strip_documents_in_hl7 tests) ---------------


async def test_reattach_splices_verbatim() -> None:
    b64 = _big_b64(300)
    ref = hashlib.sha256(b64.encode("utf-8")).hexdigest()
    handle = make_doc_ref(ref, "application/pdf")
    skeleton = _hl7_with_value(handle)

    async def reader(sha: str) -> str:
        assert sha == ref
        return b64

    out = await reattach_documents_in_hl7(skeleton, reader)
    assert _obx5_5(out) == b64  # spliced back byte-for-byte
    assert DOC_REF_MARKER not in out  # no handle text survives


async def test_reattach_no_handle_byte_identical() -> None:
    plain = _hl7_with_value(_big_b64(20))  # a real base64 doc, not a handle

    async def reader(sha: str) -> str:  # pragma: no cover - must not be called
        raise AssertionError("reader must not be called when there is no handle")

    out = await reattach_documents_in_hl7(plain, reader)
    assert out == plain  # returned UNCHANGED (byte-identical)


async def test_reattach_fail_loud_when_reader_returns_none() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "application/pdf")
    skeleton = _hl7_with_value(handle)

    async def reader(sha: str) -> str | None:
        return None  # attachment missing / GC'd

    with pytest.raises(DocRefError):
        await reattach_documents_in_hl7(skeleton, reader)


async def test_reattach_fail_loud_when_reader_raises() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "application/pdf")
    skeleton = _hl7_with_value(handle)

    async def reader(sha: str) -> str:
        raise KeyError(sha)

    with pytest.raises(KeyError):
        await reattach_documents_in_hl7(skeleton, reader)


async def test_reattach_multiple_documents() -> None:
    a, b = _big_b64(100), _big_b64(200)
    ref_a = hashlib.sha256(a.encode()).hexdigest()
    ref_b = hashlib.sha256(b.encode()).hexdigest()
    hl7 = (
        "MSH|^~\\&|A|B|C|D|20260101||MDM^T02|M1|P|2.5\r"
        f"OBX|1|ED|D1||^Application^PDF^Base64^{make_doc_ref(ref_a, 'application/pdf')}||||||F\r"
        f"OBX|2|ED|D2||^Application^PDF^Base64^{make_doc_ref(ref_b, 'application/pdf')}||||||F\r"
    )
    table = {ref_a: a, ref_b: b}

    async def reader(sha: str) -> str:
        return table[sha]

    out = await reattach_documents_in_hl7(hl7, reader)
    msg = Message.parse(out)
    assert msg.field("OBX-5.5", occurrence=1) == a
    assert msg.field("OBX-5.5", occurrence=2) == b


# --- _hydrate_payload (the delivery seam) ---------------------------------------------------------


async def test_hydrate_no_handle_byte_identical(store: MessageStore) -> None:
    runner = RegistryRunner(Registry(), store)
    plain = _hl7_with_value(_big_b64(20))
    assert await runner._hydrate_payload(plain) == plain  # single substring check, no store read


async def test_hydrate_splices_verbatim(store: MessageStore) -> None:
    b64 = _big_b64(2000)
    ref = await _store_doc(store, b64)
    runner = RegistryRunner(Registry(), store)
    hydrated = await runner._hydrate_payload(_hl7_with_value(make_doc_ref(ref, "application/pdf")))
    assert _obx5_5(hydrated) == b64


async def test_hydrate_missing_attachment_raises_delivery_error(store: MessageStore) -> None:
    # A handle whose attachment was never stored / has been GC'd → DeliveryError (retryable), never a
    # payload carrying the raw handle. Fail-loud: the connector must NEVER see mfdoc:v1:ref:.
    missing = make_doc_ref(hashlib.sha256(b"gone").hexdigest(), "application/pdf")
    runner = RegistryRunner(Registry(), store)
    with pytest.raises(DeliveryError):
        await runner._hydrate_payload(_hl7_with_value(missing))


async def test_hydrate_retry_reads_identically_without_decref(store: MessageStore) -> None:
    # At-least-once: a re-hydrate (a retry) re-derives the IDENTICAL frame off the immutable attachment,
    # and delivery is a PURE READ — the refcount is untouched (released only at retention/purge).
    b64 = _big_b64(1500)
    ref = await _store_doc(store, b64)
    runner = RegistryRunner(Registry(), store)
    payload = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    first = await runner._hydrate_payload(payload)
    second = await runner._hydrate_payload(payload)
    assert first == second  # identical frame on every attempt
    assert await _refcount(store, ref) == 1  # NOT decref'd by delivery


async def test_hydrate_unsupported_backend_raises_delivery_error(store: MessageStore) -> None:
    b64 = _big_b64(1000)
    ref = await _store_doc(store, b64)
    store.supports_streaming_attachments = False  # simulate a non-SQLite backend at read time
    runner = RegistryRunner(Registry(), store)
    with pytest.raises(DeliveryError):
        await runner._hydrate_payload(_hl7_with_value(make_doc_ref(ref, "application/pdf")))


# --- _process_delivery_item: fan-out + a claimed row ----------------------------------------------


async def test_fan_out_both_deliver_verbatim_refcount_stable(store: MessageStore) -> None:
    # ONE message fans out to TWO outbounds. Each delivery hydrates the shared attachment (a per-send
    # read), so both partners receive the full verbatim document — and the refcount stays put (delivery
    # never decrefs; a message is replayable + multi-referenced).
    b64 = _big_b64(2000)
    ref = await store.put_attachment(chunk_b64(b64), "application/pdf")
    skeleton = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    # Two deliveries reference the one skeleton; incref twice (as an ingress two-object commit would for
    # a message referenced by two outbound rows).
    await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton), (DEST2, skeleton)], now=100.0
    )
    await store.attachment_incref(ref)
    await store.attachment_incref(ref)
    assert await _refcount(store, ref) == 2

    runner = RegistryRunner(Registry(), store)
    col1, col2 = _Collector(), _Collector()
    runner._destinations[DEST] = col1
    runner._destinations[DEST2] = col2

    for dest in (DEST, DEST2):
        item = await store.claim_next_fifo(dest)
        assert item is not None
        outcome, _ = await runner._process_delivery_item(dest, item)

    assert _obx5_5(col1.deliveries[0]) == b64
    assert _obx5_5(col2.deliveries[0]) == b64
    assert await _refcount(store, ref) == 2  # fan-out delivery did NOT decref


async def test_delivery_item_retry_rehydrates_identically(store: MessageStore) -> None:
    # A first send FAILS (transient), the row re-pends; the retry re-hydrates the identical frame and
    # delivers. Proves retry idempotence over the content-addressed attachment.
    b64 = _big_b64(1800)
    ref = await _store_doc(store, b64)
    skeleton = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    runner = RegistryRunner(Registry(), store)
    col = _Collector(fail_times=1)
    runner._destinations[DEST] = col
    runner._retry[DEST] = RetryPolicy(backoff_seconds=0.0, backoff_multiplier=1.0)

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    _outcome, retry_until = await runner._process_delivery_item(DEST, item)
    assert retry_until is not None  # re-pended, not delivered
    assert col.deliveries == []

    item2 = await store.claim_next_fifo(DEST)
    assert item2 is not None
    await runner._process_delivery_item(DEST, item2)
    assert _obx5_5(col.deliveries[0]) == b64  # retry delivered the identical verbatim frame


# --- batch path -----------------------------------------------------------------------------------


async def test_batch_hydrates_every_member(store: MessageStore) -> None:
    from messagefoundry.parsing.split import split_batch

    a, b = _big_b64(600), _big_b64(800)
    ref_a, ref_b = await _store_doc(store, a), await _store_doc(store, b)
    sk_a = _hl7_with_value(make_doc_ref(ref_a, "application/pdf"))
    sk_b = _hl7_with_value(make_doc_ref(ref_b, "application/pdf"))
    await store.enqueue_message(channel_id="c1", raw=sk_a, deliveries=[(DEST, sk_a)], now=100.0)
    await store.enqueue_message(channel_id="c1", raw=sk_b, deliveries=[(DEST, sk_b)], now=101.0)

    runner = RegistryRunner(Registry(), store)
    col = _Collector()
    runner._destinations[DEST] = col
    runner._batch[DEST] = BatchConfig(max_count=5, max_wait_ms=1)
    runner._retry[DEST] = RetryPolicy()
    runner._simulate[DEST] = False

    head = await store.claim_next_fifo(DEST)
    assert head is not None
    await runner._process_delivery_batch(DEST, head, runner._batch[DEST])

    assert len(col.deliveries) == 1  # one BHS…BTS envelope
    members = split_batch(col.deliveries[0])
    assert [Message.parse(m).field("OBX-5.5") for m in members] == [a, b]  # both hydrated verbatim


# --- end-to-end Shape A: doc present at ingress → detach → pass-through → delivery hydrates --------


def _reg_shape_a(inbox: Path, outdir: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_STREAM_MDM",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            content_type=ContentType.HL7V2,
            stream_threshold_bytes=500,
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB_EPIC",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_EPIC", m))  # pure pass-through
    return reg


async def test_shape_a_end_to_end_verbatim_roundtrip(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    b64 = _big_b64(4000)  # ~5334 base64 chars, well over the 500-byte threshold
    raw = _hl7_with_value(b64)
    runner = RegistryRunner(
        _reg_shape_a(inbox, outdir), store, claim_mode="pooled", pooled_sweep_interval=0.05
    )
    await runner.start()
    col = _Collector()
    runner._destinations["OB_EPIC"] = col
    try:
        await runner._handle_inbound(runner.registry.inbound["IB_STREAM_MDM"], raw.encode("utf-8"))

        async def _delivered() -> bool:
            return (await store.stats()).get(OutboxStatus.DONE.value, 0) >= 1

        await _until(_delivered)
    finally:
        await runner.stop()

    # The DELIVERED frame's OBX-5.5 is byte-identical to the original base64 (full-pipeline round-trip).
    assert len(col.deliveries) == 1
    assert _obx5_5(col.deliveries[0]) == b64
    # The INTERMEDIATE stored skeleton carried only the handle, never the bulky document.
    cur = await store._db.execute("SELECT raw FROM messages")
    skeleton = dict(await cur.fetchone())["raw"]
    assert DOC_REF_MARKER in skeleton and b64 not in skeleton


# --- end-to-end Shape B: File binary PDF → Handler base64s + builds MDM → inline delivery ----------

_SYNTHETIC_PDF = b"%PDF-1.4\n" + bytes(range(256)) * 40 + b"\n%%EOF"  # synthetic bytes incl. NUL


def _reg_shape_b(inbox: Path) -> Registry:
    def _handler(msg):  # type: ignore[no-untyped-def]
        if not msg.is_binary:  # pragma: no cover - guarded by the router
            return None
        pdf = msg.raw_bytes
        mdm = Message.parse(
            "MSH|^~\\&|MEFOR|FAC|EPIC|EPICF|20260101||MDM^T02|"
            + hashlib.sha256(pdf).hexdigest()[:12]
            + "|P|2.5.1\rOBX|1|ED|PDF^Doc||||||F\r"
        )
        from messagefoundry.parsing.binary import embed_obx_document

        embed_obx_document(mdm, pdf, data_subtype="PDF")
        return Send("OB_EPIC", mdm)

    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_PDF_TO_MDM",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.pdf", "poll_seconds": 0.05},
            ),
            router="r",
            content_type=ContentType.BINARY,
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB_EPIC",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(inbox / "out"), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"] if m.is_binary else [])
    reg.add_handler("h", _handler)
    return reg


async def test_shape_b_end_to_end_pdf_to_mdm(store: MessageStore, tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "out").mkdir()
    runner = RegistryRunner(
        _reg_shape_b(inbox), store, claim_mode="pooled", pooled_sweep_interval=0.05
    )
    await runner.start()
    col = _Collector()
    runner._destinations["OB_EPIC"] = col
    try:
        await runner._handle_inbound(runner.registry.inbound["IB_PDF_TO_MDM"], _SYNTHETIC_PDF)

        async def _delivered() -> bool:
            return (await store.stats()).get(OutboxStatus.DONE.value, 0) >= 1

        await _until(_delivered)
    finally:
        await runner.stop()

    # The delivered MDM's OBX-5.5 base64 decodes back to the EXACT synthetic PDF bytes (no handle here —
    # a Handler-built MDM rides the outbound row terminally, byte-identical through hydration's no-op).
    assert len(col.deliveries) == 1
    delivered = Message.parse(col.deliveries[0])
    assert extract_obx_document(delivered) == _SYNTHETIC_PDF
