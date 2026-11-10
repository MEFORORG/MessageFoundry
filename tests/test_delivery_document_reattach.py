# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import logging
import re
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from messagefoundry.config.models import (
    BatchConfig,
    ConnectorType,
    ContentType,
    InternalErrorPolicy,
    RetryPolicy,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
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
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.transports.base import DeliveryError, NegativeAckError

DEST = "OB_EPIC"
DEST2 = "OB_EPIC_2"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "reattach.db")
    enqueue = s.enqueue_message

    async def _enqueue_holding(**kwargs):  # type: ignore[no-untyped-def]
        # Every message here models one the ingress detach wrote, so it holds the documents its
        # handles name (BACKLOG #5099).
        mid = await enqueue(**kwargs)
        await _hold_named(s, mid, kwargs["raw"], *(p for _d, p in kwargs["deliveries"]))
        return mid

    s.enqueue_message = _enqueue_holding  # type: ignore[method-assign]
    yield s
    await s.close()


_HANDLE_REF = re.compile(r"mfdoc:v1:ref:([0-9a-f]{64})")


async def _hold_named(store: MessageStore, message_id: str, *texts: str) -> None:
    """Link ``message_id`` to every attachment a handle in ``texts`` names, as the ingress commit
    links a document it detached. Delivery resolves a handle only to an attachment its own message
    holds (BACKLOG #5099), so a message these tests model as detached must hold its documents."""
    for ref in {m for text in texts for m in _HANDLE_REF.findall(text)}:
        await store._db.execute(
            "INSERT OR IGNORE INTO message_attachment (message_id, attachment_id) VALUES (?,?)",
            (message_id, ref),
        )
    await store._db.commit()


def _named(text: str) -> set[str]:
    """Every content address a handle in ``text`` names: the pure re-attach's ``bound``."""
    return set(_HANDLE_REF.findall(text))


async def _hydrate(runner: RegistryRunner, store: MessageStore, payload: str) -> str:
    """Hydrate ``payload`` as the delivery of a message that holds every document it names."""
    mid = await store.enqueue_message(channel_id="c1", raw=payload, deliveries=[], now=100.0)
    return await runner._hydrate_payload(payload, mid)


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


async def _until(pred, *, timeout: float = 5.0) -> None:
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

    out = await reattach_documents_in_hl7(skeleton, reader, bound=_named(skeleton))
    assert _obx5_5(out) == b64  # spliced back byte-for-byte
    assert DOC_REF_MARKER not in out  # no handle text survives


async def test_reattach_no_handle_byte_identical() -> None:
    plain = _hl7_with_value(_big_b64(20))  # a real base64 doc, not a handle

    async def reader(sha: str) -> str:  # pragma: no cover - must not be called
        raise AssertionError("reader must not be called when there is no handle")

    out = await reattach_documents_in_hl7(plain, reader, bound=set())
    assert out == plain  # returned UNCHANGED (byte-identical)


async def test_reattach_fail_loud_when_reader_returns_none() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "application/pdf")
    skeleton = _hl7_with_value(handle)

    async def reader(sha: str) -> str | None:
        return None  # attachment missing / GC'd

    with pytest.raises(DocRefError):
        await reattach_documents_in_hl7(skeleton, reader, bound=_named(skeleton))


async def test_reattach_fail_loud_when_reader_raises() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "application/pdf")
    skeleton = _hl7_with_value(handle)

    async def reader(sha: str) -> str:
        raise KeyError(sha)

    with pytest.raises(KeyError):
        await reattach_documents_in_hl7(skeleton, reader, bound=_named(skeleton))


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

    out = await reattach_documents_in_hl7(hl7, reader, bound=_named(hl7))
    msg = Message.parse(out)
    assert msg.field("OBX-5.5", occurrence=1) == a
    assert msg.field("OBX-5.5", occurrence=2) == b


# --- _hydrate_payload (the delivery seam) ---------------------------------------------------------


async def test_hydrate_no_handle_byte_identical(store: MessageStore) -> None:
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    plain = _hl7_with_value(_big_b64(20))
    assert await _hydrate(runner, store, plain) == plain  # single substring check, no store read


async def test_hydrate_splices_verbatim(store: MessageStore) -> None:
    b64 = _big_b64(2000)
    ref = await _store_doc(store, b64)
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    hydrated = await _hydrate(runner, store, _hl7_with_value(make_doc_ref(ref, "application/pdf")))
    assert _obx5_5(hydrated) == b64


async def test_hydrate_a_never_stored_attachment_is_a_permanent_refusal(
    store: MessageStore,
) -> None:
    # A handle whose attachment was never stored, or has been GC'd with its header, is linked to no
    # message (attachments_for joins the header), so it is refused permanently before any read
    # (BACKLOG #5099), never a payload carrying the raw handle. Fail-loud: the connector must NEVER
    # see mfdoc:v1:ref:. The retryable arm, a held attachment whose read fails, is
    # test_delivery_fault_classification's control.
    missing = make_doc_ref(hashlib.sha256(b"gone").hexdigest(), "application/pdf")
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    with pytest.raises(NegativeAckError) as ei:
        await _hydrate(runner, store, _hl7_with_value(missing))
    assert ei.value.permanent is True


async def test_hydrate_retry_reads_identically_without_decref(store: MessageStore) -> None:
    # At-least-once: a re-hydrate (a retry) re-derives the IDENTICAL frame off the immutable attachment,
    # and delivery is a PURE READ — the refcount is untouched (released only at retention/purge).
    b64 = _big_b64(1500)
    ref = await _store_doc(store, b64)
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    payload = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    # One message, hydrated twice: a retry of the same row, not a second message.
    mid = await store.enqueue_message(channel_id="c1", raw=payload, deliveries=[], now=100.0)
    first = await runner._hydrate_payload(payload, mid)
    second = await runner._hydrate_payload(payload, mid)
    assert first == second  # identical frame on every attempt
    assert await _refcount(store, ref) == 1  # NOT decref'd by delivery


async def test_hydrate_unsupported_backend_refuses_the_handle_permanently(
    store: MessageStore,
) -> None:
    # A backend without the substrate links no attachment to any message, so no handle there can
    # be one the engine wrote: it is refused permanently, before any read, rather than re-pended on
    # the lane until the retry cap (BACKLOG #5099).
    b64 = _big_b64(1000)
    ref = await _store_doc(store, b64)
    store.supports_streaming_attachments = False  # simulate a non-SQLite backend at read time
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    with pytest.raises(NegativeAckError) as ei:
        await _hydrate(runner, store, _hl7_with_value(make_doc_ref(ref, "application/pdf")))
    assert ei.value.permanent is True
    assert ei.value.code == "reattach"


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

    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
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
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    col = _Collector(fail_times=1)
    runner._destinations[DEST] = col
    runner._retry[DEST] = RetryPolicy(backoff_seconds=0.01, backoff_multiplier=1.0)

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    _outcome, retry_until = await runner._process_delivery_item(DEST, item)
    assert retry_until is not None  # re-pended, not delivered
    assert col.deliveries == []

    # Claim as of a moment past the 0.01 s backoff; a zero backoff is refused (vault BACKLOG #2761).
    item2 = await store.claim_next_fifo(DEST, now=time.time() + 1.0)
    assert item2 is not None
    await runner._process_delivery_item(DEST, item2)
    assert _obx5_5(col.deliveries[0]) == b64  # retry delivered the identical verbatim frame


async def _store_doc_with_a_cr(store: MessageStore, line_end: str = "\r") -> str:
    """A stored document holding a real CR (or ``line_end``). No payload can leave one since vault
    BACKLOG #2809 (the detach refuses an escape, and a raw LF ends the segment), so this stands in
    for store corruption or an engine bug. ``Message.set`` refuses it at every re-attach."""
    b64 = _big_b64(600)
    return await _store_doc(store, b64[:100] + line_end + b64[100:])


def _with_a_bad_msh2(hl7: str) -> str:
    """``hl7`` with an MSH-2 too short to name its separators: a payload-caused re-attach failure."""
    return hl7.replace("|^~\\&|", "|^~\\|", 1)


def _without_an_msh(hl7: str) -> str:
    """``hl7`` with its MSH segment dropped, so it does not parse as HL7: a payload-caused failure."""
    return hl7.split("\r", 1)[1]


async def _outbox_rows(store: MessageStore, message_id: str) -> list[tuple[str, str]]:
    return [(str(r["status"]), str(r["last_error"])) for r in await store.outbox_for(message_id)]


@pytest.mark.parametrize("breaks", [_without_an_msh, _with_a_bad_msh2], ids=["no-parse", "msh2"])
async def test_hydrate_a_reattach_the_payload_breaks_is_a_permanent_refusal(
    store: MessageStore, breaks: Callable[[str], str]
) -> None:
    # Vault BACKLOG #2809 step 2: the same payload fails the same way on every attempt, so it must not
    # be the retryable DeliveryError, nor escape as a bare ValueError to the internal-error arm.
    ref = await _store_doc(store, _big_b64(600))
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    with pytest.raises(NegativeAckError) as ei:
        await _hydrate(runner, store, breaks(_hl7_with_value(make_doc_ref(ref, "application/pdf"))))
    assert ei.value.permanent is True
    assert ei.value.code == "reattach"
    assert ei.value.__cause__ is None and ei.value.__context__ is None


@pytest.mark.parametrize("line_end", ["\r", "\n"], ids=["cr", "lf"])
async def test_hydrate_a_stored_cr_or_lf_is_an_internal_error_not_a_refusal(
    store: MessageStore, line_end: str
) -> None:
    # Vault BACKLOG #2809, the Lander's hold of 2026-11-01: a stored CR or LF is not the payload's, so
    # it is neither the permanent refusal nor the retryable DeliveryError, but a plain ValueError
    # for the outbound's internal-error policy.
    ref = await _store_doc_with_a_cr(store, line_end)
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    with pytest.raises(ValueError) as ei:
        await _hydrate(runner, store, _hl7_with_value(make_doc_ref(ref, "application/pdf")))
    assert type(ei.value) is ValueError
    assert "occurrence 1 holds a CR or LF" in str(ei.value)


async def test_a_non_hl7_payload_carrying_a_real_handle_is_never_delivered(
    store: MessageStore,
) -> None:
    # ADR 0105: a handle never reaches the wire. A Handler can copy a real handle into a JSON body,
    # which the re-attach cannot read, so the row must fail closed rather than deliver the handle
    # unhydrated and be marked DONE (vault BACKLOG #2809).
    ref = await _store_doc(store, _big_b64(600))
    payload = '{"note": "' + make_doc_ref(ref, "application/pdf") + '"}'
    await store.enqueue_message(
        channel_id="c1", raw=payload, deliveries=[(DEST, payload)], now=100.0
    )
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    col = _Collector()
    runner._destinations[DEST] = col

    with pytest.raises((NegativeAckError, DeliveryError)):
        await _hydrate(runner, store, payload)
    item = await store.claim_next_fifo(DEST)
    assert item is not None
    await runner._process_delivery_item(DEST, item)

    assert col.deliveries == []
    assert (await store.stats()).get(OutboxStatus.DONE.value, 0) == 0


@pytest.mark.parametrize("breaks", [_without_an_msh, _with_a_bad_msh2], ids=["no-parse", "msh2"])
async def test_a_reattach_the_payload_breaks_dead_letters_the_row(
    store: MessageStore, breaks: Callable[[str], str]
) -> None:
    ref = await _store_doc(store, _big_b64(600))
    skeleton = breaks(_hl7_with_value(make_doc_ref(ref, "application/pdf")))
    mid = await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    col = _Collector()
    runner._destinations[DEST] = col
    # Under STOP the internal-error arm would halt the whole lane on this one message, which is how
    # the pre-fix code handled it. A permanent refusal never reaches that arm.
    runner._internal_error[DEST] = InternalErrorPolicy.STOP

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    outcome, retry_until = await runner._process_delivery_item(DEST, item)

    assert outcome is not _ItemOutcome.STOPPED
    assert retry_until is None  # not re-pended for a retry that could never succeed
    assert col.deliveries == []
    ((status, last_error),) = await _outbox_rows(store, mid)
    assert status == OutboxStatus.DEAD.value
    # The permanent refusal, not the internal-error arm.
    assert last_error.startswith("NegativeAckError: document re-attach failed:")


@pytest.mark.parametrize("policy", [InternalErrorPolicy.STOP, InternalErrorPolicy.CONTINUE])
async def test_a_stored_cr_takes_the_outbound_internal_error_policy(
    store: MessageStore, policy: InternalErrorPolicy
) -> None:
    # Vault BACKLOG #2809, the Lander's hold of 2026-11-01: a stored CR or LF is store corruption or
    # an engine bug, which is what STOP exists for, so STOP stops the lane and keeps the row, and the
    # default CONTINUE dead-letters it on the internal-error arm.
    ref = await _store_doc_with_a_cr(store)
    skeleton = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    mid = await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    runner, sink = _stop_runner(store)
    col = _Collector()
    runner._destinations[DEST] = col
    runner._internal_error[DEST] = policy

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    outcome, _ = await runner._process_delivery_item(DEST, item)

    assert col.deliveries == []
    ((status, last_error),) = await _outbox_rows(store, mid)
    if policy is InternalErrorPolicy.STOP:
        assert outcome is _ItemOutcome.STOPPED
        assert [name for name, _ in sink.stopped] == [DEST]
        assert status == OutboxStatus.PENDING.value  # kept for the operator, not dead-lettered
    else:
        assert outcome is not _ItemOutcome.STOPPED
        assert status == OutboxStatus.DEAD.value
        assert last_error.startswith("internal error: ValueError")  # the internal-error arm


# --- batch path -----------------------------------------------------------------------------------


async def test_batch_hydrates_every_member(store: MessageStore) -> None:
    from messagefoundry.parsing.split import split_batch

    a, b = _big_b64(600), _big_b64(800)
    ref_a, ref_b = await _store_doc(store, a), await _store_doc(store, b)
    sk_a = _hl7_with_value(make_doc_ref(ref_a, "application/pdf"))
    sk_b = _hl7_with_value(make_doc_ref(ref_b, "application/pdf"))
    await store.enqueue_message(channel_id="c1", raw=sk_a, deliveries=[(DEST, sk_a)], now=100.0)
    await store.enqueue_message(channel_id="c1", raw=sk_b, deliveries=[(DEST, sk_b)], now=101.0)

    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
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


class _FramingCollector(_Collector):
    """A collector that frames (defines ``check_frame``), so the batch takes the framing branch,
    where re-attach refusals join the frame check's. It refuses nothing, and counts its checks."""

    def __init__(self) -> None:
        super().__init__()
        self.checked = 0

    def check_frame(self, payload: str, *, rewrite: bool = True) -> None:
        self.checked += 1


@pytest.mark.parametrize("framing", [False, True], ids=["no-frame", "frame"])
async def test_a_batch_member_whose_reattach_breaks_is_dead_lettered_alone(
    store: MessageStore, caplog: pytest.LogCaptureFixture, framing: bool
) -> None:
    # Vault BACKLOG #2809: the permanent re-attach refusal is the one member's, as a frame refusal
    # is, so its healthy sibling still goes out in the envelope, on both branches of the batch.
    from messagefoundry.parsing.split import split_batch

    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    a = _big_b64(600)
    ref_a, ref_bad = await _store_doc(store, a), await _store_doc(store, _big_b64(700))
    sk_a = _hl7_with_value(make_doc_ref(ref_a, "application/pdf"))
    sk_bad = _with_a_bad_msh2(_hl7_with_value(make_doc_ref(ref_bad, "application/pdf")))
    await store.enqueue_message(channel_id="c1", raw=sk_bad, deliveries=[(DEST, sk_bad)], now=100.0)
    await store.enqueue_message(channel_id="c1", raw=sk_a, deliveries=[(DEST, sk_a)], now=101.0)

    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    col = _FramingCollector() if framing else _Collector()
    runner._destinations[DEST] = col
    runner._batch[DEST] = BatchConfig(max_count=5, max_wait_ms=1)
    runner._retry[DEST] = RetryPolicy()
    runner._simulate[DEST] = False

    head = await store.claim_next_fifo(DEST)
    assert head is not None
    await runner._process_delivery_batch(DEST, head, runner._batch[DEST])

    assert len(col.deliveries) == 1
    assert [Message.parse(m).field("OBX-5.5") for m in split_batch(col.deliveries[0])] == [a]
    if isinstance(col, _FramingCollector):
        assert col.checked == 1  # only the survivor reached the frame check
    stats = await store.stats()
    assert stats.get(OutboxStatus.DEAD.value, 0) == 1
    assert stats.get(OutboxStatus.DONE.value, 0) == 1
    # The member's line names the re-attach as its reason, never a frame check that did not run.
    (line,) = [r.getMessage() for r in caplog.records if "dead-lettered alone" in r.getMessage()]
    assert "its document cannot be re-attached" in line and "code 'reattach'" in line
    assert "frame" not in line


def _engine_value_error(*_args: object, **_kwargs: object) -> str:
    """Stands in for an engine bug in the re-attach: a ``ValueError`` the payload did not cause."""
    raise ValueError("engine bug in the re-attach")


class _StopRecorder(LoggingAlertSink):
    """Records each ``connection_stopped`` alert, so a STOP test reads the alert, not only the
    outcome (vault BACKLOG #5100)."""

    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


def _stop_runner(store: MessageStore) -> tuple[RegistryRunner, _StopRecorder]:
    sink = _StopRecorder()
    runner = RegistryRunner(
        Registry(), store, egress=EgressSettings(deny_by_default=False), alert_sink=sink
    )
    return runner, sink


async def _outbox_id(store: MessageStore, message_id: str) -> str:
    (row,) = await store.outbox_for(message_id)
    return str(row["id"])


async def test_an_engine_value_error_in_the_reattach_still_stops_a_stop_lane(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #2809: only the failures the payload causes are permanent refusals. Any other
    # ValueError is a possible engine fault, so it reaches the internal-error policy, and STOP stops
    # the lane, as before the permanent refusal existed. Never dead-letters it row by row.
    ref = await _store_doc(store, _big_b64(600))
    skeleton = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    runner, sink = _stop_runner(store)
    col = _Collector()
    runner._destinations[DEST] = col
    runner._internal_error[DEST] = InternalErrorPolicy.STOP
    monkeypatch.setattr(Message, "encode", _engine_value_error)

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    outcome, _ = await runner._process_delivery_item(DEST, item)

    assert outcome is _ItemOutcome.STOPPED
    assert [name for name, _ in sink.stopped] == [DEST]
    assert col.deliveries == []
    assert (await store.stats()).get(OutboxStatus.DEAD.value, 0) == 0


async def test_a_parser_fault_in_the_reattach_still_stops_a_stop_lane(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # parse_or_refuse turns a parser fault into an HL7PeekError; the re-attach must not read that one
    # as the payload's and dead-letter it (vault BACKLOG #2809).
    from messagefoundry.parsing import _builtin_hl7

    def _faulting_parse(*_args: object, **_kwargs: object) -> object:
        raise IndexError("parser bug")

    ref = await _store_doc(store, _big_b64(600))
    skeleton = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    runner, sink = _stop_runner(store)
    runner._destinations[DEST] = _Collector()
    runner._internal_error[DEST] = InternalErrorPolicy.STOP
    monkeypatch.setattr(_builtin_hl7, "parse", _faulting_parse)

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    outcome, _ = await runner._process_delivery_item(DEST, item)

    assert outcome is _ItemOutcome.STOPPED
    assert [name for name, _ in sink.stopped] == [DEST]
    assert (await store.stats()).get(OutboxStatus.DEAD.value, 0) == 0


class _RefusingFramer(_Collector):
    """A framing collector that refuses, permanently, any payload holding ``FRAMEBAD``."""

    def check_frame(self, payload: str, *, rewrite: bool = True) -> None:
        if "FRAMEBAD" in payload:
            raise NegativeAckError("frame refused", code="framing", permanent=True)


def _batch_runner(
    store: MessageStore, connector: _Collector
) -> tuple[RegistryRunner, _StopRecorder]:
    runner, sink = _stop_runner(store)
    runner._destinations[DEST] = connector
    runner._batch[DEST] = BatchConfig(max_count=5, max_wait_ms=1)
    runner._retry[DEST] = RetryPolicy()
    runner._simulate[DEST] = False
    return runner, sink


async def _run_batch(runner: RegistryRunner, store: MessageStore) -> _ItemOutcome:
    head = await store.claim_next_fifo(DEST)
    assert head is not None
    outcome, _ = await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    return outcome


async def test_an_engine_value_error_in_a_batch_reattach_still_stops_a_stop_lane(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The batch twin: a member whose re-attach raises an engine ValueError is not refused alone; the
    # whole batch takes the internal-error policy, and STOP stops the lane (vault BACKLOG #2809).
    ref = await _store_doc(store, _big_b64(600))
    skeleton = _hl7_with_value(make_doc_ref(ref, "application/pdf"))
    mid = await store.enqueue_message(
        channel_id="c1", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    col = _Collector()
    runner, sink = _batch_runner(store, col)
    runner._internal_error[DEST] = InternalErrorPolicy.STOP
    monkeypatch.setattr(Message, "encode", _engine_value_error)

    outcome = await _run_batch(runner, store)

    assert outcome is _ItemOutcome.STOPPED
    # The alert names the member by its outbox id (vault BACKLOG #5100).
    ((name, detail),) = sink.stopped
    assert name == DEST
    assert detail.endswith(f"; batch member {await _outbox_id(store, mid)}")
    assert col.deliveries == []
    assert (await store.stats()).get(OutboxStatus.DEAD.value, 0) == 0


async def _enqueue(store: MessageStore, payloads: Sequence[str]) -> tuple[list[str], list[str]]:
    """Enqueue one member per payload, in claim order, and return the message ids and the outbox
    ids, so a test can tell a middle member from the head and the last."""
    mids = [
        await store.enqueue_message(channel_id="c1", raw=sk, deliveries=[(DEST, sk)], now=100.0)
        for sk in payloads
    ]
    return mids, [await _outbox_id(store, m) for m in mids]


def _three(middle: str) -> list[str]:
    return [_hl7_with_value(v) for v in ("clean one", middle, "clean three")]


async def _rows(store: MessageStore, mids: Sequence[str]) -> list[tuple[str, str]]:
    return [row for m in mids for row in await _outbox_rows(store, m)]


@pytest.mark.parametrize("corrupt_head", [False, True], ids=["corrupt-second", "corrupt-head"])
@pytest.mark.parametrize("policy", [InternalErrorPolicy.STOP, InternalErrorPolicy.CONTINUE])
async def test_a_batch_member_with_a_stored_cr_takes_the_whole_batch_to_the_policy(
    store: MessageStore, policy: InternalErrorPolicy, corrupt_head: bool
) -> None:
    # The batch twin of the stored-CR case (vault BACKLOG #2809): not the member's own refusal, so
    # the whole batch takes the internal-error policy, sibling included. STOP stops the lane and
    # re-pends both; CONTINUE dead-letters both on the internal-error arm (ADR 0105, Phase 1b).
    a = _big_b64(600)
    ref_a, ref_bad = await _store_doc(store, a), await _store_doc_with_a_cr(store)
    sk_a = _hl7_with_value(make_doc_ref(ref_a, "application/pdf"))
    sk_bad = _hl7_with_value(make_doc_ref(ref_bad, "application/pdf"))
    # Both orders. claim_next_fifo claims in insert order, not by `now`, so the corrupt member is
    # the head only when it is enqueued first. With it last, naming the head instead fails; with it
    # first, naming the last member instead fails.
    if corrupt_head:
        (mid_bad, mid_a), _ = await _enqueue(store, [sk_bad, sk_a])
    else:
        (mid_a, mid_bad), _ = await _enqueue(store, [sk_a, sk_bad])
    col = _Collector()
    runner, sink = _batch_runner(store, col)
    runner._internal_error[DEST] = policy

    outcome = await _run_batch(runner, store)

    assert col.deliveries == []
    rows = await _outbox_rows(store, mid_bad) + await _outbox_rows(store, mid_a)
    assert len(rows) == 2
    # Every member's error names the corrupt member by its outbox id, and only that one, so an
    # operator can find it among the clean siblings it took along (vault BACKLOG #5100).
    named = f"; batch member {await _outbox_id(store, mid_bad)}"
    stored = f"batch member {await _outbox_id(store, mid_bad)}: "
    assert all(err.startswith(stored) for _, err in rows)
    assert await _outbox_id(store, mid_a) not in rows[0][1]
    if policy is InternalErrorPolicy.STOP:
        assert outcome is _ItemOutcome.STOPPED
        assert [status for status, _ in rows] == [OutboxStatus.PENDING.value] * 2
        ((name, detail),) = sink.stopped
        assert name == DEST and detail.endswith(named)
    else:
        assert outcome is not _ItemOutcome.STOPPED
        assert sink.stopped == []
        assert [status for status, _ in rows] == [OutboxStatus.DEAD.value] * 2
        assert all(err.startswith(f"{stored}internal error: ValueError") for _, err in rows)


async def test_a_stored_cr_in_the_middle_member_names_the_middle_member(
    store: MessageStore,
) -> None:
    # Vault BACKLOG #5100: with the corrupt member neither the head nor the last, naming either of
    # those instead fails. CONTINUE still dead-letters all three (option (a), ADR 0105).
    ref_bad = await _store_doc_with_a_cr(store)
    mids, ids = await _enqueue(store, _three(make_doc_ref(ref_bad, "application/pdf")))
    col = _Collector()
    runner, _ = _batch_runner(store, col)

    await _run_batch(runner, store)

    assert col.deliveries == []
    rows = await _rows(store, mids)
    assert [status for status, _ in rows] == [OutboxStatus.DEAD.value] * 3
    assert all(err.startswith(f"batch member {ids[1]}: internal error:") for _, err in rows)
    assert not any(ids[0] in err or ids[2] in err for _, err in rows)


@pytest.mark.parametrize(
    ("fault", "blames", "logs"),
    [
        (lambda: DeliveryError("attachment missing"), True, False),
        (lambda: wiring_runner._StoreReadFault("attachment read failed"), False, True),
        # A NegativeAckError is a DeliveryError, but its own arm comes first and marks no down edge.
        (lambda: _transient_refusal(), False, False),
    ],
    ids=["delivery-error", "store-read-fault", "transient-refusal"],
)
async def test_a_retryable_fault_in_the_middle_members_reattach_names_that_member(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fault: Callable[[], Exception],
    blames: bool,
    logs: bool,
) -> None:
    # Vault BACKLOG #5100: the arms that re-pend the batch name the member whose re-attach raised,
    # in every member's stored error; a DeliveryError blames it in the lane's down edge, and a store
    # read fault names it in its log line.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    mids, ids = await _enqueue(store, _three("FAULT"))
    runner, _ = _batch_runner(store, _Collector())
    real = runner._hydrate_payload

    async def _hydrate(payload: str, message_id: str) -> str:
        if "FAULT" in payload:
            raise fault()
        return await real(payload, message_id)

    monkeypatch.setattr(runner, "_hydrate_payload", _hydrate)
    blamed: list[str] = []
    monkeypatch.setattr(runner, "_note_lane_unhealthy", lambda _n, mid, _e: blamed.append(mid))

    await _run_batch(runner, store)

    named = f"; batch member {ids[1]}"
    rows = await _rows(store, mids)
    assert [status for status, _ in rows] == [OutboxStatus.PENDING.value] * 3
    lead = f"store read during batch member {ids[1]}: " if logs else f"batch member {ids[1]}: "
    assert all(err.startswith(lead) for _, err in rows)
    assert blamed == ([ids[1]] if blames else [])
    if logs:
        # The store-fault line's own text, not the retry-cap line, which also says "before sending".
        assert any(f"row(s){named};" in r.getMessage() for r in caplog.records)


async def test_a_long_error_still_names_the_member(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #5100: the store bounds last_error at 200 characters and keeps the head, so the
    # member is named first; a suffix after a long error was the part the cut dropped.
    mids, ids = await _enqueue(store, _three("FAULT"))
    runner, _ = _batch_runner(store, _Collector())
    real = runner._hydrate_payload

    async def _hydrate(payload: str, message_id: str) -> str:
        if "FAULT" in payload:
            # Many short tokens, so safe_exc keeps about 200 characters and the store cuts again.
            raise DeliveryError("document re-attach failed: " + "xx " * 150)
        return await real(payload, message_id)

    monkeypatch.setattr(runner, "_hydrate_payload", _hydrate)

    await _run_batch(runner, store)

    rows = await _rows(store, mids)
    assert all(err.startswith(f"batch member {ids[1]}: DeliveryError") for _, err in rows)
    # Positive control: the store's cut ran, so a suffix would have been the part it dropped.
    assert all(err.endswith(" chars)") for _, err in rows)


async def test_a_non_hl7_head_names_the_head(store: MessageStore) -> None:
    # Vault BACKLOG #5100: the head's parse for BHS-11 is that member's own step, so a non-HL7 head
    # names the head, not the last member.
    mids, ids = await _enqueue(store, ["not an HL7 message at all", _hl7_with_value("clean")])
    col = _Collector()
    runner, _ = _batch_runner(store, col)

    await _run_batch(runner, store)

    assert col.deliveries == []
    rows = await _rows(store, mids)
    assert [status for status, _ in rows] == [OutboxStatus.DEAD.value] * 2
    assert all(err.startswith(f"batch member {ids[0]}: internal error:") for _, err in rows)


async def test_an_encode_batch_fault_names_no_member(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #5100: encode_batch frames every member at once, so its fault names none rather
    # than the last member whose own step ran.
    mids, _ = await _enqueue(store, _three("clean two"))
    runner, _ = _batch_runner(store, _Collector())

    def _faulting_encode(*_args: object, **_kwargs: object) -> str:
        raise ValueError("encode bug")

    monkeypatch.setattr(wiring_runner, "encode_batch", _faulting_encode)

    await _run_batch(runner, store)

    rows = await _rows(store, mids)
    assert [status for status, _ in rows] == [OutboxStatus.DEAD.value] * 3
    assert not any("batch member" in err for _, err in rows)


async def test_a_send_fault_names_no_member_and_blames_the_envelope_head(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #5100: the send is the whole envelope's, so no member is named, and the lane's
    # down edge blames the envelope's head, as before members were named.
    mids, ids = await _enqueue(store, _three("clean two"))
    runner, _ = _batch_runner(store, _Collector(fail_times=1))
    blamed: list[str] = []
    monkeypatch.setattr(runner, "_note_lane_unhealthy", lambda _n, mid, _e: blamed.append(mid))

    await _run_batch(runner, store)

    rows = await _rows(store, mids)
    assert [status for status, _ in rows] == [OutboxStatus.PENDING.value] * 3
    assert not any("batch member" in err for _, err in rows)
    assert blamed == [ids[0]]


async def test_a_batch_with_both_kinds_of_refused_member_logs_them_in_claim_order(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # Vault BACKLOG #5100: a frame-refused member claimed BEFORE a re-attach-refused one is logged
    # first, in the lane's FIFO order, though the re-attach refusals are found first; each is
    # dead-lettered alone, and the clean member goes out.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    clean = _big_b64(600)
    ref_bad, ref_clean = await _store_doc(store, _big_b64(700)), await _store_doc(store, clean)
    sk_frame = _hl7_with_value("FRAMEBAD")
    sk_reattach = _with_a_bad_msh2(_hl7_with_value(make_doc_ref(ref_bad, "application/pdf")))
    sk_clean = _hl7_with_value(make_doc_ref(ref_clean, "application/pdf"))
    mids = [
        await store.enqueue_message(channel_id="c1", raw=sk, deliveries=[(DEST, sk)], now=t)
        for sk, t in ((sk_frame, 100.0), (sk_reattach, 101.0), (sk_clean, 102.0))
    ]
    col = _RefusingFramer()
    runner, _ = _batch_runner(store, col)

    await _run_batch(runner, store)

    assert len(col.deliveries) == 1
    frame_id, reattach_id, _ = [await _outbox_id(store, m) for m in mids]
    lines = [r.getMessage() for r in caplog.records if "dead-lettered alone" in r.getMessage()]
    named = [m[1] for line in lines if (m := re.search(r"batch member (\S+) refused", line))]
    assert named == [frame_id, reattach_id]
    assert "code 'framing'" in lines[0] and "code 'reattach'" in lines[1]
    statuses = [status for m in mids for status, _ in await _outbox_rows(store, m)]
    assert statuses == [OutboxStatus.DEAD.value, OutboxStatus.DEAD.value, OutboxStatus.DONE.value]


class _FaultingFramer(_Collector):
    """A framing collector whose check raises an internal error on any payload holding
    ``FRAMEBUG``: a connector fault, not a refusal of the member."""

    def check_frame(self, payload: str, *, rewrite: bool = True) -> None:
        if "FRAMEBUG" in payload:
            raise ValueError("connector bug in the frame check")


async def test_an_internal_error_in_a_members_frame_check_names_that_member(
    store: MessageStore,
) -> None:
    # Vault BACKLOG #5100: a frame check's internal error takes the whole batch to the policy, as a
    # re-attach's does, and names the member, here not the head, by its outbox id.
    mids = []
    for t, value in ((100.0, "clean"), (101.0, "FRAMEBUG")):
        sk = _hl7_with_value(value)
        mids.append(
            await store.enqueue_message(channel_id="c1", raw=sk, deliveries=[(DEST, sk)], now=t)
        )
    col = _FaultingFramer()
    runner, _ = _batch_runner(store, col)

    await _run_batch(runner, store)

    assert col.deliveries == []
    named = f"batch member {await _outbox_id(store, mids[1])}: internal error: ValueError"
    rows = await _rows(store, mids)
    assert [status for status, _ in rows] == [OutboxStatus.DEAD.value] * 2
    assert all(err.startswith(named) for _, err in rows)


def _credential_fault() -> NegativeAckError:
    return NegativeAckError("bad password", code="reattach", permanent=True, credential_fault=True)


def _transient_refusal() -> NegativeAckError:
    return NegativeAckError("try later", code="reattach", permanent=False)


@pytest.mark.parametrize(
    ("refusal", "stops"),
    [(_credential_fault, True), (_transient_refusal, False)],
    ids=["lane-stopping", "transient"],
)
async def test_a_batch_reattach_refusal_that_is_not_the_members_own_keeps_every_member(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    refusal: Callable[[], NegativeAckError],
    stops: bool,
) -> None:
    # Vault BACKLOG #5100: the hydration catch re-raises as the frame check does. A refusal that
    # must stop the lane (a credential fault) stops it, and one that is not permanent re-pends the
    # batch; either way every member is kept rather than one dead-lettered as its own refusal.
    for t in (100.0, 101.0):
        sk = _hl7_with_value(f"plain {t}")
        await store.enqueue_message(channel_id="c1", raw=sk, deliveries=[(DEST, sk)], now=t)
    runner, sink = _batch_runner(store, _Collector())

    async def _refuse(*_args: object) -> str:
        raise refusal()

    monkeypatch.setattr(runner, "_hydrate_payload", _refuse)
    outcome = await _run_batch(runner, store)

    assert (outcome is _ItemOutcome.STOPPED) is stops
    assert [name for name, _ in sink.stopped] == ([DEST] if stops else [])
    stats = await store.stats()
    assert stats.get(OutboxStatus.DEAD.value, 0) == 0
    assert stats.get(OutboxStatus.PENDING.value, 0) == 2


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
        _reg_shape_a(inbox, outdir),
        store,
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
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
    def _handler(msg):
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
        _reg_shape_b(inbox),
        store,
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
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
