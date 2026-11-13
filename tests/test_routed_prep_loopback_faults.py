# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The transform stage's prepare step on a loopback row (BACKLOG #5708).

Two defects in :meth:`RegistryRunner._prepare_routed`, both on the reliability-invariant path:

* A loopback row whose correlation cannot be read (metadata that does not decrypt or is not JSON, a
  correlation id that is not a string, a captured reply that does not decrypt) raised before the
  method's ``try``. The caller took that as an infrastructure fault and re-pended the row, which fails
  the same way on every pass, at the head of a strict-FIFO lane. It must dead-letter instead.
* A reload that drops the inbound or the handler while the loopback reads await was read live
  afterwards, so it surfaced as a Handler error and the internal-error policy dead-lettered an ACKed
  message. It must be settled as the runner already settles a missing inbound or handler, on the
  split and the fused paths alike.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import MLLP, Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome, _RoutedPrep
from messagefoundry.store import FailOutcome, MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import CipherError, CipherUnavailableError, StoreKeylessError
from messagefoundry.store.store import OutboxItem

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
LOOP = "IB_LOOP"
HANDLER = "h_loop"
CLAIM_MODES = ["pooled", "per_lane"]


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "prep.db")
    yield s
    await s.close()


def _registry(calls: list[str]) -> Registry:
    reg = Registry()
    reg.add_inbound(build_inbound_connection(LOOP, Loopback(), router="route_loop"))
    reg.add_router("route_loop", lambda msg: [HANDLER])

    def h_loop(msg: Any) -> None:
        calls.append("ran")
        return None  # filter: the tests read whether the Handler ran, not what it sent

    reg.add_handler(HANDLER, h_loop)
    return reg


async def _routed_status(store: MessageStore, message_id: str) -> str | None:
    async with store._read() as db:
        cur = await db.execute(
            "SELECT status FROM queue WHERE message_id=? AND stage=?",
            (message_id, Stage.ROUTED.value),
        )
        row = await cur.fetchone()
    return None if row is None else str(row["status"])


async def _until(predicate: Callable[[], Awaitable[bool]], timeout: float = 5.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await predicate():
            return True
        await asyncio.sleep(0.02)
    return False


def _metadata(value: str) -> Callable[[str], Awaitable[str | None]]:
    async def read(message_id: str) -> str | None:
        return value

    return read


async def _undecryptable(*args: Any, **kwargs: Any) -> Any:
    raise CipherError("the tag did not verify")


# Each fault, as the patched store reads it: (metadata read, correlate_response read or None).
_FAULTS: dict[str, tuple[Callable[..., Awaitable[Any]], Callable[..., Awaitable[Any]] | None]] = {
    "metadata-not-json": (_metadata("{not json"), None),
    "correlation-id-not-a-string": (_metadata('{"correlation_id": 5}'), None),
    "metadata-does-not-decrypt": (_undecryptable, None),
    "reply-does-not-decrypt": (_metadata('{"correlation_id": "c-1"}'), _undecryptable),
}


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
@pytest.mark.parametrize("fault", sorted(_FAULTS))
async def test_an_unreadable_loopback_correlation_dead_letters_rather_than_wedging_the_lane(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, fault: str, claim_mode: str
) -> None:
    metadata_read, correlate_read = _FAULTS[fault]
    monkeypatch.setattr(store, "message_metadata_json", metadata_read)
    if correlate_read is not None:
        monkeypatch.setattr(store, "correlate_response", correlate_read)
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls),
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        egress=EgressSettings(deny_by_default=False),
    )
    message_id = await store.enqueue_ingress(channel_id=LOOP, raw=RAW)
    await runner.start()
    try:
        assert await _until(lambda: _dead(store, message_id)), (
            f"{fault}: the routed row was never dead-lettered (re-pended at the lane head)"
        )
    finally:
        await runner.stop()
    assert calls == [], "the Handler ran on a row whose correlation could not be read"
    message = await store.get_message(message_id)
    assert message is not None and message["status"] == MessageStatus.ERROR.value


async def _dead(store: MessageStore, message_id: str) -> bool:
    return await _routed_status(store, message_id) == OutboxStatus.DEAD.value


async def _routed_item(store: MessageStore) -> OutboxItem:
    """One claimed routed row on the loopback, for the handler, without starting a runner."""
    message_id = await store.enqueue_ingress(channel_id=LOOP, raw=RAW)
    ingress = await store.claim_next_fifo(LOOP, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=message_id,
        channel_id=LOOP,
        handlers=[(HANDLER, RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(LOOP, stage=Stage.ROUTED.value)
    assert routed is not None and routed.handler_name == HANDLER
    return routed


def _swapped_graph(dropped: str) -> Registry:
    """The graph a reload swaps in: it drops the inbound, or keeps it and drops the handler."""
    swapped = Registry()
    if dropped == "handler":
        swapped.add_inbound(build_inbound_connection(LOOP, Loopback(), router="route_loop"))
        swapped.add_router("route_loop", lambda msg: [])
    return swapped


@pytest.mark.parametrize("dropped", ["inbound", "handler"])
async def test_a_reload_during_the_loopback_read_is_not_a_handler_error(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    dropped: str,
) -> None:
    # The dispositions are the ones _process_routed_item gives the same two cases before any await:
    # a missing inbound reverts the row retry-forever and stops the lane, and a missing handler
    # dead-letters it. Never the internal-error policy, which would treat the reload as a Handler
    # fault.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    swapped = _swapped_graph(dropped)

    async def read_during_a_reload(message_id: str) -> str | None:
        runner.registry = swapped
        return None

    monkeypatch.setattr(store, "message_metadata_json", read_during_a_reload)
    outcome = await runner._process_routed_item(LOOP, item)

    assert calls == [], "the Handler ran under a graph the reload had replaced"
    status = await _routed_status(store, item.message_id)
    if dropped == "inbound":
        assert outcome == (_ItemOutcome.STOPPED, None)
        assert status == OutboxStatus.PENDING.value, "a reload alone dead-lettered an ACKed row"
    else:
        assert outcome == (_ItemOutcome.PROCESSED, None)
        assert status == OutboxStatus.DEAD.value
        # The missing-handler dead-letter, not the internal-error policy's "handler error".
        assert "is missing; dead-lettering" in caplog.text


class _Recorder:
    def __init__(self) -> None:
        self.dead: list[tuple[str, str]] = []
        self.failed: list[tuple[str, str, Any]] = []


def _spy_settlements(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> _Recorder:
    rec = _Recorder()

    async def dead_letter_now(item_id: str, reason: str) -> None:
        rec.dead.append((item_id, reason))

    async def mark_failed(item_id: str, reason: str, policy: Any) -> FailOutcome:
        rec.failed.append((item_id, reason, policy))
        return FailOutcome(retry_at=1.0, head_id=item_id, attempts=1)

    monkeypatch.setattr(store, "dead_letter_now", dead_letter_now)
    monkeypatch.setattr(store, "mark_failed", mark_failed)
    return rec


def _fused_item() -> OutboxItem:
    return OutboxItem(
        id="rtd-1",
        message_id="m-1",
        channel_id=LOOP,
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.ROUTED.value,
        handler_name=HANDLER,
    )


@pytest.mark.parametrize("case", ["unreadable", "inbound", "handler"])
async def test_the_fused_path_settles_the_row_as_the_split_path_does(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    # The fused (SQL Server) path reads the loopback correlation the same way and must settle each
    # case the same way, before anything is dispatched to its executor.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    runner._fusion_active = True
    # Only asserted non-None before the read: every case here settles before the executor is used.
    runner._fuse_transform_executor = cast(Any, object())
    if case == "unreadable":
        monkeypatch.setattr(store, "message_metadata_json", _metadata("{not json"))
    else:
        swapped = _swapped_graph(case)

        async def read_during_a_reload(message_id: str) -> str | None:
            runner.registry = swapped
            return None

        monkeypatch.setattr(store, "message_metadata_json", read_during_a_reload)
    rec = _spy_settlements(monkeypatch, store)

    outcome = await runner._process_routed_item(LOOP, _fused_item())

    assert calls == []
    if case == "inbound":
        assert outcome == (_ItemOutcome.STOPPED, None)
        assert rec.dead == []
        assert [(i, r) for i, r, _ in rec.failed] == [("rtd-1", "inbound not in registry")]
        assert rec.failed[0][2].max_attempts is None  # retry-forever, never dead-lettered
    else:
        assert outcome == (_ItemOutcome.PROCESSED, None)
        assert rec.failed == []
        assert len(rec.dead) == 1 and rec.dead[0][0] == "rtd-1"
        expected = "not JSON" if case == "unreadable" else "removed from registry"
        assert expected in rec.dead[0][1]


async def test_a_reload_before_prepare_that_drops_the_whole_feed_reverts_the_row(
    store: MessageStore,
) -> None:
    # The concurrent batch path awaits a semaphore before it calls _prepare_routed. A reload in
    # that wait that drops the inbound AND its handler must revert the row, as a missing inbound
    # always is, not dead-letter it as a missing handler.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    runner.registry = _swapped_graph("inbound")  # drops the inbound, its router and the handler

    prep = await runner._prepare_routed(LOOP, item)

    assert prep.inbound_gone and not prep.missing_handler
    assert calls == []


async def test_prepare_reads_the_inbound_type_from_the_live_graph(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A reload in the concurrent path's semaphore wait that keeps the inbound's name but makes it
    # a loopback must feed the Handler its replies: prepare decides by the graph it transforms
    # under, never by an inbound the batch read before the wait.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    reads: list[str] = []

    async def read(message_id: str) -> str | None:
        reads.append(message_id)
        return None

    monkeypatch.setattr(store, "message_metadata_json", read)
    plain = Registry()
    plain.add_inbound(build_inbound_connection(LOOP, MLLP(port=0), router="route_loop"))
    plain.add_router("route_loop", lambda msg: [HANDLER])
    plain.add_handler(HANDLER, lambda msg: None)
    runner.registry = plain
    await runner._prepare_routed(LOOP, item)
    assert reads == [], "a non-loopback inbound read loopback metadata"

    runner.registry = _registry(calls)
    prep = await runner._prepare_routed(LOOP, item)
    assert reads == [item.message_id] and prep.outcome is not None


@pytest.mark.parametrize("value", ["false", "0", '""', "[]", "{}", "null"])
async def test_a_falsy_correlation_id_still_means_no_correlation(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    # Before BACKLOG #5708 any falsy correlation id ran the Handler with no replies. Only a
    # non-string that carries a value is unreadable.
    monkeypatch.setattr(store, "message_metadata_json", _metadata(f'{{"correlation_id": {value}}}'))
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)

    prep = await runner._prepare_routed(LOOP, item)

    assert prep.outcome is not None and prep.unreadable is None
    assert calls == ["ran"]


def _transit_unreachable() -> CipherError:
    try:
        raise OSError("connection refused")
    except OSError as cause:
        err = CipherError("transit call failed")
        err.__cause__ = cause
        return err


_OUTAGES: dict[str, Callable[[], Exception]] = {
    "unavailable": lambda: CipherUnavailableError("transit unreachable"),
    "transit-oserror": _transit_unreachable,
}


@pytest.mark.parametrize(
    ("outage", "read"),
    [(o, r) for o in sorted(_OUTAGES) for r in ("metadata", "reply")]
    + [("keyless-open", "metadata")],
)
async def test_a_key_service_outage_re_pends_rather_than_dead_letters(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, read: str, outage: str
) -> None:
    # A cipher that gave no verdict on the value (an unreachable Vault Transit), or a keyless open
    # that hands encrypted metadata back unchanged, is the engine failing, not the row. That stays
    # an infrastructure fault, so the row re-pends and drains once the fault is fixed, rather than
    # every loopback row in the outage being dead-lettered.
    async def failing(*args: Any, **kwargs: Any) -> Any:
        raise _OUTAGES[outage]()

    if outage == "keyless-open":
        monkeypatch.setattr(store, "message_metadata_json", _metadata("mfenc:v4:AAAA"))
    elif read == "metadata":
        monkeypatch.setattr(store, "message_metadata_json", failing)
    else:
        monkeypatch.setattr(store, "message_metadata_json", _metadata('{"correlation_id": "c-1"}'))
        monkeypatch.setattr(store, "correlate_response", failing)
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)

    expected: type[Exception] = StoreKeylessError if outage == "keyless-open" else CipherError
    with pytest.raises(expected):
        await runner._process_routed_item(LOOP, item)
    assert calls == []
    # Raised to the worker's backoff with the row still claimed: never dead-lettered.
    assert await _routed_status(store, item.message_id) == OutboxStatus.INFLIGHT.value


@pytest.mark.parametrize("stale", ["inbound_gone", "missing_handler"])
async def test_a_stale_settle_decision_runs_the_row_under_the_restored_graph(
    store: MessageStore, stale: str
) -> None:
    # The concurrent path decides a missing inbound or handler in prepare and applies it later,
    # after earlier siblings' handoffs await. A reload that put them back in that window must not
    # see the row reverted with its lane STOPPED (that reload found the worker alive and re-armed
    # nothing) or dead-lettered: nothing ran, so the row runs under the graph that is live now.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)

    prep = (
        _RoutedPrep(inbound_gone=True)
        if stale == "inbound_gone"
        else _RoutedPrep(missing_handler=True)
    )
    outcome = await runner._apply_routed(LOOP, item, prep)

    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert calls == ["ran"]
    assert await _routed_status(store, item.message_id) is None, "the routed row was not handed off"


@pytest.mark.parametrize("stale", ["inbound_gone", "missing_handler"])
async def test_a_partial_restore_settles_the_row_by_the_live_graph(
    store: MessageStore, caplog: pytest.LogCaptureFixture, stale: str
) -> None:
    # A reload between the concurrent path's prepare and its apply can restore only one of the two.
    # Apply settles by the graph live now, never by the stale prep. The inbound back without its
    # handler dead-letters the row as a missing handler (replayable) and the lane keeps running, as
    # main's CONTINUE policy did when the live inbound lookup raised in this race; the stale
    # inbound_gone would have reverted the row and stopped a lane no later reload re-arms. The
    # converse, a stale missing_handler whose inbound a reload has since dropped, reverts the row
    # with its feed, inbound first, as on entry to prepare.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    if stale == "inbound_gone":
        prep = _RoutedPrep(inbound_gone=True)
        runner.registry = _swapped_graph("handler")  # the inbound came back, the handler did not
    else:
        prep = _RoutedPrep(missing_handler=True)
        runner.registry = _swapped_graph("inbound")  # the whole feed is gone now

    outcome = await runner._apply_routed(LOOP, item, prep)

    assert calls == []
    status = await _routed_status(store, item.message_id)
    if stale == "inbound_gone":
        assert outcome == (_ItemOutcome.PROCESSED, None), "a live inbound's lane was stopped"
        assert status == OutboxStatus.DEAD.value
        assert "is missing; dead-lettering" in caplog.text
    else:
        assert outcome == (_ItemOutcome.STOPPED, None)
        assert status == OutboxStatus.PENDING.value, "a reload alone dead-lettered an ACKed row"


async def test_a_reload_during_an_unreadable_read_reverts_rather_than_dead_letters(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A reload that drops the whole feed while the read awaits wins over the row's own refusal,
    # inbound first, as on entry: the row reverts with its feed rather than being dead-lettered.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)

    async def unreadable_during_a_reload(message_id: str) -> str | None:
        runner.registry = _swapped_graph("inbound")
        return "{not json"

    monkeypatch.setattr(store, "message_metadata_json", unreadable_during_a_reload)

    prep = await runner._prepare_routed(LOOP, item)

    assert prep.inbound_gone and prep.unreadable is None


async def test_mfenc_text_under_a_keyed_cipher_is_the_rows_fault(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only the identity cipher hands an mfenc: cell back unchanged. A keyed cipher that decrypted
    # a value to mfenc: text decrypted a corrupt value, so the row dead-letters rather than
    # re-pending forever under a false "no key is configured".
    runner = RegistryRunner(
        _registry([]), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    monkeypatch.setattr(store, "message_metadata_json", _metadata("mfenc:v4:AAAA"))
    monkeypatch.setattr(store, "cipher", lambda: SimpleNamespace(encrypts=True))

    prep = await runner._prepare_routed(LOOP, item)

    assert prep.unreadable is not None and "not JSON" in str(prep.unreadable)
