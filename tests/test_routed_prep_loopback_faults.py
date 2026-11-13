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

from messagefoundry.config.models import InternalErrorPolicy, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import MLLP, Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline import stage_dispatcher, wiring_runner
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
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    stale: str,
) -> None:
    # A reload between the concurrent path's prepare and its apply can restore only one of the two.
    # Apply settles by the graph live now, never by the stale prep. The inbound back without its
    # handler dead-letters the row as a missing handler (replayable) and the lane keeps running, as
    # the runner before BACKLOG #5708 did under the default CONTINUE policy, when the live inbound
    # lookup raised in this race (under STOP it stopped the lane, as a Handler fault); the stale
    # inbound_gone would have reverted the row and stopped a lane no later reload re-arms. The
    # converse, a stale missing_handler whose inbound a reload has since dropped, reverts the row
    # with its feed, inbound first, as on entry to prepare.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    policies: list[Any] = []
    real_mark_failed = store.mark_failed

    async def mark_failed(item_id: str, reason: str, policy: Any) -> FailOutcome:
        policies.append(policy)
        return await real_mark_failed(item_id, reason, policy)

    monkeypatch.setattr(store, "mark_failed", mark_failed)
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
        assert policies == []
        assert "is missing; dead-lettering" in caplog.text
    else:
        assert outcome == (_ItemOutcome.STOPPED, None)
        assert status == OutboxStatus.PENDING.value, "a reload alone dead-lettered an ACKed row"
        assert len(policies) == 1 and policies[0].max_attempts is None  # retry-forever


async def test_a_partial_restore_between_prepare_and_apply_keeps_the_batch_running(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # The same race through the concurrent batch path, the one path that applies a prep after an
    # await. Sibling S2's prepare sees its feed dropped (inbound_gone); a reload then restores the
    # inbound and S1's handler but not S2's before the serial apply. S1 hands off, S2 dead-letters
    # as a missing handler, and the batch does not stop the lane.
    calls: list[str] = []

    def graph(*, with_h2: bool) -> Registry:
        reg = Registry()
        reg.add_inbound(build_inbound_connection(LOOP, Loopback(), router="route_loop"))
        reg.add_router("route_loop", lambda msg: [HANDLER, "h_two"])
        reg.add_handler(HANDLER, lambda msg: calls.append(HANDLER))
        if with_h2:
            reg.add_handler("h_two", lambda msg: calls.append("h_two"))
        return reg

    runner = RegistryRunner(
        graph(with_h2=True), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    runner._transform_concurrency = 2
    message_id = await store.enqueue_ingress(channel_id=LOOP, raw=RAW)
    ingress = await store.claim_next_fifo(LOOP, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=message_id,
        channel_id=LOOP,
        handlers=[(HANDLER, RAW), ("h_two", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    items = await store.claim_next_fifo_batch(LOOP, stage=Stage.ROUTED.value, limit=2)
    assert [it.handler_name for it in items] == [HANDLER, "h_two"]

    real_prepare = runner._prepare_routed
    s1_prepared = asyncio.Event()

    async def prepare(name: str, item: OutboxItem, **kwargs: Any) -> _RoutedPrep:
        if item.handler_name == HANDLER:
            try:
                return await real_prepare(name, item, **kwargs)
            finally:
                s1_prepared.set()  # a raise in S1 fails the test rather than hanging S2
        await s1_prepared.wait()  # S1 has run under the full graph; now the feed is dropped
        runner.registry = Registry()
        prep = await real_prepare(name, item, **kwargs)
        runner.registry = graph(with_h2=False)  # the reload restores all but S2's handler
        return prep

    runner._prepare_routed = prepare  # type: ignore[method-assign]

    stopped = await runner._process_routed_batch(LOOP, items)

    assert stopped is False, "a partial restore stopped a lane the restoring reload found alive"
    assert calls == [HANDLER]
    async with store._read() as db:
        cur = await db.execute(
            "SELECT handler_name, status FROM queue WHERE message_id=? AND stage=?",
            (message_id, Stage.ROUTED.value),
        )
        rows = [(r["handler_name"], r["status"]) for r in await cur.fetchall()]
    assert rows == [("h_two", OutboxStatus.DEAD.value)], "S1 not handed off, or S2 not dead"
    # As a missing handler, not through the internal-error policy, which CONTINUE also dead-letters.
    assert "handler 'h_two'" in caplog.text and "is missing; dead-lettering" in caplog.text


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


# --- A reload that restores the inbound while its transform lane stops (BACKLOG #5708) -------------
#
# The lane stops on a row whose inbound a reload dropped during the loopback read. A second reload
# that deploys the inbound again lands before that STOP ends: in the revert's mark_failed, in the
# per-lane worker's tail release, or in the pooled adapter after the item. It finds the worker alive
# (per-lane) or the lane PROCESSING (pooled), so it re-arms nothing. The lane must keep running and
# drain the reverted row. The runner before BACKLOG #5708 dead-lettered that row under CONTINUE in
# this race and kept the lane up, so a lane left down is a regression against it.

_WINDOWS = [
    ("per_lane", "mark_failed"),
    ("per_lane", "release_tail"),
    ("pooled", "mark_failed"),
    ("pooled", "after_item"),
]


class _Race:
    """Drops the whole feed by a real reload during the first loopback read, then, unless
    ``restore`` is None, deploys it again by a real reload in the named window."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        store: MessageStore,
        runner: RegistryRunner,
        full: Registry,
        restore: str | None,
    ) -> None:
        self.runner = runner
        self.full = full
        self.restore = restore
        self.dropped = False
        self.restored = False
        real_read = store.message_metadata_json
        real_mark_failed = store.mark_failed

        async def read(message_id: str) -> str | None:
            if not self.dropped:
                self.dropped = True
                await runner.reload(Registry())
            return await real_read(message_id)

        async def mark_failed(item_id: str, reason: str, policy: Any) -> FailOutcome:
            # The same retry-forever revert, with a short backoff so the drain is quick to see.
            if policy.max_attempts is None:
                policy = RetryPolicy(max_attempts=None, backoff_seconds=0.05)
            out = await real_mark_failed(item_id, reason, policy)
            await self._restore_in("mark_failed")
            return out

        monkeypatch.setattr(store, "message_metadata_json", read)
        monkeypatch.setattr(store, "mark_failed", mark_failed)
        real_release = runner._release_tail_on_stop

        async def release(worker: str, name: str, ids: Any) -> bool:
            released = await real_release(worker, name, ids)
            if worker == "transform":
                await self._restore_in("release_tail")
            return released

        monkeypatch.setattr(runner, "_release_tail_on_stop", release)
        real_buildup = runner._pooled_maybe_buildup

        async def buildup(lane: str, stage: str) -> None:
            await real_buildup(lane, stage)
            if stage == Stage.ROUTED.value:  # the router's adapter calls it too
                await self._restore_in("after_item")

        monkeypatch.setattr(runner, "_pooled_maybe_buildup", buildup)

    async def _restore_in(self, window: str) -> None:
        if self.restore == window and self.dropped and not self.restored:
            self.restored = True
            await self.runner.reload(self.full)


def _lane_down(runner: RegistryRunner) -> bool:
    if runner._claim_mode == "pooled":
        return runner._dispatchers[Stage.ROUTED].stopped(LOOP)
    task = runner._transform_workers.get(LOOP)
    return task is None or task.done()


@pytest.mark.parametrize(("claim_mode", "window"), _WINDOWS)
async def test_a_reload_that_restores_the_inbound_while_its_lane_stops_keeps_it_running(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, claim_mode: str, window: str
) -> None:
    calls: list[str] = []
    full = _registry(calls)
    runner = RegistryRunner(
        full,
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        egress=EgressSettings(deny_by_default=False),
    )
    race = _Race(monkeypatch, store, runner, full, restore=window)
    message_id = await store.enqueue_ingress(channel_id=LOOP, raw=RAW)
    await runner.start()
    try:

        async def drained() -> bool:
            return calls == ["ran"] and await _routed_status(store, message_id) is None

        assert await _until(drained), (
            f"{claim_mode}/{window}: the restored inbound's reverted row was never transformed"
        )
        assert race.restored, "the restoring reload never ran in its window"
        assert calls == ["ran"]
        assert not _lane_down(runner), "the transform lane is down with its inbound deployed"
    finally:
        await runner.stop()


async def _routed_rows(store: MessageStore, count: int) -> list[str]:
    """Enqueue ``count`` messages and route each, so its ROUTED row waits; their message ids."""
    message_ids = []
    for _ in range(count):
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
        message_ids.append(message_id)
    return message_ids


async def test_a_restore_does_not_keep_a_worker_draining_past_a_tail_it_could_not_release(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same race with a batch tail whose release fails: those rows stay in flight. A pooled lane
    # that kept draining would claim the newer row past them, so it must stop, restore or not.
    # infra_fault_stop_after=1 ends the pooled serializer's retry of the release at its first
    # failure (EXHAUSTED). The per-lane worker re-pends such a tail instead, and the per-lane test
    # below covers it.
    calls: list[str] = []
    full = _registry(calls)
    message_ids = await _routed_rows(store, 4)
    runner = RegistryRunner(
        full,
        store,
        poll_interval=0.02,
        claim_mode="pooled",
        fifo_claim_batch=3,
        infra_fault_stop_after=1,
        egress=EgressSettings(deny_by_default=False),
    )
    race = _Race(monkeypatch, store, runner, full, restore="mark_failed")

    async def release_claimed(ids: Any) -> None:
        raise RuntimeError("store fault")

    monkeypatch.setattr(store, "release_claimed", release_claimed)
    await runner.start()
    try:

        async def down() -> bool:
            return race.restored and _lane_down(runner)

        assert await _until(down), "the worker kept draining past a tail it could not release"
        await asyncio.sleep(0.2)  # well past the revert's backoff
        assert calls == [], "a row was transformed past rows still in flight"
        statuses = [await _routed_status(store, m) for m in message_ids]
        assert statuses == [
            OutboxStatus.PENDING.value,
            OutboxStatus.INFLIGHT.value,
            OutboxStatus.INFLIGHT.value,
            OutboxStatus.PENDING.value,
        ]
    finally:
        await runner.stop()


@pytest.mark.parametrize("repend", ["lands", "fails"])
@pytest.mark.parametrize("window", ["mark_failed", "release_tail"])
async def test_a_per_lane_release_fault_in_the_restore_window_does_not_take_the_lane_down(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, window: str, repend: str
) -> None:
    # The restore lands while the per-lane worker stops, and its one release of the batch tail
    # fails. The STOP is void, so the worker re-pends the tail, held, as its except arm does. Once
    # that lands, the lane keeps running and drains every row, as it does when the release lands.
    # While it fails, the worker holds the lane and transforms nothing past the rows in flight.
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    calls: list[str] = []
    full = _registry(calls)
    message_ids = await _routed_rows(store, 4)
    runner = RegistryRunner(
        full,
        store,
        poll_interval=0.02,
        claim_mode="per_lane",
        fifo_claim_batch=3,
        egress=EgressSettings(deny_by_default=False),
    )
    race = _Race(monkeypatch, store, runner, full, restore=window)
    faults = {"release_claimed": 0, "reschedule_claimed": 0}

    async def release_claimed(ids: Any) -> None:
        faults["release_claimed"] += 1
        raise RuntimeError("store fault")

    monkeypatch.setattr(store, "release_claimed", release_claimed)
    if repend == "fails":

        async def reschedule_claimed(ids: Any, when: float) -> None:
            faults["reschedule_claimed"] += 1
            raise RuntimeError("store fault")

        monkeypatch.setattr(store, "reschedule_claimed", reschedule_claimed)
    await runner.start()
    try:
        if repend == "lands":

            async def drained() -> bool:
                statuses = [await _routed_status(store, m) for m in message_ids]
                return calls == ["ran"] * 4 and statuses == [None] * 4

            assert await _until(drained), (
                f"{window}: a failed tail release left the restored inbound's lane down"
            )
        else:

            async def holding() -> bool:
                return faults["reschedule_claimed"] >= 3

            assert await _until(holding), "the worker did not retry the failed tail release"
            assert calls == [], "a row was transformed past rows still in flight"
            statuses = [await _routed_status(store, m) for m in message_ids]
            assert statuses == [
                OutboxStatus.PENDING.value,
                OutboxStatus.INFLIGHT.value,
                OutboxStatus.INFLIGHT.value,
                OutboxStatus.PENDING.value,
            ]
        assert race.restored, "the restoring reload never ran in its window"
        assert faults["release_claimed"] >= 1, "the tail release never failed"
        assert not _lane_down(runner), "the transform lane is down with its inbound deployed"
    finally:
        await runner.stop()


@pytest.mark.parametrize("end", ["landed", "exhausted", "superseded"])
async def test_a_pooled_stop_whose_tail_release_did_not_land_stays_stopped(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, end: str
) -> None:
    # A pooled transform STOP that the runner says is void goes READY only once its tail is pending
    # again. A release that ends SUPERSEDED (another node led since the claim, so its recovery may
    # hold the rows) or EXHAUSTED (the stop policy's bound) leaves the rows in flight, so the lane
    # stays STOPPED: READY, its next claim would pass them. `landed` is the positive control.
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    await _routed_rows(store, 3)
    items = await store.claim_next_fifo_batch(LOOP, stage=Stage.ROUTED.value, limit=3)
    assert len(items) == 3
    tail = [it.id for it in items[1:]]
    epoch = 7
    asked: list[str] = []

    def stop_rearmed(lane: str) -> bool:
        asked.append(lane)
        return True  # the runner says a reload voided this STOP

    dispatcher = stage_dispatcher.StageDispatcher(
        Stage.ROUTED,
        store,
        process_item=None,  # type: ignore[arg-type]  # _drain_lane is replaced below
        lane_provider=set,
        per_lane_limit=3,
        stop_rearmed=stop_rearmed,
        infra_fault_policy="stop" if end == "exhausted" else "retry_forever",
        infra_fault_stop_after=1 if end == "exhausted" else 10,
        is_leader=lambda: True,
        current_epoch=lambda: epoch,
    )

    async def drained(lane: str, claimed: Any) -> Any:
        # The body stopped on the head, as _apply_routed does for a missing inbound.
        return stage_dispatcher._LaneOutcome(stage_dispatcher.LaneResultKind.STOP), tail, None

    monkeypatch.setattr(dispatcher, "_drain_lane", drained)
    real_release = store.release_claimed

    async def release_claimed(ids: list[str]) -> Any:
        nonlocal epoch
        if end == "landed":
            return await real_release(ids)
        if end == "superseded":
            epoch = 8  # another node took the lease while this write failed
        raise RuntimeError("store fault")

    monkeypatch.setattr(store, "release_claimed", release_claimed)
    dispatcher._states[LOOP] = stage_dispatcher._LaneState(
        phase=stage_dispatcher._LanePhase.PROCESSING
    )
    await asyncio.wait_for(dispatcher._run_lane(LOOP, items), timeout=5.0)
    statuses = {await _routed_status(store, it.message_id) for it in items[1:]}
    if end == "landed":
        assert dispatcher.phase(LOOP) is stage_dispatcher._LanePhase.READY
        assert asked == [LOOP]
        assert statuses == {OutboxStatus.PENDING.value}
    else:
        assert dispatcher.stopped(LOOP), f"{end}: a lane holding rows in flight was re-armed"
        assert statuses == {OutboxStatus.INFLIGHT.value}


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_reload_that_leaves_the_inbound_removed_still_stops_its_lane(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, claim_mode: str
) -> None:
    # The converse: with no restore, the lane stops and the row waits, reverted, for a reload that
    # deploys its inbound again. Nothing keeps a worker or a lane looping on a removed inbound.
    calls: list[str] = []
    full = _registry(calls)
    runner = RegistryRunner(
        full,
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        egress=EgressSettings(deny_by_default=False),
    )
    _Race(monkeypatch, store, runner, full, restore=None)
    message_id = await store.enqueue_ingress(channel_id=LOOP, raw=RAW)
    await runner.start()
    try:

        async def down() -> bool:
            return _lane_down(runner)

        assert await _until(down), "a lane whose inbound is gone kept running"
        await asyncio.sleep(0.2)  # well past the revert's backoff: nothing re-arms it
        assert _lane_down(runner)
        assert calls == []
        assert await _routed_status(store, message_id) == OutboxStatus.PENDING.value
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_content_stop_stays_stopped_when_a_reload_lands_while_it_stops(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, claim_mode: str
) -> None:
    # Only a STOP for a missing inbound is voided. The internal-error STOP policy stops the lane
    # for a Handler fault, and a reload that lands during that STOP's mark_failed, with the inbound
    # deployed throughout, must not undo it: the runner holds that STOP for an operator.
    full = Registry()
    full.add_inbound(build_inbound_connection(LOOP, Loopback(), router="route_loop"))
    full.add_router("route_loop", lambda msg: [HANDLER])

    def h_fails(msg: Any) -> None:
        raise ValueError("handler fault")

    full.add_handler(HANDLER, h_fails)
    runner = RegistryRunner(
        full,
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        internal_error_default=InternalErrorPolicy.STOP,
        egress=EgressSettings(deny_by_default=False),
    )
    real_mark_failed = store.mark_failed
    reloaded: list[bool] = []

    async def mark_failed(item_id: str, reason: str, policy: Any) -> FailOutcome:
        out = await real_mark_failed(item_id, reason, policy)
        if not reloaded:
            reloaded.append(True)
            await runner.reload(full)
        return out

    monkeypatch.setattr(store, "mark_failed", mark_failed)
    await store.enqueue_ingress(channel_id=LOOP, raw=RAW)
    await runner.start()
    try:

        async def down() -> bool:
            return _lane_down(runner)

        assert await _until(down), "a content STOP did not stop the lane"
        assert reloaded, "the reload never ran in the STOP's window"
        await asyncio.sleep(0.2)
        assert _lane_down(runner), "a reload landing mid-STOP voided a content STOP"
    finally:
        await runner.stop()


async def test_a_re_prepare_reads_the_batch_snapshot(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A concurrent batch's stale inbound_gone, re-prepared under the restored graph, must read the
    # batch's frozen state like its siblings, not the live state an earlier sibling may have
    # committed to.
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    seen: list[Any] = []
    real_prepare = runner._prepare_routed

    async def prepare(name: str, it: OutboxItem, **kwargs: Any) -> _RoutedPrep:
        seen.append(kwargs.get("state_snapshot"))
        return await real_prepare(name, it, **kwargs)

    monkeypatch.setattr(runner, "_prepare_routed", prepare)
    snapshot: dict[tuple[str, str], Any] = {}

    outcome = await runner._apply_routed(
        LOOP, item, _RoutedPrep(inbound_gone=True), state_snapshot=snapshot
    )

    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert calls == ["ran"]
    assert len(seen) == 1 and seen[0] is snapshot, "the re-prepare read live state"
