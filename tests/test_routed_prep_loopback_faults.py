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
  message. The row must finish under the graph it started with.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import CipherError
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


@pytest.mark.parametrize("dropped", ["inbound", "handler"])
async def test_a_reload_during_the_loopback_read_is_not_a_handler_error(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, dropped: str
) -> None:
    calls: list[str] = []
    runner = RegistryRunner(
        _registry(calls), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    item = await _routed_item(store)
    ic = runner.registry.inbound[LOOP]

    # The reload lands while the loopback read awaits: the swapped graph drops the inbound, or keeps
    # it and drops the handler.
    swapped = Registry()
    if dropped == "handler":
        swapped.add_inbound(build_inbound_connection(LOOP, Loopback(), router="route_loop"))
        swapped.add_router("route_loop", lambda msg: [])

    async def read_during_a_reload(message_id: str) -> str | None:
        runner.registry = swapped
        return None

    monkeypatch.setattr(store, "message_metadata_json", read_during_a_reload)
    prep = await runner._prepare_routed(LOOP, ic, item)

    assert prep.error is None, f"a reload that dropped the {dropped} read as a Handler error"
    assert prep.outcome is not None and calls == ["ran"]
