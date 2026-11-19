# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Stopping one reply_from listener drains only that listener's rendezvous (BACKLOG #5893).

The runner holds one ReplyRendezvous. Before the fix every reply_from source bound its drain to
that one instance, and only ``__init__`` cleared the latch, so stopping any one listener woke every
sibling's waiting turns with ``shutting_down`` and made every later arm on every listener raise
``RendezvousFull`` -- a ``degraded`` answer -- until the process restarted. The unit tests pin the
scope contract; the runner test pins that the runner hands each listener start its own scope.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ContentType, OrderingMode, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    Http,
    Registry,
    Rest,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.reply_wait import RendezvousFull, ReplyRendezvous
from messagefoundry.pipeline.sync_reply import SyncReplyResolverImpl
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from tests._harness_engine import free_port

KEY = ("m1", "OB_PARTNER")


def test_draining_one_scope_leaves_a_sibling_waiting_and_arming() -> None:
    root = ReplyRendezvous()
    a, b = root.scope(), root.scope()
    with a.arm("ma", "OB_PARTNER") as wa, b.arm("mb", "OB_PARTNER") as wb:
        a.drain("shutting_down")
        assert wa.drain_reason == "shutting_down"
        assert wb.drain_reason is None, "a sibling listener's turn was aborted"
    with b.arm(*KEY) as again:  # the sibling still arms after the drain
        assert again.drain_reason is None
    with pytest.raises(RendezvousFull), a.arm(*KEY):
        pass


def test_a_fresh_scope_arms_after_a_drained_one() -> None:
    root = ReplyRendezvous()
    root.scope().drain("shutting_down")
    with root.scope().arm(*KEY) as waiter:  # the listener's next start
        assert waiter.drain_reason is None


async def test_a_root_signal_reaches_a_scoped_waiter() -> None:
    root = ReplyRendezvous()
    scope = root.scope()
    with scope.arm(*KEY) as waiter:
        assert root.waiters == 1
        root.signal(*KEY)
        assert waiter._event.is_set(), "a delivery hint on the root missed the scoped waiter"
    assert root.waiters == 0


def test_a_root_drain_still_reaches_every_scope() -> None:
    root = ReplyRendezvous()
    a, b = root.scope(), root.scope()
    with a.arm("ma", "OB") as wa, b.arm("mb", "OB") as wb:
        root.drain("shutting_down")
        assert wa.drain_reason == wb.drain_reason == "shutting_down"
    with pytest.raises(RendezvousFull), root.scope().arm(*KEY):
        pass


def test_the_cap_is_shared_across_scopes() -> None:
    root = ReplyRendezvous(max_waiters=1)
    with (
        root.scope().arm("m1", "OB"),
        pytest.raises(RendezvousFull),
        root.scope().arm("m2", "OB"),
    ):
        pass


def _scope_of(runner: RegistryRunner, name: str) -> ReplyRendezvous:
    resolver = runner._sources[name].sync_reply
    assert isinstance(resolver, SyncReplyResolverImpl)
    return resolver._rendezvous


async def test_stopping_one_listener_does_not_latch_the_other(tmp_path: Path) -> None:
    reg = Registry()
    for name in ("IB_A", "IB_B"):
        reg.add_inbound(
            build_inbound_connection(
                name,
                Http(port=free_port(), reply_from="OB_PARTNER"),
                router="r",
                content_type=ContentType.JSON,
            )
        )
    reg.add_outbound(
        build_outbound_connection(
            "OB_PARTNER",
            Rest(url="https://partner.example/ingest", capture_response=True),
            ordering=OrderingMode.UNORDERED,
            retry=RetryPolicy(max_attempts=3),
        )
    )
    reg.add_router("r", lambda m: [])
    store = await MessageStore.open(tmp_path / "b616_5893.db")
    try:
        runner = RegistryRunner(
            reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
        )
        await runner.start()
        try:
            # A lost port race isolates a listener (ADR 0031) rather than raising; name that cause.
            assert {"IB_A", "IB_B"} <= runner._sources.keys(), "a listener failed to start"
            scope_a, scope_b = _scope_of(runner, "IB_A"), _scope_of(runner, "IB_B")
            with (
                scope_a.arm("ma", "OB_PARTNER") as stopped,
                scope_b.arm("mb", "OB_PARTNER") as waiting,
            ):
                # The runner's delivery hint goes to its root and reaches a listener's scope.
                runner._reply_rendezvous.signal("mb", "OB_PARTNER")
                assert waiting._event.is_set(), "the runner's hint missed IB_B's waiter"
                await runner.stop_inbound("IB_A")
                # IB_A's stop reached its own turn through the drain the runner bound ...
                assert stopped.drain_reason == "shutting_down"
                # ... and no other listener's.
                assert waiting.drain_reason is None, "IB_A's stop aborted IB_B's waiting turn"
            with scope_b.arm(*KEY) as later:
                assert later.drain_reason is None
            await runner.start_inbound("IB_A")
            with _scope_of(runner, "IB_A").arm(*KEY) as restarted:
                assert restarted.drain_reason is None
        finally:
            await runner.stop()
    finally:
        await store.close()
