# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 B5 PR3 — dispatch-wiring tests (non-gated, run in normal CI).

These prove the DISPATCH WIRING in ``_process_ingress_item`` / ``_process_routed_item`` in isolation:
with ``_fusion_active`` forced True on a SQLite store and the fused callables monkeypatched to return
CANNED ``_FusedRouteResult`` / ``_FusedTransformResult`` records, each branch of the two fused
dispatch bodies is exercised:

* CONTENT (``route_exc`` / ``xform_exc``) → the factored internal-error policy (CONTINUE dead-letters,
  STOP marks-failed + alerts) — the SAME helper the async except block now calls;
* INFRA (``handoff_exc``) → the exception PROPAGATES out of ``_process_*_item`` (→ the drain-lane T17
  re-pend), never a content dead-letter;
* success → the loop-side wakes (ROUTED for route; OUTBOUND + INGRESS fan-out for transform) and, for
  transform, ``publish_state_cache(applied_state)`` (the sync twin never mutates the loop-owned cache);
* the gate: INLINE (ingress) and ``_fusion_active`` False both keep the ASYNC path (fused callable NOT
  invoked) — byte-identical default;
* the missing-handler guard STAYS ahead of the fused transform branch (PR2-review prerequisite #1);
* the factored ``_apply_*_internal_error`` helpers reproduce the pre-refactor except-block outcomes
  (STOP + CONTINUE) exactly.

No live DB and NO ``pyodbc``/``aioodbc`` import — the fused callables persisting real rows on live SQL
Server are covered by the gated ``test_adr0071_dispatch_wiring_sqlserver.py``. No hashlib/hmac/secrets/
ssl here (crypto-inventory gate)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, InternalErrorPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    _FusedRouteResult,
    _FusedTransformResult,
    _ItemOutcome,
)
from messagefoundry.store import MessageStatus, MessageStore, OutboxItem, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "dispatch.db")
    yield s
    await s.close()


def _runner(store: MessageStore, *, router: Any = None, handler: Any = None) -> RegistryRunner:
    """IB (FILE, HL7V2) → router r → handler h (Send OB1) → outbound OB1. Nothing binds (never
    started); the fused callables are monkeypatched, so no connectors are built."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-out"})
        )
    )
    reg.add_router("r", router or (lambda m: ["h"]))
    reg.add_handler("h", handler or (lambda m: Send("OB1", "OUTBODY")))
    return RegistryRunner(reg, store, claim_mode="pooled")


def _ingress_item(iid: str = "ing-1", mid: str = "m-1") -> OutboxItem:
    return OutboxItem(
        id=iid,
        message_id=mid,
        channel_id="IB",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.INGRESS.value,
    )


def _routed_item(iid: str = "rtd-1", mid: str = "m-1", handler_name: str = "h") -> OutboxItem:
    return OutboxItem(
        id=iid,
        message_id=mid,
        channel_id="IB",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.ROUTED.value,
        handler_name=handler_name,
    )


class _Spy:
    """Tiny call recorder for async store spies + sync alert/wake spies (installed via monkeypatch)."""

    def __init__(self) -> None:
        self.calls: list[Any] = []


def _spy_wakes(monkeypatch: pytest.MonkeyPatch, runner: RegistryRunner) -> _Spy:
    wakes = _Spy()
    monkeypatch.setattr(runner, "_wake_lane", lambda stage, key: wakes.calls.append((stage, key)))
    return wakes


def _spy_dead_letter(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> _Spy:
    dl = _Spy()

    async def _dl(item_id: str, reason: str) -> None:
        dl.calls.append((item_id, reason))

    monkeypatch.setattr(store, "dead_letter_now", _dl)
    return dl


def _spy_mark_failed(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> _Spy:
    mf = _Spy()

    async def _mf(item_id: str, reason: str, policy: Any) -> None:
        mf.calls.append((item_id, reason, policy))

    monkeypatch.setattr(store, "mark_failed", _mf)
    return mf


def _spy_connection_stopped(monkeypatch: pytest.MonkeyPatch, runner: RegistryRunner) -> _Spy:
    cs = _Spy()
    monkeypatch.setattr(
        runner._alert_sink,
        "connection_stopped",
        lambda name, detail: cs.calls.append((name, detail)),
    )
    return cs


# ============================ ingress (route) dispatch ============================


async def test_ingress_route_exc_continue_dead_letters(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CONTENT: route_exc set, CONTINUE (default) policy ⇒ dead_letter_now + (PROCESSED, None), and
    # NO ROUTED wake fires on a content error.
    runner = _runner(store)
    runner._fusion_active = True
    seen = _Spy()

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        seen.calls.append((name, item.id))
        return _FusedRouteResult(
            names=[],
            disposition=None,
            handed_off=False,
            route_exc=ValueError("router boom"),
            handoff_exc=None,
            wake_target=None,
        )

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    dl = _spy_dead_letter(monkeypatch, store)
    wakes = _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_ingress_item("IB", _ingress_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert seen.calls == [("IB", "ing-1")]  # the fused route callable WAS dispatched
    assert dl.calls and dl.calls[0][0] == "ing-1"
    assert dl.calls[0][1].startswith("router error:")
    assert wakes.calls == []


async def test_ingress_route_exc_stop(store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> None:
    # CONTENT + STOP policy ⇒ mark_failed (ingest-stopped reason) + connection_stopped + (STOPPED, None).
    runner = _runner(store)
    runner._fusion_active = True
    runner._internal_error_default = InternalErrorPolicy.STOP

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedRouteResult([], None, False, ValueError("router boom"), None, None)

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    mf = _spy_mark_failed(monkeypatch, store)
    cs = _spy_connection_stopped(monkeypatch, runner)

    outcome = await runner._process_ingress_item("IB", _ingress_item())
    assert outcome == (_ItemOutcome.STOPPED, None)
    assert mf.calls and mf.calls[0][0] == "ing-1"
    assert mf.calls[0][1].startswith("router error (ingest stopped):")
    assert mf.calls[0][2] is runner._delivery_defaults
    assert cs.calls == [("IB", "router ValueError on ing-1")]


async def test_ingress_handoff_exc_propagates(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # INFRA: handoff_exc set ⇒ the exception PROPAGATES out of _process_ingress_item (→ drain-lane T17
    # re-pend), never a content dead-letter.
    runner = _runner(store)
    runner._fusion_active = True
    boom = RuntimeError("sync-pool acquire / handoff commit fault")

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedRouteResult(["h"], MessageStatus.ROUTED, False, None, boom, None)

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    dl = _spy_dead_letter(monkeypatch, store)

    with pytest.raises(RuntimeError) as ei:
        await runner._process_ingress_item("IB", _ingress_item())
    assert ei.value is boom
    assert dl.calls == []  # INFRA is NOT a content dead-letter


async def test_ingress_wake_target_routed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Success with a wake_target ⇒ _wake_lane(ROUTED, target) + (PROCESSED, None).
    runner = _runner(store)
    runner._fusion_active = True

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedRouteResult(["h"], MessageStatus.ROUTED, True, None, None, "IB")

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    wakes = _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_ingress_item("IB", _ingress_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert wakes.calls == [(Stage.ROUTED, "IB")]


async def test_ingress_wake_target_none(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Success with wake_target None (UNROUTED) ⇒ NO wake + (PROCESSED, None).
    runner = _runner(store)
    runner._fusion_active = True

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedRouteResult([], MessageStatus.UNROUTED, True, None, None, None)

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    wakes = _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_ingress_item("IB", _ingress_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert wakes.calls == []


async def test_ingress_inline_skips_fusion(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # INLINE (ingress) keeps the ASYNC path even when _fusion_active is True: the fused callable is NOT
    # invoked (the async inline fast-path lands on store.handoff instead).
    runner = _runner(store)
    runner._fusion_active = True
    runner._inline_ok["IB"] = True
    called = _Spy()

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        called.calls.append((name, item.id))
        return _FusedRouteResult([], None, False, None, None, None)

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    ho = _Spy()

    async def _handoff(**kwargs: Any) -> bool:
        ho.calls.append(kwargs)
        return True

    monkeypatch.setattr(store, "handoff", _handoff)
    _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_ingress_item("IB", _ingress_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert called.calls == []  # fused NOT invoked — the async inline path was taken
    assert ho.calls and ho.calls[0]["disposition"] is MessageStatus.ROUTED


async def test_ingress_fusion_off_skips_fusion(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # _fusion_active False ⇒ the ASYNC (non-inline) split path runs: fused callable NOT invoked,
    # store.route_handoff hit, ROUTED lane woken. Byte-identical default.
    runner = _runner(store)
    assert runner._fusion_active is False
    called = _Spy()

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        called.calls.append((name, item.id))
        return _FusedRouteResult([], None, False, None, None, None)

    monkeypatch.setattr(runner, "_fused_route_and_handoff", fake)
    rh = _Spy()

    async def _route_handoff(**kwargs: Any) -> bool:
        rh.calls.append(kwargs)
        return True

    monkeypatch.setattr(store, "route_handoff", _route_handoff)
    wakes = _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_ingress_item("IB", _ingress_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert called.calls == []  # fused NOT invoked
    assert rh.calls and rh.calls[0]["disposition"] is MessageStatus.ROUTED
    assert wakes.calls == [(Stage.ROUTED, "IB")]


# ============================ routed (transform) dispatch ============================


async def test_routed_xform_exc_continue_dead_letters(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CONTENT: xform_exc set, CONTINUE (default) ⇒ dead_letter_now + (PROCESSED, None).
    runner = _runner(store)
    runner._fusion_active = True
    seen = _Spy()

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        seen.calls.append((name, item.id))
        return _FusedTransformResult([], [], [], ValueError("handler boom"), None, (), ())

    monkeypatch.setattr(runner, "_fused_transform_and_handoff", fake)
    dl = _spy_dead_letter(monkeypatch, store)

    outcome = await runner._process_routed_item("IB", _routed_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert seen.calls == [("IB", "rtd-1")]
    assert dl.calls and dl.calls[0][0] == "rtd-1"
    assert dl.calls[0][1].startswith("handler error:")


async def test_routed_xform_exc_stop(store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> None:
    # CONTENT + STOP ⇒ mark_failed (transform-stopped reason) + connection_stopped + (STOPPED, None).
    runner = _runner(store)
    runner._fusion_active = True
    runner._internal_error_default = InternalErrorPolicy.STOP

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedTransformResult([], [], [], ValueError("handler boom"), None, (), ())

    monkeypatch.setattr(runner, "_fused_transform_and_handoff", fake)
    mf = _spy_mark_failed(monkeypatch, store)
    cs = _spy_connection_stopped(monkeypatch, runner)

    outcome = await runner._process_routed_item("IB", _routed_item())
    assert outcome == (_ItemOutcome.STOPPED, None)
    assert mf.calls and mf.calls[0][0] == "rtd-1"
    assert mf.calls[0][1].startswith("handler error (transform stopped):")
    assert cs.calls == [("IB", "handler ValueError on rtd-1")]


async def test_routed_handoff_exc_propagates(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # INFRA: handoff_exc set ⇒ the exception PROPAGATES out of _process_routed_item (→ T17 re-pend).
    runner = _runner(store)
    runner._fusion_active = True
    boom = RuntimeError("transform handoff commit fault")

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedTransformResult([("OB1", "B")], [], [], None, boom, (), ())

    monkeypatch.setattr(runner, "_fused_transform_and_handoff", fake)
    pub = _Spy()
    # publish_state_cache is SS-only (absent on the SQLite MessageStore) — install it as a spy.
    monkeypatch.setattr(
        store, "publish_state_cache", lambda applied: pub.calls.append(applied), raising=False
    )

    with pytest.raises(RuntimeError) as ei:
        await runner._process_routed_item("IB", _routed_item())
    assert ei.value is boom
    assert pub.calls == []  # never publish on a faulted handoff


async def test_routed_success_publishes_and_wakes(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Success ⇒ publish_state_cache(applied_state) on the LOOP + OUTBOUND fan-out wake per dest +
    # INGRESS wake per PT target + (PROCESSED, None).
    runner = _runner(store)
    runner._fusion_active = True
    applied = [(("ns", "k"), {"v": 7})]

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        return _FusedTransformResult(
            deliveries=[("OB1", "B")],
            pt_deliveries=[("PTX", "B")],
            applied_state=applied,
            xform_exc=None,
            handoff_exc=None,
            outbound_wakes=("OB1",),
            ingress_wakes=("PTX",),
        )

    monkeypatch.setattr(runner, "_fused_transform_and_handoff", fake)
    pub = _Spy()
    # publish_state_cache is SS-only (absent on the SQLite MessageStore) — install it as a spy.
    monkeypatch.setattr(store, "publish_state_cache", lambda a: pub.calls.append(a), raising=False)
    wakes = _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_routed_item("IB", _routed_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert pub.calls == [applied]
    assert wakes.calls == [(Stage.OUTBOUND, "OB1"), (Stage.INGRESS, "PTX")]


async def test_routed_missing_handler_guard_before_fusion(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The missing-handler guard STAYS ahead of the fused branch: a routed row for an unknown handler is
    # dead-lettered by the guard and the fused callable is NEVER reached (PR2-review prerequisite #1 —
    # the fused transform only asserts hname is not None, it does NOT check registry membership).
    runner = _runner(store)
    runner._fusion_active = True
    called = _Spy()

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        called.calls.append((name, item.id))
        return _FusedTransformResult([], [], [], None, None, (), ())

    monkeypatch.setattr(runner, "_fused_transform_and_handoff", fake)
    dl = _spy_dead_letter(monkeypatch, store)

    outcome = await runner._process_routed_item("IB", _routed_item(handler_name="ghost"))
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert called.calls == []  # fused NEVER reached
    assert dl.calls and dl.calls[0][0] == "rtd-1"


async def test_routed_fusion_off_skips_fusion(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # _fusion_active False ⇒ the ASYNC transform path runs: fused callable NOT invoked, store
    # .transform_handoff hit, OUTBOUND lane woken. Byte-identical default.
    runner = _runner(store)
    assert runner._fusion_active is False
    called = _Spy()

    async def fake(name: str, ic: Any, item: OutboxItem, *, now: float | None = None) -> Any:
        called.calls.append((name, item.id))
        return _FusedTransformResult([], [], [], None, None, (), ())

    monkeypatch.setattr(runner, "_fused_transform_and_handoff", fake)
    th = _Spy()

    async def _transform_handoff(**kwargs: Any) -> bool:
        th.calls.append(kwargs)
        return True

    monkeypatch.setattr(store, "transform_handoff", _transform_handoff)
    wakes = _spy_wakes(monkeypatch, runner)

    outcome = await runner._process_routed_item("IB", _routed_item())
    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert called.calls == []  # fused NOT invoked
    assert th.calls and th.calls[0]["deliveries"] == [("OB1", "OUTBODY")]
    assert wakes.calls == [(Stage.OUTBOUND, "OB1")]


# ============================ factored internal-error helpers ============================
# Direct unit tests: the factored helpers reproduce the pre-refactor except-block outcomes exactly.


async def test_apply_router_internal_error_continue(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store)
    dl = _spy_dead_letter(monkeypatch, store)
    out = await runner._apply_router_internal_error("IB", _ingress_item(), ValueError("x"))
    assert out == (_ItemOutcome.PROCESSED, None)
    assert dl.calls[0][0] == "ing-1"
    assert dl.calls[0][1].startswith("router error:")


async def test_apply_router_internal_error_stop(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store)
    runner._internal_error_default = InternalErrorPolicy.STOP
    mf = _spy_mark_failed(monkeypatch, store)
    cs = _spy_connection_stopped(monkeypatch, runner)
    out = await runner._apply_router_internal_error("IB", _ingress_item(), ValueError("x"))
    assert out == (_ItemOutcome.STOPPED, None)
    assert mf.calls[0][1].startswith("router error (ingest stopped):")
    assert mf.calls[0][2] is runner._delivery_defaults
    assert cs.calls[0] == ("IB", "router ValueError on ing-1")


async def test_apply_transform_internal_error_continue(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store)
    dl = _spy_dead_letter(monkeypatch, store)
    out = await runner._apply_transform_internal_error("IB", _routed_item(), ValueError("x"))
    assert out == (_ItemOutcome.PROCESSED, None)
    assert dl.calls[0][0] == "rtd-1"
    assert dl.calls[0][1].startswith("handler error:")


async def test_apply_transform_internal_error_stop(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store)
    runner._internal_error_default = InternalErrorPolicy.STOP
    mf = _spy_mark_failed(monkeypatch, store)
    cs = _spy_connection_stopped(monkeypatch, runner)
    out = await runner._apply_transform_internal_error("IB", _routed_item(), ValueError("x"))
    assert out == (_ItemOutcome.STOPPED, None)
    assert mf.calls[0][1].startswith("handler error (transform stopped):")
    assert cs.calls[0] == ("IB", "handler ValueError on rtd-1")
