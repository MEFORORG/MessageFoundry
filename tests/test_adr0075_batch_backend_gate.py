# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0075 AC-4 — backend gate + byte-identical-when-OFF sentinel + fail-closed activation.

* With the flag OFF, the handoffs NEVER touch the batching machinery (``_render_batch`` is never
  called) — the default path is byte-identical to before ADR 0075 (the pooled/fusion-style sentinel).
* The batched surface exists ONLY on the SQL Server store; MessageStore/PostgresStore have neither the
  batched methods nor the activation setter, so the flag is a provable no-op there.
* The runner activation is fail-closed: a store without ``set_batch_handoff_statements`` logs "ignored"
  and returns False; a SQL Server store flips the flag and returns True.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from messagefoundry.config.settings import PipelineSettings
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.store import MessageStore
from messagefoundry.store.sqlserver import SqlServerStore

import adr0075_batch_harness as h


@pytest.fixture(autouse=True)
def _restore(monkeypatch: pytest.MonkeyPatch) -> object:
    saved_uuid = ss.uuid4
    yield
    ss.uuid4 = saved_uuid  # type: ignore[assignment]


def test_flag_default_off() -> None:
    assert PipelineSettings().batch_handoff_statements is False


async def test_off_path_never_renders_a_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sentinel: with the flag OFF, no batch is ever rendered -> the OFF path cannot have changed shape.
    calls = {"render": 0}
    real_render = ss._render_batch

    def _spy(group: object) -> object:
        calls["render"] += 1
        return real_render(group)  # type: ignore[arg-type]

    monkeypatch.setattr(ss, "_render_batch", _spy)

    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    await h.drive_async(
        h.bare_store(batch=False),
        "route_handoff",
        cursor=h.AsyncRecCursor(),
        conn=h.RecConn(),
        **h.ROUTE_KWARGS,
    )
    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    await h.drive_async(
        h.bare_store(batch=False),
        "transform_handoff",
        cursor=h.AsyncRecCursor(),
        conn=h.RecConn(),
        **h.TRANSFORM_KWARGS,
    )
    assert calls["render"] == 0  # OFF: batching machinery untouched


async def test_on_path_does_render_a_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    # Control for the sentinel above: with the flag ON, a batch IS rendered (proves the OFF assertion is
    # meaningful, not a machinery that never runs).
    calls = {"render": 0}
    real_render = ss._render_batch

    def _spy(group: object) -> object:
        calls["render"] += 1
        return real_render(group)  # type: ignore[arg-type]

    monkeypatch.setattr(ss, "_render_batch", _spy)
    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    await h.drive_async(
        h.bare_store(batch=True),
        "route_handoff",
        cursor=h.BatchRecCursor(),
        conn=h.RecConn(),
        **h.ROUTE_KWARGS,
    )
    assert calls["render"] > 0


async def test_pt_deliveries_fall_back_to_unbatched_even_when_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The rare PT re-ingress branch is deliberately NOT batched: with the flag ON, a transform carrying
    # pt_deliveries must NOT dispatch to the batched form (it stays on the proven unbatched path).
    store = h.bare_store(batch=True)

    def _boom(**_kwargs: object) -> object:
        raise AssertionError("pt_deliveries must not be batched")

    monkeypatch.setattr(store, "_transform_handoff_batched", _boom)
    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    handed_off = await h.drive_async(
        store,
        "transform_handoff",
        cursor=h.AsyncRecCursor(),
        conn=h.RecConn(),
        routed_id="rtd-pt",
        message_id="m-pt",
        channel_id="IB",
        deliveries=[("OB1", "b1")],
        state_ops=(),
        pt_deliveries=[("PT", "MSH|child")],
        now=100.0,
    )
    assert handed_off is True  # completed on the unbatched path, no batching attempted


def test_batched_surface_only_on_sqlserver() -> None:
    for attr in (
        "_route_handoff_batched",
        "_transform_handoff_batched",
        "_maybe_finalize_batched",
        "set_batch_handoff_statements",
        "batch_handoff_statements",
    ):
        assert hasattr(SqlServerStore, attr), attr
    # No batched surface leaks onto the other backends — the flag is a provable no-op there.
    for attr in (
        "_route_handoff_batched",
        "_transform_handoff_batched",
        "set_batch_handoff_statements",
    ):
        assert not hasattr(MessageStore, attr), attr
        assert not hasattr(PostgresStore, attr), attr


def test_set_batch_handoff_statements_toggles_and_returns_effective() -> None:
    store = h.bare_store(batch=False)
    assert store.batch_handoff_statements is False
    assert store.set_batch_handoff_statements(True) is True
    assert store.batch_handoff_statements is True
    assert store.set_batch_handoff_statements(False) is False
    assert store.batch_handoff_statements is False


def _bare_runner(*, flag: bool, store: object, fusion_active: bool = False) -> RegistryRunner:
    runner = object.__new__(RegistryRunner)
    runner._batch_handoff_statements = flag  # type: ignore[attr-defined]
    runner._fusion_active = fusion_active  # type: ignore[attr-defined]
    runner.store = store  # type: ignore[assignment]
    return runner


def test_runner_activation_active_on_sqlserver() -> None:
    recorded: dict[str, object] = {}

    def _setter(enabled: bool) -> bool:
        recorded["enabled"] = enabled
        return enabled

    store = SimpleNamespace(
        set_batch_handoff_statements=_setter,
        backend=SimpleNamespace(value="sqlserver"),
    )
    runner = _bare_runner(flag=True, store=store)
    assert runner._activate_statement_batching() is True
    assert recorded["enabled"] is True


def test_runner_activation_logs_confounder_note_when_fusion_also_active(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Item 4: both levers on -> a startup WARNING that fused hops run unbatched (non-additive A/B).
    store = SimpleNamespace(
        set_batch_handoff_statements=lambda enabled: enabled,
        backend=SimpleNamespace(value="sqlserver"),
    )
    runner = _bare_runner(flag=True, store=store, fusion_active=True)
    import logging

    with caplog.at_level(logging.WARNING):
        assert runner._activate_statement_batching() is True
    assert any("NOT additive" in r.message for r in caplog.records)


def test_runner_activation_fail_closed_on_non_sqlserver() -> None:
    # A store without the setter (Postgres/SQLite) -> "ignored", returns False, nothing switched on.
    store = SimpleNamespace(backend=SimpleNamespace(value="postgres"))
    runner = _bare_runner(flag=True, store=store)
    assert runner._activate_statement_batching() is False


def test_runner_activation_off_when_flag_off() -> None:
    def _setter(enabled: bool) -> bool:
        raise AssertionError("must not be called when the flag is off")

    store = SimpleNamespace(
        set_batch_handoff_statements=_setter, backend=SimpleNamespace(value="sqlserver")
    )
    runner = _bare_runner(flag=False, store=store)
    assert runner._activate_statement_batching() is False
