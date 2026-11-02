# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A clean start row resolves ``posture_loosened`` only when the live posture reads clean too (vault
BACKLOG #2613).

The row's list is read off the graph the start's snapshot took, and its detail is fixed before its
commit, so a reload that lands in between leaves a clean, unmarked row over a loosened graph. These
run the real lifespan, the real row writer and the real posture reader. Only the process-wide
loosenings a test environment always has are filtered out, so that the row can read clean at all."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.api.app as app_module
from messagefoundry.api import create_managed_app
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.store import MessageStore
from tests.test_reload_dir_only_moves_on_apply import _write_valid_config
from tests.test_start_config_change_alert import _add_a_cleartext_hop

#: The one loosening these tests can turn on, by a graph reload.
_HOP_LOOSENING = "cleartext_accepted"


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    d = tmp_path / "cfg"
    _write_valid_config(d, tmp_path / "in", tmp_path / "out")
    return d


@pytest.fixture
def restored(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []
    monkeypatch.setattr(
        LoggingAlertSink, "posture_restored", lambda self, name: seen.append(name), raising=True
    )
    return seen


@pytest.fixture
def live_reads(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Keep only the hop loosening in every posture reading, and record the live readings: those
    with no ``graph`` passed, which is how the start's row differs from the route."""
    reads: list[list[str]] = []
    real = app_module._posture_loosenings

    def _only_the_hop(*args: Any, **kwargs: Any) -> tuple[list[tuple[str, str]], str | None]:
        pairs, scope = real(*args, **kwargs)
        kept = [pair for pair in pairs if pair[0] == _HOP_LOOSENING]
        if kwargs.get("graph") is None:
            reads.append([name for name, _ in kept])
        return kept, scope

    monkeypatch.setattr(app_module, "_posture_loosenings", _only_the_hop)
    return reads


def _reload_before_the_row_commits(monkeypatch: pytest.MonkeyPatch, cfg: Path) -> dict[str, Any]:
    """Swap the graph onto a loosened one as the row reaches its commit: past the swap check and
    past the point where the detail was built, so nothing marks the row."""
    seen: dict[str, Any] = {}
    real = MessageStore.record_audit

    async def _record(self: MessageStore, action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "config_loaded":
            seen["detail"] = kwargs.get("detail")
            _add_a_cleartext_hop(cfg)
            await seen["engine"]._converge_reload(1)
        return await real(self, action, *args, **kwargs)

    monkeypatch.setattr(MessageStore, "record_audit", _record)
    return seen


async def _serve(tmp_path: Path, cfg: Path, seen: dict[str, Any] | None = None) -> Engine:
    """One real start and stop, waiting inside it for the restore's read to finish."""
    app = create_managed_app(
        db_path=tmp_path / "start.db",
        config_dir=cfg,
        poll_interval=0.05,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    real_start = Engine.start

    async def _start_and_share(self: Engine) -> None:
        if seen is not None:
            seen["engine"] = self
        await real_start(self)

    with pytest.MonkeyPatch.context() as m:
        m.setattr(Engine, "start", _start_and_share)
        async with app.router.lifespan_context(app):
            engine: Engine = app.state.engine
            # Only the read's own task can be pending here; a bounded wait, never a fixed sleep.
            for _ in range(200):
                pending = [
                    t
                    for t in asyncio.all_tasks()
                    if getattr(t.get_coro(), "__name__", "") == "_resolve_if_clean"
                ]
                if not pending:
                    break
                await asyncio.wait(pending, timeout=0.05)
            return engine


async def test_a_plain_clean_start_with_a_clean_live_read_resolves(
    tmp_path: Path, cfg: Path, restored: list[str], live_reads: list[list[str]]
) -> None:
    await _serve(tmp_path, cfg)
    assert restored == ["posture:start"]
    assert live_reads == [[]]


async def test_a_reload_after_the_swap_check_and_before_the_row_leaves_the_alert_open(
    tmp_path: Path,
    cfg: Path,
    restored: list[str],
    live_reads: list[list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _reload_before_the_row_commits(monkeypatch, cfg)
    await _serve(tmp_path, cfg, seen)
    # The controls: this is the race itself. The row went out clean and unmarked.
    assert '"loosenings": []' in seen["detail"]
    assert "superseded" not in seen["detail"] and "baseline_unchecked" not in seen["detail"]
    assert restored == []
    assert live_reads == [[_HOP_LOOSENING]]


async def test_a_live_read_that_faults_leaves_the_alert_open(
    tmp_path: Path, cfg: Path, restored: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = app_module._posture_loosenings

    def _faults_when_live(*args: Any, **kwargs: Any) -> tuple[list[tuple[str, str]], str | None]:
        if kwargs.get("graph") is None:
            raise RuntimeError("synthetic posture fault")
        return [], real(*args, **kwargs)[1]

    monkeypatch.setattr(app_module, "_posture_loosenings", _faults_when_live)
    await _serve(tmp_path, cfg)
    assert restored == []


async def test_a_live_read_that_cannot_see_the_graph_is_not_a_clean_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no runner the reading declares a scope note and lists no hop. That is no clean reading."""
    monkeypatch.setattr(
        app_module,
        "_posture_loosenings",
        lambda *_a, **_k: ([], "the engine has no graph, so its hops are not listed"),
    )

    class _NoRunner:
        registry_runner = None

    assert not await app_module._live_posture_is_clean(object(), _NoRunner())  # type: ignore[arg-type]
