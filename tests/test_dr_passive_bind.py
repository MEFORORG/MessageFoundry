# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A passive DR standby binds no inbound listener until it is activated (vault BACKLOG #3140).

ADR 0048's load-balancer fence moves the service VIP to the node that answers: "only a live,
bound node answers". A box with ``[dr].enabled = true`` and ``activate = false`` used to bind its
whole graph, so it answered on every listener and the balancer could send it live traffic. Each
test here starts the engine the way ``serve`` does, through :func:`create_managed_app`, and asks
the real ports whether anything accepts a connection.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from messagefoundry.api import create_managed_app
from messagefoundry.api.app import _alert_control_action
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_dr_running_config_dir import _CRIT, _NORM
from tests.test_dr_running_config_dir import _write_tiered_graph as _write_graph


async def _accepts(port: int) -> bool:
    """Whether anything on this box accepts a TCP connection on ``port``: what an L4 health check
    asks."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=2.0
        )
    except (OSError, TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


@asynccontextmanager
async def _served(tmp_path: Path, cfg: Path, dr: DrSettings) -> AsyncIterator[Engine]:
    """The engine ``serve`` builds, through its lifespan, with ``cfg`` as the config dir."""
    app = create_managed_app(
        db_path=tmp_path / "dr-passive.db",
        config_dir=cfg,
        poll_interval=0.05,
        dr_settings=dr,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app):
        engine: Engine = app.state.engine
        yield engine


async def test_a_box_that_is_not_a_dr_standby_binds_both_listeners(tmp_path: Path) -> None:
    """The control arm: the probe below finds a bound listener, so its False is not a dead probe."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path)
    async with _served(tmp_path, cfg, DrSettings()):
        assert await _accepts(crit_port) and await _accepts(norm_port)


async def test_a_passive_standby_binds_nothing_and_an_activation_binds_the_critical_feed(
    tmp_path: Path,
) -> None:
    """Red before #3140: the passive box accepted on both ports. Activation binds the critical
    feed and parks the normal one, and a release then a reload return to binding nothing."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        assert not await _accepts(crit_port) and not await _accepts(norm_port)
        assert set(rr.filtered_inbound()) == {_CRIT, _NORM}
        assert rr.inbound_failed(_CRIT) is None  # parked, not failed
        assert rr.filtered_outbound() == {}  # a passive box parks no outbound

        # The engine callback POST /dr/activate runs once its seed and VIP gates pass.
        await engine._dr_activate_profile()
        assert await _accepts(crit_port)
        assert not await _accepts(norm_port)
        assert set(rr.filtered_inbound()) == {_NORM}
        assert set(rr.filtered_outbound()) == {"OB_NORM_ADT"}

        await engine._dr_release_drain()  # what POST /dr/release runs
        assert not await _accepts(crit_port)
        # An alert rule's restart is the engine, not an operator, so it leaves the feed down.
        await _alert_control_action(engine, "restart_inbound", _CRIT)
        assert not await _accepts(crit_port)

        await engine.reload_detail(cfg)
        assert not await _accepts(crit_port) and not await _accepts(norm_port)
        assert set(rr.filtered_inbound()) == {_CRIT, _NORM}
        assert rr.filtered_outbound() == {}


async def test_a_box_activated_at_startup_binds_only_the_critical_feed(tmp_path: Path) -> None:
    """``activate = true`` is not passive: the box serves its critical feed from the start."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=True)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        assert await _accepts(crit_port)
        assert not await _accepts(norm_port)
        assert rr.dr_standby is None


@pytest.mark.parametrize("door", ["operator", "alert_rule"])
async def test_only_an_operator_start_binds_a_listener_on_a_passive_standby(
    tmp_path: Path, door: str
) -> None:
    """ADR 0048 Decision 3: an operator start of an inbound overrides the profile. The engine's
    own doors do not, so the passive fence holds until a person chooses to open it."""
    cfg = tmp_path / "cfg"
    crit_port, _norm_port = _write_graph(cfg, tmp_path)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        if door == "operator":
            await rr.start_inbound(_CRIT)
            assert await _accepts(crit_port)
        else:
            await _alert_control_action(engine, "restart_inbound", _CRIT)
            assert not await _accepts(crit_port)
