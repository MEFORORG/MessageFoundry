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
from messagefoundry.config.models import Priority
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_dr_running_config_dir import _BOTH_OUTBOUNDS, _CRIT, _NORM, _free_ports
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


_DB = "dr-passive.db"


@asynccontextmanager
async def _served(
    tmp_path: Path, cfg: Path, dr: DrSettings, claim_mode: str = "pooled"
) -> AsyncIterator[Engine]:
    """The engine ``serve`` builds, through its lifespan, with ``cfg`` as the config dir."""
    app = create_managed_app(
        db_path=tmp_path / _DB,
        config_dir=cfg,
        poll_interval=0.05,
        dr_settings=dr,
        egress_settings=EgressSettings(deny_by_default=False),
        claim_mode=claim_mode,
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
        # A passive box parks every outbound too (vault BACKLOG #3262).
        assert set(rr.filtered_outbound()) == _BOTH_OUTBOUNDS

        # The engine callback POST /dr/activate runs once its seed and VIP gates pass.
        await engine._dr_activate_profile()
        assert await _accepts(crit_port)
        assert not await _accepts(norm_port)
        assert set(rr.filtered_inbound()) == {_NORM}
        assert set(rr.filtered_outbound()) == {"OB_NORM_ADT"}

        await engine._dr_release_drain()  # what POST /dr/release runs
        assert not await _accepts(crit_port)
        # An alert rule's restart is the engine, not an operator, so it leaves the feed down.
        await _alert_control_action(engine, "restart_inbound", _CRIT, default_target=False)
        assert not await _accepts(crit_port)

        await engine.reload_detail(cfg)
        assert not await _accepts(crit_port) and not await _accepts(norm_port)
        assert set(rr.filtered_inbound()) == {_CRIT, _NORM}
        assert set(rr.filtered_outbound()) == _BOTH_OUTBOUNDS


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


async def test_only_an_operator_start_binds_a_listener_on_a_passive_standby(
    tmp_path: Path,
) -> None:
    """ADR 0048 Decision 3: an operator start of an inbound overrides the profile. The engine's
    own doors do not, so the passive fence holds until a person chooses to open it, and an
    alert rule's restart cannot undo that person's start either."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        await rr.start_inbound(_NORM)  # the scheduler's call: an engine door
        await _alert_control_action(engine, "restart_inbound", _NORM, default_target=False)
        assert not await _accepts(norm_port)
        # The door holds without the marker the scheduler and the alert action read first.
        rr._filtered.clear()
        await rr.restart_inbound(_NORM)
        assert not rr.inbound_running(_NORM)

        await rr.start_inbound(_CRIT, operator=True)  # the API's call
        assert await _accepts(crit_port)
        await rr.restart_inbound(_CRIT)  # an engine restart is refused whole
        assert rr.inbound_running(_CRIT) and await _accepts(crit_port)


async def test_no_engine_door_binds_a_listener_while_a_release_drains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The release parks intake before its drain, not after it. Red when the standby was set only
    once the drain ended: the scheduler's start bound the critical listener mid-drain."""
    cfg = tmp_path / "cfg"
    crit_port, _norm_port = _write_graph(cfg, tmp_path)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        await engine._dr_activate_profile()
        assert await _accepts(crit_port)  # control: the activation bound it
        real_drain = engine._drain_pipeline
        mid_drain: list[bool] = []

        async def drain_with_a_scheduler_tick() -> tuple[int, int]:
            await rr.start_inbound(_CRIT)
            mid_drain.append(await _accepts(crit_port))
            return await real_drain()

        monkeypatch.setattr(engine, "_drain_pipeline", drain_with_a_scheduler_tick)
        await engine._dr_release_drain()
        assert mid_drain == [False]
        assert _CRIT in rr.filtered_inbound()


@pytest.mark.parametrize("norm_auto_start", [True, False], ids=["auto_start", "operator_started"])
@pytest.mark.parametrize("fails_at", ["first_park", "drain", "drain_cancelled", "second_park"])
async def test_a_failed_release_leaves_the_box_active_with_the_profile_parks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fails_at: str, norm_auto_start: bool
) -> None:
    """The coordinator keeps a box active when its release fails, so the profile's parks stay:
    the normal feed keeps its marker, an alert rule's restart leaves it down, and the operator's
    reload binds the critical set and nothing else.

    Red at ``dcbeb5de0b``. A failed drain or second park purged every inbound marker, so the
    alert rule bound the normal feed. A failed first park ran outside the guard, so the runner
    kept the standby on an active box and the reload bound nothing, not even the critical feed.
    The ``operator_started`` case is an ``auto_start = false`` feed whose marker a reload wrote;
    rebuilding the markers from ``auto_start`` alone lost it."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path, norm_inbound_auto_start=norm_auto_start)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        await engine._dr_activate_profile()
        if not norm_auto_start:
            # An operator start, then a reload: the reload parks the feed with the profile's marker.
            await rr.start_inbound(_NORM, operator=True)
            assert await _accepts(norm_port)  # control: the probe sees a bound feed
            await engine.reload_detail(cfg)
        assert rr.inbound_filtered(_NORM) is not None and not await _accepts(norm_port)
        parks_before = rr.filtered_inbound()
        assert _CRIT not in parks_before

        if fails_at == "first_park":
            source = rr._sources[_CRIT]
            real_stop = source.stop

            async def stop_then_raise() -> None:
                await real_stop()
                raise OSError("injected release failure")

            source.stop = stop_then_raise  # type: ignore[method-assign]
        elif fails_at == "second_park":
            real_park = rr.park_intake
            parks: list[object] = []

            async def park_then_raise_once_drained(standby: Priority) -> None:
                await real_park(standby)
                parks.append(standby)
                if len(parks) == 2:
                    raise OSError("injected release failure")

            monkeypatch.setattr(rr, "park_intake", park_then_raise_once_drained)
        else:
            failure: BaseException = (
                asyncio.CancelledError()
                if fails_at == "drain_cancelled"
                else OSError("injected release failure")
            )

            async def failing_drain() -> tuple[int, int]:
                raise failure

            monkeypatch.setattr(engine, "_drain_pipeline", failing_drain)
        with pytest.raises((OSError, asyncio.CancelledError)):
            await engine._dr_release_drain()

        assert engine.dr_active and rr.dr_standby is None
        assert rr.filtered_inbound() == parks_before  # the profile's parks, reasons and all
        await _alert_control_action(engine, "restart_inbound", _NORM, default_target=False)
        assert not await _accepts(norm_port)
        await engine.reload_detail(cfg)
        assert await _accepts(crit_port) and not await _accepts(norm_port)


async def test_a_failed_release_parks_a_normal_feed_a_reload_added_during_the_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The restore judges the registry as it is when the release fails, not the one it read
    before the park. Red with a restore that put back only the pre-release markers: the feed a
    reload added mid-drain had none, and an alert rule bound it on an active box."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path)
    # Those two sockets are closed now, so the OS may hand either back; skip them.
    added_port = next(p for p in _free_ports(3) if p not in (crit_port, norm_port))
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        await engine._dr_activate_profile()

        async def reload_then_fail() -> tuple[int, int]:
            with (cfg / "cfg.py").open("a", encoding="utf-8") as f:
                f.write(
                    f"inbound('IB_NORM2_ADT', MLLP(port={added_port}), router='r', "
                    "priority=Priority.NORMAL)\n"
                )
            await engine.reload_detail(cfg)
            raise OSError("injected release failure")

        monkeypatch.setattr(engine, "_drain_pipeline", reload_then_fail)
        with pytest.raises(OSError):
            await engine._dr_release_drain()
        assert set(rr.filtered_inbound()) == {_NORM, "IB_NORM2_ADT"}
        await _alert_control_action(engine, "restart_inbound", "IB_NORM2_ADT", default_target=False)
        assert not await _accepts(added_port)
        await engine.reload_detail(cfg)
        assert await _accepts(crit_port) and not await _accepts(added_port)


@pytest.mark.parametrize("norm_auto_start", [True, False], ids=["auto_start", "no_auto_start"])
async def test_a_failed_release_parks_a_feed_an_operator_started_before_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, norm_auto_start: bool
) -> None:
    """A deliberate choice, pinned here: the restore errs toward parking. A below-threshold
    feed an operator started before the release is parked after a failed one, so only an
    operator start brings it back. Leaving it unmarked needed a record of which parks an
    operator overrode, and a stand-in for that record left a re-tiered feed unparked. The
    ``no_auto_start`` case was unmarked, so an alert rule bound it, until the park marked every
    inbound it stopped."""
    cfg = tmp_path / "cfg"
    crit_port, norm_port = _write_graph(cfg, tmp_path, norm_inbound_auto_start=norm_auto_start)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        await engine._dr_activate_profile()
        await rr.start_inbound(_NORM, operator=True)
        assert rr.inbound_filtered(_NORM) is None and await _accepts(norm_port)

        async def failing_drain() -> tuple[int, int]:
            raise OSError("injected release failure")

        monkeypatch.setattr(engine, "_drain_pipeline", failing_drain)
        with pytest.raises(OSError):
            await engine._dr_release_drain()
        assert engine.dr_active and rr.dr_standby is None
        assert set(rr.filtered_inbound()) == {_NORM}
        assert not await _accepts(norm_port)  # the park unbound it
        await _alert_control_action(engine, "restart_inbound", _NORM, default_target=False)
        assert not await _accepts(norm_port)
        await engine.reload_detail(cfg)
        assert await _accepts(crit_port) and not await _accepts(norm_port)
        await rr.start_inbound(_NORM, operator=True)
        assert await _accepts(norm_port)


@pytest.mark.parametrize("norm_auto_start", [True, False], ids=["auto_start", "operator_started"])
async def test_an_activation_parks_the_normal_feed_before_its_reload_runs(
    tmp_path: Path, norm_auto_start: bool
) -> None:
    """Leaving the standby writes the profile's markers at once, so a scheduler tick or an alert
    rule between an activation's flip and its reload binds no feed below the threshold. Red at
    ``dcbeb5de0b``, which purged every inbound marker there. The ``operator_started`` case is an
    ``auto_start = false`` feed a reload on the passive box parked after an operator start."""
    cfg = tmp_path / "cfg"
    _crit_port, norm_port = _write_graph(cfg, tmp_path, norm_inbound_auto_start=norm_auto_start)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=False)) as engine:
        rr = engine.registry_runner
        assert rr is not None
        if not norm_auto_start:
            await rr.start_inbound(_NORM, operator=True)
            assert await _accepts(norm_port)  # control: the probe sees a bound feed
            await engine.reload_detail(cfg)
        assert rr.inbound_filtered(_NORM) is not None and not await _accepts(norm_port)

        engine._set_dr_active(True)  # the activation's flip, before its reload takes the lock
        assert rr.dr_standby is None
        assert set(rr.filtered_inbound()) == {_NORM}
        await _alert_control_action(engine, "restart_inbound", _NORM, default_target=False)
        assert not await _accepts(norm_port)

        await engine._dr_activate_profile()
        assert set(rr.filtered_inbound()) == {_NORM}
        await _alert_control_action(engine, "restart_inbound", _NORM, default_target=False)
        assert not await _accepts(norm_port)
