# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DR activation re-applies the running graph under the DR threshold, and reads no config dir.

vault BACKLOG #3067: the runner's DR threshold was set only at construction, and the activation
reloaded through that same runner, so on a box built passive ``POST /dr/activate`` parked nothing.
The engine now hands the runner the threshold before the reload, and clears it on release.

The same item moved the activation off the disk. It used to reload :attr:`Engine.running_config_dir`
(vault BACKLOG #2840), which put live any bytes edited there since the last approved reload, with no
second person, and refused the activation when that dir had gone with the failed site. It now
re-applies the graph the runner holds in memory. A disk that differs is recorded on the
``dr.activate`` row and logged, and only the gated ``POST /config/reload`` applies it.

vault BACKLOG #2839: the seed marker's digest is the running graph's provenance digest, so a file
name that is not UTF-8 cannot fail an activation or a release, and no digest is taken on the loop.
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from messagefoundry.config import fingerprint as fp
from messagefoundry.config.models import Priority
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr import DrActivationError
from tests.test_dr_activation import _seed

# A name that cannot be encoded as UTF-8: a lone surrogate. NTFS stores it as UTF-16, and on a
# POSIX file system Python writes it as the raw byte 0x80. Under environments/ it is fingerprinted
# (environments/*.toml is in the fold) but never loaded, so the graph still builds.
_BAD_NAME = "x\udc80.toml"

_CRIT = "IB_CRIT_ADT"
_NORM = "IB_NORM_ADT"


def _free_ports(count: int) -> list[int]:
    """Distinct free ports: every socket stays bound until all are picked, so no two match."""
    socks = [socket.socket() for _ in range(count)]
    try:
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [int(s.getsockname()[1]) for s in socks]
    finally:
        for s in socks:
            s.close()


def _write_graph(cfg: Path, tmp_path: Path, inbound: str) -> None:
    inbox = tmp_path / f"in-{inbound}"
    outdir = tmp_path / f"out-{inbound}"
    for d in (cfg, inbox, outdir):
        d.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound({inbound!r}, File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n",
        encoding="utf-8",
    )


def _write_tiered_graph(cfg: Path, tmp_path: Path) -> None:
    """One critical and one normal MLLP inbound, each with an outbound of the same tier."""
    cfg.mkdir(parents=True, exist_ok=True)
    out_crit, out_norm = tmp_path / "out-crit", tmp_path / "out-norm"
    out_crit.mkdir(exist_ok=True)
    out_norm.mkdir(exist_ok=True)
    crit_port, norm_port = _free_ports(2)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File, MLLP\n"
        "from messagefoundry.config.models import Priority\n"
        f"inbound({_CRIT!r}, MLLP(port={crit_port}), router='r', priority=Priority.CRITICAL)\n"
        f"inbound({_NORM!r}, MLLP(port={norm_port}), router='r', priority=Priority.NORMAL)\n"
        f"outbound('OB_CRIT_ADT', File(directory={str(out_crit)!r}), "
        "priority=Priority.CRITICAL)\n"
        f"outbound('OB_NORM_ADT', File(directory={str(out_norm)!r}), priority=Priority.NORMAL)\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return [Send('OB_CRIT_ADT', msg), Send('OB_NORM_ADT', msg)]\n",
        encoding="utf-8",
    )


class _Box(NamedTuple):
    engine: Engine
    live: Path
    staging: Path
    tiered: Path


@pytest.fixture
async def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_Box]:
    """A passive DR box, with ``live`` as its startup dir and ``staging`` and ``tiered`` as two
    more allowed reload roots. The store is encrypted and carries a cold-seed archive of itself,
    so an activation clears its gates."""
    live = tmp_path / "live"
    staging = tmp_path / "staging"
    tiered = tmp_path / "tiered"
    _write_graph(live, tmp_path, "IB_LIVE_ADT")
    _write_graph(staging, tmp_path, "IB_STAGING_ADT")
    _write_tiered_graph(tiered, tmp_path)
    store, archive, ss = await _seed(tmp_path)
    engine = Engine(
        store,
        poll_interval=0.05,
        config_dir=live,
        config_reload_roots=[str(staging), str(tiered)],
        store_settings=ss,
        dr_settings=DrSettings(enabled=True, activate=False, seed_archive=archive),
        egress_settings=EgressSettings(deny_by_default=False),
    )

    async def drained() -> None:
        # The seeded store holds a row for a destination these graphs lack, so a real drain would
        # wait out its whole timeout. The release paths under test are the coordinator's and the
        # threshold reset, not the drain.
        return None

    monkeypatch.setattr(engine, "_drain_pipeline", drained)
    try:
        yield _Box(engine, live, staging, tiered)
    finally:
        await engine.stop()


def _inbound_names(engine: Engine) -> set[str]:
    rr = engine.registry_runner
    assert rr is not None
    return set(rr.registry.inbound)


async def _seed_marker(engine: Engine) -> dict[str, object]:
    rows = await engine.store.list_audit(action="dr_seed")
    assert len(rows) == 1
    marker: dict[str, object] = json.loads(rows[0]["detail"])
    return marker


async def _activate_row(engine: Engine) -> dict[str, object]:
    rows = await engine.store.list_audit(action="dr.activate")
    assert len(rows) == 1
    detail: dict[str, object] = json.loads(rows[0]["detail"])
    return detail


def _loaded_digest(engine: Engine) -> str:
    loaded = engine.loaded_config_fingerprint
    assert loaded is not None
    digest = loaded["fingerprint"]
    assert isinstance(digest, str)
    return digest


# --- #3067: the activation parks the below-threshold feeds on a running box -----------------------


async def test_an_activation_parks_the_normal_feed_and_keeps_the_critical_one(box: _Box) -> None:
    """Red before #3067: the runner kept the threshold it was built with (None on a passive box),
    so the activation reload bound both inbounds again."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    # Control: a passive box serves its full graph.
    assert rr.inbound_running(_CRIT) and rr.inbound_running(_NORM)
    assert rr.filtered_inbound() == {} and rr.filtered_outbound() == {}

    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    assert engine.dr_active is True and rr.dr_threshold is Priority.CRITICAL
    assert rr.inbound_running(_CRIT)
    assert not rr.inbound_running(_NORM)
    assert _NORM in rr.filtered_inbound() and _CRIT not in rr.filtered_inbound()
    assert rr.inbound_failed(_NORM) is None  # parked, not failed
    assert "OB_NORM_ADT" in rr.filtered_outbound()
    assert "OB_CRIT_ADT" not in rr.filtered_outbound()

    # An operator reload while the profile is on keeps the normal feed parked.
    await engine.reload_detail(box.tiered)
    assert rr.inbound_running(_CRIT) and not rr.inbound_running(_NORM)


async def test_a_release_then_a_reload_binds_the_normal_feed_again(box: _Box) -> None:
    """Red before #3067 in the other direction: a runner built under the profile kept its threshold
    after a release, so every later reload went on parking the normal feeds."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")
    assert not rr.inbound_running(_NORM)  # control: the profile parked it

    await coord.release(actor="alice")
    assert engine.dr_active is False and rr.dr_threshold is None
    assert not rr.inbound_running(_CRIT)  # the release unbound all intake
    # Released, nothing reports parked, even before a reload re-evaluates the graph.
    assert rr.filtered_inbound() == {} and rr.filtered_outbound() == {}

    await engine.reload_detail(box.tiered)
    assert rr.inbound_running(_CRIT) and rr.inbound_running(_NORM)
    assert rr.filtered_inbound() == {} and rr.filtered_outbound() == {}


async def test_a_refused_activation_puts_the_threshold_back(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The latch and the runner's threshold go back together, so a later reload on a box the
    coordinator reports as not active parks nothing."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None

    async def refuse(registry: object) -> None:
        raise WiringError("a trust anchor this graph names is not readable")

    real_preflight = engine.preflight_registry
    monkeypatch.setattr(engine, "preflight_registry", refuse)
    coord = engine.dr_coordinator
    assert coord is not None
    with pytest.raises(DrActivationError) as caught:
        await coord.activate(actor="alice")

    assert caught.value.kind == "profile"
    assert "could not bind the priority feeds" in str(caught.value)
    assert coord.active is False and engine.dr_active is False
    assert rr.dr_threshold is None
    assert rr.inbound_running(_CRIT) and rr.inbound_running(_NORM)
    monkeypatch.setattr(engine, "preflight_registry", real_preflight)
    await engine.reload_detail(box.tiered)
    assert rr.inbound_running(_NORM)


# --- the activation applies the running graph, not the disk ----------------------------------------


async def test_a_dr_activation_keeps_the_graph_an_operator_reloaded(box: _Box) -> None:
    """Red before #2840: the activation reloaded ``live`` and IB_LIVE_ADT came back."""
    engine = box.engine
    await engine.reload_detail(box.live)
    assert _inbound_names(engine) == {"IB_LIVE_ADT"}  # control: the startup graph went live
    await engine.reload_detail(box.staging)  # the operator's deliberate reload
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}

    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    assert engine.dr_active is True
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert engine.last_reload_dir == box.staging.resolve()


async def test_bytes_edited_after_the_reload_are_recorded_and_not_applied(
    box: _Box, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before #3067: the activation reloaded the dir, so an edit nobody approved went live."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    activated = _loaded_digest(engine)
    _write_graph(box.staging, box.staging.parent, "IB_EDITED_ADT")  # nobody approved this
    on_disk = fp.config_fingerprint(box.staging)
    assert on_disk != activated  # control: the disk really moved

    coord = engine.dr_coordinator
    assert coord is not None
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
        await coord.activate(actor="alice")

    assert _inbound_names(engine) == {"IB_STAGING_ADT"}  # the in-memory graph, not the edit
    assert _loaded_digest(engine) == activated
    row = await _activate_row(engine)
    assert row["config_fingerprint"] == activated
    assert row["disk_config"] == "differs"
    assert row["disk_config_fingerprint"] == on_disk
    assert (await _seed_marker(engine))["config_fingerprint"] == activated
    drift = [r.getMessage() for r in caplog.records if "now differs on disk" in r.getMessage()]
    assert len(drift) == 1
    assert activated in drift[0] and on_disk in drift[0] and "IB_EDITED_ADT" not in drift[0]
    # The operator's gated reload is what applies it.
    await engine.reload_detail(box.staging)
    assert _inbound_names(engine) == {"IB_EDITED_ADT"}


async def test_an_unchanged_dir_is_recorded_as_matching(box: _Box) -> None:
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    row = await _activate_row(engine)
    assert row["config_fingerprint"] == _loaded_digest(engine)
    assert row["disk_config"] == "matches"
    assert "disk_config_fingerprint" not in row


async def test_an_activation_succeeds_with_the_config_dir_removed(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at 7a59a4bd24 and at #2840's preflight: a gone dir aborted the activation. The
    activation no longer reads it, so it goes ahead, runs the takeover hook, and records that the
    disk could not be read."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    activated = _loaded_digest(engine)
    shutil.rmtree(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    hooks: list[str] = []
    real_hook = coord._run_vip_hook

    async def spy(command: str, *, phase: str, actor: str, now: float) -> bool:
        hooks.append(phase)
        return await real_hook(command, phase=phase, actor=actor, now=now)

    monkeypatch.setattr(coord, "_run_vip_hook", spy)

    result = await coord.activate(actor="alice")

    assert result.active is True and engine.dr_active is True
    assert hooks == ["takeover"]
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert await engine.store.list_audit(action="dr_activation_aborted") == []
    row = await _activate_row(engine)
    assert row["config_fingerprint"] == activated
    assert row["disk_config"] == "unreadable"
    assert isinstance(row["disk_config_error"], str) and row["disk_config_error"]
    # The marker carries the running graph's digest, not None and not an empty bundle's.
    assert (await _seed_marker(engine))["config_fingerprint"] == activated


async def test_a_dir_that_goes_during_the_takeover_hook_does_not_abort(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at #2840: the profile step reloaded the dir after the hook, so a dir that went while
    the VIP moved left the VIP on a box not running the profile."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None

    async def hook_removes_the_dir(command: str, *, phase: str, actor: str, now: float) -> bool:
        shutil.rmtree(box.staging)
        return True

    monkeypatch.setattr(coord, "_run_vip_hook", hook_removes_the_dir)

    result = await coord.activate(actor="alice")

    assert result.active is True and engine.dr_active is True
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert (await _activate_row(engine))["disk_config"] == "unreadable"


async def test_a_drift_check_that_raises_does_not_undo_the_activation(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check runs after the graph is live. A raise there used to reach the coordinator, which
    recorded an abort and reported the box as not active while it served the profile."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None

    async def broken(path: Path) -> tuple[dict[str, object] | None, str | None]:
        raise RuntimeError("the fingerprint module failed")

    monkeypatch.setattr(engine, "fingerprint_bundle", broken)
    coord = engine.dr_coordinator
    assert coord is not None
    result = await coord.activate(actor="alice")

    assert result.active is True and coord.active is True and engine.dr_active is True
    assert not rr.inbound_running(_NORM)
    assert await engine.store.list_audit(action="dr_activation_aborted") == []
    row = await _activate_row(engine)
    assert row["disk_config"] == "unreadable"
    assert "the fingerprint module failed" in str(row["disk_config_error"])


async def test_a_running_graph_with_no_digest_is_recorded_as_unknown(box: _Box) -> None:
    """With nothing to compare, the verdict is ``unknown``, not ``differs``."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    engine.loaded_config_fingerprint = None  # as when the load could not read its bundle
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    row = await _activate_row(engine)
    assert row["config_fingerprint"] is None
    assert row["disk_config"] == "unknown"
    assert row["disk_config_fingerprint"] == fp.config_fingerprint(box.staging)


async def test_convergence_still_reloads_the_startup_dir(box: _Box) -> None:
    """Each node converges on its own startup dir, so a convergence after an operator reload from
    another root still loads ``live``."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}  # control: the operator's graph runs

    await engine._converge_reload()

    assert _inbound_names(engine) == {"IB_LIVE_ADT"}


# --- #2839: the seed marker's digest ---------------------------------------------------------------


async def test_the_seed_marker_carries_the_running_graphs_digest(box: _Box) -> None:
    """Red before #2839: the marker carried the startup dir's digest after a reload elsewhere."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    marker = await _seed_marker(engine)
    assert marker["config_fingerprint"] == fp.config_fingerprint(box.staging)
    assert marker["config_fingerprint"] != fp.config_fingerprint(box.live)  # the two differ


async def test_a_file_name_that_is_not_utf8_does_not_fail_dr(box: _Box) -> None:
    """Red before #2839: reading ``dr_coordinator`` raised UnicodeEncodeError."""
    engine = box.engine
    try:
        (box.live / "environments").mkdir()
        (box.live / "environments" / _BAD_NAME).write_text("", encoding="utf-8")
    except (OSError, UnicodeEncodeError) as exc:
        pytest.skip(f"this file system refuses a name that is not UTF-8: {type(exc).__name__}")
    with pytest.raises(UnicodeEncodeError):
        fp.config_fingerprint(box.live)  # control: the fold really refuses this bundle

    await engine.reload_detail(box.live)  # a reload tolerates it already (#2597)
    coord = engine.dr_coordinator
    assert coord is not None
    result = await coord.activate(actor="alice")
    assert result.active is True
    assert (await _seed_marker(engine))["config_fingerprint"] is None
    assert (await _activate_row(engine))["disk_config"] == "unreadable"

    released = await coord.release(actor="alice")
    assert released.active is False


async def test_the_dr_fingerprint_is_not_taken_on_the_event_loop(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before #2839: the property called config_fingerprint on the loop's own thread."""
    engine = box.engine
    await engine.reload_detail(box.live)
    loop_thread = threading.get_ident()
    seen: list[tuple[str, int]] = []

    def spy(name: str) -> Callable[[str | Path], Any]:
        real = getattr(fp, name)

        def wrapped(directory: str | Path) -> Any:
            seen.append((name, threading.get_ident()))
            return real(directory)

        return wrapped

    # Both: the old property called the plain one, fingerprint_bundle calls the detail one.
    for name in ("config_fingerprint", "config_fingerprint_detail"):
        monkeypatch.setattr(fp, name, spy(name))

    coord = engine.dr_coordinator
    assert coord is not None
    assert seen == []  # building the coordinator read no file
    await coord.activate(actor="alice")

    # Control: the drift check fingerprinted the dir during the activation, so the calls checked
    # below are not an empty list.
    assert seen, "the activation took no digest of the config dir"
    assert all(thread != loop_thread for _name, thread in seen), seen
