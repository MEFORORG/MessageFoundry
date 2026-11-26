# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An activated DR box that restarts comes back passive and fails loud (BACKLOG #5965; owner
ruling 2026-11-25, decision d20261126T042906640-0b0f76).

No setting starts a box active, so a restart of an activated box drops it to passive. The start
now reads the newest ``dr.activate`` or ``dr.release`` row its own process identity wrote. When
that row is a ``dr.activate``, it logs at ERROR and raises the critical ``dr_restarted_passive``
alert, which closes the open ``dr_activated``; it never re-activates the box. Each engine shard
reads only its own rows. While a box is activated it also writes no ``dr_backup`` row of its own,
so a later re-activation of the same restore still passes the restore-token vintage check."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import Priority
from messagefoundry.config.settings import BackupSettings, DrSettings, EgressSettings, StoreSettings
from messagefoundry.config.wiring import MLLP, Registry, build_inbound_connection
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.dr import DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher
from tests.test_alert_failover import _drain, _RecordingStore, _RecordingTransport
from tests.test_dr_running_config_dir import _free_ports


class _Sink(LoggingAlertSink):
    """Records the DR alerts and logs every other event as the default sink does."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def dr_activated(self, node: str, *, role: str) -> None:
        self.events.append(("dr_activated", node))

    def dr_released(self, node: str, *, role: str) -> None:
        self.events.append(("dr_released", node))

    def dr_restarted_passive(self, node: str) -> None:
        self.events.append(("dr_restarted_passive", node))


async def _seed(tmp_path: Path) -> tuple[Path, str, StoreSettings, str]:
    """A store with one row and a verified cold-seed archive of it, closed again."""
    key = generate_key()
    db = tmp_path / "dr.db"
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await store.enqueue_message(
            channel_id="c1",
            raw="MSH|^~\\&|x",
            deliveries=[("d1", "OUT|y")],
            control_id="CID-1",
            now=1.0,
        )
        ss = StoreSettings(path=str(db), encryption_key=key)
        result = await BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "b")),
            store_settings=ss,
            config_dir=None,
        ).run_once(now=1.0)
        assert result is not None
    finally:
        await store.close()
    return db, result.archive_path, ss, key


def _coord(
    store: MessageStore, ss: StoreSettings, archive: str, sink: _Sink, instance: str | None
) -> DrCoordinator:
    async def act() -> None:
        return None

    async def deact() -> None:
        return None

    return DrCoordinator(
        store,
        DrSettings(enabled=True, seed_archive=archive),
        store_settings=ss,
        activate_profile=act,
        deactivate_profile=deact,
        alert_sink=sink,
        instance=lambda: instance,
    )


def _registry(port: int) -> Registry:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("IB_CRIT", MLLP(port=port), router="r", priority=Priority.CRITICAL)
    )
    reg.add_router("r", lambda m: [])
    return reg


def _engine(
    store: MessageStore,
    ss: StoreSettings,
    archive: str,
    sink: _Sink,
    *,
    backup: BackupSettings | None = None,
) -> Engine:
    return Engine(
        store,
        poll_interval=0.05,
        config_dir=None,
        store_settings=ss,
        dr_settings=DrSettings(enabled=True, seed_archive=archive),
        backup_settings=backup,
        alert_sink=sink,
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def _activations(store: MessageStore) -> int:
    return len(await store.list_audit(action="dr.activate", limit=50))


async def test_a_restart_after_activation_alerts_and_stays_passive(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    (port,) = _free_ports(1)
    first_sink = _Sink()
    first = _engine(await MessageStore.open(db, cipher=make_cipher(key)), ss, archive, first_sink)
    first.add_registry(_registry(port))
    try:
        await first.start()
        coord = first.dr_coordinator
        assert coord is not None
        await coord.activate(actor="alice")
        assert first.dr_active
    finally:
        await first.stop()
    assert first_sink.events == [("dr_activated", first_sink_label(first_sink))]

    sink = _Sink()
    store = await MessageStore.open(db, cipher=make_cipher(key))
    engine = _engine(store, ss, archive, sink)
    engine.add_registry(_registry(port))
    try:
        with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.dr"):
            await engine.start()
        # Loud: the critical alert, for the same label the activation raised, and an ERROR line.
        assert sink.events == [("dr_restarted_passive", first_sink_label(first_sink))]
        assert any(
            r.levelno == logging.ERROR and "POST /dr/activate" in r.getMessage()
            for r in caplog.records
        )
        # Still refusing to serve, and nothing re-activated it.
        assert not engine.dr_active
        assert engine._registry_runner is not None
        assert engine._registry_runner.listening_inbounds() == frozenset()
        assert await _activations(store) == 1
    finally:
        await engine.stop()


def first_sink_label(sink: _Sink) -> str:
    """The label the first event carried, which is the host on a lone engine."""
    return sink.events[0][1]


async def test_a_never_activated_box_raises_nothing(tmp_path: Path) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    sink = _Sink()
    engine = _engine(await MessageStore.open(db, cipher=make_cipher(key)), ss, archive, sink)
    try:
        await engine.start()
        assert sink.events == []
        assert not engine.dr_active
    finally:
        await engine.stop()


async def test_a_released_box_raises_nothing_on_restart(tmp_path: Path) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), None).activate(actor="alice")
        released = _coord(store, ss, archive, _Sink(), None)
        released._active = True  # the same process, still serving, then fails back
        await released.release(actor="alice")
        sink = _Sink()
        assert await _coord(store, ss, archive, sink, None).check_restarted_passive() is False
        assert sink.events == []
    finally:
        await store.close()


async def test_each_engine_shard_alerts_on_its_own(tmp_path: Path) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), "shard:a").activate(actor="alice")
        await _coord(store, ss, archive, _Sink(), "shard:b").activate(actor="alice")
        b_back = _coord(store, ss, archive, _Sink(), "shard:b")
        b_back._active = True
        await b_back.release(actor="alice")
        # Shard a was last activated, so it alerts under its own label; b handed back, so not.
        a_sink, b_sink = _Sink(), _Sink()
        assert await _coord(store, ss, archive, a_sink, "shard:a").check_restarted_passive()
        assert not await _coord(store, ss, archive, b_sink, "shard:b").check_restarted_passive()
        assert len(a_sink.events) == 1
        kind, label = a_sink.events[0]
        assert kind == "dr_restarted_passive" and label.endswith(" shard:a")
        assert b_sink.events == []
        # A shard that never activated reads nothing of its siblings' rows.
        c_sink = _Sink()
        assert not await _coord(store, ss, archive, c_sink, "shard:c").check_restarted_passive()
        assert c_sink.events == []
    finally:
        await store.close()


async def test_an_activated_box_writes_no_dr_backup_row(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    backup = BackupSettings(enabled=True, destination=str(tmp_path / "b2"))
    engine = _engine(store, ss, archive, _Sink(), backup=backup)
    try:
        await engine.start()
        before = len(await store.list_audit(action="dr_backup", limit=50))
        coord = engine.dr_coordinator
        assert coord is not None
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
            await coord.activate(actor="alice")
        assert engine.dr_active
        runner = engine._backup_runner
        assert runner is not None
        assert await runner.run_once(now=5.0) is None
        assert len(await store.list_audit(action="dr_backup", limit=50)) == before
        paused = [
            r for r in caplog.records if "paused while this box is activated" in r.getMessage()
        ]
        assert len(paused) == 1 and paused[0].levelno == logging.WARNING
    finally:
        await engine.stop()


async def test_the_restart_alert_closes_dr_activated_and_is_critical() -> None:
    store = _RecordingStore()
    sink = NotifierAlertSink([], store=store)
    sink.dr_activated("dr-box", role="dr_standby")
    sink.dr_restarted_passive("dr-box")
    await _drain(sink)
    assert {"event_type": "dr_activated", "connection": "dr-box"} in store.resolves
    assert {"event_type": "dr_restarted_passive", "connection": "dr-box"} in store.upserts
    # The next activation closes the critical one.
    assert _AUTO_RESOLVE["dr_reactivated"] == "dr_restarted_passive"


async def test_the_restart_alert_defaults_to_critical() -> None:
    t = _RecordingTransport()
    sink = NotifierAlertSink([t])
    sink.dr_restarted_passive("dr-box")
    sink.dr_activated("dr-box", role="dr_standby")
    await _drain(sink)
    by_type = {e["type"]: e for e in t.events}
    assert by_type["dr_restarted_passive"]["severity"] == "critical"
    assert by_type["dr_activated"]["severity"] == "warning"
