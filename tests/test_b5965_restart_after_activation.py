# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An activated DR box that restarts comes back passive and fails loud (BACKLOG #5965; owner
ruling 2026-11-25, decision d20261126T042906640-0b0f76).

No setting starts a box active, so a restart of an activated box drops it to passive. The start
now reads the newest ``dr.activate``, ``dr.release`` or ``dr.stay_passive`` row its own
identity wrote. When
that row is a ``dr.activate``, it logs at ERROR and raises the critical ``dr_restarted_passive``
alert, which closes the open ``dr_activated``; it never re-activates the box. Each engine shard
reads only its own rows. An activated server-DB box with ``[dr].restore_token`` set also writes no
``dr_backup`` row of its own, so a later re-activation of the same restore still passes the
restore-token vintage check; any other activated box keeps backing up (owner ruling 2026-11-26)."""

from __future__ import annotations

import json
import logging
import socket
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import Priority
from messagefoundry.config.settings import (
    AlertRule,
    AlertSeverity,
    BackupSettings,
    DrSettings,
    EgressSettings,
    StoreSettings,
)
from messagefoundry.config.wiring import MLLP, Registry, build_inbound_connection
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import AlertRuleSet, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner, _day_key
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
    store: MessageStore,
    ss: StoreSettings,
    archive: str,
    sink: LoggingAlertSink,
    instance: str | None,
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
    # A lone engine's label is the host.
    assert first_sink.events == [("dr_activated", socket.gethostname())]

    sink = _Sink()
    store = await MessageStore.open(db, cipher=make_cipher(key))
    engine = _engine(store, ss, archive, sink)
    engine.add_registry(_registry(port))
    try:
        with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.dr"):
            await engine.start()
        # Loud: the critical alert, for the same label the activation raised, and an ERROR line.
        assert sink.events == [("dr_restarted_passive", socket.gethostname())]
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
        served = _coord(store, ss, archive, _Sink(), None)
        await served.activate(actor="alice")
        await served.release(actor="alice")
        sink = _Sink()
        assert await _coord(store, ss, archive, sink, None).check_restarted_passive() is False
        assert sink.events == []
    finally:
        await store.close()


async def test_a_store_rebuilt_from_an_activated_snapshot_alerts_without_claiming_a_restart(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The store is rebuilt from a snapshot taken while the box was activated, and the box failed
    # back after that snapshot. Its newest own row is still dr.activate, so it alerts as before,
    # but neither the ERROR line nor the default sink's CRITICAL line may say it was serving.
    db, archive, ss, key = await _seed(tmp_path)
    snapshot = tmp_path / "snapshot.db"
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        served = _coord(store, ss, archive, _Sink(), None)
        await served.activate(actor="alice")
        await store.snapshot_to(snapshot)
        await served.release(actor="alice")
        assert len(await store.list_audit(action="dr.release", limit=5)) == 1
    finally:
        await store.close()

    rebuilt = await MessageStore.open(snapshot, cipher=make_cipher(key))
    try:
        assert await rebuilt.list_audit(action="dr.release", limit=5) == []
        assert len(await rebuilt.list_audit(action="dr.activate", limit=5)) == 1
        # Twice: the second start, of a box that already came back passive, reads the same.
        for _start in range(2):
            caplog.clear()
            sink = _Sink()
            with caplog.at_level(logging.ERROR):
                coord = _coord(rebuilt, ss, archive, sink, None)
                assert await coord.check_restarted_passive()
                LoggingAlertSink().dr_restarted_passive(socket.gethostname())
            # Same alert and same passive outcome as a restart while serving.
            assert sink.events == [("dr_restarted_passive", socket.gethostname())]
            assert not coord.active
            records = [r for r in caplog.records if r.levelno >= logging.ERROR]
            assert [r.levelno for r in records] == [logging.ERROR, logging.CRITICAL]
            assert "snapshot" in records[0].getMessage()
            for line in (r.getMessage() for r in records):
                assert "was last ACTIVATED" not in line and "after a restart" not in line
                assert "went down while serving" not in line
                # The activate advice is conditional: in these cases the primary may be serving.
                assert "confirmed the primary is not serving" in line
            # The starting process wrote no record, so the line names the identity's record.
            assert "for this identity" in records[0].getMessage()
            assert "this process" not in records[0].getMessage()
    finally:
        await rebuilt.close()


async def test_a_release_on_the_restarted_box_records_that_it_stays_passive(
    tmp_path: Path,
) -> None:
    # The operator's way to leave a restarted box passive, so later starts stop paging.
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), None).activate(actor="alice")
        restarted_sink = _Sink()
        restarted = _coord(store, ss, archive, restarted_sink, None)
        assert await restarted.check_restarted_passive()
        result = await restarted.release(actor="bob")
        assert result.active is False and not restarted.active
        # Not a fail-back: no drain ran, so it is its own action and no dr.release row.
        assert await store.list_audit(action="dr.release", limit=5) == []
        rows = await store.list_audit(action="dr.stay_passive", limit=5)
        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"])
        assert detail["vip_hook_ran"] is False and detail["host"] == socket.gethostname()
        assert restarted_sink.events[-1] == ("dr_released", socket.gethostname())
        # A second release records nothing more, and the next start raises nothing.
        assert await restarted.release(actor="bob") == result
        assert len(await store.list_audit(action="dr.stay_passive", limit=5)) == 1
        later = _Sink()
        assert not await _coord(store, ss, archive, later, None).check_restarted_passive()
        assert later.events == []
    finally:
        await store.close()


async def test_the_stay_passive_line_claims_no_hand_back(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A release on a restarted passive box hands nothing back, so the default sink's line for the
    # dr_released it raises must not say it did.
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), None).activate(actor="alice")
        restarted = _coord(store, ss, archive, LoggingAlertSink(), None)
        assert await restarted.check_restarted_passive()
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.alerts"):
            await restarted.release(actor="bob")
        lines = [
            r.getMessage() for r in caplog.records if r.getMessage().startswith("ALERT dr_released")
        ]
        assert len(lines) == 1
        assert "handed back" not in lines[0]
        assert "released; it is not activated as DR" in lines[0]
        # The box releases with an operator-started inbound still bound, so the line claims
        # nothing about who serves.
        assert "serving" not in lines[0]
        assert await store.list_audit(action="dr.stay_passive", limit=5) != []
    finally:
        await store.close()


def test_the_restart_alert_line_says_how_to_close_it(caplog: pytest.LogCaptureFixture) -> None:
    # The CRITICAL line names both ways out: this start's release, and a hand resolve for an
    # alert an earlier start left open.
    with caplog.at_level(logging.CRITICAL, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().dr_restarted_passive("dr-box")
    (line,) = [r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL]
    assert "POST /dr/release on this start records that it stays passive and closes" in line
    assert "earlier start left open is resolved by hand" in line
    assert "POST /alerts/{alert_id}/resolve" in line and "Resolve in the web console" in line


async def test_a_never_activated_box_writes_no_release_row(tmp_path: Path) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        sink = _Sink()
        await _coord(store, ss, archive, sink, None).release(actor="bob")
        assert await store.list_audit(action="dr.release", limit=5) == []
        assert await store.list_audit(action="dr.stay_passive", limit=5) == []
        assert sink.events == []
    finally:
        await store.close()


async def test_a_row_another_box_wrote_does_not_count(tmp_path: Path) -> None:
    # A store restored from another box carries that box's rows; only this host's count.
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        other = _coord(store, ss, archive, _Sink(), None)
        other._host = "other-dr-box"
        await other.activate(actor="alice")
        sink = _Sink()
        assert not await _coord(store, ss, archive, sink, None).check_restarted_passive()
        assert sink.events == []
    finally:
        await store.close()


async def test_an_unreadable_store_at_start_fails_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:

        async def refuse(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
            raise OSError("disk I/O error")

        real = store.recent_audit_of
        monkeypatch.setattr(store, "recent_audit_of", refuse)
        sink = _Sink()
        coord = _coord(store, ss, archive, sink, None)
        assert await coord.check_restarted_passive()
        assert sink.events == [("dr_restarted_passive", socket.gethostname())]
        # The release still settles the alert it raised, though the box was never activated.
        monkeypatch.setattr(store, "recent_audit_of", real)
        await coord.release(actor="bob")
        assert sink.events[-1] == ("dr_released", socket.gethostname())
        assert len(await store.list_audit(action="dr.stay_passive", limit=5)) == 1
    finally:
        await store.close()


async def test_an_activation_settles_the_restart_alert_for_a_later_release(
    tmp_path: Path,
) -> None:
    # Lander hold 7204995471, item 1: once a dr.activate row is written, the start's alert no
    # longer describes the box. A later activation that aborts at the profile step leaves the
    # identity's newest row a dr.release, so a release then records no dr.stay_passive.
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), None).activate(actor="alice")
        fail_profile = False

        async def act() -> None:
            if fail_profile:
                raise RuntimeError("synthetic profile failure")

        async def deact() -> None:
            return None

        sink = _Sink()
        coord = DrCoordinator(
            store,
            DrSettings(enabled=True, seed_archive=archive),
            store_settings=ss,
            activate_profile=act,
            deactivate_profile=deact,
            alert_sink=sink,
            instance=lambda: None,
        )
        assert await coord.check_restarted_passive()
        await coord.activate(actor="alice")
        await coord.release(actor="alice")
        fail_profile = True
        with pytest.raises(DrActivationError) as aborted:
            await coord.activate(actor="alice")
        # The abort must reach the profile step, where the earlier release's result is dropped;
        # an earlier abort would answer from that result and never reach the stay-passive read.
        assert aborted.value.kind == "profile"
        assert not coord.active
        events = len(sink.events)
        await coord.release(actor="bob")
        assert await store.list_audit(action="dr.stay_passive", limit=5) == []
        assert len(sink.events) == events
    finally:
        await store.close()


async def test_a_failed_hook_on_a_stay_passive_release_claims_no_hand_back(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Lander hold 7204995471, item 4: a release on a passive box hands nothing back.
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), None).activate(actor="alice")

        async def noop() -> None:
            return None

        restarted = DrCoordinator(
            store,
            DrSettings(enabled=True, seed_archive=archive, release_hook="exit 7"),
            store_settings=ss,
            activate_profile=noop,
            deactivate_profile=noop,
            alert_sink=_Sink(),
            instance=lambda: None,
        )
        assert await restarted.check_restarted_passive()
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.dr"):
            await restarted.release(actor="bob")
        lines = [r.getMessage() for r in caplog.records if "hook exited non-zero" in r.getMessage()]
        assert len(lines) == 1
        assert "hand-back" not in lines[0]
        assert lines[0].startswith("DR release on a passive box")
        assert len(await store.list_audit(action="dr.stay_passive", limit=5)) == 1
    finally:
        await store.close()


async def test_each_engine_shard_alerts_on_its_own(tmp_path: Path) -> None:
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        await _coord(store, ss, archive, _Sink(), "shard:a").activate(actor="alice")
        b_served = _coord(store, ss, archive, _Sink(), "shard:b")
        await b_served.activate(actor="alice")
        await b_served.release(actor="alice")
        # Engine shard a was last activated, so it alerts under its own label; b handed back, so not.
        a_sink, b_sink = _Sink(), _Sink()
        assert await _coord(store, ss, archive, a_sink, "shard:a").check_restarted_passive()
        assert not await _coord(store, ss, archive, b_sink, "shard:b").check_restarted_passive()
        assert a_sink.events == [("dr_restarted_passive", f"{socket.gethostname()} shard:a")]
        assert b_sink.events == []
        # An engine shard that never activated reads nothing of its siblings' rows.
        c_sink = _Sink()
        assert not await _coord(store, ss, archive, c_sink, "shard:c").check_restarted_passive()
        assert c_sink.events == []
    finally:
        await store.close()


async def test_an_activated_sqlite_box_still_backs_up_and_logs_no_pause_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Owner ruling 2026-11-26 (decision d20261126T095342812-893e1d): only a server-DB box with
    # [dr].restore_token set pauses its backups while activated (tests/test_b5712_standby_backup.py
    # covers that box). A SQLite box runs no token check, so it keeps backing up.
    db, archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(db, cipher=make_cipher(key))
    backup = BackupSettings(enabled=True, destination=str(tmp_path / "b2"))
    engine = _engine(store, ss, archive, _Sink(), backup=backup)
    try:
        await engine.start()
        runner = engine._backup_runner
        assert runner is not None and runner.scheduled  # the warning's own precondition holds
        # Today's scheduled pass counts as run, so the loop cannot race the explicit pass below.
        runner._last_backup_day = _day_key(time.time())
        before = len(await store.list_audit(action="dr_backup", limit=50))
        coord = engine.dr_coordinator
        assert coord is not None
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
            await coord.activate(actor="alice")
        assert engine.dr_active
        assert await runner.run_once(now=5.0) is not None
        assert len(await store.list_audit(action="dr_backup", limit=50)) == before + 1
        assert not [
            r for r in caplog.records if "DR backup: scheduled passes are paused" in r.getMessage()
        ]
    finally:
        await engine.stop()


async def test_the_restart_alert_closes_dr_activated_and_an_activation_closes_it() -> None:
    store = _RecordingStore()
    sink = NotifierAlertSink([], store=store)
    sink.dr_restarted_passive("dr-box")
    await _drain(sink)
    assert store.resolves == [{"event_type": "dr_activated", "connection": "dr-box"}]
    assert store.upserts == [{"event_type": "dr_restarted_passive", "connection": "dr-box"}]
    store.resolves.clear()
    sink.dr_activated("dr-box", role="dr_standby")
    await _drain(sink)
    assert store.resolves == [{"event_type": "dr_restarted_passive", "connection": "dr-box"}]


async def test_the_restart_alert_defaults_to_critical() -> None:
    t = _RecordingTransport()
    sink = NotifierAlertSink([t])
    sink.dr_restarted_passive("dr-box")
    sink.dr_activated("dr-box", role="dr_standby")
    await _drain(sink)
    by_type = {e["type"]: e for e in t.events}
    assert by_type["dr_restarted_passive"]["severity"] == "critical"
    assert by_type["dr_activated"]["severity"] == "warning"


def test_a_rule_that_names_no_severity_keeps_it_critical() -> None:
    event = {"type": "dr_restarted_passive", "connection": "dr-box"}
    catch_all = AlertRuleSet([AlertRule(cooldown_seconds=600)])
    assert catch_all.decide(event).severity == "critical"
    named = AlertRuleSet([AlertRule(severity=AlertSeverity.INFO)])
    assert named.decide(event).severity == "info"
    # Every other event type keeps the rule's default.
    assert catch_all.decide({"type": "dr_activated", "connection": "x"}).severity == "warning"
