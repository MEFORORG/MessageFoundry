# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[dr].activate = true`` resumes, at start, only an activation this box made (BACKLOG #5965).

Before: the engine latched the DR run-profile at construction from ``enabled`` and ``activate``
alone, so a boot bound the priority feeds with no seed verification, takeover hook or
``dr.activate`` audit row. Refusing the key outright made a box promoted by ``POST /dr/activate``
come back passive after a restart, and on a server-DB box with a restore token its own
``dr_backup`` rows then refused the activation again. Now a boot resumes only the newest
``dr.activate`` row written on this host with no ``dr.release`` or later ``dr_seed`` after it,
and records a ``dr.resume`` row. Otherwise it starts passive, logs an ERROR and alerts: refusing
the start would crash-loop a box restarted after a proper release with the key still set."""

from __future__ import annotations

import json
import logging
import socket
from pathlib import Path

import pytest

from messagefoundry.config.models import Priority
from messagefoundry.config.settings import (
    BackupSettings,
    DrSettings,
    EgressSettings,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.config.wiring import load_config
from messagefoundry.engine_secrets import SecretsDirectoryError
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.dr import (
    RESUME_ALERT_SUBJECT,
    DrActivationError,
    DrCoordinator,
    record_resume,
    resumable_activation,
)
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher
from tests.test_shard_recovery_engine import _only, _write_cfg


async def _seed(tmp_path: Path) -> tuple[str, StoreSettings, str]:
    """A store carrying a #60 backup of itself, as a restored DR box does: the archive, the store
    settings and the key. The store is closed again, for the engine to open."""
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
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "b")),
            store_settings=ss,
            config_dir=None,
        )
        res = await runner.run_once(now=1.0)
        assert res is not None
    finally:
        await store.close()
    return res.archive_path, ss, key


class _StopSpy(LoggingAlertSink):
    """Records each ``connection_stopped`` it is sent."""

    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


async def _engine(
    ss: StoreSettings,
    key: str,
    dr: DrSettings,
    *,
    alert_sink: _StopSpy | None = None,
    shard: str | None = None,
) -> Engine:
    return Engine(
        await MessageStore.open(ss.path, cipher=make_cipher(key)),
        poll_interval=0.05,
        store_settings=ss,
        dr_settings=dr,
        egress_settings=EgressSettings(deny_by_default=False),
        alert_sink=alert_sink,
        registry_filter=None if shard is None else _only(shard),
    )


async def _activate_once(ss: StoreSettings, key: str, archive: str) -> int:
    """Promote the box through ``POST /dr/activate``'s coordinator, then stop it. Returns the
    ``dr.activate`` row id."""
    first = await _engine(ss, key, DrSettings(enabled=True, seed_archive=archive))
    try:
        await first.start()
        coord = first.dr_coordinator
        assert coord is not None
        await coord.activate(actor="alice")
        rows = await first.store.list_audit(action="dr.activate", limit=1)
        return int(rows[0]["id"])
    finally:
        await first.stop()


async def _actions(engine: Engine) -> list[str]:
    return [r["action"] for r in await engine.store.list_audit(limit=200)]


async def test_a_restart_after_an_api_activation_resumes_it(tmp_path: Path) -> None:
    archive, ss, key = await _seed(tmp_path)
    passive = DrSettings(enabled=True, seed_archive=archive)
    first = await _engine(ss, key, passive)
    try:
        await first.start()
        assert not first.dr_active
        coord = first.dr_coordinator
        assert coord is not None
        await coord.activate(actor="alice")
        assert first.dr_active
        rows = await first.store.list_audit(action="dr.activate", limit=5)
        assert len(rows) == 1
        activation_id = rows[0]["id"]
        assert json.loads(rows[0]["detail"])["node"] == socket.gethostname()
    finally:
        await first.stop()

    kept = DrSettings(enabled=True, activate=True, seed_archive=archive)
    for restart in range(2):  # a second restart resumes the same activation again
        engine = await _engine(ss, key, kept)
        try:
            if restart:
                # A coordinator built before start reads the latch as off until start resumes it.
                early = engine.dr_coordinator
                assert early is not None and not early.active
            await engine.start()
            assert engine.dr_active
            assert not engine._dr_backup_paused()  # the box's own backups run, as after activation
            resumed = await engine.store.list_audit(action="dr.resume", limit=1)
            assert json.loads(resumed[0]["detail"])["activation_id"] == activation_id
            coord = engine.dr_coordinator
            assert coord is not None and coord.active
            seeds_before = (await _actions(engine)).count("dr_seed")
            # A repeated POST /dr/activate finds the box active and seeds nothing again.
            again = await coord.activate(actor="alice")
            assert again.active
            assert (await _actions(engine)).count("dr_seed") == seeds_before
        finally:
            await engine.stop()


async def test_activate_true_with_no_prior_activation_starts_passive_and_alerts(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """No refusal of the start, which would crash-loop the service: the box comes up passive, an
    ERROR names the reason and POST /dr/activate, and the alert path raises ``dr:resume``."""
    archive, ss, key = await _seed(tmp_path)
    spy = _StopSpy()
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)
    engine = await _engine(ss, key, dr, alert_sink=spy)
    try:
        with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.dr"):
            await engine.start()
        assert not engine.dr_active
        assert "dr.resume" not in await _actions(engine)
        errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert (
            "records no POST /dr/activate" in errors[0]
            and "does not take the DR run-profile" in errors[0]
        )
        assert "POST /dr/activate (dr:operate)" in errors[0]
        assert [name for name, _ in spy.stopped] == [RESUME_ALERT_SUBJECT]
        assert "records no POST /dr/activate" in spy.stopped[0][1]
        # The control: POST /dr/activate still promotes the passive box.
        coord = engine.dr_coordinator
        assert coord is not None
        await coord.activate(actor="alice")
        assert engine.dr_active
    finally:
        await engine.stop()


async def test_a_single_shard_supervise_start_resumes(tmp_path: Path) -> None:
    """``supervise`` passes ``--shard`` for its one engine shard of a config with no ``shard=``
    too. That engine shares the store with no sibling, so it resumes as a lone engine does."""
    archive, ss, key = await _seed(tmp_path)
    activation_id = await _activate_once(ss, key, archive)
    full = load_config(_write_cfg(tmp_path / "cfg", tmp_path, [None]))
    spy = _StopSpy()
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)
    engine = await _engine(ss, key, dr, alert_sink=spy, shard="default")
    try:
        engine.add_registry(filter_registry_for_shard(full, "default"))
        assert engine.filters_its_graph and engine.instance_identity is None
        await engine.start()
        assert engine.dr_active
        resumed = await engine.store.list_audit(action="dr.resume", limit=1)
        assert json.loads(resumed[0]["detail"])["activation_id"] == activation_id
        assert spy.stopped == []
    finally:
        await engine.stop()


async def test_an_engine_shard_of_a_multi_shard_config_starts_passive(tmp_path: Path) -> None:
    """The rows name the host, not the engine shard, so a sibling's live activation would read as
    this engine shard's own. It starts passive, alerts, and writes no dr.lapsed row, which would
    end a sibling's activation."""
    archive, ss, key = await _seed(tmp_path)
    await _activate_once(ss, key, archive)
    full = load_config(_write_cfg(tmp_path / "cfg", tmp_path, ["a", "b"]))
    spy = _StopSpy()
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)
    engine = await _engine(ss, key, dr, alert_sink=spy, shard="a")
    try:
        engine.add_registry(filter_registry_for_shard(full, "a"))
        assert engine.instance_identity == "shard:a"
        await engine.start()
        assert not engine.dr_active
        actions = await _actions(engine)
        assert "dr.resume" not in actions and "dr.lapsed" not in actions
        assert [name for name, _ in spy.stopped] == [RESUME_ALERT_SUBJECT]
        assert "engine shard cannot tell" in spy.stopped[0][1]
    finally:
        await engine.stop()


async def test_a_start_refused_later_writes_no_resume_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dr.resume row is written only once the start's own refusals have passed."""
    archive, ss, key = await _seed(tmp_path)
    await _activate_once(ss, key, archive)
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)
    engine = await _engine(ss, key, dr)
    try:
        engine.add_registry(load_config(_write_cfg(tmp_path / "cfg", tmp_path, [None])))
        monkeypatch.setattr(engine.store, "supports_ingest_stage", False, raising=False)
        with pytest.raises(RuntimeError, match=r"staged ingress pipeline"):
            await engine.start()
        assert "dr.resume" not in await _actions(engine)
    finally:
        await engine.stop()


async def test_a_passive_start_ends_the_activation_it_starts_over(tmp_path: Path) -> None:
    """The resume is activate's, not the store's: a passive start over a live activation stays
    passive, and records that the activation ended, so a later start under activate = true does
    not resume one the box stopped serving."""
    archive, ss, key = await _seed(tmp_path)
    passive = DrSettings(enabled=True, seed_archive=archive)
    first = await _engine(ss, key, passive)
    try:
        await first.start()
        coord = first.dr_coordinator
        assert coord is not None
        await coord.activate(actor="alice")
    finally:
        await first.stop()
    engine = await _engine(ss, key, passive)
    try:
        await engine.start()
        assert not engine.dr_active
        actions = await _actions(engine)
        assert "dr.resume" not in actions and actions.count("dr.lapsed") == 1
    finally:
        await engine.stop()
    again = await _engine(ss, key, passive)  # a second passive start adds no second marker
    try:
        await again.start()
        assert (await _actions(again)).count("dr.lapsed") == 1
    finally:
        await again.stop()
    spy = _StopSpy()
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)
    kept = await _engine(ss, key, dr, alert_sink=spy)
    try:
        await kept.start()
        assert not kept.dr_active
        assert "started passive since the last activation" in spy.stopped[0][1]
    finally:
        await kept.stop()


async def test_a_released_activation_is_not_resumed(tmp_path: Path) -> None:
    archive, ss, key = await _seed(tmp_path)
    first = await _engine(ss, key, DrSettings(enabled=True, seed_archive=archive))
    try:
        await first.start()
        coord = first.dr_coordinator
        assert coord is not None
        await coord.activate(actor="alice")
        await coord.release(actor="alice")
        assert not first.dr_active
    finally:
        await first.stop()
    spy = _StopSpy()
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)
    engine = await _engine(ss, key, dr, alert_sink=spy)
    try:
        await engine.start()  # a restart after a proper release starts, passive
        assert not engine.dr_active
        assert "released by POST /dr/release" in spy.stopped[0][1]
    finally:
        await engine.stop()


async def _record(store: MessageStore, action: str, detail: dict[str, object]) -> None:
    await store.record_audit(action, actor="alice", detail=json.dumps(detail), now=1.0)


@pytest.mark.parametrize(
    ("rows", "reason"),
    [
        # Carried in a restored store from another box, never made here.
        ([("dr.activate", {"node": "another-host"})], "not recorded on this host"),
        # Written before the row named its host.
        ([("dr.activate", {})], "not recorded on this host"),
        # A later attempt from a passive box opened a seed segment: the activation had ended.
        ([("dr.activate", {"node": "HERE"}), ("dr_seed", {})], "passive box"),
        ([("dr.activate", {"node": "HERE"}), ("dr.release", {})], "released"),
        # Recorded at another threshold than the one configured now.
        ([("dr.activate", {"node": "HERE", "threshold": "normal"})], "different"),
        # A later attempt refused before its seed marker came from a passive box too.
        ([("dr.activate", {"node": "HERE"}), ("dr_activation_aborted", {})], "passive box"),
        ([("dr.activate", {"node": "HERE"}), ("dr.lapsed", {})], "started passive"),
    ],
)
async def test_an_activation_that_is_not_this_boxes_live_one_is_refused(
    tmp_path: Path, rows: list[tuple[str, dict[str, object]]], reason: str
) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        for action, detail in rows:
            if detail.get("node") == "HERE":
                detail = {"threshold": "critical", **detail, "node": socket.gethostname()}
            await _record(store, action, detail)
        activation, why = await resumable_activation(store, DrSettings())
        assert activation is None and why is not None and reason in why
        assert not await store.list_audit(action="dr.resume", limit=1)
    finally:
        await store.close()


async def test_a_server_db_box_resumes_where_activating_again_is_refused(tmp_path: Path) -> None:
    """The case the refusal broke. On a server-DB box with a restore token, the activated box's own
    backup becomes the latest ``dr_backup`` anchor, so a second activation is refused; the resume
    reads only the audit rows and keeps the box active. A SQLite store stands in for the server DB,
    with its backend set, as ``tests/test_dr_server_seed_gate.py`` does."""
    archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(ss.path, cipher=make_cipher(key))
    try:
        store.backend = StoreBackend.POSTGRES
        token = tmp_path / "restore.token"
        token.write_text(
            json.dumps({"expected_backup_archive": Path(archive).name}), encoding="utf-8"
        )
        dr = DrSettings(enabled=True, seed_archive=archive, restore_token=str(token))

        async def _noop() -> None:
            return None

        def _coord() -> DrCoordinator:
            return DrCoordinator(
                store, dr, store_settings=ss, activate_profile=_noop, deactivate_profile=_noop
            )

        await _coord().activate(dba_attests_restored=True, actor="alice")
        # The activated box backs itself up, which writes the newer anchor.
        await _record(store, "dr_backup", {"archive": "dr-box-own.mfbak"})

        activation, _ = await resumable_activation(store, dr)
        assert activation is not None
        assert activation == (await store.list_audit(action="dr.activate", limit=1))[0]["id"]
        await record_resume(store, dr, activation, now=3.0)
        assert await store.list_audit(action="dr.resume", limit=1)

        # The control: activating again after the restart is what the resume avoids.
        with pytest.raises(DrActivationError) as exc:
            await _coord().activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
    finally:
        await store.close()


async def test_an_engine_shard_never_resumes(tmp_path: Path) -> None:
    """The rows name the host, not the engine shard, so a sibling's live activation would read as
    this engine shard's own. The control is the same row resuming on a lone engine."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        await _record(store, "dr.activate", {"node": socket.gethostname(), "threshold": "critical"})
        activation, why = await resumable_activation(store, DrSettings(), engine_shard=True)
        assert activation is None and why is not None and "engine shard cannot tell" in why
        activation, why = await resumable_activation(store, DrSettings())
        assert activation is not None and activation > 0 and why is None
    finally:
        await store.close()


async def test_a_refused_mismatch_ends_nothing_and_a_corrected_restart_resumes(
    tmp_path: Path,
) -> None:
    """A resume refused for a mismatched ``priority_threshold`` writes no ``dr.lapsed`` row: the
    activation is not that start's to end, so correcting the threshold brings the resume back."""
    archive, ss, key = await _seed(tmp_path)
    activation_id = await _activate_once(ss, key, archive)
    spy = _StopSpy()
    typo = DrSettings(
        enabled=True, activate=True, seed_archive=archive, priority_threshold=Priority.NORMAL
    )
    wrong = await _engine(ss, key, typo, alert_sink=spy)
    try:
        await wrong.start()
        assert not wrong.dr_active
        assert "different [dr].priority_threshold" in spy.stopped[0][1]
        actions = await _actions(wrong)
        assert "dr.lapsed" not in actions and "dr.resume" not in actions
    finally:
        await wrong.stop()
    fixed = await _engine(ss, key, DrSettings(enabled=True, activate=True, seed_archive=archive))
    try:
        await fixed.start()
        assert fixed.dr_active
        resumed = await fixed.store.list_audit(action="dr.resume", limit=1)
        assert json.loads(resumed[0]["detail"])["activation_id"] == activation_id
    finally:
        await fixed.stop()


async def test_a_passive_start_does_not_end_another_hosts_activation(tmp_path: Path) -> None:
    """``dr.lapsed`` ends only an activation of this host: one another host recorded in the store
    is not this box's to end. The control is this host's own activation, which a passive start
    does end."""
    archive, ss, key = await _seed(tmp_path)
    store = await MessageStore.open(ss.path, cipher=make_cipher(key))
    try:
        await _record(store, "dr.activate", {"node": "another-host", "threshold": "critical"})
    finally:
        await store.close()
    passive = DrSettings(enabled=True, seed_archive=archive)
    engine = await _engine(ss, key, passive)
    try:
        await engine.start()
        assert "dr.lapsed" not in await _actions(engine)
        here = json.dumps({"node": socket.gethostname(), "threshold": "critical"})
        await engine.store.record_audit("dr.activate", actor="alice", detail=here, now=1.0)
    finally:
        await engine.stop()
    again = await _engine(ss, key, passive)
    try:
        await again.start()
        assert (await _actions(again)).count("dr.lapsed") == 1
    finally:
        await again.stop()


async def test_a_start_refused_after_the_graph_step_writes_no_resume_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resume latches before the graph comes up, but its ``dr.resume`` row is written only once
    the start has passed every refusal, so a service that crash-loops on a later refusal adds no
    row per restart. The control: the start that succeeds writes exactly one."""
    archive, ss, key = await _seed(tmp_path)
    await _activate_once(ss, key, archive)
    dr = DrSettings(enabled=True, activate=True, seed_archive=archive)

    async def _refuse(self: Engine) -> None:
        raise SecretsDirectoryError("a secrets file the engine must not use")

    for _ in range(2):
        engine = await _engine(ss, key, dr)
        try:
            engine.add_registry(load_config(_write_cfg(tmp_path / "cfg", tmp_path, [None])))
            with monkeypatch.context() as patch:
                patch.setattr(Engine, "_start_graph", _refuse)
                with pytest.raises(SecretsDirectoryError):
                    await engine.start()
            assert "dr.resume" not in await _actions(engine)
        finally:
            await engine.stop()
    engine = await _engine(ss, key, dr)
    try:
        await engine.start()
        assert engine.dr_active
        assert (await _actions(engine)).count("dr.resume") == 1
    finally:
        await engine.stop()
