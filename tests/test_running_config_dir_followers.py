# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DR backup and the subprocess sandbox follow the running config dir (vault BACKLOG #3094).

In the code before this change both read the STARTUP ``--config`` dir. After an operator reload
from another allowed root, the backup would archive and fingerprint a directory the engine no
longer runs, and a ``[sandbox].mode=subprocess`` worker would re-load the startup graph, whose
shape differs from the graph the parent serves, so every sandboxed dispatch would be refused. The
backup now reads
:attr:`Engine.running_config_dir` once per pass and takes its digest off the event loop under the
shared best-effort rule. A worker loads ``Registry.source_dir``, the directory the served graph came
from. Each reading below sits beside a control that tells the two roots apart. Synthetic HL7 only.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import tarfile
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from messagefoundry.config import fingerprint as fp
from messagefoundry.config.settings import (
    BackupSettings,
    EgressSettings,
    SandboxSettings,
    StoreSettings,
)
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner
from messagefoundry.pipeline.sandbox import SandboxMode, SandboxPolicy
from messagefoundry.pipeline.sharding import DEFAULT_SHARD, filter_registry_for_shard
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage, Store
from tests.test_dr_running_config_dir import _write_graph

RAW = "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||ADT^A01|DIR00001|P|2.5\rPID|1||MRN1\r"


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    live, staging = tmp_path / "live", tmp_path / "staging"
    _write_graph(live, tmp_path, "IB_LIVE_ADT")
    _write_graph(staging, tmp_path, "IB_STAGING_ADT")
    return live, staging


def _archive_tar(path: str) -> tarfile.TarFile:
    # An unencrypted archive is the plain tar, written verbatim.
    return tarfile.open(fileobj=io.BytesIO(Path(path).read_bytes()), mode="r")


def _manifest(tar: tarfile.TarFile) -> dict[str, object]:
    member = tar.extractfile("manifest.json")
    assert member is not None
    loaded: dict[str, object] = json.loads(member.read())
    return loaded


@pytest.fixture
async def backup_engine(tmp_path: Path) -> AsyncIterator[tuple[Engine, Path, Path]]:
    """A started engine with an on-demand backup, ``live`` as its startup dir and ``staging`` as an
    allowed reload root."""
    live, staging = _roots(tmp_path)
    db = tmp_path / "e.db"
    engine = Engine(
        await MessageStore.open(db),
        poll_interval=0.05,
        config_dir=live,
        config_reload_roots=[str(staging)],
        store_settings=StoreSettings(path=str(db)),
        backup_settings=BackupSettings(
            enabled=True,
            destination=str(tmp_path / "backups"),
            allow_unencrypted=True,
            schedule_at="",  # on-demand only: no scheduled pass races the test's own
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
        yield engine, live, staging
    finally:
        await engine.stop()


async def _last_audit(store: Store) -> dict[str, object]:
    rows = await store.list_audit(action="dr_backup")
    assert rows
    detail: dict[str, object] = json.loads(rows[0]["detail"])
    return detail


def _bundle_fields(record: dict[str, object]) -> tuple[object, object, object]:
    return record["config_bundled"], record["config_dir"], record["config_bundle_error"]


async def test_a_backup_after_a_reload_from_another_root_carries_that_root(
    backup_engine: tuple[Engine, Path, Path],
) -> None:
    engine, live, staging = backup_engine
    runner = engine._backup_runner
    assert runner is not None
    # Control: before any reload the backup names the startup dir.
    first = await runner.run_once(now=1.0)
    assert first is not None
    assert first.config_fingerprint == fp.config_fingerprint(live)
    assert (first.config_bundled, first.config_dir) == (True, str(live.resolve()))

    await engine.reload_detail(staging)
    assert engine.running_config_dir == staging.resolve()
    second = await runner.run_once(now=2.0 + 86_400)
    assert second is not None
    assert second.config_fingerprint == fp.config_fingerprint(staging)
    assert second.config_fingerprint != fp.config_fingerprint(live), "the two roots differ"
    # The same digest the running graph's provenance recorded, and the archive carries those bytes.
    loaded = engine.loaded_config_fingerprint
    assert loaded is not None and second.config_fingerprint == loaded["fingerprint"]
    # Which directory was bundled is recorded in both places.
    bundled = (True, str(staging.resolve()), None)
    assert _bundle_fields(await _last_audit(engine.store)) == bundled
    with _archive_tar(second.archive_path) as tar:
        manifest = _manifest(tar)
        assert manifest["config_fingerprint"] == second.config_fingerprint
        assert _bundle_fields(manifest) == bundled
        member = tar.extractfile("config/cfg.py")
        assert member is not None
        assert b"IB_STAGING_ADT" in member.read()


class _Run(NamedTuple):
    fingerprint: str | None
    manifest: dict[str, object]
    audit: dict[str, object]
    names: list[str]


async def _backup_of(tmp_path: Path, cfg: Path) -> _Run:
    tmp_path.mkdir(exist_ok=True)
    db = tmp_path / "b.db"
    store = await MessageStore.open(db)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "out"), allow_unencrypted=True),
        store_settings=StoreSettings(path=str(db)),
        config_dir=cfg,
    )
    try:
        result = await runner.run_once(now=1.0)
        audit = await _last_audit(store)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.status == "PASS"
    with _archive_tar(result.archive_path) as tar:
        return _Run(result.config_fingerprint, _manifest(tar), audit, tar.getnames())


@pytest.mark.parametrize("fault", ["unlistable-dir", "gone-dir"])
async def test_a_config_dir_that_cannot_be_read_is_recorded_as_not_bundled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fault: str,
) -> None:
    """The fold and the archive walk both list through glob, which swallows the error, so the
    archive would carry an empty config/ under a clean success. The backup still succeeds, since
    the store snapshot is worth keeping, and says plainly that it carries no config."""
    cfg, _staging = _roots(tmp_path)
    threads: list[threading.Thread] = []
    if fault == "unlistable-dir":
        expected = "PermissionError"
        # Listing the dir is denied while stat still works.
        real_scandir = os.scandir

        def scandir(path: Any = ".") -> Any:
            # On Linux shutil.rmtree walks by file descriptor and calls scandir(<int fd>); the
            # staging cleanup goes through here too, so anything that is not a path passes
            # straight through. Path(<int>) raised TypeError there and the cleanup kept the
            # plaintext staging dir (the ubuntu red on PR 2140).
            if isinstance(path, str | os.PathLike) and Path(path) == cfg:
                threads.append(threading.current_thread())
                raise PermissionError(13, "Permission denied", str(path))
            return real_scandir(path)

        monkeypatch.setattr(os, "scandir", scandir)
    else:
        expected = "FileNotFoundError"
        cfg = tmp_path / "gone"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.dr_backup"):
        run = await _backup_of(tmp_path, cfg)
    assert run.fingerprint is None
    not_bundled = (False, str(cfg), expected)
    assert _bundle_fields(run.manifest) == not_bundled
    assert _bundle_fields(run.audit) == not_bundled
    assert run.manifest["config_fingerprint"] is None and run.audit["config_fingerprint"] is None
    assert not [n for n in run.names if n.startswith("config/")]
    warnings = [r.getMessage() for r in caplog.records if "could not be read" in r.message]
    assert len(warnings) == 1 and str(cfg) in warnings[0] and expected in warnings[0]
    if fault == "unlistable-dir":
        # Every read of the config dir ran off the event loop.
        assert threads and all(t is not threading.main_thread() for t in threads)
    # The plaintext staging dir under the data dir is gone after the fault. The data dir holds the
    # store, so the walk below reads a real population.
    entries = list(tmp_path.iterdir())
    assert entries
    staged = [p.name for p in entries if p.name.startswith("mefor-") and p.is_dir()]
    assert staged == [], f"plaintext staging left behind: {staged}"


async def test_a_config_only_backup_of_an_unreadable_dir_fails(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A config-only archive without its config holds nothing to restore, yet it would verify and
    take a keep-N slot from one that does. It fails, through the existing failure path."""
    db = tmp_path / "b.db"
    store = await MessageStore.open(db)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "out"), allow_unencrypted=True),
        store_settings=StoreSettings(path=str(db)),
        config_dir=tmp_path / "gone",
    )
    try:
        with pytest.raises(BackupError) as raised:
            await runner.run_once(now=1.0, force_config_only=True)
        audit = await _last_audit(store)
    finally:
        await store.close()
    assert raised.value.kind == "snapshot" and "FileNotFoundError" in str(raised.value)
    assert audit["outcome"] == "error"
    # Control: the same runner shape with a readable dir writes a config-only archive.
    cfg, _staging = _roots(tmp_path / "control")
    run = await _backup_of(tmp_path / "control", cfg)
    assert run.manifest["config_bundled"] is True and "config/cfg.py" in run.names


async def test_a_fingerprint_fault_costs_only_the_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cfg, _staging = _roots(tmp_path)
    threads: list[threading.Thread] = []

    def failing(directory: object) -> str:
        threads.append(threading.current_thread())
        # What the fold raises on a file name that is not UTF-8 (vault BACKLOG #2839).
        raise UnicodeEncodeError("utf-8", "x\udc80", 1, 2, "surrogates not allowed")

    monkeypatch.setattr(fp, "config_fingerprint", failing)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.dr_backup"):
        run = await _backup_of(tmp_path, cfg)
    assert run.fingerprint is None
    # Taken once, and off the event loop.
    assert len(threads) == 1 and threads[0] is not threading.main_thread()
    warnings = [r.getMessage() for r in caplog.records if "config fingerprint failed" in r.message]
    assert len(warnings) == 1 and str(cfg) in warnings[0]
    assert _bundle_fields(run.manifest) == (True, str(cfg), None)
    assert "config/cfg.py" in run.names, "the config is still archived"


async def test_a_real_non_utf8_file_name_costs_only_the_fingerprint(tmp_path: Path) -> None:
    """The fault unmocked: the name vault BACKLOG #2839 used, which the fold cannot encode."""
    cfg, _staging = _roots(tmp_path)
    assert isinstance((await _backup_of(tmp_path / "control", cfg)).fingerprint, str)
    (cfg / "environments").mkdir()
    try:
        (cfg / "environments" / "x\udc80.toml").write_text("", encoding="utf-8")
    except (OSError, UnicodeEncodeError):
        pytest.skip("this file system will not store a name that is not UTF-8")
    run = await _backup_of(tmp_path / "bad", cfg)
    assert run.fingerprint is None and run.manifest["config_bundled"] is True


async def test_an_unexpected_fingerprint_fault_fails_the_pass_and_the_loop_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shared rule tolerates only a read fault. Anything else fails the pass, which the run's
    own failure path records, and the daily loop goes on to its next tick."""
    cfg, _staging = _roots(tmp_path)
    db = tmp_path / "b.db"
    store = await MessageStore.open(db)

    def broken(directory: object) -> str:
        raise RuntimeError("not a read fault")

    monkeypatch.setattr(fp, "config_fingerprint", broken)
    runner = BackupRunner(
        store,
        BackupSettings(
            enabled=True,
            destination=str(tmp_path / "out"),
            allow_unencrypted=True,
            schedule_at="00:00",
        ),
        store_settings=StoreSettings(path=str(db)),
        config_dir=cfg,
    )
    slept = asyncio.Event()

    async def sleep(_delay: float) -> None:
        slept.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(runner, "_sleep", sleep)
    try:
        runner.start()
        await asyncio.wait_for(slept.wait(), 30)
        task = runner._task
        assert task is not None and not task.done(), "the loop survived the failed pass"
        rows = await store.list_audit(action="dr_backup")
        assert len(rows) == 1 and json.loads(rows[0]["detail"])["outcome"] == "error"
    finally:
        await runner.stop()
        await store.close()


# --- the subprocess sandbox --------------------------------------------------------------------


def test_load_config_records_the_directory_and_the_shard_filter_keeps_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live, staging = _roots(tmp_path)
    # A relative --config is recorded resolved, so a worker spawned later loads the same target.
    monkeypatch.chdir(tmp_path)
    assert load_config("live").source_dir == live.resolve()
    assert load_config(staging).source_dir == staging.resolve()
    shard = filter_registry_for_shard(load_config(staging), DEFAULT_SHARD)
    assert shard.source_dir == staging.resolve()
    assert Registry().source_dir is None, "a graph built in code names no directory"


async def test_a_graph_built_in_code_falls_back_to_the_configured_source(tmp_path: Path) -> None:
    live, _staging = _roots(tmp_path)
    loaded = load_config(live)
    built = Registry(
        inbound=loaded.inbound,
        outbound=loaded.outbound,
        routers=loaded.routers,
        handlers=loaded.handlers,
    )
    store = await MessageStore.open(tmp_path / "s.db")
    policy = SandboxPolicy(mode=SandboxMode.SUBPROCESS)
    try:
        configured = RegistryRunner(
            built,
            store,
            sandbox_policy=policy,
            sandbox_config_source=(str(live), None),
            egress=EgressSettings(deny_by_default=False),
        )
        session = configured._sandbox_for("IB_LIVE_ADT")
        assert session is not None and session._config_dir == str(live)
        # With no directory on either side there is nothing to load, so it runs in-process.
        bare = RegistryRunner(
            built, store, sandbox_policy=policy, egress=EgressSettings(deny_by_default=False)
        )
        assert bare._sandbox_for("IB_LIVE_ADT") is None
    finally:
        await store.close()


async def _settled(store: MessageStore, mid: str, timeout: float = 90.0) -> str:
    terminal = {MessageStatus.PROCESSED.value, MessageStatus.ERROR.value}
    deadline = asyncio.get_running_loop().time() + timeout
    status = ""
    while asyncio.get_running_loop().time() < deadline:
        msg = await store.get_message(mid)
        assert msg is not None
        status = str(msg["status"])
        if status in terminal:
            return status
        await asyncio.sleep(0.05)
    return status


async def test_sandbox_workers_load_the_root_a_reload_applied(tmp_path: Path) -> None:
    """After a reload from another root a worker loads that root: a dispatch on the new graph's
    inbound is served by a child whose graph matches the parent's. A child that loaded the startup
    dir would hold IB_LIVE_ADT where the parent serves IB_STAGING_ADT, and be refused."""
    live, staging = _roots(tmp_path)
    store = await MessageStore.open(tmp_path / "sb.db")
    engine = Engine(
        store,
        poll_interval=0.05,
        config_dir=live,
        config_reload_roots=[str(staging)],
        sandbox_settings=SandboxSettings(mode="subprocess", wall_seconds=60.0),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.reload_detail(live)
        rr = engine.registry_runner
        assert rr is not None
        # Control: under the startup graph a session loads the startup dir.
        before = rr._sandbox_for("IB_LIVE_ADT")
        assert before is not None and Path(before._config_dir) == live.resolve()

        await engine.reload_detail(staging)
        after = rr._sandbox_for("IB_STAGING_ADT")
        assert after is not None and Path(after._config_dir) == staging.resolve()
        assert before._closed, "the reload recycled the session made under the old graph"

        mid = await store.enqueue_ingress(
            channel_id="IB_STAGING_ADT", raw=RAW, control_id="DIR00001", message_type="ADT^A01"
        )
        rr._wake_lane(Stage.INGRESS, "IB_STAGING_ADT")
        assert await _settled(store, mid) == MessageStatus.PROCESSED.value
    finally:
        await engine.stop()
