# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L3 multi-process supervisor: shard-spec derivation + spawn/restart/stop lifecycle.

The lifecycle tests inject a fake "process" (a controllable stand-in for an
``asyncio.subprocess.Process``) so they exercise the supervisor's monitor/restart/terminate logic
deterministically and fast, without launching real engine subprocesses (Windows-safe)."""

from __future__ import annotations

import argparse
import asyncio

import pytest

from messagefoundry.pipeline.supervisor import (
    ShardSpec,
    Supervisor,
    build_shard_specs,
)


# --- shard-spec derivation (pure) --------------------------------------------


def test_single_default_shard_keeps_base_path_and_port() -> None:
    specs = build_shard_specs(["default"], config="cfg", db_base="mefor.db", base_port=8765)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.db_path == "mefor.db"  # bare base — identical to a non-sharded serve
    assert spec.port == 8765
    assert "--shard" in spec.argv and "default" in spec.argv


def test_multi_shard_derives_distinct_db_and_ports_in_sorted_order() -> None:
    specs = build_shard_specs(["b", "a"], config="cfg", db_base="store/mefor.db", base_port=9000)
    by_shard = {s.shard: s for s in specs}
    # Sorted order assigns ports deterministically (a -> base, b -> base+1).
    assert by_shard["a"].port == 9000
    assert by_shard["b"].port == 9001
    # Each shard gets its own db file (<stem>_<shard><suffix>), distinct from siblings.
    assert by_shard["a"].db_path.endswith("mefor_a.db")
    assert by_shard["b"].db_path.endswith("mefor_b.db")
    assert by_shard["a"].db_path != by_shard["b"].db_path


def test_spec_argv_includes_env_and_service_config_when_given() -> None:
    specs = build_shard_specs(
        ["a", "b"],
        config="cfg",
        db_base="m.db",
        base_port=8765,
        env="prod",
        service_config="svc.toml",
    )
    argv = specs[0].argv
    assert "--env" in argv and "prod" in argv
    assert "--service-config" in argv and "svc.toml" in argv
    assert argv[:4] == (specs[0].argv[0], "-m", "messagefoundry", "serve")


def test_spec_argv_includes_project_root_when_given() -> None:
    # --project-root is forwarded to EVERY shard so a spawned `serve --env <e>` resolves
    # environments/<e>.toml against the given root, not the child's working directory.
    specs = build_shard_specs(
        ["a", "b"],
        config="cfg",
        db_base="m.db",
        base_port=8765,
        env="prod",
        project_root="C:/srv/mefor",
    )
    for spec in specs:
        argv = spec.argv
        assert "--project-root" in argv
        assert argv[argv.index("--project-root") + 1] == "C:/srv/mefor"


def test_spec_argv_omits_project_root_when_not_given() -> None:
    specs = build_shard_specs(["a"], config="cfg", db_base="m.db", base_port=8765)
    assert "--project-root" not in specs[0].argv


def test_shard_db_composes_under_project_root(tmp_path: object) -> None:
    """ADR 0050 AC-9: with ``supervise --project-root R`` and a relative ``--db`` (no absolute path), the
    supervisor composes each shard's ``<stem>_<shard>.db`` **under R** — not against the child CWD.

    Anchoring happens in ``_supervise`` BEFORE ``supervise()`` discovers shards, so the db_base passed to
    ``build_shard_specs`` is already absolute-under-R; the per-shard composition then keeps it there. We
    patch ``supervise`` (as imported into ``_supervise``) to capture the resolved config + db_base, run
    ``build_shard_specs`` on the captured base, and assert each shard DB lands under R.
    """
    from pathlib import Path

    from messagefoundry import __main__ as cli

    root = Path(str(tmp_path)) / "repo"
    root.mkdir()
    captured: dict[str, object] = {}

    async def _fake_supervise(config: str, *, db_base: str, **_kw: object) -> int:
        captured["config"] = config
        captured["db_base"] = db_base
        return 0

    monkey = pytest.MonkeyPatch()
    monkey.setattr("messagefoundry.pipeline.supervisor.supervise", _fake_supervise)
    try:
        args = argparse.Namespace(
            config="config",  # relative — must resolve under R
            db="mefor.db",  # relative — must resolve under R
            base_port=8765,
            env="prod",
            service_config=None,
            project_root=str(root),
        )
        assert cli._supervise(args) == 0
    finally:
        monkey.undo()

    # The discovery config + db base are anchored under R (so discover_shard_specs.load_config and the
    # per-shard composition both resolve against R, from any CWD).
    assert captured["config"] == str(root / "config")
    assert captured["db_base"] == str(root / "mefor.db")
    # And the per-shard <stem>_<shard>.db therefore composes under R.
    specs = build_shard_specs(
        ["a", "b"], config=str(captured["config"]), db_base=str(captured["db_base"]), base_port=8765
    )
    for spec in specs:
        assert Path(spec.db_path).parent == root
        assert Path(spec.db_path).name in {"mefor_a.db", "mefor_b.db"}


# --- lifecycle (fake process) ------------------------------------------------


class _FakeProcess:
    """A controllable stand-in for asyncio.subprocess.Process.

    ``wait()`` blocks until ``finish(rc)`` is called (simulating a child exit / crash). ``terminate()``
    finishes it with rc=-15; ``kill()`` with rc=-9. ``returncode`` is None until it finishes."""

    _next_pid = 1000

    def __init__(self) -> None:
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.returncode: int | None = None
        self._exited = asyncio.Event()
        self.terminated = False
        self.killed = False

    def finish(self, rc: int = 0) -> None:
        if self.returncode is None:
            self.returncode = rc
            self._exited.set()

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.finish(-15)

    def kill(self) -> None:
        self.killed = True
        self.finish(-9)


def _spec(shard: str, port: int = 8765) -> ShardSpec:
    return ShardSpec(shard=shard, db_path=f"{shard}.db", port=port, argv=("python", shard))


@pytest.mark.asyncio
async def test_spawns_one_child_per_shard_then_stops_cleanly() -> None:
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor([_spec("a", 8765), _spec("b", 8766)], spawn=spawn, terminate_grace=2.0)
    run = asyncio.create_task(sup.run())
    # Let both children spawn.
    for _ in range(50):
        if len(spawned) == 2:
            break
        await asyncio.sleep(0)
    assert len(spawned) == 2

    sup.stop()
    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run
    # Every child was terminated on shutdown.
    assert all(p.terminated for p in spawned)


@pytest.mark.asyncio
async def test_restarts_a_crashed_child() -> None:
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor([_spec("a")], spawn=spawn, restart=True, terminate_grace=2.0)
    run = asyncio.create_task(sup.run())
    while not spawned:
        await asyncio.sleep(0)

    # First child crashes -> the supervisor must spawn a replacement.
    spawned[0].finish(1)
    for _ in range(100):
        if len(spawned) == 2:
            break
        await asyncio.sleep(0)
    assert len(spawned) == 2
    assert sup.restarts["a"] == 1

    sup.stop()
    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run


@pytest.mark.asyncio
async def test_no_restart_when_disabled() -> None:
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor([_spec("a")], spawn=spawn, restart=False)
    run = asyncio.create_task(sup.run())
    while not spawned:
        await asyncio.sleep(0)

    spawned[0].finish(0)  # clean exit; restart disabled -> the watcher returns
    await asyncio.wait_for(run, timeout=2.0)  # run() completes once the only watcher returns
    assert len(spawned) == 1
    assert "a" not in sup.restarts


@pytest.mark.asyncio
async def test_terminate_escalates_to_kill_after_grace() -> None:
    class _StubbornProcess(_FakeProcess):
        def terminate(self) -> None:  # ignore terminate -> force the kill escalation path
            self.terminated = True

    proc = _StubbornProcess()

    async def spawn(spec: ShardSpec) -> _StubbornProcess:
        return proc

    # A tiny grace so the kill-after-timeout path runs fast.
    sup = Supervisor([_spec("a")], spawn=spawn, terminate_grace=0.05)
    run = asyncio.create_task(sup.run())
    for _ in range(50):
        if "a" in sup._children:  # wait until the child is spawned + registered
            break
        await asyncio.sleep(0)
    assert "a" in sup._children

    sup.stop()
    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run
    assert proc.terminated and proc.killed  # escalated to kill after the grace elapsed
