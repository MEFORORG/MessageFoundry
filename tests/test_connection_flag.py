# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Object flagging + the FIRST console→connections.toml write seam (BACKLOG #131, ADR 0007 amendment).

``Engine.set_connection_flag`` persists the operator "object of interest" flag into ``connections.toml``
via the comment-preserving, validate-before-persist writer and reflects it on the LIVE registry without a
reload. It is scoped to ``connections.toml``-managed connections ONLY — the SCOPE FORK: a code-first
connection has no TOML home for it, so the write is refused (→ 409 at the API), and this lane makes NO
store schema change. A cluster node refuses it too (vault BACKLOG #2933), and the engine records the
``connection_flag_set`` row itself (vault BACKLOG #2945)."""

from __future__ import annotations

import asyncio
import os
import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry.pipeline import Engine

# A code-first module supplying the router/handler the TOML inbound binds by name, PLUS a code-first
# outbound (OB_CODE) that has no connections.toml home — the scope-fork subject. Loopback MLLP hosts so
# build_check's cleartext-hop guard never refuses (loopback is exempt), no File dirs to create.
LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import MLLP, Send, handler, outbound, router

    outbound("OB_CODE", MLLP(host="127.0.0.1", port=2701))

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB_TOML", msg)
    """
)

CONNECTIONS_TOML = textwrap.dedent(
    """
    # A hand-authored comment that must survive the flag write (tomlkit preserves it).
    [[inbound]]
    name = "IB_TOML"
    transport = "mllp"
    router = "r"
    [inbound.settings]
    port = 2600

    [[outbound]]
    name = "OB_TOML"
    transport = "mllp"
    [outbound.settings]
    host = "127.0.0.1"
    port = 2700
    """
)


def _config_dir(tmp_path: Path) -> Path:
    (tmp_path / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(CONNECTIONS_TOML, encoding="utf-8")
    return tmp_path


@pytest.fixture
async def engine(tmp_path: Path):
    cfg = _config_dir(tmp_path)
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    # Load + attach the graph WITHOUT starting listeners (no socket binds needed for this test).
    eng.add_registry(load_config(cfg))
    yield eng
    await eng.stop()


async def test_flag_toggle_persists_and_reflects(engine: Engine, tmp_path: Path) -> None:
    """A flag toggle on a connections.toml-managed connection persists ``flagged = true`` (comments
    preserved) AND updates the live registry entry in place — no reload, no store schema change."""
    toml_path = tmp_path / "connections.toml"
    assert engine.registry_runner is not None
    assert engine.registry_runner.registry.outbound["OB_TOML"].flagged is False

    await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
    )

    # Persisted to connections.toml (comment intact), and reflected on the LIVE registry immediately.
    text = toml_path.read_text(encoding="utf-8")
    assert "flagged = true" in text
    assert "A hand-authored comment" in text  # tomlkit preserved the surrounding trivia
    assert engine.registry_runner.registry.outbound["OB_TOML"].flagged is True

    # Toggling back clears it.
    await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=False, actor="tester", client=None
    )
    assert engine.registry_runner.registry.outbound["OB_TOML"].flagged is False
    assert "flagged = false" in toml_path.read_text(encoding="utf-8")


async def _exposed_engine(tmp_path: Path, *, allow: bool) -> Engine:
    """An engine whose inbound listeners bind 0.0.0.0 in cleartext, on a non-enforcing instance, with
    or without the cleartext escape. IB_TOML is then exposed."""
    from messagefoundry.config.tls_policy import HopPosture

    cfg = _config_dir(tmp_path)
    return await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        inbound_bind_host="0.0.0.0",
        allow_insecure_bind=allow,
        hop_posture=HopPosture(enforcing=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )


@pytest.mark.parametrize("allow", [True, False])
async def test_flag_toggle_and_dry_run_carry_the_engines_escape(
    tmp_path: Path, allow: bool
) -> None:
    """Vault BACKLOG #2622 item 1: the build check both paths run now includes the inbound exposure
    gates. An engine started with the escape accepted IB_TOML, so neither its dry-run reload (no
    live runner, so a throwaway checker) nor a flag toggle may refuse it. Without the escape both
    refuse, which shows the pass is the escape reaching the gate and not the gate never running."""
    eng = await _exposed_engine(tmp_path, allow=allow)
    try:
        if allow:
            await eng.reload_detail(str(tmp_path), dry_run=True)
        else:
            with pytest.raises(WiringError, match="without TLS"):
                await eng.reload_detail(str(tmp_path), dry_run=True)
        eng.add_registry(load_config(tmp_path))
        if allow:
            await eng.set_connection_flag(
                "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
            )
        else:
            with pytest.raises(WiringError, match="without TLS"):
                await eng.set_connection_flag(
                    "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
                )
    finally:
        await eng.stop()


@pytest.mark.parametrize("auto_start", [False, True])
async def test_a_listener_start_leaves_down_refuses_no_reload_toggle_or_dr_activation(
    tmp_path: Path, auto_start: bool
) -> None:
    """Vault BACKLOG #2622 item 1, review round 3. IB_TOML binds 0.0.0.0 in cleartext with no escape.
    With ``auto_start = false`` engine start never binds it, so a dry run, a reload, a flag toggle
    and a DR activation (a re-apply of the running graph, vault BACKLOG #3067) must all apply, as
    they did before the build check ran the exposure gates. With ``auto_start = true`` the
    listener would be bound, so the build check still refuses all four, naming the listener and the two settings that leave it
    down. That is the control: the passes are the predicate, not a gate that never ran."""
    eng = await _exposed_engine(tmp_path, allow=False)
    toml_path = tmp_path / "connections.toml"
    text = toml_path.read_text(encoding="utf-8")
    # priority = "critical" keeps the DR arm about auto_start alone: no DR threshold parks it.
    lifecycle = f'auto_start = {str(auto_start).lower()}\npriority = "critical"\n'
    toml_path.write_text(
        text.replace('router = "r"\n', f'router = "r"\n{lifecycle}'), encoding="utf-8"
    )
    try:
        # Running, so the reload and the DR activation take the quiesce-and-swap path rather than the
        # not-running shortcut. No listener binds: IB_TOML is either auto_start = false, or isolated
        # by the very gate under test.
        await eng.add_registry(load_config(tmp_path)).start()

        async def _flag() -> None:
            await eng.set_connection_flag(
                "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
            )

        steps = {
            "dry run": lambda: eng.reload_detail(str(tmp_path), dry_run=True),
            "reload": lambda: eng.reload(tmp_path),
            "flag toggle": _flag,
            "DR activation": eng._dr_activate_profile,
        }
        for step, run in steps.items():
            if auto_start:
                with pytest.raises(WiringError, match="without TLS") as refused:
                    await run()
                assert "'IB_TOML' would be bound" in str(refused.value), step
                assert "auto_start = false" in str(refused.value), step
            else:
                await run()
        # A refused activation puts the DR latch back; an applied one leaves it set.
        assert eng.dr_active is (not auto_start)
    finally:
        await eng.stop()


async def test_flag_toggle_reflects_on_inbound(engine: Engine, tmp_path: Path) -> None:
    await engine.set_connection_flag(
        "IB_TOML", direction="inbound", flagged=True, actor="tester", client=None
    )
    assert engine.registry_runner is not None
    assert engine.registry_runner.registry.inbound["IB_TOML"].flagged is True
    assert "flagged = true" in (tmp_path / "connections.toml").read_text(encoding="utf-8")


async def test_flag_toggle_refuses_code_first(engine: Engine, tmp_path: Path) -> None:
    """The SCOPE FORK: a code-first connection (not in connections.toml) has no TOML home, so the flag
    write is refused and connections.toml is left untouched (no store schema change is ever attempted)."""
    before = (tmp_path / "connections.toml").read_text(encoding="utf-8")
    with pytest.raises(WiringError, match="not managed in connections.toml"):
        await engine.set_connection_flag(
            "OB_CODE", direction="outbound", flagged=True, actor="tester", client=None
        )
    assert (tmp_path / "connections.toml").read_text(encoding="utf-8") == before


async def test_flag_toggle_rejects_bad_direction(engine: Engine) -> None:
    with pytest.raises(WiringError, match="direction"):
        await engine.set_connection_flag(
            "OB_TOML", direction="sideways", flagged=True, actor="tester", client=None
        )


async def test_concurrent_flag_writes_both_land(engine: Engine, tmp_path: Path) -> None:
    """Two overlapping console→connections.toml flag writes BOTH land — serialized by the engine-level
    TOML-write lock, so neither read-modify-write loses the other's update — and the file stays valid
    with no leftover temp (the unique per-write temp is renamed or cleaned up). Locks the #131/#136
    review's concurrency fix (the FIRST console→TOML write seam)."""
    await asyncio.gather(
        engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        ),
        engine.set_connection_flag(
            "IB_TOML", direction="inbound", flagged=True, actor="tester", client=None
        ),
    )
    reg = load_config(tmp_path)  # the file still parses + loads cleanly
    assert reg.outbound["OB_TOML"].flagged is True  # neither update was lost
    assert reg.inbound["IB_TOML"].flagged is True
    # No leftover edit candidate, in either the old temp-file shape or the private-directory one.
    assert not list(tmp_path.glob("connections.toml.*.tmp"))
    assert not list(tmp_path.glob(".connections.toml.*.edit"))


def test_flagged_survives_toml_roundtrip(tmp_path: Path) -> None:
    """The write schema carries ``flagged`` (parity with the read schema), so a load→write→load
    round-trip preserves it — the #234 key-loss guard, now covering the new key."""
    (tmp_path / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(CONNECTIONS_TOML, encoding="utf-8")
    from messagefoundry.config import connections_edit

    def _noop(_dir: Path) -> None: ...

    entries = connections_edit.list_connections(tmp_path)
    ob = next(e for e in entries if e["name"] == "OB_TOML")
    ob["flagged"] = True
    connections_edit.upsert_connection(tmp_path, ob, validate=_noop)

    reg = load_config(tmp_path)
    assert reg.outbound["OB_TOML"].flagged is True


async def test_a_cluster_node_refuses_the_toggle_and_writes_nothing(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #2933: each cluster node loads its own config directory, which
    docs/CLUSTERING.md requires to be identical on every node. A toggle on one node could reach only
    that node's connections.toml, so the nodes' files would diverge. A cluster node refuses it before
    any write: the file, the live flag and the audit trail are all unchanged. RED on the unfixed
    engine, which never read ``is_clustered()`` and wrote the file."""
    from messagefoundry.pipeline.engine import ClusteredConfigWrite

    toml_path = tmp_path / "connections.toml"
    before = toml_path.read_bytes()
    monkeypatch.setattr(type(engine.coordinator), "is_clustered", lambda self: True)
    with pytest.raises(ClusteredConfigWrite, match="cluster node"):
        await engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    assert toml_path.read_bytes() == before
    assert engine.registry_runner is not None
    assert engine.registry_runner.registry.outbound["OB_TOML"].flagged is False
    assert await engine.store.list_audit(action="connection_flag_set") == []
    # A WiringError, so the route answers it 409 as it does every refused flag write.
    assert issubclass(ClusteredConfigWrite, WiringError)

    # Control: the same engine, single-node again, writes the flag and records the row.
    monkeypatch.undo()
    await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
    )
    assert "flagged = true" in toml_path.read_text(encoding="utf-8")
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 1


async def test_the_toggle_records_its_own_baseline_row(engine: Engine, tmp_path: Path) -> None:
    """Vault BACKLOG #2945: the write, its digest and the ``connection_flag_set`` row come from one
    engine helper, so the row names the digest of the bytes just written, under the actor given."""
    import json

    from messagefoundry.config.fingerprint import config_fingerprint_detail

    engine.loaded_config_fingerprint = config_fingerprint_detail(tmp_path)
    returned = await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="alice", client="127.0.0.1"
    )
    on_disk = config_fingerprint_detail(tmp_path)["fingerprint"]
    assert returned is not None and returned["fingerprint"] == on_disk
    assert engine.loaded_config_fingerprint == returned
    rows = await engine.store.list_audit(action="connection_flag_set")
    assert [row["actor"] for row in rows] == ["alice"]
    detail = json.loads(rows[0]["detail"])
    assert detail["fingerprint"] == on_disk
    assert detail["connection"] == "OB_TOML" and detail["flagged"] is True
    assert detail["node"] == engine.coordinator.node_id


async def test_the_helper_refuses_a_detail_it_cannot_record_before_writing(
    engine: Engine, tmp_path: Path
) -> None:
    """A detail key the helper writes itself, or a value JSON cannot carry, is refused before the
    write, so a fault there can never leave a landed write with no row."""
    wrote: list[Path] = []
    for detail in ({"fingerprint": "f" * 64}, {"path": tmp_path}):
        with pytest.raises((ValueError, TypeError)):
            await engine.write_baseline_config(
                "connection_flag_set",
                wrote.append,
                touches=(),
                detail=detail,
                actor="tester",
                client=None,
            )
    assert wrote == []
    assert await engine.store.list_audit(action="connection_flag_set") == []


async def test_a_cancelled_caller_does_not_cost_a_landed_write_its_row(engine: Engine) -> None:
    """Once the write is under way, cancelling the caller (a request deadline, a client that went
    away) still lets the write and its row finish, so the next start sees no change nobody made."""
    import threading

    started, release = threading.Event(), threading.Event()

    def _write(_cfg: Path) -> None:
        started.set()
        release.wait(20)

    caller = asyncio.ensure_future(
        engine.write_baseline_config(
            "connection_flag_set",
            _write,
            touches=(),
            detail={"probe": True},
            actor="tester",
            client=None,
        )
    )
    try:
        assert await asyncio.to_thread(started.wait, 20)
        caller.cancel()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await caller
    for _ in range(200):
        if await engine.store.list_audit(action="connection_flag_set"):
            break
        await asyncio.sleep(0.05)
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 1


async def test_a_caller_cancelled_before_its_write_starts_gets_no_write(
    engine: Engine, tmp_path: Path
) -> None:
    """A caller still queued for the engine lock has started nothing, so cancelling it leaves the
    file and the audit trail alone, even once the lock frees. Under the round-one shield the queued
    write ran later anyway, under the name of a caller who had been told it failed."""
    toml_path = tmp_path / "connections.toml"
    before = toml_path.read_bytes()
    await engine._toml_write_lock.acquire()
    try:
        caller = asyncio.ensure_future(
            engine.set_connection_flag(
                "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
            )
        )
        await asyncio.sleep(0.1)
        assert not caller.done(), "control: the toggle is queued on the held lock"
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
    finally:
        engine._toml_write_lock.release()
    await asyncio.sleep(0.5)
    assert toml_path.read_bytes() == before
    assert await engine.store.list_audit(action="connection_flag_set") == []
    assert not engine._toml_write_lock.locked()


async def test_a_failed_row_does_not_leave_the_loaded_digest_behind(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the row fails, the write is put back (vault BACKLOG #2945), so this process's baseline
    still matches its own disk and live graph, and its next toggle vouches again and records the
    true digest. The round-one order kept the old digest, and every later row recorded it until a
    reload."""
    from messagefoundry.config.fingerprint import config_fingerprint_detail
    from messagefoundry.pipeline.engine import ConfigWriteAuditFailed

    engine.loaded_config_fingerprint = config_fingerprint_detail(tmp_path)
    toml_path = tmp_path / "connections.toml"
    before = toml_path.read_bytes()

    async def _refused(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("the audit store refused the row")

    monkeypatch.setattr(engine.store, "record_audit", _refused)
    # A refusal that says whether the change was undone, not the store's own error, which a route
    # could only answer 500 (vault BACKLOG #2945). The store's error stays chained for the log.
    with pytest.raises(ConfigWriteAuditFailed, match="was undone") as refused:
        await engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    assert refused.value.undone is True
    assert isinstance(refused.value.__cause__, RuntimeError)
    # No write left on disk without its row, and the live graph never showed it.
    assert toml_path.read_bytes() == before
    assert engine.registry_runner is not None
    assert engine.registry_runner.registry.outbound["OB_TOML"].flagged is False
    assert engine.loaded_config_fingerprint == config_fingerprint_detail(tmp_path)
    monkeypatch.undo()
    returned = await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=False, actor="tester", client=None
    )
    assert returned is not None
    assert returned["fingerprint"] == config_fingerprint_detail(tmp_path)["fingerprint"]


async def test_stop_waits_for_a_write_whose_caller_was_cancelled(tmp_path: Path) -> None:
    """stop() lets a write whose caller has gone finish before it closes the store, so the write's
    row lands. With the round-one untracked task the store closed under it and the row was lost."""
    import threading

    cfg = _config_dir(tmp_path)
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    eng.add_registry(load_config(cfg))
    started, release = threading.Event(), threading.Event()
    recorded: list[str] = []
    real_record = eng.store.record_audit

    async def _recording(action: str, **kwargs: object) -> None:
        await real_record(action, **kwargs)  # type: ignore[arg-type]
        recorded.append(action)

    eng.store.record_audit = _recording  # type: ignore[method-assign]

    def _write(_cfg: Path) -> None:
        started.set()
        release.wait(20)

    stopping: asyncio.Future[None] | None = None
    try:
        caller = asyncio.ensure_future(
            eng.write_baseline_config(
                "connection_flag_set",
                _write,
                touches=(),
                detail={"probe": True},
                actor="tester",
                client=None,
            )
        )
        try:
            assert await asyncio.to_thread(started.wait, 20)
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller
            stopping = asyncio.ensure_future(eng.stop())
            await asyncio.sleep(0.2)
        finally:
            release.set()
        await stopping
        assert recorded == ["connection_flag_set"]
    finally:
        if stopping is None:
            await eng.stop()


async def test_a_write_queued_when_stop_begins_is_refused_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """stop() closes the gate before it waits, so a caller still queued for the engine lock is
    refused once it gets the lock, instead of starting a write the drain never saw and landing it
    on disk as the store closes."""
    cfg = _config_dir(tmp_path)
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    eng.add_registry(load_config(cfg))
    toml_path = cfg / "connections.toml"
    before = toml_path.read_bytes()
    await eng._toml_write_lock.acquire()
    caller = asyncio.ensure_future(
        eng.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    )
    try:
        await asyncio.sleep(0.1)
        assert not caller.done(), "control: the toggle is queued on the held lock"
        await eng.stop()
    finally:
        eng._toml_write_lock.release()
    with pytest.raises(WiringError, match="stopping"):
        await caller
    assert toml_path.read_bytes() == before


async def test_a_write_cancelled_before_its_first_step_releases_the_lock(engine: Engine) -> None:
    """The engine lock is released however the write's task ends. A task cancelled before it ever
    ran never entered the round-one try/finally, so the lock stayed held and every later toggle
    queued forever."""
    caller = asyncio.ensure_future(
        engine.write_baseline_config(
            "connection_flag_set",
            lambda _cfg: None,
            touches=(),
            detail={},
            actor="tester",
            client=None,
        )
    )
    # One pass of the loop: the caller takes the free lock and schedules its task, which has not
    # run yet.
    await asyncio.sleep(0)
    (task,) = engine._config_writes
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert not engine._toml_write_lock.locked()
    # And the engine still takes a write.
    await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
    )


async def test_a_write_that_fails_after_its_caller_went_is_logged_once(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """A write that fails once its caller is gone is logged once, through safe_exc, and not also
    reported by asyncio as an exception in a shielded future with a raw traceback."""
    import logging
    import threading

    started, release = threading.Event(), threading.Event()

    def _write(_cfg: Path) -> None:
        started.set()
        release.wait(20)
        raise WiringError("validate refused the candidate")

    caller = asyncio.ensure_future(
        engine.write_baseline_config(
            "connection_flag_set", _write, touches=(), detail={}, actor="tester", client=None
        )
    )
    with caplog.at_level(logging.WARNING):
        try:
            assert await asyncio.to_thread(started.wait, 20)
            caller.cancel()
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await caller
        while engine._config_writes:
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.05)
    messages = [record.getMessage() for record in caplog.records]
    abandoned = [m for m in messages if m.startswith("config write failed after its caller")]
    assert len(abandoned) == 1, messages
    assert "validate refused the candidate" in abandoned[0]
    assert not [m for m in messages if "shielded future" in m]
    assert await engine.store.list_audit(action="connection_flag_set") == []


async def test_the_toggle_takes_its_digests_under_the_config_edit_lock(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #2782: both config digests are taken while the toggle holds the cross-process
    edit lock, so a `connection` or `codeset` CLI edit cannot land between them and be vouched for as
    loaded. Probed from a second thread, which must find the lock taken at each digest."""
    import threading

    from messagefoundry.config import atomic_edit
    from messagefoundry.config.fingerprint import config_fingerprint_detail

    engine.loaded_config_fingerprint = config_fingerprint_detail(tmp_path)
    real = Engine.fingerprint_bundle_blocking
    held_at_digest: list[bool] = []

    def _probe() -> bool:
        free: list[bool] = []

        def run() -> None:
            try:
                with atomic_edit.edit_lock(tmp_path / "connections.toml", timeout=0):
                    free.append(True)
            except TimeoutError:
                free.append(False)

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(20)
        return free == [False]

    def _recording(self: Engine, path: Path) -> tuple[dict[str, object] | None, str | None]:
        held_at_digest.append(_probe())
        return real(self, path)

    monkeypatch.setattr(Engine, "fingerprint_bundle_blocking", _recording)
    await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
    )
    assert held_at_digest == [True, True], "control: both digests were taken, each under the lock"
    assert not _probe(), "control: the probe reads the lock as free once the toggle returns"


def _hang_the_row(engine: Engine, monkeypatch: pytest.MonkeyPatch, *, bound: float = 0.3) -> None:
    """A store that never answers the config row, and a short audit bound (vault BACKLOG #2945)."""
    from messagefoundry.pipeline import engine as engine_module

    async def _hung(*_args: object, **_kwargs: object) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(engine_module, "CONFIG_WRITE_AUDIT_TIMEOUT_SECONDS", bound)
    monkeypatch.setattr(engine.store, "record_audit", _hung)


async def test_a_hung_row_times_out_undoes_the_write_and_frees_the_lock(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #2945: the row is written under the engine lock, so a store that never answers
    used to hold the lock, and every later config write, until it did. The row is now bounded: the
    write times out, its file goes back to the bytes it held, the caller is told why, and the lock
    is free for the next write."""
    from messagefoundry.config.fingerprint import config_fingerprint_detail
    from messagefoundry.pipeline.engine import ConfigWriteAuditTimeout

    engine.loaded_config_fingerprint = loaded = config_fingerprint_detail(tmp_path)
    toml_path = tmp_path / "connections.toml"
    before = toml_path.read_bytes()
    _hang_the_row(engine, monkeypatch)
    with pytest.raises(ConfigWriteAuditTimeout, match="was not recorded within 0.3 s") as refused:
        await asyncio.wait_for(
            engine.set_connection_flag(
                "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
            ),
            20,
        )
    assert refused.value.undone is True
    assert "undone" in str(refused.value)
    assert isinstance(refused.value, WiringError), "a refusal, never a raw error"
    assert toml_path.read_bytes() == before
    assert engine.registry_runner is not None
    assert engine.registry_runner.registry.outbound["OB_TOML"].flagged is False
    assert engine.loaded_config_fingerprint == loaded
    assert not engine._toml_write_lock.locked()
    assert not engine._config_writes
    # The store answers again, and the next write lands with its row.
    monkeypatch.undo()
    returned = await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
    )
    assert returned is not None
    assert returned["fingerprint"] == config_fingerprint_detail(tmp_path)["fingerprint"]
    assert "flagged = true" in toml_path.read_text(encoding="utf-8")
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 1


async def test_a_hung_row_undoes_a_file_the_write_created(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A declared file the write created is removed by the undo, so the directory digests as it did
    before the write; a file the write does not declare is not the undo's to touch."""
    from messagefoundry.config.fingerprint import config_fingerprint
    from messagefoundry.pipeline.engine import ConfigWriteAuditTimeout

    digest_before = config_fingerprint(tmp_path)

    def _write(cfg: Path) -> None:
        (cfg / "environments").mkdir()
        (cfg / "environments" / "dev.toml").write_text("x = 1\n", encoding="utf-8")
        (cfg / "notes.txt").write_text("not declared\n", encoding="utf-8")

    _hang_the_row(engine, monkeypatch)
    with pytest.raises(ConfigWriteAuditTimeout):
        await engine.write_baseline_config(
            "connection_flag_set",
            _write,
            touches=("environments/dev.toml",),
            detail={},
            actor="tester",
            client=None,
        )
    assert not (tmp_path / "environments" / "dev.toml").exists()
    assert (tmp_path / "notes.txt").exists(), "control: the write ran"
    assert config_fingerprint(tmp_path) == digest_before


async def test_the_helper_refuses_a_touched_path_outside_the_config_dir(engine: Engine) -> None:
    """A declared path the undo would resolve outside the config directory is refused before the
    write runs."""
    wrote: list[Path] = []
    rels = ["../outside.toml", "", ".", str(Path.cwd() / "x.toml")]
    if os.name == "nt":
        # A rooted path with no drive and a drive-relative one escape only on Windows.
        rels += ["\\x.toml", "C:x.toml"]
    for rel in rels:
        with pytest.raises(ValueError, match="outside the config directory"):
            await engine.write_baseline_config(
                "connection_flag_set",
                wrote.append,
                touches=(rel,),
                detail={},
                actor="tester",
                client=None,
            )
    with pytest.raises(TypeError, match="not one string"):
        await engine.write_baseline_config(
            "connection_flag_set",
            wrote.append,
            touches="connections.toml",
            detail={},
            actor="tester",
            client=None,
        )
    assert wrote == []


async def test_a_failed_rows_undo_leaves_an_edit_made_elsewhere_during_the_write(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #2945: the undo puts back only the files the write declares. A writer that
    takes no lock, such as an editor saving ``environments/dev.toml``, can land while the toggle
    runs. Under a whole-directory snapshot that edit read as the toggle's own change, and the undo
    deleted the new file."""
    from messagefoundry.config import connections_edit
    from messagefoundry.pipeline.engine import ConfigWriteAuditTimeout

    real_upsert = connections_edit.upsert_connection
    edited = tmp_path / "environments" / "dev.toml"

    def _upsert_beside_an_editor(*args: Any, **kwargs: Any) -> None:
        edited.parent.mkdir()
        edited.write_text("operator = 'saved meanwhile'\n", encoding="utf-8")
        real_upsert(*args, **kwargs)

    monkeypatch.setattr(connections_edit, "upsert_connection", _upsert_beside_an_editor)
    toml_path = tmp_path / "connections.toml"
    before = toml_path.read_bytes()
    _hang_the_row(engine, monkeypatch)
    with pytest.raises(ConfigWriteAuditTimeout) as refused:
        await engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    assert refused.value.undone is True
    assert toml_path.read_bytes() == before, "control: the toggle itself was undone"
    assert edited.read_text(encoding="utf-8") == "operator = 'saved meanwhile'\n"


async def test_a_file_unreadable_before_the_write_is_never_deleted_by_the_undo(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A declared file that could not be read before the write (a scanner or another program held
    it) is not taken for one the write created, so the undo never deletes it. It is left as the
    write left it, and the refusal says the change could not be fully undone."""
    from messagefoundry.pipeline.engine import ConfigWriteAuditTimeout

    toml_path = tmp_path / "connections.toml"
    real_read = Path.read_bytes
    held = [True]

    def _held_once(self: Path) -> bytes:
        if held[0] and self.name == "connections.toml":
            held[0] = False
            raise PermissionError(13, "synthetic: held open by another program")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", _held_once)
    _hang_the_row(engine, monkeypatch)
    with pytest.raises(ConfigWriteAuditTimeout, match="could not be fully undone") as refused:
        await engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    assert not held[0], "control: the first read of the file failed"
    assert refused.value.undone is False
    assert toml_path.exists()
    assert "flagged = true" in toml_path.read_text(encoding="utf-8")


async def test_a_write_cancelled_mid_row_is_undone(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #2945: a shutdown cancels a write its drain left waiting on a stuck row. The
    cancellation is not an ``Exception``, so it used to skip the undo and leave the toggle on disk
    with no row."""
    toml_path = tmp_path / "connections.toml"
    before = toml_path.read_bytes()
    entered = asyncio.Event()

    async def _hung(*_args: object, **_kwargs: object) -> None:
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(engine.store, "record_audit", _hung)
    caller = asyncio.ensure_future(
        engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    )
    await asyncio.wait_for(entered.wait(), 20)
    assert "flagged = true" in toml_path.read_text(encoding="utf-8"), "control: written"
    (task,) = engine._config_writes
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert task.cancelled()
    assert toml_path.read_bytes() == before
    assert not engine._toml_write_lock.locked()


async def test_a_write_cancelled_before_its_row_is_undone_once_its_thread_lands(
    engine: Engine, tmp_path: Path
) -> None:
    """A cancel that reaches the write task while its worker thread is still writing (blocked
    behind the edit lock, or validating) used to let the thread land the write after the task had
    gone, with no row and no undo. The task now waits for the thread and puts the file back."""
    import threading

    started, release = threading.Event(), threading.Event()
    target = tmp_path / "environments" / "dev.toml"

    def _write(cfg: Path) -> None:
        started.set()
        release.wait(20)
        (cfg / "environments").mkdir()
        (cfg / "environments" / "dev.toml").write_text("x = 1\n", encoding="utf-8")

    caller = asyncio.ensure_future(
        engine.write_baseline_config(
            "connection_flag_set",
            _write,
            touches=("environments/dev.toml",),
            detail={},
            actor="tester",
            client=None,
        )
    )
    try:
        assert await asyncio.to_thread(started.wait, 20)
        (task,) = engine._config_writes
        task.cancel()
        await asyncio.sleep(0.1)
        assert not task.done(), "the task waits for its thread"
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert task.cancelled()
    assert not target.exists(), "the thread's write was put back"
    assert await engine.store.list_audit(action="connection_flag_set") == []
    assert not engine._toml_write_lock.locked()


def test_the_undo_reports_a_lock_it_could_not_take_rather_than_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``OSError`` taking the cross-process lock (a sharing violation, say) is logged and
    reported as not undone, so the caller's refusal is not replaced by a raw error."""
    from messagefoundry.config import connections_edit
    from messagefoundry.pipeline import engine as engine_module

    def _refused(_cfg: object) -> Any:
        raise OSError(32, "synthetic: sharing violation")

    monkeypatch.setattr(connections_edit, "locked", _refused)
    target = tmp_path / "connections.toml"
    assert engine_module._undo_write(tmp_path, {target: (b"old", b"new")}) is False


async def test_a_hung_row_leaves_an_edit_that_landed_since(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo puts a file back only while it holds the bytes the write left, so an edit that
    landed while the row hung (a `connection` CLI edit, say) is never overwritten. The refusal says
    the change could not be fully undone."""
    from messagefoundry.pipeline import engine as engine_module
    from messagefoundry.pipeline.engine import ConfigWriteAuditTimeout

    toml_path = tmp_path / "connections.toml"
    other = b"# another editor's bytes\n"

    async def _hung(*_args: object, **_kwargs: object) -> None:
        toml_path.write_bytes(other)
        await asyncio.Event().wait()

    monkeypatch.setattr(engine_module, "CONFIG_WRITE_AUDIT_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(engine.store, "record_audit", _hung)
    with pytest.raises(ConfigWriteAuditTimeout, match="could not be fully undone") as refused:
        await engine.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
    assert refused.value.undone is False
    assert toml_path.read_bytes() == other
    assert not engine._toml_write_lock.locked()
