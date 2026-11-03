# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The operator's object-of-interest flag lives in the store (BACKLOG #131, #2623).

``Engine.set_connection_flag`` writes one table and one audit row in one transaction. It runs no
config module, writes no file in the config directory and moves no config digest, so the service
account needs no write access to the directory it executes code from. The flag drives no engine
path, so it is not on the :class:`Registry`, the loader never reads it, and no stored row can refuse
a start or a reload. ``tests/test_connection_flag_readers.py`` is what keeps it that way.

The two probes the row reproduces are here too: a toggle re-ran every config module, which it no
longer does, and a dry-run reload runs them, which it still does and ``docs/SECURITY.md`` records."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import textwrap
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    InboundConnection,
    OutboundConnection,
    WiringError,
    load_config,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.engine import ConnectionFlagNotRecorded
from messagefoundry.store.store import AuditAppend, MessageStore
from tests._operator_audit_atomic_contract import AppendFailed, failing_append

#: Where the engine reads the toggle's bound, at call time.
BOUND = "messagefoundry.pipeline.engine.CONNECTION_FLAG_WRITE_TIMEOUT_SECONDS"
#: Counts each run of a config module's top-level code: the probe the row's two findings came from.
RUNS_ENV = "MEFOR_TEST_FLAG_MODULE_RUNS"

# A code-first module supplying the router/handler the TOML inbound binds by name, PLUS a code-first
# outbound (OB_CODE). Loopback MLLP hosts so build_check's cleartext-hop guard never refuses
# (loopback is exempt), no File dirs to create.
LOGIC_PY = textwrap.dedent(
    f"""
    import os

    from messagefoundry import MLLP, Send, handler, outbound, router

    with open(os.environ[{RUNS_ENV!r}], "a", encoding="utf-8") as runs:
        runs.write("ran\\n")

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


def _config_dir(root: Path) -> Path:
    cfg = root / "config"
    cfg.mkdir()
    (cfg / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    (cfg / "connections.toml").write_text(CONNECTIONS_TOML, encoding="utf-8")
    return cfg


def _runs(root: Path) -> int:
    log_file = root / "runs.log"
    return len(log_file.read_text(encoding="utf-8").splitlines()) if log_file.exists() else 0


def _bytes_of(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


async def _engine(root: Path) -> Engine:
    cfg = root / "config"
    eng = await Engine.create(
        root / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    # Load + attach the graph WITHOUT starting listeners (no socket binds needed for this test).
    eng.add_registry(load_config(cfg))
    return eng


@pytest.fixture(autouse=True)
def _count_module_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RUNS_ENV, str(tmp_path / "runs.log"))


@pytest.fixture
async def engine(tmp_path: Path):
    _config_dir(tmp_path)
    eng = await _engine(tmp_path)
    yield eng
    await eng.stop()


async def _flag(eng: Engine, name: str, direction: str, flagged: bool = True) -> None:
    await eng.set_connection_flag(
        name, direction=direction, flagged=flagged, actor="tester", client=None
    )


# --- The two probes ------------------------------------------------------------------------------


async def test_a_toggle_runs_no_config_module(engine: Engine, tmp_path: Path) -> None:
    """The first probe (BACKLOG #2623): a toggle's validate step called ``load_config`` on the live
    directory, so one toggle was one more top-level run of every config module, in the engine's own
    process and with no approver. RED on that path: the count rose by one."""
    before = _runs(tmp_path)
    assert before == 1, "control: the fixture's load is one run, so the probe counts"
    await _flag(engine, "OB_TOML", "outbound")
    assert _runs(tmp_path) == before
    # Control, so an unchanged count is the toggle and not a counter that stopped counting.
    load_config(tmp_path / "config")
    assert _runs(tmp_path) == before + 1


async def test_a_dry_run_reload_runs_every_config_module_and_applies_nothing(
    engine: Engine, tmp_path: Path
) -> None:
    """The second probe (BACKLOG #2623), pinned rather than fixed: ``docs/SECURITY.md`` records that
    a dry run executes config code until it can run in a throwaway worker. A change here means that
    record is wrong. This calls the engine, so it says nothing about a hold. That half of the record
    is ``test_dry_run_reload_is_never_held`` in ``tests/test_dual_control_reload.py``, which goes
    through the route with ``config_reload`` gated."""
    assert engine.registry_runner is not None
    live = engine.registry_runner.registry
    before = _runs(tmp_path)
    outcome = await engine.reload_detail(str(tmp_path / "config"), dry_run=True)
    assert _runs(tmp_path) == before + 1
    assert outcome.applied is False
    assert engine.registry_runner.registry is live


async def test_a_toggle_changes_nothing_in_the_config_directory(
    engine: Engine, tmp_path: Path
) -> None:
    """RED on the old path, which rewrote ``connections.toml``."""
    cfg = tmp_path / "config"
    before = _bytes_of(cfg)
    await _flag(engine, "OB_TOML", "outbound")
    await _flag(engine, "OB_TOML", "outbound", False)
    assert _bytes_of(cfg) == before


async def test_a_toggle_lands_in_a_config_directory_the_account_cannot_write(
    engine: Engine, tmp_path: Path
) -> None:
    """The design conflict in BACKLOG #2623: a least-privilege install gives the service account read
    and execute on the config directory, and the old write made a temp file there. RED on that path
    wherever the permission bits bind: the refused write answered a ``WiringError``."""
    cfg = tmp_path / "config"
    toml = cfg / "connections.toml"
    original = toml.stat().st_mode, cfg.stat().st_mode
    toml.chmod(0o444)
    cfg.chmod(0o555)
    try:
        await _flag(engine, "OB_TOML", "outbound")
    finally:
        cfg.chmod(original[1])
        toml.chmod(original[0])
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}


async def test_a_toggle_moves_no_config_digest(engine: Engine) -> None:
    """A flag is not config, so the digest the running graph vouches for stays what it was."""
    await engine.capture_start_provenance()
    loaded = engine.loaded_config_fingerprint
    assert loaded is not None
    await _flag(engine, "OB_TOML", "outbound")
    assert engine.loaded_config_fingerprint is loaded


# --- The gates a toggle no longer meets, and the paths that still meet them ------------------------


async def _exposed_engine(root: Path, *, allow: bool) -> Engine:
    """An engine whose inbound listeners bind 0.0.0.0 in cleartext, on a non-enforcing instance, with
    or without the cleartext escape. IB_TOML is then exposed."""
    from messagefoundry.config.tls_policy import HopPosture

    return await Engine.create(
        root / "flag.db",
        poll_interval=0.02,
        config_dir=root / "config",
        inbound_bind_host="0.0.0.0",
        allow_insecure_bind=allow,
        hop_posture=HopPosture(enforcing=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )


@pytest.mark.parametrize("allow", [True, False])
async def test_a_dry_run_carries_the_engines_escape_and_a_toggle_meets_no_gate(
    tmp_path: Path, allow: bool
) -> None:
    """Vault BACKLOG #2622 item 1: a dry run includes the inbound exposure gates. An engine started
    with the escape accepted IB_TOML, so its dry-run reload (no live runner, so a throwaway checker)
    may not refuse it. Without the escape it refuses, which shows the pass is the escape reaching
    the gate and not the gate never running. A toggle builds no graph, so it lands either way: the
    flag has no say in what an engine binds (BACKLOG #2623)."""
    _config_dir(tmp_path)
    eng = await _exposed_engine(tmp_path, allow=allow)
    try:
        if allow:
            await eng.reload_detail(str(tmp_path / "config"), dry_run=True)
        else:
            with pytest.raises(WiringError, match="without TLS"):
                await eng.reload_detail(str(tmp_path / "config"), dry_run=True)
        eng.add_registry(load_config(tmp_path / "config"))
        await _flag(eng, "OB_TOML", "outbound")
        assert await eng.store.list_connection_flags() == {("OB_TOML", "outbound")}
    finally:
        await eng.stop()


@pytest.mark.parametrize("auto_start", [False, True])
async def test_a_listener_start_leaves_down_refuses_no_reload_or_dr_activation(
    tmp_path: Path, auto_start: bool
) -> None:
    """Vault BACKLOG #2622 item 1, review round 3. IB_TOML binds 0.0.0.0 in cleartext with no escape.
    With ``auto_start = false`` engine start never binds it, so a dry run, a reload and a DR
    activation (a re-apply of the running graph, vault BACKLOG #3067) must all apply, as they did
    before the build check ran the exposure gates. With ``auto_start = true`` the listener would be
    bound, so the build check still refuses all three, naming the listener and the two settings that
    leave it down. That is the control: the passes are the predicate, not a gate that never ran."""
    cfg = _config_dir(tmp_path)
    eng = await _exposed_engine(tmp_path, allow=False)
    toml_path = cfg / "connections.toml"
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
        await eng.add_registry(load_config(cfg)).start()
        steps = {
            "dry run": lambda: eng.reload_detail(str(cfg), dry_run=True),
            "reload": lambda: eng.reload(cfg),
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


# --- The write -----------------------------------------------------------------------------------


async def test_a_toggle_persists_in_the_store_and_clears(engine: Engine, tmp_path: Path) -> None:
    await _flag(engine, "OB_TOML", "outbound")
    await _flag(engine, "IB_TOML", "inbound")
    assert await engine.store.list_connection_flags() == {
        ("OB_TOML", "outbound"),
        ("IB_TOML", "inbound"),
    }
    await _flag(engine, "OB_TOML", "outbound", False)
    assert await engine.store.list_connection_flags() == {("IB_TOML", "inbound")}


async def test_the_flag_outlives_a_restart_on_the_same_store(tmp_path: Path) -> None:
    _config_dir(tmp_path)
    first = await _engine(tmp_path)
    await _flag(first, "OB_TOML", "outbound")
    await first.stop()
    second = await _engine(tmp_path)
    try:
        assert await second.store.list_connection_flags() == {("OB_TOML", "outbound")}
    finally:
        await second.stop()


async def test_a_code_first_connection_takes_the_flag(engine: Engine) -> None:
    """ADR 0007 deferred this branch because a code-first connection had no TOML home. The store
    is that home. RED on the old path, which refused ``OB_CODE`` with the scope fork."""
    await _flag(engine, "OB_CODE", "outbound")
    assert await engine.store.list_connection_flags() == {("OB_CODE", "outbound")}


async def test_one_name_flags_each_direction_apart(tmp_path: Path) -> None:
    """A name may be both an inbound and an outbound, which is why the key carries the direction."""
    cfg = _config_dir(tmp_path)
    (cfg / "both.py").write_text(
        textwrap.dedent(
            """
            from messagefoundry import MLLP, inbound, outbound

            inbound("BOTH", MLLP(port=2610), router="r")
            outbound("BOTH", MLLP(host="127.0.0.1", port=2711))
            """
        ),
        encoding="utf-8",
    )
    eng = await _engine(tmp_path)
    try:
        await _flag(eng, "BOTH", "inbound")
        assert await eng.store.list_connection_flags() == {("BOTH", "inbound")}
        await _flag(eng, "BOTH", "outbound")
        await _flag(eng, "BOTH", "inbound", False)
        assert await eng.store.list_connection_flags() == {("BOTH", "outbound")}
    finally:
        await eng.stop()


async def test_a_name_the_graph_does_not_have_is_refused_with_no_row(engine: Engine) -> None:
    """The store would take any text, so the name is checked here. Also the wrong direction: a real
    name on the side it was not declared. RED if the check goes: the flag and the row would land."""
    for name, direction in (("OB_NOPE", "outbound"), ("OB_TOML", "inbound")):
        with pytest.raises(WiringError, match="the running graph has no"):
            await _flag(engine, name, direction)
    assert await engine.store.list_connection_flags() == set()
    assert await engine.store.list_audit(action="connection_flag_set") == []


async def test_a_toggle_with_no_graph_is_refused(tmp_path: Path) -> None:
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        with pytest.raises(WiringError, match="the running graph has no"):
            await _flag(eng, "OB_TOML", "outbound")
    finally:
        await eng.stop()


async def test_a_toggle_rejects_a_bad_direction(engine: Engine) -> None:
    with pytest.raises(WiringError, match="direction"):
        await _flag(engine, "OB_TOML", "sideways")


async def test_concurrent_toggles_both_land(engine: Engine) -> None:
    await asyncio.gather(_flag(engine, "OB_TOML", "outbound"), _flag(engine, "IB_TOML", "inbound"))
    assert await engine.store.list_connection_flags() == {
        ("OB_TOML", "outbound"),
        ("IB_TOML", "inbound"),
    }
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 2


async def test_an_engine_shard_flags_an_inbound_a_sibling_owns(engine: Engine) -> None:
    """An engine shard's graph holds only its own inbounds, and the store is the one every engine
    shard shares. RED if the guard reads ``registry.inbound``, which this view does not fill."""
    runner = engine.registry_runner
    assert runner is not None
    runner.registry.all_inbound = frozenset({"IB_TOML", "IB_SIBLING"})
    await _flag(engine, "IB_SIBLING", "inbound")
    assert await engine.store.list_connection_flags() == {("IB_SIBLING", "inbound")}


async def test_a_cluster_node_toggles_for_every_node(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The store is the one thing every node shares, so a cluster node no longer refuses. RED on the
    old path, which raised ``ClusteredConfigWrite``."""
    monkeypatch.setattr(engine.coordinator, "is_clustered", lambda: True)
    await _flag(engine, "OB_TOML", "outbound")
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}


# --- The audit row -------------------------------------------------------------------------------


async def test_a_toggle_writes_its_row_with_no_digest(engine: Engine) -> None:
    """A toggle still leaves ``connection_flag_set`` with its actor and client. The row carries no
    digest keys: the flag left the config digest, so a digest here would vouch for nothing. RED on
    the old path, whose row carried the fingerprint."""
    await engine.capture_start_provenance()
    await engine.set_connection_flag(
        "OB_TOML", direction="outbound", flagged=True, actor="tester", client="10.0.0.5"
    )
    [row] = await engine.store.list_audit(action="connection_flag_set")
    assert (row["actor"], row["client"], row["channel_id"]) == ("tester", "10.0.0.5", None)
    assert json.loads(str(row["detail"])) == {
        "connection": "OB_TOML",
        "direction": "outbound",
        "flagged": True,
        "node": engine.coordinator.node_id,
    }


async def test_a_toggle_to_the_value_it_already_has_still_writes_its_row(engine: Engine) -> None:
    await _flag(engine, "OB_TOML", "outbound")
    await _flag(engine, "OB_TOML", "outbound")
    await _flag(engine, "OB_CODE", "outbound", False)
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 3
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}


async def test_a_failed_row_changes_no_flag_and_names_the_store(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The flag and its row are one transaction. The refusal is the type the route answers 503 for,
    and the fault's own text goes to the log, not the operator."""
    await _flag(engine, "IB_TOML", "inbound")
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.engine"),
        failing_append(engine.store, "connection_flag_set"),
        pytest.raises(ConnectionFlagNotRecorded, match="did not confirm this toggle") as refused,
    ):
        await _flag(engine, "OB_TOML", "outbound")
    assert await engine.store.list_connection_flags() == {("IB_TOML", "inbound")}
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 1
    assert isinstance(refused.value.__cause__, AppendFailed)
    assert "the store did not confirm a connection flag change" in caplog.text


async def test_a_store_that_never_answers_gets_the_refusal_within_the_bound(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A hung store is refused at the bound, as the type the route answers 503 for, so the console
    can show its page. RED without the bound: the toggle waits on the store, and here on the test's
    own guard, as a real caller would wait on the 120 s request deadline."""

    async def _hung(*_args: object, **_kwargs: object) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(BOUND, 0.05)
    monkeypatch.setattr(engine.store, "set_connection_flag", _hung)
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.engine"),
        pytest.raises(ConnectionFlagNotRecorded, match="may or may not have changed"),
    ):
        async with asyncio.timeout(5):
            await _flag(engine, "OB_TOML", "outbound")
    assert "within 0.05 s (outbound OB_TOML)" in caplog.text
    assert not engine._config_writes


@pytest.mark.parametrize("landed", [False, True], ids=["before-commit", "after-commit"])
async def test_a_refusal_at_the_bound_cannot_say_whether_the_write_landed(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, landed: bool
) -> None:
    """Why the refusal and its page say neither. The store goes silent either side of its commit,
    the operator gets the same refusal, and only the second has the flag and its row. The writer is
    free again in both, so the toggle the page sends the operator to can land."""
    store = engine.store
    assert isinstance(store, MessageStore)
    commit = store._commit

    async def _silent() -> None:
        if landed:
            await commit()
        await asyncio.Event().wait()

    with monkeypatch.context() as hung:
        # Long enough for the real commit of the second case, and over before the closing toggle.
        hung.setattr(BOUND, 0.5)
        hung.setattr(store, "_commit", _silent)
        with pytest.raises(ConnectionFlagNotRecorded, match="may or may not have changed"):
            async with asyncio.timeout(5):
                await _flag(engine, "OB_TOML", "outbound")
    assert await store.list_connection_flags() == ({("OB_TOML", "outbound")} if landed else set())
    assert len(await store.list_audit(action="connection_flag_set")) == int(landed)
    await _flag(engine, "OB_CODE", "outbound")
    assert ("OB_CODE", "outbound") in await store.list_connection_flags()


# --- The write outlives its caller ---------------------------------------------------------------


class _SlowWrite:
    """Holds the store's flag write open until :attr:`release`, then runs it. ``ended`` records how
    it finished, so a test can tell a write that landed from one its caller cut short."""

    def __init__(self, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.entered, self.release = asyncio.Event(), asyncio.Event()
        self.ended: list[str] = []
        real: Callable[..., Awaitable[None]] = engine.store.set_connection_flag

        async def _slow(*args: object, **kwargs: object) -> None:
            self.entered.set()
            try:
                await self.release.wait()
                await real(*args, **kwargs)
            except asyncio.CancelledError:
                self.ended.append("cancelled")
                raise
            self.ended.append("landed")

        monkeypatch.setattr(engine.store, "set_connection_flag", _slow)


async def test_a_request_deadline_stops_the_wait_and_not_the_write(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deadline cancels the route (``api/request_timeout.py``, an ``asyncio.timeout`` around
    the handler, which this reproduces). The write is the engine's task, so it runs on and lands
    with its row. RED while the write runs inside the request, which cancels it."""
    slow = _SlowWrite(engine, monkeypatch)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.1):
            await _flag(engine, "OB_TOML", "outbound")
    assert slow.entered.is_set(), "control: the deadline fell during the write"
    assert slow.ended == [], "the deadline reached the write"
    slow.release.set()
    await asyncio.wait_for(asyncio.gather(*engine._config_writes), 5)
    assert slow.ended == ["landed"]
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 1
    assert not engine._config_writes


async def test_stop_waits_for_a_write_whose_caller_went(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write whose caller was cancelled still has its store write to finish, so stop waits for it
    before the store closes, and the flag and its row are there at the next start. RED while the
    write runs inside the request: the cancel ends it, and stop has nothing to wait for."""
    _config_dir(tmp_path)
    eng = await _engine(tmp_path)
    slow = _SlowWrite(eng, monkeypatch)
    real_close = eng.store.close

    async def _close() -> None:
        slow.ended.append("store closed")
        await real_close()

    monkeypatch.setattr(eng.store, "close", _close)
    caller = asyncio.ensure_future(_flag(eng, "OB_TOML", "outbound"))
    await asyncio.wait_for(slow.entered.wait(), 5)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    asyncio.get_running_loop().call_later(0.1, slow.release.set)
    await eng.stop()
    assert slow.ended == ["landed", "store closed"]
    again = await _engine(tmp_path)
    try:
        assert await again.store.list_connection_flags() == {("OB_TOML", "outbound")}
        assert len(await again.store.list_audit(action="connection_flag_set")) == 1
    finally:
        await again.stop()


async def test_a_toggle_once_the_drain_has_begun_is_refused(engine: Engine) -> None:
    """The gate closes before the drain waits, so a toggle that arrives after it is refused rather
    than started as a write the drain never saw, landing as the store closes. RED with no gate."""
    await engine.drain_config_writes(0.1)
    with pytest.raises(WiringError, match="stopping"):
        await _flag(engine, "OB_TOML", "outbound")
    assert await engine.store.list_connection_flags() == set()
    assert await engine.store.list_audit(action="connection_flag_set") == []


async def test_the_bound_holds_for_a_write_whose_caller_went(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The bound sits inside the write, so a hung store ends a write nobody is waiting on, and the
    drain has nothing left to wait for. Its failure is logged through ``safe_exc``, and the line
    says its caller had gone; asyncio does not also report an exception nobody retrieved."""
    # Never released, so the store does not answer.
    slow = _SlowWrite(engine, monkeypatch)
    monkeypatch.setattr(BOUND, 0.2)
    caller = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound"))
    # One pass of the loop, so the caller is waiting on its task. Cancelled here rather than once
    # the store is entered, so no timing of the bound can reach the caller first.
    await asyncio.sleep(0)
    (task,) = engine._config_writes
    with caplog.at_level(logging.WARNING):
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        await asyncio.wait_for(asyncio.wait({task}), 5)
    assert slow.entered.is_set(), "control: the write reached the store after its caller went"
    messages = [record.getMessage() for record in caplog.records]
    abandoned = [m for m in messages if m.startswith("config write failed after its caller")]
    assert len(abandoned) == 1, messages
    assert "did not confirm this toggle" in abandoned[0]
    assert "within 0.2 s (outbound OB_TOML)" in caplog.text
    assert not [m for m in messages if "shielded future" in m]
    assert not engine._config_writes
    assert await engine.store.list_connection_flags() == set()
    assert await engine.store.list_audit(action="connection_flag_set") == []


async def test_a_drain_that_runs_out_leaves_the_write_running(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Waiting never cancels a write. One still running when the drain's wait ends is logged and
    left, so a slow shutdown does not cut off a commit, and it lands if the store is still open."""
    slow = _SlowWrite(engine, monkeypatch)
    caller = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound"))
    await asyncio.wait_for(slow.entered.wait(), 5)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
        await engine.drain_config_writes(0.05)
    assert "1 connection flag write(s) still running or queued at shutdown" in caplog.text
    assert slow.ended == [], "the drain reached the write"
    assert not caller.done(), "the caller still waits on the write"
    slow.release.set()
    await asyncio.wait_for(caller, 5)
    assert slow.ended == ["landed"]
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}


async def test_a_write_cancelled_before_its_first_step_leaves_no_task_behind(
    engine: Engine,
) -> None:
    """A task cancelled before it ever ran is still forgotten, or the drain would wait on it."""
    caller = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound"))
    # One pass of the loop: the caller schedules its task, which has not run yet.
    await asyncio.sleep(0)
    (task,) = engine._config_writes
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert task.cancelled()
    assert not engine._config_writes
    # And the engine still takes a write.
    await _flag(engine, "OB_TOML", "outbound")
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}


# --- Toggles run one at a time -------------------------------------------------------------------


class _SlowFirstWrite:
    """Holds the first flag write open until :attr:`release`, around the real store, and lets every
    later write through, so a later toggle nothing holds back overtakes it.

    A clear that overtakes takes the one branch here that is not the real store. It models a READ
    COMMITTED server store that took the audit lock only at the append: a clear during an
    uncommitted set saw no row, deleted nothing, and still appended its audit row, after the set's.
    The server stores now take that lock before the flag statement, which the cross-handle contract
    in ``tests/_operator_audit_atomic_contract.py`` pins, so the engine lock here keeps arrival
    order, and the branch is what a store without that lock would do."""

    def __init__(self, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.entered, self.release, self.first_done = (asyncio.Event() for _ in range(3))
        self.calls = 0
        store = engine.store
        real: Callable[..., Awaitable[None]] = store.set_connection_flag

        async def _write(
            connection: str, direction: str, *, flagged: bool, audit: AuditAppend
        ) -> None:
            self.calls += 1
            if self.calls == 1:
                self.entered.set()
                await self.release.wait()
                await real(connection, direction, flagged=flagged, audit=audit)
                self.first_done.set()
            elif not flagged and not self.first_done.is_set():
                await self.first_done.wait()
                await store.record_audit(audit.action, actor=audit.actor, detail=audit.detail)
            else:
                await real(connection, direction, flagged=flagged, audit=audit)

        monkeypatch.setattr(store, "set_connection_flag", _write)


@pytest.mark.parametrize("caller_goes", [False, True], ids=["caller-waits", "caller-went"])
@pytest.mark.parametrize("later", [False, True], ids=["set-then-clear", "clear-then-set"])
async def test_two_overlapping_toggles_leave_the_flag_matching_the_last_audit_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, later: bool, caller_goes: bool
) -> None:
    """The later toggle waits for the earlier, even one whose caller has gone, so the flag and the
    newest row both say what the last toggle said, and the model's branch never runs.

    RED with no lock, or one that a gone caller gives up, on either ordering. A clear that overtakes
    a set leaves the flag stored under a newest row that says it is not, which is the disagreement,
    through the modelled branch. A set that overtakes a clear agrees with its row, on the real store
    alone, but both end on the EARLIER toggle. SQLite cannot show the disagreement unmodelled."""
    slow = _SlowFirstWrite(engine, monkeypatch)
    first = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound", not later))
    await asyncio.wait_for(slow.entered.wait(), 5)
    if caller_goes:
        first.cancel()
        await asyncio.wait({first})
    second = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound", later))
    # Time for the later toggle to reach the store, if nothing holds it back.
    await asyncio.sleep(0.05)
    writes = list(engine._config_writes)
    slow.release.set()
    await asyncio.wait_for(asyncio.gather(*writes), 5)
    await asyncio.wait({first, second}, timeout=5)
    rows = await engine.store.list_audit(action="connection_flag_set")
    assert len(rows) == 2
    newest = json.loads(str(rows[0]["detail"]))["flagged"]
    assert (("OB_TOML", "outbound") in await engine.store.list_connection_flags()) is newest
    assert newest is later


async def test_a_queue_behind_a_stuck_toggle_gets_the_refusal_at_its_own_bound(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The bound covers the wait for the lock too, so a toggle behind a stuck one hears
    the typed refusal rather than the 120 s request deadline, even while the stuck one has not
    unwound. It never reached the store, and the log says so. RED with the bound around the store
    call alone: the later toggle waits for the lock and here meets the test's own guard."""
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def _stuck(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        entered.set()
        # A store that takes longer to give way than the bound runs for.
        while not release.is_set():
            with contextlib.suppress(asyncio.CancelledError):
                await release.wait()

    monkeypatch.setattr(BOUND, 0.05)
    monkeypatch.setattr(engine.store, "set_connection_flag", _stuck)
    first = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound"))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        with (
            caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.engine"),
            pytest.raises(ConnectionFlagNotRecorded, match="may or may not have changed"),
        ):
            await asyncio.wait_for(_flag(engine, "OB_CODE", "outbound"), 1)
        assert not first.done(), "control: the stuck toggle still holds the lock"
    finally:
        # Before the rest, so a failure here does not leave the engine's stop waiting on it.
        release.set()
    await asyncio.wait_for(first, 5)
    assert "was not started (outbound OB_CODE)" in caplog.text
    assert "may still land" not in caplog.text
    assert calls == 1


async def test_time_in_the_queue_does_not_eat_the_bound_of_the_store_call(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two toggles that each fit the bound both land, one behind the other. RED with one clock over
    the queue and the store call: the second is cut off in the store, with a refusal that cannot
    say whether it landed, on a store that is only slow."""
    real: Callable[..., Awaitable[None]] = engine.store.set_connection_flag

    async def _slow(*args: object, **kwargs: object) -> None:
        await asyncio.sleep(2.0)
        await real(*args, **kwargs)

    monkeypatch.setattr(BOUND, 3.0)
    monkeypatch.setattr(engine.store, "set_connection_flag", _slow)
    await asyncio.gather(
        _flag(engine, "OB_TOML", "outbound"),
        _flag(engine, "OB_CODE", "outbound"),
    )
    assert await engine.store.list_connection_flags() == {
        ("OB_TOML", "outbound"),
        ("OB_CODE", "outbound"),
    }


async def test_a_toggle_queued_when_the_drain_begins_is_refused_at_the_lock(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate is read again under the lock, so a toggle that was already queued does not start a
    write once a shutdown has begun, and the store may be closing behind it. RED with the gate at
    the door alone: the queued toggle lands."""
    slow = _SlowWrite(engine, monkeypatch)
    first = asyncio.ensure_future(_flag(engine, "OB_TOML", "outbound"))
    await asyncio.wait_for(slow.entered.wait(), 5)
    second = asyncio.ensure_future(_flag(engine, "OB_CODE", "outbound"))
    await asyncio.sleep(0)
    drain = asyncio.ensure_future(engine.drain_config_writes(5))
    await asyncio.sleep(0)
    slow.release.set()
    await asyncio.wait_for(first, 5)
    with pytest.raises(WiringError, match="stopping"):
        await asyncio.wait_for(second, 5)
    await asyncio.wait_for(drain, 5)
    assert await engine.store.list_connection_flags() == {("OB_TOML", "outbound")}


# --- What no longer holds the flag ---------------------------------------------------------------


@pytest.mark.parametrize("model", [InboundConnection, OutboundConnection])
def test_the_registry_does_not_carry_the_flag(model: type) -> None:
    """Off the model, so nothing that loads a graph reads it. ``auto_start`` and ``deployed`` act,
    and they stay: only the flag moved."""
    fields = {f.name for f in dataclasses.fields(model)}
    assert "flagged" not in fields
    assert {"auto_start", "deployed"} <= fields


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_a_flagged_key_in_connections_toml_is_refused(tmp_path: Path, direction: str) -> None:
    """One source of truth. The loader refuses the key rather than ignoring it, so a hand edit that
    reads as flagging a connection cannot sit there flagging nothing."""
    cfg = _config_dir(tmp_path)
    toml = cfg / "connections.toml"
    header = f"[[{direction}]]\n"
    toml.write_text(
        toml.read_text(encoding="utf-8").replace(header, f"{header}flagged = true\n"),
        encoding="utf-8",
    )
    assert "flagged = true" in toml.read_text(encoding="utf-8"), "control: the edit landed"
    with pytest.raises(WiringError, match=r"unknown key\(s\) flagged"):
        load_config(cfg)


def test_a_flagged_argument_on_a_declaration_is_refused(tmp_path: Path) -> None:
    """The loader withholds the TypeError's own text, so the match names the module and the line.
    The control drops the argument and loads, so the refusal is that argument and nothing else."""
    cfg = _config_dir(tmp_path)
    extra = cfg / "extra.py"
    source = textwrap.dedent(
        """
        from messagefoundry import MLLP, outbound

        outbound("OB_MARKED", MLLP(host="127.0.0.1", port=2702), flagged=True)
        """
    )
    extra.write_text(source, encoding="utf-8")
    with pytest.raises(WiringError, match=r"extra\.py: TypeError at line 4"):
        load_config(cfg)
    extra.write_text(source.replace(", flagged=True", ""), encoding="utf-8")
    assert "OB_MARKED" in load_config(cfg).outbound


# --- A database writer with no key ---------------------------------------------------------------


async def _plant_rows(eng: Engine) -> None:
    """Rows no toggle can write: a name no graph has, a direction nobody spelled, and a name that
    is not text at all. What a database writer with no key could leave."""
    await eng.store._db.execute(  # type: ignore[attr-defined]
        "INSERT INTO connection_flag (connection, direction) VALUES"
        " ('OB_GONE', 'outbound'), ('OB_TOML', 'sideways'), (CAST(X'FF' AS TEXT), 'inbound')"
    )
    await eng.store._db.commit()  # type: ignore[attr-defined]


async def test_a_stored_row_refuses_neither_a_start_nor_a_reload(tmp_path: Path) -> None:
    """The loader's ``_require_bool`` refuses a malformed ``flagged`` in TOML, and carrying that to
    the store would let a writer with no key refuse a start. Neither path reads the table. This runs
    a real start of the runner and then a reload on it. A row IS the flag, so there is no value to
    parse. ``auto_start = false`` keeps the start from binding a port, and the start still runs."""
    cfg = _config_dir(tmp_path)
    toml = cfg / "connections.toml"
    toml.write_text(
        toml.read_text(encoding="utf-8").replace(
            'router = "r"\n', 'router = "r"\nauto_start = false\n'
        ),
        encoding="utf-8",
    )
    first = await _engine(tmp_path)
    await _plant_rows(first)
    await first.stop()
    second = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=tmp_path / "config",
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await second.add_registry(load_config(cfg)).start()
        outcome = await second.reload_detail(str(cfg))
        assert outcome.applied is True
    finally:
        await second.stop()


@pytest.mark.parametrize("flagged", [True, False], ids=["set", "clear"])
async def test_the_postgres_toggle_takes_the_audit_lock_before_its_flag_statement(
    flagged: bool,
) -> None:
    """Offline, against a recording connection: the order the live cross-handle contract in
    ``tests/test_postgres_store.py`` depends on. The lock taken only at the append let a clear run
    beside another shard's uncommitted set at READ COMMITTED, delete nothing, and append the newer
    row. Pinned to READ COMMITTED, since a REPEATABLE READ snapshot would predate the lock wait."""
    from contextlib import asynccontextmanager
    from typing import Any

    from messagefoundry.store.postgres import PostgresStore

    log: list[str] = []

    class _Conn:
        @asynccontextmanager
        async def transaction(self, **kwargs: Any) -> Any:
            log.append(f"BEGIN {kwargs.get('isolation')}")
            yield None

        async def execute(self, sql: str, *_params: Any) -> str:
            log.append(sql.split()[0])
            return "OK"

    store = object.__new__(PostgresStore)

    @asynccontextmanager
    async def _timed_acquire(*, record: bool = True) -> Any:
        yield _Conn()

    async def _advisory_lock(_conn: Any, _classid: int, key: str) -> None:
        log.append(f"LOCK {key}")

    async def _append_operator_audit(*_args: Any) -> None:
        log.append("APPEND")

    vars(store).update(
        _timed_acquire=_timed_acquire,
        _advisory_lock=_advisory_lock,
        _append_operator_audit=_append_operator_audit,
    )
    await store.set_connection_flag(
        "OB_A", "outbound", flagged=flagged, audit=AuditAppend("connection_flag_set")
    )
    statement = "INSERT" if flagged else "DELETE"
    assert log == ["BEGIN read_committed", "LOCK mefor_audit_chain", statement, "APPEND"]
