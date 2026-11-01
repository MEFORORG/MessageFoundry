# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The operator's object-of-interest flag lives in the store (BACKLOG #131, #2623).

``Engine.set_connection_flag`` writes one table and one audit row in one transaction. It runs no
config module, writes no file in the config directory and moves no config digest, so the service
account needs no write access to the directory it executes code from. The flag decides nothing, so
it is not on the :class:`Registry`, the loader never reads it, and no stored row can refuse a start
or a reload. ``tests/test_connection_flag_readers.py`` is what keeps it that way.

The two probes the row reproduces are here too: a toggle re-ran every config module, which it no
longer does, and a dry-run reload runs them, which it still does and ``docs/SECURITY.md`` records."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import textwrap
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
from tests._operator_audit_atomic_contract import AppendFailed, failing_append

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
    a dry run executes config code until it can run in a throwaway worker. It is not held for an
    approver, because the IDE promote pre-flight would stall on a second person. A change here means
    that record is wrong."""
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
    the gate and not the gate never running. A toggle builds no graph, so it lands either way: a
    display marker has no say in what an engine binds (BACKLOG #2623)."""
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


# --- What no longer holds the flag ---------------------------------------------------------------


@pytest.mark.parametrize("model", [InboundConnection, OutboundConnection])
def test_the_registry_does_not_carry_the_flag(model: type) -> None:
    """Off the model, so nothing that loads a graph reads it. ``auto_start`` and ``deployed`` act,
    and they stay: only the display marker moved."""
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
    cfg = _config_dir(tmp_path)
    (cfg / "extra.py").write_text(
        textwrap.dedent(
            """
            from messagefoundry import MLLP, outbound

            outbound("OB_MARKED", MLLP(host="127.0.0.1", port=2702), flagged=True)
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(WiringError):
        load_config(cfg)


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
