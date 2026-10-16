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
import textwrap
from pathlib import Path

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
                "connection_flag_set", wrote.append, detail=detail, actor="tester", client=None
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
            "connection_flag_set", _write, detail={"probe": True}, actor="tester", client=None
        )
    )
    assert await asyncio.to_thread(started.wait, 20)
    caller.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await caller
    for _ in range(200):
        if await engine.store.list_audit(action="connection_flag_set"):
            break
        await asyncio.sleep(0.05)
    assert len(await engine.store.list_audit(action="connection_flag_set")) == 1


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
