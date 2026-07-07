# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-level wiring for ADR 0073 ownership-scoped crash recovery (SQLite-backed).

Covers the Engine seams of the sharded-recovery build:

* ``Engine._owned_lanes()`` — ``None`` for an unsharded registry; the shard's inbound names +
  rendezvous-owned destination set for a sharded one.
* ``Engine.start()`` passes ``owned=<OwnedLanes>`` to ``store.reset_stale_inflight`` when sharded
  and ``owned=None`` (global recovery, byte-identical) when not.
* ``Engine.reload`` REFUSES a config whose engine-shard universe changed (outbound-lane ownership
  is pinned to the universe; a per-process reload can't re-map it fleet-wide) and accepts a
  same-universe reload.
* ``DrCoordinator`` activation passes the engine's ownership scope to the activation
  ``reset_stale_inflight`` when constructed with ``owned_lanes=...`` and ``owned=None`` without it.
* ``serve --shard`` + ``[cluster].enabled`` is refused (exit 2) before any store/app is built.

NOTE: ``require_unified_store`` (multi-shard => server-DB) is a SUPERVISOR-path guard enforced when
spawning a fleet — an in-process Engine over SQLite with a sharded registry is fine for these
wiring tests (no sibling shard process ever shares the file).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, DrSettings, StoreSettings
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr import DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.pipeline.sharding import (
    filter_registry_for_shard,
    owned_destination_set,
)
from messagefoundry.store import MessageStore, Store
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import OwnedLanes

# --- config-module scaffolding ------------------------------------------------

_CFG_HEADER = "from messagefoundry import inbound, outbound, router, handler, Send, File\n"

_CFG_LOGIC = textwrap.dedent(
    """
    @router('r')
    def route(msg):
        return ['h']

    @handler('h')
    def handle(msg):
        return Send('OB_ONE', msg)
    """
)


def _write_cfg(cfg: Path, tmp: Path, shards: list[str | None]) -> Path:
    """Write a minimal File-only config dir (no sockets) with one inbound per entry in ``shards``
    (``None`` = untagged) and two shared outbounds. Returns ``cfg``."""
    cfg.mkdir(parents=True, exist_ok=True)
    outdir = tmp / "out"
    outdir.mkdir(exist_ok=True)
    lines = [_CFG_HEADER]
    for shard in shards:
        label = (shard or "plain").upper()
        inbox = tmp / f"in_{label}"
        inbox.mkdir(exist_ok=True)
        shard_kw = f", shard={shard!r}" if shard is not None else ""
        lines.append(
            f"inbound('IB_{label}', File(directory={str(inbox)!r}, pattern='*.hl7', "
            f"poll_seconds=0.02), router='r'{shard_kw})\n"
        )
    lines.append(
        f"outbound('OB_ONE', File(directory={str(outdir)!r}, filename='one_{{MSH-10}}.hl7'))\n"
    )
    lines.append(
        f"outbound('OB_TWO', File(directory={str(outdir)!r}, filename='two_{{MSH-10}}.hl7'))\n"
    )
    lines.append(_CFG_LOGIC)
    (cfg / "cfg.py").write_text("".join(lines), encoding="utf-8")
    return cfg


def _only(shard: str):  # type: ignore[no-untyped-def]
    """The per-process shard filter exactly as `serve --shard` builds it."""

    def _filter(reg: Registry) -> Registry:
        return filter_registry_for_shard(reg, shard)

    return _filter


class _ResetSpy:
    """Wraps a store's bound ``reset_stale_inflight``, recording each call's ``owned`` kwarg."""

    def __init__(self, store: Store) -> None:
        self._orig = store.reset_stale_inflight
        self.owned_calls: list[OwnedLanes | None] = []

    async def __call__(
        self,
        now: float | None = None,
        *,
        stage: str | None = None,
        owned: OwnedLanes | None = None,
    ) -> int:
        self.owned_calls.append(owned)
        return await self._orig(now, stage=stage, owned=owned)


# --- 1. Engine._owned_lanes() --------------------------------------------------


async def test_owned_lanes_none_without_registry(tmp_path: Path) -> None:
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    try:
        assert eng._owned_lanes() is None  # no wired graph at all -> global recovery
    finally:
        await eng.stop()


async def test_owned_lanes_none_for_unsharded_registry(tmp_path: Path) -> None:
    # A single-shard/untagged config never attaches shard identity (byte-identical to plain serve),
    # so the recovery scope stays None (global) even when the filter is applied.
    cfg = _write_cfg(tmp_path / "cfg", tmp_path, [None])
    reg = load_config(cfg)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    try:
        eng.add_registry(reg)
        assert reg.shard_id is None and reg.all_shard_ids is None
        assert eng._owned_lanes() is None
    finally:
        await eng.stop()


async def test_owned_lanes_for_shard_of_two_shard_config(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path / "cfg", tmp_path, ["a", "b"])
    full = load_config(cfg)
    reg_a = filter_registry_for_shard(full, "a")
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02, registry_filter=_only("a"))
    try:
        eng.add_registry(reg_a)
        owned = eng._owned_lanes()
        assert owned is not None
        # Channel lanes = exactly this shard's inbounds; destination lanes = the rendezvous-owned
        # subset of the (shared) outbound map under the pinned {a, b} universe.
        assert owned.channels == frozenset({"IB_A"})
        assert owned.destinations == owned_destination_set(reg_a, "a", ("a", "b"))
        # The two shards' destination sets PARTITION the outbound map: disjoint, and together they
        # cover every lane (no outbound lane is unowned or double-owned).
        owned_b = owned_destination_set(full, "b", ("a", "b"))
        assert owned.destinations.isdisjoint(owned_b)
        assert owned.destinations | owned_b == set(full.outbound)
    finally:
        await eng.stop()


# --- 2. Engine.start() recovery scoping ----------------------------------------


async def test_start_passes_owned_lanes_to_reset_when_sharded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _write_cfg(tmp_path / "cfg", tmp_path, ["a", "b"])
    full = load_config(cfg)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02, registry_filter=_only("a"))
    eng.add_registry(filter_registry_for_shard(full, "a"))
    spy = _ResetSpy(eng.store)
    monkeypatch.setattr(eng.store, "reset_stale_inflight", spy)
    try:
        await eng.start()
        expected = eng._owned_lanes()
        assert expected is not None
        assert spy.owned_calls == [expected]  # exactly one startup reset, ownership-scoped
    finally:
        await eng.stop()


async def test_start_passes_owned_none_when_unsharded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Single-node unsharded startup recovery stays the unconditional global reset (owned=None) —
    # byte-identical to the pre-ADR-0073 path. (The CLUSTERED skip — no reset at all when the
    # coordinator reclaims in-flight rows — is covered by the existing cluster/leader-tasks tests;
    # not duplicated here.)
    cfg = _write_cfg(tmp_path / "cfg", tmp_path, [None])
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(cfg))
    spy = _ResetSpy(eng.store)
    monkeypatch.setattr(eng.store, "reset_stale_inflight", spy)
    try:
        await eng.start()
        assert spy.owned_calls == [None]
    finally:
        await eng.stop()


# --- 3. Reload shard-set refusal -------------------------------------------------


async def test_reload_refuses_shard_universe_change_and_accepts_same_set(tmp_path: Path) -> None:
    """A running shard 'a' of a {a,b} config: reloading a {a,b,c} config is REFUSED (WiringError
    naming the shard set — ownership is pinned to the universe, a per-process reload can't re-map
    it fleet-wide) and leaves the live graph untouched; reloading the SAME {a,b} set succeeds and
    keeps ownership/filtering intact."""
    two = _write_cfg(tmp_path / "cfg_two", tmp_path, ["a", "b"])
    three = _write_cfg(tmp_path / "cfg_three", tmp_path, ["a", "b", "c"])
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02, registry_filter=_only("a"))
    eng.add_registry(_only("a")(load_config(two)))
    await eng.start()
    try:
        owned_before = eng._owned_lanes()
        assert owned_before is not None

        # Same {a,b} universe: reload succeeds, still filtered to shard a, ownership unchanged.
        await eng.reload(two)
        rr = eng.registry_runner
        assert rr is not None and rr.running
        assert set(rr.registry.inbound) == {"IB_A"}
        assert rr.registry.shard_id == "a" and rr.registry.all_shard_ids == ("a", "b")
        assert eng._owned_lanes() == owned_before

        # Changed universe {a,b,c}: refused, and the refusal message names the shard sets.
        with pytest.raises(WiringError, match=r"engine-shard set.*a,b.*a,b,c"):
            await eng.reload(three)

        # The running graph is untouched by the refusal — still shard a of {a,b}, still running.
        rr = eng.registry_runner
        assert rr is not None and rr.running
        assert set(rr.registry.inbound) == {"IB_A"}
        assert rr.registry.all_shard_ids == ("a", "b")
        assert eng._owned_lanes() == owned_before
    finally:
        await eng.stop()


# --- 4. DR activation recovery scoping -------------------------------------------


async def _seeded_store(tmp_path: Path) -> tuple[MessageStore, str, StoreSettings]:
    """A real encrypted store + a verified #60 backup archive (the DR cold seed) — the same idiom
    as tests/test_dr_activation.py, so activate() runs its real fail-closed path to step 2."""
    key = generate_key()
    store = await MessageStore.open(tmp_path / "msg.db", cipher=make_cipher(key))
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    res = await runner.run_once(now=1.0)
    assert res is not None
    return store, res.archive_path, ss


async def _noop() -> None:
    return None


async def test_dr_activation_reset_is_ownership_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, archive, ss = await _seeded_store(tmp_path)
    owned = OwnedLanes(channels=frozenset({"IB_A"}), destinations=frozenset({"OB_ONE"}))
    try:
        coord = DrCoordinator(
            store,
            DrSettings(enabled=True, seed_archive=archive),
            store_settings=ss,
            activate_profile=_noop,
            deactivate_profile=_noop,
            owned_lanes=lambda: owned,  # the engine's scope callable (ADR 0073)
        )
        spy = _ResetSpy(store)
        monkeypatch.setattr(store, "reset_stale_inflight", spy)
        result = await coord.activate(actor="alice")
        assert result.active
        assert spy.owned_calls == [owned]  # step-2 recovery ran scoped to this shard's lanes
    finally:
        await store.close()


async def test_dr_activation_reset_is_global_without_owned_lanes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, archive, ss = await _seeded_store(tmp_path)
    try:
        coord = DrCoordinator(
            store,
            DrSettings(enabled=True, seed_archive=archive),
            store_settings=ss,
            activate_profile=_noop,
            deactivate_profile=_noop,
            # no owned_lanes -> the unsharded DR box: global recovery, byte-identical
        )
        spy = _ResetSpy(store)
        monkeypatch.setattr(store, "reset_stale_inflight", spy)
        result = await coord.activate(actor="alice")
        assert result.active
        assert spy.owned_calls == [None]
    finally:
        await store.close()


# --- 5. serve: --shard + [cluster].enabled refusal --------------------------------

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def test_serve_refuses_shard_with_cluster_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0073: engine sharding and [cluster] active-passive are mutually exclusive — the store-wide
    # leadership lease would transfer across shard ids and strand a dead shard's lanes. serve must
    # refuse the combination (exit 2) BEFORE building the store/app.
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(
        # [cluster].enabled requires a server-DB backend (+ its connection essentials) at settings
        # validation; the refusal under test fires before any store is opened, so nothing is dialed.
        '[store]\nbackend = "postgres"\nserver = "127.0.0.1"\ndatabase = "mf"\n'
        'username = "mf"\n\n[cluster]\nenabled = true\n',
        encoding="utf-8",
    )
    # Defensive: the refusal must return before either of these is reached.
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    rc = main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev", "--shard", "a"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--shard cannot be combined with [cluster].enabled" in err
