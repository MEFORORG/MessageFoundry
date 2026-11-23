# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5615: on a single node the expiry refusals run before the graph, and the rotation stamps
they read are saved only once the start has got past the point where they were always saved.

The order matters because a stamp is a claim that a secret was rotated. A start that fails with a
candidate value must not record it: putting the old value back would then read as a second rotation
and reset the clock of a secret that was never rotated.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import EgressSettings, SecretRotationSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline import secret_rotation as sr
from messagefoundry.pipeline.cluster import ClusterCoordinator
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.secret_rotation import (
    SecretRotationOverdueError,
    SecretStamp,
    StoreKeyRotationOverdueError,
    reconcile_rotation_meta,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.crypto import generate_key, make_cipher, seal_rotation_fingerprint
from messagefoundry.store.store import MessageStore
from tests.test_cluster_graph_gating import _FlipCoordinator, _minimal_graph

_AD = "MEFOR_AUTH_AD_BIND_PASSWORD"
_OLD = "test-only-old-value"  # nosec B105 - a test value, never a real credential
_CANDIDATE = "test-only-candidate-value"  # nosec B105 - a test value, never a real credential
_LONG_AGO = "2020-01-01"


class _Site:
    """One store file, reopened for each start under the same key, as a restarted engine does."""

    def __init__(self, tmp_path: Path) -> None:
        self.db = tmp_path / "site.db"
        self.key = generate_key()
        self.cfg = tmp_path / "cfg"
        _minimal_graph(self.cfg, tmp_path)

    async def open(self) -> MessageStore:
        return await MessageStore.open(self.db, cipher=make_cipher(self.key))

    async def seed_old_stamp(self) -> None:
        store = await self.open()
        cipher = store.secret_rotation_cipher()
        assert cipher is not None, "premise: a keyed store fingerprints secrets"
        await store.upsert_secret_rotation_meta(
            _AD,
            fingerprint=seal_rotation_fingerprint(cipher, _AD, sr._fingerprint_cell(_AD, _OLD)),
            tracked_since=_LONG_AGO,
            last_rotated=_LONG_AGO,
        )
        await store.close()

    async def rows(self) -> dict[str, Any]:
        store = await self.open()
        try:
            return dict(await store.get_secret_rotation_meta())
        finally:
            await store.close()

    async def engine(
        self,
        settings: SecretRotationSettings,
        *,
        coordinator: ClusterCoordinator | None = None,
    ) -> Engine:
        return Engine(
            await self.open(),
            secret_rotation_settings=settings,
            security_enforcement=SecurityEnforcement.ENFORCE,
            egress_settings=EgressSettings(deny_by_default=False),
            coordinator=coordinator,
        )

    async def start(
        self,
        settings: SecretRotationSettings,
        *,
        coordinator: ClusterCoordinator | None = None,
    ) -> Engine:
        """Start an engine on the graph. A start that raises is torn down before it propagates."""
        engine = await self.engine(settings, coordinator=coordinator)
        engine.add_registry(load_config(self.cfg))
        try:
            await engine.start()
        except BaseException:
            await engine.stop()
            raise
        return engine


class _StartFailed(RuntimeError):
    """The injected failure of a start, distinct from every refusal under test."""


def _fail_the_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(self: RegistryRunner, **_k: Any) -> None:
        raise _StartFailed("graph start failed")

    monkeypatch.setattr(RegistryRunner, "start", refuse)


def _fail_after_the_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    """A later maintenance runner fails, after the graph is up and before the point in ``start``
    where the stamps have always been saved."""

    def refuse(*_a: Any, **_k: Any) -> None:
        raise _StartFailed("a runner after the graph failed")

    monkeypatch.setattr("messagefoundry.pipeline.engine.GcmInvocationRunner", refuse)


@pytest.mark.parametrize(
    "fail", [_fail_the_graph, _fail_after_the_graph], ids=["graph", "after-graph"]
)
async def test_a_failed_start_on_a_candidate_does_not_unlock_the_old_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail: Any
) -> None:
    """The defect the earlier attempt had: the candidate is stamped, the old value reads as a new
    rotation, and a secret that was never rotated starts."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    settings = SecretRotationSettings(enforce_secret_expiry_classes=[_AD])

    monkeypatch.setenv(_AD, _CANDIDATE)
    with monkeypatch.context() as failing:
        fail(failing)
        with pytest.raises(_StartFailed):
            await site.start(settings)
    assert (await site.rows())[_AD].last_rotated == _LONG_AGO

    monkeypatch.setenv(_AD, _OLD)
    with pytest.raises(SecretRotationOverdueError):
        await site.start(settings)


@pytest.mark.parametrize(
    ("settings", "refusal"),
    [
        (SecretRotationSettings(store_key_last_rotated=_LONG_AGO), StoreKeyRotationOverdueError),
        (SecretRotationSettings(enforce_secret_expiry_classes=[_AD]), SecretRotationOverdueError),
        (SecretRotationSettings(), None),
    ],
    ids=["store-key", "secret", "control-not-refused"],
)
async def test_an_overdue_start_binds_no_listener_on_a_single_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings: SecretRotationSettings,
    refusal: type[Exception] | None,
) -> None:
    """The control shows the recorder does see a start of this same graph."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    monkeypatch.setenv(_AD, _OLD)
    starts: list[RegistryRunner] = []
    real_start = RegistryRunner.start

    async def recording_start(self: RegistryRunner, **kwargs: Any) -> None:
        starts.append(self)
        await real_start(self, **kwargs)

    monkeypatch.setattr(RegistryRunner, "start", recording_start)
    if refusal is None:
        engine = await site.start(settings)
        await engine.stop()
        assert len(starts) == 1
    else:
        with pytest.raises(refusal):
            await site.start(settings)
        assert starts == []


async def test_a_failed_reconcile_still_refuses_before_any_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A compute failure leaves the stamps empty, which reads as an undetermined age."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    monkeypatch.setenv(_AD, _OLD)
    starts: list[RegistryRunner] = []

    async def boom(*_a: Any, **_k: Any) -> dict[str, SecretStamp]:
        raise RuntimeError("meta store is unreachable")

    async def recording_start(self: RegistryRunner, **_k: Any) -> None:
        starts.append(self)

    monkeypatch.setattr("messagefoundry.pipeline.engine.reconcile_rotation_meta", boom)
    monkeypatch.setattr(RegistryRunner, "start", recording_start)
    with pytest.raises(StoreKeyRotationOverdueError):
        await site.start(SecretRotationSettings())
    assert starts == []


async def test_a_refused_start_persists_no_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A changed secret beside an overdue store key: the refusal must not record the change."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    before = await site.rows()
    monkeypatch.setenv(_AD, _CANDIDATE)
    with pytest.raises(StoreKeyRotationOverdueError):
        await site.start(SecretRotationSettings(store_key_last_rotated=_LONG_AGO))
    assert await site.rows() == before


async def test_the_clustered_path_reconciles_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A standby never runs the graph, so nothing could ever save a deferred stamp there."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    monkeypatch.setenv(_AD, _CANDIDATE)
    deferred: list[object] = []

    async def spying(*args: Any, **kwargs: Any) -> dict[str, SecretStamp]:
        deferred.append(kwargs.get("defer_writes"))
        return await reconcile_rotation_meta(*args, **kwargs)

    monkeypatch.setattr("messagefoundry.pipeline.engine.reconcile_rotation_meta", spying)
    engine = await site.start(SecretRotationSettings(), coordinator=_FlipCoordinator(leader=False))
    try:
        assert engine._registry_runner is not None and not engine._registry_runner.running
    finally:
        await engine.stop()
    assert deferred == [None]
    assert (await site.rows())[_AD].last_rotated != _LONG_AGO


async def test_an_engine_with_no_graph_reconciles_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    monkeypatch.setenv(_AD, _CANDIDATE)
    engine = await site.engine(SecretRotationSettings())
    await engine.start()
    await engine.stop()
    assert (await site.rows())[_AD].last_rotated != _LONG_AGO


async def test_deferred_writes_save_the_value_sealed_in_compute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    before = await site.rows()
    monkeypatch.setenv(_AD, _CANDIDATE)
    store = await site.open()
    try:
        pending: list[sr.PendingRotationStamp] = []
        stamps = await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=store.cipher_info().active_key_id,
            enforcement=SecurityEnforcement.ENFORCE,
            defer_writes=pending,
        )
        assert dict(await store.get_secret_rotation_meta()) == before, "compute wrote a stamp"
        assert stamps[_AD].last_rotated.isoformat() != _LONG_AGO
        await sr.persist_rotation_meta(store, pending)
        saved = await store.get_secret_rotation_meta()
        assert saved[_AD].fingerprint == stamps[_AD].fingerprint
        assert saved[_AD].last_rotated == stamps[_AD].last_rotated.isoformat()
        assert saved[_AD].tracked_since == _LONG_AGO
    finally:
        await store.close()


async def test_a_crash_before_the_save_is_detected_again_on_the_next_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A failed save does not refuse a start that is already up, and loses no rotation: the stored
    stamp still differs from the value held, so the next start sees the same change."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    monkeypatch.setenv(_AD, _CANDIDATE)

    async def failed_save(*_a: Any, **_k: Any) -> None:
        raise OSError(f"disk full near {_CANDIDATE}")

    with monkeypatch.context() as failing:
        failing.setattr("messagefoundry.pipeline.engine.persist_rotation_meta", failed_save)
        with caplog.at_level("ERROR", logger="messagefoundry.pipeline.engine"):
            engine = await site.start(SecretRotationSettings())
        try:
            assert engine._registry_runner is not None and engine._registry_runner.running
        finally:
            await engine.stop()
    assert "OSError" in caplog.text
    assert _CANDIDATE not in caplog.text
    assert (await site.rows())[_AD].last_rotated == _LONG_AGO

    engine = await site.start(SecretRotationSettings())
    await engine.stop()
    assert (await site.rows())[_AD].last_rotated != _LONG_AGO
