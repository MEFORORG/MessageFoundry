# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5615: on a single node the expiry refusals run before the graph, and the rotation stamps
and rotation record they read are saved only once the start has got past the point where they
were always saved.

The order matters because a stamp is a claim that a secret was rotated. A start that fails with a
candidate value must not record it: putting the old value back would then read as a second rotation
and reset the clock of a secret that was never rotated.
"""

from __future__ import annotations

import time
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
from messagefoundry.store.crypto import (
    cipher_info,
    generate_key,
    make_cipher,
    seal_rotation_fingerprint,
)
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
        pending = sr.PendingRotationWrites()
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


async def test_a_failed_save_refuses_and_the_next_start_detects_the_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """As on main, where a failed write left the age undetermined under ENFORCE. Without this a
    store that cannot keep a date would never age a key."""
    site = _Site(tmp_path)
    await site.seed_old_stamp()
    monkeypatch.setenv(_AD, _CANDIDATE)

    async def failed_save(*_a: Any, **_k: Any) -> None:
        raise OSError(f"disk full near {_CANDIDATE}")

    with monkeypatch.context() as failing:
        failing.setattr("messagefoundry.pipeline.engine.persist_rotation_meta", failed_save)
        with (
            caplog.at_level("ERROR", logger="messagefoundry.pipeline.engine"),
            pytest.raises(StoreKeyRotationOverdueError),
        ):
            await site.start(SecretRotationSettings())
    assert "OSError" in caplog.text
    assert _CANDIDATE not in caplog.text
    assert (await site.rows())[_AD].last_rotated == _LONG_AGO

    engine = await site.start(SecretRotationSettings())
    await engine.stop()
    assert (await site.rows())[_AD].last_rotated != _LONG_AGO


async def test_a_record_opened_during_bring_up_stops_the_deferred_stamp(tmp_path: Path) -> None:
    """A run that opened a record for this key after the compute must not read as complete."""
    site = _Site(tmp_path)
    store = await site.open()
    try:
        key_id = store.cipher_info().active_key_id
        assert key_id is not None
        pending = sr.PendingRotationWrites()
        await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=key_id,
            enforcement=SecurityEnforcement.ENFORCE,
            defer_writes=pending,
        )
        assert [row[0] for row in pending.stamps] == [sr._DEK_CLASS_ID], "premise: a DEK stamp"
        await sr.open_rotation_record(store, key_id, "2026-01-01")
        await sr.persist_rotation_meta(store, pending)
        rows = await store.get_secret_rotation_meta()
        assert sr._DEK_CLASS_ID not in rows
        assert rows[sr.ROTATION_RECORD_ID].fingerprint == sr.dek_fingerprint(key_id)
    finally:
        await store.close()


# --- the store key: a failed or refused start leaves no rotation record ------------------------

_DEK = sr._DEK_CLASS_ID
_REC = sr.ROTATION_RECORD_ID
_DEFAULTS = SecretRotationSettings()
_LIMIT = _DEFAULTS.store_key_max_age_days + _DEFAULTS.enforce_grace_days
_UP, _FAILED, _REFUSED = "started", "failed", "refused"


class _Clock:
    """Stands in for the time module inside secret_rotation only."""

    def __init__(self) -> None:
        self.day = 0
        self._epoch = time.time()

    def time(self) -> float:
        return self._epoch + self.day * 86400


class _KeySite:
    """One store file started under named keys, every other named key kept as retired."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.db = tmp_path / "keys.db"
        self.cfg = tmp_path / "cfg"
        _minimal_graph(self.cfg, tmp_path)
        self.keys = {name: generate_key() for name in "abc"}
        self.monkeypatch = monkeypatch
        self.clock = _Clock()
        monkeypatch.setattr(sr, "time", self.clock)

    async def open(self, active: str) -> MessageStore:
        retired = [key for name, key in self.keys.items() if name != active]
        cipher = make_cipher(self.keys[active], retired)
        return await MessageStore.open(self.db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())

    async def seed_chain(self) -> None:
        store = await self.open("a")
        await store.record_audit("test.seed", actor="u")
        await store.close()

    async def start(
        self,
        active: str,
        *,
        fail: bool = False,
        day: int | None = None,
        settings: SecretRotationSettings | None = None,
    ) -> str:
        if day is not None:
            self.clock.day = day
        engine = Engine(
            await self.open(active),
            secret_rotation_settings=settings or SecretRotationSettings(),
            security_enforcement=SecurityEnforcement.ENFORCE,
            egress_settings=EgressSettings(deny_by_default=False),
        )
        engine.add_registry(load_config(self.cfg))
        try:
            with self.monkeypatch.context() as patch:
                if fail:
                    _fail_the_graph(patch)
                await engine.start()
            return _UP
        except _StartFailed:
            return _FAILED
        except StoreKeyRotationOverdueError:
            return _REFUSED
        finally:
            await engine.stop()

    async def rows(self, active: str = "a") -> dict[str, Any]:
        store = await self.open(active)
        try:
            return dict(await store.get_secret_rotation_meta())
        finally:
            await store.close()

    async def backdate_stamp(self) -> None:
        store = await self.open("a")
        try:
            row = (await store.get_secret_rotation_meta())[_DEK]
            await store.upsert_secret_rotation_meta(
                _DEK, fingerprint=row.fingerprint, tracked_since=_LONG_AGO, last_rotated=_LONG_AGO
            )
        finally:
            await store.close()

    def fingerprint(self, name: str) -> str:
        return sr.dek_fingerprint(self.key_id(name))

    def key_id(self, name: str) -> str:
        key_id = cipher_info(make_cipher(self.keys[name])).active_key_id
        assert key_id is not None, "premise: a keyed cipher names its key"
        return key_id

    def record_names(self, rows: dict[str, Any]) -> str | None:
        """The named key an open record holds, or None when no record stands open."""
        record = rows.get(_REC)
        if not sr._record_open(record):
            return None
        return next(n for n in self.keys if self.fingerprint(n) == record.fingerprint)


@pytest.fixture
async def keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _KeySite:
    site = _KeySite(tmp_path, monkeypatch)
    await site.seed_chain()
    return site


async def test_v1_candidate_fails_and_the_original_restarts(keys: _KeySite) -> None:
    assert await keys.start("a") == _UP
    assert await keys.start("b", fail=True) == _FAILED
    assert keys.record_names(await keys.rows()) is None
    assert [await keys.start("a"), await keys.start("a")] == [_UP, _UP]
    rows = await keys.rows()
    assert keys.record_names(rows) is None
    assert rows[_DEK].fingerprint == keys.fingerprint("a")


async def test_v2_overdue_original_stays_refused_after_a_candidate(keys: _KeySite) -> None:
    """The candidate is held against the overdue stamp, so it is now refused before the graph."""
    await keys.start("a")
    await keys.backdate_stamp()
    assert await keys.start("b", fail=True) == _REFUSED
    assert await keys.start("a") == _REFUSED
    assert keys.record_names(await keys.rows()) is None


async def test_v3_unstamped_original_is_stamped_with_no_candidate_record(keys: _KeySite) -> None:
    assert await keys.start("a", fail=True) == _FAILED
    assert await keys.start("b", fail=True) == _FAILED
    after_failures = await keys.rows()
    assert _DEK not in after_failures and keys.record_names(after_failures) is None
    assert [await keys.start("a"), await keys.start("a")] == [_UP, _UP]
    rows = await keys.rows()
    assert keys.record_names(rows) is None
    assert rows[_DEK].fingerprint == keys.fingerprint("a")


async def test_v4_restored_original_ages_from_its_stamp(keys: _KeySite) -> None:
    await keys.start("a", fail=True)
    await keys.start("b", fail=True)
    assert await keys.start("a") == _UP
    await keys.backdate_stamp()
    assert await keys.start("a") == _REFUSED


async def test_v5_a_third_key_after_a_failed_candidate(keys: _KeySite) -> None:
    await keys.start("a")
    await keys.start("b", fail=True)
    assert await keys.start("c") == _UP
    rows = await keys.rows("c")
    assert keys.record_names(rows) == "c"
    assert rows[_DEK].fingerprint == keys.fingerprint("a")


async def test_v6_the_candidate_starting_opens_the_record_main_opens(keys: _KeySite) -> None:
    await keys.start("a")
    before = (await keys.rows())[_DEK]
    await keys.start("b", fail=True)
    assert await keys.start("b") == _UP
    rows = await keys.rows("b")
    assert keys.record_names(rows) == "b"
    assert rows[_DEK].fingerprint == before.fingerprint, "a held key is not stamped"


async def test_v7_failed_candidate_does_not_date_the_restored_key(keys: _KeySite) -> None:
    await keys.start("a", fail=True, day=0)
    await keys.start("b", fail=True, day=0)
    assert await keys.start("a", day=_LIMIT // 2) == _UP
    assert await keys.start("a", day=_LIMIT + 10) == _UP


async def test_v8_control_with_no_candidate(keys: _KeySite) -> None:
    assert await keys.start("a", day=_LIMIT // 2) == _UP
    assert await keys.start("a", day=_LIMIT + 10) == _UP
    assert await keys.start("a", day=_LIMIT // 2 + _LIMIT + 10) == _REFUSED


async def test_a_failed_candidate_start_writes_no_row_at_all(keys: _KeySite) -> None:
    await keys.start("a")
    before = await keys.rows()
    assert await keys.start("b", fail=True) == _FAILED
    assert await keys.rows() == before


async def test_refusal_against_a_held_key_with_an_open_record(keys: _KeySite) -> None:
    """A record already open for this key holds it, and its dates are the age the refusal reads."""
    store = await keys.open("b")
    await sr.open_rotation_record(store, keys.key_id("b"), _LONG_AGO)
    await store.close()
    assert await keys.start("b") == _REFUSED
    assert keys.record_names(await keys.rows("b")) == "b"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="BACKLOG #5615 HELD: main stamps the first sighting before it refuses, so the age "
    "survives the refusal. Writing nothing on a refused start loses it and this start passes.",
)
async def test_a_refused_first_start_still_dates_the_key(keys: _KeySite) -> None:
    overdue = SecretRotationSettings(store_key_last_rotated=_LONG_AGO)
    assert await keys.start("a", day=0, settings=overdue) == _REFUSED
    assert await keys.start("a", day=_LIMIT + 10) == _REFUSED
