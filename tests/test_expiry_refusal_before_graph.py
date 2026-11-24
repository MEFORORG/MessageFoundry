# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5615: a single node refuses an expired store key or opted-in secret before any listener
binds, and every other start behaves as it did. Synthetic keys and values, temporary stores."""

from __future__ import annotations

import ast
import logging
import textwrap
import time as real_time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import EgressSettings, SecretRotationSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline import secret_rotation as sr
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.secret_rotation import (
    SecretRotationOverdueError,
    StoreKeyRotationOverdueError,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.crypto import CipherError, cipher_info, generate_key, make_cipher
from messagefoundry.store.store import MessageStore, SecretRotationMetaRow
from tests._ast_sites import call_sites

DEK = sr._DEK_CLASS_ID
RECORD = sr.ROTATION_RECORD_ID
AD = "MEFOR_AUTH_AD_BIND_PASSWORD"
OLD = "2020-01-01"
_BASE = SecretRotationSettings()
DEK_LIMIT = _BASE.store_key_max_age_days + _BASE.enforce_grace_days
SECRET_LIMIT = _BASE.secret_max_age_days + _BASE.enforce_grace_days
_ENGINE_PY = Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline" / "engine.py"


class _Clock:
    """Stands in for the ``time`` module inside ``secret_rotation`` only."""

    offset_days = 0

    @classmethod
    def time(cls) -> float:
        return real_time.time() + cls.offset_days * 86400


class _Rig:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.cfg = root / "cfg"
        self.cfg.mkdir()
        (root / "in").mkdir()
        (self.cfg / "c.py").write_text(
            textwrap.dedent(
                f"""
                from messagefoundry import inbound, outbound, router, handler, Send, File
                inbound("in", File(directory={str(root / "in")!r}, pattern="*.hl7",
                        poll_seconds=0.05), router="r")
                outbound("out", File(directory={str(root / "out")!r}, filename="x.hl7"))
                @router("r")
                def route(msg):
                    return ["h"]
                @handler("h")
                def handle(msg):
                    return Send("out", msg)
                """
            ),
            encoding="utf-8",
        )
        self.graph_starts = 0

    async def open(self, active: str, retired: tuple[str, ...] = ()) -> MessageStore:
        cipher = make_cipher(active, list(retired))
        return await MessageStore.open(
            self.root / "s.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )

    async def seed_chain(self, key: str) -> None:
        store = await self.open(key)
        try:
            await store.record_audit("test.seed", actor="u")
        finally:
            await store.close()

    async def start(
        self,
        active: str,
        retired: tuple[str, ...] = (),
        *,
        fail: bool = False,
        settings: SecretRotationSettings | None = None,
        enforcement: SecurityEnforcement = SecurityEnforcement.ENFORCE,
    ) -> str:
        """``STARTED``, ``FAILED`` (the injected graph failure) or the refusal's type name."""
        store = await self.open(active, retired)
        engine = Engine(
            store,
            secret_rotation_settings=settings or SecretRotationSettings(),
            security_enforcement=enforcement,
            egress_settings=EgressSettings(deny_by_default=False),
        )
        engine.add_registry(load_config(self.cfg))
        real = RegistryRunner.start
        rig = self

        async def counted(runner: RegistryRunner, **kwargs: Any) -> None:
            rig.graph_starts += 1
            if fail:
                raise ConnectionError("injected graph failure")
            await real(runner, **kwargs)

        RegistryRunner.start = counted  # type: ignore[method-assign,assignment]
        try:
            await engine.start()
            return "STARTED"
        except ConnectionError:
            return "FAILED"
        except (StoreKeyRotationOverdueError, SecretRotationOverdueError) as exc:
            return type(exc).__name__
        finally:
            RegistryRunner.start = real  # type: ignore[method-assign]
            await engine.stop()

    async def rows(
        self, active: str, retired: tuple[str, ...] = ()
    ) -> dict[str, SecretRotationMetaRow]:
        store = await self.open(active, retired)
        try:
            return dict(await store.get_secret_rotation_meta())
        finally:
            await store.close()

    async def backdate(self, key: str, class_id: str) -> None:
        store = await self.open(key)
        try:
            row = (await store.get_secret_rotation_meta())[class_id]
            await store.upsert_secret_rotation_meta(
                class_id, fingerprint=row.fingerprint, tracked_since=OLD, last_rotated=OLD
            )
        finally:
            await store.close()


def _fp(key: str) -> str:
    key_id = cipher_info(make_cipher(key)).active_key_id
    assert key_id is not None
    return sr.dek_fingerprint(key_id)


def _record_for(rows: dict[str, SecretRotationMetaRow]) -> str | None:
    row = rows.get(RECORD)
    return None if row is None or not row.fingerprint else row.fingerprint


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Rig:
    _Clock.offset_days = 0
    monkeypatch.setattr(sr, "time", _Clock)
    return _Rig(tmp_path)


# --- the defect ---------------------------------------------------------------------------------


async def test_an_overdue_key_is_refused_before_any_listener_binds(rig: _Rig) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    assert await rig.start(key) == "STARTED"
    await rig.backdate(key, DEK)
    rig.graph_starts = 0
    assert await rig.start(key) == "StoreKeyRotationOverdueError"
    assert rig.graph_starts == 0


async def test_an_overdue_opted_in_secret_is_refused_before_any_listener_binds(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    opted = SecretRotationSettings(enforce_secret_expiry_classes=[AD])
    await rig.seed_chain(key)
    monkeypatch.setenv(AD, "test-only-value")
    assert await rig.start(key, settings=opted) == "STARTED"
    await rig.backdate(key, AD)
    rig.graph_starts = 0
    assert await rig.start(key, settings=opted) == "SecretRotationOverdueError"
    assert rig.graph_starts == 0


async def test_a_refusal_alerts_and_logs_once(
    rig: _Rig, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    await rig.start(key)
    await rig.backdate(key, DEK)
    calls: list[str] = []

    def due(_self: Any, name: str, **_kw: Any) -> None:
        calls.append(name)

    monkeypatch.setattr("messagefoundry.pipeline.alerts.LoggingAlertSink.secret_rotation_due", due)
    with caplog.at_level(logging.WARNING, logger=sr.log.name):
        assert await rig.start(key) == "StoreKeyRotationOverdueError"
    assert len(calls) == 1
    lines = [r.getMessage() for r in caplog.records if r.name == sr.log.name]
    assert len(lines) == len(set(lines))


# --- candidate-key sequences: V1 to V8 ----------------------------------------------------------


async def test_v1_healthy_key_restored_after_a_failed_candidate(rig: _Rig) -> None:
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    assert await rig.start(k1) == "STARTED"
    assert await rig.start(k2, (k1,), fail=True) == "FAILED"
    assert await rig.start(k1, (k2,)) == "STARTED"
    assert await rig.start(k1, (k2,)) == "STARTED"
    rows = await rig.rows(k1, (k2,))
    assert _record_for(rows) is None
    assert rows[DEK].fingerprint == _fp(k1)


async def test_v2_overdue_key_is_refused_on_the_candidate_and_opens_no_record(
    rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """The one named difference: main reported the injected graph failure here. The reconcile's
    line says it opened a record, so the start must also say that write was not saved."""
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    await rig.start(k1)
    await rig.backdate(k1, DEK)
    with caplog.at_level(logging.WARNING, logger=sr.log.name):
        assert await rig.start(k2, (k1,), fail=True) == "StoreKeyRotationOverdueError"
    assert any("were NOT saved" in r.getMessage() for r in caplog.records)
    assert await rig.start(k1, (k2,)) == "StoreKeyRotationOverdueError"
    rows = await rig.rows(k1, (k2,))
    assert _record_for(rows) is None
    assert rows[DEK].fingerprint == _fp(k1)
    assert rows[DEK].last_rotated == OLD


async def test_v3_unstamped_original_key(rig: _Rig) -> None:
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    assert await rig.start(k1, fail=True) == "FAILED"
    assert await rig.start(k2, (k1,), fail=True) == "FAILED"
    assert DEK not in await rig.rows(k2, (k1,))
    assert await rig.start(k1, (k2,)) == "STARTED"
    assert await rig.start(k1, (k2,)) == "STARTED"
    assert (await rig.rows(k1, (k2,)))[DEK].fingerprint == _fp(k1)


async def test_v4_unstamped_original_key_then_aged(rig: _Rig) -> None:
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    await rig.start(k1, fail=True)
    await rig.start(k2, (k1,), fail=True)
    assert await rig.start(k1, (k2,)) == "STARTED"
    await rig.backdate(k1, DEK)
    assert await rig.start(k1, (k2,)) == "StoreKeyRotationOverdueError"


async def test_v5_third_key_is_held(rig: _Rig) -> None:
    k1, k2, k3 = generate_key(), generate_key(), generate_key()
    await rig.seed_chain(k1)
    await rig.start(k1)
    assert await rig.start(k2, (k1,), fail=True) == "FAILED"
    assert await rig.start(k3, (k1, k2)) == "STARTED"
    rows = await rig.rows(k3, (k1, k2))
    assert _record_for(rows) == _fp(k3)
    assert rows[DEK].fingerprint == _fp(k1)


async def test_v6_candidate_started_again_is_held(rig: _Rig) -> None:
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    await rig.start(k1)
    assert await rig.start(k2, (k1,), fail=True) == "FAILED"
    assert await rig.start(k2, (k1,)) == "STARTED"
    rows = await rig.rows(k2, (k1,))
    assert _record_for(rows) == _fp(k2)
    assert rows[DEK].fingerprint == _fp(k1)


async def test_v7_age_is_not_counted_from_a_failed_candidate(rig: _Rig) -> None:
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    await rig.start(k1, fail=True)
    await rig.start(k2, (k1,), fail=True)
    _Clock.offset_days = DEK_LIMIT // 2
    assert await rig.start(k1, (k2,)) == "STARTED"
    _Clock.offset_days = DEK_LIMIT + 10
    assert await rig.start(k1, (k2,)) == "STARTED"


async def test_v8_clock_control_with_no_candidate(rig: _Rig) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    _Clock.offset_days = DEK_LIMIT // 2
    assert await rig.start(key) == "STARTED"
    _Clock.offset_days = DEK_LIMIT + 10
    assert await rig.start(key) == "STARTED"
    _Clock.offset_days = DEK_LIMIT // 2 + DEK_LIMIT + 10
    assert await rig.start(key) == "StoreKeyRotationOverdueError"


# --- what a refused start must still record: R1, R2, W5, the held first start -------------------


async def test_r1_first_sighting_on_a_refused_start_keeps_the_key_age(rig: _Rig) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    overdue = SecretRotationSettings(store_key_last_rotated=OLD)
    assert await rig.start(key, settings=overdue) == "StoreKeyRotationOverdueError"
    _Clock.offset_days = DEK_LIMIT + 10
    assert await rig.start(key) == "StoreKeyRotationOverdueError"


async def test_r2_secret_first_seen_by_a_refused_start_keeps_its_age(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    monkeypatch.setenv(AD, "test-only-value")
    overdue = SecretRotationSettings(store_key_last_rotated=OLD)
    assert await rig.start(key, settings=overdue) == "StoreKeyRotationOverdueError"
    _Clock.offset_days = SECRET_LIMIT + 10
    later = SecretRotationSettings(
        enforce_secret_expiry_classes=[AD], store_key_last_rotated="2099-01-01"
    )
    assert await rig.start(key, settings=later) == "SecretRotationOverdueError"


async def test_w5_a_refused_candidate_secret_does_not_reset_the_original(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    opted = SecretRotationSettings(enforce_secret_expiry_classes=[AD])
    override = SecretRotationSettings(
        enforce_secret_expiry_classes=[AD], store_key_last_rotated=OLD
    )
    monkeypatch.setenv(AD, "test-only-s1")
    assert await rig.start(key, settings=opted) == "STARTED"
    await rig.backdate(key, AD)
    monkeypatch.setenv(AD, "test-only-s2")
    assert await rig.start(key, settings=override, fail=True) == "StoreKeyRotationOverdueError"
    monkeypatch.setenv(AD, "test-only-s1")
    assert await rig.start(key, settings=opted) == "SecretRotationOverdueError"


async def test_a_held_first_start_key_keeps_its_age_through_a_refused_start(rig: _Rig) -> None:
    """No stamp and a chain not rolled to the key: the record a refused start opens dates it."""
    k1, k2 = generate_key(), generate_key()
    await rig.seed_chain(k1)
    overdue = SecretRotationSettings(store_key_last_rotated=OLD)
    assert await rig.start(k2, (k1,), settings=overdue) == "StoreKeyRotationOverdueError"
    rows = await rig.rows(k2, (k1,))
    assert DEK not in rows
    assert _record_for(rows) == _fp(k2)
    _Clock.offset_days = DEK_LIMIT + 10
    assert await rig.start(k2, (k1,)) == "StoreKeyRotationOverdueError"


# --- a prediction that fails, and starts it must not touch --------------------------------------


async def test_a_failed_prediction_lets_the_start_continue_and_the_later_block_decide(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    await rig.start(key)
    await rig.backdate(key, DEK)
    real = sr.reconcile_rotation_meta

    async def fail_on_overlay(meta: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(meta, sr._InMemoryRotationMeta):
            raise RuntimeError("injected prediction failure")
        return await real(meta, *args, **kwargs)

    monkeypatch.setattr(sr, "reconcile_rotation_meta", fail_on_overlay)
    rig.graph_starts = 0
    assert await rig.start(key) == "StoreKeyRotationOverdueError"
    assert rig.graph_starts == 1  # the later block refused, after the graph, as on main


async def test_a_secrets_directory_error_in_prediction_is_left_to_the_later_block(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.engine_secrets import SecretsDirectoryError

    key = generate_key()
    opted = SecretRotationSettings(enforce_secret_expiry_classes=[AD])
    await rig.seed_chain(key)
    await rig.start(key, settings=opted)
    calls = 0
    real = sr.held_env_secret_values

    def fail_first(environ: Any = None) -> dict[str, str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise SecretsDirectoryError("injected")
        return real(environ)

    monkeypatch.setattr(sr, "held_env_secret_values", fail_first)
    rig.graph_starts = 0
    assert await rig.start(key, settings=opted) == "STARTED"
    assert rig.graph_starts == 1
    assert calls > 1  # the failed read was the prediction's, and the later block read again


async def test_a_cancellation_is_not_taken_for_a_failed_prediction(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    key = generate_key()
    await rig.seed_chain(key)
    await rig.start(key)

    async def cancelled(*_a: Any, **_k: Any) -> Any:
        raise asyncio.CancelledError

    monkeypatch.setattr(sr, "reconcile_rotation_meta", cancelled)
    rig.graph_starts = 0
    with pytest.raises(asyncio.CancelledError):
        await rig.start(key)
    assert rig.graph_starts == 0


@pytest.mark.parametrize(
    ("enforcement", "settings"),
    [
        (SecurityEnforcement.WARN, SecretRotationSettings()),
        (SecurityEnforcement.ENFORCE, SecretRotationSettings(enforce_store_key_expiry=False)),
    ],
    ids=["not-enforce", "dek-refusal-off"],
)
async def test_no_prediction_where_the_gate_is_off(
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
    enforcement: SecurityEnforcement,
    settings: SecretRotationSettings,
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    await rig.start(key, settings=settings, enforcement=enforcement)
    await rig.backdate(key, DEK)
    calls = 0
    real = sr.reconcile_rotation_meta

    async def counted(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return await real(*args, **kwargs)

    monkeypatch.setattr(sr, "reconcile_rotation_meta", counted)
    assert await rig.start(key, settings=settings, enforcement=enforcement) == "STARTED"
    assert calls == 0


@pytest.mark.parametrize("key_id", [None, ""], ids=["keyless", "no-local-key"])
async def test_no_prediction_without_a_local_key(key_id: str | None) -> None:
    class _Meta:
        def secret_rotation_cipher(self) -> None:
            raise AssertionError("must not be read")

        async def get_secret_rotation_meta(self) -> dict[str, SecretRotationMetaRow]:
            raise AssertionError("must not be read")

        async def upsert_secret_rotation_meta(self, *_a: Any, **_k: Any) -> None:
            raise AssertionError("must not be written")

    async def held() -> frozenset[str]:
        raise AssertionError("must not be read")

    await sr.refuse_expiry_before_graph(
        _Meta(),
        SecretRotationSettings(),
        dek_key_id=lambda: key_id,
        enforcement=SecurityEnforcement.ENFORCE,
        alert_sink=None,
        extra_values=dict,
        audit_rolled=lambda: None,
        held=held,
    )


async def test_no_prediction_on_vault_transit_shape() -> None:
    """A key id with no sealing cipher: the later block handles it, and no row is read."""

    class _Meta:
        def secret_rotation_cipher(self) -> None:
            return None

        async def get_secret_rotation_meta(self) -> dict[str, SecretRotationMetaRow]:
            raise AssertionError("must not be read")

        async def upsert_secret_rotation_meta(self, *_a: Any, **_k: Any) -> None:
            raise AssertionError("must not be written")

    async def held() -> frozenset[str]:
        raise AssertionError("must not be read")

    await sr.refuse_expiry_before_graph(
        _Meta(),
        SecretRotationSettings(),
        dek_key_id=lambda: "transit-key",
        enforcement=SecurityEnforcement.ENFORCE,
        alert_sink=None,
        extra_values=dict,
        audit_rolled=lambda: None,
        held=held,
    )


async def test_no_prediction_on_a_clustered_start(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    await rig.start(key)
    calls = 0

    async def counted(*_a: Any, **_k: Any) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr("messagefoundry.pipeline.engine.refuse_expiry_before_graph", counted)
    monkeypatch.setattr(
        "messagefoundry.pipeline.engine.NullCoordinator.is_clustered", lambda _self: True
    )
    try:
        await rig.start(key)
    except Exception:  # a forced-clustered SQLite start may stop later; only the gate is read here
        logging.getLogger(__name__).debug("forced-clustered start stopped", exc_info=True)
    assert calls == 0


async def test_a_clean_start_writes_and_logs_nothing_twice(
    rig: _Rig, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A start that is not refused: only the later block writes, so a first start seals once."""
    key = generate_key()
    await rig.seed_chain(key)
    monkeypatch.setenv(AD, "test-only-value")
    assert await rig.start(key) == "STARTED"
    await rig.backdate(key, AD)
    store = await rig.open(key)
    try:
        before = await store.get_secret_rotation_meta()
        row = before[AD]
        await store.upsert_secret_rotation_meta(
            AD, fingerprint="garbled", tracked_since=OLD, last_rotated=OLD
        )
    finally:
        await store.close()
    with caplog.at_level(logging.WARNING, logger=sr.log.name):
        assert await rig.start(key) == "STARTED"
    lines = [r for r in caplog.records if "written by an earlier release" in r.getMessage()]
    assert len(lines) == 1
    assert (await rig.rows(key))[AD].fingerprint != row.fingerprint


# --- a seal failure stays where main has it -------------------------------------------------------


async def test_a_seal_failure_on_an_opted_in_class_refuses_after_the_graph(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    await rig.seed_chain(key)
    monkeypatch.setenv(AD, "test-only-value")

    def seal(cipher: Any, _class_id: str, _cell: str) -> str:
        if isinstance(cipher, sr._UnchargedCipher):
            return "predicted"  # the prediction charges nothing, so it cannot see this failure
        raise CipherError("injected invocation ceiling")

    monkeypatch.setattr(sr, "seal_rotation_fingerprint", seal)
    rig.graph_starts = 0
    opted = SecretRotationSettings(enforce_secret_expiry_classes=[AD])
    assert await rig.start(key, settings=opted) == "SecretRotationOverdueError"
    assert rig.graph_starts == 1


def test_a_refused_start_charges_a_real_seal_only_for_a_first_sighting() -> None:
    class _Recording:
        def __init__(self) -> None:
            self.sealed: list[str] = []

        def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
            self.sealed.append(plaintext)
            return "real"

    real = _Recording()
    cipher = sr._FirstSightingCipher(real, {"KNOWN"})  # type: ignore[arg-type]
    assert cipher.encrypt("aa:bb:KNOWN") == "predicted"
    assert real.sealed == []
    assert cipher.encrypt("aa:bb:NEW") == "real"
    assert real.sealed == ["aa:bb:NEW"]


# --- the siting -----------------------------------------------------------------------------------


def test_engine_py_has_one_bare_reconcile_call_and_one_of_each_refusal() -> None:
    """The siting guards in the calendar and opt-in test files find THE guarded reconcile by walking
    for a bare call, so a second one in engine.py would make their answer depend on walk order."""
    tree = ast.parse(_ENGINE_PY.read_text(encoding="utf-8"))
    for name in (
        "reconcile_rotation_meta",
        "enforce_store_key_expiry",
        "enforce_secret_expiry",
        "refuse_expiry_before_graph",
    ):
        assert len(call_sites(tree, name, bare_only=True)) == 1, name
