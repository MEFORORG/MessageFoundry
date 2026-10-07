# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DEK rotation is a RE-KEY of the secret-rotation fingerprints, not a rotation of every secret
(ASVS 13.3.4, BACKLOG #2242).

The fingerprint MAC key is derived from the store DEK. Before this fix, a DEK rotation changed every
non-DEK class's stored fingerprint, so the reconcile read each one as rotated and reset its clock.
That lifted every overdue refusal under ``[secret_rotation].enforce_secret_expiry_classes`` (#1932).

Synthetic values only: every "secret" here is a test string.
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path

import pytest

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import EgressSettings, SecretRotationSettings
from messagefoundry.pipeline import secret_rotation as sr
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.secret_rotation import (
    SecretRotationOverdueError,
    SecretStamp,
    reconcile_rotation_meta,
)
from messagefoundry.store.crypto import (
    generate_key,
    make_cipher,
    rotation_fingerprint_key,
    rotation_fingerprint_keys,
)
from messagefoundry.store.store import MessageStore

_AD = "MEFOR_AUTH_AD_BIND_PASSWORD"
_OLD = "2020-01-01"
_VALUE = "test-only-bind-password"  # nosec B105 - a test value, never a real credential
_UTC = datetime.UTC
_TODAY = datetime.datetime.now(tz=_UTC).date()


async def _seed_under(path: Path, dek: str) -> None:
    """A keyed store holding an AD-password stamp from 2020, fingerprinted under ``dek``."""
    store = await MessageStore.open(path, cipher=make_cipher(dek))
    try:
        fp_key = store.secret_rotation_fingerprint_key()
        assert fp_key is not None, "premise: a keyed store fingerprints secrets"
        await store.upsert_secret_rotation_meta(
            _AD,
            fingerprint=sr._keyed_fingerprint(fp_key, _VALUE),
            tracked_since=_OLD,
            last_rotated=_OLD,
        )
    finally:
        await store.close()


async def _reconcile_after_rotation(
    path: Path, *, retired: tuple[str, ...], value: str, new_dek: str
) -> tuple[dict[str, SecretStamp], str]:
    """Reopen the store under ``new_dek`` (with ``retired`` still configured) and reconcile, as the
    engine does at start. Returns the stamps and the AD row's stored fingerprint afterwards."""
    store = await MessageStore.open(path, cipher=make_cipher(new_dek, retired))
    try:
        stamps = await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=store.cipher_info().active_key_id,
            enforcement=SecurityEnforcement.WARN,
            env_values={_AD: value},
            prior_fingerprint_keys=rotation_fingerprint_keys(store.cipher()),
        )
        return stamps, (await store.get_secret_rotation_meta())[_AD].fingerprint
    finally:
        await store.close()


async def test_a_dek_rotation_keeps_another_classs_last_rotated(tmp_path: Path) -> None:
    path, a, b = tmp_path / "rekey.db", generate_key(), generate_key()
    await _seed_under(path, a)
    stamps, stored = await _reconcile_after_rotation(path, retired=(a,), value=_VALUE, new_dek=b)
    assert stamps[_AD].last_rotated == datetime.date.fromisoformat(_OLD)
    assert stamps[_AD].tracked_since == datetime.date.fromisoformat(_OLD)
    # Re-fingerprinted under the new key, so the next start compares equal and writes nothing.
    new_fp_key = rotation_fingerprint_key(make_cipher(b))
    assert new_fp_key is not None
    assert stored == sr._keyed_fingerprint(new_fp_key, _VALUE)


async def test_a_secret_changed_with_the_dek_still_reads_as_rotated(tmp_path: Path) -> None:
    """The prior key is in hand, so a secret that changed in the same window is told apart."""
    path, a, b = tmp_path / "both.db", generate_key(), generate_key()
    await _seed_under(path, a)
    stamps, _stored = await _reconcile_after_rotation(
        path, retired=(a,), value="test-only-new-bind-password", new_dek=b
    )
    assert stamps[_AD].last_rotated == _TODAY
    assert stamps[_AD].tracked_since == datetime.date.fromisoformat(_OLD)


async def test_with_the_prior_dek_dropped_the_age_is_kept_and_the_gap_is_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Without the key that made the stored fingerprint, nothing can tell a re-key from a change.
    The reconcile keeps the older date, the direction that can only over-report an age."""
    path, a, b = tmp_path / "dropped.db", generate_key(), generate_key()
    await _seed_under(path, a)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        stamps, _stored = await _reconcile_after_rotation(path, retired=(), value=_VALUE, new_dek=b)
    assert stamps[_AD].last_rotated == datetime.date.fromisoformat(_OLD)
    assert "no longer configured" in caplog.text and _AD in caplog.text
    assert _VALUE not in caplog.text


async def test_control_a_changed_secret_under_the_same_dek_reads_as_rotated(
    tmp_path: Path,
) -> None:
    """Without this arm, the arms above could pass with change detection switched off."""
    path, a = tmp_path / "control.db", generate_key()
    await _seed_under(path, a)
    stamps, _stored = await _reconcile_after_rotation(
        path, retired=(), value="test-only-new-bind-password", new_dek=a
    )
    assert stamps[_AD].last_rotated == _TODAY


async def test_a_dek_rotation_does_not_lift_an_opted_in_overdue_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The item's own consequence, end to end through Engine.start: an AD password last rotated in
    2020 must still refuse the start after the DEK is rotated and nothing else changed."""
    path, a, b = tmp_path / "engine.db", generate_key(), generate_key()
    await _seed_under(path, a)
    monkeypatch.setenv(_AD, _VALUE)
    store = await MessageStore.open(path, cipher=make_cipher(b, (a,)))
    engine = Engine(
        store,
        secret_rotation_settings=SecretRotationSettings(enforce_secret_expiry_classes=[_AD]),
        security_enforcement=SecurityEnforcement.ENFORCE,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        with pytest.raises(SecretRotationOverdueError) as exc:
            await engine.start()
        assert [r.class_id for r in exc.value.refused] == [_AD]
    finally:
        try:
            await engine.stop()
        except Exception:  # a refused start leaves a partially wired engine; best-effort teardown
            await store.close()
