# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A store key rotation does not move the secret-rotation fingerprints (ASVS 13.3.4, BACKLOG #3472,
ADR 0213).

Each non-DEK fingerprint is a store-cipher cell holding a per-row random HMAC key, the value's MAC
and the row's class id. ``rotate-key``'s ``reencrypt_to_active`` re-seals it under the new key, so a
start that no longer holds the retired key, as the Windows service's first start after a rotation
does not, still tells an unchanged secret from a changed one. Before this, the MAC key was derived
from the store key, so that start could tell neither and kept every date
(``test_a_secret_changed_with_the_store_key_reads_as_rotated`` fails on the code before #3472).

No test here assumes a retired key is still configured at the start after a rotation.

Synthetic values only: every "secret" here is a test string.
"""

from __future__ import annotations

import ast
import datetime
import hmac
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
    ROTATION_FP_SEALED_SCHEME,
    AesGcmCipher,
    generate_key,
    make_cipher,
    open_rotation_fingerprint,
    rotation_fingerprint_cipher,
    seal_rotation_fingerprint,
)
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.store.store import MessageStore

_AD = "MEFOR_AUTH_AD_BIND_PASSWORD"
_SMTP = "MEFOR_ALERTS_EMAIL_PASSWORD"
_OLD = datetime.date(2020, 1, 1)
_VALUE = "test-only-bind-password"  # nosec B105 - a test value, never a real credential
_NEW_VALUE = "test-only-new-bind-password"  # nosec B105 - a test value
_UTC = datetime.UTC
# Fixed clocks, so a run across UTC midnight cannot flake the date asserts.
_THEN = datetime.datetime(2020, 1, 1, 12, 0, tzinfo=_UTC)
_NOW = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=_UTC)
_TODAY = _NOW.date()
_LOGGER = "messagefoundry.pipeline.secret_rotation"


def _cipher(key: str, retired: tuple[str, ...] = (), *, aad_bind: bool = True) -> AesGcmCipher:
    cipher = make_cipher(key, retired, write_v2=aad_bind)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


async def _reconcile(
    store: MessageStore, value: str, *, now: datetime.datetime = _NOW
) -> dict[str, SecretStamp]:
    return await reconcile_rotation_meta(
        store,
        SecretRotationSettings(),
        dek_key_id=store.cipher_info().active_key_id,
        enforcement=SecurityEnforcement.WARN,
        now=now.timestamp(),
        env_values={_AD: value},
    )


async def _seed(path: Path, key: str, *, aad_bind: bool = True) -> None:
    """A keyed store whose AD-password stamp has been tracked, unchanged, since 2020."""
    store = await MessageStore.open(path, cipher=_cipher(key, aad_bind=aad_bind))
    try:
        stamps = await _reconcile(store, _VALUE, now=_THEN)
        assert stamps[_AD].last_rotated == _OLD, "premise: seeded in 2020"
    finally:
        await store.close()


async def _rotate(path: Path, old: str, new: str, *, aad_bind: bool = True) -> int:
    """``rotate-key``'s store pass: open under the new key with the old one retired, re-encrypt."""
    store = await MessageStore.open(path, cipher=_cipher(new, (old,), aad_bind=aad_bind))
    try:
        return await store.reencrypt_to_active()
    finally:
        await store.close()


async def _start(path: Path, key: str, value: str) -> tuple[dict[str, SecretStamp], str]:
    """The first start after a rotation, holding the NEW key only. Returns the stamps and the AD
    row's stored fingerprint afterwards."""
    store = await MessageStore.open(path, cipher=_cipher(key))
    try:
        stamps = await _reconcile(store, value)
        return stamps, (await store.get_secret_rotation_meta())[_AD].fingerprint
    finally:
        await store.close()


async def _stored(path: Path, key: str) -> str:
    store = await MessageStore.open(path, cipher=_cipher(key))
    try:
        return (await store.get_secret_rotation_meta())[_AD].fingerprint
    finally:
        await store.close()


async def _plant(
    path: Path, key: str, fingerprint: str, *, last_rotated: str = "2020-01-01"
) -> None:
    """Write the AD row behind the reconcile's back, as an out-of-band writer or an older release
    would."""
    store = await MessageStore.open(path, cipher=_cipher(key))
    try:
        await store.upsert_secret_rotation_meta(
            _AD, fingerprint=fingerprint, tracked_since="2020-01-01", last_rotated=last_rotated
        )
    finally:
        await store.close()


# --- AC-1 / AC-2: a store key rotation ---------------------------------------------------------------


@pytest.mark.parametrize("aad_bind", [True, False])
async def test_a_store_key_rotation_keeps_every_clock(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, aad_bind: bool
) -> None:
    path, a, b = tmp_path / "rotate.db", generate_key(), generate_key()
    await _seed(path, a, aad_bind=aad_bind)
    before = await _stored(path, a)
    assert await _rotate(path, a, b, aad_bind=aad_bind) >= 1
    after = await _stored(path, b)
    # The cell was re-sealed under the new key, so a start holding only that key can open it.
    assert after != before
    assert open_rotation_fingerprint(_cipher(b), _AD, after) is not None
    assert open_rotation_fingerprint(_cipher(b), _AD, before) is None
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        stamps, stored = await _start(path, b, _VALUE)
    assert stamps[_AD].last_rotated == _OLD
    assert stamps[_AD].tracked_since == _OLD
    assert stored == after, "an unchanged secret must not be rewritten"
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


async def test_a_secret_changed_with_the_store_key_reads_as_rotated(tmp_path: Path) -> None:
    """The defect #3472 closes. The retired key is gone at the start, and a secret changed in the
    same window must still reset its clock. Before #3472 this start could not tell and kept 2020."""
    path, a, b = tmp_path / "both.db", generate_key(), generate_key()
    await _seed(path, a)
    await _rotate(path, a, b)
    stamps, stored = await _start(path, b, _NEW_VALUE)
    assert stamps[_AD].last_rotated == _TODAY
    assert stamps[_AD].tracked_since == _OLD
    # And the new value is what the next start compares against.
    again, _ = await _start(path, b, _NEW_VALUE)
    assert again[_AD].last_rotated == _TODAY
    assert stored.startswith(f"{ROTATION_FP_SEALED_SCHEME}:")


async def test_control_a_changed_secret_under_the_same_key_reads_as_rotated(
    tmp_path: Path,
) -> None:
    """Without this arm, the arms above could pass with change detection switched off."""
    path, a = tmp_path / "control.db", generate_key()
    await _seed(path, a)
    same, _ = await _start(path, a, _VALUE)
    assert same[_AD].last_rotated == _OLD
    changed, _ = await _start(path, a, _NEW_VALUE)
    assert changed[_AD].last_rotated == _TODAY


async def test_the_rotation_leaves_a_cell_no_key_opens_and_does_not_stop(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A fingerprint is not PHI, so a cell sealed under a key nobody supplied must not abort a key
    rotation. It is left as it is, counted in one WARNING, and the next start keeps its dates."""
    path, a, b, stray = tmp_path / "stray.db", generate_key(), generate_key(), generate_key()
    await _seed(path, a)
    planted = seal_rotation_fingerprint(_cipher(stray), _AD, sr._fingerprint_cell(_AD, _VALUE))
    await _plant(path, a, planted)
    caplog.set_level(logging.WARNING, logger="messagefoundry.store.crypto")
    await _rotate(path, a, b)
    assert await _stored(path, b) == planted
    warned = [r for r in caplog.records if "could not be opened by any configured" in r.message]
    assert len(warned) == 1 and warned[0].getMessage().startswith("key rotation: 1 ")
    assert _AD not in caplog.text
    stamps, _ = await _start(path, b, _NEW_VALUE)
    assert stamps[_AD].last_rotated == _OLD


async def test_a_start_before_rotate_key_reads_the_retired_key_and_rewrites_nothing(
    tmp_path: Path,
) -> None:
    """The window between setting a new active key and running ``rotate-key``: the old key is
    configured as retired, and a start there still reads each cell under it. An unchanged secret is
    not rewritten, so the cell stays under the retired key for ``rotate-key`` to re-seal, and a
    changed one still resets its clock."""
    path, a, b = tmp_path / "window.db", generate_key(), generate_key()
    await _seed(path, a)
    before = await _stored(path, a)
    store = await MessageStore.open(path, cipher=_cipher(b, (a,)))
    try:
        same = await _reconcile(store, _VALUE)
        assert same[_AD].last_rotated == _OLD
        assert (await store.get_secret_rotation_meta())[_AD].fingerprint == before
        changed = await _reconcile(store, _NEW_VALUE)
        assert changed[_AD].last_rotated == _TODAY
    finally:
        await store.close()


async def test_the_rotation_never_reseals_a_cell_moved_from_another_row(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The frozen v1 writer seals with no AAD, so only the class id inside the plaintext says whose
    cell it is. A cell moved from another row must not be re-sealed as this row's, which would make
    it AAD-valid here; it is left, and the next start keeps the dates."""
    path, a, b = tmp_path / "moved.db", generate_key(), generate_key()
    await _seed(path, a)
    moved = seal_rotation_fingerprint(
        _cipher(a, aad_bind=False), _SMTP, sr._fingerprint_cell(_SMTP, _VALUE)
    )
    await _plant(path, a, moved)
    caplog.set_level(logging.WARNING, logger="messagefoundry.store.crypto")
    await _rotate(path, a, b)
    assert await _stored(path, b) == moved
    assert "key rotation: 1 " in caplog.text
    stamps, _ = await _start(path, b, _NEW_VALUE)
    assert stamps[_AD].last_rotated == _OLD


async def test_a_held_value_with_a_lone_surrogate_is_fingerprinted(tmp_path: Path) -> None:
    """A POSIX environment value decoded with ``surrogateescape`` must not raise inside the
    reconcile, which the engine would swallow for every class."""
    path, key = tmp_path / "surrogate.db", generate_key()
    store = await MessageStore.open(path, cipher=_cipher(key))
    try:
        first = await _reconcile(store, "test-only-" + chr(0xDCFF) + "-value")
        assert _AD in first
        again = await _reconcile(store, "test-only-" + chr(0xDCFF) + "-value")
        assert again[_AD].last_rotated == first[_AD].last_rotated
    finally:
        await store.close()


def test_the_sql_server_column_holds_a_sealed_cell() -> None:
    """A sealed cell is longer than the NVARCHAR(255) the SQL Server table was created with, so the
    column is NVARCHAR(MAX) and an existing table is widened in place (BACKLOG #3472)."""
    from messagefoundry.store import sqlserver

    longest = max(
        len(seal_rotation_fingerprint(_cipher(generate_key()), c, sr._fingerprint_cell(c, _VALUE)))
        for c in ("X", _AD, "acme_partner_api_key_for_the_lab_feed")
    )
    assert longest > 255, "premise: the old width could not hold one"
    batch = [" ".join(str(stmt).split()) for stmt in sqlserver._SCHEMA]
    assert any(
        "CREATE TABLE secret_rotation_meta" in stmt and "fingerprint NVARCHAR(MAX) NOT NULL" in stmt
        for stmt in batch
    )
    assert any(
        "COL_LENGTH('secret_rotation_meta','fingerprint') <> -1" in stmt
        and "ALTER COLUMN fingerprint NVARCHAR(MAX) NOT NULL" in stmt
        for stmt in batch
    )


async def test_a_store_key_rotation_does_not_lift_an_opted_in_overdue_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through Engine.start, holding only the new key: an AD password last rotated in
    2020 still refuses the start after the store key is rotated and nothing else changed."""
    path, a, b = tmp_path / "engine.db", generate_key(), generate_key()
    await _seed(path, a)
    await _rotate(path, a, b)
    monkeypatch.setenv(_AD, _VALUE)
    store = await MessageStore.open(path, cipher=_cipher(b))
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


async def test_a_secret_rotated_with_the_store_key_clears_the_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half: rotating the overdue secret together with the store key lets the start
    through, with no retired key held. Before #3472 that start kept 2020 and refused."""
    path, a, b = tmp_path / "cleared.db", generate_key(), generate_key()
    await _seed(path, a)
    await _rotate(path, a, b)
    monkeypatch.setenv(_AD, _NEW_VALUE)
    store = await MessageStore.open(path, cipher=_cipher(b))
    engine = Engine(
        store,
        secret_rotation_settings=SecretRotationSettings(enforce_secret_expiry_classes=[_AD]),
        security_enforcement=SecurityEnforcement.ENFORCE,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
    finally:
        await engine.stop()
    assert (await _stored(path, b)).startswith(f"{ROTATION_FP_SEALED_SCHEME}:")


# --- AC-3: an unreadable fingerprint ----------------------------------------------------------------


def _legacy_rows() -> dict[str, str]:
    return {
        "a pre-#3472 keyed MAC": f"{sr._FP_SCHEME}:0123456789abcdef:{'a' * 32}",
        "an untagged pre-#3421 MAC": "b" * 32,
    }


def _unreadable_rows(key: str, stray: str) -> dict[str, str]:
    tag = f"{ROTATION_FP_SEALED_SCHEME}:"
    return {
        "an unknown scheme": "zz-scheme:abcdef",
        "a blank": "",
        "a cell under a key nobody supplied": seal_rotation_fingerprint(
            _cipher(stray), _AD, sr._fingerprint_cell(_AD, _VALUE)
        ),
        "another row's cell": seal_rotation_fingerprint(
            _cipher(key), _SMTP, sr._fingerprint_cell(_SMTP, _VALUE)
        ),
        "another row's cell, moved under the frozen writer": seal_rotation_fingerprint(
            _cipher(key, aad_bind=False), _SMTP, sr._fingerprint_cell(_SMTP, _VALUE)
        ),
        "an empty tag": ":abcdef",
        "a corrupt cell": f"{tag}mfenc:v4:not-a-real-cell",
        "a sealed tag over plaintext": f"{tag}{'c' * 64}:{'d' * 32}:{_AD}",
        "a cell with a malformed plaintext": seal_rotation_fingerprint(
            _cipher(key), _AD, "not-hex:" + "e" * 32 + f":{_AD}"
        ),
    }


_UNREADABLE_CASES = (
    "an unknown scheme",
    "a blank",
    "a cell under a key nobody supplied",
    "another row's cell",
    "another row's cell, moved under the frozen writer",
    "an empty tag",
    "a corrupt cell",
    "a sealed tag over plaintext",
    "a cell with a malformed plaintext",
)


def test_the_case_list_names_every_unreadable_row() -> None:
    assert set(_UNREADABLE_CASES) == set(_unreadable_rows(generate_key(), generate_key()))


@pytest.mark.parametrize("case", [*_legacy_rows(), *_UNREADABLE_CASES])
@pytest.mark.parametrize("value", [_VALUE, _NEW_VALUE])
async def test_an_unreadable_fingerprint_never_resets_a_clock(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, case: str, value: str
) -> None:
    """Whatever cannot be read keeps its dates, whether or not the secret changed, and is replaced
    by a sealed cell, so the NEXT change is detected. Keeping a date can only over-report an age."""
    path, key, stray = tmp_path / "unreadable.db", generate_key(), generate_key()
    rows = {**_legacy_rows(), **_unreadable_rows(key, stray)}
    await _plant(path, key, rows[case])
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        stamps, stored = await _start(path, key, value)
    assert stamps[_AD].last_rotated == _OLD
    assert stamps[_AD].tracked_since == _OLD
    assert open_rotation_fingerprint(_cipher(key), _AD, stored) is not None
    kind = "earlier release" if case in _legacy_rows() else "could not be read"
    warned = [r for r in caplog.records if kind in r.getMessage()]
    assert len(warned) == 1 and warned[0].getMessage().startswith("secret rotation: 1 ")
    # The count only: neither the class id (it names the secret) nor the value reaches the log.
    assert _AD not in caplog.text
    assert value not in caplog.text
    # Detection is restored from here on.
    changed, _ = await _start(path, key, "test-only-third-value")
    assert changed[_AD].last_rotated == _TODAY


async def test_a_malformed_stored_date_on_an_unreadable_row_falls_back_to_tracked_since(
    tmp_path: Path,
) -> None:
    """The row is writable out of band. A date that does not parse must not fail the reconcile, and
    must not reset the clock to today either: that would lift an overdue refusal."""
    path, key = tmp_path / "malformed.db", generate_key()
    await _plant(path, key, f"{sr._FP_SCHEME}:0123456789abcdef:{'a' * 32}", last_rotated="nope")
    stamps, _ = await _start(path, key, _VALUE)
    assert stamps[_AD].last_rotated == _OLD


# --- AC-4: the stored form -------------------------------------------------------------------------


async def test_the_fingerprint_is_stored_sealed(tmp_path: Path) -> None:
    path, key = tmp_path / "sealed.db", generate_key()
    await _seed(path, key)
    stored = await _stored(path, key)
    tag, _, inner = stored.partition(":")
    assert tag == ROTATION_FP_SEALED_SCHEME
    assert _cipher(key).is_encrypted(inner)
    cell = open_rotation_fingerprint(_cipher(key), _AD, stored)
    assert cell is not None
    key_hex, mac, bound = cell.split(":")
    assert bound == _AD
    assert len(bytes.fromhex(key_hex)) == 32
    # No bare MAC of the value is stored, and the per-row key makes two cells of one value differ.
    assert mac not in stored
    assert sr._fingerprint_cell(_AD, _VALUE) != sr._fingerprint_cell(_AD, _VALUE)
    assert sr._cell_unchanged(cell, _AD, _VALUE) is True
    assert sr._cell_unchanged(cell, _AD, _NEW_VALUE) is False
    assert sr._cell_unchanged(cell, _SMTP, _VALUE) is None


def test_the_cell_compare_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """ASVS 11.2.4 (BACKLOG #1167): the MAC is compared through ``hmac.compare_digest``."""
    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def counting(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", counting)
    cell = sr._fingerprint_cell(_AD, _VALUE)
    assert sr._cell_unchanged(cell, _AD, _NEW_VALUE) is False
    assert len(calls) == 1 and all(isinstance(x, bytes) for x in calls[0])


# --- AC-5: which ciphers fingerprint ----------------------------------------------------------------


async def test_only_the_in_process_cipher_fingerprints(tmp_path: Path) -> None:
    """``vault_transit`` stays off (vault BACKLOG #3473) and a keyless store has nothing to seal
    under; only the in-process AES-GCM cipher seals fingerprint cells."""
    assert rotation_fingerprint_cipher(_cipher(generate_key())) is not None
    assert rotation_fingerprint_cipher(make_cipher(None)) is None
    transit = object.__new__(TransitCipher)  # no Vault client: a type check needs none
    assert rotation_fingerprint_cipher(transit) is None

    keyless = await MessageStore.open(tmp_path / "keyless.db")
    try:
        assert keyless.secret_rotation_cipher() is None
        stamps = await _reconcile(keyless, _VALUE)
        assert _AD not in stamps
        assert _AD not in await keyless.get_secret_rotation_meta()
    finally:
        await keyless.close()


# --- every backend re-seals -------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["store.py", "sqlserver.py", "postgres.py"])
def test_every_backend_rotation_reseals_the_fingerprints(backend: str) -> None:
    """Each backend's ``reencrypt_to_active`` calls its fingerprint re-seal pass, and that pass goes
    through the one shared ``reseal_rotation_fingerprints``. The server legs open keyless by default,
    so this static check is what covers SQL Server and Postgres on the plain leg; the live round trip
    is in ``tests/test_secret_rotation_meta_server_backends.py``."""
    src = (Path(__file__).resolve().parent.parent / "messagefoundry" / "store" / backend).read_text(
        encoding="utf-8"
    )
    funcs = {
        n.name: n
        for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef)
    }

    def calls(fn: str) -> set[str]:
        return {
            c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", "")
            for c in ast.walk(funcs[fn])
            if isinstance(c, ast.Call)
        }

    assert "_reseal_rotation_fingerprints_to_active" in calls("reencrypt_to_active")
    assert "reseal_rotation_fingerprints" in calls("_reseal_rotation_fingerprints_to_active")
