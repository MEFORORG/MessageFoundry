# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 13.3.4 (BACKLOG #282) — the SecretRotationMetaStore protocol on the SERVER store backends.

The narrow ``SecretRotationMetaStore`` slice the rotation watcher persists through was implemented on the
SQLite :class:`MessageStore` only, so the engine's structural
``isinstance(store, SecretRotationMetaStore)`` gate (``pipeline/engine.py``) was False on the SQL
Server store and the reconcile no-op'd, degrading 13.3.4 to the pre-lane DEK-only reminder. This suite
pins the structural conformance of :class:`SqlServerStore` and :class:`PostgresStore` (runs locally, no
DB) and — behind the live-DB env gates — round-trips an upsert->get on each REAL backend (CI only).

NON-SECRET throughout: the fixtures carry only identifiers, ISO dates, and a synthetic keyed-MAC-shaped
fingerprint STRING, never a secret value (this is exactly what the persisted meta is)."""

from __future__ import annotations

import importlib
import os
import uuid
from typing import Any

import pytest

from messagefoundry.pipeline.secret_rotation import (
    ROTATION_RECORD_ID,
    close_rotation_record,
    dek_fingerprint,
    open_rotation_record,
)
from messagefoundry.store.crypto import (
    ROTATION_FP_SEALED_SCHEME,
    AesGcmCipher,
    generate_key,
    make_cipher,
    open_rotation_fingerprint,
    seal_rotation_fingerprint,
)
from messagefoundry.store.store import SecretRotationMetaRow, SecretRotationMetaStore

#: (module, class-name) for every shipped SERVER backend (SQLite is the reference and already conforms).
_SERVER_BACKENDS: list[tuple[str, str]] = [
    ("messagefoundry.store.sqlserver", "SqlServerStore"),
    ("messagefoundry.store.postgres", "PostgresStore"),
]

_ROT_MEMBERS = (
    "secret_rotation_cipher",
    "get_secret_rotation_meta",
    "upsert_secret_rotation_meta",
)


def _store_class(module: str, name: str) -> type[Any]:
    return getattr(importlib.import_module(module), name)


# --- structural conformance (no DB; runs locally) ---------------------------


@pytest.mark.parametrize(("module", "name"), _SERVER_BACKENDS)
def test_server_backend_satisfies_secret_rotation_meta_protocol(module: str, name: str) -> None:
    """The structural gate the engine relies on: a bare instance of each server backend must satisfy
    ``isinstance(store, SecretRotationMetaStore)`` so the 13.3.4 reconcile runs on SQL Server / Postgres,
    not just SQLite. ``runtime_checkable`` checks the three protocol members are present on the class —
    no DB / pool is needed to assert conformance."""
    cls = _store_class(module, name)
    store = object.__new__(cls)  # no __init__ / pool — structural check only
    assert isinstance(store, SecretRotationMetaStore), (
        f"{name} must implement SecretRotationMetaStore, or the engine's isinstance gate silently "
        "no-ops the 13.3.4 rotation reconcile on this backend"
    )
    for member in _ROT_MEMBERS:
        assert callable(getattr(cls, member, None)), f"{name}.{member} missing"


@pytest.mark.parametrize(("module", "name"), _SERVER_BACKENDS)
def test_secret_rotation_meta_table_in_schema_batch(module: str, name: str) -> None:
    """The table must join each backend's ADR-0064 schema batch, so ``_schema_hash`` changes and the
    table is actually CREATEd at open — otherwise the backend opens against a schema that lacks it and
    every get/upsert errors at runtime."""
    mod = importlib.import_module(module)
    batch = "\n".join(str(stmt) for stmt in mod._SCHEMA)
    assert "secret_rotation_meta" in batch, (
        f"{name}: secret_rotation_meta is missing from _SCHEMA; the table won't be created at open"
    )


# --- live-DB round-trip (CI only; skips locally per the SS/PG env gates) -----


def _aes(key: str) -> AesGcmCipher:
    cipher = make_cipher(key)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


async def _reseal_roundtrip(store: Any, retired_key: str) -> None:
    """BACKLOG #3472: the backend's rotation pass re-seals a fingerprint cell sealed under a retired
    key, so it opens under the active key with the same plaintext, and leaves one no key opens.
    Called directly, not through ``reencrypt_to_active``: the CI database is shared, and a full
    rotation would try to re-encrypt other tests' rows under keys this store does not hold."""
    sealed_key = f"TEST_3472_{uuid.uuid4().hex}"
    stray_key = f"TEST_3472_{uuid.uuid4().hex}"
    cell = f"{'ab' * 32}:{'cd' * 16}:{sealed_key}"  # synthetic cell shape -- NEVER a value
    old = seal_rotation_fingerprint(_aes(retired_key), sealed_key, cell)
    stray_cell = f"{'ab' * 32}:{'cd' * 16}:{stray_key}"
    stray = seal_rotation_fingerprint(_aes(generate_key()), stray_key, stray_cell)
    try:
        for key, fingerprint in ((sealed_key, old), (stray_key, stray)):
            await store.upsert_secret_rotation_meta(
                key, fingerprint=fingerprint, tracked_since="2026-06-15", last_rotated="2026-06-15"
            )
        cipher = store.cipher()
        active = cipher.active_marker_prefix
        await store._reseal_rotation_fingerprints_to_active(cipher, f"{active}%")
        got = await store.get_secret_rotation_meta()
        assert got[sealed_key].fingerprint.startswith(f"{ROTATION_FP_SEALED_SCHEME}:{active}")
        assert open_rotation_fingerprint(cipher, sealed_key, got[sealed_key].fingerprint) == cell
        assert got[stray_key].fingerprint == stray, "a cell no key opens is left in place"
    finally:
        # The CI database is shared across runs, so this test's two rows go with it.
        for key in (sealed_key, stray_key):
            if type(store).__name__ == "PostgresStore":
                await store._execute("DELETE FROM secret_rotation_meta WHERE secret_key = $1", key)
            else:
                await store._execute(
                    "DELETE FROM secret_rotation_meta WHERE secret_key = ?", (key,)
                )


async def _roundtrip(store: Any, retired_key: str) -> None:
    # The sealing cipher is the live in-process cipher when keyed, None when keyless (BACKLOG #3472).
    sealing = store.secret_rotation_cipher()
    assert sealing is None or sealing is store.cipher()
    if sealing is not None:
        await _reseal_roundtrip(store, retired_key)

    row = SecretRotationMetaRow(
        secret_key="MEFOR_STORE_ENCRYPTION_KEY",
        fingerprint="kmac:v1:" + "ab" * 16,  # synthetic keyed-MAC shape — NEVER a value
        tracked_since="2026-06-15",
        last_rotated="2026-06-15",
    )
    await store.upsert_secret_rotation_meta(
        row.secret_key,
        fingerprint=row.fingerprint,
        tracked_since=row.tracked_since,
        last_rotated=row.last_rotated,
    )
    got = await store.get_secret_rotation_meta()
    assert got[row.secret_key] == row

    # Auto-detected rotation: re-upsert the SAME key with a NEW fingerprint/date replaces IN PLACE (PK
    # idempotency), never a second row — so a re-run or a sibling node converges rather than duplicating.
    await store.upsert_secret_rotation_meta(
        row.secret_key,
        fingerprint="kmac:v1:" + "cd" * 16,
        tracked_since=row.tracked_since,
        last_rotated="2026-07-01",
    )
    got2 = await store.get_secret_rotation_meta()
    assert got2[row.secret_key].fingerprint == "kmac:v1:" + "cd" * 16
    assert got2[row.secret_key].tracked_since == row.tracked_since  # unchanged floor
    assert got2[row.secret_key].last_rotated == "2026-07-01"

    # BACKLOG #3737: the rotation record rides this same row shape on every backend, and its closed
    # state is a blank fingerprint, which each backend must store and return as a blank.
    try:
        await open_rotation_record(store, "ab" * 8, "2026-10-30")
        opened = (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID]
        assert opened.fingerprint == dek_fingerprint("ab" * 8)
        await close_rotation_record(store, "2026-10-31")
        closed = (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID]
        assert (closed.fingerprint, closed.last_rotated) == ("", "2026-10-31")
    finally:
        if type(store).__name__ == "PostgresStore":
            await store._execute(
                "DELETE FROM secret_rotation_meta WHERE secret_key = $1", ROTATION_RECORD_ID
            )
        else:
            await store._execute(
                "DELETE FROM secret_rotation_meta WHERE secret_key = ?", (ROTATION_RECORD_ID,)
            )


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)
async def test_sqlserver_secret_rotation_meta_roundtrip() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    retired = generate_key()
    store = await SqlServerStore.open(settings, cipher=make_cipher(generate_key(), (retired,)))
    try:
        await _roundtrip(store, retired)
    finally:
        await store.close()


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)
async def test_postgres_secret_rotation_meta_roundtrip() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    retired = generate_key()
    store = await PostgresStore.open(settings, cipher=make_cipher(generate_key(), (retired,)))
    try:
        await _roundtrip(store, retired)
    finally:
        await store.close()
