# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from typing import Any

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import SecretRotationMetaRow, SecretRotationMetaStore

#: (module, class-name) for every shipped SERVER backend (SQLite is the reference and already conforms).
_SERVER_BACKENDS: list[tuple[str, str]] = [
    ("messagefoundry.store.sqlserver", "SqlServerStore"),
    ("messagefoundry.store.postgres", "PostgresStore"),
]

_ROT_MEMBERS = (
    "secret_rotation_fingerprint_key",
    "get_secret_rotation_meta",
    "upsert_secret_rotation_meta",
)


def _store_class(module: str, name: str) -> type[Any]:
    return getattr(importlib.import_module(module), name)  # type: ignore[no-any-return]


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


async def _roundtrip(store: Any) -> None:
    # The fingerprint-key derivation is wired to the live cipher (bytes when keyed, None when keyless).
    fp = store.secret_rotation_fingerprint_key()
    assert fp is None or isinstance(fp, bytes)

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


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)
async def test_sqlserver_secret_rotation_meta_roundtrip() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    store = await SqlServerStore.open(settings, cipher=make_cipher(generate_key()))
    try:
        await _roundtrip(store)
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
    store = await PostgresStore.open(settings, cipher=make_cipher(generate_key()))
    try:
        await _roundtrip(store)
    finally:
        await store.close()
