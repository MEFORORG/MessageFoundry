# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the known sign-in address record (vault BACKLOG #2145).

NOT a test module (the leading underscore keeps pytest from collecting it). The SQLite suite
(``tests/test_auth_store.py``) and both live server suites call it, so the SQL Server ``MERGE`` and
the Postgres ``ON CONFLICT`` bodies run the same assertions as SQLite. Extra-free, on the
``_webauthn_store_contract`` precedent: it uses only ``AuthStore`` methods.
"""

from __future__ import annotations

from typing import Any


async def _account(store: Any, user_id: str, username: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=username,
        auth_provider="local",
        password_hash="h",
        now=100.0,
        password_generated=False,
    )


async def _assert_login_address_contract(store: Any) -> None:
    """Upsert, the lookback read, the per-account prune, byte-exact keys, and account deletion."""
    await _account(store, "ka-u1", "ka-alice")
    await _account(store, "ka-u2", "ka-bob")

    assert await store.list_known_login_addresses("ka-u1", since=0.0) == []

    await store.remember_login_address("ka-u1", "192.0.2.1", now=1000.0, forget_before=0.0)
    await store.remember_login_address("ka-u2", "192.0.2.1", now=1000.0, forget_before=0.0)
    assert await store.list_known_login_addresses("ka-u1", since=0.0) == ["192.0.2.1"]

    # The read honours the lookback: a row last seen before ``since`` is not returned.
    assert await store.list_known_login_addresses("ka-u1", since=1000.0) == ["192.0.2.1"]
    assert await store.list_known_login_addresses("ka-u1", since=1000.5) == []

    # A second write of the same key is an upsert that moves ``last_seen``, never a second row or a
    # key collision.
    await store.remember_login_address("ka-u1", "192.0.2.1", now=2000.0, forget_before=0.0)
    assert await store.list_known_login_addresses("ka-u1", since=1500.0) == ["192.0.2.1"]
    # ``last_seen`` never moves back: a late write carrying an older clock (another engine shard,
    # or a delayed write) must not age a still-used address out of the lookback early.
    await store.remember_login_address("ka-u1", "192.0.2.1", now=1200.0, forget_before=0.0)
    assert await store.list_known_login_addresses("ka-u1", since=1500.0) == ["192.0.2.1"]

    # Keys compare byte for byte on every backend, so case is significant. The service writes only
    # canonical host keys; this pins that the store does not fold them a second way.
    await store.remember_login_address("ka-u1", "Host-A", now=2000.0, forget_before=0.0)
    await store.remember_login_address("ka-u1", "host-a", now=2000.0, forget_before=0.0)
    assert sorted(await store.list_known_login_addresses("ka-u1", since=0.0)) == [
        "192.0.2.1",
        "Host-A",
        "host-a",
    ]

    # The prune deletes only THIS account's rows older than ``forget_before``.
    await store.remember_login_address("ka-u1", "198.51.100.9", now=5000.0, forget_before=3000.0)
    assert await store.list_known_login_addresses("ka-u1", since=0.0) == ["198.51.100.9"]
    assert await store.list_known_login_addresses("ka-u2", since=0.0) == ["192.0.2.1"]

    # A write whose own ``now`` is older than ``forget_before`` keeps nothing for that account.
    await store.remember_login_address("ka-u2", "203.0.113.4", now=6000.0, forget_before=7000.0)
    assert await store.list_known_login_addresses("ka-u2", since=0.0) == []

    # Deleting the account deletes its rows; a re-created namesake under a new id inherits none.
    await store.delete_user("ka-u1")
    assert await store.list_known_login_addresses("ka-u1", since=0.0) == []
    await _account(store, "ka-u3", "ka-alice")
    assert await store.list_known_login_addresses("ka-u3", since=0.0) == []
