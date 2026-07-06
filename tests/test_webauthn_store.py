# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SQLite leg of the WebAuthn credential store contract (+ TOTP backfill) — ADR 0068 §4.

Extra-free by design (no ``webauthn`` import anywhere on this path): the shared contract lives in
``tests/_webauthn_store_contract.py`` and is imported *inside* the test functions, exactly as the
live Postgres/SQL Server suites do — so all three backends run the identical parity assertions.
The ceremony/verify tests (which DO need the ``[webauthn]`` extra) live in ``tests/test_webauthn.py``.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.store.store import MessageStore


async def test_webauthn_store_contract_sqlite(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "wa.db")
    try:
        from tests._webauthn_store_contract import _assert_webauthn_store_contract

        await _assert_webauthn_store_contract(store)
    finally:
        await store.close()


async def test_totp_store_contract_sqlite(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "totp.db")
    try:
        from tests._webauthn_store_contract import _assert_totp_contract

        await _assert_totp_contract(store)
    finally:
        await store.close()


async def test_webauthn_table_created_on_reopen(tmp_path: Path) -> None:
    """A pre-L5 database gains the webauthn_credentials table on open (CREATE IF NOT EXISTS is
    the whole migration for a NEW table — fresh DDL and upgrade are the same statement)."""
    db = tmp_path / "pre-l5.db"
    store = await MessageStore.open(db)
    # White-box: drop the table to simulate a database created before this release.
    await store._db.execute("DROP TABLE webauthn_credentials")  # noqa: SLF001
    await store._db.commit()  # noqa: SLF001
    await store.close()

    reopened = await MessageStore.open(db)
    try:
        assert await reopened.has_webauthn_credentials("nobody") is False  # table exists again
    finally:
        await reopened.close()


async def test_webauthn_public_key_plaintext_under_cipher(tmp_path: Path) -> None:
    """The deliberate ADR 0068 §4 posture: with the store cipher ACTIVE, COSE public keys are
    still stored plaintext (verification material, not a secret — excluded from cipher + rekey).
    Guards against a well-meaning future change silently cipher-wrapping the column and breaking
    the rekey-loop exclusion assumption."""
    from messagefoundry.store.crypto import generate_key, make_cipher

    from tests._webauthn_store_contract import _cred

    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        await store.create_user(
            user_id="u1", username="alice", auth_provider="local", password_hash="h", now=1.0
        )
        await store.add_webauthn_credential(_cred("u1", "key", id_hash="h1", created_at=2.0))
        async with store._read() as conn:  # noqa: SLF001 - white-box: raw column, no decrypt
            cur = await conn.execute(
                "SELECT public_key FROM webauthn_credentials WHERE credential_id_hash='h1'"
            )
            row = await cur.fetchone()
        assert row["public_key"] == "cose-public-key-b64url"  # raw at rest, no mfenc: envelope
        # The cipher-covered column next door IS encrypted (the contrast pin).
        await store.set_totp_secret("u1", secret="JBSWY3DPEHPK3PXP", now=3.0)
        async with store._read() as conn:  # noqa: SLF001
            cur = await conn.execute("SELECT totp_secret FROM users WHERE id='u1'")
            row = await cur.fetchone()
        assert row["totp_secret"] != "JBSWY3DPEHPK3PXP"  # encrypted at rest
    finally:
        await store.close()
