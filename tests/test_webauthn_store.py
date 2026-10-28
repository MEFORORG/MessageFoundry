# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQLite leg of the WebAuthn credential store contract (+ TOTP backfill) — ADR 0068 §4.

Extra-free by design (no ``webauthn`` import anywhere on this path): the shared contract lives in
``tests/_webauthn_store_contract.py`` and is imported *inside* the test functions, exactly as the
live Postgres/SQL Server suites do — so all three backends run the identical parity assertions.
The ceremony/verify tests (which DO need the ``[webauthn]`` extra) live in ``tests/test_webauthn.py``.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, cast

from messagefoundry.store.store import MessageStore, session_owes_unproven_factor


async def test_webauthn_store_contract_sqlite(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "wa.db")
    try:
        from tests._webauthn_store_contract import _assert_webauthn_store_contract

        await _assert_webauthn_store_contract(store)
    finally:
        await store.close()


async def test_webauthn_rehash_contract_sqlite(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "rehash.db")
    try:
        from tests._webauthn_store_contract import _assert_webauthn_rehash_contract

        await _assert_webauthn_rehash_contract(store)
    finally:
        await store.close()


async def test_webauthn_conditional_bind_contract_sqlite(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "bind.db")
    try:
        from tests._webauthn_store_contract import _assert_webauthn_conditional_bind_contract

        await _assert_webauthn_conditional_bind_contract(store)
    finally:
        await store.close()


class _Sealer:
    """A stand-in row sealer whose session and user verdicts the test sets."""

    def __init__(self, *, session_ok: bool, user_ok: bool) -> None:
        self.session_ok, self.user_ok = session_ok, user_ok

    def verify(self, kind: str, fields: object, seal: str) -> bool:
        return self.session_ok

    def verify_held(self, kind: str, fields: object, seal: str) -> bool:
        return self.user_ok


async def test_the_conditional_bind_predicate_fails_closed_on_seals_and_epochs(
    tmp_path: Path,
) -> None:
    """BACKLOG #3014, #3690 item 1: the branches a keyless contract store cannot reach. RED when
    ``session_owes_unproven_factor`` trusts a session or account row whose seal fails, or a
    session minted under an older account epoch, which ``identity_for_token`` ends."""
    store = await MessageStore.open(tmp_path / "pred.db")
    try:
        await store.create_user(
            user_id="p1", username="p1", auth_provider="local", now=1.0, password_generated=False
        )
        assert await store.create_session(token_hash="ps", user_id="p1", expires_at=1e10, now=1.0)
        await store.mark_session_mfa_verified("ps", now=2.0)
        session = await store.get_session("ps")
        record = await store._read_user_record("p1")
        assert session is not None and record is not None
        sound = cast(Any, _Sealer(session_ok=True, user_ok=True))
        # The control: a stamped, sealed, current session owes nothing.
        assert session_owes_unproven_factor(sound, session, record, []) is False
        bad_session = cast(Any, _Sealer(session_ok=False, user_ok=True))
        assert session_owes_unproven_factor(bad_session, session, record, []) is True
        bad_user = cast(Any, _Sealer(session_ok=True, user_ok=False))
        assert session_owes_unproven_factor(bad_user, session, record, []) is True
        stale = dataclasses.replace(session, user_epoch=record.row.session_epoch + 1)
        assert session_owes_unproven_factor(sound, stale, record, []) is True
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
            user_id="u1",
            username="alice",
            auth_provider="local",
            password_hash="h",
            now=1.0,
            password_generated=False,
        )
        await store.add_webauthn_credential(_cred("u1", "key", id_hash="h1", created_at=2.0))
        async with store._read() as conn:  # noqa: SLF001 - white-box: raw column, no decrypt
            cur = await conn.execute(
                "SELECT public_key FROM webauthn_credentials WHERE credential_id_hash='h1'"
            )
            row = await cur.fetchone()
        assert row is not None
        assert row["public_key"] == "cose-public-key-b64url"  # raw at rest, no mfenc: envelope
        # The cipher-covered column next door IS encrypted (the contrast pin).
        await store.set_totp_secret("u1", secret="JBSWY3DPEHPK3PXP", now=3.0)
        async with store._read() as conn:  # noqa: SLF001
            cur = await conn.execute("SELECT totp_secret FROM users WHERE id='u1'")
            row = await cur.fetchone()
        assert row is not None
        assert row["totp_secret"] != "JBSWY3DPEHPK3PXP"  # encrypted at rest
    finally:
        await store.close()


async def test_session_rotation_contract_sqlite(tmp_path: Path) -> None:
    """SQLite leg of the ASVS 7.2.4 rotate_session contract — same shared assertions the live
    Postgres / SQL Server suites run, so a backend that drifts is caught on whichever leg runs."""
    store = await MessageStore.open(tmp_path / "rot.db")
    try:
        from tests._session_rotation_contract import assert_session_rotation_contract

        await assert_session_rotation_contract(store)
    finally:
        await store.close()


async def test_session_supersession_contract_sqlite(tmp_path: Path) -> None:
    """SQLite leg of the BACKLOG #2146 supersede_session contract, shared with the live Postgres /
    SQL Server suites."""
    store = await MessageStore.open(tmp_path / "sup.db")
    try:
        from tests._session_rotation_contract import assert_session_supersession_contract

        await assert_session_supersession_contract(store)
    finally:
        await store.close()


async def test_session_lineage_contract_sqlite(tmp_path: Path) -> None:
    """SQLite leg of the vault BACKLOG #3028 session lineage contract, shared with the live Postgres
    / SQL Server suites."""
    store = await MessageStore.open(tmp_path / "lin.db")
    try:
        from tests._session_rotation_contract import assert_session_lineage_contract

        await assert_session_lineage_contract(store)
    finally:
        await store.close()
