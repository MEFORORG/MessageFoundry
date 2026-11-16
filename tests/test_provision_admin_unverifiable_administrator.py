# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``provision-admin`` refuses, before any account write, while an account's record reads
Unverifiable under the Transit row sealer (ADR 0217 (a), engine PR 2860 hold, finding R3-F1).

The account scans drop an Unverifiable record, so the self-sufficient-Administrator refusal could
not see an Administrator whose seal Vault transit could not verify. The command then cleared the
earlier holder's factors and sessions and wrote its own credential before the first-administrator
grant's guard raised on that same row. An Unverifiable record's roles are part of what its seal
covers, so any one of them may be an Administrator: the command now refuses on one and changes no
account (its scan may write ``integrity.authority_seal_unverifiable`` audit rows, as the
seal-failure throttle allows). Synthetic data only; severity is conditional (CLAUDE.md section 0).
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_UNVERIFIABLE_ACTION,
    AuthService,
    FirstAdministratorRefused,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import TransitRowSealer
from messagefoundry.store.store import MessageStore, WebAuthnCredential
from tests._admin_account import create_admin, provision_totp
from tests._transit_seal_fake import FakeBackend, with_version

_PASSWORD = "a-long-enough-operator-passphrase"
_EMAIL = "operator@example.invalid"
_HOLDER = "roleless"
_HOLDER_PASSWORD = "the-earlier-holders-passphrase"


def _plant(path: Path, user_id: str) -> None:
    """Name version 5 in the account's stored seal, which the stand-in does not hold: Transit
    answers 400 while the probe works, so the record reads Unverifiable."""
    conn = sqlite3.connect(path)
    try:
        (seal,) = conn.execute("SELECT authz_seal FROM users WHERE id=?", (user_id,)).fetchone()
        conn.execute(
            "UPDATE users SET authz_seal=? WHERE id=?", (with_version(str(seal), "5"), user_id)
        )
        conn.commit()
    finally:
        conn.close()


def _holder_rows(path: Path) -> dict[str, list[tuple[object, ...]]]:
    """Every stored row of the earlier holder: its account row and each table keyed to it."""
    conn = sqlite3.connect(path)
    try:
        tables = [
            name
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        out: dict[str, list[tuple[object, ...]]] = {}
        for table in tables:
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
            key = "id" if table == "users" else "user_id" if "user_id" in columns else None
            if key is None:
                continue
            rows = conn.execute(
                f'SELECT * FROM "{table}" WHERE "{key}"=? ORDER BY 1', (_HOLDER,)
            ).fetchall()
            out[table] = sorted(rows, key=repr)
        return out
    finally:
        conn.close()


async def _earlier_holder(store: MessageStore, service: AuthService) -> str:
    """A roleless local account a repair could take over, holding a password, TOTP with recovery
    codes, a passkey and a live session. Returns the session token."""
    await store.create_user(
        user_id=_HOLDER,
        username="site-admin",
        auth_provider=AuthProvider.LOCAL.value,
        email="holder@example.invalid",
        password_hash=None,
        must_change_password=True,
        password_generated=False,
        audits=(),
    )
    await store.set_password(
        _HOLDER,
        password_hash=await asyncio.to_thread(hash_password, _HOLDER_PASSWORD),
        must_change_password=False,
        password_generated=False,
    )
    staged_cell = await store.set_totp_secret(_HOLDER, secret="JBSWY3DPEHPK3PXP")
    assert await store.enable_totp(
        _HOLDER, expected_secret_cell=staged_cell, recovery_code_hashes=["h1", "h2"]
    )
    await store.add_webauthn_credential(
        WebAuthnCredential(
            credential_id_hash="holder-passkey-hash",
            credential_id="holder-passkey-id",
            user_id=_HOLDER,
            rp_id="t",
            public_key="cose-public-key-b64url",
            sign_count=0,
            transports=None,
            device_type="multi_device",
            backed_up=True,
            label="theirs",
            aaguid=None,
            created_at=1.0,
        )
    )
    kept = await service.login("site-admin", _HOLDER_PASSWORD)
    assert kept.ok and kept.token is not None
    return kept.token


async def test_an_unverifiable_administrator_refuses_provision_before_any_write(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provision_unverifiable.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    store._row_sealer = TransitRowSealer(FakeBackend())
    try:
        holder = AuthService(store, AuthSettings(require_mfa=False))
        await holder.initialize()
        admin = await create_admin(holder)
        token = await _earlier_holder(store, holder)

        service = AuthService(store, AuthSettings())
        # Control: while the Administrator's record verifies, the pre-check refuses on it.
        control = await service.provision_refusal("site-admin", notify_email=_EMAIL)
        assert control is not None and "already has an enabled Administrator" in control

        _plant(path, admin.user_id)
        before = _holder_rows(path)
        assert before["users"] and before["sessions"] and before["webauthn_credentials"]

        async def provision() -> None:
            await service.provision_first_administrator(
                username="site-admin",
                password=_PASSWORD,
                notify_email=_EMAIL,
                actor="test",
                **provision_totp(),
            )

        # The command's path, as `_provision_admin` runs it: the pre-check before any prompt, and
        # the write only when the pre-check refuses nothing.
        refusal = await service.provision_refusal("site-admin", notify_email=_EMAIL)
        command_raised: BaseException | None = None
        if refusal is None:
            try:
                await provision()
            except Exception as exc:  # noqa: BLE001 -- recorded, then asserted below
                command_raised = exc
        assert _holder_rows(path) == before  # factors, sessions and credential byte-unchanged
        assert command_raised is None
        assert refusal is not None and "could not be verified by Vault transit" in refusal
        # The write refuses on its own too, whatever the pre-check said, and still changes no
        # account.
        with pytest.raises(FirstAdministratorRefused, match="could not be verified by Vault"):
            await provision()
        assert _holder_rows(path) == before
        assert await store.get_user_role_ids(_HOLDER) == []
        assert await service.identity_for_token(token, activity=False) is not None
        # The scan's report of the Unverifiable record still runs.
        rows = await store.list_audit(action=AUTHORITY_SEAL_UNVERIFIABLE_ACTION, limit=100)
        assert any(admin.user_id in str(row["detail"]) for row in rows)
        actions = [row["action"] for row in await store.list_audit(limit=500)]
        assert "auth.first_administrator_provisioned" not in actions
    finally:
        await store.close()
