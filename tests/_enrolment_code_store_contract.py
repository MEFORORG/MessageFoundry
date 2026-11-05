# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for a directory account's enrolment code (ADR 0207).

Extra-free, as ``tests/_webauthn_store_contract.py`` is, so the live Postgres and SQL Server suites
import it inside their test functions. Every refusal has a control beside it: the same write on an
account that meets the condition goes through, so a write that refused everything fails here too.

AC-10's race, two spends of one code at once, is driven with ``asyncio.gather`` on each backend: on
SQLite the writer lock serializes them, on Postgres ``FOR UPDATE`` and on SQL Server ``UPDLOCK``
lock the row, and the seal compare is the second guard.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from messagefoundry.auth.tokens import hash_token
from messagefoundry.store.store import WebAuthnCredential

_N = 0


def _digest(text: str) -> str:
    return hash_token(text)


async def _directory_account(store: Any, name: str) -> str:
    global _N
    _N += 1
    user_id = f"code-{name}-{_N}-{time.time_ns()}"
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="ad",
        password_generated=False,
        audits=(),
    )
    return user_id


async def _local_account(store: Any, name: str) -> str:
    global _N
    _N += 1
    user_id = f"code-local-{name}-{_N}-{time.time_ns()}"
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        password_hash="not-a-real-hash",
        password_generated=False,
        audits=(),
    )
    return user_id


def _passkey(user_id: str) -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id_hash=f"h-{user_id}",
        credential_id="cred-id-b64url",
        user_id=user_id,
        rp_id="t",
        public_key="cose-public-key-b64url",
        sign_count=0,
        transports=None,
        device_type="multi_device",
        backed_up=True,
        label="key",
        aaguid="aaguid-0000",
        created_at=1000.0,
        last_used_at=None,
        discoverable=True,
    )


async def _code(store: Any, user_id: str) -> tuple[str | None, float | None, str | None]:
    user = await store.get_user(user_id)
    assert user is not None
    return (
        user.enrolment_code_digest,
        user.enrolment_code_expires_at,
        user.enrolment_code_issuer,
    )


async def assert_enrolment_code_store_contract(store: Any) -> None:
    """Drive the enrolment-code writes through their whole contract on ``store``'s backend."""
    now = time.time()
    later = now + 3600

    # --- issue: only an enabled directory account with no factor ------------------------------
    ad = await _directory_account(store, "issue")
    issued = await store.issue_enrolment_code(
        ad, code_digest=_digest("one"), expires_at=later, issuer_id="admin-1"
    )
    assert issued is not None and not issued.replaced
    assert await _code(store, ad) == (_digest("one"), later, "admin-1")
    # A second issue replaces the first, and says so.
    again = await store.issue_enrolment_code(
        ad, code_digest=_digest("two"), expires_at=later, issuer_id=None
    )
    assert again is not None and again.replaced
    assert await _code(store, ad) == (_digest("two"), later, None)

    local = await _local_account(store, "issue")
    assert (
        await store.issue_enrolment_code(
            local, code_digest=_digest("x"), expires_at=later, issuer_id=None
        )
        is None
    )
    assert await _code(store, local) == (None, None, None)
    assert (
        await store.issue_enrolment_code(
            "no-such-account", code_digest=_digest("x"), expires_at=later, issuer_id=None
        )
        is None
    )

    with_totp = await _directory_account(store, "totp")
    cell = await store.set_totp_secret(with_totp, secret="JBSWY3DPEHPK3PXP")
    assert await store.enable_totp(with_totp, recovery_code_hashes=[], expected_secret_cell=cell)
    assert (
        await store.issue_enrolment_code(
            with_totp, code_digest=_digest("x"), expires_at=later, issuer_id=None
        )
        is None
    )

    with_passkey = await _directory_account(store, "passkey")
    assert await store.add_webauthn_credential(_passkey(with_passkey))
    assert (
        await store.issue_enrolment_code(
            with_passkey, code_digest=_digest("x"), expires_at=later, issuer_id=None
        )
        is None
    )

    # --- a disable clears the code, and a disabled account takes none (AC-15) -----------------
    disabled = await _directory_account(store, "disabled")
    assert await store.issue_enrolment_code(
        disabled, code_digest=_digest("d"), expires_at=later, issuer_id="admin-1"
    )
    await store.set_user_disabled(disabled, disabled=True)
    assert await _code(store, disabled) == (None, None, None)
    assert (
        await store.issue_enrolment_code(
            disabled, code_digest=_digest("d"), expires_at=later, issuer_id=None
        )
        is None
    )
    await store.set_user_disabled(disabled, disabled=False)
    assert await _code(store, disabled) == (None, None, None)  # re-enabling revives nothing
    assert await store.spend_enrolment_code(disabled, code_digest=_digest("d")) is None, (
        "the old code must not spend after a re-enable"
    )

    # --- revoke ----------------------------------------------------------------------------------
    revoked = await _directory_account(store, "revoke")
    assert not await store.revoke_enrolment_code(revoked)  # nothing to revoke
    assert await store.issue_enrolment_code(
        revoked, code_digest=_digest("r"), expires_at=later, issuer_id="admin-1"
    )
    assert await store.revoke_enrolment_code(revoked)
    assert await _code(store, revoked) == (None, None, None)
    assert await store.spend_enrolment_code(revoked, code_digest=_digest("r")) is None

    # --- spend: only the matching, unexpired code, once ------------------------------------------
    spend = await _directory_account(store, "spend")
    assert await store.issue_enrolment_code(
        spend, code_digest=_digest("s"), expires_at=later, issuer_id="admin-9"
    )
    assert await store.spend_enrolment_code(spend, code_digest=_digest("wrong")) is None
    assert await _code(store, spend) == (
        _digest("s"),
        later,
        "admin-9",
    )  # a wrong code costs nothing
    spent = await store.spend_enrolment_code(spend, code_digest=_digest("s"))
    assert spent is not None and spent.issuer_id == "admin-9"
    assert await _code(store, spend) == (None, None, None)
    assert await store.spend_enrolment_code(spend, code_digest=_digest("s")) is None  # single use

    expired = await _directory_account(store, "expired")
    assert await store.issue_enrolment_code(
        expired, code_digest=_digest("e"), expires_at=now - 1, issuer_id=None
    )
    assert await store.spend_enrolment_code(expired, code_digest=_digest("e")) is None
    # Control: the same code with a live expiry spends.
    assert await store.issue_enrolment_code(
        expired, code_digest=_digest("e"), expires_at=later, issuer_id=None
    )
    assert await store.spend_enrolment_code(expired, code_digest=_digest("e")) is not None

    # A factor bound after the issue, by a path that asks no code, blocks the spend (AC-19).
    gained = await _directory_account(store, "gained")
    assert await store.issue_enrolment_code(
        gained, code_digest=_digest("g"), expires_at=later, issuer_id=None
    )
    assert await store.add_webauthn_credential(_passkey(gained))
    assert await store.spend_enrolment_code(gained, code_digest=_digest("g")) is None
    assert (await _code(store, gained))[0] == _digest("g")  # the code stays unspent

    # --- the TOTP fold: enable and spend in one write, or neither -------------------------------
    fold = await _directory_account(store, "fold")
    fold_cell = await store.set_totp_secret(fold, secret="JBSWY3DPEHPK3PXP")
    assert await store.issue_enrolment_code(
        fold, code_digest=_digest("f"), expires_at=later, issuer_id="admin-3"
    )
    # A stale secret cell matches no row and spends nothing.
    assert (
        await store.enable_totp_spending_enrolment_code(
            fold,
            recovery_code_hashes=["h"],
            expected_secret_cell="not-the-cell",
            code_digest=_digest("f"),
        )
        is None
    )
    assert (await _code(store, fold))[0] == _digest("f")
    # A wrong code enables nothing.
    assert (
        await store.enable_totp_spending_enrolment_code(
            fold,
            recovery_code_hashes=["h"],
            expected_secret_cell=fold_cell,
            code_digest=_digest("wrong"),
        )
        is None
    )
    user = await store.get_user(fold)
    assert user is not None and not user.totp_enabled
    folded = await store.enable_totp_spending_enrolment_code(
        fold, recovery_code_hashes=["h"], expected_secret_cell=fold_cell, code_digest=_digest("f")
    )
    assert folded is not None and folded.issuer_id == "admin-3"
    user = await store.get_user(fold)
    assert user is not None and user.totp_enabled
    assert await _code(store, fold) == (None, None, None)

    # A passkey bound before the fold leaves TOTP off and the code unspent (AC-19).
    fold_pk = await _directory_account(store, "fold-pk")
    fold_pk_cell = await store.set_totp_secret(fold_pk, secret="JBSWY3DPEHPK3PXP")
    assert await store.issue_enrolment_code(
        fold_pk, code_digest=_digest("p"), expires_at=later, issuer_id=None
    )
    assert await store.add_webauthn_credential(_passkey(fold_pk))
    assert (
        await store.enable_totp_spending_enrolment_code(
            fold_pk,
            recovery_code_hashes=["h"],
            expected_secret_cell=fold_pk_cell,
            code_digest=_digest("p"),
        )
        is None
    )
    user = await store.get_user(fold_pk)
    assert user is not None and not user.totp_enabled
    assert (await _code(store, fold_pk))[0] == _digest("p")

    # --- AC-10: two spends of one code at once, exactly one wins ------------------------------
    race = await _directory_account(store, "race")
    race_cell = await store.set_totp_secret(race, secret="JBSWY3DPEHPK3PXP")
    assert await store.issue_enrolment_code(
        race, code_digest=_digest("race"), expires_at=later, issuer_id=None
    )
    results = await asyncio.gather(
        store.spend_enrolment_code(race, code_digest=_digest("race")),
        store.enable_totp_spending_enrolment_code(
            race,
            recovery_code_hashes=["h"],
            expected_secret_cell=race_cell,
            code_digest=_digest("race"),
        ),
        store.spend_enrolment_code(race, code_digest=_digest("race")),
    )
    assert sum(r is not None for r in results) == 1, results
    assert await _code(store, race) == (None, None, None)
