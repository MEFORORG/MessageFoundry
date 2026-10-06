# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contracts for the WebAuthn credential surface (+ the TOTP backfill).

Deliberately **extra-free** (ADR 0068 §4 / decision 4): this module imports NOTHING from the
optional ``webauthn`` extra — it exercises only ``AuthStore`` methods and the
``WebAuthnCredential`` record — so the live Postgres/SQL Server suites can import it *inside their
test functions* and run the parity contract on CI legs that install ``.[dev,postgres]`` /
``.[dev,sqlserver]`` **without** the webauthn extra. (A module-level
``pytest.importorskip("webauthn")`` anywhere on this path would silently skip parity on exactly
the two legs it exists to cover.)

``_assert_totp_contract`` backfills the gap the recon found: the TOTP store methods shipped with
SQLite-only service-level coverage, so the Postgres ``FOR UPDATE`` / SQL Server ``UPDLOCK`` paths
had never executed under test. It lands in the same commit as the WebAuthn contract, and both are
invoked from the SQLite suite (``tests/test_webauthn_store.py``) and both live suites.
"""

from __future__ import annotations

import secrets
from typing import Any

from messagefoundry.store.store import WebAuthnCredential

#: A base64url credential id at WebAuthn's maximum raw size (1023 bytes -> ~1364 chars) — the
#: round-trip that motivated the digest PK (unboundable as a SQL Server index key otherwise).
_MAX_RAW_ID_BYTES = 1023


def _cred(
    user_id: str,
    label: str,
    *,
    id_hash: str,
    credential_id: str = "cred-id-b64url",
    sign_count: int = 0,
    rp_id: str = "t",
    transports: list[str] | None = None,
    created_at: float = 1000.0,
) -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id_hash=id_hash,
        credential_id=credential_id,
        user_id=user_id,
        rp_id=rp_id,
        public_key="cose-public-key-b64url",  # plaintext by design — verification material
        sign_count=sign_count,
        transports=transports,
        device_type="multi_device",
        backed_up=True,
        label=label,
        aaguid="aaguid-0000",
        created_at=created_at,
        last_used_at=None,
    )


async def _assert_webauthn_store_contract(store: Any) -> None:
    """The webauthn_credentials contract every backend must satisfy (ADR 0068 §4)."""
    await store.create_user(
        user_id="wa-u1",
        username="wa-alice",
        auth_provider="local",
        password_hash="h",
        now=100.0,
        password_generated=False,
    )
    await store.create_user(
        user_id="wa-u2",
        username="wa-bob",
        auth_provider="local",
        password_hash="h",
        now=100.0,
        password_generated=False,
    )

    # Multi-row round-trip: fields survive intact (transports JSON, backed_up bool, aaguid, rp_id).
    assert await store.has_webauthn_credentials("wa-u1") is False
    assert await store.any_webauthn_credentials() is False  # L5b advisory probe: clean store
    c1 = _cred(
        "wa-u1", "yubikey", id_hash="h1", transports=["usb", "nfc"], sign_count=5, created_at=10.0
    )
    c2 = _cred("wa-u1", "phone", id_hash="h2", transports=None, sign_count=0, created_at=20.0)
    await store.add_webauthn_credential(c1)
    await store.add_webauthn_credential(c2)
    assert await store.has_webauthn_credentials("wa-u1") is True
    assert await store.any_webauthn_credentials() is True
    listed = await store.list_webauthn_credentials("wa-u1")
    assert [c.credential_id_hash for c in listed] == ["h1", "h2"]  # oldest first
    got = await store.get_webauthn_credential("h1")
    assert got is not None
    assert got.user_id == "wa-u1" and got.label == "yubikey" and got.rp_id == "t"
    assert got.transports == ["usb", "nfc"] and got.backed_up is True
    assert got.sign_count == 5 and got.aaguid == "aaguid-0000" and got.last_used_at is None
    assert (await store.get_webauthn_credential("h2")).transports is None
    assert await store.get_webauthn_credential("missing") is None

    # Max-length credential id (1023 raw bytes as base64url) rides the unbounded body column.
    import base64

    big_id = base64.urlsafe_b64encode(secrets.token_bytes(_MAX_RAW_ID_BYTES)).rstrip(b"=").decode()
    await store.add_webauthn_credential(
        _cred("wa-u2", "big", id_hash="h-big", credential_id=big_id, created_at=30.0)
    )
    assert (await store.get_webauthn_credential("h-big")).credential_id == big_id

    # Duplicate (user_id, label) violates ux_webauthn_label with the backend's native integrity
    # error (sqlite3.IntegrityError / asyncpg UniqueViolationError / pyodbc.IntegrityError) — the
    # service catches it and renders "label already in use". Same label on ANOTHER user is fine.
    await store.add_webauthn_credential(_cred("wa-u2", "yubikey", id_hash="h3", created_at=40.0))
    try:
        await store.add_webauthn_credential(
            _cred("wa-u1", "yubikey", id_hash="h-dup", created_at=50.0)
        )
    except Exception as exc:  # noqa: BLE001 - each backend raises its own integrity class
        name = type(exc).__name__ + "".join(t.__name__ for t in type(exc).__mro__)
        assert "Integrity" in name or "UniqueViolation" in name, (
            f"duplicate label raised {type(exc).__name__}, not an integrity violation"
        )
    else:
        raise AssertionError("duplicate (user_id, label) was silently accepted")

    # Sign-count CAS (the consume_totp_step precedent): True iff stored == expected; a miss is the
    # clone signal. 0->0 (synced passkey) succeeds repeatedly and stays 0; last_used_at is stamped.
    assert await store.update_webauthn_sign_count("h1", expected=5, new=6, used_at=60.0) is True
    assert await store.update_webauthn_sign_count("h1", expected=5, new=7, used_at=61.0) is False
    got = await store.get_webauthn_credential("h1")
    assert got.sign_count == 6 and got.last_used_at == 60.0
    for used_at in (70.0, 71.0):
        assert (
            await store.update_webauthn_sign_count("h2", expected=0, new=0, used_at=used_at) is True
        )
    assert (await store.get_webauthn_credential("h2")).sign_count == 0

    # Delete is self-scoped (rowcount-guarded): the wrong user_id removes nothing.
    assert await store.delete_webauthn_credential("wa-u2", "h1") is False
    assert await store.get_webauthn_credential("h1") is not None
    assert await store.delete_webauthn_credential("wa-u1", "h1") is True
    assert await store.delete_webauthn_credential("wa-u1", "h1") is False  # already gone
    assert await store.has_webauthn_credentials("wa-u1") is True  # h2 remains

    # delete_all (admin_reset_mfa) returns the removed count.
    assert await store.delete_all_webauthn_credentials("wa-u1") == 1
    assert await store.has_webauthn_credentials("wa-u1") is False

    # delete_user removes the user's credentials in the same transaction (no orphans).
    assert await store.has_webauthn_credentials("wa-u2") is True
    await store.delete_user("wa-u2")
    assert await store.get_webauthn_credential("h-big") is None
    assert await store.get_webauthn_credential("h3") is None
    assert await store.has_webauthn_credentials("wa-u2") is False


async def _assert_totp_contract(store: Any) -> None:
    """The TOTP store contract (WP-14) — backfilled so the server backends' row-lock paths
    (Postgres ``FOR UPDATE`` / SQL Server ``UPDLOCK``) finally execute under test."""
    await store.create_user(
        user_id="totp-u1",
        username="totp-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )

    # Secret staging round-trip (cipher-covered column) + clear.
    assert await store.get_totp_secret("totp-u1") is None
    await store.set_totp_secret("totp-u1", secret="JBSWY3DPEHPK3PXP", now=2.0)
    assert await store.get_totp_secret("totp-u1") == "JBSWY3DPEHPK3PXP"
    await store.set_totp_secret("totp-u1", secret=None, now=3.0)
    assert await store.get_totp_secret("totp-u1") is None

    # Enable + recovery codes: single-use consumption is atomic (the double-spend guard).
    await store.set_totp_secret("totp-u1", secret="JBSWY3DPEHPK3PXP", now=4.0)
    assert await store.enable_totp("totp-u1", recovery_code_hashes=["rc1", "rc2"], now=5.0) is True
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is True
    assert set(await store.get_recovery_code_hashes("totp-u1")) == {"rc1", "rc2"}
    # The enable is conditional (BACKLOG #2224): a second confirm that lands once TOTP is on matches
    # no row, so it cannot replace the recovery codes the first one handed out.
    assert await store.enable_totp("totp-u1", recovery_code_hashes=["loser"], now=5.5) is False
    assert set(await store.get_recovery_code_hashes("totp-u1")) == {"rc1", "rc2"}
    assert await store.consume_recovery_code_hash("totp-u1", "rc1", now=6.0) is True
    assert await store.consume_recovery_code_hash("totp-u1", "rc1", now=7.0) is False
    assert await store.get_recovery_code_hashes("totp-u1") == ["rc2"]

    # consume_totp_step: strictly-increasing single-use steps (replay window defense, ASVS 6.5.1).
    assert await store.consume_totp_step("totp-u1", 100) is True
    assert await store.consume_totp_step("totp-u1", 100) is False  # replay
    assert await store.consume_totp_step("totp-u1", 99) is False  # older step
    assert await store.consume_totp_step("totp-u1", 101) is True
    assert await store.consume_totp_step("missing-user", 1) is False

    # Disable clears everything.
    await store.disable_totp("totp-u1", now=8.0)
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is False
    assert await store.get_totp_secret("totp-u1") is None
    assert await store.get_recovery_code_hashes("totp-u1") == []

    # The reset race (BACKLOG #2224): an enable that lands after a factor reset cleared the staged
    # secret matches no row, so TOTP is never flagged on over a NULL secret.
    assert await store.enable_totp("totp-u1", recovery_code_hashes=["late"], now=9.0) is False
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is False
    assert await store.get_totp_secret("totp-u1") is None
    assert await store.get_recovery_code_hashes("totp-u1") == []
    assert await store.enable_totp("missing-user", recovery_code_hashes=[], now=9.0) is False

    # replace_totp_enrolment (ADR 0171 Amendment B, BACKLOG #2226): conditional on TOTP being ON, so
    # it can never turn TOTP on for an account without it.
    # The old seed reversed: a different valid base32 seed, without a second key-shaped literal.
    new_seed = "JBSWY3DPEHPK3PXP"[::-1]
    replaced: dict[str, Any] = {"secret": new_seed, "recovery_code_hashes": ["n1"]}
    assert await store.replace_totp_enrolment("totp-u1", step=200, now=10.0, **replaced) is False
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is False
    assert await store.get_totp_secret("totp-u1") is None
    # On an enabled row it swaps the seed, the codes and the step in one write, with TOTP still on.
    await store.set_totp_secret("totp-u1", secret="JBSWY3DPEHPK3PXP", now=11.0)
    assert await store.enable_totp("totp-u1", recovery_code_hashes=["o1", "o2"], now=12.0) is True
    assert await store.consume_totp_step("totp-u1", 300) is True  # the old seed's history
    assert await store.replace_totp_enrolment("totp-u1", step=200, now=13.0, **replaced) is True
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is True
    assert await store.get_totp_secret("totp-u1") == new_seed
    assert await store.get_recovery_code_hashes("totp-u1") == ["n1"]
    # The high-water mark is the proving code's step, not the old seed's: 200 is spent, 201 is not.
    assert await store.consume_totp_step("totp-u1", 200) is False
    assert await store.consume_totp_step("totp-u1", 201) is True
    assert await store.replace_totp_enrolment("missing-user", step=1, now=14.0, **replaced) is False

    await store.delete_user("totp-u1")
