# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contracts for the WebAuthn credential surface (+ the TOTP backfill).

Deliberately **extra-free** (ADR 0068 §4 / decision 4): this module imports NOTHING from the
optional ``webauthn`` extra — it exercises only ``AuthStore`` methods and the
``WebAuthnCredential`` record, and judges a refusal with the service's own extra-free
``_is_integrity_refusal`` — so the live Postgres/SQL Server suites can import it *inside their
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
from collections.abc import Awaitable
from contextlib import AbstractContextManager
from typing import Any

import pytest

from messagefoundry.auth.service import _is_integrity_refusal
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


async def _assert_integrity_refused(write: Awaitable[object], what: str) -> None:
    """``write`` fails with a refusal the service recognises as an integrity refusal: the one
    predicate it uses, so this contract pins exactly what finish_webauthn_registration relies on."""
    try:
        await write
    except Exception as exc:  # noqa: BLE001 - each backend raises its own integrity class
        assert _is_integrity_refusal(exc), (
            f"{what} raised {type(exc).__name__}, not an integrity refusal"
        )
    else:
        raise AssertionError(f"{what} was accepted")


async def _assert_webauthn_rehash_contract(store: Any) -> None:
    """BACKLOG #3423: a passkey moves to a new ``credential_id_hash`` that fits the column (the
    68-character ``wc1:`` form), only on its own account, and the account stays sealed over it, so
    a later passkey write on the same account still succeeds."""
    await store.create_user(
        user_id="wa-r1",
        username="wa-rehash",
        auth_provider="local",
        password_hash="h",
        now=100.0,
        password_generated=False,
    )
    bare, tagged = "ab" * 32, "wc1:" + "ab" * 32
    await store.add_webauthn_credential(_cred("wa-r1", "key", id_hash=bare))
    assert await store.rehash_webauthn_credential("someone-else", bare, tagged) is False
    assert await store.rehash_webauthn_credential("wa-r1", bare, tagged) is True
    assert await store.get_webauthn_credential(bare) is None
    moved = await store.get_webauthn_credential(tagged)
    assert moved is not None and moved.credential_id == "cred-id-b64url"
    assert await store.rehash_webauthn_credential("wa-r1", bare, tagged) is False  # already moved
    await store.add_webauthn_credential(_cred("wa-r1", "second", id_hash="wc1:" + "cd" * 32))
    assert await store.delete_webauthn_credential("wa-r1", tagged) is True


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
    await _assert_integrity_refused(
        store.add_webauthn_credential(_cred("wa-u1", "yubikey", id_hash="h-dup", created_at=50.0)),
        "duplicate (user_id, label)",
    )

    # Sign-count CAS (the consume_totp_step precedent), answered by the one locked write (BACKLOG
    # #3774): "moved" iff stored == expected; "mismatch" when the passkey exists with another count
    # (the clone signal), which writes nothing; "gone" when there is no such passkey. 0->0 (synced
    # passkey) succeeds repeatedly and stays 0; last_used_at is stamped.
    assert await store.update_webauthn_sign_count("h1", expected=5, new=6, used_at=60.0) == "moved"
    assert (
        await store.update_webauthn_sign_count("h1", expected=5, new=7, used_at=61.0) == "mismatch"
    )
    got = await store.get_webauthn_credential("h1")
    assert got.sign_count == 6 and got.last_used_at == 60.0
    assert (
        await store.update_webauthn_sign_count("h-none", expected=0, new=1, used_at=62.0) == "gone"
    )
    assert await store.get_webauthn_credential("h-none") is None
    for used_at in (70.0, 71.0):
        assert (
            await store.update_webauthn_sign_count("h2", expected=0, new=0, used_at=used_at)
            == "moved"
        )
    assert (await store.get_webauthn_credential("h2")).sign_count == 0

    # Delete is self-scoped (rowcount-guarded): the wrong user_id removes nothing.
    assert await store.delete_webauthn_credential("wa-u2", "h1") is False
    assert await store.get_webauthn_credential("h1") is not None
    assert await store.delete_webauthn_credential("wa-u1", "h1") is True
    assert await store.delete_webauthn_credential("wa-u1", "h1") is False  # already gone
    # A deleted passkey answers "gone" whatever count is offered, the stored one included.
    assert await store.update_webauthn_sign_count("h1", expected=6, new=8, used_at=63.0) == "gone"
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

    # BACKLOG #2733: a passkey for an account that does not exist is refused by the user foreign
    # key on every backend. SQL Server lacked the key, so this write once committed an orphan there.
    await _assert_integrity_refused(
        store.add_webauthn_credential(_cred("wa-u2", "orphan", id_hash="h-orphan")),
        "a passkey for an account that does not exist",
    )
    assert await store.get_webauthn_credential("h-orphan") is None


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
    first_cell = await store.set_totp_secret("totp-u1", secret="JBSWY3DPEHPK3PXP", now=2.0)
    assert first_cell is not None
    assert await store.get_totp_secret("totp-u1") == "JBSWY3DPEHPK3PXP"
    await store.disable_totp("totp-u1", now=3.0)
    assert await store.get_totp_secret("totp-u1") is None

    # Enable + recovery codes: single-use consumption is atomic (the double-spend guard).
    staged_cell = await store.set_totp_secret("totp-u1", secret="JBSWY3DPEHPK3PXP", now=4.0)
    assert (
        await store.enable_totp(
            "totp-u1",
            expected_secret_cell=staged_cell,
            recovery_code_hashes=["rc1", "rc2"],
            now=5.0,
        )
        is True
    )
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is True
    assert set(await store.get_recovery_code_hashes("totp-u1")) == {"rc1", "rc2"}
    # The enable is conditional (BACKLOG #2224): a second confirm that lands once TOTP is on matches
    # no row, so it cannot replace the recovery codes the first one handed out.
    assert (
        await store.enable_totp(
            "totp-u1",
            recovery_code_hashes=["loser"],
            expected_secret_cell=staged_cell,
            now=5.5,
        )
        is False
    )
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
    assert (
        await store.enable_totp(
            "totp-u1", recovery_code_hashes=["late"], expected_secret_cell=staged_cell, now=9.0
        )
        is False
    )
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is False
    assert await store.get_totp_secret("totp-u1") is None
    assert await store.get_recovery_code_hashes("totp-u1") == []
    assert (
        await store.enable_totp(
            "missing-user", recovery_code_hashes=[], expected_secret_cell=staged_cell, now=9.0
        )
        is False
    )

    # replace_totp_enrolment (ADR 0171 Amendment B, BACKLOG #2226): conditional on TOTP being ON
    # and on the enrolment instant the caller read, so it can never turn TOTP on for an account
    # without it, nor overwrite a re-enrolment. The swap, the session sweep and the audit row are
    # one transaction, so a refused write leaves none of them.
    from messagefoundry.store.store import AuditAppend

    action = "auth.admin_totp_reset"
    audit = AuditAppend(action, actor="cli:contract", detail="{}")

    async def audit_rows() -> int:
        return len(await store.list_audit(limit=10, action=action))

    # The old seed reversed: a different valid base32 seed, without a second key-shaped literal.
    new_seed = "JBSWY3DPEHPK3PXP"[::-1]
    replaced: dict[str, Any] = {"secret": new_seed, "recovery_code_hashes": ["n1"], "audit": audit}
    assert (
        await store.replace_totp_enrolment(
            "totp-u1", step=200, expected_enrolled_at=None, now=10.0, **replaced
        )
        is None
    )
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is False
    assert await store.get_totp_secret("totp-u1") is None
    assert await audit_rows() == 0
    # On an enabled row it swaps the seed, the codes and the step in one write, with TOTP still on.
    staged_cell = await store.set_totp_secret("totp-u1", secret="JBSWY3DPEHPK3PXP", now=11.0)
    assert (
        await store.enable_totp(
            "totp-u1", expected_secret_cell=staged_cell, recovery_code_hashes=["o1", "o2"], now=12.0
        )
        is True
    )
    assert await store.consume_totp_step("totp-u1", 300) is True  # the old seed's history
    await store.create_session(
        token_hash="totp-u1-session", user_id="totp-u1", expires_at=1e12, auth_mechanism="password"
    )
    # A stale compare-and-set (an enrolment instant the row no longer holds) writes nothing at all.
    stale = await store.replace_totp_enrolment(
        "totp-u1", step=200, expected_enrolled_at=11.5, now=12.5, **replaced
    )
    assert stale is None
    assert await store.get_totp_secret("totp-u1") == "JBSWY3DPEHPK3PXP"
    assert len(await store.list_sessions("totp-u1")) == 1
    assert await audit_rows() == 0
    # A refused audit append, or a refused COMMIT where the store has a seam for one, leaves the
    # seed, the sessions and the audit log as they were and tees nothing, and the swap that commits
    # tees its row once (vault BACKLOG #3324). Under the commit fault the append has run for real,
    # so a tee before the commit would show.
    from tests._operator_audit_atomic_contract import (
        AppendFailed,
        CommitFailed,
        TeeTap,
        commit_seam,
        failing_append,
        failing_commit,
    )

    faults: list[tuple[AbstractContextManager[None], type[Exception]]] = [
        (failing_append(store, action), AppendFailed)
    ]
    if commit_seam(store):
        faults.append((failing_commit(store), CommitFailed))
    tap = TeeTap()
    try:
        for fault, raised in faults:
            with fault, pytest.raises(raised):
                await store.replace_totp_enrolment(
                    "totp-u1", step=200, expected_enrolled_at=12.0, now=12.75, **replaced
                )
            assert await store.get_totp_secret("totp-u1") == "JBSWY3DPEHPK3PXP", raised
            assert await store.get_recovery_code_hashes("totp-u1") == ["o1", "o2"], raised
            user = await store.get_user("totp-u1")
            assert user is not None and user.totp_enabled is True, raised
            assert len(await store.list_sessions("totp-u1")) == 1, raised
            assert await audit_rows() == 0, raised
        ended = await store.replace_totp_enrolment(
            "totp-u1", step=200, expected_enrolled_at=12.0, now=13.0, **replaced
        )
    finally:
        tap.stop()
    assert ended == 1
    [written] = await store.list_audit(limit=10, action=action)
    assert tap.ids(action) == [int(written["id"])]
    user = await store.get_user("totp-u1")
    assert user is not None and user.totp_enabled is True
    assert await store.get_totp_secret("totp-u1") == new_seed
    assert await store.get_recovery_code_hashes("totp-u1") == ["n1"]
    assert await store.list_sessions("totp-u1") == []
    # The high-water mark is the proving code's step, not the old seed's: 200 is spent, 201 is not.
    assert await store.consume_totp_step("totp-u1", 200) is False
    assert await store.consume_totp_step("totp-u1", 201) is True
    missing = await store.replace_totp_enrolment(
        "missing-user", step=1, expected_enrolled_at=None, now=14.0, **replaced
    )
    assert missing is None
    assert await audit_rows() == 1

    await store.delete_user("totp-u1")
    await _assert_totp_binding_contract(store)


async def _assert_totp_binding_contract(store: Any) -> None:
    """BACKLOG #3025: the enable turns on only the secret the caller verified, on every backend.

    ``set_totp_secret`` returns the stored cell; ``enable_totp`` writes only while the row still
    holds that cell. A second stage in between makes it refuse, and a write to any other column of
    the row in between does not."""
    await store.create_user(
        user_id="totp-u2",
        username="totp-bob",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    verified = await store.set_totp_secret("totp-u2", secret="JBSWY3DPEHPK3PXP", now=2.0)
    assert verified is not None
    # A second begin stages another secret after the first one was verified.
    other_seed = "JBSWY3DPEHPK3PXP"[::-1]
    replacing = await store.set_totp_secret("totp-u2", secret=other_seed, now=3.0)
    assert replacing is not None and replacing != verified
    assert (
        await store.enable_totp(
            "totp-u2", recovery_code_hashes=["x"], expected_secret_cell=verified, now=4.0
        )
        is False
    )
    user = await store.get_user("totp-u2")
    assert user is not None and user.totp_enabled is False
    assert await store.get_totp_secret("totp-u2") == other_seed
    assert await store.get_recovery_code_hashes("totp-u2") == []
    # None matches nothing, even with a secret staged.
    assert (
        await store.enable_totp("totp-u2", recovery_code_hashes=[], expected_secret_cell=None)
        is False
    )

    # The false-refusal trap: writes to OTHER columns between the stage and the enable carry the
    # stored cell over byte for byte, so the compare still matches.
    await store.set_user_notify_email("totp-u2", email="bob@example.test", now=5.0)
    await store.record_login_success("totp-u2", now=6.0)
    assert (
        await store.enable_totp(
            "totp-u2", recovery_code_hashes=["y"], expected_secret_cell=replacing, now=7.0
        )
        is True
    )
    assert await store.get_totp_secret("totp-u2") == other_seed
    assert await store.get_recovery_code_hashes("totp-u2") == ["y"]

    # Once TOTP is on, a stage writes nothing and the enabled secret stands.
    assert await store.set_totp_secret("totp-u2", secret="JBSWY3DPEHPK3PXP", now=8.0) is None
    assert await store.get_totp_secret("totp-u2") == other_seed
    assert await store.set_totp_secret("missing-user", secret="JBSWY3DPEHPK3PXP") is None

    await store.delete_user("totp-u2")
