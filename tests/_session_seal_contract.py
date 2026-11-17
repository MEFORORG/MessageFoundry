# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for session-row integrity seals (BACKLOG #2592).

Deliberately **extra-free**, on the ``_session_rotation_contract`` precedent: it imports nothing
optional, so the live Postgres and SQL Server suites import it inside their test functions and run
the same assertions on legs that install only their own driver extra.

The caller passes a store opened with a store key, and ``raw``: a way to run one SQL statement
against the same database without going through the store's helpers.
``raw`` takes SQL written with ``?`` placeholders and its parameters; each backend's adapter
respells the placeholders for its driver and commits.

Every refusal below has a control beside it: the same row resolves before the change, or the same
change made through the store keeps it resolving. A sealer that refused everything, or accepted
everything, fails this contract.
"""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import fields
from typing import Any

from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import SEAL_PREFIX, RowSealError
from messagefoundry.store.store import (
    PendingFactorAnchor,
    SessionRecord,
    no_audit_row,
    session_seal_ok,
)

#: Runs one statement with ``?`` placeholders against the store's database, outside the store.
RawSql = Callable[[str, tuple[Any, ...]], Awaitable[None]]


def dollar_placeholders(sql: str) -> str:
    """``sql`` with each ``?`` respelled ``$1``, ``$2``, ... for asyncpg. The contract's statements
    carry no ``?`` inside a literal, so a plain left-to-right count is exact."""
    counter = iter(range(1, sql.count("?") + 1))
    return re.sub(r"\?", lambda _m: f"${next(counter)}", sql)


def assert_session_columns(columns: set[str]) -> None:
    """The ``sessions`` table has exactly :class:`SessionRecord`'s fields, so a column added to one
    and not the other cannot sit outside the seal unnoticed (BACKLOG #2592)."""
    assert {c.lower() for c in columns} == {f.name for f in fields(SessionRecord)}


#: Each sealed column, and a value that differs from what ``_mint`` writes.
_SEALED_CHANGES: tuple[tuple[str, Any], ...] = (
    ("user_id", "seal-u2"),
    ("created_at", 1.0),
    ("expires_at", 4_000_000_000.0),
    ("client", "192.0.2.77"),
    ("reauth_at", 1.0),
    ("mfa_verified_at", 1.0),
    ("auth_mechanism", "oidc"),
    ("idp_auth_time", 1.0),
    ("user_epoch", 7),
    ("global_epoch", 7),  # BACKLOG #5091
)


async def _user(store: Any, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=time.time(),
        password_generated=False,
        audits=(),
    )


async def _mint(store: Any, user_id: str = "seal-u1") -> str:
    token = mint_token()
    await store.create_session(
        token_hash=hash_token(token),
        user_id=user_id,
        expires_at=time.time() + 3600,
        client="192.0.2.10",
        auth_mechanism="password",
    )
    return token


async def assert_session_seal_contract(store: Any, raw: RawSql) -> None:
    """Drive the session seal through its whole contract on ``store``'s backend."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    await _user(store, "seal-u2")

    # --- a session the store wrote carries a seal and resolves ----------------------------------
    token = await _mint(store)
    row = await store.get_session(hash_token(token))
    assert row is not None and row.seal.startswith(SEAL_PREFIX)
    assert session_seal_ok(sealer, row)
    identity = await service.identity_for_token(token)
    assert identity is not None and identity.user_id == "seal-u1"
    assert await service.has_recent_step_up(token)

    # --- a row the store did not write resolves to nothing -------------------------------------
    unsealed = mint_token()
    now = time.time()
    await raw(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
        " client, reauth_at, mfa_verified_at, auth_mechanism) VALUES (?,?,?,?,?,?,?,?,?)",
        (hash_token(unsealed), "seal-u2", now, now + 3600, now, None, now, now, "password"),
    )
    assert await service.identity_for_token(unsealed) is None
    assert not await service.has_recent_step_up(unsealed)
    ended = await store.get_session(hash_token(unsealed))
    assert ended is not None and ended.revoked_at is not None  # refused, then ended
    # A valid seal copied from another row does not carry over: it covers that row's token hash.
    # The copy carries global_epoch too (BACKLOG #5091), a sealed column: without it, on a store
    # whose global epoch is above 0, the copy would differ in that column as well, and the seal's
    # refusal would not show that it binds the token hash.
    copied = mint_token()
    await raw(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
        " client, reauth_at, auth_mechanism, user_epoch, global_epoch, seal)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            hash_token(copied),
            row.user_id,
            row.created_at,
            row.expires_at,
            row.last_used_at,
            row.client,
            row.reauth_at,
            row.auth_mechanism,
            row.user_epoch,
            row.global_epoch,
            row.seal,
        ),
    )
    assert await service.identity_for_token(copied) is None

    # --- a sealed column changed outside the store resolves to nothing -------------------------
    for column, value in _SEALED_CHANGES:
        changed = await _mint(store)
        assert await service.identity_for_token(changed) is not None, column  # control
        await raw(
            f"UPDATE sessions SET {column}=? WHERE token_hash=?", (value, hash_token(changed))
        )
        assert await service.identity_for_token(changed) is None, column
        assert not await service.has_recent_step_up(changed), column

    # --- the one column outside the seal: last_used_at -----------------------------------------
    touched = await _mint(store)
    await raw(
        "UPDATE sessions SET last_used_at=? WHERE token_hash=?",
        (time.time() - 5, hash_token(touched)),
    )
    assert await service.identity_for_token(touched) is not None

    # --- revoking blanks the seal, so clearing revoked_at brings nothing back ------------------
    revoked = await _mint(store)
    await store.revoke_session(hash_token(revoked))
    gone = await store.get_session(hash_token(revoked))
    assert gone is not None and gone.revoked_at is not None and gone.seal == ""
    await raw("UPDATE sessions SET revoked_at=NULL WHERE token_hash=?", (hash_token(revoked),))
    assert await service.identity_for_token(revoked) is None

    # --- the write helper refuses a row whose seal fails, and does not re-seal it --------------
    bent = await _mint(store)
    await raw("UPDATE sessions SET client=? WHERE token_hash=?", ("192.0.2.99", hash_token(bent)))
    before = await store.get_session(hash_token(bent))
    for write in (
        lambda: store.mark_session_reauthed(hash_token(bent), client="192.0.2.10"),
        lambda: store.mark_session_mfa_verified(hash_token(bent)),
        lambda: store.rotate_session(hash_token(bent), new_token_hash=hash_token(mint_token())),
    ):
        try:
            await write()
        except RowSealError:
            pass
        else:
            raise AssertionError("a write over a row that fails its seal was not refused")
    after = await store.get_session(hash_token(bent))
    assert after == before  # nothing written, so the failing seal was not replaced
    assert await service.identity_for_token(bent) is None

    # --- control: the same writes through the store keep a sealed row resolving -------------
    kept = await _mint(store)
    await store.mark_session_reauthed(hash_token(kept), client="192.0.2.11")
    await store.mark_session_mfa_verified(hash_token(kept))
    stamped = await store.get_session(hash_token(kept))
    assert stamped is not None and stamped.mfa_verified_at is not None
    assert stamped.client == "192.0.2.11" and session_seal_ok(sealer, stamped)
    rotated = mint_token()
    assert await store.rotate_session(hash_token(kept), new_token_hash=hash_token(rotated))
    assert await service.identity_for_token(rotated) is not None
    assert await service.identity_for_token(kept) is None  # the old hash names no row now

    # --- the factor write applies its anchor only to a row that has not met its factor ---------
    # Vault BACKLOG #2964 item 14: decided inside the write, on the row it reads and replaces.
    pending = await _mint(store)
    seeded = await store.get_session(hash_token(pending))
    assert seeded is not None and seeded.mfa_verified_at is None and seeded.reauth_at is not None
    shut = PendingFactorAnchor("192.0.2.5", open_window=False)
    assert await store.mark_session_mfa_verified(hash_token(pending), anchor=shut) is True
    moved = await store.get_session(hash_token(pending))
    assert moved is not None and moved.mfa_verified_at is not None
    # Without open_window the window is cleared, whatever it held.
    assert (moved.client, moved.reauth_at) == ("192.0.2.5", None)
    assert session_seal_ok(sealer, moved)
    # Again, on the row that has now met its factor: only the factor stamp moves.
    later = moved.mfa_verified_at + 5
    other_anchor = PendingFactorAnchor("192.0.2.6", open_window=True)
    assert (
        await store.mark_session_mfa_verified(hash_token(pending), now=later, anchor=other_anchor)
        is False
    )
    met = await store.get_session(hash_token(pending))
    assert met is not None and (met.client, met.reauth_at, met.mfa_verified_at) == (
        "192.0.2.5",
        None,
        later,
    )
    assert session_seal_ok(sealer, met)
    # open_window on a fresh pending row stamps the window; a None client keeps the address.
    opening = await _mint(store)
    at = time.time() + 1
    opener = PendingFactorAnchor(None, open_window=True)
    assert await store.mark_session_mfa_verified(hash_token(opening), now=at, anchor=opener)
    opened = await store.get_session(hash_token(opening))
    assert opened is not None and (opened.client, opened.reauth_at) == ("192.0.2.10", at)
    # Control: no anchor applies nothing and answers False, as every other caller expects.
    plain = await _mint(store)
    unanchored = await store.get_session(hash_token(plain))
    assert unanchored is not None
    assert await store.mark_session_mfa_verified(hash_token(plain)) is False
    stamped_only = await store.get_session(hash_token(plain))
    assert stamped_only is not None and stamped_only.mfa_verified_at is not None
    assert (stamped_only.client, stamped_only.reauth_at) == (
        unanchored.client,
        unanchored.reauth_at,
    )
    # A hash that names no row writes nothing and answers False.
    assert not await store.mark_session_mfa_verified(hash_token(mint_token()), anchor=shut)

    # --- ending every session raises the epoch: an older copy of a row is refused --------------
    mine = await _mint(store)
    other = await _mint(store)
    copy = await store.get_session(hash_token(other))
    assert copy is not None
    # BACKLOG #3393: the count the factor-change offer shows is the number this revoke ends, over
    # every kind of row the contract has left on the account. That includes an expired row nobody
    # revoked, which the inventory hides and the revoke still ends.
    lapsed = mint_token()
    await raw(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
        " auth_mechanism) VALUES (?,?,?,?,?,?)",
        (hash_token(lapsed), "seal-u1", now - 7200, now - 3600, now - 7200, "password"),
    )
    listed = {s.token_hash for s in await store.list_sessions("seal-u1")}
    assert hash_token(lapsed) not in listed and hash_token(other) in listed  # control
    others = await store.count_user_sessions("seal-u1", except_token_hash=hash_token(mine))
    assert others >= 2
    assert await store.count_user_sessions("seal-u1") == others + 1  # mine is unrevoked too
    absent = hash_token(mint_token())  # a hash that names no row excepts nothing
    assert await store.count_user_sessions("seal-u1", except_token_hash=absent) == others + 1
    result = await store.revoke_user_sessions(
        "seal-u1", except_token_hash=hash_token(mine), audit=no_audit_row
    )
    assert (result.count, result.kept) == (others, True)  # kept: re-stamped (BACKLOG #4975)
    assert await store.count_user_sessions("seal-u1", except_token_hash=hash_token(mine)) == 0
    assert await store.count_user_sessions("seal-u1") == 1
    assert await service.identity_for_token(mine) is not None  # the kept session, re-sealed
    assert await service.identity_for_token(other) is None
    await raw(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (copy.seal, hash_token(other)),
    )
    restored = await store.get_session(hash_token(other))
    assert restored is not None and session_seal_ok(sealer, restored)  # the copy's seal holds...
    assert await service.identity_for_token(other) is None  # ...and its epoch is stale
    assert await service.identity_for_token(mine) is not None

    # --- a kept session a sweep missed is ended, not stamped back to validity (BACKLOG #4975) ----
    # Restoring a revoked row's sealed copy leaves it where a row the sweep missed stands: live,
    # sealed, an epoch behind its account. The service is not asked about it before the revoke,
    # because a refusal would end it. The revoke ends it in its own transaction and counts it
    # (follow-up to BACKLOG #4975).
    missed = await _mint(store)
    snapshot = await store.get_session(hash_token(missed))
    assert snapshot is not None
    current = await _mint(store)
    result = await store.revoke_user_sessions(
        "seal-u1", except_token_hash=hash_token(current), audit=no_audit_row
    )
    assert result.count >= 1 and result.kept  # control: a current one is kept, and said to be
    assert not result.ended_kept
    assert await service.identity_for_token(current) is not None
    await raw(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (snapshot.seal, hash_token(missed)),
    )
    swept = await store.count_user_sessions("seal-u1", except_token_hash=hash_token(missed))
    assert swept >= 1  # `current`, at least
    result = await store.revoke_user_sessions(
        "seal-u1", except_token_hash=hash_token(missed), audit=no_audit_row
    )
    assert (result.count, result.kept, result.ended_kept) == (swept + 1, False, True)
    left = await store.get_session(hash_token(missed))
    assert left is not None and left.revoked_at is not None  # ended, in the same transaction
    assert left.user_epoch == snapshot.user_epoch  # not re-stamped with the new epoch
    assert await store.count_user_sessions("seal-u1") == 0  # nothing of the account left live
    assert await service.identity_for_token(missed) is None
    assert await service.identity_for_token(current) is None  # the revoke still ended the others

    # --- nor when the account's own seal fails and its epoch cannot move ------------------------
    # With no raise nothing is stamped, a current session included, so the revoke ends the kept
    # session and counts it. Its own account, so the bent record touches nothing above. The
    # control is the same current session kept while the record's seal still holds.
    await _user(store, "seal-u3")
    behind = await _mint(store, "seal-u3")
    snapshot = await store.get_session(hash_token(behind))
    account = await store.get_user("seal-u3")
    assert snapshot is not None and account is not None
    await store.revoke_user_sessions("seal-u3", audit=no_audit_row)
    raised = await store.get_user("seal-u3")
    assert raised is not None and raised.session_epoch == account.session_epoch + 1  # control
    fresh = await _mint(store, "seal-u3")
    one_behind = await store.get_session(hash_token(fresh))  # one epoch behind after the control
    assert one_behind is not None
    result = await store.revoke_user_sessions(
        "seal-u3", except_token_hash=hash_token(fresh), audit=no_audit_row
    )
    assert (result.count, result.kept, result.ended_kept) == (0, True, False)  # control
    assert await service.identity_for_token(fresh) is not None
    await raw(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (snapshot.seal, hash_token(behind)),
    )
    stamped = await store.get_user("seal-u3")
    assert stamped is not None
    await raw("UPDATE users SET authz_seal=? WHERE id=?", ("mfseal:v1:b4975:bogus", "seal-u3"))
    result = await store.revoke_user_sessions(
        "seal-u3", except_token_hash=hash_token(fresh), audit=no_audit_row
    )
    assert (result.count, result.kept, result.ended_kept) == (2, False, True)  # behind + fresh
    unmoved = await store.get_user("seal-u3")
    assert unmoved is not None and unmoved.session_epoch == stamped.session_epoch  # seal failed
    for token in (fresh, behind):
        left = await store.get_session(hash_token(token))
        assert left is not None and left.revoked_at is not None
    # A session exactly one epoch behind is ended too: the guard compares to the epoch the raise
    # replaced, not to the new epoch less one, which with no raise it would match.
    await raw(  # the control re-stamped the row, so its epoch goes back with its seal
        "UPDATE sessions SET revoked_at=NULL, user_epoch=?, seal=? WHERE token_hash=?",
        (one_behind.user_epoch, one_behind.seal, hash_token(fresh)),
    )
    assert one_behind.user_epoch == stamped.session_epoch - 1  # the account still unmoved
    result = await store.revoke_user_sessions(
        "seal-u3", except_token_hash=hash_token(fresh), audit=no_audit_row
    )
    assert (result.count, result.kept, result.ended_kept) == (1, False, True)
    left = await store.get_session(hash_token(fresh))
    assert left is not None and left.revoked_at is not None
    assert left.user_epoch == one_behind.user_epoch

    # --- a kept session of ANOTHER account is left as it is (BACKLOG #5742) ---------------------
    # Handed another account's token hash as the kept session, the revoke must neither seal-check
    # nor re-seal that row: a broken foreign seal would otherwise raise and roll back the caller's
    # own revocation. The caller's sessions still end; the foreign row is not touched.
    await _user(store, "seal-u4")
    await _user(store, "seal-u5")
    own = [await _mint(store, "seal-u4") for _ in range(2)]
    foreign = await _mint(store, "seal-u5")
    bogus = "mfseal:v1:b5742:bogus"
    await raw("UPDATE sessions SET seal=? WHERE token_hash=?", (bogus, hash_token(foreign)))
    result = await store.revoke_user_sessions(
        "seal-u4", except_token_hash=hash_token(foreign), audit=no_audit_row
    )
    assert (result.count, result.kept, result.ended_kept) == (2, False, False)
    for token in own:
        assert await service.identity_for_token(token) is None
    untouched = await store.get_session(hash_token(foreign))
    assert untouched is not None and untouched.revoked_at is None
    assert untouched.seal == bogus and untouched.user_id == "seal-u5"
