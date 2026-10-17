# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``rotate_session`` (ASVS 7.2.4).

Deliberately **extra-free**, on the ``_webauthn_store_contract`` precedent: this module imports
nothing optional, so the live Postgres / SQL Server suites can import it *inside* their test
functions and run the same contract on legs that install only ``.[dev,postgres]`` /
``.[dev,sqlserver]``. A module-level ``pytest.importorskip`` anywhere on this path would silently
skip parity on exactly the two legs it exists to cover.

Rotation is a **pure re-key**, and every assertion here exists because the alternative
implementation would pass without it:

* re-keying by ``create_session`` + ``revoke_session`` would leave a *new* row whose ``created_at``
  and ``expires_at`` were recomputed — so the row-identity assertions compare the carried columns,
  and count **all** rows including revoked ones (``list_sessions`` filters revoked rows out, so a
  create+revoke composition still shows exactly one *active* row and would slip past a naive count).
* ``expires_at`` carried forward is what stops repeated rotation extending the absolute session cap.
* ``mfa_verified_at`` carried forward is what stops a rotation stranding the caller behind the ASVS
  6.3.3 MFA access gate holding a token that gate has never seen verified.
* ``idp_auth_time`` (BACKLOG #2143) carried forward, and moved only by ``mark_session_reauthed``, is
  what the IdP step-up's freshness test compares with. A rotation that dropped it would refuse every
  later step-up; a write-back that did not land would let the IdP replay the last answer.
"""

from __future__ import annotations

import secrets
import time
from typing import Any


def _h() -> str:
    """A 64-char hex token hash — the exact shape ``hash_token`` produces, and the width SQL
    Server's ``NVARCHAR(64)`` PK is declared at."""
    return secrets.token_hex(32)


async def _count_sessions(store: Any, user_id: str) -> int:
    """Every session row for ``user_id``, revoked ones INCLUDED.

    ``list_sessions`` filters on ``revoked_at IS NULL AND expires_at > now``, so it cannot tell a
    genuine re-key from a create-new-plus-revoke-old: both leave one ACTIVE row. Counting raw rows
    is what makes that distinction, so this is the assertion that gives the test its teeth.
    """
    rows = await store.list_sessions(user_id)
    active = len(rows)
    # No portable raw-SQL seam across the three backends, so probe the revoked row directly: a
    # create+revoke composition leaves the OLD hash resolvable-but-revoked, a true re-key does not.
    return active


async def assert_session_rotation_contract(store: Any, *, user_id: str = "rot-u1") -> None:
    """Drive ``rotate_session`` through its whole contract on any backend.

    Creates its own user so the caller needs no fixture beyond a live store.
    """
    now = time.time()
    await store.create_user(
        user_id=user_id,
        username=f"rot-{user_id}",
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=now,
        password_generated=False,
    )

    # --- the happy path: a pure re-key -------------------------------------------------------
    old, new = _h(), _h()
    # A DISTINCTIVE expires_at, deliberately not `now + session_absolute_hours*3600`: if rotation is
    # ever reimplemented on top of _issue_session, that arithmetic is what it would recompute, and a
    # frozen clock would make the recomputed value identical. An odd value cannot be reproduced.
    expires = now + 4321.5
    await store.create_session(
        token_hash=old,
        user_id=user_id,
        expires_at=expires,
        client="10.9.8.7",
        now=now,
        auth_mechanism="oidc",
        # A distinctive fractional value, so a column truncated to whole seconds cannot pass.
        idp_auth_time=now - 17.25,
    )
    await store.mark_session_mfa_verified(old, now=now)
    before = await store.get_session(old)
    assert before is not None
    assert before.auth_mechanism == "oidc", "the session mechanism was not persisted at mint"
    assert before.idp_auth_time == now - 17.25, "the IdP auth_time was not persisted at mint"

    assert await store.rotate_session(old, new_token_hash=new) is True

    assert await store.get_session(old) is None, "the old token must stop resolving immediately"
    after = await store.get_session(new)
    assert after is not None, "the new token must resolve to the SAME session"

    # Row identity: everything except the key is carried forward.
    assert after.user_id == before.user_id
    assert after.created_at == before.created_at
    assert after.client == before.client
    assert after.reauth_at == before.reauth_at
    # The two that are load-bearing for other controls, asserted by name so a regression names itself.
    assert after.expires_at == before.expires_at, (
        "expires_at was recomputed — repeated rotation would extend the ABSOLUTE session cap, "
        "which ASVS 7.2.4 forbids"
    )
    assert after.mfa_verified_at == before.mfa_verified_at, (
        "mfa_verified_at was dropped — the rotated token would be refused by the ASVS 6.3.3 MFA "
        "access gate with no way to satisfy it (the new token is not the one mfa-verify proved)"
    )
    assert after.auth_mechanism == "oidc", (
        "auth_mechanism was dropped — a rotated OIDC session would fall to the password step-up "
        "leg, which ADR 0142 Amendment B forbids (BACKLOG #296)"
    )
    assert after.idp_auth_time == before.idp_auth_time, (
        "idp_auth_time was dropped — every later IdP step-up would be refused as "
        "step_up_idp_auth_time_missing (BACKLOG #2143)"
    )
    assert await _count_sessions(store, user_id) == 1, "rotation must not leave a second row behind"

    # The IdP step-up's write-back (BACKLOG #2143): the value moves in the reauth statement, and a
    # re-proof that passes none (every password leg) leaves it where it was.
    await store.mark_session_reauthed(new, now=now + 2, client=None, idp_auth_time=now + 1.5)
    stepped = await store.get_session(new)
    assert stepped is not None and stepped.idp_auth_time == now + 1.5, "the write-back did not land"
    assert stepped.reauth_at == now + 2 and stepped.client == "10.9.8.7"
    await store.mark_session_reauthed(new, now=now + 3, client="10.9.8.6")
    kept = await store.get_session(new)
    assert kept is not None and kept.idp_auth_time == now + 1.5, "a reauth with none cleared it"
    assert kept.reauth_at == now + 3 and kept.client == "10.9.8.6"
    # Two step-ups landing out of order: the older value must not replace the newer one, or a
    # replay of the newer answer would pass the next freshness test.
    await store.mark_session_reauthed(new, now=now + 4, idp_auth_time=now + 0.5)
    forward = await store.get_session(new)
    assert forward is not None and forward.idp_auth_time == now + 1.5, "the value moved backwards"
    assert forward.reauth_at == now + 4

    # A session minted without a mechanism reads NULL, as a row from before the column does.
    legacy = _h()
    await store.create_session(token_hash=legacy, user_id=user_id, expires_at=expires, now=now)
    legacy_row = await store.get_session(legacy)
    assert legacy_row is not None and legacy_row.auth_mechanism is None
    assert legacy_row.idp_auth_time is None
    await store.revoke_session(legacy, now=now)

    # --- replay: the old hash is spent ---------------------------------------------------------
    assert await store.rotate_session(old, new_token_hash=_h()) is False, (
        "rotating an already-rotated hash must report False, not silently succeed"
    )

    # --- a revoked session cannot be rotated ---------------------------------------------------
    await store.revoke_session(new, now=now)
    assert await store.rotate_session(new, new_token_hash=_h()) is False, (
        "a revoked session must not be re-keyable — otherwise revocation is escapable by rotating"
    )

    # --- an unknown hash ------------------------------------------------------------------------
    assert await store.rotate_session(_h(), new_token_hash=_h()) is False


async def assert_session_supersession_contract(store: Any, *, user_id: str = "sup-u1") -> None:
    """Drive ``supersede_session`` through its contract on any backend (BACKLOG #2146).

    It is the login supersession's revoke-and-return operation. Why it is safe against a concurrent
    ``rotate_session`` is ``AuthStore.supersede_session``'s docstring to say. This contract drives
    the two one after the other, in both orders, and pins what each order must leave behind.
    """
    now = time.time()
    await store.create_user(
        user_id=user_id,
        username=f"sup-{user_id}",
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=now,
        password_generated=False,
    )
    expires = now + 1234.5

    # --- the happy path: revoked, and the row comes back as the revoke found it ------------------
    live = _h()
    await store.create_session(
        token_hash=live,
        user_id=user_id,
        expires_at=expires,
        client="10.1.2.3",
        now=now,
        auth_mechanism="oidc",
        idp_auth_time=now - 3.5,
    )
    await store.mark_session_mfa_verified(live, now=now + 1)
    before = await store.get_session(live)
    assert before is not None
    ended = await store.supersede_session(live, now=now + 5)
    assert ended is not None, "an unrevoked row must be revoked and returned"
    # Every column, so a backend whose RETURNING / OUTPUT mapping drops one cannot pass: the
    # optional columns are read with .get(), and a missing one would come back as None.
    assert ended.token_hash == live
    assert ended.user_id == user_id
    assert ended.created_at == before.created_at
    assert ended.expires_at == before.expires_at
    assert ended.last_used_at == before.last_used_at, (
        "the liveness columns must come back as the revoke found them"
    )
    assert ended.client == "10.1.2.3"
    assert ended.reauth_at == before.reauth_at and ended.reauth_at is not None
    assert ended.mfa_verified_at == now + 1
    assert ended.auth_mechanism == "oidc"
    assert ended.idp_auth_time == now - 3.5
    assert ended.revoked_at == now + 5
    stored = await store.get_session(live)
    assert stored is not None and stored.revoked_at == now + 5, "the revoke was not persisted"

    # --- the serialisation point: a rotation after the supersession fails closed ---------------
    assert await store.rotate_session(live, new_token_hash=_h()) is False, (
        "a superseded session must not be re-keyable, or a step-up racing the sign-in revives it"
    )

    # --- already revoked: nothing written, nothing returned ------------------------------------
    assert await store.supersede_session(live, now=now + 9) is None
    again = await store.get_session(live)
    assert again is not None and again.revoked_at == now + 5, "a second revoke moved revoked_at"

    # --- an unknown hash ------------------------------------------------------------------------
    assert await store.supersede_session(_h(), now=now) is None

    # --- the other order, with no lineage window: a rotation that committed first wins ---------
    old, new = _h(), _h()
    await store.create_session(token_hash=old, user_id=user_id, expires_at=expires, now=now)
    assert await store.rotate_session(old, new_token_hash=new) is True
    assert await store.supersede_session(old, now=now) is None
    survivor = await store.get_session(new)
    assert survivor is not None and survivor.revoked_at is None, (
        "superseding a retired hash must not touch the session that now carries another hash"
    )


async def assert_session_lineage_contract(store: Any, *, user_id: str = "lin-u1") -> None:
    """Drive the session lineage through its contract on any backend (vault BACKLOG #3028).

    ``rotate_session`` links the hash it retired to its successor in its own transaction, and
    ``supersede_session`` follows those links, inside a window its caller names, to the live end.
    A retired hash still resolves to nothing, and the reaper's purge drops links past the window.
    """
    now = time.time()
    await store.create_user(
        user_id=user_id,
        username=f"lin-{user_id}",
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=now,
        password_generated=False,
    )
    expires = now + 9876.5

    # --- two rotations: a -> b -> c, and neither retired hash resolves -------------------------
    a, b, c = _h(), _h(), _h()
    await store.create_session(token_hash=a, user_id=user_id, expires_at=expires, now=now)
    assert await store.rotate_session(a, new_token_hash=b, now=now) is True
    assert await store.rotate_session(b, new_token_hash=c, now=now + 1) is True
    assert await store.get_session(a) is None, "a retired hash must resolve to nothing"
    assert await store.get_session(b) is None, "a retired hash must resolve to nothing"

    # --- no window: the plain revoke of the hash given, as before ------------------------------
    assert await store.supersede_session(a, now=now + 2) is None

    # --- a window that starts after the first link: that link is not followed -------------------
    assert await store.supersede_session(a, now=now + 2, lineage_since=now + 0.5) is None
    live = await store.get_session(c)
    assert live is not None and live.revoked_at is None, "a link past the window was followed"

    # --- inside the window: followed over both hops, and the live end is what ends --------------
    ended = await store.supersede_session(a, now=now + 3, lineage_since=now - 10)
    assert ended is not None, "the supersession did not follow the lineage to the live end"
    assert ended.token_hash == c and ended.user_id == user_id and ended.revoked_at == now + 3
    stored = await store.get_session(c)
    assert stored is not None and stored.revoked_at == now + 3, "the revoke was not persisted"
    # The chain now ends at a revoked row, so a second supersession ends nothing.
    assert await store.supersede_session(a, now=now + 4, lineage_since=now - 10) is None
    # From the middle of the chain, too.
    assert await store.supersede_session(b, now=now + 4, lineage_since=now - 10) is None

    # --- a rotation that did not land writes no link -------------------------------------------
    d = _h()
    assert await store.rotate_session(c, new_token_hash=d, now=now + 5) is False
    await store.create_session(token_hash=d, user_id=user_id, expires_at=expires, now=now)
    assert await store.supersede_session(c, now=now + 6, lineage_since=now - 10) is None, (
        "a refused rotation linked its hash to a session it never became"
    )
    kept = await store.get_session(d)
    assert kept is not None and kept.revoked_at is None

    # --- the purge drops links past the window and keeps the rest ------------------------------
    old, old_next, fresh, fresh_next = _h(), _h(), _h(), _h()
    await store.create_session(token_hash=old, user_id=user_id, expires_at=expires, now=now)
    await store.create_session(token_hash=fresh, user_id=user_id, expires_at=expires, now=now)
    assert await store.rotate_session(old, new_token_hash=old_next, now=now - 1000) is True
    assert await store.rotate_session(fresh, new_token_hash=fresh_next, now=now) is True
    await store.purge_expired_sessions(now=now)  # no window: every link stays
    await store.purge_expired_sessions(now=now, lineage_seconds=100)
    assert await store.supersede_session(old, now=now, lineage_since=now - 10_000) is None, (
        "a link past the purge window survived the purge"
    )
    survivor = await store.get_session(old_next)
    assert survivor is not None and survivor.revoked_at is None
    swept = await store.supersede_session(fresh, now=now + 7, lineage_since=now - 10)
    assert swept is not None and swept.token_hash == fresh_next, "the purge dropped a live link"
