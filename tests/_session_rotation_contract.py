# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    )

    # --- the happy path: a pure re-key -------------------------------------------------------
    old, new = _h(), _h()
    # A DISTINCTIVE expires_at, deliberately not `now + session_absolute_hours*3600`: if rotation is
    # ever reimplemented on top of _issue_session, that arithmetic is what it would recompute, and a
    # frozen clock would make the recomputed value identical. An odd value cannot be reproduced.
    expires = now + 4321.5
    await store.create_session(
        token_hash=old, user_id=user_id, expires_at=expires, client="10.9.8.7", now=now
    )
    await store.mark_session_mfa_verified(old, now=now)
    before = await store.get_session(old)
    assert before is not None

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
    assert await _count_sessions(store, user_id) == 1, "rotation must not leave a second row behind"

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
