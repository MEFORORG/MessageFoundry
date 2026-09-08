# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 7.2.4 — the SERVICE-level rotation primitive, above the store contract.

``tests/_session_rotation_contract.py`` pins the store op on all three backends. This pins the layer
above it: ``AuthService._rotate_session_token`` and the process-local state ``_rekey_token_state``
must carry with it.

Why this file exists at all. The primitive landed ahead of its call sites — wiring rotation into the
five in-place elevation sites is the remaining 7.2.4 work, researched under BACKLOG #1146 — so it had
NO coverage and no caller, and its job is precisely the part that fails *silently*: three in-memory
maps keyed on the session's token hash, each of which strands differently if it is missed. Untested
code whose failure mode is silence is worse than absent code, so it is tested here rather than left
to the wiring commit.

What those five sites do to the caller's token TODAY is measured in
``tests/test_session_token_at_elevation_sites.py``, at the ``identity_for_token`` seam rather than by
grepping for this primitive's name.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.auth import webauthn
from messagefoundry.auth.service import (
    STEP_UP_ACTION_MFA_ENROLL,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "rot_primitive.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service_and_token(engine: Engine) -> tuple[AuthService, str]:
    """An initialized service plus a live session token for a local user."""
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False))
    await service.initialize()
    user_id = await service.create_local_user(
        username="rot",
        password=PW,
        display_name=None,
        email=None,
        roles=[],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    outcome = await service.login("rot", PW)
    assert outcome.ok and outcome.token is not None
    return service, outcome.token


# --- the primitive itself ---------------------------------------------------


async def test_rotation_returns_a_new_token_and_kills_the_old_one(engine: Engine) -> None:
    """RED when: _rotate_session_token stops calling the store op, or returns the same token.

    Asserted through ``identity_for_token`` — the seam every gate actually authenticates on — rather
    than by inspecting the store, so a primitive that re-keys the row but hands back the stale token
    still fails.
    """
    service, token = await _service_and_token(engine)
    assert await service.identity_for_token(token) is not None

    rotated = await service._rotate_session_token(token)
    assert rotated is not None and rotated != token

    assert await service.identity_for_token(token) is None, "the old token must stop authenticating"
    assert await service.identity_for_token(rotated) is not None


async def test_rotation_fails_closed_when_the_session_is_gone(engine: Engine) -> None:
    """RED when: the primitive stops checking the store op's rowcount.

    A revoked session must yield None, never a freshly minted token that authenticates nothing — the
    caller hands this straight to a user, so a truthy return on a dead row is a broken sign-in.
    """
    service, token = await _service_and_token(engine)
    await service.store.revoke_session(hash_token(token))
    assert await service._rotate_session_token(token) is None


# --- the process-local state that must travel with it -----------------------


async def test_the_action_step_up_grant_survives_rotation(engine: Engine) -> None:
    """RED when: _rekey_token_state stops moving _action_step_up_grants.

    Stranded, the ceremony the user just completed silently no-ops and the next route demands another
    step-up — a confusing loop rather than an error.
    """
    service, token = await _service_and_token(engine)
    service._grant_action_step_up(hash_token(token), STEP_UP_ACTION_MFA_ENROLL)

    rotated = await service._rotate_session_token(token)
    assert rotated is not None

    # has_action_step_up is single-use, so this both proves the move and spends it.
    assert await service.has_action_step_up(rotated, STEP_UP_ACTION_MFA_ENROLL) is True
    # ...and the grant is NOT still sitting under the retired hash.
    assert await service.has_action_step_up(token, STEP_UP_ACTION_MFA_ENROLL) is False


async def test_a_pending_webauthn_ceremony_survives_rotation(engine: Engine) -> None:
    """RED when: _rekey_token_state stops calling ChallengeCache.rekey.

    Stranded, a passkey ceremony begun before the rotation can NEVER be finished — the challenge is
    single-use, so the user is dead-ended rather than able to retry.
    """
    service, token = await _service_and_token(engine)
    challenge = webauthn.new_challenge()
    service._webauthn_challenges.put((hash_token(token), "register"), "u-rot", challenge)

    rotated = await service._rotate_session_token(token)
    assert rotated is not None

    assert service._webauthn_challenges.pop((hash_token(token), "register")) is None
    carried = service._webauthn_challenges.pop((hash_token(rotated), "register"))
    assert carried is not None and carried.challenge == challenge


async def test_the_new_ip_dedupe_survives_rotation(engine: Engine) -> None:
    """RED when: _rekey_token_state stops moving _new_ip_seen.

    Stranded, the caller is charged a SECOND new-IP step-up (and a second audit row) for an address
    the session already re-verified from.
    """
    service, token = await _service_and_token(engine)
    service._new_ip_seen[hash_token(token)] = "10.11.12.13"

    rotated = await service._rotate_session_token(token)
    assert rotated is not None

    assert hash_token(token) not in service._new_ip_seen
    assert service._new_ip_seen.get(hash_token(rotated)) == "10.11.12.13"


def test_rekey_carries_the_ceremony_deadline_rather_than_refreshing_it() -> None:
    """RED when: ChallengeCache.rekey re-stamps the deadline instead of carrying it.

    A session rotation must not extend an in-flight ceremony's TTL — otherwise repeated rotation is a
    way to hold a challenge open indefinitely. Driven at the cache directly so the assertion is about
    the deadline value, not about timing.
    """
    now = [1000.0]
    cache = webauthn.ChallengeCache(ttl_seconds=120.0, clock=lambda: now[0])
    cache.put(("old", "register"), "u1", webauthn.new_challenge())
    before = cache._entries[("old", "register")].deadline

    now[0] += 60.0  # time passes; a refresh here would be visible
    assert cache.rekey("old", "new") == 1

    assert cache._entries[("new", "register")].deadline == before
    assert ("old", "register") not in cache._entries


def test_rekey_leaves_other_sessions_alone() -> None:
    """RED when: rekey moves entries it does not own (e.g. drops the token-hash predicate).

    One session's rotation must not disturb another's in-flight ceremony.
    """
    cache = webauthn.ChallengeCache(ttl_seconds=120.0, clock=lambda: 1000.0)
    cache.put(("mine", "register"), "u1", webauthn.new_challenge())
    cache.put(("theirs", "register"), "u2", webauthn.new_challenge())

    assert cache.rekey("mine", "moved") == 1

    assert cache.pop(("theirs", "register")) is not None, "a sibling session was disturbed"
    assert cache.pop(("moved", "register")) is not None
