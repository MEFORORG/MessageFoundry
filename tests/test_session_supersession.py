# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Login-side session supersession in the service (ASVS 7.2.4, BACKLOG #1146).

A console sign-in passes the session token its browser presented as ``supersedes``, and the engine
ends that one session inside the new session's mint. The console suite drives the three legs end to
end. These pin what a route test cannot see:

* the ORDER against the per-user session cap -- superseding after the cap would let the cap evict
  another device's oldest session to make room for one that was about to go anyway;
* which inputs are no-ops, and that a no-op writes no audit row;
* that the federated flow stages a HASH and supersedes only when the IdP proof succeeds.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.oidc import FederatedPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)

_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@x",
    dn="CN=jdoe,DC=x",
    groups=frozenset({"cn=mf-ops,dc=x"}),
)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "supersede.db")
    yield s
    await s.close()


class _FakeLdap:
    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return _PRINCIPAL if username == "jdoe" else None


async def _service(store: MessageStore, **over: object) -> AuthService:
    settings: dict[str, object] = {"require_mfa": False}
    settings.update(over)
    service = AuthService(store, AuthSettings(**settings), ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    for name in ("op", "other"):
        user_id = await service.create_local_user(
            username=name,
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        user = await store.get_user(user_id)
        assert user is not None and user.password_hash is not None
        await store.set_password(
            user_id, password_hash=user.password_hash, must_change_password=False
        )
    return service


async def _token(service: AuthService, username: str = "op", supersedes: str | None = None) -> str:
    outcome = await service.login(username, PW, supersedes=supersedes)
    assert outcome.ok and outcome.token is not None
    return outcome.token


async def _live(service: AuthService, token: str) -> bool:
    return await service.identity_for_token(token, activity=False) is not None


async def _superseded(store: MessageStore) -> list[dict[str, object]]:
    """Each ``superseded`` row as its detail plus the row's ``actor``."""
    out: list[dict[str, object]] = []
    for row in await store.list_audit():
        if row["action"] == "auth.session_revoked" and row["detail"]:
            detail = json.loads(str(row["detail"]))
            if detail.get("scope") == "superseded":
                out.append({**detail, "actor": row["actor"]})
    return out


async def test_a_sign_in_ends_only_the_presented_session_and_audits_it(
    store: MessageStore,
) -> None:
    service = await _service(store)
    prior, elsewhere = await _token(service), await _token(service)
    new = await _token(service, supersedes=prior)
    assert not await _live(service, prior)
    assert await _live(service, elsewhere), "a whole-user revoke, not a supersession"
    assert await _live(service, new)
    assert await _superseded(store) == [
        {"scope": "superseded", "session": hash_token(prior)[:12], "actor": "op"}
    ]


async def test_superseding_at_the_session_cap_signs_no_other_device_out(
    store: MessageStore,
) -> None:
    # The review finding this pins: at the cap, a same-browser re-sign-in used to evict the OLDEST
    # session of another device as well as the one it replaced, because the cap ran first.
    service = await _service(store, max_sessions_per_user=3)
    devices = [await _token(service), await _token(service)]
    browser = await _token(service)  # the cap is now full: 3 of 3
    new = await _token(service, supersedes=browser)
    assert [await _live(service, t) for t in devices] == [True, True], "the cap evicted a device"
    assert not await _live(service, browser)
    assert await _live(service, new)


async def test_a_prior_session_of_another_user_is_ended_under_its_owner(
    store: MessageStore,
) -> None:
    # A shared workstation: another operator's session was in the browser. It can never be presented
    # from here again, so it is ended too. The row is filed under its OWNER, because
    # /me/security-events selects by actor: it belongs in their feed, and nothing of theirs belongs
    # in the feed of whoever signed in.
    service = await _service(store)
    theirs = await _token(service, "other")
    await _token(service, "op", supersedes=theirs)
    assert not await _live(service, theirs)
    rows = await _superseded(store)
    assert [r["actor"] for r in rows] == ["other"]
    assert all("user_id" not in r for r in rows)


async def test_a_lapsed_prior_at_the_cap_is_still_revoked_so_no_device_is_evicted(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Round-2 finding: a prior session over its idle limit but not yet lazily revoked still counts
    # toward the cap. Skipping it would let the cap evict a LIVE device in its place. The device
    # must be OLDER than the lapsed session and still live, or the cap would pick the lapsed row
    # anyway and the test could not fail.
    service = await _service(store, max_sessions_per_user=3, session_idle_timeout_minutes=30)
    clock = {"offset": 0.0}
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + clock["offset"])
    device = await _token(service)  # oldest, and kept live below
    browser = await _token(service)  # newer, and about to lapse
    clock["offset"] = 20 * 60
    assert await service.identity_for_token(device) is not None  # the device is in use
    clock["offset"] = 40 * 60  # browser idle 40 min: lapsed; device idle 20 min: live
    second = await _token(service)  # 3 of 3 unrevoked: device, browser, second
    await _token(service, supersedes=browser)
    assert [await _live(service, t) for t in (device, second)] == [True, True], (
        "the cap evicted a live device"
    )
    record = await store.get_session(hash_token(browser))
    assert record is not None and record.revoked_at is not None
    assert await _superseded(store) == [], "a lapsed session was recorded as superseded"


async def test_a_failed_sign_in_ends_nothing(store: MessageStore) -> None:
    service = await _service(store)
    prior = await _token(service)
    outcome = await service.login("op", "not-the-password", supersedes=prior)
    assert not outcome.ok
    assert await _live(service, prior)
    assert await _superseded(store) == []


@pytest.mark.parametrize("case", ["none", "empty", "unknown", "already_revoked"])
async def test_the_no_op_inputs_revoke_nothing_and_write_no_row(
    store: MessageStore, case: str
) -> None:
    service = await _service(store)
    dead = await _token(service)
    await service.logout(dead)
    prior: str | None = {
        "none": None,
        "empty": "",
        "unknown": "not-a-session-token",
        "already_revoked": dead,
    }[case]
    await _token(service, supersedes=prior)
    assert await _superseded(store) == []


@pytest.mark.parametrize(
    ("case", "shift_minutes"),
    # Each case trips exactly ONE of the two liveness limits, so each guard is measured alone:
    # past the 60-minute absolute cap but inside the 90-minute idle window, and the reverse.
    [("absolute_expired", 61), ("idle_expired", 31)],
)
async def test_a_session_already_over_is_not_recorded_as_superseded(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, case: str, shift_minutes: int
) -> None:
    # Over but not yet lazily revoked. It had already ended, so the trail must not say a sign-in
    # ended it.
    over = (
        {"session_absolute_hours": 1, "session_idle_timeout_minutes": 90}
        if case == "absolute_expired"
        else {"session_absolute_hours": 12, "session_idle_timeout_minutes": 30}
    )
    service = await _service(store, **over)
    prior = await _token(service)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + shift_minutes * 60)
    await _token(service, supersedes=prior)
    assert await _superseded(store) == []


async def test_the_bearer_default_supersedes_nothing(store: MessageStore) -> None:
    # POST /auth/login passes no `supersedes`; a bearer caller may run several sessions at once.
    service = await _service(store)
    first = await _token(service)
    await _token(service)
    assert await _live(service, first)
    assert await _superseded(store) == []


# --- the federated leg: the start stages a hash, the callback supersedes on success only ----------


def _oidc_settings() -> dict[str, object]:
    return {
        "ad_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
    }


async def test_the_flow_stages_the_hash_never_the_token(store: MessageStore) -> None:
    service = await _service(store, **_oidc_settings())
    prior = await _token(service)
    flow_id, _url = await service.begin_oidc_login(
        client="10.0.0.5", public_origin="https://ops.example", prior_session=prior
    )
    assert service._oidc_flows is not None
    flow = service._oidc_flows.pop(flow_id)
    assert flow is not None
    assert flow.prior_session_hash == hash_token(prior)
    assert prior not in repr(flow)
    assert await _live(service, prior), "the START leg must revoke nothing"


@pytest.mark.parametrize("ok", [True, False])
async def test_the_callback_supersedes_only_after_the_proof_succeeds(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, ok: bool
) -> None:
    # The IdP exchange is replaced at the one seam the service calls. The directory resolve, the
    # AD mirror row and the mint all run for real, so the supersession is reached the way it is live.
    service = await _service(store, **_oidc_settings())
    await service.set_ad_group_map([("cn=mf-ops,dc=x", Role.OPERATOR.value)], actor="admin")
    prior = await _token(service)

    def _exchange(*_a: object, **_k: object) -> FederatedPrincipal:
        return FederatedPrincipal(
            username="jdoe" if ok else "stranger",
            subject="S-1-5-21-fed",
            issuer="https://idp.example",
            amr=("pwd", "mfa"),
            acr=None,
            expires_at=time.time() + 600,
        )

    monkeypatch.setattr(service, "_exchange_and_validate", _exchange)
    flow_id, url = await service.begin_oidc_login(
        client=None, public_origin="https://ops.example", prior_session=prior
    )
    outcome = await service.complete_oidc_login(
        flow_id=flow_id,
        state=dict(parse_qsl(urlsplit(url).query))["state"],
        code="authcode",
        client=None,
        public_origin="https://ops.example",
    )
    assert outcome.ok is ok, outcome
    assert await _live(service, prior) is not ok
    assert len(await _superseded(store)) == (1 if ok else 0)
