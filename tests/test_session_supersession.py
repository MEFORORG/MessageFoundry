# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``AuthService.supersede_session`` and the federated flow that carries it (ASVS 7.2.4, BACKLOG #1146).

The console suite drives the three sign-in legs end to end. These pin the service contract those legs
rest on, where a route test cannot see it: which inputs are no-ops, that the no-ops write no audit row,
and that the federated flow stages a HASH and supersedes only after the IdP proof succeeded.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "supersede.db")
    yield s
    await s.close()


class _FakeLdap:
    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return None


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


async def _token(service: AuthService, username: str = "op") -> str:
    outcome = await service.login(username, PW)
    assert outcome.ok and outcome.token is not None
    return outcome.token


async def _live(service: AuthService, token: str) -> bool:
    return await service.identity_for_token(token, activity=False) is not None


async def _superseded(store: MessageStore) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for row in await store.list_audit():
        if row["action"] == "auth.session_revoked" and row["detail"]:
            detail = json.loads(str(row["detail"]))
            if detail.get("scope") == "superseded":
                out.append(detail)
    return out


async def test_supersede_revokes_only_the_presented_session_and_audits_it(
    store: MessageStore,
) -> None:
    service = await _service(store)
    prior, elsewhere, new = await _token(service), await _token(service), await _token(service)
    assert await service.supersede_session(prior, new_token=new, actor="op", client="10.0.0.5")
    assert not await _live(service, prior)
    assert await _live(service, elsewhere), "a whole-user revoke, not a supersession"
    assert await _live(service, new)
    rows = await _superseded(store)
    op = await store.get_user_by_username("op")
    assert op is not None
    assert rows == [{"scope": "superseded", "session": hash_token(prior)[:12], "user_id": op.id}]


async def test_a_prior_session_of_another_user_is_ended_and_named(store: MessageStore) -> None:
    # A shared workstation: another operator's session was in the browser. It can never be presented
    # from here again, so it is ended too -- and the row names whose it was, not only who signed in.
    service = await _service(store)
    theirs, mine = await _token(service, "other"), await _token(service, "op")
    assert await service.supersede_session(theirs, new_token=mine, actor="op")
    assert not await _live(service, theirs)
    other = await store.get_user_by_username("other")
    assert other is not None
    assert [r["user_id"] for r in await _superseded(store)] == [other.id]


@pytest.mark.parametrize("case", ["none", "empty", "identical", "unknown", "already_revoked"])
async def test_the_no_op_inputs_revoke_nothing_and_write_no_row(
    store: MessageStore, case: str
) -> None:
    service = await _service(store)
    new = await _token(service)
    dead = await _token(service)
    await service.logout(dead)
    prior: str | None = {
        "none": None,
        "empty": "",
        "identical": new,
        "unknown": "not-a-session-token",
        "already_revoked": dead,
    }[case]
    assert not await service.supersede_session(prior, new_token=new, actor="op")
    assert await _live(service, new)
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
    service = await _service(store, **_oidc_settings())
    prior = await _token(service)

    async def _proof(*_a: object, **_k: object) -> LoginOutcome:
        if ok:
            return await service.login("op", PW)
        return LoginOutcome(ok=False, error="federated sign-in failed", reason="claim_aud")

    monkeypatch.setattr(service, "authenticate_oidc", _proof)
    flow_id, url = await service.begin_oidc_login(
        client=None, public_origin="https://ops.example", prior_session=prior
    )
    state = dict(parse_qsl(urlsplit(url).query))["state"]
    outcome = await service.complete_oidc_login(
        flow_id=flow_id,
        state=state,
        code="authcode",
        client=None,
        public_origin="https://ops.example",
    )
    assert outcome.ok is ok
    assert await _live(service, prior) is not ok
    assert len(await _superseded(store)) == (1 if ok else 0)
