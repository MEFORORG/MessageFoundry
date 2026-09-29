# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 14.2.2 and 7.2.4 -- every reply whose body carries a live credential is served ``no-store``.

A session token, a staged TOTP seed, one-time recovery codes and an admin-issued temporary password
all reach a bearer client in a response body. None of those replies may sit in a proxy or browser
cache. Three of them set the header and four did not: ``POST /auth/login``, ``POST
/auth/negotiate``, ``POST /me/mfa/enroll`` and ``POST /users/{user_id}/reset-password`` (BACKLOG
#1185). All seven now declare the ``_no_store_reply`` route dependency in ``api/auth_routes.py``.

``tests/test_no_store_phi_coverage.py`` could not see them. Its classification arm examines a field
only when the field's NAME matches a rated store column, and the enroll reply returns the PL-3
``users.totp_secret`` as a field named ``secret``. So this module selects on a different key: the
credential field names themselves.

Two halves, and each needs the other. The first finds every route whose response model carries one
of the field names in ``_CREDENTIAL_FIELDS`` and pins that set, so a new route returning one reds
until it is driven here. The second drives every one of them through the real ASGI app with auth ON
and reads the header off the wire, so a route that drops the dependency reds even if the set is
unchanged.

**What this cannot see.** It keys on a closed list of field NAMES, the same shape of blind spot it
covers in the PHI guard. A credential returned under a new name (``api_key``, ``refresh_token``) is
neither pinned nor driven until someone adds the name. That shape rests on review.
"""

from __future__ import annotations

import base64
import functools
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import fresh_totp
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import PW, _add, _auth, _client, _login, _reauth, _service
from tests.test_no_store_phi_coverage import _response_models

#: Response-model field names whose value is a live credential. A bearer token (``token``), a TOTP
#: seed (``secret``, and ``otpauth_uri``, which embeds the seed), a set of one-time recovery codes,
#: and a one-time temporary password.
_CREDENTIAL_FIELDS = frozenset(
    {"token", "secret", "otpauth_uri", "recovery_codes", "temp_password"}
)

#: Every credential-bearing route, pinned literally. Deliberately NOT derived from the walk below:
#: an expectation that shrinks with the thing it checks cannot fail.
_EXPECTED = frozenset(
    {
        ("POST", "/auth/login"),
        ("POST", "/auth/negotiate"),
        ("POST", "/me/reauth"),
        ("POST", "/auth/mfa-verify"),
        ("POST", "/me/mfa/enroll"),
        ("POST", "/me/mfa/confirm"),
        ("POST", "/users/{user_id}/reset-password"),
        # ADR 0197 Amendment A: account creation and the factor reset issue a generated credential.
        ("POST", "/users"),
        ("POST", "/users/{user_id}/reset-mfa"),
    }
)


@functools.cache
def _app_routes() -> tuple[Any, ...]:
    """One app for the two route-table tests. Neither mutates it, and each build costs a full
    ``create_app``."""
    return tuple(create_app().routes)


def _credential_routes(routes: tuple[Any, ...] | list[Any]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for route in routes:
        if not isinstance(route, APIRoute):
            continue
        if any(
            set(m.model_fields) & _CREDENTIAL_FIELDS for m in _response_models(route.response_model)
        ):
            found |= {(method, route.path) for method in route.methods or set()}
    return found


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "credential_no_store.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def test_the_credential_route_set_is_pinned() -> None:
    """A new route returning a credential field reds here until it is added to ``_EXPECTED`` and
    driven below. A route that stops returning one reds too, so the pin cannot go stale."""
    found = _credential_routes(_app_routes())
    assert found == _EXPECTED, (
        f"credential-bearing routes changed. New: {sorted(found - _EXPECTED)}. "
        f"Gone: {sorted(_EXPECTED - found)}. A new one must declare _no_store_reply and be driven below."
    )


def test_the_route_walk_can_see_a_credential_field() -> None:
    """Non-vacuity. The enroll reply is the case the PHI coverage guard's name-keyed arm misses, so
    this walk must select it by its ``secret`` field alone."""
    enroll = [r for r in _app_routes() if isinstance(r, APIRoute) and r.path == "/me/mfa/enroll"]
    assert len(enroll) == 1
    assert _credential_routes(enroll) == {("POST", "/me/mfa/enroll")}


async def test_every_credential_reply_is_no_store_on_the_wire(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive each credential-bearing route to a 200 with auth ON and read the served header.

    Asserts a 200 on every call first. A directive checked on a refusal proves nothing here: the
    header is set on the success path, and the refusal carries no credential."""
    # The calls run at machine speed, so the timing floors are off: the shipped 1 s sign-in to MFA
    # floor would refuse the verify below with a 401 (BACKLOG #2301).
    service = await _service(
        engine,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0,
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            login_rate_limit_enabled=False,
        ),
    )
    await _add(service, "adm", Role.ADMINISTRATOR)
    await _add(service, "mfa", Role.VIEWER)
    await _add(service, "target", Role.VIEWER)
    target = await service.store.get_user_by_username("target")
    assert target is not None
    served: dict[tuple[str, str], str | None] = {}

    def note(key: tuple[str, str], resp: httpx.Response, *, ok: int = 200) -> None:
        assert resp.status_code == ok, (key, resp.status_code, resp.text)
        served[key] = resp.headers.get("cache-control")

    async with _client(engine, service) as c:
        login = await _login(c, "adm")
        note(("POST", "/auth/login"), login)
        tok = login.json()["token"]

        r, tok = await _reauth(c, tok, purpose="admin_reset_password")
        note(("POST", "/me/reauth"), r)
        reset = await c.post(f"/users/{target.id}/reset-password", headers=_auth(tok))
        note(("POST", "/users/{user_id}/reset-password"), reset)
        assert reset.json()["temp_password"]

        r, tok = await _reauth(c, tok, purpose="admin_reset_mfa")
        reset_mfa = await c.post(f"/users/{target.id}/reset-mfa", headers=_auth(tok))
        note(("POST", "/users/{user_id}/reset-mfa"), reset_mfa)
        assert reset_mfa.json()["temp_password"], "a local account's factor reset issues one"

        created = await c.post(
            "/users",
            json={"username": "born", "roles": ["viewer"], "email": "born@example.org"},
            headers=_auth(tok),
        )
        note(("POST", "/users"), created, ok=201)
        assert created.json()["temp_password"]

        # The Kerberos leg needs a KDC. Stand in a successful outcome from the local sign-in seam,
        # so the route's own reply path, the one this module measures, runs unchanged.
        outcome = await service.login("adm", PW)
        assert outcome.ok

        async def _kerberos_ok(token: bytes, **_kw: Any) -> Any:
            return outcome

        monkeypatch.setattr(service, "authenticate_kerberos", _kerberos_ok)
        negotiate_header = {"Authorization": "Negotiate " + base64.b64encode(b"x").decode()}
        note(("POST", "/auth/negotiate"), await c.post("/auth/negotiate", headers=negotiate_header))

        mtok = (await _login(c, "mfa")).json()["token"]
        _r, mtok = await _reauth(c, mtok, purpose="mfa_enroll")
        enroll = await c.post("/me/mfa/enroll", headers=_auth(mtok))
        note(("POST", "/me/mfa/enroll"), enroll)
        secret = enroll.json()["secret"]
        _r, mtok = await _reauth(c, mtok, purpose="mfa_confirm")
        confirm = await c.post(
            "/me/mfa/confirm", json={"code": fresh_totp(secret)}, headers=_auth(mtok)
        )
        note(("POST", "/me/mfa/confirm"), confirm)
        recovery = confirm.json()["recovery_codes"]

        # A fresh sign-in owes the second factor; a recovery code satisfies it without a clock race.
        owing = (await _login(c, "mfa")).json()["token"]
        verify = await c.post("/auth/mfa-verify", json={"code": recovery[0]}, headers=_auth(owing))
        note(("POST", "/auth/mfa-verify"), verify)

        # Negative control: an auth reply with no credential in it is NOT stamped. Without this, a
        # change that stamped every response would keep the check above green while the per-route
        # dependency it measures stopped mattering.
        me = await c.get("/auth/me", headers=_auth(tok))
        assert me.status_code == 200
        assert me.headers.get("cache-control") is None

    assert set(served) == _EXPECTED, f"drove {sorted(served)}, expected {sorted(_EXPECTED)}"
    missing = sorted(f"{m} {p} -> {v!r}" for (m, p), v in served.items() if v != "no-store")
    assert missing == [], f"credential-bearing replies served without no-store: {missing}"
