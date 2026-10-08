# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 14.2.2 and 7.2.4 -- every reply whose body carries a live credential is served ``no-store``.

A session token, a staged TOTP seed, one-time recovery codes and an admin-issued temporary password
all reach a bearer client in a response body. None of those replies may sit in a proxy or browser
cache. Three of them set the header and four did not: ``POST /auth/login``, ``POST
/auth/negotiate``, ``POST /me/mfa/enroll`` and ``POST /users/{user_id}/reset-password`` (BACKLOG
#1185). Each then declared a ``_no_store_reply`` route dependency. Since BACKLOG #2372 none
declares anything: each response model subclasses ``CredentialReply``, and the engine's route class
adds ``security.no_store_reply`` to every route returning one, so a new route cannot forget it.

``tests/test_no_store_phi_coverage.py`` could not see them. Its classification arm examines a field
only when the field's NAME matches a rated store column, and the enroll reply returns the PL-3
``users.totp_secret`` as a field named ``secret``. So this module selects on a different key: the
credential field names themselves.

Two halves, and each needs the other. The first finds every route whose response model carries one
of the field names in ``_CREDENTIAL_FIELDS`` and pins that set, so a new route returning one reds
until it is driven here. The second drives every one of them through the real ASGI app with auth ON
and reads the header off the wire, so a route that drops the dependency reds even if the set is
unchanged.

Two more read the route table rather than the wire (BACKLOG #2372): every model holding a credential
field name must be marked, and every route returning a marked model must carry the no-store step.

**What this cannot see.** A credential returned under a new field name (``api_key``,
``refresh_token``) in a model nobody marked is neither served no-store nor caught here. Marking the
model is the one act left, and that shape rests on review.
"""

from __future__ import annotations

import base64
import functools
import inspect
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import fresh_totp
from fastapi import Depends
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import CredentialReply, CurrentUser, LoginResponse
from messagefoundry.api.security import carries_credential, no_store_reply, public_route
from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings, EgressSettings
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


def _is_credential_model(model: type[BaseModel]) -> bool:
    """Marked as a credential reply, or carrying a credential field name, or both."""
    return issubclass(model, CredentialReply) or bool(set(model.model_fields) & _CREDENTIAL_FIELDS)


def _credential_routes(routes: tuple[Any, ...] | list[Any]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for route in routes:
        if not isinstance(route, APIRoute):
            continue
        if any(_is_credential_model(m) for m in _response_models(route.response_model)):
            found |= {(method, route.path) for method in route.methods or set()}
    return found


def _declares_no_store(route: APIRoute) -> bool:
    return any(d.call is no_store_reply for d in route.dependant.dependencies)


def test_every_credential_model_is_marked() -> None:
    """BACKLOG #2372. A response model holding a credential field name must subclass
    ``CredentialReply``, because the mark is what makes the route class serve it no-store. The field
    names are the backstop for a model someone forgot to mark."""
    models = {
        m
        for route in _app_routes()
        if isinstance(route, APIRoute)
        for m in _response_models(route.response_model)
    }
    assert len(models) > 20, "the walk found too few response models to mean anything"
    unmarked = sorted(
        m.__name__
        for m in models
        if set(m.model_fields) & _CREDENTIAL_FIELDS and not issubclass(m, CredentialReply)
    )
    assert unmarked == [], (
        f"carry a credential field but do not subclass CredentialReply: {unmarked}"
    )


def test_every_credential_route_carries_the_no_store_step() -> None:
    """BACKLOG #2372. Read off the built route table, so it covers a route no test drives: every
    route whose response model is or contains a credential model has the ``no_store_reply`` step.
    A route added through ``include_router`` or with the credential model nested inside another
    model escapes the route class, and reds here."""
    routes = [r for r in _app_routes() if isinstance(r, APIRoute)]
    credential = [
        r
        for r in routes
        if any(_is_credential_model(m) for m in _response_models(r.response_model))
    ]
    assert len(credential) >= len(_EXPECTED), "control: the walk sees the credential routes"
    missing = sorted(r.path for r in credential if not _declares_no_store(r))
    assert missing == [], f"credential routes without the no-store step: {missing}"


def test_a_route_returning_a_credential_model_by_annotation_carries_the_step() -> None:
    """The escape the route class cannot see: ``response_model=None`` with an endpoint annotated to
    return a credential model. Read off each endpoint's return annotation instead."""
    returning = [
        route
        for route in _app_routes()
        if isinstance(route, APIRoute)
        and carries_credential(inspect.signature(route.endpoint, eval_str=True).return_annotation)
    ]
    assert len(returning) >= len(_EXPECTED), "control: the walk sees the credential handlers"
    missing = sorted(route.path for route in returning if not _declares_no_store(route))
    assert missing == [], f"handlers returning a credential model without no-store: {missing}"


class _Wrapped(BaseModel):
    """A model that holds a credential reply in a field rather than being one."""

    login: LoginResponse


def test_the_route_class_adds_the_step_with_nothing_declared() -> None:
    """The mechanism, on routes this file plants: a credential model gets the step whether the
    route names its response model or only annotates the return, and declares nothing else. A
    model that carries no credential gets none, so the step is not simply on every route."""
    app = create_app()

    async def _explicit() -> Any:
        raise AssertionError("never called")

    async def _inferred() -> LoginResponse:
        raise AssertionError("never called")

    async def _plain() -> CurrentUser:
        raise AssertionError("never called")

    app.post("/planted/explicit", response_model=LoginResponse)(public_route("test")(_explicit))
    app.post("/planted/inferred")(public_route("test")(_inferred))
    app.post("/planted/optional", response_model=LoginResponse | None)(
        public_route("test")(_explicit)
    )
    app.get("/planted/plain")(public_route("test")(_plain))
    app.post("/planted/nested", response_model=_Wrapped)(public_route("test")(_explicit))
    planted = {r.path: r for r in app.routes if isinstance(r, APIRoute) and "/planted/" in r.path}
    assert len(planted) == 5
    assert _declares_no_store(planted["/planted/nested"])
    assert _declares_no_store(planted["/planted/explicit"])
    assert _declares_no_store(planted["/planted/inferred"])
    assert _declares_no_store(planted["/planted/optional"])
    assert not _declares_no_store(planted["/planted/plain"])
    # Declared once, not twice, when a route also names the step itself.
    app.post(
        "/planted/twice", response_model=LoginResponse, dependencies=[Depends(no_store_reply)]
    )(public_route("test")(_explicit))
    (twice,) = [r for r in app.routes if isinstance(r, APIRoute) and r.path == "/planted/twice"]
    assert sum(d.call is no_store_reply for d in twice.dependant.dependencies) == 1


class _Page[T](BaseModel):
    """A pydantic generic, the shape the route class's docstring once said escapes the mark."""

    items: list[T]


def test_a_pydantic_generic_of_a_credential_model_carries_it() -> None:
    """A parametrized pydantic generic carries its argument in its fields, so the walk finds it."""
    assert carries_credential(_Page[LoginResponse])
    assert not carries_credential(_Page[CurrentUser]), "control: a plain argument is not marked"


async def test_a_raw_response_from_a_marked_route_is_still_no_store(engine: Engine) -> None:
    """The escape the vault re-read of ASVS 14.2.2 measured: FastAPI serves a ``Response`` the
    endpoint built itself as is, so the header ``no_store_reply`` set on FastAPI's own reply never
    reached it. The route class stamps the returned ``Response`` too. A raw reply from an unmarked
    route stays unstamped, so the stamp is not simply on every response."""
    service = await _service(engine, AuthSettings())
    app = create_app(engine, auth=service)

    async def _raw() -> Any:
        return JSONResponse({"token": "planted"}, headers={"Cache-Control": "max-age=600"})

    app.post("/planted/raw", response_model=LoginResponse)(public_route("test")(_raw))
    app.post("/planted/raw-plain", response_model=CurrentUser)(public_route("test")(_raw))
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        marked = await c.post("/planted/raw")
        plain = await c.post("/planted/raw-plain")
    assert marked.status_code == 200, marked.text
    assert marked.headers.get("cache-control") == "no-store"
    assert plain.status_code == 200, plain.text
    assert plain.headers.get("cache-control") == "max-age=600"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "credential_no_store.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def test_the_credential_route_set_is_pinned() -> None:
    """A new route returning a credential field reds here until it is added to ``_EXPECTED`` and
    driven below. A route that stops returning one reds too, so the pin cannot go stale."""
    found = _credential_routes(_app_routes())
    assert found == _EXPECTED, (
        f"credential-bearing routes changed. New: {sorted(found - _EXPECTED)}. "
        f"Gone: {sorted(_EXPECTED - found)}. A new one must return a CredentialReply and be driven below."
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
