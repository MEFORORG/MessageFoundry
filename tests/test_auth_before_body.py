# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The check that refuses a caller with no identity before a request body is read (vault BACKLOG
#2739).

FastAPI reads and decodes a declared body before it solves a route's dependencies, and the sign-in
check is a dependency. ``messagefoundry.api.security.AuthenticatedBeforeBodyRoute`` runs the
authentication step of a route's gate, and the guards ahead of it, before FastAPI reads the body.
``tests/test_preauth_malformed_body.py`` pins what an unauthenticated caller sees on every
body-taking operation. This file tests the mechanism.

THE CONTROL APP. Most cases compare the live app with ``_served_by_fastapi_alone``: the same app,
built by the same ``create_app`` over the same engine and service, with every route's handler
rebuilt by FastAPI's own route class. That is the engine as it answered before the change, so "the
same answer as the gate gave" is measured against the gate and not against a copy written here.

WHAT THIS DOES NOT SEE, at least:

* A gate reached through ``include_router`` with router-level dependencies. The engine includes no
  router. A route on one would be served by that router's route class.
* A gate that is a sub-dependency of another dependency. ``scripts/security/route_gates.py`` reads
  top-level dependencies only, and so does the route class.
* A federated (OIDC) sign-in. Its session is the same bearer token the local and Kerberos cases
  below carry, so it is not driven separately.
* The listener. Requests go through ``httpx.ASGITransport``, so no uvicorn answer is measured.
"""

from __future__ import annotations

import base64
import collections
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from _totp_clock import fresh_totp
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute, request_response
from pydantic import BaseModel

from messagefoundry.api import create_app
from messagefoundry.api import security as api_security
from messagefoundry.api.auth_routes import _no_store_reply
from messagefoundry.api.security import (
    AuthenticatedBeforeBodyRoute,
    before_body_of,
    require,
    require_service_cert,
    steps_before_body,
)
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, SecuritySettings
from messagefoundry.config.tls_policy import HopDisposition
from messagefoundry.pipeline import Engine
from scripts.security import route_gates
from tests._admin_account import create_local_user_chosen
from tests.test_api_tls import _ISSUER, _peercert, _wrap_with_cert
from tests.test_directory_login_step_up_seed import _service as _directory_service
from tests.test_preauth_malformed_body import _ARMS as _PROBES
from tests.test_preauth_malformed_body import _JSON

PW = "a-strong-test-passphrase"
_PEER = ("127.0.0.1", 123)

# ``_PROBES`` is the four probes tests/test_preauth_malformed_body.py sends, imported and not
# copied, so the two files cannot come to measure different bytes.
#: A request with no body problem: nothing for FastAPI to parse, so the gate is what answers.
_NO_BODY: tuple[bytes, dict[str, str]] = (b"", {})

#: One gated JSON route with a body that is cheap to reach and changes nothing. With ``[ai]`` at
#: its default the handler answers 409, which shows the gate passed AND the handler ran.
_CHAT = "/ai/chat"
_CHAT_BODY = b'{"prompt": "synthetic"}'
_HANDLER_RAN = 409
_REFUSED = b'{"detail":"not authenticated"}'
_CERT_REFUSED = b'{"detail":"client certificate not authorized"}'

_Fingerprint = tuple[int, tuple[tuple[bytes, bytes], ...], bytes]


def _fingerprint(response: httpx.Response) -> _Fingerprint:
    """Everything a caller can read off a response: the status, every header in order, the bytes."""
    return response.status_code, tuple(response.headers.raw), response.content


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "auth_before_body.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, **settings: Any) -> AuthService:
    """Sign-in rate limiting and write pacing off, so one case's requests cannot refuse another's.
    ``require_mfa`` off, so a local account owes no factor and the gates past sign-in are open."""
    service = AuthService(
        engine.store,
        AuthSettings(
            login_rate_limit_enabled=False,
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            **settings,
        ),
    )
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    """An onboarded local account: the password chosen, no rotation owed, the whole estate in scope."""
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value for role in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    return user_id


def _client(app: Any, *, peer: tuple[str, int] = _PEER) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=peer, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _sign_in(app: FastAPI, username: str) -> dict[str, str]:
    """The bearer header of a session opened through ``POST /auth/login`` from ``_PEER``."""
    async with _client(app) as client:
        response = await client.post(
            "/auth/login", json={"username": username, "password": PW, "provider": "local"}
        )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _served_by_fastapi_alone(app: FastAPI) -> FastAPI:
    """THE CONTROL APP: ``app`` with every route answering as FastAPI's own route class answers.

    ``APIRoute.get_route_handler`` is the method the engine's route class overrides. Calling the
    base method on each route and installing the result is the route as it was served before the
    change, with every middleware, exception handler and dependency left exactly as it is."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            route.app = request_response(APIRoute.get_route_handler(route))
    return app


def _live_and_control(build: Callable[[], FastAPI]) -> tuple[FastAPI, FastAPI]:
    """Two apps from one recipe: the live one, and the control served by FastAPI alone."""
    return build(), _served_by_fastapi_alone(build())


def _api_gate(route: APIRoute) -> Callable[..., Any] | None:
    """The route's JSON API gate, read by ``route_gates`` and NOT by the engine's own marker, so
    the two derivations can disagree. ``None`` for no gate and for the console's ``require_ui*``."""
    for dependency in route.dependant.dependencies:
        found = route_gates.gate_of(dependency.call)
        if found is not None:
            return None if found[0].startswith("require_ui") else dependency.call
    return None


def _fastapi_own_handler(route: APIRoute) -> bool:
    """Whether the route would be served by FastAPI's handler with nothing in front of it."""
    name = route.get_route_handler().__qualname__
    return name == APIRoute.get_route_handler(route).__qualname__


def _uncovered(app: FastAPI) -> list[str]:
    """Every JSON-API-gated route the early check does not stand in front of, and why."""
    problems: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        gate = _api_gate(route)
        if gate is None:
            continue
        steps = steps_before_body(route.dependant)
        if not isinstance(route, AuthenticatedBeforeBodyRoute):
            problems.append(f"{route.path}: served by {type(route).__name__}")
        elif not steps or steps[-1][0] is not gate:
            problems.append(f"{route.path}: its gate carries no step that answers before the body")
        elif _fastapi_own_handler(route):
            problems.append(f"{route.path}: FastAPI's own handler serves it")
    return problems


# --- 1. Uniform and structural -------------------------------------------------------------------


class _Body(BaseModel):
    value: int


async def test_every_gated_json_route_is_covered_with_no_list_kept_by_hand(engine: Engine) -> None:
    app = create_app(engine, auth=await _service(engine), serve_ui=True, oidc_enabled=True)
    routes = [route for route in app.routes if isinstance(route, APIRoute)]
    gated = [route for route in routes if _api_gate(route) is not None]
    with_body = [route for route in gated if route.body_field is not None]
    # Measured 2026-10-02: 100 gated JSON routes, 34 of them with a declared body.
    assert len(gated) >= 90 and len(with_body) >= 30, (len(gated), len(with_body))
    assert _uncovered(app) == []
    # Every route on the app is built by the class, the console's included: nothing opts in.
    assert {type(route) for route in routes} == {AuthenticatedBeforeBodyRoute}


def require_unmarked(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """A gate factory in the closure shape ``route_gates.gate_of`` reads, written the way a new
    ``require_*`` would be if its author forgot the step that answers before the body."""

    async def dependency(request: Request) -> Identity:
        assert permissions
        raise HTTPException(401, "not authenticated")

    return dependency


_SESSION_GATE = require()
_UNMARKED_GATE = require_unmarked()


async def _session_gated(body: _Body, identity: Identity = Depends(_SESSION_GATE)) -> None:
    return None


async def _unmarked_gated(body: _Body, identity: Identity = Depends(_UNMARKED_GATE)) -> None:
    return None


async def test_a_gated_route_the_check_does_not_cover_is_named(engine: Engine) -> None:
    """THE CONTROL for the case above. Each planted route is gated, takes a body, and is missed by
    the early check in a different way. ``_uncovered`` names both."""
    app = create_app(engine, auth=await _service(engine))
    assert _uncovered(app) == []

    app.router.add_api_route(
        "/planted/plain-class", _session_gated, methods=["POST"], route_class_override=APIRoute
    )
    app.post("/planted/unmarked-gate")(_unmarked_gated)
    assert _uncovered(app) == [
        "/planted/plain-class: served by APIRoute",
        "/planted/unmarked-gate: its gate carries no step that answers before the body",
    ]


async def test_every_dependency_ahead_of_a_gate_is_accounted_for(engine: Engine) -> None:
    """A dependency that runs BEFORE the gate answers first today. So the early check has to run
    it first too, or a caller with no session gets a different answer than the gate's own flow
    gives. Each one is either marked ``answers_before_body`` or is on the short list below of
    dependencies read and found unable to refuse. A new kind fails here until someone reads it."""
    cannot_refuse = {_no_store_reply}
    app = create_app(engine, auth=await _service(engine), serve_ui=True, oidc_enabled=True)
    marked: set[str] = set()
    skipped: set[str] = set()
    unread: set[str] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute) or _api_gate(route) is None:
            continue
        for dependency in route.dependant.dependencies:
            call = dependency.call
            assert call is not None
            found = before_body_of(call)
            if found is not None and found.authenticates:
                break
            if found is not None:
                marked.add(call.__qualname__)
            elif call in cannot_refuse:
                skipped.add(call.__qualname__)
            else:
                unread.add(f"{route.path}: {call.__qualname__}")
    assert not unread, unread
    # Non-vacuous: both kinds exist on the live app, so both arms above ran.
    assert marked == {"_get_engine", "_service"}
    assert skipped == {"_no_store_reply"}


# --- 5. Ungated routes and the console are untouched ----------------------------------------------


async def test_a_route_with_no_json_gate_is_served_by_fastapis_own_handler(engine: Engine) -> None:
    app = create_app(engine, auth=await _service(engine), serve_ui=True, oidc_enabled=True)
    ungated: list[str] = []
    console: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or _api_gate(route) is not None:
            continue
        assert steps_before_body(route.dependant) == (), route.path
        assert _fastapi_own_handler(route), route.path
        (console if route.path.startswith("/ui") else ungated).append(route.path)
    # Sign-in parses a body from a caller with no session by design, and it sits behind a guard the
    # early check knows. With no gate after that guard, the check stays out of the way.
    assert "/auth/login" in ungated and "/auth/negotiate" in ungated and "/health" in ungated
    assert len(console) >= 100, len(console)
    # The control: a gated JSON route is NOT served by FastAPI's own handler.
    gated = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == _CHAT)
    assert not _fastapi_own_handler(gated)


# --- 2. The answer is the same answer -------------------------------------------------------------


def _refuse_phi_reads(app: FastAPI) -> FastAPI:
    app.state.phi_read_hop_disposition = HopDisposition.REFUSE
    return app


async def _unauthenticated_answers(
    app: FastAPI, operations: list[tuple[str, str]], probes: dict[str, tuple[bytes, dict[str, str]]]
) -> dict[tuple[str, str, str], _Fingerprint]:
    answers: dict[tuple[str, str, str], _Fingerprint] = {}
    async with _client(app) as client:
        for method, path in operations:
            url = route_gates.concrete_path(path)
            for probe, (body, headers) in probes.items():
                response = await client.request(method, url, content=body, headers=headers)
                answers[method, path, probe] = _fingerprint(response)
    return answers


@pytest.mark.parametrize(
    ("state", "statuses"),
    [
        # Every gate refuses a caller with no identity. /service/identity is the cert plane's 401.
        ("signed out", {401}),
        # ``_get_engine`` sits ahead of the gate on most routes and answers first. The rest refuse.
        ("no engine attached", {401, 503}),
        # Fail closed: ``_service`` answers on the account routes, the gate itself on the others.
        ("no auth service attached", {401, 503}),
        # The PHI-read hop refusal answers ahead of sign-in inside ``require_phi_read``.
        ("PHI reads refused on this hop", {401, 403}),
    ],
)
async def test_the_early_refusal_is_the_gates_own_answer_byte_for_byte(
    engine: Engine, state: str, statuses: set[int]
) -> None:
    """For a caller with no identity, on EVERY gated JSON operation and in each app state where
    something other than the gate can answer first: the live app's answer to each probe is the
    control app's answer to a request with no body, down to the status, every header and every
    byte. So the early check gives the answer the route's own gate flow gives, and nothing in it
    says whether the body parsed or whether the route takes one."""
    service = None if state == "no auth service attached" else await _service(engine)

    def build() -> FastAPI:
        app = create_app(None if state == "no engine attached" else engine, auth=service)
        return _refuse_phi_reads(app) if state.startswith("PHI") else app

    live, control = _live_and_control(build)
    operations = [
        (row.method, row.path)
        for row in route_gates.gated_http_rows(live)
        if not (row.gate or "").startswith("require_ui")
    ]
    assert len(operations) >= 90, len(operations)

    reference = await _unauthenticated_answers(control, operations, {"no body": _NO_BODY})
    measured = await _unauthenticated_answers(live, operations, {"no body": _NO_BODY, **_PROBES})
    different = {
        key: (answer, reference[key[0], key[1], "no body"])
        for key, answer in measured.items()
        if answer != reference[key[0], key[1], "no body"]
    }
    assert not different, different
    assert {status for status, _headers, _body in reference.values()} == statuses

    if state == "signed out":
        # The reference is the refusal this file thinks it is, and it challenges for nothing.
        assert {body for _status, _headers, body in reference.values()} == {_REFUSED, _CERT_REFUSED}
        names = {name.lower() for _s, headers, _b in reference.values() for name, _ in headers}
        assert b"www-authenticate" not in names
        # THE CONTROL: with FastAPI's own route class the same probes DO change the answer, on the
        # routes that declare a body. That difference is what the comparison above can see.
        old = await _unauthenticated_answers(control, operations, _PROBES)
        told_apart = {
            (method, path)
            for (method, path, _probe), answer in old.items()
            if answer != reference[method, path, "no body"]
        }
        assert len(told_apart) >= 30, len(told_apart)


async def test_an_overridden_gate_decides_in_place_of_the_early_check(engine: Engine) -> None:
    """``dependency_overrides`` replaces a dependency where FastAPI runs it. The early check
    stands aside for an overridden one, or a gate an embedder replaced would still refuse first.
    An override is set in process, so it is no way in from the wire."""
    app = create_app(engine, auth=await _service(engine))
    route = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == _CHAT)
    gate = _api_gate(route)
    assert gate is not None
    async with _client(app) as client:
        refused = await client.post(_CHAT, content=_CHAT_BODY, headers=_JSON)
        assert (refused.status_code, refused.content) == (401, _REFUSED)
        app.dependency_overrides[gate] = lambda: api_security._SYSTEM_IDENTITY
        ran = await client.post(_CHAT, content=_CHAT_BODY, headers=_JSON)
        parsed = await client.post(_CHAT, content=_PROBES["malformed JSON"][0], headers=_JSON)
    assert (ran.status_code, parsed.status_code) == (_HANDLER_RAN, 422)


# --- 3. Nothing is charged twice ------------------------------------------------------------------

#: Every call the gates make that reads or writes something countable, on the service and on the
#: store. ``_audit`` is the one writer of an audit row, so it counts rows whichever method asked.
_SERVICE_CALLS = (
    "identity_for_token",
    "identity_for_cert_user_id",
    "must_enrol_before_rotating",
    "mfa_satisfied",
    "password_change_owes_factor",
    "factor_binding_is_blocked",
    "audit_mfa_denied",
    "audit_permission_denied",
    "audit_permission_granted",
    "allow_admin_write",
    "allow_phi_read",
    "flag_new_client_ip",
    "has_recent_step_up",
    "has_action_step_up",
    "_audit",
)
_STORE_CALLS = ("get_session", "touch_session", "revoke_session")
#: The calls that are a charge, a row or a spent grant. One request makes each at most once.
_ONCE = (
    "identity_for_token",
    "touch_session",
    "audit_mfa_denied",
    "audit_permission_denied",
    "audit_permission_granted",
    "allow_admin_write",
    "allow_phi_read",
    "flag_new_client_ip",
    "has_action_step_up",
    "_audit",
)


def _count_calls(monkeypatch: pytest.MonkeyPatch, service: AuthService) -> collections.Counter[str]:
    tally: collections.Counter[str] = collections.Counter()

    def counted(target: object, name: str) -> None:
        original = getattr(target, name)

        # Counts at the call. For an async method the caller awaits what this returns.
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tally[name] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(target, name, wrapper)

    for name in _SERVICE_CALLS:
        counted(service, name)
    for name in _STORE_CALLS:
        counted(service.store, name)
    return tally


def _gate_twice(app: FastAPI) -> FastAPI:
    """A WRONG early check, for the control: it runs the route's whole gate ahead of the body,
    drops what the gate said, and FastAPI then runs the gate again as the dependency. A refusal
    is charged twice too. This is the double charge the counters must see."""

    def handler_for(route: APIRoute, gate: Callable[..., Any]) -> Callable[[Request], Any]:
        own = APIRoute.get_route_handler(route)

        async def twice(request: Request) -> Any:
            with contextlib.suppress(HTTPException):
                await gate(request)
            return await own(request)

        return twice

    for route in app.routes:
        if isinstance(route, APIRoute) and (gate := _api_gate(route)) is not None:
            route.app = request_response(handler_for(route, gate))
    return app


_WRONG_SHAPE = _PROBES["valid JSON, wrong shape"]
_MALFORMED = _PROBES["malformed JSON"]
#: ``(what, method, path, body probe, who)``. A wrong-shape body parses, so the gate runs in full
#: and FastAPI then refuses the body: every gate family is driven with no handler ever running.
_SCENARIOS: list[tuple[str, str, str, tuple[bytes, dict[str, str]], str]] = [
    ("no credential", "POST", _CHAT, (_CHAT_BODY, _JSON), "nobody"),
    ("a token no session holds", "POST", _CHAT, (_CHAT_BODY, _JSON), "stranger"),
    ("require, granted", "POST", _CHAT, _WRONG_SHAPE, "admin"),
    ("require, the handler runs", "POST", _CHAT, (_CHAT_BODY, _JSON), "admin"),
    ("require, permission denied", "POST", _CHAT, _WRONG_SHAPE, "viewer"),
    ("require, a factor is owed", "POST", _CHAT, _WRONG_SHAPE, "pending"),
    ("require_paced", "POST", "/statistics/reset", _WRONG_SHAPE, "admin"),
    ("require_step_up", "POST", "/roles/custom", _WRONG_SHAPE, "admin"),
    ("require_step_up, denied", "POST", "/roles/custom", _WRONG_SHAPE, "viewer"),
    ("require_step_up_action", "PATCH", "/users/" + "0" * 32, _WRONG_SHAPE, "admin"),
    ("require_reauth_only_action", "POST", "/me/mfa/confirm", _WRONG_SHAPE, "admin"),
    ("require_phi_read", "GET", "/messages", _NO_BODY, "admin"),
]


async def test_one_request_charges_each_side_effect_once(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every countable thing a gate does on a refusal and on a success, per request, with the early
    check and without it. The two tallies are equal in every scenario, so the early check adds no
    audit row, no pacing or PHI-read charge, no new-address signal, no spent grant and no second
    session lookup. The one difference there is to find is pinned in the next case."""
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    await _add(service, "viewer", Role.VIEWER)
    # An account with a factor enrolled: a fresh password sign-in is a session that owes it.
    pending_id = await _add(service, "pending", Role.ADMINISTRATOR)
    pending = await service.identity_for_user_id(pending_id)
    setup = await service.login("pending", PW)
    assert pending is not None and setup.token is not None
    secret = (await service.begin_mfa_enrollment(pending)).secret
    assert (await service.confirm_mfa_enrollment(pending, fresh_totp(secret), token=setup.token)).ok
    live, control = _live_and_control(lambda: create_app(engine, auth=service))
    twice = _gate_twice(create_app(engine, auth=service))
    who = {
        "nobody": {},
        "stranger": {"Authorization": "Bearer no-session-holds-this"},
        "admin": await _sign_in(live, "admin"),
        "viewer": await _sign_in(live, "viewer"),
        "pending": await _sign_in(live, "pending"),
    }
    tally = _count_calls(monkeypatch, service)

    async def one_request(
        app: FastAPI, scenario: tuple[str, str, str, tuple[bytes, dict[str, str]], str]
    ) -> tuple[int, dict[str, int]]:
        _what, method, path, (body, headers), caller = scenario
        tally.clear()
        async with _client(app) as client:
            response = await client.request(
                method, path, content=body, headers={**headers, **who[caller]}
            )
        return response.status_code, dict(tally)

    seen: collections.Counter[str] = collections.Counter()
    doubled: collections.Counter[str] = collections.Counter()
    for scenario in _SCENARIOS:
        what = scenario[0]
        before = await one_request(control, scenario)
        after = await one_request(live, scenario)
        assert after == before, (what, after, before)
        over = {name: count for name, count in after[1].items() if name in _ONCE and count > 1}
        assert not over, (what, over)
        seen.update(after[1])
        wrong_status, wrong = await one_request(twice, scenario)
        assert wrong_status == after[0], what
        doubled.update({name: n for name, n in wrong.items() if n == 2 * after[1].get(name, 0)})

    # Non-vacuous: the scenarios drove every charge at least once.
    for name in _ONCE:
        assert seen[name] >= 1, (name, dict(seen))
    # THE CONTROL: the same counters over a check that runs the gate twice see every charge twice.
    for name in _ONCE:
        assert doubled[name] >= 1, (name, dict(doubled))


async def test_a_signed_in_caller_pays_one_session_lookup_whatever_the_body(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE ONE COST THE EARLY CHECK ADDS. A signed-in caller whose body does not parse used to be
    answered by the parser with no session read at all. The session is now read first, once, and
    its idle clock moves as it does for any request. No row, no charge and no grant goes with it."""
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    live, control = _live_and_control(lambda: create_app(engine, auth=service))
    bearer = await _sign_in(live, "admin")
    tally = _count_calls(monkeypatch, service)

    async def post(app: FastAPI, body: bytes) -> tuple[int, dict[str, int]]:
        tally.clear()
        async with _client(app) as client:
            response = await client.post(_CHAT, content=body, headers={**_JSON, **bearer})
        return response.status_code, dict(tally)

    lookup = {"identity_for_token": 1, "get_session": 1, "touch_session": 1}
    assert await post(control, _MALFORMED[0]) == (422, {})
    assert await post(live, _MALFORMED[0]) == (422, lookup)
    # A body that parses: one lookup by the early check, none by the gate, which takes the carried
    # identity. The second ``get_session`` is the factor gate's own read, there before the change.
    status, parsed = await post(live, _CHAT_BODY)
    assert status == _HANDLER_RAN
    assert await post(control, _CHAT_BODY) == (status, parsed)
    assert parsed["identity_for_token"] == 1 and parsed["touch_session"] == 1


# --- 4. Authenticated behaviour is unchanged ------------------------------------------------------


async def test_a_signed_in_caller_gets_what_it_got_before_on_every_body_route(
    engine: Engine,
) -> None:
    """Every gated JSON operation that declares a body, all four probes, signed in as an
    Administrator: the live app and the control app give the same response, byte for byte. The
    422 and the 400 the parser gives a signed-in caller are among them."""
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    live, control = _live_and_control(lambda: create_app(engine, auth=service))
    bearer = await _sign_in(live, "admin")
    declared = {
        (method, route.path)
        for route in live.routes
        if isinstance(route, APIRoute) and route.body_field is not None
        for method in route.methods or ()
    }
    operations = [
        (row.method, row.path)
        for row in route_gates.gated_http_rows(live)
        if (row.method, row.path) in declared
    ]
    assert len(operations) >= 30, len(operations)

    statuses: collections.Counter[tuple[str, int]] = collections.Counter()
    async with _client(live) as new, _client(control) as old:
        for method, path in operations:
            url = route_gates.concrete_path(path)
            for probe, (body, headers) in _PROBES.items():
                sent = {**headers, **bearer}
                before = await old.request(method, url, content=body, headers=sent)
                after = await new.request(method, url, content=body, headers=sent)
                assert _fingerprint(after) == _fingerprint(before), (method, path, probe)
                # No handler ran: none of these bodies is one a route accepts.
                assert after.status_code >= 400, (method, path, probe, after.status_code)
                statuses[probe, after.status_code] += 1
    assert statuses["malformed JSON", 422] == len(operations)
    assert statuses["undecodable bytes", 400] == len(operations)


def _request(
    app: FastAPI, headers: dict[str, str] | None = None, *, scope: dict[str, object] | None = None
) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": _CHAT,
            "query_string": b"",
            "headers": raw,
            "client": _PEER,
            "app": app,
            **(scope or {}),
        }
    )


async def test_the_carried_identity_is_spent_once_and_cannot_be_planted(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The early check hands the gate the identity it resolved. Only a value this module built,
    under the session key, in the ASGI scope, is taken, and the gate that takes it removes it."""
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    app = create_app(engine, auth=service)
    bearer = await _sign_in(app, "admin")
    tally = _count_calls(monkeypatch, service)
    session_key, cert_key = api_security._CARRIED_SESSION, api_security._CARRIED_CERT
    gate = require()

    # The round trip: one lookup, the gate takes the carried identity, and it is gone afterwards.
    request = _request(app, bearer)
    await api_security._authenticate_session_before_body(request)
    assert isinstance(request.scope[session_key], api_security._Carried)
    identity = await gate(request)
    assert identity.username == "admin" and session_key not in request.scope
    assert tally["identity_for_token"] == 1
    # Spent: the same gate asked again on the same request does its own lookup.
    assert (await gate(request)).username == "admin" and tally["identity_for_token"] == 2

    # Nothing but this module's own class is taken. Each of these is a caller with NO token.
    system = api_security._SYSTEM_IDENTITY
    planted: list[object] = [
        system,
        {"identity": system},
        SimpleNamespace(identity=system),
        "system",
    ]
    for value in planted:
        with pytest.raises(HTTPException) as refused:
            await gate(_request(app, scope={session_key: value}))
        assert refused.value.status_code == 401, value
    # The cert plane's carry does not satisfy a session gate, nor the session's a cert gate.
    with pytest.raises(HTTPException) as refused:
        await gate(_request(app, scope={cert_key: api_security._Carried(system)}))
    assert refused.value.status_code == 401
    with pytest.raises(HTTPException) as refused:
        await require_service_cert()(
            _request(app, scope={session_key: api_security._Carried(system)})
        )
    assert refused.value.status_code == 401
    # THE CONTROL: the real thing under the right key IS taken, with no lookup, so the refusals
    # above are the check and not a gate that refuses everything.
    lookups = tally["identity_for_token"]
    planted_request = _request(app, bearer, scope={session_key: api_security._Carried(identity)})
    assert await gate(planted_request) is identity
    assert tally["identity_for_token"] == lookups

    # And the wire cannot name the key: a header and a query parameter of that name are just that.
    async with _client(app) as client:
        response = await client.post(
            f"{_CHAT}?{session_key}=system",
            content=_CHAT_BODY,
            headers={**_JSON, session_key: "system"},
        )
    assert (response.status_code, response.content) == (401, _REFUSED)


# --- 7. Every credential form the gate accepts -----------------------------------------------------


async def _post_chat(app: Any, headers: dict[str, str], *, peer: tuple[str, int] = _PEER) -> Any:
    """``(the well-formed body's answer, the malformed body's answer)`` for one caller."""
    async with _client(app, peer=peer) as client:
        good = await client.post(_CHAT, content=_CHAT_BODY, headers={**_JSON, **headers})
        bad = await client.post(_CHAT, content=_MALFORMED[0], headers={**_JSON, **headers})
    return _fingerprint(good), _fingerprint(bad)


async def _assert_accepted(live: Any, control: Any, headers: dict[str, str], **kw: Any) -> None:
    """A caller the gate accepts is never refused early: its well-formed request reaches the
    handler, its malformed one reaches the parser, and both answers are the control app's."""
    good, bad = await _post_chat(live, headers, **kw)
    assert (good[0], bad[0]) == (_HANDLER_RAN, 422)
    assert (good, bad) == await _post_chat(control, headers, **kw)


async def test_a_local_session_token_is_accepted(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    live, control = _live_and_control(lambda: create_app(engine, auth=service))
    bearer = await _sign_in(live, "admin")
    await _assert_accepted(live, control, bearer)
    # The same token where the JSON gate does not read it is no credential, before and after.
    token = bearer["Authorization"].removeprefix("Bearer ")
    for cookie in ("mf_session", "__Host-mf_session", "__Secure-mf_session"):
        answers = await _post_chat(live, {"Cookie": f"{cookie}={token}"})
        assert [(status, body) for status, _headers, body in answers] == [(401, _REFUSED)] * 2
        assert answers[0] == (await _post_chat(control, {"Cookie": f"{cookie}={token}"}))[0]


async def test_a_kerberos_negotiate_session_token_is_accepted(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mock seam is the one tests/test_directory_login_step_up_seed.py drives: a fake
    directory whose group maps to Administrator, and a patched ticket check."""
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    service = await _directory_service(engine)
    live, control = _live_and_control(lambda: create_app(engine, auth=service))
    negotiate = {"Authorization": "Negotiate " + base64.b64encode(b"tok").decode()}
    async with _client(live) as client:
        # Sign-in itself has no gate, so the early check is not in front of it.
        signed_in = await client.post("/auth/negotiate", headers=negotiate)
    assert signed_in.status_code == 200, signed_in.text
    await _assert_accepted(live, control, {"Authorization": f"Bearer {signed_in.json()['token']}"})
    # The Negotiate header itself is not a credential on a gated route, before and after.
    refused = await _post_chat(live, negotiate)
    assert [(status, body) for status, _headers, body in refused] == [(401, _REFUSED)] * 2
    assert refused[0] == (await _post_chat(control, negotiate))[0]


async def test_the_no_auth_embedding_opt_in_is_accepted(engine: Engine) -> None:
    live, control = _live_and_control(lambda: create_app(engine, allow_no_auth=True))
    await _assert_accepted(live, control, {})


async def test_a_caller_inside_the_source_network_allow_list_is_accepted(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    networks = SecuritySettings(allowed_client_networks=["10.0.0.0/8"])
    live, control = _live_and_control(
        lambda: create_app(engine, auth=service, security_settings=networks)
    )
    bearer = await _sign_in(live, "admin")  # from loopback, which the allow-list always admits
    inside, outside = ("10.1.2.3", 4000), ("192.0.2.9", 4000)
    await _assert_accepted(live, control, bearer, peer=inside)
    # Outside the list the network gate answers, ahead of routing, whatever the body or the token.
    refused = await _post_chat(live, bearer, peer=outside)
    assert [status for status, _headers, _body in refused] == [403, 403]
    assert refused[0][1:] == refused[1][1:]
    assert refused == await _post_chat(control, bearer, peer=outside)
    # Inside the list with no token, sign-in is what refuses.
    assert [(s, b) for s, _h, b in await _post_chat(live, {}, peer=inside)] == [(401, _REFUSED)] * 2


_SERVICE_ROUTE = "/planted/service-body"


_CERT_GATE = require_service_cert(Permission.MONITORING_READ)


async def _service_body(body: _Body, identity: Identity = Depends(_CERT_GATE)) -> dict[str, str]:
    return {"username": identity.username}


async def test_a_mapped_client_certificate_is_accepted(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No shipped route on the cert gate takes a body, so one is planted. The cert plane gets the
    same early check from the same class, with its own refusal and its own carried identity."""
    service = await _service(engine)
    user_id = await _add(service, "svc", Role.VIEWER)
    bearer_app = create_app(engine, auth=service)
    bearer = await _sign_in(bearer_app, "svc")

    def build() -> FastAPI:
        app = create_app(
            engine,
            auth=service,
            tls_client_cert_identities={_ISSUER: {"CN:svc.internal": user_id}},
        )
        app.post(_SERVICE_ROUTE)(_service_body)
        return app

    live, control = _live_and_control(build)
    assert _uncovered(live) == []
    tally = _count_calls(monkeypatch, service)

    async def post(app: FastAPI, common_name: str | None, body: bytes, **headers: str) -> Any:
        tally.clear()
        # ``_wrap_with_cert`` stands in for the mTLS shim: it stashes a verified peer cert.
        cert = _peercert(common_name) if common_name is not None else None
        async with _client(_wrap_with_cert(app, cert)) as client:
            response = await client.post(_SERVICE_ROUTE, content=body, headers={**_JSON, **headers})
        return response.status_code, response.content

    good, bad = b'{"value": 1}', _MALFORMED[0]
    # Accepted: the handler runs, the parser answers a malformed body, and the cert is resolved once.
    for app in (live, control):
        assert await post(app, "svc.internal", good) == (200, b'{"username":"svc"}')
        assert tally["identity_for_cert_user_id"] == 1
        assert (await post(app, "svc.internal", bad))[0] == 422
    # Not accepted: no cert, an unmapped subject, and a bearer session with no cert.
    for common_name, headers in ((None, {}), ("attacker.example", {}), (None, bearer)):
        assert await post(live, common_name, good, **headers) == (401, _CERT_REFUSED)
        assert await post(live, common_name, bad, **headers) == (401, _CERT_REFUSED)
        assert await post(control, common_name, good, **headers) == (401, _CERT_REFUSED)
        # THE CONTROL: FastAPI's own class answered this plane's malformed body from the parser.
        assert (await post(control, common_name, bad, **headers))[0] == 422
