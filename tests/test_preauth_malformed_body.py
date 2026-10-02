# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What an unauthenticated caller gets for a request body that does not parse (vault BACKLOG #2703).

THIS FILE PINS WHAT WAS MEASURED. IT DOES NOT SAY WHAT THE ANSWER SHOULD BE. The DAST sweep
(``tests/test_dast_auth_sweep.py``) sends an empty body, which covers a body that parsed. Nothing
covered a body that fails to parse, so a change that parsed more of a request before the login check
could land with every test green. Each status below was read off the live app and written down, so
that such a change now reds a test and has to be looked at.

ONE CLASS IS A MEASURED, UNRULED BEHAVIOUR. A JSON route behind an API gate that declares a body
gives an unauthenticated caller a parser answer, and not the 401 it gives every other
unauthenticated request. There are at least two such answers: 422 for bytes that are not valid
JSON, and 400 for bytes that are not text at all. FastAPI reads and decodes a declared JSON body
before it solves the route's dependencies, and the login check is a dependency. The owner has not
ruled on whether that order is acceptable. Do not "fix" it here in either direction: change a
pinned status only together with the engine change that moves it, under an owner ruling.

HOW THE WALK IS BUILT. Every operation comes from the live route table through
``scripts/security/route_gates.py``, the one derivation of a route's gate. Nothing here is a list
kept by hand, except the short set of operations that carry no dependency gate, which is compared
for equality against what the walk finds. An operation is walked when its method is not GET, or
when FastAPI holds a declared body for it. Both planes are walked: the JSON API and the web console
under ``/ui``, on an app built with the console mounted and federated sign-in on.

HOW A GATED OPERATION IS CLASSIFIED. By its dependencies, never by its name or its path. Its gate
is the ``require*()`` closure ``route_gates`` found among them: a ``require_ui*`` gate is the
console's and any other is the API's. It "declares a body" when the route holds a FastAPI body
field, which is what makes FastAPI parse before it solves dependencies. An operation with no gate
at all is not classified: it is pinned by name, one entry each.

WHAT THIS DOES NOT SEE, at least:

* Any other way a body can fail to parse. Four probes are sent, and FastAPI has more parser paths
  than those four reach.
* A GET handler that reads a body by hand. No GET operation declares one today.
* ``/ws/stats`` and the ``/ui/static`` mount. Neither takes a request body. The walk fails if any
  other route joins them, so a mounted app or an included router cannot hide operations from it.
* Form and multipart bodies. No arm sends one. No route declares one: FastAPI refuses to register
  such a route without ``python-multipart``, which the engine does not install. The console reads
  its forms by hand inside the handler.
* Routes registered only under a setting this app leaves off, such as the four documentation
  routes of ``expose_docs``.
* The listener. Requests go through ``httpx.ASGITransport``, so no uvicorn answer is measured.
* The sign-in rate limiter. It is switched off here, because it counts requests across the whole
  module and would make ``POST /ui/login`` answer 429 depending on what ran before it.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest
from fastapi.routing import APIRoute

from messagefoundry.api.app import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from scripts.security import route_gates
from scripts.security.dast_auth_sweep import DEFAULT_POLICY, _key, load_policy

#: The four probes, in the order every status tuple below is written. The first is not valid JSON:
#: an object that never closes. The second is the same bytes with no content type. The third is
#: valid JSON of the wrong shape, a bare string, and is the contrast that shows the first answer
#: comes from the bytes and not from the route. The fourth is not UTF-8, so it fails before the
#: JSON decoder sees it.
_JSON = {"Content-Type": "application/json"}
_ARMS: dict[str, tuple[bytes, dict[str, str]]] = {
    "malformed JSON": (b'{"probe": ', _JSON),
    "malformed, no content type": (b'{"probe": ', {}),
    "valid JSON, wrong shape": (b'"wrong-shape"', _JSON),
    "undecodable bytes": (b"\xff\xfe{", _JSON),
}

#: The route-table rows the walk cannot send a body to. Anything else here fails the walk.
_NOT_PROBED = {
    (route_gates.WS_METHOD, "/ws/stats"),
    (route_gates.MOUNT_METHOD, "/ui/static"),
}

_REFUSED = {"detail": "not authenticated"}
#: FastAPI's own answer when reading the body raises. It carries none of the bytes and none of the
#: exception text.
_UNREADABLE = {"detail": "There was an error parsing the body"}

_API, _CONSOLE = "api", "console"

#: What an operation WITH a dependency gate answers, by ``(gate family, declares a body)``. One
#: status per arm, in ``_ARMS`` order.
_GATED: dict[tuple[str, bool], tuple[int, int, int, int]] = {
    (_API, False): (401, 401, 401, 401),
    # MEASURED, UNRULED, AWAITING AN OWNER RULING. See the module docstring. A parser answers the
    # first arm and the last before the login check runs.
    (_API, True): (422, 401, 401, 400),
    (_CONSOLE, False): (303, 303, 303, 303),
}

#: Floors under how many operations the walk found in each class above. Measured 2026-10-01
#: against d68abee5b9: 27, 34 and 60, of 131 operations in all. Raise a floor when the number
#: grows. Never lower one to make a run pass.
_FLOORS = {(_API, False): 24, (_API, True): 30, (_CONSOLE, False): 54}


def _every_arm(status: int) -> tuple[int, ...]:
    return (status,) * len(_ARMS)


#: Every operation with NO dependency gate, with the status each arm got and the ``Location`` they
#: all got. The walk must find exactly this set, so a new operation that takes a body without a
#: gate fails here until someone reads it and adds it. The ``Location`` is pinned whole, because
#: its error code is what tells a handler that refused the session from one that read the body.
_NO_DEPENDENCY_GATE: dict[tuple[str, str], tuple[tuple[int, ...], str | None]] = {
    # Anonymous by design, and on the DAST policy's reviewed anonymous list. Sign-in has to parse
    # a body from a caller with no session, so a parser answer here is not a finding.
    ("POST", "/auth/login"): ((422, 422, 422, 400), None),
    # Reads the Authorization header and no body. The 400 is the missing SPNEGO token.
    ("POST", "/auth/negotiate"): (_every_arm(400), None),
    # The console's sign-in form, its sign-out, and the start of federated sign-in.
    ("POST", "/ui/login"): (_every_arm(303), "/ui/login?e=bad"),
    ("POST", "/ui/logout"): (_every_arm(303), "/ui/login?e=loggedout"),
    ("POST", "/ui/oidc/start"): (_every_arm(303), "/ui/login?e=oidc_unavailable"),
    # The browser's CSP report sink. It takes any body from anyone and answers 204.
    ("POST", "/ui/csp-report"): (_every_arm(204), None),
    # These four check the session inside the handler. Each answered with its own refusal.
    ("POST", "/ui/mfa"): (_every_arm(303), "/ui/login?e=expired"),
    ("POST", "/ui/reauth"): (_every_arm(303), "/ui/login?e=expired"),
    ("POST", "/ui/reauth/oidc"): (_every_arm(303), "/ui/login?e=expired"),
    ("POST", "/ui/reauth/webauthn"): (_every_arm(401), None),
}


@dataclass(frozen=True)
class _Operation:
    method: str
    path: str
    #: ``(gate family, declares a body)``, or ``None`` for an operation with no dependency gate.
    gate_class: tuple[str, bool] | None

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


@dataclass(frozen=True)
class _Sweep:
    not_probed: frozenset[tuple[str, str]]
    answers: dict[_Operation, tuple[httpx.Response, ...]]

    def of_class(self, gate_class: tuple[str, bool] | None) -> list[_Operation]:
        return [operation for operation in self.answers if operation.gate_class == gate_class]

    def statuses(self, operation: _Operation) -> tuple[int, ...]:
        return tuple(response.status_code for response in self.answers[operation])

    def pinned(self, gate_class: tuple[str, bool]) -> list[_Operation]:
        """The operations of a gated class, having checked each answered what ``_GATED`` pins."""
        operations = self.of_class(gate_class)
        assert operations, f"the walk found no operation of class {gate_class}"
        wrong = {
            str(operation): statuses
            for operation in operations
            if (statuses := self.statuses(operation)) != _GATED[gate_class]
        }
        assert not wrong, (
            f"of {len(operations)} operation(s) of class {gate_class}, these did not answer "
            f"{_GATED[gate_class]} to {list(_ARMS)}: {wrong}"
        )
        return operations


@pytest.fixture(scope="module")
async def sweep(tmp_path_factory: pytest.TempPathFactory) -> _Sweep:
    """One pass over the live app with no credential, shared by every case below."""
    engine = await Engine.create(
        tmp_path_factory.mktemp("preauth-body") / "preauth.db", poll_interval=0.05
    )
    try:
        service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False))
        await service.initialize()
        app = create_app(engine, auth=service, serve_ui=True, oidc_enabled=True)

        declared = {
            (method, route.path)
            for route in app.routes
            if isinstance(route, APIRoute) and route.body_field is not None
            for method in route.methods or ()
        }
        rows = route_gates.route_rows(app)
        unprobeable = (route_gates.WS_METHOD, route_gates.MOUNT_METHOD)
        answers: dict[_Operation, tuple[httpx.Response, ...]] = {}
        # A real peer address: the client-network gate fails closed on a request with none. A
        # handler that raises is recorded as its 500, so the case that reads it can name the route.
        transport = httpx.ASGITransport(
            app=app, client=("127.0.0.1", 123), raise_app_exceptions=False
        )
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            for row in rows:
                declares = (row.method, row.path) in declared
                if row.method in unprobeable or (row.method == "GET" and not declares):
                    continue
                family = _CONSOLE if (row.gate or "").startswith("require_ui") else _API
                operation = _Operation(
                    row.method, row.path, (family, declares) if row.gate is not None else None
                )
                url = route_gates.concrete_path(row.path)
                answers[operation] = tuple(
                    [
                        await client.request(row.method, url, content=body, headers=headers)
                        for body, headers in _ARMS.values()
                    ]
                )
        return _Sweep(
            not_probed=frozenset(
                (row.method, row.path) for row in rows if row.method in unprobeable
            ),
            answers=answers,
        )
    finally:
        await engine.stop()


async def test_the_walk_reaches_every_body_taking_operation(sweep: _Sweep) -> None:
    assert sweep.answers, "the walk found no body-taking operation at all"
    for gate_class, floor in _FLOORS.items():
        found = len(sweep.of_class(gate_class))
        assert found >= floor, (
            f"class {gate_class}: {found} operation(s), under the floor {floor}, of "
            f"{len(sweep.answers)} the walk found. A sweep over nothing would pass every case below."
        )
    assert sweep.not_probed == _NOT_PROBED, (
        "the route table holds a row this walk cannot send a body to, or lost one it expected: "
        f"{sorted(sweep.not_probed ^ _NOT_PROBED)}. A mounted app or an included router hides its "
        "operations from the walk, so each one has to be read before it is allowed here."
    )
    unclassed = sorted(
        str(operation)
        for operation in sweep.answers
        if operation.gate_class is not None and operation.gate_class not in _GATED
    )
    assert not unclassed, (
        "a gated operation is of a class no status is pinned for. Measure what it answers and add "
        f"the class to _GATED: {unclassed}"
    )


async def test_authentication_refuses_first_where_no_body_is_declared(sweep: _Sweep) -> None:
    """The control. With no declared body there is nothing for FastAPI to parse, so the login
    check is the first thing that answers, whatever bytes arrive."""
    operations = sweep.pinned((_API, False))
    assert "POST /auth/logout" in {str(operation) for operation in operations}, (
        "the control route is not among the API-gated operations with no declared body: the walk "
        f"found {len(operations)} of those, and {len(sweep.answers)} operation(s) in all"
    )
    assert all(
        response.json() == _REFUSED
        for operation in operations
        for response in sweep.answers[operation]
    )


async def test_a_gated_json_route_answers_a_malformed_body_before_it_authenticates(
    sweep: _Sweep,
) -> None:
    """THE MEASURED, UNRULED BEHAVIOUR. See the module docstring before changing a status here."""
    for operation in sweep.pinned((_API, True)):
        invalid_json, no_content_type, wrong_shape, undecodable = sweep.answers[operation]
        # The 422 is the JSON decoder's, and it gives back a position and nothing of the body.
        (error,) = invalid_json.json()["detail"]
        assert set(error) == {"type", "loc", "msg"}, (str(operation), error)
        assert error["type"] == "json_invalid", (str(operation), error)
        assert undecodable.json() == _UNREADABLE, str(operation)
        # The same route refuses the same caller once the bytes are not handed to the decoder.
        assert no_content_type.json() == wrong_shape.json() == _REFUSED, str(operation)


async def test_a_gated_console_route_redirects_to_sign_in_whatever_the_body(
    sweep: _Sweep,
) -> None:
    operations = sweep.pinned((_CONSOLE, False))
    assert operations
    # The redirect is the gate's own, to the sign-in page, and not some other 303.
    elsewhere = {
        str(operation): locations
        for operation in operations
        if (locations := [r.headers.get("location") for r in sweep.answers[operation]])
        != ["/ui/login"] * len(_ARMS)
    }
    assert not elsewhere, elsewhere


async def test_operations_with_no_dependency_gate_are_exactly_the_pinned_set(
    sweep: _Sweep,
) -> None:
    measured = {
        (operation.method, operation.path): (
            sweep.statuses(operation),
            {r.headers.get("location") for r in sweep.answers[operation]},
        )
        for operation in sweep.of_class(None)
    }
    assert set(measured) == set(_NO_DEPENDENCY_GATE), (
        f"newly without a dependency gate: {sorted(set(measured) - set(_NO_DEPENDENCY_GATE))}; "
        f"pinned but gone or now gated: {sorted(set(_NO_DEPENDENCY_GATE) - set(measured))}"
    )
    assert measured == {
        key: (statuses, {location}) for key, (statuses, location) in _NO_DEPENDENCY_GATE.items()
    }

    # "Anonymous by design" on the JSON plane is the reviewed list the DAST sweep holds the app
    # to, not a name this file chose. The console has no such list, so its entries are pinned
    # above, and the path is what says which of the two an entry belongs to.
    assert measured
    reviewed = {_key(entry) for entry in load_policy(DEFAULT_POLICY)["anonymous_allowlist"]}
    unreviewed = sorted(
        key for key in measured if key not in reviewed and not key[1].startswith("/ui/")
    )
    assert not unreviewed, f"anonymous on the JSON plane and not on the reviewed list: {unreviewed}"
