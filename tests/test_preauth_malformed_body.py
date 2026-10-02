# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What an unauthenticated caller gets for a request body that does not parse (vault BACKLOG #2703).

THIS FILE PINS WHAT WAS MEASURED. IT DOES NOT SAY WHAT THE ANSWER SHOULD BE. The DAST sweep
(``tests/test_dast_auth_sweep.py``) sends an empty body, which covers a body that parsed. Nothing
covered a body that fails to parse, so a change that parsed more of a request before the login check
could land with every test green. Each status below was read off the live app and written down, so
that such a change now reds a test and has to be looked at.

ONE CLASS IS A MEASURED, UNRULED BEHAVIOUR. A gated JSON route that declares a body answers a
malformed JSON body with 422 and not with the 401 it gives every other unauthenticated request.
FastAPI reads and decodes a declared JSON body before it solves the route's dependencies, and the
login check is a dependency. The owner has not ruled on whether that order is acceptable. Do not
"fix" it here in either direction: change the pinned status only together with the engine change
that moves it, under an owner ruling.

HOW THE WALK IS BUILT. Every operation comes from the live route table through
``scripts/security/route_gates.py``, the one derivation of a route's gate. Nothing here is a list
kept by hand, except the short set of operations that carry no dependency gate, which is compared
for equality against what the walk finds. An operation is walked when its method is not GET, or
when FastAPI holds a declared body for it. Both planes are walked: the JSON API and the web console
under ``/ui``, on an app built with the console mounted and federated sign-in on.

HOW AN OPERATION IS CLASSIFIED. By its dependencies, never by its name. "Gated" means
``route_gates.gate_of`` found a ``require*()`` closure among them. "Declared" means the route holds
a FastAPI body field, which is what makes FastAPI parse before it solves dependencies.

WHAT THIS DOES NOT SEE, at least:

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

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from fastapi.routing import APIRoute

from messagefoundry.api.app import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from scripts.security import route_gates

_POLICY = Path(__file__).resolve().parents[1] / "scripts" / "security" / "dast-policy.json"

#: The three probes, in the order every status tuple below is written. The first is not valid
#: JSON: an object that never closes. The second is the same bytes with no content type. The third
#: is valid JSON of the wrong shape, a bare string, and is the contrast that shows the first answer
#: comes from the bytes and not from the route.
_JSON = {"Content-Type": "application/json"}
_ARMS: dict[str, tuple[bytes, dict[str, str]]] = {
    "malformed JSON": (b'{"probe": ', _JSON),
    "malformed, no content type": (b'{"probe": ', {}),
    "valid JSON, wrong shape": (b'"wrong-shape"', _JSON),
}

#: The route-table rows the walk cannot send a body to. Anything else here fails the walk.
_NOT_PROBED = {
    (route_gates.WS_METHOD, "/ws/stats"),
    (route_gates.MOUNT_METHOD, "/ui/static"),
}

_REFUSED = "not authenticated"

#: What an operation WITH a dependency gate answers, by ``(plane, declares a body)``. One status per
#: arm, in ``_ARMS`` order.
_GATED: dict[tuple[str, bool], tuple[int, int, int]] = {
    ("api", False): (401, 401, 401),
    # MEASURED, UNRULED, AWAITING AN OWNER RULING. See the module docstring. The parser answers
    # the first arm before the login check runs.
    ("api", True): (422, 401, 401),
    ("ui", False): (303, 303, 303),
}

#: Every operation with NO dependency gate, with the status and the ``Location`` all three arms
#: got. The walk must find exactly this set, so a new operation that takes a body without a gate
#: fails here until someone reads it and adds it.
_NO_DEPENDENCY_GATE: dict[tuple[str, str], tuple[int, str | None]] = {
    # Anonymous by design, and on the DAST policy's reviewed anonymous list. Sign-in has to parse
    # a body from a caller with no session, so a parser answer here is not a finding.
    ("POST", "/auth/login"): (422, None),
    # Reads the Authorization header and no body. The 400 is the missing SPNEGO token.
    ("POST", "/auth/negotiate"): (400, None),
    # The console's sign-in form, its sign-out, and the start of federated sign-in.
    ("POST", "/ui/login"): (303, "/ui/login?e=bad"),
    ("POST", "/ui/logout"): (303, "/ui/login?e=loggedout"),
    ("POST", "/ui/oidc/start"): (303, "/ui/login?e=oidc_unavailable"),
    # The browser's CSP report sink. It takes any body from anyone and answers 204.
    ("POST", "/ui/csp-report"): (204, None),
    # These four check the session inside the handler. Each answered with its own refusal.
    ("POST", "/ui/mfa"): (303, "/ui/login?e=expired"),
    ("POST", "/ui/reauth"): (303, "/ui/login?e=expired"),
    ("POST", "/ui/reauth/oidc"): (303, "/ui/login?e=expired"),
    ("POST", "/ui/reauth/webauthn"): (401, None),
}

#: Floors under what the walk found, by ``(plane, gated, declares a body)``. Measured 2026-10-01
#: against d68abee5b9: 34, 27, 60, and 131 operations in all. Raise a floor when the number grows.
#: Never lower one to make a run pass.
_FLOORS = {("api", True, True): 30, ("api", True, False): 24, ("ui", True, False): 54}
_MIN_OPERATIONS = 120


@dataclass(frozen=True)
class _Operation:
    method: str
    path: str
    gate: str | None
    declared: bool

    @property
    def plane(self) -> str:
        return "ui" if self.path == "/ui" or self.path.startswith("/ui/") else "api"

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


@dataclass(frozen=True)
class _Sweep:
    operations: tuple[_Operation, ...]
    not_probed: frozenset[tuple[str, str]]
    answers: dict[_Operation, tuple[httpx.Response, ...]]

    def statuses(self, operation: _Operation) -> tuple[int, ...]:
        return tuple(response.status_code for response in self.answers[operation])

    def of_class(self, plane: str, declared: bool) -> list[_Operation]:
        return [
            op
            for op in self.operations
            if op.gate is not None and op.plane == plane and op.declared is declared
        ]

    def off_pin(self, plane: str, declared: bool) -> dict[str, tuple[int, ...]]:
        """The gated operations of a class that did not answer what ``_GATED`` pins for it."""
        return {
            str(op): got
            for op in self.of_class(plane, declared)
            if (got := self.statuses(op)) != _GATED[plane, declared]
        }

    def counts(self) -> Counter[tuple[str, bool, bool]]:
        return Counter((op.plane, op.gate is not None, op.declared) for op in self.operations)


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
            for method in route.methods
        }
        rows = route_gates.route_rows(app)
        unprobeable = (route_gates.WS_METHOD, route_gates.MOUNT_METHOD)
        operations = tuple(
            _Operation(row.method, row.path, row.gate, (row.method, row.path) in declared)
            for row in rows
            if row.method not in unprobeable
            and (row.method != "GET" or (row.method, row.path) in declared)
        )

        answers: dict[_Operation, tuple[httpx.Response, ...]] = {}
        # A real peer address: the client-network gate fails closed on a request with none.
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            for operation in operations:
                url = route_gates.concrete_path(operation.path)
                answers[operation] = tuple(
                    [
                        await client.request(operation.method, url, content=body, headers=headers)
                        for body, headers in _ARMS.values()
                    ]
                )
        return _Sweep(
            operations=operations,
            not_probed=frozenset(
                (row.method, row.path) for row in rows if row.method in unprobeable
            ),
            answers=answers,
        )
    finally:
        await engine.stop()


async def test_the_walk_reaches_every_body_taking_operation(sweep: _Sweep) -> None:
    counts = sweep.counts()
    assert len(sweep.operations) >= _MIN_OPERATIONS, (
        f"the walk found {len(sweep.operations)} body-taking operation(s), by class {dict(counts)}. "
        "A sweep over nothing would pass every case below."
    )
    for key, floor in _FLOORS.items():
        assert counts[key] >= floor, f"{key}: {counts[key]} operation(s), under the floor {floor}"
    assert sweep.not_probed == _NOT_PROBED, (
        "the route table holds a row this walk cannot send a body to, or lost one it expected: "
        f"{sorted(sweep.not_probed ^ _NOT_PROBED)}. A mounted app or an included router hides its "
        "operations from the walk, so each one has to be read before it is allowed here."
    )
    unclassed = sorted(
        str(op)
        for op in sweep.operations
        if op.gate is not None and (op.plane, op.declared) not in _GATED
    )
    assert not unclassed, (
        "a gated operation is of a class no status is pinned for. Measure what it answers and add "
        f"the class to _GATED: {unclassed}"
    )


async def test_authentication_refuses_first_where_no_body_is_declared(sweep: _Sweep) -> None:
    """The control. With no declared body there is nothing for FastAPI to parse, so the login
    check is the first thing that answers, whatever bytes arrive."""
    operations = sweep.of_class("api", False)
    assert "POST /auth/logout" in {str(op) for op in operations}, (
        "the control route is not among the gated operations with no declared body: the walk "
        f"found {len(operations)} of those, and {len(sweep.operations)} operation(s) in all"
    )
    wrong = sweep.off_pin("api", False)
    assert not wrong, f"of {len(operations)} gated operation(s) with no declared body: {wrong}"
    assert all(
        response.json() == {"detail": _REFUSED}
        for op in operations
        for response in sweep.answers[op]
    )


async def test_a_gated_json_route_answers_a_malformed_body_before_it_authenticates(
    sweep: _Sweep,
) -> None:
    """THE MEASURED, UNRULED BEHAVIOUR. See the module docstring before changing a status here."""
    operations = sweep.of_class("api", True)
    wrong = sweep.off_pin("api", True)
    assert not wrong, (
        f"of {len(operations)} gated JSON operation(s) that declare a body, these did not answer "
        f"{_GATED['api', True]} to {list(_ARMS)}: {wrong}"
    )
    for operation in operations:
        parser_answer, *refusals = sweep.answers[operation]
        # The 422 is the JSON decoder's, and it gives back a position and nothing of the body.
        (error,) = parser_answer.json()["detail"]
        assert set(error) == {"type", "loc", "msg"}, (str(operation), error)
        assert error["type"] == "json_invalid", (str(operation), error)
        # The same route refuses the same caller once the bytes are not handed to the decoder.
        assert [response.json() for response in refusals] == [{"detail": _REFUSED}] * 2


async def test_a_gated_console_route_redirects_to_sign_in_whatever_the_body(
    sweep: _Sweep,
) -> None:
    operations = sweep.of_class("ui", False)
    wrong = sweep.off_pin("ui", False)
    assert not wrong, f"of {len(operations)} gated console operation(s): {wrong}"
    # The redirect is the gate's own, to the sign-in page, and not some other 303.
    elsewhere = {
        str(op): locations
        for op in operations
        if (locations := [r.headers.get("location") for r in sweep.answers[op]])
        != ["/ui/login"] * len(_ARMS)
    }
    assert not elsewhere, elsewhere


async def test_operations_with_no_dependency_gate_are_exactly_the_pinned_set(
    sweep: _Sweep,
) -> None:
    ungated = {(op.method, op.path): op for op in sweep.operations if op.gate is None}
    assert set(ungated) == set(_NO_DEPENDENCY_GATE), (
        f"newly without a dependency gate: {sorted(set(ungated) - set(_NO_DEPENDENCY_GATE))}; "
        f"pinned but gone or now gated: {sorted(set(_NO_DEPENDENCY_GATE) - set(ungated))}"
    )
    measured = {
        key: [(r.status_code, r.headers.get("location")) for r in sweep.answers[op]]
        for key, op in ungated.items()
    }
    assert measured == {key: [pinned] * len(_ARMS) for key, pinned in _NO_DEPENDENCY_GATE.items()}

    # On the JSON plane "anonymous by design" is the reviewed list the DAST sweep holds the app
    # to, not a name this file chose. The console has no such list, so its entries are pinned above.
    policy = json.loads(_POLICY.read_text(encoding="utf-8"))
    reviewed = {(entry["method"], entry["path"]) for entry in policy["anonymous_allowlist"]}
    unreviewed = sorted(
        key for key, op in ungated.items() if op.plane == "api" and key not in reviewed
    )
    assert not unreviewed, f"anonymous on the JSON plane and not on the reviewed list: {unreviewed}"
