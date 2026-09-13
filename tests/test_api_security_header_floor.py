# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The baseline security headers must be on EVERY response, including the ones no route produced.

`_security_headers` is the INNERMOST user middleware, so every emitter outside it escaped: the request
body cap's four short-circuits shipped with none of the baseline, and an unhandled exception shipped
with none of it either (a handler registered for Exception/500 becomes ServerErrorMiddleware's, which
Starlette places outside `user_middleware` entirely). These tests assert the SECURITY property on the
error paths themselves — a normal 200 carrying the headers was already true before the fix and proves
nothing about it.

Every short-circuit is driven through a hand-built ASGI scope rather than a client, because two of the
four are unreachable through one: no HTTP client will emit `Content-Length` together with
`Transfer-Encoding`, or a non-integer `Content-Length`.

Two later requirements are pinned here as well, because both are properties of the same floor:

* **ASVS 3.4.6** — `frame-ancestors` on every response. The assertions are on the EFFECTIVE value, not
  on the directive's presence: a response may carry more than one policy field, CSP Level 3 enforces
  each independently, and "the directive appears somewhere" would pass on a policy that permits
  framing. `_frame_ancestors_values` deliberately re-derives the parse instead of importing
  `csp_names_frame_ancestors`, so the instrument can disagree with the implementation it measures.
* **ASVS 3.4.1** — HSTS only where a user agent is permitted to note it. Since ADR 0172 the engine
  serves https from a self-signed pair by default, so the scheme test alone now fires on a stock
  loopback install. Every suppression assertion below is paired with a posture that DOES carry the
  header in the same run.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError
from starlette.types import Message, Receive, Scope, Send

from messagefoundry.api.app import create_app
from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    CSP_HEADER,
    FRAME_ANCESTORS_CSP,
    HSTS_HEADER,
    HSTS_VALUE,
    SecurityHeaderFloorMiddleware,
    csp_names_frame_ancestors,
    host_is_ip_literal,
    hsts_notable,
    request_host,
)
from messagefoundry.api.request_timeout import TIMEOUT_STATE_ATTR, RequestTimeoutMiddleware
from messagefoundry.config.settings import ApiSettings

_BASELINE_NAMES = tuple(name.lower() for name, _ in BASELINE_SECURITY_HEADERS)

#: A DNS host, so the default driver posture is one HSTS is ALLOWED on. The IP-literal legs pass their
#: own host explicitly — a default of 127.0.0.1 would have suppressed HSTS everywhere and turned the
#: positive controls in this file into vacuous passes.
_DNS_HOST = "ops.example.com"


async def _drive_raw(
    app: Any,
    *,
    method: str = "GET",
    path: str = "/health",
    headers: tuple[tuple[str, str], ...] = (),
    scheme: str = "http",
    host: str = _DNS_HOST,
    client: tuple[str, int] = ("127.0.0.1", 50000),
    expect_raise: bool = False,
    scope_app: Any = None,
) -> tuple[int, list[tuple[str, str]]]:
    """Send one request straight into the ASGI app; return (status, header fields IN ORDER).

    The list form is what lets the CSP assertions see a repeated field. ``scope_app`` populates
    ``scope["app"]``, which is the only way a hand-composed middleware stack can reach the
    ``app.state`` knobs the real app supplies — ``RequestTimeoutMiddleware`` reads its deadline from
    there and otherwise degrades to the shipped 120s default."""
    raw_headers = list(headers)
    if not any(name.lower() == "host" for name, _ in raw_headers):
        raw_headers.insert(0, ("host", host))
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in raw_headers],
        "client": client,
        "server": ("127.0.0.1", 8765),
    }
    if scope_app is not None:
        scope["app"] = scope_app
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    if expect_raise:
        # ServerErrorMiddleware ALWAYS re-raises after sending the 500 response, so an unhandled
        # exception must be caught here or the assertions below never run at all. Matched on the
        # route's own sentinel rather than bare Exception, so a DIFFERENT failure surfaces instead of
        # being swallowed into a passing test.
        with pytest.raises(RuntimeError, match="deliberate"):
            await app(scope, receive, send)
    else:
        await app(scope, receive, send)

    start = next(m for m in sent if m["type"] == "http.response.start")
    return int(start["status"]), [(k.decode().lower(), v.decode()) for k, v in start["headers"]]


async def _drive(app: Any, **kwargs: Any) -> tuple[int, dict[str, str]]:
    """(status, lower-cased headers) — the single-valued view, for the names nothing repeats."""
    status, raw = await _drive_raw(app, **kwargs)
    return status, dict(raw)


def _frame_ancestors_values(raw: list[tuple[str, str]]) -> list[str]:
    """Every ``frame-ancestors`` source list across every CSP field on the response.

    Re-derived here rather than imported from the module under test: an instrument that shares the
    implementation's parser cannot report that the parser is wrong."""
    found: list[str] = []
    for name, value in raw:
        if name != CSP_HEADER.lower():
            continue
        for serialized in value.split(";"):
            parts = serialized.strip().split(None, 1)
            if parts and parts[0].casefold() == "frame-ancestors":
                found.append(parts[1].strip() if len(parts) > 1 else "")
    return found


def _assert_framing_denied(raw: list[tuple[str, str]], label: str) -> None:
    """The EFFECTIVE value is ``'none'``: at least one policy names the directive, and no policy names
    it with anything weaker. Two policies intersect, so one permissive field cannot loosen a strict
    one — but a lone permissive field would, and that is what this rules out."""
    values = _frame_ancestors_values(raw)
    assert values, f"{label}: no policy on the response names frame-ancestors ({raw})"
    assert set(values) == {"'none'"}, f"{label}: effective frame-ancestors is {values}, not 'none'"


class _BareApp:
    """An ASGI app that emits a response with the headers under test deliberately absent."""

    def __init__(self, status: int = 413, headers: tuple[tuple[bytes, bytes], ...] = ()) -> None:
        self.status = status
        self.headers = headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {"type": "http.response.start", "status": self.status, "headers": list(self.headers)}
        )
        await send({"type": "http.response.body", "body": b"{}"})


async def test_the_driver_reports_a_missing_header_as_missing() -> None:
    """VACUITY GUARD, and it is the load-bearing test in this file.

    Every other assertion here is "the header is present". An instrument that reported every header
    present would pass all of them while proving nothing. So drive an app that emits NO baseline
    headers and assert the driver sees their absence, then wrap that same app in the floor and assert
    the same driver now sees them. The pair is what makes the presence assertions evidence."""
    bare = _BareApp()
    status, raw = await _drive_raw(bare)
    headers = dict(raw)
    assert status == 413
    assert [n for n in _BASELINE_NAMES if n in headers] == [], (
        f"the driver must observe absence for this file's assertions to mean anything; got {headers}"
    )
    assert _frame_ancestors_values(raw) == [], "the CSP instrument must observe absence too"

    status, raw = await _drive_raw(SecurityHeaderFloorMiddleware(bare))
    assert status == 413, "the floor must not alter the status"
    assert [n for n in _BASELINE_NAMES if n in dict(raw)] == list(_BASELINE_NAMES)
    _assert_framing_denied(raw, "a bare response wrapped in the floor")


async def test_the_floor_never_overwrites_a_header_an_inner_emitter_assigned() -> None:
    """The floor runs LAST on the response path, so it must setdefault and never assign.

    Four inner writers ASSIGN a Content-Security-Policy or Cache-Control and depend on
    last-writer-wins — the /ui CSP overlay, the attachment sandbox CSP, the console's nonce CSP and
    the two denial header sets. An assigning floor would silently replace them; this pins the
    difference on a header the floor does own, which is the strictest case."""
    app = SecurityHeaderFloorMiddleware(
        _BareApp(status=200, headers=((b"x-frame-options", b"SAMEORIGIN"),))
    )
    _, headers = await _drive(app)
    assert headers["x-frame-options"] == "SAMEORIGIN"
    assert headers["x-content-type-options"] == "nosniff"  # the ones it did not find, it still sets


# --- ASVS 3.4.6: frame-ancestors ----------------------------------------------------------------


async def test_the_floor_appends_a_second_policy_rather_than_replacing_the_sandbox() -> None:
    """`setdefault` is a NO-OP on a header that already exists, and the responses that most need
    frame-ancestors are exactly the ones already carrying a policy that omits it — the attachment
    sandbox is the headline case. So the carrier APPENDS.

    Two policy fields is the correct shape, not a workaround: CSP Level 3 enforces each independently
    and the effect is their intersection, so a second field naming only frame-ancestors cannot weaken
    the first. Both halves are asserted: the sandbox survives byte-for-byte AND framing is denied."""
    sandbox = b"default-src 'none'; sandbox"
    app = SecurityHeaderFloorMiddleware(
        _BareApp(status=200, headers=((CSP_HEADER.lower().encode(), sandbox),))
    )
    _, raw = await _drive_raw(app)
    policies = [value for name, value in raw if name == CSP_HEADER.lower()]
    assert policies == [sandbox.decode(), FRAME_ANCESTORS_CSP], policies
    _assert_framing_denied(raw, "a response already carrying the attachment sandbox")


async def test_the_floor_leaves_a_policy_that_already_decided_framing_alone() -> None:
    """A writer that HAS made a frame-ancestors decision keeps it — the floor is a floor, not an
    override. Asserted on a value the floor would never write, so the test cannot pass by accident."""
    decided = b"default-src 'self'; frame-ancestors 'self'"
    app = SecurityHeaderFloorMiddleware(
        _BareApp(status=200, headers=((CSP_HEADER.lower().encode(), decided),))
    )
    _, raw = await _drive_raw(app)
    assert [value for name, value in raw if name == CSP_HEADER.lower()] == [decided.decode()]
    assert _frame_ancestors_values(raw) == ["'self'"]


def test_csp_names_frame_ancestors_parses_directives_not_substrings() -> None:
    """A substring test would be wrong in both directions, so the parser is pinned in both."""
    assert csp_names_frame_ancestors(["frame-ancestors 'none'"])
    assert csp_names_frame_ancestors(["default-src 'none'; sandbox; frame-ancestors 'none'"])
    assert csp_names_frame_ancestors(["FRAME-ANCESTORS 'none'"])  # names are case-insensitive
    assert csp_names_frame_ancestors(["default-src 'none'", "frame-ancestors 'none'"])
    assert not csp_names_frame_ancestors([])
    assert not csp_names_frame_ancestors(["default-src 'none'; sandbox"])
    # The near-misses a substring test would get wrong: the token inside another directive's VALUE.
    assert not csp_names_frame_ancestors(["report-uri /ui/frame-ancestors"])
    assert not csp_names_frame_ancestors(["script-src 'self' https://frame-ancestors.example"])


@pytest.mark.parametrize(
    ("label", "method", "path", "request_headers", "expected_status"),
    [
        ("a routed 200", "GET", "/health", (), 200),
        ("a 404 no route produced", "GET", "/no/such/path", (), 404),
        (
            "the CL+TE framing refusal",
            "POST",
            "/messages",
            (("content-length", "10"), ("transfer-encoding", "chunked")),
            400,
        ),
        (
            "the chunked-without-length refusal",
            "POST",
            "/messages",
            (("transfer-encoding", "chunked"),),
            411,
        ),
        (
            "the invalid Content-Length refusal",
            "POST",
            "/messages",
            (("content-length", "not-a-number"),),
            400,
        ),
        (
            "the oversized-body refusal",
            "POST",
            "/messages",
            (("content-length", "99999999"),),
            413,
        ),
    ],
)
async def test_every_response_family_is_governed_by_frame_ancestors_none(
    label: str,
    method: str,
    path: str,
    request_headers: tuple[tuple[str, str], ...],
    expected_status: int,
) -> None:
    """ASVS 3.4.6 asks for the directive on EVERY response, and every one of these is navigable — a
    JSON 200, a 404, a 413 and a body-cap 400 can all be loaded into a frame. Before the carrier the
    JSON API carried no Content-Security-Policy at all; the directive takes no fallback from
    `default-src`, so even the attachment sandbox was not a framing decision."""
    app = create_app(allow_no_auth=True)
    status, raw = await _drive_raw(app, method=method, path=path, headers=request_headers)
    assert status == expected_status, label
    _assert_framing_denied(raw, label)


async def test_the_unhandled_500_carries_frame_ancestors_the_floor_cannot_reach() -> None:
    """ServerErrorMiddleware sits OUTSIDE user_middleware, so the floor's carrier is not in this
    response's path at all. `_unhandled_exception` has to set the directive itself, and the negative
    control for that claim is the floor test above: this leg fails if only the floor is fixed."""
    app = create_app(allow_no_auth=True)

    @app.get("/_test/boom_csp")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    status, raw = await _drive_raw(app, path="/_test/boom_csp", expect_raise=True)
    assert status == 500
    _assert_framing_denied(raw, "the unhandled 500")


async def test_both_client_network_denial_arms_deny_framing() -> None:
    """The HTML page had a CSP that omitted the directive; the JSON arm had no CSP at all. Both are
    403s a refused browser sees before sign-in, and both short-circuit every /ui CSP writer."""
    app = create_app(allow_no_auth=True)
    app.state.client_networks = ("10.0.0.0/8",)
    denied = ("192.0.2.7", 50000)

    status, raw = await _drive_raw(app, path="/status", client=denied)
    assert status == 403
    _assert_framing_denied(raw, "the JSON denial arm")

    status, raw = await _drive_raw(
        app, path="/status", client=denied, headers=(("accept", "text/html,*/*"),)
    )
    assert status == 403
    _assert_framing_denied(raw, "the HTML denial page")
    # The page's own carve-out for its single inline <style> block must survive the addition.
    policies = [value for name, value in raw if name == CSP_HEADER.lower()]
    assert policies == ["default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"]


async def test_the_attachment_sandbox_is_not_split_into_two_policies() -> None:
    """The sandbox constant names the directive itself, so the carrier skips it and the response
    carries ONE policy. That is not cosmetic: it is what keeps the constant, and not the floor, the
    thing the attachment response is governed by if the floor is ever removed or re-ordered."""
    from messagefoundry.api.app import _ATTACHMENT_CSP

    assert _ATTACHMENT_CSP == "default-src 'none'; sandbox; frame-ancestors 'none'"
    assert csp_names_frame_ancestors([_ATTACHMENT_CSP])
    assert _frame_ancestors_values([(CSP_HEADER.lower(), _ATTACHMENT_CSP)]) == ["'none'"]


# --- the baseline set on the escaped paths -------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "request_headers", "expected_status"),
    [
        (
            "ambiguous CL+TE framing",
            (("content-length", "10"), ("transfer-encoding", "chunked")),
            400,
        ),
        ("chunked without a Content-Length", (("transfer-encoding", "chunked"),), 411),
        ("non-integer Content-Length", (("content-length", "not-a-number"),), 400),
        ("oversized Content-Length", (("content-length", "99999999"),), 413),
    ],
)
async def test_a_body_cap_refusal_carries_the_baseline_headers(
    label: str, request_headers: tuple[tuple[str, str], ...], expected_status: int
) -> None:
    """Each of the body cap's four short-circuits returns its own JSONResponse from one layer OUTSIDE
    `_security_headers`, so before the floor every one of them shipped bare. These are pre-auth
    refusals reachable by anyone who can open a socket — exactly the responses a browser most needs
    nosniff and frame-deny on."""
    app = create_app(allow_no_auth=True)
    status, headers = await _drive(app, method="POST", path="/messages", headers=request_headers)
    assert status == expected_status, label
    missing = [n for n in _BASELINE_NAMES if n not in headers]
    assert missing == [], f"{label} shipped without {missing}"


async def test_an_unhandled_exception_carries_the_baseline_headers() -> None:
    """The 500 is the one path NO middleware can reach.

    Starlette's `build_middleware_stack` routes an Exception/500 handler to ServerErrorMiddleware and
    places it OUTSIDE `user_middleware`, so the outermost floor is still inside it. `_unhandled_
    exception` therefore sets the baseline on its own response; this asserts that it does, and that
    the status and PHI-free body are unchanged by the addition."""
    app = create_app(allow_no_auth=True)

    @app.get("/_test/boom")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    status, headers = await _drive(app, path="/_test/boom", expect_raise=True)
    assert status == 500
    missing = [n for n in _BASELINE_NAMES if n not in headers]
    assert missing == [], f"the unhandled-exception response shipped without {missing}"


async def test_the_500_body_and_status_are_unchanged_by_the_header_addition() -> None:
    """This change adds headers. It must not alter the generic body (ASVS 16.5.1 — no internal detail
    reaches the client) or the status, so both are pinned alongside the header assertions."""
    from starlette.testclient import TestClient

    app = create_app(allow_no_auth=True)

    @app.get("/_test/boom2")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/boom2")
    assert response.status_code == 500
    assert response.json() == {"detail": "internal error"}
    assert "deliberate" not in response.text and "RuntimeError" not in response.text


# --- ASVS 3.4.1: HSTS only where a user agent may note it ----------------------------------------


async def test_hsts_is_not_emitted_on_the_shipped_minted_certificate_posture() -> None:
    """THE REGRESSION THIS GUARD EXISTS FOR, and it is not hypothetical.

    Since ADR 0172 the engine mints a self-signed pair and serves https with no operator
    configuration, so the per-request scheme is `https` while `exposure_protected` stays false
    (`ApiSettings.exposure_protected` is `tls_enabled or ...`, and `tls_enabled` is
    `bool(tls_cert_file)`). Measured before the guard: a stock `create_app` driven over that posture
    stamped a one-year `includeSubDomains` policy onto `/health`. RFC 6797 forbids a user agent from
    noting it — the host is an IP literal and the chain is self-signed — and `includeSubDomains` on a
    policy a browser DID note would force https on every other http service on that host for a year.

    The positive control runs in the SAME test: an operator chain on a DNS host still carries it."""
    stock = create_app(allow_no_auth=True)
    _, headers = await _drive(stock, scheme="https", host="127.0.0.1")
    assert HSTS_HEADER.lower() not in headers, headers

    operator_chain = create_app(allow_no_auth=True, exposure_protected=True)
    _, headers = await _drive(operator_chain, scheme="https", host=_DNS_HOST)
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE, (
        "the positive control did not fire, so the suppression above proves nothing"
    )


async def test_hsts_is_refused_for_an_ip_literal_host_under_an_operator_chain() -> None:
    """The two arms are independent: an operator-supplied certificate clears the self-signed test and
    the host test still refuses, because RFC 6797 section 8.1.1 forbids noting an IP-literal host
    however good the chain is. Both IPv4 and a bracketed IPv6 authority are driven, with the DNS
    control for each in the same run."""
    app = create_app(allow_no_auth=True, exposure_protected=True)
    for literal in ("10.1.2.3", "127.0.0.1", "[::1]"):
        _, headers = await _drive(app, scheme="https", host=literal)
        assert HSTS_HEADER.lower() not in headers, literal
    _, headers = await _drive(app, scheme="https", host=_DNS_HOST)
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE


async def test_a_declared_upstream_terminator_still_carries_hsts_over_the_cleartext_hop() -> None:
    """The topology ADR 0172 deliberately excludes: the proxy terminates browser TLS and speaks http
    to the engine, so the engine mints nothing and the per-request scheme reads `http`. The chain in
    front is the OPERATOR'S, so the header belongs on it — the guard must not read a cleartext hop as
    a self-signed one."""
    app = create_app(allow_no_auth=True, exposure_protected=True)
    _, headers = await _drive(app, scheme="http", host=_DNS_HOST)
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE


async def test_hsts_on_an_escaped_response_follows_the_gate_not_a_blanket_default() -> None:
    """HSTS is conditional everywhere else, and the floor must not become the one emitter that ships
    it unconditionally. The http leg is also a second negative control: it shows the presence
    assertions in this file are not simply reporting every header as present."""
    app = create_app(allow_no_auth=True, exposure_protected=True)
    over_http = (("content-length", "99999999"),)

    status, headers = await _drive(
        create_app(allow_no_auth=True), method="POST", path="/messages", headers=over_http
    )
    assert status == 413
    assert HSTS_HEADER.lower() not in headers, "HSTS must not be asserted over cleartext"

    status, headers = await _drive(
        app, method="POST", path="/messages", headers=over_http, scheme="https"
    )
    assert status == 413
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE


async def test_an_operator_declared_https_terminator_gets_hsts_on_the_escaped_paths() -> None:
    """`exposure_protected` is the operator's declaration that the browser-facing scheme is https;
    behind a proxy that omits X-Forwarded-Proto the per-request scheme reads http. Both the floor and
    the 500 handler must honour it, or the escaped responses are the only ones that silently do not."""
    app = create_app(allow_no_auth=True, exposure_protected=True)

    @app.get("/_test/boom3")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    _, headers = await _drive(
        app, method="POST", path="/messages", headers=(("content-length", "99999999"),)
    )
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE

    _, headers = await _drive(app, path="/_test/boom3", expect_raise=True)
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE


async def test_the_timeout_and_network_denial_hand_copies_now_get_hsts_from_the_floor() -> None:
    """`client_networks._DENIAL_HEADERS` and `request_timeout._TIMEOUT_HEADERS` are static tuples that
    cannot decide a scheme-conditional header, so neither carries HSTS — a copy drifting from its
    original is the exact failure the floor exists to end.

    BOTH hand-copies are asserted, because the name says both. The denial is drivable through the real
    app; the timeout needs a handler that never responds, so its leg composes the same two middlewares
    in the same order the app registers them (floor outside, deadline inside) against a stalling inner
    app. Each leg asserts the tuple's OWN header survived alongside the HSTS the floor added, so this
    cannot pass by the floor having flattened the hand-copy."""
    app = create_app(allow_no_auth=True, exposure_protected=True)
    app.state.client_networks = ("10.0.0.0/8",)

    # Loopback is unconditionally allowed by client_network_allowed, so the denial has to be driven
    # from an off-list NON-loopback address or the gate never fires and this test measures nothing.
    status, headers = await _drive(
        app, path="/messages", scheme="https", client=("192.0.2.7", 50000)
    )
    assert status == 403
    assert headers["x-content-type-options"] == "nosniff"  # its own hand-copy, untouched
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE  # supplied by the floor, not by the tuple

    class _Stalls:
        """Never sends a response start, so the deadline is what produces the 503."""

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await asyncio.Event().wait()

    class _FastDeadline:
        # exposure_protected mirrors the app above: without it the https scheme alone now reads as
        # the minted self-signed posture and the floor correctly withholds HSTS.
        state = SimpleNamespace(**{TIMEOUT_STATE_ATTR: 0.01, "exposure_protected": True})

    timeout_stack = SecurityHeaderFloorMiddleware(RequestTimeoutMiddleware(_Stalls()))
    status, headers = await _drive(timeout_stack, scheme="https", scope_app=_FastDeadline())
    assert status == 503
    assert headers["x-content-type-options"] == "nosniff"  # _TIMEOUT_HEADERS, untouched
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE  # supplied by the floor, not by the tuple

    # NEGATIVE CONTROL for the leg above: without the floor the same stack yields the same 503 with
    # NO HSTS, so the assertion is evidence about the floor rather than about the tuple.
    status, headers = await _drive(
        RequestTimeoutMiddleware(_Stalls()), scheme="https", scope_app=_FastDeadline()
    )
    assert status == 503
    assert HSTS_HEADER.lower() not in headers


@pytest.mark.parametrize(
    ("url_host", "bare_host", "is_literal"),
    [
        ("10.1.2.3", "10.1.2.3", True),
        ("127.0.0.1", "127.0.0.1", True),
        ("[::1]", "::1", True),
        ("ops.example.com", "ops.example.com", False),
        ("localhost", "localhost", False),
    ],
)
def test_host_is_ip_literal_agrees_with_the_settings_validator(
    url_host: str, bare_host: str, is_literal: bool
) -> None:
    """ONE definition of "un-notable host", measured rather than asserted.

    `ApiSettings` already refuses an IP-literal `[api].public_origin` under a declared TLS posture,
    with the same RFC 6797 reasoning. The engine must not now apply a SECOND, divergent test to its
    own default posture. The one-way dependency rule forbids `config/` importing `api/`, so the
    predicate cannot literally be shared — this test is what stands in for that, and it exercises
    both arms: the settings model must RAISE exactly where the predicate says literal, and ACCEPT
    exactly where it says name."""
    assert host_is_ip_literal(bare_host) is is_literal
    kwargs: dict[str, Any] = {
        "public_origin": f"https://{url_host}",
        "tls_terminated_upstream": True,
        "trusted_proxies": ["10.0.0.1"],
    }
    if is_literal:
        with pytest.raises(ValidationError, match="IP literal"):
            ApiSettings(**kwargs)
    else:
        assert ApiSettings(**kwargs).public_origin is not None


def test_hsts_notable_requires_the_host_to_be_passed() -> None:
    """`host` is keyword-only and has no default, so an emitter cannot reach the permissive answer by
    forgetting it. Pinned because a default would make every future call site silently un-guarded."""
    with pytest.raises(TypeError):
        hsts_notable("https", True)  # type: ignore[call-arg]
    assert hsts_notable("https", True, host=_DNS_HOST) is True
    assert hsts_notable("https", False, host=_DNS_HOST) is False  # minted self-signed
    assert hsts_notable("https", True, host="10.1.2.3") is False  # un-notable host
    assert hsts_notable("http", False, host=_DNS_HOST) is False  # cleartext, nothing declared


def test_request_host_reads_the_host_header_and_falls_back_to_the_server_tuple() -> None:
    """The Host header is client-supplied, so it is used only to make the floor STRICTER. The fallback
    matters because a forged DNS Host must not be the only thing standing between a loopback install
    and an HSTS policy — which is why the scheme and self-signed tests do not consult it at all."""
    assert request_host({"headers": [(b"host", b"ops.example.com:8765")]}) == "ops.example.com"
    assert request_host({"headers": [(b"host", b"[::1]:8765")]}) == "::1"
    assert request_host({"headers": [(b"host", b"::1")]}) == "::1"  # bare IPv6, no port
    assert request_host({"headers": [], "server": ("127.0.0.1", 8765)}) == "127.0.0.1"
    assert request_host({"headers": []}) == ""
