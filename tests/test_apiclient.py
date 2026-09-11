# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The extracted Qt-free / FastAPI-free engine-client library (ADR 0088).

This is the canonical engine-client entrypoint (:mod:`messagefoundry.apiclient`) — the desktop
console and its ``messagefoundry.console.client`` shim were retired (BACKLOG #103). Here we assert the
public entrypoint works and — critically — that importing it drags in neither PySide6 nor FastAPI, so
the harness / any future client can depend on it headlessly.
"""

from __future__ import annotations

import contextlib
import json
import pathlib
import subprocess
import sys
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from messagefoundry.apiclient import ApiError, EngineClient


def test_public_surface_is_reexported() -> None:
    # The package re-exports the two public names from the client module (same objects).
    from messagefoundry.apiclient.client import ApiError as ClientApiError
    from messagefoundry.apiclient.client import EngineClient as ClientEngineClient

    assert EngineClient is ClientEngineClient
    assert ApiError is ClientApiError


def test_import_pulls_in_no_pyside6_or_fastapi() -> None:
    """Import-integrity (ADR 0088): a fresh interpreter that imports messagefoundry.apiclient must not
    load PySide6 or FastAPI. Run in a subprocess so an already-imported GUI/server from another test
    can't mask a real regression."""
    code = (
        "import sys, json, messagefoundry.apiclient\n"
        "loaded = {\n"
        "  'pyside6': any(m == 'PySide6' or m.startswith('PySide6.') for m in sys.modules),\n"
        "  'fastapi': any(m == 'fastapi' or m.startswith('fastapi.') for m in sys.modules),\n"
        "  'has_client': hasattr(messagefoundry.apiclient, 'EngineClient'),\n"
        "}\n"
        "print(json.dumps(loaded))\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    loaded = json.loads(proc.stdout.strip())
    assert loaded["has_client"] is True
    assert loaded["pyside6"] is False, "importing apiclient must not load PySide6"
    assert loaded["fastapi"] is False, "importing apiclient must not load FastAPI"


def test_transport_guard_refuses_remote_plaintext_http() -> None:
    with pytest.raises(ApiError, match="cleartext"):
        EngineClient("http://engine.example.com:8765")


def test_loopback_http_constructs() -> None:
    EngineClient("http://127.0.0.1:8765").close()


def test_request_maps_non_2xx_to_apierror(monkeypatch: pytest.MonkeyPatch) -> None:
    client = EngineClient("http://127.0.0.1:8765")

    class _Resp:
        status_code = 500
        headers: dict[str, str] = {}
        text = "boom"
        reason_phrase = "Server Error"

        def json(self) -> dict[str, object]:
            return {"detail": "kaboom"}

    # `_request` builds the request (so the #1047 length bound can measure the RESOLVED url) and
    # dispatches it through `send`, so `send` is the transport seam a stub replaces.
    monkeypatch.setattr(client._http, "send", lambda *a, **k: _Resp())
    with pytest.raises(ApiError) as excinfo:
        client.health()
    assert excinfo.value.status == 500


def test_decode_helpers_map_bad_body_to_apierror() -> None:
    from messagefoundry.api.models import ChannelInfo, EngineInfo
    from messagefoundry.apiclient.client import _decode, _decode_list

    with pytest.raises(ApiError, match="invalid response"):
        _decode(httpx.Response(200, json={"unexpected": "shape"}), EngineInfo)
    with pytest.raises(ApiError):
        _decode_list(httpx.Response(200, json={"not": "a list"}), ChannelInfo)


# --- ASVS 4.2.5: the client's own outbound length bound --------------------------------------------


def test_apiclient_length_bounds_match_the_transport_constants() -> None:
    """The constants are DUPLICATED in apiclient rather than imported, because ADR 0088 keeps this
    package engine-free — a GUI/harness process must not pull `transports/` in just to make an HTTP
    call. This test is where the duplication is kept honest: it imports both sides in a TEST process,
    where the coupling is harmless, and reds if either drifts.

    Mutation: change either constant on either side. Red: the assertion names both values."""
    from messagefoundry.apiclient.client import (
        MAX_REQUEST_HEADER_VALUE_LEN,
        MAX_REQUEST_URL_LEN,
    )
    from messagefoundry.transports.rest import (
        MAX_OUTBOUND_HEADER_VALUE_LEN,
        MAX_OUTBOUND_URL_LEN,
    )

    assert MAX_REQUEST_URL_LEN == MAX_OUTBOUND_URL_LEN, (
        f"apiclient bounds the URL at {MAX_REQUEST_URL_LEN} but the transports bound it at "
        f"{MAX_OUTBOUND_URL_LEN}; the duplication has drifted"
    )
    assert MAX_REQUEST_HEADER_VALUE_LEN == MAX_OUTBOUND_HEADER_VALUE_LEN, (
        f"apiclient bounds a header value at {MAX_REQUEST_HEADER_VALUE_LEN} but the transports "
        f"bound it at {MAX_OUTBOUND_HEADER_VALUE_LEN}; the duplication has drifted"
    )


def test_apiclient_refuses_an_over_length_request_path() -> None:
    """`_request` builds `base_url + path`; nothing measured it before. Mutation: delete the URL
    check in `_request`. Red: DID NOT RAISE (the request reaches httpx instead)."""
    from messagefoundry.apiclient.client import ApiError, EngineClient

    client = EngineClient("http://127.0.0.1:8765")
    with pytest.raises(ApiError, match="over the 8192-char limit"):
        client._request("GET", "/messages?q=" + "a" * 9000)


def test_apiclient_measures_the_query_string_httpx_appends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1047: the bound must measure the URL httpx actually sends, not the one the caller
    typed. Every read the console/harness/tray makes goes through ``_get``, which hands its filters
    to httpx as ``params=`` — appended to the URL AFTER any length measured from ``base_url`` and
    ``path`` alone. A long filter value (a search needle, a control id) therefore built an over-long
    request line with nothing refusing it.

    The transport is replaced by a tripwire rather than a stub response: the claim is that the
    request is refused *before* it reaches the wire, and a stub 200 could not tell that apart from a
    request that went out and came back. ``httpx.Client.request`` dispatches through
    ``self.send``, so this one patch covers both the pre-fix (``_http.request``) and post-fix
    (``build_request`` + ``_http.send``) call shapes.

    Mutation: measure ``len(self.base_url) + len(path)`` again. Red: AssertionError from the
    tripwire — the over-long request reached the transport."""
    from messagefoundry.apiclient.client import ApiError, EngineClient

    client = EngineClient("http://127.0.0.1:8765")

    def _tripwire(*args: object, **kwargs: object) -> object:
        raise AssertionError("an over-length request reached the transport")

    monkeypatch.setattr(client._http, "send", _tripwire)
    # base_url + path is 33 chars; the query httpx appends is what breaches the limit.
    with pytest.raises(ApiError, match="over the 8192-char limit"):
        client._get("/messages", control_id="a" * 9000)


def test_apiclient_still_sends_a_query_that_fits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control for the test above: the same call shape with a short query MUST reach the
    transport. Without this, a bound that refused every query-bearing GET would look identical to a
    correct one."""
    from messagefoundry.apiclient.client import EngineClient

    client = EngineClient("http://127.0.0.1:8765")
    sent: list[str] = []

    def _capture(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(client._http, "send", _capture)
    client._get("/messages", control_id="MSG1")
    assert sent == ["http://127.0.0.1:8765/messages?control_id=MSG1"], (
        "the resolved URL (query included) is what the bound measures, so it is what must go out"
    )


# --- ASVS 1.2.2 (BACKLOG #1107): contextual encoding + a URL scheme allow-list ----------------
#
# Two clauses, and only two. Clause 1 percent-encodes the identifiers this client interpolates into
# URL PATH SEGMENTS; clause 2 replaces the host-keyed transport check with a positive URL scheme
# allow-list. The web console URL builder and the FHIR structured-parameter work are clauses 3 and 4
# of the same item and are NOT in scope here (clause 3 already shipped in transports/fhir.py).


def _resolved_raw_path(
    client: EngineClient, call: Callable[[EngineClient, Any], object], identifier: Any
) -> str:
    """Return the path httpx would actually put on the wire for ``call(client, identifier)``.

    The subject is the RESOLVED request, so this asserts against ``httpx.Client.build_request`` --
    the same resolution step ``_request`` uses -- rather than against the f-string the method typed.
    ``raw_path`` is read, never ``.path``: httpx DECODES ``.path``, so a correctly encoded ``%2F``
    reads back there as a bare ``/`` and the assertion would pass on broken code.

    A 2xx with an empty JSON body decodes fine for the methods that return ``None``, and raises
    ``ApiError`` for the ones that decode a model. Either way the request was already built, which
    is the only thing under test, so the decode failure is suppressed.
    """
    captured: list[httpx.Request] = []

    def _capture(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={}, request=request)

    original_send = client._http.send
    client._http.send = _capture  # type: ignore[method-assign]
    try:
        with contextlib.suppress(ApiError):
            call(client, identifier)
    finally:
        client._http.send = original_send  # type: ignore[method-assign]
    assert captured, "the call never reached the transport, so nothing was measured"
    return captured[0].url.raw_path.decode().split("?", 1)[0]


# Every path-segment interpolation site in the client, as (label, call, path template). The template
# holds the LITERAL route around the segment; "{seg}" is where the identifier lands.
_PATH_SEGMENT_SITES: list[tuple[str, Callable[[EngineClient, Any], object], str]] = [
    ("reset_user_mfa", lambda c, v: c.reset_user_mfa(v), "/users/{seg}/reset-mfa"),
    ("start_connection", lambda c, v: c.start_connection(v), "/connections/{seg}/start"),
    ("stop_connection", lambda c, v: c.stop_connection(v), "/connections/{seg}/stop"),
    ("restart_connection", lambda c, v: c.restart_connection(v), "/connections/{seg}/restart"),
    ("purge_connection", lambda c, v: c.purge_connection(v), "/connections/{seg}/purge"),
    ("get_message", lambda c, v: c.get_message(v), "/messages/{seg}"),
    ("replay", lambda c, v: c.replay(v), "/messages/{seg}/replay"),
    ("ack_alert", lambda c, v: c.ack_alert(v), "/alerts/{seg}/ack"),
    ("resolve_alert", lambda c, v: c.resolve_alert(v), "/alerts/{seg}/resolve"),
    ("revoke_session", lambda c, v: c.revoke_session(v), "/me/sessions/{seg}"),
    ("revoke_user_sessions", lambda c, v: c.revoke_user_sessions(v), "/users/{seg}/sessions"),
    ("update_custom_role", lambda c, v: c.update_custom_role(v, "d", []), "/roles/custom/{seg}"),
    ("delete_custom_role", lambda c, v: c.delete_custom_role(v), "/roles/custom/{seg}"),
    ("set_user_roles", lambda c, v: c.set_user_roles(v, []), "/users/{seg}/roles"),
    ("get_channel_scope", lambda c, v: c.get_channel_scope(v), "/users/{seg}/channel-scope"),
    ("set_channel_scope", lambda c, v: c.set_channel_scope(v, None), "/users/{seg}/channel-scope"),
    ("delete_user", lambda c, v: c.delete_user(v), "/users/{seg}"),
]


def test_the_path_segment_site_table_covers_every_interpolation_in_the_client() -> None:
    """Guard the guard: the table above is only evidence if it is the WHOLE population.

    Counts the interpolated path literals in the client source and requires the table to match. A
    new endpoint that interpolates an identifier reds this test rather than slipping in unencoded.

    Mutation: delete a row from ``_PATH_SEGMENT_SITES``. Red: the two counts disagree, and the
    failure prints the literals it found so the difference is readable rather than a bare number."""
    import re

    from messagefoundry.apiclient import client as client_module

    source = pathlib.Path(client_module.__file__).read_text(encoding="utf-8")
    interpolated = re.findall(r'f"(/[^"]*\{[^"]*)"', source)
    assert len(interpolated) == len(_PATH_SEGMENT_SITES), (
        f"the client has {len(interpolated)} interpolated path literals but the table covers "
        f"{len(_PATH_SEGMENT_SITES)}; the literals found were {interpolated}"
    )


@pytest.mark.parametrize(("label", "call", "template"), _PATH_SEGMENT_SITES, ids=lambda v: v)
def test_apiclient_percent_encodes_every_interpolated_path_segment(
    label: str, call: Callable[[EngineClient, Any], object], template: str
) -> None:
    """ASVS 1.2.2 clause 1: an identifier carrying path metacharacters must land in ONE segment.

    ``../..`` is the sharp case. Unencoded it does not merely look wrong -- httpx resolves it and
    the request RETARGETS, so ``start_connection("../../users/admin")`` leaves ``/connections/``
    altogether. Four of these sites carry a connection NAME, which is unconstrained free text
    (``Registry._add`` in config/wiring.py checks only for a duplicate), so the "every id is a
    uuid4 hex" argument does not cover them.

    Mutation: drop the encode helper at any one site. Red: that site's resolved path is the escaped
    or split form instead of the single-segment one, and the message names the site."""
    client = EngineClient("http://127.0.0.1:8765")
    try:
        resolved = _resolved_raw_path(client, call, "../../users/admin")
    finally:
        client.close()
    assert resolved == template.format(seg="..%2F..%2Fusers%2Fadmin"), (
        f"{label}: the identifier escaped its path segment; resolved to {resolved!r}"
    )


@pytest.mark.parametrize(
    ("hostile", "encoded"),
    [
        ("../../users/admin", "..%2F..%2Fusers%2Fadmin"),
        ("a/b", "a%2Fb"),
        ("x?scope=all", "x%3Fscope%3Dall"),
        ("x#frag", "x%23frag"),
    ],
    ids=["dot-dot", "slash", "question", "hash"],
)
def test_apiclient_path_metacharacters_cannot_change_the_resolved_path(
    hostile: str, encoded: str
) -> None:
    """The four metacharacters the item names, against one representative site.

    Each breaks the resolved request differently on unencoded code: ``..`` retargets the route,
    ``/`` splits the segment, ``?`` starts a query, and ``#`` TRUNCATES the path at the fragment --
    so ``start_connection("x#frag")`` resolves to ``/connections/x`` and the ``/start`` verb is gone.

    Mutation: revert the helper at start_connection. Red: the resolved path is the mangled form."""
    client = EngineClient("http://127.0.0.1:8765")
    try:
        resolved = _resolved_raw_path(client, lambda c, v: c.start_connection(v), hostile)
    finally:
        client.close()
    assert resolved == f"/connections/{encoded}/start", (
        f"{hostile!r} changed the resolved path to {resolved!r}"
    )


@pytest.mark.parametrize(("label", "call", "template"), _PATH_SEGMENT_SITES, ids=lambda v: v)
def test_apiclient_leaves_a_plain_identifier_untouched(
    label: str, call: Callable[[EngineClient, Any], object], template: str
) -> None:
    """NEGATIVE CONTROL for the encoding tests above, and it is not optional.

    An encoder that mangled every identifier would satisfy the hostile-input assertions perfectly
    while breaking every real call. This pins that an ordinary identifier -- the shape the API
    actually receives -- rides through byte-identical.

    Mutation: encode an already-encoded value a second time (double-encoding). Red: the plain
    identifier comes back percent-mangled."""
    client = EngineClient("http://127.0.0.1:8765")
    try:
        resolved = _resolved_raw_path(client, call, "IB_ACME_ADT")
    finally:
        client.close()
    assert resolved == template.format(seg="IB_ACME_ADT"), (
        f"{label}: a plain identifier was altered; resolved to {resolved!r}"
    )


def test_apiclient_still_accepts_an_integer_identifier() -> None:
    """``ack_alert``/``resolve_alert`` take an ``int``, and ``urllib.parse.quote`` raises
    ``TypeError`` on a non-str, so the helper has to coerce. This is the test that says so.

    Mutation: drop the ``str()`` coercion in the helper. Red: TypeError, not an assertion."""
    client = EngineClient("http://127.0.0.1:8765")
    try:
        resolved = _resolved_raw_path(client, lambda c, v: c.ack_alert(v), 7)
    finally:
        client.close()
    assert resolved == "/alerts/7/ack", f"an int alert id resolved to {resolved!r}"


@pytest.mark.parametrize(
    "base_url",
    [
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "file:///C:/Windows/win.ini",
        "ms-msdt:/id",
    ],
    ids=["javascript", "data", "file", "os-protocol-handler"],
)
def test_transport_guard_refuses_a_non_http_url_scheme(base_url: str) -> None:
    """ASVS 1.2.2 clause 2: only safe URL protocols are permitted, as a POSITIVE allow-list.

    The shipped check is host-keyed -- it returns early when the host is loopback OR empty. None of
    these four URLs has a hostname, so ``host == ""`` and every one of them builds a client today,
    including the two schemes the ASVS verb names by name.

    Mutation: move the allow-list below the ``host == ""`` early return. Red: DID NOT RAISE."""
    with pytest.raises(ApiError, match="scheme"):
        EngineClient(base_url)


def test_transport_guard_refuses_a_base_url_with_no_scheme() -> None:
    """A schemeless base_url is a typo, and today it builds a client that can never work: urlsplit
    reads ``127.0.0.1:8765`` as scheme ``""`` and ``localhost:8765`` as scheme ``localhost``, both
    with no hostname, so both slip through the ``host == ""`` early return.

    This is a DELIBERATE behavior change, pinned here so it stays a decision rather than a side
    effect: an allow-list admitting only ``http`` and ``https`` refuses both. Failing at
    construction beats failing on the first request with a transport error. Every in-repo caller
    passes an explicit scheme, so nothing shipped changes."""
    with pytest.raises(ApiError, match="scheme"):
        EngineClient("127.0.0.1:8765")
    with pytest.raises(ApiError, match="scheme"):
        EngineClient("localhost:8765")


def test_transport_guard_permits_https_and_loopback_http() -> None:
    """NEGATIVE CONTROL for the allow-list: the two schemes the client exists to speak must pass.

    Without this, an allow-list that refused everything would look identical to a correct one. The
    plaintext-http refusal for a REMOTE host is a separate control with its own test above --
    ``http`` has to clear the allow-list and then still meet that check, message intact."""
    EngineClient("https://engine.example.com:8765").close()
    EngineClient("http://127.0.0.1:8765").close()


# --- ASVS 14.2.1 (BACKLOG #1184): the search needle never rides the query string -------------------


def test_apiclient_sends_the_search_needle_in_the_body_not_the_url() -> None:
    """The needle an operator types is PHI-shaped, and a query string is copied into the engine's
    access log, the reverse proxy's log and browser history — none of which the redactor can reach.

    The subject is the RESOLVED request, so this reads what ``build_request`` produced rather than
    what ``search_messages`` typed. Absence from the URL is asserted TOGETHER with presence in the
    body: on its own, "not in the URL" would also pass for a client that quietly dropped the term.

    Mutation: put ``content=``/``field_value=`` back on the ``_get``. Red: the needle is found in the
    resolved URL, which the message prints."""
    client = EngineClient("http://127.0.0.1:8765")
    captured: list[httpx.Request] = []

    def _capture(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={}, request=request)

    client._http.send = _capture  # type: ignore[method-assign]
    try:
        with contextlib.suppress(ApiError):
            client.search_messages(content="SMITH", field_path="PID-5", field_value="9001")
    finally:
        client.close()

    assert captured, "the call never reached the transport, so nothing was measured"
    sent = captured[0]
    url = str(sent.url)
    assert sent.method == "POST", f"search is still a {sent.method}; the needle cannot ride a body"
    for needle in ("SMITH", "9001"):
        assert needle not in url, f"the needle {needle!r} rode the resolved URL: {url}"
        assert needle.encode() in sent.content, (
            f"the needle {needle!r} reached neither the URL nor the body — it was dropped, not moved"
        )
    assert b"PID-5" in sent.content  # the structural locator travels with its value


# --- ASVS 12.3.3 (BACKLOG #1179): the plaintext escape carries no credential -----------------------
#
# `allow_insecure` used to permit ANYTHING over a non-loopback plaintext hop -- including the bearer
# token and the password its own refusal text names as the reason the hop is refused. ADR 0172 makes
# a stock engine mint a certificate and serve TLS, so the escape can now only ever reach an engine an
# operator DECLARED plaintext (`tls_terminated_upstream`), and it is clamped to unauthenticated reads.
#
# Removing the parameter outright was the alternative. It was rejected because it would delete the
# only expression of that topology and leave the two-box bench rig with no posture at all, while the
# clamp removes the harm and keeps the expression. Measured 2026-09-05: every caller that threads
# `allow_insecure=True` polls tokenless, so the clamp costs them nothing.

_REMOTE_HTTP = "http://engine.example.com:8765"


def _stub_ok(client: EngineClient) -> list[httpx.Request]:
    """Replace the transport seam and record what reached it."""
    captured: list[httpx.Request] = []

    def _capture(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={}, request=request)

    client._http.send = _capture  # type: ignore[method-assign]
    return captured


def test_the_plaintext_escape_still_permits_an_unauthenticated_remote_read() -> None:
    """NEGATIVE CONTROL, and the reason the clamp is a clamp rather than a deletion.

    A clamp that refused everything would look identical to a correct one. The two-box bench pollers
    (``harness/load/shardcert.py``) read ``/stats`` and ``/health`` over exactly this hop with
    ``token=None``, so an unauthenticated read must still go out, with no Authorization header.

    Mutation: move the guard from ``_request``'s token branch to the top of ``_request``. Red: the
    read raises instead of reaching the transport."""
    client = EngineClient(_REMOTE_HTTP, allow_insecure=True)
    captured = _stub_ok(client)
    try:
        with contextlib.suppress(ApiError):
            client.health()
    finally:
        client.close()
    assert captured, "the tokenless read never reached the transport -- the clamp is too wide"
    assert "authorization" not in {k.lower() for k in captured[0].headers}


@pytest.mark.parametrize(
    ("call", "what"),
    [
        (lambda c: c.set_token("tok"), "a bearer token"),
        (lambda c: c.login("alice", "hunter2"), "a password"),
        (lambda c: c.reauth("hunter2"), "a password"),
        (lambda c: c.verify_mfa("123456"), "a second factor"),
    ],
    ids=["set_token", "login", "reauth", "verify_mfa"],
)
def test_the_plaintext_escape_refuses_every_credential(
    call: Callable[[EngineClient], object], what: str
) -> None:
    """Each of the four entry points that attaches or proves a credential must refuse, and the
    refusal must reach the transport seam ZERO times -- a credential that goes out and is then
    reported as refused has already crossed the wire.

    Mutation: drop any one ``_refuse_credential_on_cleartext`` call. Red: that parametrization
    records a request on a hop the message says carries none."""
    client = EngineClient(_REMOTE_HTTP, allow_insecure=True)
    captured = _stub_ok(client)
    try:
        with pytest.raises(ApiError, match="never a credential") as excinfo:
            call(client)
        assert what in str(excinfo.value)
    finally:
        client.close()
    assert captured == [], f"{what} reached the transport before the refusal"


def test_a_token_copied_past_the_entry_points_still_cannot_cross() -> None:
    """A clamp that lived only on ``set_token`` would hold by accident rather than by construction.
    ``_request`` re-checks, so any path that writes the token without going through an entry point is
    covered too — ``_adopt_rotated`` (ASVS 7.2.4) is exactly such a path, and it writes through the
    shared cell rather than the entry points.

    Mutation: delete the token branch in ``_request``. Red: the Authorization header goes out over
    plaintext http to a non-loopback host."""
    client = EngineClient(_REMOTE_HTTP, allow_insecure=True)
    captured = _stub_ok(client)
    client._token = "smuggled"
    try:
        with pytest.raises(ApiError, match="never a credential"):
            client.health()
    finally:
        client.close()
    assert captured == [], "the smuggled bearer token reached the transport"


def test_the_clamp_is_scoped_to_the_cleartext_hop() -> None:
    """POSITIVE CONTROL for the scope: loopback http and https are not cleartext non-loopback hops,
    so a credential must still attach there. Without this, a clamp that fired on every client would
    pass every test above while breaking the console and the harness monitor.

    Mutation: make ``_assert_safe_transport`` return True unconditionally. Red: both arms raise."""
    for url in ("http://127.0.0.1:8765", "https://engine.example.com:8765"):
        client = EngineClient(url)
        assert client._cleartext_hop is False, url
        client._refuse_credential_on_cleartext("a bearer token")  # must not raise
        client.close()


def test_the_remote_plaintext_refusal_no_longer_advertises_the_escape_as_a_fix() -> None:
    """The refusal used to end "Use an https URL, or pass --insecure for a trusted-network dev
    setup", which offered cleartext as a co-equal answer. ADR 0172 makes that false: a stock engine
    serves TLS, so ``--insecure`` cannot make it answer http -- measured 2026-09-05 against a real TLS
    listener, the escape got the client built and the first request died with an opaque
    ``httpx.ReadError``. Advertising a fallback the ASVS verb forbids, which also does not work, is
    the sentence this pins out of the tree.

    Mutation: restore the old sentence. Red: the retired phrasing is found."""
    with pytest.raises(ApiError) as excinfo:
        EngineClient(_REMOTE_HTTP)
    message = str(excinfo.value)
    assert "or pass --insecure for a trusted-network dev setup" not in message
    assert "Use an https URL" in message
    assert "ADR 0172" in message, "the refusal must say WHY http is the wrong scheme"
    assert "carries no credential" in message, (
        "the refusal must state what the escape now cannot do"
    )


# --- ASVS 7.2.4: a rotation must reach the background poll clients -----------


def test_a_rotation_reaches_a_poll_client_cloned_before_it() -> None:
    """RED when: for_polling goes back to COPYING the token instead of sharing the cell.

    The console clones a poll client once, at start-up, and then re-authenticates over the life of
    the session. With a copied token every elevation would strand that clone on a retired bearer and
    every background read on it would 401 -- silently, because the poll client has no handlers and
    the main-thread client would carry on working.
    """
    client = EngineClient("http://127.0.0.1:8765")
    try:
        client._token = "before-rotation"
        poll = client.for_polling()  # cloned BEFORE the rotation, as the console does
        assert poll.token == "before-rotation"

        client._token = "after-rotation"  # what _adopt_rotated does on an elevation response
        assert poll.token == "after-rotation", "the rotation did not reach the poll clone"
    finally:
        client.close()


def test_a_poll_client_never_writes_the_shared_token() -> None:
    """RED when: a background read path starts assigning the token.

    The cell is shared, so a writer on a worker thread would now reach the main-thread client too.
    Sharing is only safe while the primary stays the sole writer -- this pins the direction, and is
    the reason for_polling still installs no step-up/MFA handlers.
    """
    client = EngineClient("http://127.0.0.1:8765")
    try:
        client._token = "primary"
        poll = client.for_polling()
        assert poll._step_up_handler is None and poll._mfa_handler is None
    finally:
        client.close()


# --- ADR 0056 / BACKLOG #1495: the planned-failover call ---------------------------------------------


def test_cluster_stepdown_posts_force_in_the_body_and_decodes_the_result() -> None:
    from messagefoundry.api.request_timeout import DEFAULT_REQUEST_TIMEOUT_SECONDS

    body = {
        "node_id": "node-a",
        "was_leader": True,
        "released_at": 1.5,
        "new_leader_eligible": False,
        "force": True,
    }
    client = EngineClient("http://127.0.0.1:8765")
    captured: list[httpx.Request] = []

    def _capture(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=body, request=request)

    client._http.send = _capture  # type: ignore[method-assign]
    try:
        result = client.cluster_stepdown(force=True)
    finally:
        client.close()

    assert [(r.method, r.url.path) for r in captured] == [("POST", "/cluster/stepdown")]
    assert json.loads(captured[0].content) == {"force": True}
    assert result.model_dump() == body
    # RED when the client's wait drops to or below the engine's request deadline; the comment in
    # EngineClient.cluster_stepdown says why. It compares against the engine constant, not a
    # literal, so raising the engine deadline alone also reds here.
    assert captured[0].extensions["timeout"]["read"] > DEFAULT_REQUEST_TIMEOUT_SECONDS


@pytest.mark.parametrize("status", [400, 403, 409, 412, 503])
def test_cluster_stepdown_keeps_the_engine_status_for_the_caller_to_branch_on(status: int) -> None:
    """A 412 and a 409 call for different next steps, so the status has to survive to the caller."""
    client = EngineClient("http://127.0.0.1:8765")

    def _refuse(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        return httpx.Response(status, json={"detail": f"engine says {status}"}, request=request)

    client._http.send = _refuse  # type: ignore[method-assign]
    try:
        with pytest.raises(ApiError) as caught:
            client.cluster_stepdown()
    finally:
        client.close()
    assert caught.value.status == status
    assert f"engine says {status}" in str(caught.value)
