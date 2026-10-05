# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``fhir_lookup`` read-by-id refuses an id that is only dots (vault BACKLOG #1589).

The row asked one question before any fix: does a dot-only id change the addressed URL after
client-side normalisation, and does the allowlist run before or after that normalisation? This
module holds the half of the answer a test can reach, in four parts.

1. **The refusal.** ``_resolve_read_url`` and ``FhirLookupExecutor.read`` refuse ``.``, ``..`` and
   ``...``, and still build ``{base}/Patient/<id>`` for an id that only CONTAINS a dot.
2. **The engine does not normalise.** A path handed to the executor's GET reaches the wire as
   written. A loopback server records the request line, so this reads the bytes sent, not the
   ``Request`` object.
3. **The allowlist is asked once, for the base URL, about host and port.** It never sees a per-call
   path, so it could not tell ``{base}/Patient/..`` from ``{base}``.
4. **What RFC 3986 section 5.2.4 does to those paths.** The standard library's own
   ``remove_dot_segments`` (``urljoin``) is the model: ``Patient/..`` becomes the base and
   ``Patient/.`` becomes the type, host unchanged.

**NOT tested, and not testable here:** what a real proxy or FHIR server in front of the engine does
with a dot segment. Part 4 shows what a hop that follows the RFC would do; it is not a reading of
any product. Synthetic data only.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from collections.abc import Iterator

import pytest

from messagefoundry.config.fhir_lookup import FhirLookupError
from messagefoundry.config.settings import EgressSettings
from messagefoundry.transports import egress
from messagefoundry.transports.fhir import (
    _FHIR_ID_RE,
    _FHIR_PATH_ID_RE,
    FhirLookupExecutor,
    _resolve_read_url,
)
from tests.test_fhir_lookup import _FakeOpener

HOST = "fhir.example.org"
BASE = f"https://{HOST}/fhir"
PATIENT = json.dumps({"resourceType": "Patient", "id": "a.b"}).encode()

DOT_ONLY = [".", "..", "..."]
# Each holds a dot and is a real FHIR id. None is a dot segment, so none may be refused.
DOTTED = ["a.b", "1.2.3", ".a", "a.", "..a", "a..", "-.-"]


def _executor(
    egress_settings: EgressSettings | None = None,
) -> tuple[FhirLookupExecutor, _FakeOpener]:
    ex = FhirLookupExecutor(
        {"epic": {"url": BASE}}, egress=egress_settings or EgressSettings(deny_by_default=False)
    )
    opener = _FakeOpener(body=PATIENT)
    ex._opener["epic"] = opener  # type: ignore[assignment]
    return ex, opener


# --- 1. the refusal ----------------------------------------------------------


@pytest.mark.parametrize("dots", DOT_ONLY)
def test_the_plain_id_grammar_admits_dots_and_the_path_id_grammar_does_not(dots: str) -> None:
    """What the refusal tests below rest on, and why a path id has its own pattern.

    The plain id grammar accepts each of these, and percent-encoding leaves each as it is. So the
    ``ValueError`` those tests see can come only from the path-id pattern. If the first line ever
    fails, the plain grammar has been tightened and the second pattern may have become redundant."""
    assert _FHIR_ID_RE.match(dots)
    assert urllib.parse.quote(dots, safe="") == dots
    assert not _FHIR_PATH_ID_RE.match(dots)


@pytest.mark.parametrize("dots", DOT_ONLY)
def test_resolve_read_url_refuses_a_dot_only_id(dots: str) -> None:
    # `match=` names the ID refusal, so a refusal for another reason cannot pass for this one.
    with pytest.raises(ValueError, match="read id is not a valid FHIR id"):
        _resolve_read_url(BASE, f"Patient/{dots}")


@pytest.mark.parametrize("resource_id", DOTTED)
def test_resolve_read_url_still_builds_an_id_that_contains_a_dot(resource_id: str) -> None:
    assert _resolve_read_url(BASE, f"Patient/{resource_id}") == f"{BASE}/Patient/{resource_id}"


@pytest.mark.parametrize("dots", DOT_ONLY)
async def test_read_issues_no_request_for_a_dot_only_id(dots: str) -> None:
    ex, opener = _executor()
    with pytest.raises(FhirLookupError, match="read id is not a valid FHIR id") as ei:
        await ex.read("epic", f"Patient/{dots}")
    assert "'epic'" in str(ei.value)  # names the connection ...
    assert f"Patient/{dots}" not in str(ei.value)  # ... and never the query
    assert opener.requests == []


async def test_read_sends_the_exact_url_for_an_id_that_contains_a_dot() -> None:
    ex, opener = _executor()
    assert await ex.read("epic", "Patient/a.b") == {"resourceType": "Patient", "id": "a.b"}
    assert [(r.get_method(), r.full_url) for r in opener.requests] == [
        ("GET", f"{BASE}/Patient/a.b")
    ]


# --- 2. the engine does not normalise: what reaches the wire -----------------


class _RecordingServer:
    """A loopback HTTP server that keeps each request line exactly as the client sent it."""

    def __init__(self) -> None:
        request_lines: list[str] = []

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                # Not self.path: http.server rewrites a leading '//' there. This is the raw line.
                request_lines.append(self.requestline)
                self.send_response(200)
                self.send_header("Content-Type", "application/fhir+json")
                self.send_header("Content-Length", str(len(PATIENT)))
                self.end_headers()
                self.wfile.write(PATIENT)

            def log_message(self, format: str, *args: object) -> None:
                return None

        self.request_lines = request_lines
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}/fhir"
        # shutdown() waits out one poll, and the default poll is half a second.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def server() -> Iterator[_RecordingServer]:
    srv = _RecordingServer()
    try:
        yield srv
    finally:
        srv.close()


@pytest.mark.parametrize("last_segment", [".", "..", "...", "a.b"])
def test_the_engine_sends_the_path_as_written(server: _RecordingServer, last_segment: str) -> None:
    """The executor's real opener, urllib and http.client remove no dot segment.

    This calls ``_get`` with a hand-built URL, which is the only way a dot-only path can reach the
    opener now that ``read`` refuses one. It answers "would the engine itself have changed the
    target": no. ``a.b`` is the control that shows the recorder is live and reads a different path
    for a different input.

    This records a finding, not a rule. If ``_get`` ever refuses or removes a dot segment itself,
    the ``.`` and ``..`` cases here should change with it: that would be a second gate, not a
    regression."""
    ex = FhirLookupExecutor(
        {"lk": {"url": server.base}}, egress=EgressSettings(deny_by_default=False)
    )
    body, status = ex._get("lk", f"{server.base}/Patient/{last_segment}")
    assert status == 200 and json.loads(body)["resourceType"] == "Patient"
    assert server.request_lines == [f"GET /fhir/Patient/{last_segment} HTTP/1.1"]


# --- 3. the allowlist: asked once, for the base, about host and port ---------


async def test_the_allowlist_is_asked_once_for_the_base_url_and_never_per_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why no allowlist stood between a dot-only id and the request: it is not asked per read.

    This records a finding, not a rule. A per-read egress check would be a gain, and this test
    should then change to say what that check is asked."""
    asked: list[str] = []
    real = egress._http_egress_allowed

    def recording(url: str, allowed: list[str]) -> bool:
        asked.append(url)
        return real(url, allowed)

    monkeypatch.setattr(egress, "_http_egress_allowed", recording)
    ex, opener = _executor(EgressSettings(deny_by_default=True, allowed_http=[HOST]))
    assert asked == [BASE]  # at construction, for the configured base
    await ex.read("epic", "Patient/a.b")
    assert len(opener.requests) == 1  # the read went out ...
    assert asked == [BASE]  # ... and the allowlist was not asked about its URL


@pytest.mark.parametrize("path", ["", "/", "/Patient", "/Patient/a.b", "/Patient/.", "/Patient/.."])
def test_the_allowlist_cannot_tell_one_path_from_another(path: str) -> None:
    assert egress._http_egress_allowed(f"{BASE}{path}", [HOST]) is True
    # The control: the same matcher does refuse, on the one thing it reads.
    assert egress._http_egress_allowed(f"https://other.example.org/fhir{path}", [HOST]) is False


# --- 4. what RFC 3986 section 5.2.4 does to those paths ----------------------


@pytest.mark.parametrize(
    ("last_segment", "normalised"),
    [
        ("..", f"{BASE}/"),  # the base: a whole-system request
        (".", f"{BASE}/Patient/"),  # the type: a type-level request
        ("...", f"{BASE}/Patient/..."),  # not a dot segment, so unchanged
        ("a.b", f"{BASE}/Patient/a.b"),  # the control
    ],
)
def test_rfc_3986_dot_segment_removal_changes_the_target_on_the_same_host(
    last_segment: str, normalised: str
) -> None:
    """A MODEL of a hop that follows the RFC, using the standard library's own implementation.

    It is why ``.`` and ``..`` are refused for more than tidiness: the host the allowlist checked
    is unchanged, and the path is not. It says nothing about what any particular proxy or FHIR
    server does."""
    after = urllib.parse.urljoin(f"{BASE}/", f"Patient/{last_segment}")
    assert after == normalised
    assert urllib.parse.urlsplit(after).hostname == HOST
