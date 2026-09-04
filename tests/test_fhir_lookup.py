# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for handler-callable live fhir_lookup (ADR 0043).

Covers the accessor + active-runner indirection (config/fhir_lookup.py), the GET-only read executor
against a FAKED opener (transports/fhir.py FhirLookupExecutor), the FhirLookup factory + Registry table
+ SMART composition (config/wiring.py, transports/smart.py), the fail-closed [egress].allowed_http gate,
the read-by-id / search grammar gate, the CapabilityStatement probe, off-loop execution, and the
end-to-end dry-run-raises / router-raises behavior. Synthetic data only — never real PHI.
"""

from __future__ import annotations

import email.message
import io
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest

from messagefoundry import FhirRaw, FhirToken, fhir_lookup, fhirsearch
from messagefoundry.config.fhir_lookup import FhirLookupError, activated
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    MLLP,
    FhirLookup,
    FhirLookupSpec,
    Registry,
    WiringError,
    build_inbound_connection,
)
from messagefoundry.pipeline import dryrun
from messagefoundry.pipeline.wiring_runner import check_fhir_lookup_allowed
from messagefoundry.store import MessageStatus
from messagefoundry.transports.fhir import (
    FhirLookupExecutor,
    _encode_search_params,
    _resolve_read_url,
)
from messagefoundry.transports.smart import SmartAuthError, with_smart_backend

BASE = "https://fhir.example.org/fhir"
_CONN = {"epic": {"url": BASE}}

PATIENT = json.dumps({"resourceType": "Patient", "id": "123", "name": [{"family": "Synthetic"}]})
SEARCHSET = json.dumps(
    {
        "resourceType": "Bundle",
        "type": "searchset",
        "total": 1,
        "entry": [{"resource": {"resourceType": "Patient", "id": "123"}}],
    }
)


# --- a faked urllib opener (no network) --------------------------------------


class _FakeResp:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _FakeOpener:
    """Records each Request, returns a chosen response or raises a chosen error (per call)."""

    def __init__(self, exc: Exception | None = None, body: bytes = b"", status: int = 200) -> None:
        self.exc = exc
        self.body = body
        self.status = status
        self.requests: list[urllib.request.Request] = []
        self.thread_names: list[str] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        self.requests.append(req)
        self.thread_names.append(threading.current_thread().name)
        if self.exc is not None:
            raise self.exc
        return _FakeResp(self.body, self.status)


def _http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(BASE, code, "err", email.message.Message(), io.BytesIO(body))


def _executor(
    *,
    exc: Exception | None = None,
    body: bytes = b"",
    status: int = 200,
    conn: dict | None = None,
) -> tuple[FhirLookupExecutor, _FakeOpener]:
    ex = FhirLookupExecutor(conn or _CONN)
    opener = _FakeOpener(exc=exc, body=body, status=status)
    for name in ex.connections:  # swap the per-connection opener for the fake
        ex._opener[name] = opener  # type: ignore[attr-defined]
    return ex, opener


# --- accessor + active-runner indirection ------------------------------------


def test_fhir_lookup_raises_with_no_active_runner() -> None:
    # Outside a live Handler (Router / dry-run / no lookups) there is no runner → fail loud.
    with pytest.raises(FhirLookupError, match="unavailable here"):
        fhir_lookup("epic", "Patient/123")


def test_fhir_lookup_delegates_to_active_runner() -> None:
    calls: list[tuple[str, str, Any]] = []

    def runner(connection: str, query: str, params: Any = None) -> dict[str, Any]:
        calls.append((connection, query, params))
        return {"resourceType": "Patient", "id": "123"}

    with activated(runner):
        res = fhir_lookup("epic", "Patient/123")
        # The structured params= form threads through the accessor → runner unchanged (BACKLOG #204).
        # The accessor does not screen: a value's KIND is resolved at encode time (#1243), so the
        # runner receives exactly the FhirToken the author wrote.
        fhir_lookup("epic", "Patient", {"identifier": FhirToken("MRN", "123")})
    assert res == {"resourceType": "Patient", "id": "123"}
    assert calls == [
        ("epic", "Patient/123", None),
        ("epic", "Patient", {"identifier": FhirToken("MRN", "123")}),
    ]
    # The runner is reset on exit — calling again raises.
    with pytest.raises(FhirLookupError):
        fhir_lookup("epic", "Patient/123")


# --- the read executor (faked opener) ----------------------------------------


async def test_read_by_id_returns_resource() -> None:  # AC-1
    ex, opener = _executor(body=PATIENT.encode())
    res = await ex.read("epic", "Patient/123")
    assert res == {"resourceType": "Patient", "id": "123", "name": [{"family": "Synthetic"}]}
    # A read-only GET of {base}/Patient/123 over the hardened opener.
    assert len(opener.requests) == 1
    req = opener.requests[0]
    assert req.get_method() == "GET"
    assert req.full_url == f"{BASE}/Patient/123"
    assert req.data is None  # GET-only: no body, structurally read-only


async def test_search_returns_bundle() -> None:  # AC-2 as amended 2026-08-13 (#1243)
    # ADR 0043's AC-2 originally specified the flat "Patient?identifier=MRN|123" form and named this
    # test as its evidence. #1243 removed that form; the ADR amendment supersedes AC-2 accordingly.
    ex, opener = _executor(body=SEARCHSET.encode())
    res = await ex.read("epic", "Patient", {"identifier": FhirToken("MRN", "123")})
    assert res["resourceType"] == "Bundle" and res["type"] == "searchset"
    req = opener.requests[0]
    assert req.get_method() == "GET"
    assert req.full_url == f"{BASE}/Patient?identifier=MRN%7C123"


async def test_read_unknown_connection() -> None:  # AC-6 (unknown connection)
    ex, _ = _executor()
    with pytest.raises(FhirLookupError, match="no FhirLookup connection named 'nope'"):
        await ex.read("nope", "Patient/123")


async def test_read_runs_off_the_event_loop() -> None:  # AC-9
    ex, opener = _executor(body=PATIENT.encode())
    await ex.read("epic", "Patient/123")
    # The blocking GET ran in a worker thread (asyncio.to_thread), never on the main/loop thread.
    assert opener.thread_names and opener.thread_names[0] != threading.main_thread().name


# --- grammar gate (CWE-918): read-by-id / search path validation -------------


def test_resolve_read_url_by_id() -> None:
    assert _resolve_read_url(BASE, "Patient/123") == f"{BASE}/Patient/123"


def test_resolve_read_url_refuses_flat_query() -> None:  # #1243 limb A
    # The flat '?'-query is GONE. It appended the caller's string with no encoding at all, so there is
    # now exactly one search form and it is encoded by construction.
    with pytest.raises(ValueError, match="not supported") as ei:
        _resolve_read_url(BASE, "Patient?identifier=MRN|123")
    assert "MRN" not in str(ei.value)  # PHI-safe: names the shape, never the query's values


def test_resolve_read_url_refuses_flat_query_even_when_clean() -> None:  # #1243 limb A
    # A query carrying none of the three shapes the old screen rejected ('#', a second '?', a control
    # char) is STILL refused -- the removal is unconditional, not a widened denylist.
    with pytest.raises(ValueError, match="not supported"):
        _resolve_read_url(BASE, "Patient?given=Ann&family=Lee")


@pytest.mark.parametrize(
    "query",
    [
        "../Patient?x=1",  # traversal + a query
        "Patient/1/2?x=1",  # too many segments + a query
        "Pat ient?x=1",  # bad type grammar + a query
    ],
)
def test_path_gate_outranks_the_query_refusal(query: str) -> None:  # #1243 limb A
    """A malformed PATH carrying a '?' must report the PATH defect, not the '?'-query refusal.

    The `?` check sits after the grammar gates deliberately. Moving it earlier would be an easy and
    invisible refactor: every one of these still raises ValueError, so a bare `pytest.raises(ValueError)`
    would pass either way -- and a traversal attempt would then be reported as "pass params= instead",
    masking the more dangerous condition behind the more cosmetic one. The `match=` clause below is
    what makes this test discriminate, so it is mandatory rather than decorative."""
    with pytest.raises(ValueError, match="resourceType is not a valid|path must be"):
        _resolve_read_url(BASE, query)


@pytest.mark.parametrize(
    "query",
    [
        "Patient/123/_history",  # extra path segment (nested/operation)
        "Patient/../Observation",  # traversal
        "../Patient",  # leading traversal
        "Pat ient/1",  # space in type
        "Patient/1#frag",  # '#' in id
        "Patient/1@host",  # '@' in id (userinfo-style host swap)
        "Patient/" + "a" * 65,  # id over the 64-char FHIR grammar
        "http://evil.example/Patient",  # absolute URL smuggled as the path
        "",  # empty
    ],
)
def test_resolve_read_url_rejects_bad_path(query: str) -> None:
    with pytest.raises(ValueError):
        _resolve_read_url(BASE, query)


@pytest.mark.parametrize(
    "query",
    [
        "Patient\n/123",  # LF ends the resourceType segment
        "Patient\n/123\n",  # LF ends both segments
    ],
)
def test_resolve_read_url_rejects_lf_terminated_segment(query: str) -> None:  # #1240
    r"""Python's `$` matches BEFORE a final newline, so `^...$` accepted a segment ending in LF.

    The patterns use `\Z` for exactly this. THE SHAPE MATTERS AND THE OBVIOUS TEST DOES NOT
    DISCRIMINATE: a trailing LF on the whole query (`Patient/123\n`) is normalised away upstream and
    builds a URL byte-identical to the clean input, measured before and after the fix -- so a test
    written that way passes either way and proves nothing. Only an LF ending a segment that is
    followed by more path reaches a gate as a newline-bearing token, and that is what flips from
    BUILT to refused here.
    """
    with pytest.raises(ValueError):
        _resolve_read_url(BASE, query)


def test_lf_terminated_query_is_normalised_not_gated() -> None:  # #1240
    r"""Pins WHY the sibling test uses the shape it does, so nobody 'simplifies' it back.

    `Patient/123\n` builds the same URL as `Patient/123`. That is upstream normalisation, NOT the
    grammar gate doing its job -- if this ever starts raising, the sibling test above is no longer
    the discriminating case and needs re-deriving rather than deleting.
    """
    assert _resolve_read_url(BASE, "Patient/123\n") == _resolve_read_url(BASE, "Patient/123")


async def test_read_rejects_bad_query_phi_safe() -> None:
    ex, opener = _executor(body=PATIENT.encode())
    with pytest.raises(FhirLookupError) as ei:
        await ex.read("epic", "Patient/../secret")
    assert "epic" in str(ei.value)
    assert len(opener.requests) == 0  # never dialed out on an invalid path


# --- structured params= search form: enforced per-value encoding (BACKLOG #204) --------------


def test_resolve_read_url_params_percent_encodes_each_value() -> None:  # #204 (a)
    # The safe structured form: each value is percent-encoded, structure (key=value) preserved.
    url = _resolve_read_url(BASE, "Patient", {"identifier": FhirToken("MRN", "123")})
    assert url == f"{BASE}/Patient?identifier=MRN%7C123"


def test_resolve_read_url_params_multi_and_list() -> None:  # #204 (a)
    # Multiple params keep order/structure; a list value expands to repeated params, which FHIR
    # reads as an AND. A comma inside ONE value is the OR, and that is what FhirRaw exists for
    # (#1243) -- a plain str carrying one is refused, so a list can never be mistaken for an OR.
    url = _resolve_read_url(
        BASE,
        "Patient",
        {"family": "O'Hara", "identifier": [FhirToken("a", "1"), FhirToken("b", "2")]},
    )
    assert url == f"{BASE}/Patient?family=O%27Hara&identifier=a%7C1&identifier=b%7C2"


def test_resolve_read_url_empty_params_is_bare_search() -> None:  # #204 (a)
    # An empty params mapping = a search of the whole resource type (no trailing '?').
    assert _resolve_read_url(BASE, "Patient", {}) == f"{BASE}/Patient"


def _separators_refused_in_a_plain_str() -> list[str]:
    """Which of FHIR's value-layer separators the encoder refuses inside a plain ``str`` value.

    THE PROPERTY, factored out so the same call can be run against a MUTATED screen -- that is the
    negative control below, and without it a green here could come from a check that cannot see the
    failure class at all (SDS-3.8)."""
    refused: list[str] = []
    for separator in fhirsearch.FHIR_VALUE_SEPARATORS:
        try:
            _encode_search_params({"identifier": f"MRN{separator}123"})
        except ValueError:
            refused.append(separator)
    return refused


def test_encode_search_params_holds_the_url_layer_and_refuses_at_the_value_layer() -> None:  # #1243
    """Pin BOTH layers of _encode_search_params' BEHAVIOUR; the mechanism is on that function.

    The URL-layer guarantee is the positive control in the same function: it must keep PASSING while
    the value-layer arm changes, so a value-layer refusal can never be mistaken for the encoder
    having been broken wholesale.

    This arm REPLACES the one that pinned the separators surviving to the value layer. That was the
    documented behaviour until BACKLOG #1243 limb B; it is not any more, and rewriting it is the
    intended act rather than a regression."""
    # CONTROL -- the guarantee that has always held: a value cannot inject an extra search PARAMETER.
    # The exact-list equality pins the count too, so there is no separate len() assertion. Note this
    # value carries NO FHIR value-layer separator, so it is still accepted; only the layers differ.
    hostile = _encode_search_params({"code": "abc&_count=999&identifier=evil"})
    assert hostile == "code=abc%26_count%3D999%26identifier%3Devil"
    assert urllib.parse.parse_qsl(hostile) == [("code", "abc&_count=999&identifier=evil")], (
        "CWE-88 control: one value must stay one parameter"
    )

    # UNDER TEST -- a plain str is DATA, so every FHIR value-layer separator in one is refused. The
    # value never reaches the wire, so no server's escaping behaviour can be wrong about it.
    assert _separators_refused_in_a_plain_str() == list(fhirsearch.FHIR_VALUE_SEPARATORS)


def test_plain_str_refusal_names_the_key_and_withholds_the_value() -> None:  # #1243
    """A refusal must be actionable AND PHI-safe: the key and the character, never the value.

    A search value is the most message-derived string the engine builds, so leaking it into an error
    would put PHI on a path the store does not control (CLAUDE.md section 9)."""
    with pytest.raises(ValueError) as ei:
        _encode_search_params({"identifier": "MRN|8675309"})
    message = str(ei.value)
    assert "identifier" in message, "the author cannot act on a refusal that hides which param"
    assert "8675309" not in message and "MRN|8675309" not in message, (
        "the refused value must NOT appear in the error -- it may carry PHI"
    )
    assert "'|'" in message, (
        "naming the offending separator is routing-safe and makes the fix clear"
    )


def test_fhir_token_passes_the_system_half_and_screens_the_code_half() -> None:  # #1243
    """The token pair is the answer to 'one string, two provenances' -- by not having one string."""
    # The system half is an author literal: it rides through and re-forms the '|' on purpose.
    assert _encode_search_params({"identifier": FhirToken("MRN", "123")}) == "identifier=MRN%7C123"
    # The code half is where message data goes, so it screens exactly as a plain str does.
    for separator in fhirsearch.FHIR_VALUE_SEPARATORS:
        with pytest.raises(ValueError, match="code half"):
            _encode_search_params({"identifier": FhirToken("MRN", f"1{separator}2")})


def test_fhir_raw_carries_author_syntax_through_percent_encoding_only() -> None:  # #1243
    """FHIR's own grammar puts separators INSIDE one value, so the author must be able to say so.

    A composite is one value carrying '$', three '|' and a ',', all structural; repeated params are
    ANDed, so a comma inside one value is the only way to write an OR. Refusing commas with no
    FhirRaw would remove OR from the surface entirely."""
    composite = "code$loinc|12907-2,value$ge150|http://unitsofmeasure.org|mmol/L"
    encoded = _encode_search_params({"code-value-quantity": FhirRaw(composite)})
    # Percent-encoded (the URL layer still holds) and byte-identical after the server decodes it.
    assert urllib.parse.parse_qsl(encoded) == [("code-value-quantity", composite)]
    assert _encode_search_params({"_sort": FhirRaw("status,-date")}) == "_sort=status%2C-date"


def test_an_unsupported_value_kind_is_refused_phi_safely() -> None:  # #1243
    """Config is dynamically loaded Python, so a wrong kind is a runtime question, not just mypy's."""
    with pytest.raises(ValueError) as ei:
        _encode_search_params({"identifier": 8675309})  # type: ignore[dict-item]
    assert "identifier" in str(ei.value) and "8675309" not in str(ei.value)


def test_separator_refusal_negative_control(monkeypatch: pytest.MonkeyPatch) -> None:  # #1243
    """SDS-3.8 non-vacuity: mutate the screen to a pass-through and the property MUST go red.

    A green from a check that cannot see its own failure class is worth nothing, and that is the
    defect BACKLOG #1243 found in the first place -- a suite pinning %7C in five places could not
    disagree with itself. So the control runs the SAME property function as the test above against a
    screen that refuses nothing: it must return an empty list where the real one returns all three."""

    def _passthrough(key: str, value: str, *, half: str) -> str:
        return value  # the mutant: no screen at all

    monkeypatch.setattr(fhirsearch, "_screen", _passthrough)
    assert _separators_refused_in_a_plain_str() == [], (
        "the mutated screen must refuse nothing -- if this still reports refusals, the property is "
        "measuring something other than the screen and proves nothing about it"
    )


# The retired claim, verbatim from the docstring this item corrected. A behaviour test cannot catch
# it coming back -- reverting the prose alone leaves every assertion above green -- so the text is
# pinned separately, the way test_secret_rotation_inventory.py pins its own docstring claim.
_RETIRED_ENCODE_CLAIMS = ("stays a literal, never a separator", "never a separator")


def _encode_docstring_lie(doc: str) -> str | None:
    """The retired claim ``doc`` still makes, else None. Split out so the guard is self-testable."""
    collapsed = " ".join(doc.split())
    return next((lie for lie in _RETIRED_ENCODE_CLAIMS if lie in collapsed), None)


def test_encode_search_params_docstring_states_the_value_layer_rule() -> None:  # #1243
    """The docstring is a security contract, so pin its TEXT, not just the behaviour behind it.

    It used to tell an author that a '|' in a value "stays a literal, never a separator", which is
    false at the FHIR value layer and is the SDS-3.7 defect BACKLOG #1243 records. The behaviour test
    above cannot see that sentence return; this one can. Since limb B it must also state the rule
    that replaced the gap -- refusal by value kind -- because a docstring that merely stops lying
    still leaves an author guessing what to write."""
    doc = _encode_search_params.__doc__ or ""
    assert doc, "_encode_search_params must keep its docstring -- it is the contract under test"

    lie = _encode_docstring_lie(doc)
    assert lie is None, (
        f"_encode_search_params.__doc__ says {lie!r} again. Percent-encoding does NOT make a FHIR "
        "value-layer separator a literal: the server percent-decodes first, then reads FHIR's own "
        "syntax in the decoded value. See BACKLOG #1243."
    )

    collapsed = " ".join(doc.split())
    assert "does not neutralise" in collapsed, (
        "the docstring must positively state the limit, not merely omit the false claim"
    )
    assert "refuses" in collapsed or "refuse" in collapsed, (
        "the docstring must state what happens now, not only what percent-encoding cannot do"
    )
    # Read the alphabet from the engine, not a literal: a fourth separator added there must widen
    # this guard too, rather than leaving it silently passing on three.
    for separator in fhirsearch.FHIR_VALUE_SEPARATORS:
        assert f"``{separator}``" in collapsed, (
            f"the docstring must name {separator!r} as a value-layer separator it does not neutralise"
        )
    for kind in ("FhirToken", "FhirRaw"):
        assert kind in collapsed, f"the docstring must name {kind}, the way out of a refusal"
    assert "#1243" in collapsed, "the docstring must cite the item"


def test_encode_docstring_guard_self_test() -> None:  # #1243
    """Non-vacuity: the guard must FIRE on the retired wording and CLEAR the shipped wording.

    Without this the guard could be silently unable to see its own failure class, which is the
    green-gate trap SDS-3.8 names."""
    retired = "an ``&``/``=``/``|``/``#`` in a value becomes ``%26``/``%3D``/``%7C``/``%23`` and\nstays a literal, never a separator."
    assert _encode_docstring_lie(retired) is not None, "the guard must catch the retired wording"
    assert _encode_docstring_lie(_encode_search_params.__doc__ or "") is None


def test_resolve_read_url_rejects_params_with_query_string() -> None:  # #204, #1243
    # Was "ambiguous, pick one form"; since #1243 removed the flat form a '?' is refused outright,
    # so this case is subsumed rather than special.
    with pytest.raises(ValueError, match="not supported"):
        _resolve_read_url(BASE, "Patient?active=true", {"identifier": FhirToken("MRN", "123")})


async def test_read_params_injection_value_is_encoded() -> None:  # #204 (b)
    ex, opener = _executor(body=SEARCHSET.encode())
    # An attacker-influenced value that TRIES to inject a second FHIR search param via '&_count='.
    await ex.read("epic", "Patient", {"identifier": "123&_count=99999"})
    assert len(opener.requests) == 1
    req = opener.requests[0]
    # The '&' and '=' are percent-encoded → one 'identifier' param, no injected '_count' on the wire.
    assert req.full_url == f"{BASE}/Patient?identifier=123%26_count%3D99999"
    parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)
    assert parsed == {"identifier": ["123&_count=99999"]}  # a single intended search param
    assert "_count" not in parsed  # the injected param never became a real param


# --- flat-string defense-in-depth screen (rejects unambiguous injection shapes) --------------


@pytest.mark.parametrize(
    "query",
    [
        "Patient?identifier=MRN|123#frag",  # a URL fragment ('#')
        "Patient?identifier=MRN|123?evil=1",  # a second '?'
        "Patient?identifier=%0d%0aX-Injected:1",  # percent-decoded control char (CRLF smuggling)
        "Patient?identifier=%00null",  # percent-decoded NUL
    ],
)
async def test_read_flat_search_screen_rejects_injection_shapes(query: str) -> None:  # #204 (c)
    ex, opener = _executor(body=PATIENT.encode())
    with pytest.raises(FhirLookupError):
        await ex.read("epic", query)
    assert len(opener.requests) == 0  # screened BEFORE any dial-out


# --- 1.2.2 / #1243 limb A: there is exactly ONE search form, encoded by construction -----------


def test_read_by_id_unaffected_by_the_removal() -> None:  # #1243 limb A
    # A read-by-id carries no '?' at all, so it never touched the flat path and is unchanged.
    assert _resolve_read_url(BASE, "Patient/123") == f"{BASE}/Patient/123"


def test_structured_params_are_the_only_search_form() -> None:  # #1243 limb A
    # The safe form is untouched by the removal: values stay percent-encoded, structure preserved.
    assert (
        _resolve_read_url(BASE, "Patient", {"identifier": FhirToken("MRN", "123")})
        == f"{BASE}/Patient?identifier=MRN%7C123"
    )


async def test_executor_refuses_flat_read_before_dialling_out() -> None:  # #1243 limb A
    ex, opener = _executor(body=PATIENT.encode())
    with pytest.raises(FhirLookupError):
        await ex.read("epic", "Patient?identifier=MRN|123")
    assert len(opener.requests) == 0  # refused before any dial-out


async def test_executor_params_read_still_works() -> None:  # #1243 limb A
    ex, opener = _executor(body=SEARCHSET.encode())
    await ex.read("epic", "Patient", {"identifier": FhirToken("MRN", "123")})
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url == f"{BASE}/Patient?identifier=MRN%7C123"


async def test_executor_refuses_a_separator_value_before_dialling_out() -> None:  # #1243 limb B
    """The refusal surfaces as a PHI-safe FhirLookupError and no byte leaves the process.

    That last clause is the whole reason limb B refuses rather than backslash-escapes: an escape is
    correct only if the far end implements the unescape, and server behaviour there varies. A value
    that never goes on the wire cannot be misread by any server."""
    ex, opener = _executor(body=SEARCHSET.encode())
    with pytest.raises(FhirLookupError) as ei:
        await ex.read("epic", "Patient", {"identifier": "MRN|8675309"})
    assert "epic" in str(ei.value) and "identifier" in str(ei.value)
    assert "8675309" not in str(ei.value)  # PHI-safe: the value is withheld
    assert len(opener.requests) == 0  # refused before any dial-out


# --- error path is PHI- and secret-safe (AC-6) -------------------------------


async def test_error_is_phi_and_secret_safe_on_http_error() -> None:  # AC-6
    # A 404/500 names only the connection + redacted host + status — never the query values or a body.
    # The value is a FhirToken so the search reaches the HTTP round trip at all: since #1243 a plain
    # str carrying the '|' is refused before dial-out, which would have this test proving the wrong
    # thing (it asserts the error names no parameter, and a refusal names one by design).
    ex, _ = _executor(exc=_http_error(404, body=b'{"resourceType":"OperationOutcome"}'))
    with pytest.raises(FhirLookupError) as ei:
        await ex.read("epic", "Patient", {"identifier": FhirToken("SSN", "000-00-0000")})
    msg = str(ei.value)
    assert "epic" in msg and "404" in msg
    assert "000-00-0000" not in msg  # the query value never reaches the error
    assert "OperationOutcome" not in msg and "identifier" not in msg


async def test_error_on_unparseable_body() -> None:  # AC-6 (unparseable)
    ex, _ = _executor(body=b"<html>not fhir json</html>")
    with pytest.raises(FhirLookupError, match="unparseable"):
        await ex.read("epic", "Patient/123")


async def test_error_on_network_failure() -> None:  # AC-6 (timeout/conn)
    ex, _ = _executor(exc=urllib.error.URLError("connection refused"))
    with pytest.raises(FhirLookupError, match="unreachable"):
        await ex.read("epic", "Patient/123")


# --- SMART bearer (AC-5) -----------------------------------------------------


def _smart_settings(token_url: str = "https://auth.example.org/token") -> dict[str, Any]:
    spec = with_smart_backend(
        FhirLookupSpec("epic", {"url": BASE}),
        token_url=token_url,
        client_id="cid",
        private_key="<pem>",
        scope="system/Patient.rs",
    )
    return spec.settings


def test_with_smart_backend_accepts_fhir_lookup_spec() -> None:  # AC-5 wiring
    s = _smart_settings()
    assert s["smart_token_url"] == "https://auth.example.org/token"
    assert s["smart_client_id"] == "cid" and s["smart_scope"] == "system/Patient.rs"


def test_with_smart_backend_rejects_non_fhir_spec() -> None:
    from messagefoundry.config.wiring import MLLP as _MLLP

    with pytest.raises(SmartAuthError, match="REST/FHIR"):
        with_smart_backend(
            _MLLP(host="h", port=1),
            token_url="https://auth/token",
            client_id="c",
            private_key="k",
        )


async def test_smart_bearer_applied_and_reminted_on_401() -> None:  # AC-5
    # A fake token provider: counts mints + invalidations, no real signing/network.
    class _FakeProvider:
        def __init__(self) -> None:
            self.minted = 0
            self.invalidated = 0

        def access_token(self) -> str:
            self.minted += 1
            return f"tok-{self.minted}"

        def invalidate(self) -> None:
            self.invalidated += 1

    ex, opener = _executor(body=PATIENT.encode())
    prov = _FakeProvider()
    ex._token["epic"] = prov  # type: ignore[attr-defined]
    await ex.read("epic", "Patient/123")
    req = opener.requests[0]
    # The SMART bearer rides the Authorization header on the GET.
    assert req.get_header("Authorization") == "Bearer tok-1"
    assert prov.minted == 1 and prov.invalidated == 0

    # On a 401 the provider is invalidated so the next read re-mints.
    ex2 = FhirLookupExecutor(_CONN)
    opener2 = _FakeOpener(exc=_http_error(401))
    ex2._opener["epic"] = opener2  # type: ignore[attr-defined]
    prov2 = _FakeProvider()
    ex2._token["epic"] = prov2  # type: ignore[attr-defined]
    with pytest.raises(FhirLookupError, match="401"):
        await ex2.read("epic", "Patient/123")
    assert prov2.invalidated == 1


# --- CapabilityStatement probe (AC-8) ----------------------------------------


async def test_capability_statement_probe() -> None:  # AC-8
    ex, opener = _executor(body=b'{"resourceType":"CapabilityStatement"}')
    await ex.test_connection("epic")
    req = opener.requests[0]
    assert req.get_method() == "GET" and req.full_url == f"{BASE}/metadata"


async def test_probe_reports_credential_failure() -> None:  # AC-8 (401/403)
    ex, _ = _executor(exc=_http_error(403))
    with pytest.raises(FhirLookupError, match="check credentials"):
        await ex.test_connection("epic")


async def test_probe_any_other_status_is_reachable() -> None:  # AC-8
    ex, _ = _executor(exc=_http_error(404))  # host answered → reachable, no raise
    await ex.test_connection("epic")


# --- FhirLookup factory + Registry table -------------------------------------


def test_fhir_lookup_factory_registers_and_returns_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import wiring

    reg = Registry()
    monkeypatch.setattr(wiring, "_active", reg)
    spec = FhirLookup("epic", url=BASE)
    assert "epic" in reg.fhir_lookups  # self-registered
    assert reg.fhir_lookups["epic"].settings["url"] == BASE
    assert isinstance(spec, FhirLookupSpec) and spec is reg.fhir_lookups["epic"]  # composable


def test_fhir_lookup_duplicate_name(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import wiring

    reg = Registry()
    monkeypatch.setattr(wiring, "_active", reg)
    FhirLookup("epic", url=BASE)
    with pytest.raises(WiringError, match="duplicate fhir lookup"):
        FhirLookup("epic", url="https://other.example/fhir")


def test_executor_requires_url() -> None:
    with pytest.raises(ValueError, match="requires a 'url'"):
        FhirLookupExecutor({"bad": {"fhir_version": "R4B"}})


def test_executor_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="must be http or https"):
        FhirLookupExecutor({"bad": {"url": "ftp://h/fhir"}})


@pytest.mark.parametrize(
    "url",
    [
        "https://h/fhir\r\nX-Evil: 1",  # CRLF -- request splitting / header injection
        "https://h/fhir\n",  # bare LF
        "https://h/\x00fhir",  # NUL
    ],
)
def test_executor_rejects_control_char_in_url(url: str) -> None:  # #1241
    """The READ executor screens its operator-configured base URL, exactly as the destination does.

    #1241's subject is the ASYMMETRY: one sink screened while a sibling is not reproduces the very
    defect the item reports. This is that sibling -- a second url construction site in the same
    module, reached from operator config, previously checked for type and scheme only.

    Screened at CONSTRUCTION rather than per call: a bad setting is wrong for every lookup this
    connection will ever serve, so it fails the connection at load rather than failing an unbounded
    stream of reads that were never at fault.
    """
    with pytest.raises(ValueError, match="control character"):
        FhirLookupExecutor({"bad": {"url": url}})


def test_executor_clean_url_still_constructs() -> None:  # #1241
    """Positive control: the screen must admit what it is not screening for."""
    ex = FhirLookupExecutor({"ok": {"url": "https://h/fhir"}})
    assert "ok" in ex.connections


# --- fail-closed egress gate (AC-4) ------------------------------------------


def test_check_fhir_lookup_allowed_permits_allowlisted_host() -> None:
    egress = EgressSettings(allowed_http=["fhir.example.org"])
    check_fhir_lookup_allowed("epic", {"url": BASE}, egress)  # no raise


def test_check_fhir_lookup_allowed_denies_unlisted_host() -> None:  # AC-4
    egress = EgressSettings(allowed_http=["fhir.example.org"])
    with pytest.raises(WiringError, match="not in the \\[egress\\].allowed_http"):
        check_fhir_lookup_allowed("epic", {"url": "https://evil.example/fhir"}, egress)


def test_check_fhir_lookup_deny_by_default_refuses_empty_allowlist() -> None:  # AC-4
    egress = EgressSettings(deny_by_default=True)  # empty allowed_http
    with pytest.raises(WiringError, match="deny_by_default"):
        check_fhir_lookup_allowed("epic", {"url": BASE}, egress)


def test_check_fhir_lookup_unrestricted_when_empty() -> None:
    check_fhir_lookup_allowed("epic", {"url": BASE}, EgressSettings())  # no raise


def test_check_fhir_lookup_denies_unlisted_smart_token_url() -> None:  # DELTA-04
    # FHIR base host is allowlisted, but the SMART token endpoint host is not. The signed
    # client_assertion would be POSTed there, so it must be refused exactly like the outbound arm.
    egress = EgressSettings(allowed_http=["fhir.example.org"])
    settings = {"url": BASE, "smart_token_url": "https://evil.example/token"}
    with pytest.raises(WiringError, match="SMART token endpoint"):
        check_fhir_lookup_allowed("epic", settings, egress)


def test_check_fhir_lookup_permits_allowlisted_smart_token_url() -> None:  # DELTA-04
    egress = EgressSettings(allowed_http=["fhir.example.org", "auth.example.org"])
    settings = {"url": BASE, "smart_token_url": "https://auth.example.org/token"}
    check_fhir_lookup_allowed("epic", settings, egress)  # no raise


# --- end-to-end: router + dry-run raise (fhir_lookup is the live exception) ---


def _reg_with_fhir_handler(fn: Any) -> Registry:
    reg = Registry()
    reg.add_router("r", lambda msg: ["h"])  # type: ignore[arg-type]
    reg.add_handler("h", fn)  # type: ignore[arg-type]
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=2576), router="r"))
    return reg


def test_dry_run_raises_when_handler_calls_fhir_lookup() -> None:  # AC-3 (dry-run)
    def handler(msg: Any) -> None:
        fhir_lookup("epic", "Patient", {"identifier": FhirToken("MRN", msg["PID-3.1"])})
        return None

    reg = _reg_with_fhir_handler(handler)
    raw = "MSH|^~\\&|S|F|R|F|20260614||ADT^A01|1|P|2.5\rPID|1||M1^^^MR\r"
    result = dryrun.dry_run(reg, raw, inbound="IB")
    assert result.disposition is MessageStatus.ERROR
    assert "fhir_lookup" in (result.error or "")


def test_router_raises_when_calling_fhir_lookup() -> None:  # AC-3 (router)
    reg = Registry()

    def router(msg: Any) -> list[str]:
        fhir_lookup("epic", "Patient/123")  # routers are pure — no live lookup
        return ["h"]

    reg.add_router("r", router)  # type: ignore[arg-type]
    reg.add_handler("h", lambda msg: None)  # type: ignore[arg-type]
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=2577), router="r"))
    raw = "MSH|^~\\&|S|F|R|F|20260614||ADT^A01|1|P|2.5\rPID|1||M1^^^MR\r"
    result = dryrun.dry_run(reg, raw, inbound="IB")
    assert result.disposition is MessageStatus.ERROR
    assert "fhir_lookup" in (result.error or "")


def test_no_lookup_declared_is_unchanged() -> None:  # AC-7
    # A graph with no FhirLookup: the accessor raises (no runner published), byte-identical to today.
    reg = Registry()
    assert reg.fhir_lookups == {}
    with pytest.raises(FhirLookupError):
        fhir_lookup("epic", "Patient/123")


# --- ASVS 4.2.5: the read URL is the most message-derived URL in the engine ------------------------


async def test_fhir_lookup_over_length_read_url_is_refused() -> None:
    """This executor never called the construction length gate at ALL — fhir.py's only call site was
    the DESTINATION's __init__ — so both the configured base and the per-call read URL were unbounded.
    The query is Handler-supplied and reaches `{base}/{query}` verbatim.

    Mutation: replace the `find_outbound_length_violation` call in `_get` with `violation = None`.
    Red: the `match=` below. **That clause is mandatory, not decorative** — with the guard gone the
    oversize GET reaches the fake opener and `_parse` raises `FhirLookupError` anyway, so a bare
    `pytest.raises(FhirLookupError)` would pass either way and prove nothing."""
    ex, opener = _executor()
    with pytest.raises(FhirLookupError, match="over the 8192-char limit"):
        await ex.read("epic", "Patient", {"name": "a" * 9000})
    assert opener.requests == [], "the over-length request must never reach the opener"


async def test_fhir_lookup_ordinary_read_still_reaches_the_opener() -> None:
    """Byte-identity control for the gate above: a normal read is untouched. Mutation: drop
    MAX_OUTBOUND_URL_LEN to 8 → this reds, proving the gate sits on the ordinary path."""
    ex, opener = _executor(body=b'{"resourceType": "Patient", "id": "123"}')
    await ex.read("epic", "Patient/123")
    assert len(opener.requests) == 1
