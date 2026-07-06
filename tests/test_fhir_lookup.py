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
import urllib.request
from typing import Any

import pytest

from messagefoundry import fhir_lookup
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
from messagefoundry.transports.fhir import FhirLookupExecutor, _resolve_read_url
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
    *, exc: Exception | None = None, body: bytes = b"", status: int = 200, conn: dict | None = None
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
    calls: list[tuple[str, str]] = []

    def runner(connection: str, query: str) -> dict[str, Any]:
        calls.append((connection, query))
        return {"resourceType": "Patient", "id": "123"}

    with activated(runner):
        res = fhir_lookup("epic", "Patient/123")
    assert res == {"resourceType": "Patient", "id": "123"}
    assert calls == [("epic", "Patient/123")]
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


async def test_search_returns_bundle() -> None:  # AC-2
    ex, opener = _executor(body=SEARCHSET.encode())
    res = await ex.read("epic", "Patient?identifier=MRN|123")
    assert res["resourceType"] == "Bundle" and res["type"] == "searchset"
    req = opener.requests[0]
    assert req.get_method() == "GET"
    assert req.full_url == f"{BASE}/Patient?identifier=MRN|123"


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


def test_resolve_read_url_search() -> None:
    assert (
        _resolve_read_url(BASE, "Patient?identifier=MRN|123")
        == f"{BASE}/Patient?identifier=MRN|123"
    )


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


async def test_read_rejects_bad_query_phi_safe() -> None:
    ex, opener = _executor(body=PATIENT.encode())
    with pytest.raises(FhirLookupError) as ei:
        await ex.read("epic", "Patient/../secret")
    assert "epic" in str(ei.value)
    assert len(opener.requests) == 0  # never dialed out on an invalid path


# --- error path is PHI- and secret-safe (AC-6) -------------------------------


async def test_error_is_phi_and_secret_safe_on_http_error() -> None:  # AC-6
    # A 404/500 names only the connection + redacted host + status — never the query values or a body.
    ex, _ = _executor(exc=_http_error(404, body=b'{"resourceType":"OperationOutcome"}'))
    with pytest.raises(FhirLookupError) as ei:
        await ex.read("epic", "Patient?identifier=SSN|000-00-0000")
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
        fhir_lookup("epic", f"Patient?identifier=MRN|{msg['PID-3.1']}")
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
