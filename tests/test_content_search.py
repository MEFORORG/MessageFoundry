# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Message-content search (ADR 0046, BACKLOG #51) — scan-and-decrypt-per-row first slice.

Covers the encrypted-row scan finding a needle in a body the at-rest bytes hide, the metadata
pre-filter bounding the candidate set, the scan/result caps truncating + telling, the HL7 field-path
resolver, the step-up gate + view_summary redaction, the dedicated ``message_search`` audit row that
never records an MRN-shaped needle, and that the scan runs off the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.content_search import (
    ContentSearchError,
    SearchTarget,
    make_spec,
    row_matches,
)
from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # ≥15, satisfies the ASVS policy

# A synthetic ADT carrying a (fake) MRN + name in PID — never real PHI.
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN9001^^^H^MR||DOE^JANE\r"
ADT2 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG2|P|2.5.1\rPID|1||MRN9002^^^H^MR||ROE^RICHARD\r"


# --- pure matcher unit tests -------------------------------------------------


def test_make_spec_requires_exactly_one_needle() -> None:
    with pytest.raises(ContentSearchError):
        make_spec(content=None, field_path=None, field_value=None)
    with pytest.raises(ContentSearchError):
        make_spec(content="x", field_path="PID-3", field_value=None)


def test_make_spec_rejects_bad_field_path() -> None:
    with pytest.raises(ContentSearchError):
        make_spec(content=None, field_path="not a path", field_value="x")


def test_make_spec_clamps_scan_limit() -> None:
    spec = make_spec(content="x", field_path=None, field_value=None, scan_limit=10_000_000)
    assert spec.scan_limit == 10_000  # MAX_SCAN_LIMIT
    spec0 = make_spec(content="x", field_path=None, field_value=None, scan_limit=0)
    assert spec0.scan_limit == 1


def test_row_matches_substring_case_insensitive() -> None:
    spec = make_spec(content="jane", field_path=None, field_value=None)
    assert row_matches(spec, raw=ADT, summary=None) is True
    assert row_matches(spec, raw=ADT2, summary=None) is False


def test_row_matches_target_summary_only() -> None:
    spec = make_spec(
        content="smith", field_path=None, field_value=None, target=SearchTarget.SUMMARY
    )
    assert row_matches(spec, raw="x smith y", summary=None) is False  # raw ignored
    assert row_matches(spec, raw=None, summary="patient SMITH") is True


def test_row_matches_field_path_value_and_presence() -> None:
    by_value = make_spec(content=None, field_path="PID-5.1", field_value="DOE")
    assert row_matches(by_value, raw=ADT, summary=None) is True
    assert row_matches(by_value, raw=ADT2, summary=None) is False
    presence = make_spec(content=None, field_path="PID-3", field_value=None)
    assert row_matches(presence, raw=ADT, summary=None) is True
    # A body with no PID-3 doesn't satisfy a presence test.
    bare = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|M|P|2.5.1\rPID|1\r"
    assert row_matches(presence, raw=bare, summary=None) is False


def test_row_matches_unparseable_body_is_no_match_not_error() -> None:
    spec = make_spec(content=None, field_path="PID-3", field_value="x")
    assert row_matches(spec, raw="this is not hl7 at all", summary=None) is False


# --- store scan tests (encrypted) --------------------------------------------


async def _seed(store: MessageStore) -> None:
    await store.enqueue_message(
        channel_id="IB_A", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
    )
    await store.enqueue_message(
        channel_id="IB_B", raw=ADT2, deliveries=[], message_type="ADT^A01", control_id="MSG2"
    )


async def test_content_match_on_encrypted_store(tmp_path: Path) -> None:
    """AC-1: a content search returns the message whose DECRYPTED raw matches, even though the at-rest
    bytes are mfenc: ciphertext that a plain SQL LIKE would never match."""
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        await _seed(store)
        # Sanity: the needle is NOT in the at-rest ciphertext (a SQL LIKE would find nothing).
        import sqlite3

        con = sqlite3.connect(db)
        try:
            at_rest = [str(r[0]) for r in con.execute("SELECT raw FROM messages").fetchall()]
        finally:
            con.close()
        # Whole-plaintext absence, not the 4-char needle: a random base64 body contains any given short
        # run with probability ~len/64^k, so `"JANE" not in v` can fail on correct encryption -- and,
        # worse, would pass on a weak encoding that merely missed those four characters. Both seeded
        # messages carry '|' and '\r', which base64 cannot emit, so this form is deterministic.
        assert all(v.startswith(MARKER_PREFIX) for v in at_rest)
        assert all(ADT not in v and ADT2 not in v for v in at_rest)

        spec = make_spec(content="JANE", field_path=None, field_value=None)
        result = await store.search_messages(spec)
        assert result.matched == 1
        assert result.rows[0]["control_id"] == "MSG1"
        assert "raw" not in result.rows[0]  # metadata-only result — no decrypted body returned
    finally:
        await store.close()


async def test_field_path_match(tmp_path: Path) -> None:
    """AC-4: a field-path needle resolves via Peek.field against each decrypted candidate."""
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        await _seed(store)
        spec = make_spec(content=None, field_path="PID-5.1", field_value="ROE")
        result = await store.search_messages(spec)
        assert result.matched == 1 and result.rows[0]["control_id"] == "MSG2"
    finally:
        await store.close()


async def test_metadata_prefilter_bounds_scan(tmp_path: Path) -> None:
    """AC-2: a metadata filter narrows the candidate set so only those rows are decrypted+scanned."""
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        await _seed(store)
        # Channel pre-filter to IB_A: only one candidate row is even considered (scanned == 1).
        spec = make_spec(content="ADT", field_path=None, field_value=None)
        result = await store.search_messages(spec, channel_id="IB_A")
        assert result.scanned == 1 and result.matched == 1
        assert result.rows[0]["channel_id"] == "IB_A"
    finally:
        await store.close()


async def test_scan_cap_truncates(tmp_path: Path) -> None:
    """AC-3: when the candidate set exceeds scan_limit the scan stops and reports truncated."""
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        for i in range(5):
            await store.enqueue_message(
                channel_id="IB_A", raw=ADT2, deliveries=[], control_id=f"C{i}"
            )
        # A needle that matches NOTHING, scan_limit below the candidate count → truncated.
        spec = make_spec(
            content="no-such-needle-xyz", field_path=None, field_value=None, scan_limit=3
        )
        result = await store.search_messages(spec)
        assert result.scanned == 3 and result.matched == 0 and result.truncated is True
    finally:
        await store.close()


async def test_result_cap_limits_returned_rows(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        for i in range(5):
            await store.enqueue_message(
                channel_id="IB_A", raw=ADT, deliveries=[], control_id=f"C{i}"
            )
        spec = make_spec(content="JANE", field_path=None, field_value=None)
        result = await store.search_messages(spec, limit=2)
        assert result.matched == 2 and len(result.rows) == 2  # result cap honored
    finally:
        await store.close()


async def test_identity_store_matches_same_as_encrypted(tmp_path: Path) -> None:
    """The search does not branch on whether a key is configured (IdentityCipher → scan-and-match)."""
    store = await MessageStore.open(tmp_path / "plain.db")  # no cipher
    try:
        await _seed(store)
        spec = make_spec(content="JANE", field_path=None, field_value=None)
        result = await store.search_messages(spec)
        assert result.matched == 1 and result.rows[0]["control_id"] == "MSG1"
    finally:
        await store.close()


async def test_scan_runs_off_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-7: the decrypt+match scan runs via asyncio.to_thread (off the event loop)."""
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        await _seed(store)
        calls: list[str] = []
        real_to_thread = asyncio.to_thread

        async def _spy(func, /, *args, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(getattr(func, "__name__", str(func)))
            return await real_to_thread(func, *args, **kwargs)

        monkeypatch.setattr(asyncio, "to_thread", _spy)
        spec = make_spec(content="JANE", field_path=None, field_value=None)
        await store.search_messages(spec)
        assert "_scan_rows" in calls  # the per-row decrypt loop went off the loop
    finally:
        await store.close()


async def test_no_decrypt_leak_in_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A search must not log the decrypted body or the needle value anywhere (PHI)."""
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        await _seed(store)
        with caplog.at_level(logging.DEBUG):
            spec = make_spec(content="JANE", field_path=None, field_value=None)
            await store.search_messages(spec)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "JANE" not in text and "DOE" not in text and "MRN9001" not in text
    finally:
        await store.close()


# --- API: gating, redaction, audit -------------------------------------------


@pytest.fixture
async def enc_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "api-enc.db", cipher=make_cipher(generate_key()))
    eng = Engine(store)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # Content-search RBAC/step-up gating test, not an MFA test: pin require_mfa=False so the admin's
    # step-up search isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add_user(service: AuthService, username: str, roles: list[str]) -> None:
    user_id = await service.create_local_user(
        username=username, password=PW, display_name=None, email=None, roles=roles, actor="test"
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_search_requires_step_up(enc_engine: Engine) -> None:
    """AC-5: the search route is step-up gated; a stale session is refused (403) before any scan."""
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        # Fresh login is within the step-up window → search works. POST, because the needle now
        # travels in the body (BACKLOG #1184); the gate is the same on both shapes.
        ok = await c.post("/messages/search", headers=_auth(token), json={"content": "JANE"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["matched"] == 1
        # Back-date the step-up window → blocked with the step-up signal.
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)
        blocked = await c.post("/messages/search", headers=_auth(token), json={"content": "JANE"})
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"


async def test_search_gated_and_redacted(enc_engine: Engine) -> None:
    """AC-5: a caller lacking messages:view_summary gets summary/error nulled in the results."""
    service = await _service(enc_engine)
    # OPERATOR has messages:read + replay (step-up capable) but NOT view_summary in the fixed roles?
    # Use ADMINISTRATOR for the full-access baseline and VIEWER-equivalent for the redacted check.
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(
        channel_id="IB_A", raw=ADT, deliveries=[], summary="MRN9001 DOE JANE"
    )
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        r = await c.post(
            "/messages/search",
            headers=_auth(token),
            json={"content": "JANE", "target": "raw"},
        )
        assert r.status_code == 200, r.text
        msgs = r.json()["messages"]
        assert msgs and msgs[0]["summary"] == "MRN9001 DOE JANE"  # admin sees summary


async def test_search_audited_without_phi_needle(enc_engine: Engine) -> None:
    """AC-6: a message_search audit row records actor + filters + counts + needle SHAPE, never the
    MRN-shaped needle value."""
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        # An MRN-shaped digit needle — must NOT appear verbatim in the audit.
        r = await c.post(
            "/messages/search",
            headers=_auth(token),
            json={"content": "9001", "channel_id": "IB_A"},
        )
        assert r.status_code == 200, r.text
    rows = await enc_engine.store.list_audit(limit=50)
    search_rows = [dict(r) for r in rows if r["action"] == "message_search"]
    assert search_rows, "a message_search audit row must be written"
    detail = search_rows[0]["detail"]
    assert "9001" not in detail  # the needle value is never recorded
    parsed = json.loads(detail)
    assert parsed["needle_kind"] == "substring"
    assert parsed["needle_shape"] == "digits"
    assert parsed["needle_len"] == 4
    assert parsed["filters"]["channel_id"] == "IB_A"
    assert "scanned" in parsed and "matched" in parsed


async def test_search_field_path_audit_records_path_not_value(enc_engine: Engine) -> None:
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        r = await c.post(
            "/messages/search",
            headers=_auth(token),
            json={"field_path": "PID-3", "field_value": "MRN9001"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["matched"] == 1
    rows = await enc_engine.store.list_audit(limit=50)
    detail = next(dict(r)["detail"] for r in rows if r["action"] == "message_search")
    assert "MRN9001" not in detail  # the value is PHI — never recorded
    parsed = json.loads(detail)
    assert parsed["field_path"] == "PID-3"  # the structural locator IS recorded
    assert parsed["field_value_present"] is True


async def test_search_bad_request_returns_400(enc_engine: Engine) -> None:
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        # Neither needle supplied.
        r = await c.get("/messages/search", headers=_auth(token))
        assert r.status_code == 400


# --- BACKLOG #1184 (ASVS 14.2.1): the PHI needle is off the query string --------------------------
#
# uvicorn writes the whole request line — query string included — into the stream NSSM captures, and a
# reverse proxy logs it again; browser history keeps a third copy. None of those is reachable by the
# log redactor. So `content` and `field_value` must reach the engine in the BODY, never the URL.
# `field_path` STAYS on the GET: app.py's own `_search_audit_detail` records it as a structural
# locator rather than PHI, which is why it is audited by value while the needle never is.


def test_get_search_routes_declare_no_phi_needle_query_parameter() -> None:
    """The three sibling GETs must not INVITE the needle onto the URL.

    Reads the app's own OpenAPI parameter list, so this measures what the route DECLARES rather than
    what a caller happens to send. ``field_path`` is asserted present on every path as the positive
    control: without it a scan that simply failed to find the route would read identically to a
    route that dropped both needle parameters.

    Mutation: put ``content: str | None = Query(...)`` back on any of the three. Red: the assertion
    prints the offending path and its full parameter list."""
    schema = create_app().openapi()

    def _names(path: str) -> set[str]:
        return {p["name"] for p in schema["paths"][path]["get"].get("parameters", [])}

    for path in ("/messages/search", "/messages/export", "/uploads/{file_id}/messages"):
        names = _names(path)
        assert "field_path" in names, (
            f"GET {path} no longer declares field_path — the structural locator must STAY on the "
            f"query string. Declared: {sorted(names)}"
        )
        assert not ({"content", "field_value"} & names), (
            f"GET {path} still declares the PHI needle on the query string: "
            f"{sorted({'content', 'field_value'} & names)} (all declared: {sorted(names)})"
        )


async def test_search_get_no_longer_honours_a_needle_on_the_query_string(
    enc_engine: Engine,
) -> None:
    """A needle typed onto the GET URL is not merely undeclared — it selects nothing, so no caller can
    keep using the old shape and still get results.

    The positive control runs in the same test: ``field_path`` on the SAME route still returns the
    seeded match, so the 400 below is the needle being gone, not the route being broken."""
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        stale = await c.get("/messages/search", headers=_auth(token), params={"content": "JANE"})
        assert stale.status_code == 400, (
            f"a query-string needle still reached the search: {stale.status_code} {stale.text}"
        )
        ok = await c.get("/messages/search", headers=_auth(token), params={"field_path": "PID-3"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["matched"] == 1  # control: the route works, field_path is kept


async def test_search_takes_the_needle_in_a_post_body(enc_engine: Engine) -> None:
    """POST /messages/search carries the criteria in the request BODY.

    Asserts on the RESOLVED request, not on the call: the needle must be absent from the URL httpx
    put on the wire AND present in the bytes it sent. Asserting only the absence would pass a client
    that silently dropped the term."""
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        r = await c.post(
            "/messages/search",
            headers=_auth(token),
            json={"content": "JANE", "channel_id": "IB_A"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["matched"] == 1
        assert "JANE" not in str(r.request.url), f"the needle rode the URL: {r.request.url}"
        assert b"JANE" in r.request.content  # control: it really was sent, in the body


async def test_post_search_is_still_step_up_gated_and_audited_without_the_needle(
    enc_engine: Engine,
) -> None:
    """The POST variant inherits the GET's controls: step-up, and an audit row that records the
    needle's SHAPE but never its value."""
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    await enc_engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        ok = await c.post("/messages/search", headers=_auth(token), json={"content": "9001"})
        assert ok.status_code == 200, ok.text
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)
        blocked = await c.post("/messages/search", headers=_auth(token), json={"content": "9001"})
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
    rows = [dict(r) for r in await enc_engine.store.list_audit(limit=50)]
    detail = next(r["detail"] for r in rows if r["action"] == "message_search")
    assert "9001" not in detail
    assert json.loads(detail)["needle_shape"] == "digits"


def test_the_search_body_model_and_the_preset_criteria_stay_in_step() -> None:
    """``SearchPresetCriteria``'s docstring claims it "Mirrors the ``/messages/search`` typed params
    exactly". Nothing checked that until BACKLOG #1184 gave the route a body model of its own, so the
    two are now duplicates and a duplicate that nothing pins is a duplicate that drifts.

    They are deliberately separate types rather than one subclassing the other: the console validates
    a posted form against the preset model, the JSON route validates a request body against the
    request model, and neither name should acquire the other's meaning. This is where the copy is kept
    honest -- the same arrangement ``test_apiclient_length_bounds_match_the_transport_constants``
    uses for the bounds ADR 0088 forbids importing.

    ``scan_limit`` is the ONE deliberate difference: it is a per-request cost ceiling, not a saved
    criterion, so it exists on the request and not on the preset.

    Mutation: change ``max_length`` on either model's ``content``. Red: the assertion prints the field
    and both bounds."""
    from messagefoundry.api.models import MessageSearchRequest, SearchPresetCriteria

    request_fields = dict(MessageSearchRequest.model_fields)
    scan_limit = request_fields.pop("scan_limit", None)
    assert scan_limit is not None, "MessageSearchRequest lost its scan_limit ceiling"
    preset_fields = dict(SearchPresetCriteria.model_fields)
    assert set(request_fields) == set(preset_fields), (
        "the search body model and the preset criteria no longer carry the same fields: "
        f"only on the request {sorted(set(request_fields) - set(preset_fields))}; "
        f"only on the preset {sorted(set(preset_fields) - set(request_fields))}"
    )
    for name, field in request_fields.items():
        other = preset_fields[name]
        assert repr(field.annotation) == repr(other.annotation), (
            f"{name}: the request declares {field.annotation}, the preset {other.annotation}"
        )
        assert [repr(m) for m in field.metadata] == [repr(m) for m in other.metadata], (
            f"{name}: the request bounds it {field.metadata}, the preset {other.metadata}"
        )


def test_no_get_or_head_route_declares_a_phi_needle_parameter() -> None:
    """No GET or HEAD route, on either plane, may declare ``content`` or ``field_value``.

    BACKLOG #1184 names this guard directly, and it is the DURABLE half of the item: deleting the
    parameter from five signatures earns the verdict once, this keeps it. Every other test for
    #1184 pins ONE route, so a new GET route -- or a well-meaning re-add to an existing one --
    would put the operator's typed term back into the address bar, browser history and every
    access log on the way, with nothing red.

    Both planes deliberately: the console reaches the handlers in-process, so a console GET that
    re-declared the needle would never touch the JSON route this would otherwise check.
    """
    app = create_app(serve_ui=True)
    banned = {"content", "field_value"}
    offenders: list[str] = []
    seen_query_params = 0
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        methods = route.methods or set()
        if not (methods & {"GET", "HEAD"}):
            continue
        for param in route.dependant.query_params:
            seen_query_params += 1
            name = getattr(param, "alias", None) or param.name
            if name in banned:
                offenders.append(f"{sorted(methods)} {route.path} declares {name!r}")
    # Positive control FIRST: a walk that inspects nothing would report a clean repo forever, which
    # is indistinguishable from a guard that works. Mirrors the "backstop is inert" check elsewhere
    # in this suite.
    assert seen_query_params > 20, (
        f"the route walk found only {seen_query_params} query parameters -- the guard is inert and "
        "its clean result means nothing"
    )
    assert not offenders, (
        "a PHI search needle is declared on a GET/HEAD route again (BACKLOG #1184, ASVS 14.2.1). "
        "The URL, browser history and the access log are outside the redactor's reach; send it in a "
        f"POST body instead. Offenders: {offenders}"
    )
