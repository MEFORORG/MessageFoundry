# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HTTP response-header capture on a captured DeliveryResponse (BACKLOG #154, ADR 0013 amendment).

Covers the four contract points: (1) the connector captures ONLY the per-connection allow-listed
response headers (a non-allow-listed header is never captured — the PHI gate); (2) with no allow-list
the reply is byte-identical (``headers == {}``); (3) the headers round-trip through the store
(``complete_with_response`` → ``correlate_response``, encrypted at rest); (4) a re-ingressed answer's
Handler reads them via ``response_get(dest).headers``.
"""

from __future__ import annotations

import asyncio
import email.message
import urllib.request
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import (
    Loopback,
    Registry,
    Rest,
    build_inbound_connection,
)
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import build_destination
from messagefoundry.transports.rest import (
    RestDestination,
    capture_response_headers,
    normalize_header_allowlist,
)

URL = "https://api.example.com/fhir/Patient"


# --- the pure helpers --------------------------------------------------------


def test_normalize_header_allowlist_lowercases_and_parses() -> None:
    assert normalize_header_allowlist(["Location", "ETag"]) == frozenset({"location", "etag"})
    assert normalize_header_allowlist("Location, ETag ,X-Id") == frozenset(
        {"location", "etag", "x-id"}
    )
    assert normalize_header_allowlist(None) == frozenset()
    assert normalize_header_allowlist([]) == frozenset()
    assert normalize_header_allowlist(123) == frozenset()  # non-list/str → empty


def _reply_headers(**pairs: str) -> email.message.Message:
    msg = email.message.Message()
    for k, v in pairs.items():
        msg[k] = v
    return msg


def test_capture_response_headers_filters_by_allowlist_case_insensitively() -> None:
    hdrs = _reply_headers(Location="/Patient/123", ETag='W/"1"', **{"X-Secret": "PHI"})
    got = capture_response_headers(hdrs, frozenset({"location"}))
    assert got == {"Location": "/Patient/123"}  # allow-listed only; X-Secret NOT captured
    # empty allow-list → nothing captured (byte-identical)
    assert capture_response_headers(hdrs, frozenset()) == {}
    # a header object without .items() → {} (defensive)
    assert capture_response_headers(object(), frozenset({"location"})) == {}


# --- the connector capture ---------------------------------------------------


class _FakeResp:
    def __init__(self, body: bytes, headers: email.message.Message, status: int = 200) -> None:
        self._body = body
        self.headers = headers
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _FakeOpener:
    def __init__(self, resp: _FakeResp) -> None:
        self._resp = resp

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        return self._resp


def _rest(**over: object) -> RestDestination:
    settings = Rest(url=URL, **over).settings  # type: ignore[arg-type]
    d = build_destination(Destination(name="OB_REST", type=ConnectorType.REST, settings=settings))
    assert isinstance(d, RestDestination)
    return d


async def test_rest_captures_only_allowlisted_response_header() -> None:
    dest = _rest(capture_response=True, capture_response_headers=["Location", "ETag"])
    hdrs = _reply_headers(Location="/Patient/9", ETag='W/"3"', **{"X-Trace": "abc"})
    dest._opener = _FakeOpener(_FakeResp(b'{"resourceType":"Patient"}', hdrs, 201))  # type: ignore[assignment]
    resp = await dest.send('{"resourceType":"Patient"}')
    assert resp is not None
    assert resp.outcome == "accepted"
    assert dict(resp.headers) == {"Location": "/Patient/9", "ETag": 'W/"3"'}
    assert "X-Trace" not in resp.headers  # not allow-listed → never captured (PHI gate)


async def test_rest_no_allowlist_is_byte_identical_empty_headers() -> None:
    dest = _rest(capture_response=True)  # capture_response_headers not set
    hdrs = _reply_headers(Location="/Patient/9")
    dest._opener = _FakeOpener(_FakeResp(b"OK", hdrs, 200))  # type: ignore[assignment]
    resp = await dest.send("body")
    assert resp is not None
    assert dict(resp.headers) == {}  # no allow-list → no capture


async def test_rest_empty_2xx_still_carries_headers() -> None:
    dest = _rest(capture_response=True, capture_response_headers=["Location"])
    hdrs = _reply_headers(Location="/Patient/created")
    dest._opener = _FakeOpener(_FakeResp(b"", hdrs, 201))  # type: ignore[assignment]
    resp = await dest.send("body")
    assert resp is not None
    assert resp.outcome == "no_reply"  # empty body
    assert dict(resp.headers) == {"Location": "/Patient/created"}


# --- store round-trip --------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = await MessageStore.open(tmp_path / "rh.db")
    yield s
    await s.close()


async def _enqueue_and_claim(store: MessageStore, *, dest: str = "OB_Q", now: float = 100.0) -> Any:
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|p", deliveries=[(dest, "MSH|p")], now=now
    )
    items = await store.claim_ready(destination_name=dest, now=now)
    assert len(items) == 1
    return mid, items[0]


async def test_complete_with_response_round_trips_headers(store: MessageStore) -> None:
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(
        item.id,
        body="{}",
        outcome="accepted",
        detail="HTTP 201",
        response_headers={"Location": "/Patient/42", "ETag": 'W/"7"'},
        now=101.0,
    )
    caps = await store.correlate_response(mid)
    assert len(caps) == 1
    assert caps[0].headers == {"Location": "/Patient/42", "ETag": 'W/"7"'}


async def test_no_headers_stores_null_and_reads_empty(store: MessageStore) -> None:
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(item.id, body="{}", outcome="accepted", now=101.0)
    cur = await store._db.execute("SELECT resp_headers FROM response WHERE message_id=?", (mid,))
    assert (await cur.fetchone())["resp_headers"] is None  # NULL, byte-identical to pre-#154
    caps = await store.correlate_response(mid)
    assert caps[0].headers == {}


async def test_captured_headers_encrypted_at_rest(tmp_path: Any) -> None:
    # With a cipher configured the resp_headers column is ciphertext (never a plaintext header at rest).
    from messagefoundry.store.crypto import generate_key, make_cipher

    s = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        mid, item = await _enqueue_and_claim(s)
        await s.complete_with_response(
            item.id,
            body="{}",
            outcome="accepted",
            response_headers={"Location": "/Patient/SECRET-MRN"},
            now=101.0,
        )
        cur = await s._db.execute("SELECT resp_headers FROM response WHERE message_id=?", (mid,))
        raw = (await cur.fetchone())["resp_headers"]
        assert raw is not None and "SECRET-MRN" not in raw  # encrypted at rest
        assert (await s.correlate_response(mid))[0].headers == {"Location": "/Patient/SECRET-MRN"}
    finally:
        await s.close()


# --- end-to-end: a re-ingressed Handler reads the captured headers -----------


async def test_reingressed_handler_reads_response_headers_via_response_get(tmp_path: Any) -> None:
    from messagefoundry import response_get
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    store = await MessageStore.open(tmp_path / "e2e.db")
    seen: dict[str, Any] = {}
    try:
        reg = Registry()
        reg.add_inbound(build_inbound_connection("IB_LOOP", Loopback(), router="route_loop"))
        reg.add_router("route_loop", lambda msg: ["h_loop"])

        def h_loop(msg: Any) -> None:
            reply = response_get("OB_X")
            seen["headers"] = None if reply is None else dict(reply.headers)
            return None  # filter

        reg.add_handler("h_loop", h_loop)

        await store.enqueue_message(
            channel_id="IB_REAL", raw="MSH|q", deliveries=[("OB_X", "q")], now=100.0
        )
        item = (await store.claim_ready(destination_name="OB_X", now=100.0))[0]
        reply = "MSH|^~\\&|P|F|R|RF|20260101||RSP^K11|R1|P|2.5.1\r"
        await store.complete_with_response(
            item.id,
            body=reply,
            outcome="accepted",
            response_headers={"Location": "/Patient/abc", "ETag": 'W/"2"'},
            reingress_to="IB_LOOP",
            now=101.0,
        )
        runner = RegistryRunner(reg, store, poll_interval=0.02)
        await runner.start()
        try:
            for _ in range(200):
                await asyncio.sleep(0.02)
                if "headers" in seen:
                    break
        finally:
            await runner.stop()
        assert seen.get("headers") == {"Location": "/Patient/abc", "ETag": 'W/"2"'}
    finally:
        await store.close()
