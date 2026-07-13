# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Operator attachment read/download surface (#149, ADR 0105 Phase 3b).

The store read method (``attachments_for``), the ``MessageDetail.attachments`` metadata list, and the
audited, PHI-gated ``GET /messages/{message_id}/attachments/{attachment_id}`` download endpoint. Covers
the byte round-trip, the RBAC gate (Viewer → 403), the channel-scope + linkage 404s (the security
crux: never pull a shared content-addressed blob unlinked to an in-scope message), the audit chain
(``record_view`` + ``attachment_download`` with NO bytes), and the Content-Type / Content-Disposition.
"""

from __future__ import annotations

import base64
import logging
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # ≥15, no vendor terms — satisfies the ASVS policy
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

# A synthetic "document" (fake PDF bytes) → base64, exactly as Approach B carries the verbatim OBX-5.5
# value into the attachment substrate. The download must decode this back to DOC byte-for-byte.
DOC = b"%PDF-1.4\nsynthetic document body \x00\x01\x02 not real PHI\n%%EOF\n"
DOC_B64 = base64.b64encode(DOC).decode("ascii")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "attach_api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def _seed_streaming(
    engine: Engine, *, channel_id: str = "ch1", content_type: str = "application/pdf"
) -> tuple[str, str]:
    """Put a detached document + a message that links it (the ingress two-object commit). Returns
    ``(message_id, attachment_ref)``."""
    ref = await engine.store.put_attachment([DOC_B64], content_type)
    mid = await engine.store.enqueue_ingress(
        channel_id=channel_id, raw=ADT, control_id="MSG1", attachment_refs=[ref]
    )
    return mid, ref


# --- store: attachments_for --------------------------------------------------


async def test_attachments_for_returns_linked_metadata(engine: Engine) -> None:
    mid, ref = await _seed_streaming(engine)
    rows = await engine.store.attachments_for(mid)
    assert len(rows) == 1
    row = dict(rows[0])
    assert row["attachment_id"] == ref
    assert row["content_type"] == "application/pdf"
    # total_bytes is the reconstructed (verbatim base64) size the store recorded, never a body read.
    assert row["total_bytes"] == len(DOC_B64.encode("utf-8"))


async def test_attachments_for_empty_for_normal_message(engine: Engine) -> None:
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    assert await engine.store.attachments_for(mid) == []


# --- API: MessageDetail.attachments ------------------------------------------


async def test_message_detail_lists_attachments(engine: Engine, client: httpx.AsyncClient) -> None:
    mid, ref = await _seed_streaming(engine)
    detail = (await client.get(f"/messages/{mid}")).json()
    assert len(detail["attachments"]) == 1
    att = detail["attachments"][0]
    assert att["id"] == ref
    assert att["content_type"] == "application/pdf"
    assert att["total_bytes"] == len(DOC_B64.encode("utf-8"))


async def test_message_detail_attachments_empty_for_normal_message(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    assert (await client.get(f"/messages/{mid}")).json()["attachments"] == []


# --- API: download endpoint --------------------------------------------------


async def test_download_round_trips_to_original_bytes(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid, ref = await _seed_streaming(engine)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    # The decoded download is byte-for-byte the original document (the security invariant (f)).
    assert r.content == DOC
    assert r.headers["content-type"].startswith("application/pdf")
    disp = r.headers["content-disposition"]
    assert disp.startswith("attachment; filename=")
    assert ref[:16] in disp  # header-safe filename derived from the sha256 content address


async def test_download_audits_view_and_download_before_returning(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid, ref = await _seed_streaming(engine)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    # record_view → a per-message 'viewed' event; attachment_download → a tamper-evident audit row.
    assert any(e["event"] == "viewed" for e in await engine.store.events_for(mid))
    audit = await engine.store.list_audit()
    dl = [a for a in audit if a["action"] == "attachment_download"]
    assert len(dl) == 1
    # The audit detail names the id pair but NEVER the bytes/base64 (security invariant (b)/(c)).
    detail = dl[0]["detail"] or ""
    assert mid in detail and ref in detail
    assert DOC_B64 not in detail


async def test_download_never_logs_bytes(
    engine: Engine, client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    mid, ref = await _seed_streaming(engine)
    with caplog.at_level(logging.DEBUG):
        r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    blob = "\n".join(rec.getMessage() for rec in caplog.records)
    assert DOC_B64 not in blob
    assert "synthetic document body" not in blob


async def test_download_content_type_defaults_when_not_clean_mime(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # A hostile/attacker-influenced content_type (CRLF header-injection attempt) is never trusted into
    # the response header — it is served as the generic binary type (security invariant on the header).
    ref = await engine.store.put_attachment([DOC_B64], "text/html\r\nX-Evil: 1")
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert "X-Evil" not in r.headers


async def test_download_unknown_message_is_404(client: httpx.AsyncClient) -> None:
    assert (await client.get("/messages/missing/attachments/" + "a" * 64)).status_code == 404


async def test_download_unlinked_attachment_is_404(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # The SECURITY CRUX: an attachment that physically EXISTS but is NOT linked to this message must
    # never be pullable by guessing its content address (content-addressing shares a blob across
    # messages/tenants — the linkage is what scopes access).
    other_ref = await engine.store.put_attachment([DOC_B64], "application/pdf")
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    r = await client.get(f"/messages/{mid}/attachments/{other_ref}")
    assert r.status_code == 404


# --- RBAC + channel scope ----------------------------------------------------


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    uid = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return uid


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_download_requires_view_raw(engine: Engine) -> None:
    # A detached document IS the raw body's PHI — same MESSAGES_VIEW_RAW gate as get_message. A Viewer
    # (no view_raw) is refused 403; an Operator (holds it) downloads it.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "vw", Role.VIEWER)
    mid, ref = await _seed_streaming(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        op = await _login(c, "op")
        vw = await _login(c, "vw")
        assert (await c.get(f"/messages/{mid}/attachments/{ref}", headers=op)).status_code == 200
        assert (await c.get(f"/messages/{mid}/attachments/{ref}", headers=vw)).status_code == 403


async def test_download_out_of_scope_message_is_404_not_403(engine: Engine) -> None:
    # A channel-scoped operator downloading an attachment on a message OUTSIDE their scope gets 404
    # (existence hidden), not 403 — mirroring get_message; the denial is audited.
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    mid_a, ref_a = await _seed_streaming(engine, channel_id="IB_A")
    mid_b, ref_b = await _seed_streaming(engine, channel_id="IB_B")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        assert (await c.get(f"/messages/{mid_a}/attachments/{ref_a}", headers=h)).status_code == 200
        assert (await c.get(f"/messages/{mid_b}/attachments/{ref_b}", headers=h)).status_code == 404
    assert any(a["action"] == "auth.channel_denied" for a in await engine.store.list_audit())
