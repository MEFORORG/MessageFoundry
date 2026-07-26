# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Operator attachment read/download surface (#149, ADR 0105 Phase 3b) + its ASVS 1.3.4 serve-time
neutralization.

The store read method (``attachments_for``), the ``MessageDetail.attachments`` metadata list, and the
audited, PHI-gated ``GET /messages/{message_id}/attachments/{attachment_id}`` download endpoint. Covers
the byte round-trip, the RBAC gate (Viewer → 403), the channel-scope + linkage 404s (the security
crux: never pull a shared content-addressed blob unlinked to an in-scope message), the audit chain
(``record_view`` + ``attachment_download`` with NO bytes), and the Content-Type / Content-Disposition.

**ASVS 1.3.4 (browser-active downgrade + sandbox CSP).** The stored ``content_type`` is a verbatim,
attacker-influenced OBX-5.2 label. The serve-time control is *neutralize at serve*, never a sanitizing
rewrite of the stored clinical bytes (ADR 0105 Approach B keeps the OBX-5.5 value verbatim): a
browser-active label is downgraded to ``application/octet-stream`` — case-folded, so ``Image/SVG+XML``
is treated exactly like ``image/svg+xml`` — which also keeps a ``.svg``/``.html`` extension out of the
download name, and every download response carries ``Content-Security-Policy: default-src 'none';
sandbox``, **including the console's ``/ui`` delegate**, where two ``/ui``-scoped middlewares would
otherwise overwrite a route-level CSP with a console policy that has no ``sandbox``.
"""

from __future__ import annotations

import base64
import logging
import mimetypes
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import _ATTACHMENT_CSP
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

#: Labels a browser may EXECUTE or render as markup — every one of them must serve as the inert binary
#: type. Beyond the four subtypes and the ``+xml`` family the assessor named, this pins the vectors an
#: exact-subtype / suffix test misses: ``application/x-javascript`` (browsers honour it as script),
#: ``image/svg`` (no ``+xml``), ``application/xml-dtd``, ``multipart/x-mixed-replace`` (browser-rendered)
#: and ``text/x-html`` — plus the MIXED-CASE vectors, which the token grammar admits verbatim today and
#: which ``mimetypes`` still resolves to ``.svg``/``.html``.
_BROWSER_ACTIVE_LABELS = (
    "image/svg+xml",
    "text/html",
    "Image/SVG+XML",
    "TEXT/HTML",
    "text/HtMl",
    "application/xhtml+xml",
    "text/xml",
    "application/xml",
    "application/javascript",
    "text/javascript",
    "application/ecmascript",
    "application/x-javascript",
    "application/rss+xml",
    "image/svg",
    "application/xml-dtd",
    "multipart/x-mixed-replace",
    "text/x-html",
)

#: Inert labels that must keep passing through under their own type — the operator still gets a usable
#: download hint, and browser PDF/image viewers are themselves sandboxed.
_PASS_THROUGH_LABELS = ("application/pdf", "image/png", "application/dicom", "text/plain")
#: Leading magic so a CORRECTLY-labelled inert attachment agrees with its declared MIME (ASVS 5.2.2):
#: the download-side MIME-vs-magic check downgrades a sniffable label whose bytes contradict it.
#: dicom/text carry no leading signature, so they need none.
_PASS_THROUGH_MAGIC: dict[str, bytes] = {
    "application/pdf": b"%PDF-",
    "image/png": bytes.fromhex("89504e470d0a1a0a"),  # PNG signature
}


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


async def _seed_labelled(
    engine: Engine, content_type: str, marker: str, *, prefix: bytes = b""
) -> tuple[str, str]:
    """Seed one document carrying ``content_type``, with bytes UNIQUE to ``marker``.

    Attachments are content-addressed and deduplicated: ``put_attachment`` on bytes that already exist
    returns the existing ref and writes nothing, so the FIRST writer's ``content_type`` governs every
    later linkage of the same body. A per-MIME table that reused one document would therefore collapse
    onto the first label and assert nothing — every case must seed its own bytes."""
    doc = base64.b64encode(prefix + f"synthetic document {marker} not real PHI".encode()).decode(
        "ascii"
    )
    ref = await engine.store.put_attachment([doc], content_type)
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    return mid, ref


def _base_media_type(response: httpx.Response) -> str:
    """The served media type without parameters — Starlette appends ``; charset=utf-8`` to any
    ``text/*``, so an equality assertion has to compare the type alone."""
    return response.headers["content-type"].split(";")[0].strip()


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
    # 5.4.1 re-score: pin the FULL served Content-Disposition, not just a substring — the fixed
    # 'attachment; filename="attachment-' prefix + the sha256 content address cut to 16 hex + a
    # mimetypes extension hint, quoted; no user/attacker text reaches the header
    # (api/app.py:_attachment_filename). Seeded straight through the store, so this holds WITHOUT
    # enabling the opt-in stream_threshold_bytes. Compute ext the same way the endpoint does.
    ext = mimetypes.guess_extension("application/pdf") or ""
    assert r.headers["content-disposition"] == f'attachment; filename="attachment-{ref[:16]}{ext}"'


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
    # 5.4.2 re-score: a non-allowlisted / injection-bearing MIME is served as the generic binary
    # type, never the attacker value verbatim (_safe_attachment_content_type), and no injected
    # header survives.
    assert r.headers["content-type"] == "application/octet-stream"
    assert "X-Evil" not in r.headers
    # The served-filename control still holds on a rejected MIME: the extension hint then derives
    # from the octet-stream default, never the attacker text.
    ext = mimetypes.guess_extension("application/octet-stream") or ""
    assert r.headers["content-disposition"] == f'attachment; filename="attachment-{ref[:16]}{ext}"'


async def test_download_downgrades_mislabelled_active_mime_to_octet_stream(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # ASVS 1.3.4/5.2.2: even a TOKEN-CLEAN stored MIME is sender-influenced (OBX-5.2). If it names a
    # sniffable family (image/png) whose magic the reconstructed bytes contradict (DOC leads with %PDF),
    # the download is served as the generic octet-stream so a mislabelled active-content payload can't be
    # rendered as its claimed inert type. The bytes still round-trip byte-for-byte (only the MIME shifts).
    ref = await engine.store.put_attachment([DOC_B64], "image/png")
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.content == DOC  # bytes unchanged; only the served MIME is downgraded


# --- ASVS 1.3.4: browser-active downgrade + sandbox CSP ----------------------


@pytest.mark.parametrize("label", _BROWSER_ACTIVE_LABELS)
async def test_browser_active_label_is_downgraded_to_octet_stream(
    engine: Engine, client: httpx.AsyncClient, label: str
) -> None:
    """A label a browser would execute or render as markup is NEVER served verbatim.

    Mechanically: the served ``Content-Type`` is exactly ``application/octet-stream``, and the served
    filename is exactly the one derived from that inert type — so no ``.svg``/``.html``/``.js`` name is
    produced either. Mixed-case vectors are in the table because the token grammar admits uppercase and
    ``mimetypes`` lower-cases internally, so ``Image/SVG+XML`` yielded a ``.svg`` name before the fix."""
    mid, ref = await _seed_labelled(engine, label, marker=label)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert _base_media_type(r) == "application/octet-stream"
    # Compute the extension the way the endpoint does (mimetypes is machine-local — never pin a
    # literal): the served name must be the octet-stream one, never a scriptable extension.
    ext = mimetypes.guess_extension("application/octet-stream") or ""
    assert r.headers["content-disposition"] == f'attachment; filename="attachment-{ref[:16]}{ext}"'
    assert not r.headers["content-disposition"].rstrip('"').endswith((".svg", ".html", ".xml"))


@pytest.mark.parametrize("label", _PASS_THROUGH_LABELS)
async def test_inert_label_passes_through_unchanged(
    engine: Engine, client: httpx.AsyncClient, label: str
) -> None:
    """The downgrade is targeted, not a blanket octet-stream: a correctly-labelled inert type still
    serves as itself (and still supplies the download-name extension), so operators keep a usable hint.
    Sniffable families (pdf/png) are seeded with matching magic so the 5.2.2 MIME-vs-magic check agrees."""
    mid, ref = await _seed_labelled(
        engine, label, marker=label, prefix=_PASS_THROUGH_MAGIC.get(label, b"")
    )
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert _base_media_type(r) == label
    ext = mimetypes.guess_extension(label) or ""
    assert r.headers["content-disposition"] == f'attachment; filename="attachment-{ref[:16]}{ext}"'


async def test_overlong_label_is_downgraded(engine: Engine, client: httpx.AsyncClient) -> None:
    """The token grammar is unbounded and the stored column has no length check, so an arbitrarily long
    attacker label would otherwise be echoed into a response header."""
    mid, ref = await _seed_labelled(engine, "application/" + "a" * 300, marker="overlong")
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert _base_media_type(r) == "application/octet-stream"


async def test_download_carries_sandbox_csp(engine: Engine, client: httpx.AsyncClient) -> None:
    """Every attachment download response carries ``default-src 'none'; sandbox`` — the clause the
    assessor scored as "no CSP on that response". ``sandbox`` with no ``allow-*`` token puts the
    response in a unique opaque origin, so nothing it contains can execute in the application origin."""
    mid, ref = await _seed_streaming(engine)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert (
        _ATTACHMENT_CSP == "default-src 'none'; sandbox"
    )  # the constant the product actually ships
    # The pre-existing layers are unchanged — the CSP is the fourth, not a replacement.
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("loopback", [False, True])
async def test_ui_delegate_serves_the_sandbox_csp_not_the_console_csp(
    engine: Engine, loopback: bool
) -> None:
    """THE ORDERING GUARD. The console's ``GET /ui/messages/{id}/attachments/{id}`` re-serves the very
    same ``Response`` object, but two ``/ui``-scoped middlewares ASSIGN a ``Content-Security-Policy`` on
    any non-static ``/ui`` path — the engine's ``ui_csp`` overlay and (on a secure context, which
    ``loopback=True`` engages per ADR 0143) the console's per-response nonce CSP. Neither contains
    ``sandbox``, so a route-level header alone is silently overwritten here.

    Mechanically asserts the SERVED header on the delegate is exactly the attachment CSP — the assertion
    fails the moment a middleware re-ordering puts a /ui CSP writer back on top."""
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    mid, ref = await _seed_streaming(engine)
    app = create_app(engine, auth=service, serve_ui=True, loopback=loopback)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        r = await c.get(f"/ui/messages/{mid}/attachments/{ref}")
        assert r.status_code == 200
        assert r.content == DOC
        assert r.headers["content-security-policy"] == _ATTACHMENT_CSP
        assert "sandbox" in r.headers["content-security-policy"]
        # Proof the guard is not vacuous: a sibling /ui page on the SAME app does get a console CSP,
        # so the assertion above is discriminating between two live writers, not observing a no-op.
        # Under loopback the writer is the console's per-response nonce CSP (ADR 0143), the OUTERMOST
        # of the two — pinning the nonce proves the outer writer really is engaged on this app.
        page = await c.get("/ui/messages")
        assert page.status_code == 200
        assert "sandbox" not in page.headers["content-security-policy"]
        assert ("nonce-" in page.headers["content-security-policy"]) is loopback


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


# NOTE: test_runbook_documents_the_shipped_download_safety_mechanism moved to tests/test_off_loopback_runbook.py (2026-07-26). They asserted against
# the deny-listed off-loopback runbook, so on the public mirror they failed at runtime and took
# this whole module's required test leg red — while the rest of this file guards shipped
# behaviour that must keep running publicly. The new home already carries the doc-absent guard.
