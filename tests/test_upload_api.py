# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline uploaded-logs API — upload/list/browse/resend/delete (BACKLOG #125/#126, ADR 0134).

RBAC + step-up + audit + the DISTINCT inject path (enqueue_ingress, not reingress) + the path-traversal
guard. Postgres/SQL Server parity is CI's job; these run on SQLite."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    CUSTOM_ROLE_FORBIDDEN_PERMISSIONS,
    CustomRoleError,
    Permission,
    validate_custom_role_permissions,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN123^^^H^MR||DOE^JANE\r"
ADT2 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A04|MSG2|P|2.5.1\rPID|1||MRN999\r"
BATCH = ADT + ADT2


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    e = await Engine.create(tmp_path / "up.db", poll_interval=0.02)
    try:
        yield e
    finally:
        await e.stop()


def _uploads_settings(tmp_path: Path) -> StoreSettings:
    return StoreSettings(uploads_dir=str(tmp_path / "uploads"), max_upload_bytes=1_000_000)


async def _make_user(engine: Engine, role: Role, *, name: str) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username=name,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return service


async def _add_user(service: AuthService, role: Role, *, name: str) -> str:
    """Add a SECOND user to an existing AuthService (the cross-operator tests need two principals on
    one app) and return its user_id. Mirrors _make_user's must-change-password clearing, which every
    route depends on."""
    uid = await service.create_local_user(
        username=name,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return uid


async def _login(c: httpx.AsyncClient, name: str) -> dict[str, str]:
    r = await c.post("/auth/login", json={"username": name, "password": PW, "provider": "local"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _running_registry(tmp_path: Path) -> Registry:
    (tmp_path / "in").mkdir(exist_ok=True)
    (tmp_path / "o1").mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o1")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    return reg


async def test_routes_503_when_unconfigured(engine: Engine, tmp_path: Path) -> None:
    # No [store].uploads_dir → the whole subsystem is disabled (no PHI-at-rest surface).
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/uploads")
        assert r.status_code == 503


async def test_upload_list_browse_roundtrip(engine: Engine, tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        up = await c.post(
            "/uploads", files={"file": ("acme.hl7", BATCH, "application/octet-stream")}, headers=h
        )
        assert up.status_code == 200, up.text
        fid = up.json()["file_id"]
        assert up.json()["message_count"] == 2

        lst = await c.get("/uploads", headers=h)
        assert lst.status_code == 200
        assert [f["file_id"] for f in lst.json()["files"]] == [fid]

        # browse: no filter → both messages, metadata only (never a body).
        br = await c.get(f"/uploads/{fid}/messages", headers=h)
        assert br.status_code == 200, br.text
        body = br.json()
        assert body["total_messages"] == 2 and body["matched"] == 2
        assert {m["message_type"] for m in body["messages"]} == {"ADT^A01", "ADT^A04"}
        assert "PID" not in br.text and "MRN123" not in br.text  # no decrypted body leaks

        # content-search filter on a PHI-shaped needle → the audit records the SHAPE, never the value.
        f = await c.get(f"/uploads/{fid}/messages", params={"content": "MRN123"}, headers=h)
        assert f.status_code == 200 and f.json()["matched"] == 1

    audits = await engine.store.list_audit()
    browse = [a for a in audits if a["action"] == "upload.browse"]
    assert browse, "browse must be audited"
    joined = " ".join(str(a["detail"] or "") for a in browse)
    assert "MRN123" not in joined  # needle value never audited
    assert "digits" in joined or "alnum" in joined  # the needle SHAPE is


async def test_upload_denied_for_viewer(engine: Engine, tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.VIEWER, name="vw")  # no files:* permissions
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "vw")
        up = await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        assert up.status_code == 403
        lst = await c.get("/uploads", headers=h)
        assert lst.status_code == 403


async def test_upload_rejects_disallowed_extension(engine: Engine, tmp_path: Path) -> None:
    # ASVS 5.2.2: a non-text extension is refused with HTTP 400 + a metadata-only upload.reject audit;
    # nothing is written. Covers POST /uploads (which also backs POST /ui/uploaded-logs/upload).
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        up = await c.post(
            "/uploads", files={"file": ("evil.png", BATCH, "application/octet-stream")}, headers=h
        )
        assert up.status_code == 400, up.text
        assert (await c.get("/uploads", headers=h)).json()["files"] == []  # not written
    rej = [a for a in await engine.store.list_audit() if a["action"] == "upload.reject"]
    assert len(rej) == 1
    detail = rej[0]["detail"] or ""
    assert "evil.png" in detail  # sanitized filename + reason (metadata only)
    assert "MSH" not in detail and "MRN" not in detail  # never any body content


async def test_upload_rejects_content_extension_mismatch(engine: Engine, tmp_path: Path) -> None:
    # ASVS 5.2.2: a non-HL7 TEXT body under a .hl7 name passes the 14.2.8 text-only gate but fails the HL7
    # header sniff → HTTP 400 + a metadata-only upload.reject audit, nothing written. (A binary CONTAINER
    # under .hl7 is instead caught earlier by the 14.2.8 text-only 415 gate — see the 415 tests below.)
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        not_hl7 = b"this is a plain text line, not an HL7 message\n"
        up = await c.post("/uploads", files={"file": ("x.hl7", not_hl7, "text/plain")}, headers=h)
        assert up.status_code == 400, up.text
        assert (await c.get("/uploads", headers=h)).json()["files"] == []
    assert any(a["action"] == "upload.reject" for a in await engine.store.list_audit())


async def test_upload_accepts_txt_and_xml(engine: Engine, tmp_path: Path) -> None:
    # ASVS 5.2.2: the accepted text formats flow through unchanged (a plain .txt and a leading-'<' .xml).
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        t = await c.post(
            "/uploads",
            files={"file": ("log.txt", b"a plain diagnostic line\n", "text/plain")},
            headers=h,
        )
        assert t.status_code == 200, t.text
        assert t.json()["content_type"] == "text"
        x = await c.post(
            "/uploads",
            files={"file": ("d.xml", b"<root><child/></root>", "application/xml")},
            headers=h,
        )
        assert x.status_code == 200, x.text
        assert x.json()["content_type"] == "xml"


async def test_upload_rejects_binary_container_415(engine: Engine, tmp_path: Path) -> None:
    # ASVS 14.2.8: a metadata-bearing binary container (JPEG/PDF/ZIP incl. DOCX) is refused with HTTP 415
    # BEFORE anything is written, even under a permitted text extension — so no embedded metadata
    # (EXIF/XMP/docProps) can be stored (closes "no metadata stripping" without a stripper). The magic
    # bytes are sent as BYTES so they survive multipart encoding; the audit records the shape, never a body.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    containers = [
        ("shot.txt", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01 rest of jpeg"),  # JPEG
        ("doc.txt", b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF"),  # PDF
        (
            "bundle.hl7",
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00 [Content_Types].xml word/",
        ),  # ZIP / DOCX
    ]
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        for name, blob in containers:
            up = await c.post("/uploads", files={"file": (name, blob, "text/plain")}, headers=h)
            assert up.status_code == 415, (name, up.status_code, up.text)
        assert (await c.get("/uploads", headers=h)).json()["files"] == []  # nothing written
    rej = [a for a in await engine.store.list_audit() if a["action"] == "upload.reject"]
    assert len(rej) == len(containers)
    joined = " ".join(str(a["detail"] or "") for a in rej)
    assert "shot.txt" in joined and "doc.txt" in joined and "bundle.hl7" in joined  # names recorded
    # Never any body bytes in the audit (only the sanitized filename + a MIME-family reason).
    assert "JFIF" not in joined and "endobj" not in joined and "Content_Types" not in joined


async def test_upload_rejects_nul_body_415(engine: Engine, tmp_path: Path) -> None:
    # ASVS 14.2.8: a NUL-bearing body that is not a recognized container is still refused 415 as non-text.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        up = await c.post(
            "/uploads",
            files={"file": ("log.txt", b"looks textual\x00then a NUL byte", "text/plain")},
            headers=h,
        )
        assert up.status_code == 415, up.text
        assert (await c.get("/uploads", headers=h)).json()["files"] == []
    assert any(a["action"] == "upload.reject" for a in await engine.store.list_audit())


async def test_upload_text_formats_pass_text_only_gate(engine: Engine, tmp_path: Path) -> None:
    # ASVS 14.2.8: the permitted text fixtures are UNCHANGED by the text-only 415 gate — a valid .hl7,
    # a plain .txt and a leading-'<' .xml all still upload (200).
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        for name, blob in (
            ("acme.hl7", BATCH.encode()),
            ("note.txt", b"a plain diagnostic line\n"),
            ("d.xml", b"<root><child/></root>"),
        ):
            up = await c.post("/uploads", files={"file": (name, blob, "text/plain")}, headers=h)
            assert up.status_code == 200, (name, up.text)


async def test_upload_over_quota_rejected_409_and_audited(engine: Engine, tmp_path: Path) -> None:
    # ASVS 5.2.4: with a file-count cap of 1, the second upload is refused HTTP 409 + a metadata-only
    # upload.reject_quota audit; the store still holds exactly one file.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    settings = StoreSettings(
        uploads_dir=str(tmp_path / "uploads"),
        max_upload_bytes=1_000_000,
        max_upload_files_per_user=1,
    )
    app = create_app(engine, auth=service, store_settings=settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        first = await c.post(
            "/uploads", files={"file": ("a.hl7", ADT, "application/octet-stream")}, headers=h
        )
        assert first.status_code == 200, first.text
        second = await c.post(
            "/uploads", files={"file": ("b.hl7", ADT2, "application/octet-stream")}, headers=h
        )
        assert second.status_code == 409, second.text
        assert len((await c.get("/uploads", headers=h)).json()["files"]) == 1  # only the first
    rej = [a for a in await engine.store.list_audit() if a["action"] == "upload.reject_quota"]
    assert len(rej) == 1
    detail = rej[0]["detail"] or ""
    assert "b.hl7" in detail  # sanitized filename + reason (metadata only)
    assert "MSH" not in detail and "MRN" not in detail  # never any body content


async def test_browse_and_delete_path_traversal_404(engine: Engine, tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        # A path-traversal-shaped id never resolves to a file — 404, no filesystem touch.
        for bad in ("..%2f..%2fetc", "abc", "0" * 31):
            r = await c.get(f"/uploads/{bad}/messages", headers=h)
            assert r.status_code == 404, (bad, r.status_code)
        # A well-formed but non-existent id is also 404.
        r = await c.delete(f"/uploads/{'0' * 32}", headers=h)
        assert r.status_code == 404


async def test_delete_confirm_audits(engine: Engine, tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        d = await c.delete(f"/uploads/{fid}", headers=h)
        assert d.status_code == 200 and d.json()["deleted"] is True
        # gone from the listing
        assert (await c.get("/uploads", headers=h)).json()["files"] == []
    assert any(a["action"] == "upload.delete" for a in await engine.store.list_audit())


async def test_resend_injects_via_enqueue_ingress(engine: Engine, tmp_path: Path) -> None:
    # AC-4: resend to a RUNNING inbound injects a fresh RECEIVED message on that channel (the distinct
    # inject path — enqueue_ingress, NOT reingress, which would 404 with no origin row).
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine.add_registry(_running_registry(tmp_path))
    await engine.start()
    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("b.hl7", BATCH, "text/plain")}, headers=h)
        ).json()["file_id"]
        r = await c.post(f"/uploads/{fid}/resend", json={"index": 1, "to": "in1"}, headers=h)
        assert r.status_code == 200, r.text
        mid = r.json()["message_id"]
        assert r.json()["status"] == "injected"

    row = await engine.store.get_message(mid)
    assert row is not None
    assert row["channel_id"] == "in1"
    assert row["source_type"] == "upload"
    # It entered at the ingress stage as a genuine receipt (RECEIVED or already routed by the worker).
    assert row["status"] in (
        MessageStatus.RECEIVED.value,
        MessageStatus.ROUTED.value,
        MessageStatus.PROCESSED.value,
    )
    assert any(a["action"] == "upload.resend" for a in await engine.store.list_audit())


async def test_resend_unknown_and_not_running_inbound(engine: Engine, tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine.add_registry(
        _running_registry(tmp_path)
    )  # registered but engine NOT started → not running
    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("b.hl7", BATCH, "text/plain")}, headers=h)
        ).json()["file_id"]
        # registered-but-not-running → 409
        r = await c.post(f"/uploads/{fid}/resend", json={"index": 0, "to": "in1"}, headers=h)
        assert r.status_code == 409, r.text
        # unregistered inbound → 404
        r = await c.post(f"/uploads/{fid}/resend", json={"index": 0, "to": "nope"}, headers=h)
        assert r.status_code == 404


async def test_engine_inject_message_creates_received(engine: Engine) -> None:
    # The distinct inject primitive at the engine level: a fresh RECEIVED message + ingress row, NO origin.
    mid = await engine.inject_message(channel_id="in1", raw=ADT, source_type="upload")
    row = await engine.store.get_message(mid)
    assert row is not None
    assert row["channel_id"] == "in1"
    assert row["status"] == MessageStatus.RECEIVED.value
    assert row["source_type"] == "upload"


async def test_browse_requires_step_up_and_audits_shape(engine: Engine, tmp_path: Path) -> None:
    # ADR 0134 AC-6: the browse route (decrypts PHI) is step-up gated + records the needle SHAPE, never
    # the value. A fresh login is within the window (200 + shape audit); a back-dated step-up is refused
    # (403 + X-Step-Up-Required), mirroring the content-search guard test.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = await c.post(
            "/auth/login", json={"username": "op", "password": PW, "provider": "local"}
        )
        token = login.json()["token"]
        h = {"Authorization": f"Bearer {token}"}
        fid = (
            await c.post("/uploads", files={"file": ("b.hl7", BATCH, "text/plain")}, headers=h)
        ).json()["file_id"]

        # Fresh login is within the step-up window → browse works, with a PHI-shaped needle.
        ok = await c.get(f"/uploads/{fid}/messages", params={"content": "MRN123"}, headers=h)
        assert ok.status_code == 200, ok.text
        assert ok.json()["matched"] == 1

        # Back-date the step-up window → the next browse is refused BEFORE any decrypt/scan.
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)
        blocked = await c.get(f"/uploads/{fid}/messages", params={"content": "MRN123"}, headers=h)
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"

    # The successful browse recorded the needle SHAPE (digits), never the MRN-shaped value.
    browse = [a for a in await engine.store.list_audit() if a["action"] == "upload.browse"]
    assert browse, "browse must be audited"
    joined = " ".join(str(a["detail"] or "") for a in browse)
    assert "MRN123" not in joined and "alnum" in joined


# --- object-level authorization: owner-only uploaded files (ASVS 8.2.2, BACKLOG #1152) --------------


def test_cross_operator_override_is_granted_to_administrator_only() -> None:
    # The override is the ONLY way past owner-only, so which roles hold it IS the control. Administrator
    # gets it for free (the role is literally frozenset(Permission)); no other built-in role may.
    granting = {
        role
        for role, perms in BUILTIN_ROLE_PERMISSIONS.items()
        if Permission.FILES_ACCESS_ANY in perms
    }
    assert granting == {Role.ADMINISTRATOR}, granting
    assert Permission.FILES_ACCESS_ANY not in BUILTIN_ROLE_PERMISSIONS[Role.OPERATOR]


def test_the_override_cannot_be_minted_onto_a_custom_role() -> None:
    # Walking BUILTIN_ROLE_PERMISSIONS above is NOT enough to make "Administrator only" true: the
    # custom-role builder is a second minting path over the same catalogue (ADR 0045), so unless the
    # override is carved out there, an admin could mint `custom:` with it and hand every operator's
    # uploaded PHI to a non-administrator while docs/SECURITY.md says the grant is admin-only.
    assert Permission.FILES_ACCESS_ANY in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions([Permission.FILES_ACCESS_ANY.value])
    # Carved out on its own, not by poisoning the whole set: browse+delete stay mintable.
    assert validate_custom_role_permissions(
        [Permission.FILES_BROWSE.value, Permission.FILES_DELETE.value]
    ) == [Permission.FILES_BROWSE, Permission.FILES_DELETE]
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions(
            [Permission.FILES_BROWSE.value, Permission.FILES_ACCESS_ANY.value]
        )


async def test_uploaded_files_are_owner_only_across_operators(
    engine: Engine, tmp_path: Path
) -> None:
    # ASVS 8.2.2: a file belongs to the operator who uploaded it. A SECOND operator holding the SAME
    # files:* permissions must not see it in the listing, browse it (the matched/scanned counts are a
    # content oracle over another operator's decrypted PHI), resend it into an inbound they can reach
    # (a two-step path to the body), or delete it. Every denial is a 404 — the same answer as an absent
    # id — so the by-id routes cannot enumerate another operator's file ids.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine.add_registry(_running_registry(tmp_path))
    await engine.start()  # so a resend denial is the OWNER check, not "inbound not running" (409)
    service = await _make_user(engine, Role.OPERATOR, name="op")
    op2_id = await _add_user(service, Role.OPERATOR, name="op2")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h1 = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("acme.hl7", BATCH, "text/plain")}, headers=h1)
        ).json()["file_id"]

        h2 = await _login(c, "op2")
        lst = await c.get("/uploads", headers=h2)
        assert lst.status_code == 200
        assert lst.json() == {"total": 0, "files": [], "scope": "own"}
        assert (await c.get(f"/uploads/{fid}/messages", headers=h2)).status_code == 404
        rs = await c.post(f"/uploads/{fid}/resend", json={"index": 0, "to": "in1"}, headers=h2)
        assert rs.status_code == 404, rs.text
        assert (await c.delete(f"/uploads/{fid}", headers=h2)).status_code == 404

        # The owner is unaffected on every route.
        assert [f["file_id"] for f in (await c.get("/uploads", headers=h1)).json()["files"]] == [
            fid
        ]
        assert (await c.get(f"/uploads/{fid}/messages", headers=h1)).status_code == 200
        own = await c.post(f"/uploads/{fid}/resend", json={"index": 0, "to": "in1"}, headers=h1)
        assert own.status_code == 200, own.text
        assert (await c.delete(f"/uploads/{fid}", headers=h1)).status_code == 200

    denied = [a for a in await engine.store.list_audit() if a["action"] == "upload.denied"]
    assert {json.loads(str(a["detail"]))["operation"] for a in denied} == {
        "browse",
        "resend",
        "delete",
    }
    assert {a["actor"] for a in denied} == {"op2"}
    joined = " ".join(str(a["detail"] or "") for a in denied)
    assert fid in joined  # the denial names the object it refused
    # ...and the PRINCIPAL it refused, by the immutable id, because the actor column's username is the
    # very value this control established is not an identity (see the recycled-username test below).
    assert {json.loads(str(a["detail"]))["actor_user_id"] for a in denied} == {op2_id}
    # ...and nothing else: the detail carries exactly those four keys, so no filename, no owner
    # username and no body content can ride along (the audit log is not a PHI sink).
    for row in denied:
        assert set(json.loads(str(row["detail"]))) == {
            "file_id",
            "operation",
            "reason",
            "actor_user_id",
        }
    assert "acme.hl7" not in joined and "MSH" not in joined and "MRN123" not in joined


async def test_administrator_override_reaches_another_operators_upload(
    engine: Engine, tmp_path: Path
) -> None:
    # ASVS 8.2.2: files:access_any is the explicit cross-operator override. It restores the oversight
    # path owner-only otherwise closes (reviewing or cleaning up a departed operator's uploads), and an
    # administrator holds it with no extra grant because the role is the whole catalogue.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    await _add_user(service, Role.ADMINISTRATOR, name="root")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h1 = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("acme.hl7", BATCH, "text/plain")}, headers=h1)
        ).json()["file_id"]

        ha = await _login(c, "root")
        lst = await c.get("/uploads", headers=ha)
        assert lst.status_code == 200
        assert [(f["file_id"], f["uploader"]) for f in lst.json()["files"]] == [(fid, "op")]
        assert (await c.get(f"/uploads/{fid}/messages", headers=ha)).status_code == 200
        assert (await c.delete(f"/uploads/{fid}", headers=ha)).status_code == 200

    # An allowed cross-operator access is not a denial: nothing is recorded as upload.denied, and the
    # listing audit says which scope the count was taken over.
    audits = await engine.store.list_audit()
    assert not [a for a in audits if a["action"] == "upload.denied"]
    scopes = {json.loads(str(a["detail"]))["scope"] for a in audits if a["action"] == "upload.list"}
    assert scopes == {"any_owner"}


async def test_upload_with_no_owner_id_is_reachable_only_with_the_override(
    engine: Engine, tmp_path: Path
) -> None:
    # FAIL CLOSED on a sidecar carrying no owner id. save() refuses to write one, but UploadStore's
    # tolerant sidecar loader yields uploader_id == "" when the key is absent, and a hand-placed sidecar
    # can be in that state because with no configured key the cipher is the identity cipher and the
    # sidecar is plaintext JSON on disk. Such a file matches NOBODY: it disappears for every operator —
    # including the one who originally uploaded it — and only files:access_any reaches it. Note the
    # DISPLAY name survives here: stripping it is not what makes the file unreachable, which is the
    # whole point of keying authorization on the id. Synthetic HL7 only.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    await _add_user(service, Role.ADMINISTRATOR, name="root")
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h1 = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("acme.hl7", BATCH, "text/plain")}, headers=h1)
        ).json()["file_id"]

        sidecar = tmp_path / "uploads" / f"{fid}.meta"
        stored = json.loads(sidecar.read_text(encoding="utf-8"))
        assert stored.pop("uploader_id")  # plaintext under the identity cipher
        assert stored["uploader"] == "op"  # the display label is deliberately left in place
        sidecar.write_text(json.dumps(stored), encoding="utf-8")

        assert (await c.get("/uploads", headers=h1)).json() == {
            "total": 0,
            "files": [],
            "scope": "own",
        }
        assert (await c.get(f"/uploads/{fid}/messages", headers=h1)).status_code == 404
        assert (await c.delete(f"/uploads/{fid}", headers=h1)).status_code == 404

        ha = await _login(c, "root")
        lst = await c.get("/uploads", headers=ha)
        assert [(f["file_id"], f["uploader"]) for f in lst.json()["files"]] == [(fid, "op")]
        assert lst.json()["scope"] == "any_owner"  # the override holder's listing says so
        assert (await c.get(f"/uploads/{fid}/messages", headers=ha)).status_code == 200
        assert (await c.delete(f"/uploads/{fid}", headers=ha)).status_code == 200


async def test_a_recreated_username_cannot_reach_the_departed_operators_upload(
    engine: Engine, tmp_path: Path
) -> None:
    """ASVS 8.2.2: ownership keys on the IMMUTABLE account id, never on the username.

    A username is unique among live accounts but it is reusable: ``delete_user`` frees it and
    ``create_local_user`` takes it back, minting a DIFFERENT ``user_id``. Keying on the name would
    hand that new principal — which holds no ``files:access_any`` — the departed operator's uploaded
    PHI: 200 on the listing, 200 on the decrypting browse, 200 on delete, and no ``upload.denied``
    row, because the engine would consider it the owner. Synthetic HL7 only.

    SCOPE OF THIS TEST, stated so a green is not over-read. It pins the LOCAL delete-and-recreate
    path, where a new ``user_id`` is genuinely minted. ``_upsert_ad_user`` mints one only when NO
    mirror row survives — i.e. also only after a delete — so on the DEFAULT AD path (a
    ``sAMAccountName`` recycled in the directory with the MessageFoundry row left in place) the
    existing row is adopted and its ``user_id`` is RE-BOUND. That case is NOT covered here and is not
    closeable by this key; it needs the directory-immutable binding tracked as BACKLOG #1143.
    """
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    departed = await service.store.get_user_by_username("op")
    assert departed is not None
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h1 = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("acme.hl7", BATCH, "text/plain")}, headers=h1)
        ).json()["file_id"]

        # The operator leaves; the name is recycled onto a brand-new account.
        await service.delete_user(departed.id, actor="test")
        successor = await _add_user(service, Role.OPERATOR, name="op")
        assert successor != departed.id, "the premise: same username, different account"

        h2 = await _login(c, "op")
        assert (await c.get("/uploads", headers=h2)).json() == {
            "total": 0,
            "files": [],
            "scope": "own",
        }
        assert (await c.get(f"/uploads/{fid}/messages", headers=h2)).status_code == 404
        assert (await c.delete(f"/uploads/{fid}", headers=h2)).status_code == 404

    denied = [a for a in await engine.store.list_audit() if a["action"] == "upload.denied"]
    assert {json.loads(str(a["detail"]))["operation"] for a in denied} == {"browse", "delete"}
    # The audit's actor COLUMN names the username, which here is the same string for both accounts —
    # so on that column alone the successor's denials are indistinguishable from anything the departed
    # operator ever did. This is the scenario that makes the point: the row therefore also carries the
    # acting user_id, and it names the SUCCESSOR, not the account that owns the file.
    assert {a["actor"] for a in denied} == {"op"}
    actor_ids = {json.loads(str(a["detail"]))["actor_user_id"] for a in denied}
    assert actor_ids == {successor}
    assert departed.id not in actor_ids
