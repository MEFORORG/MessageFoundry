# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""/ui uploaded-logs page smoke tests (BACKLOG #125/#126, ADR 0134).

The console reaches the engine through the seam-v7 CoreHandlers; these drive the cookie flow end to
end (upload → list → browse → delete) and the RBAC/off-by-default gates."""

from __future__ import annotations

from pathlib import Path

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.pipeline import Engine

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN123^^^H^MR||DOE^JANE\r"
ADT2 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A04|MSG2|P|2.5.1\rPID|1||MRN999\r"
BATCH = ADT + ADT2


async def _service(engine: Engine, *users: tuple[str, Role]) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    for name, role in users:
        uid = await service.create_local_user(
            username=name, password=PW, display_name=None, email=None, roles=[role.value], actor="t"
        )
        user = await service.store.get_user(uid)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            uid, password_hash=user.password_hash, must_change_password=False
        )
    return service


def _app(engine: Engine, service: AuthService, tmp_path: Path, *, uploads: bool = True) -> object:
    store_settings = (
        StoreSettings(uploads_dir=str(tmp_path / "uploads"), max_upload_bytes=1_000_000)
        if uploads
        else None
    )
    return create_app(engine, auth=service, serve_ui=True, store_settings=store_settings)


async def _login(c: httpx.AsyncClient, name: str) -> None:
    r = await c.post("/ui/login", data={"username": name, "password": PW})
    assert r.status_code in (200, 303), r.text


async def test_uploaded_logs_ui_flow(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        # empty list renders
        r = await c.get("/ui/uploaded-logs")
        assert r.status_code == 200 and "Uploaded logs" in r.text

        # upload form + upload
        assert (await c.get("/ui/uploaded-logs/upload")).status_code == 200
        up = await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        assert up.status_code in (200, 303), up.text

        # the file now shows in the list
        r = await c.get("/ui/uploaded-logs")
        assert "acme.hl7" in r.text
        # find the file_id from the browse link
        marker = "/ui/uploaded-logs/file/"
        fid = r.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        assert len(fid) == 32

        # browse renders metadata only (no decrypted body)
        b = await c.get(f"/ui/uploaded-logs/file/{fid}")
        assert b.status_code == 200, b.text
        assert "ADT^A01" in b.text and "ADT^A04" in b.text
        assert "PID|" not in b.text and "MRN123" not in b.text

        # delete confirm → delete
        cf = await c.get(f"/ui/uploaded-logs/file/{fid}/delete-confirm")
        assert cf.status_code == 200 and "Delete uploaded file" in cf.text
        d = await c.post(f"/ui/uploaded-logs/file/{fid}/delete")
        assert d.status_code in (200, 303)
        assert "acme.hl7" not in (await c.get("/ui/uploaded-logs")).text


def test_upload_form_states_consent_affordance() -> None:
    # ASVS 14.2.8: the upload form states, above the submit button, what non-body metadata is retained and
    # who sees it — submitting the form IS the consent (no separate stored flag). Pure page-render check.
    from messagefoundry_webconsole import pages

    html = str(pages.uploaded_logs_upload())
    assert "original filename" in html and "your username" in html
    assert "authorized operators" in html and "audit log" in html
    assert "Submitting this form is your consent" in html
    # The consent notice sits inside the form, ABOVE the submit button.
    assert html.index("your consent") < html.index("Upload</button>")


async def test_uploaded_logs_ui_denied_for_viewer(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine, ("vw", Role.VIEWER))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "vw")
        assert (await c.get("/ui/uploaded-logs")).status_code == 403


async def test_uploaded_logs_ui_503_when_unconfigured(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path, uploads=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        assert (await c.get("/ui/uploaded-logs")).status_code == 503
