# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's half of the upload refusal follow-ups (BACKLOG #5388 added items 1 and 2, #5397
added item 2).

A 423 is told apart by the typed ``upload_refusal`` signal the engine's refusal carries, never by
its text. A file the filesystem refuses the engine lands on its own notice, which does not invite
a delete. The damaged delete notice promises no removal it cannot keep. The SSO and federated
sign-in legs pass the session cookie on as the one they replace only within the bound /ui/login
uses. Synthetic data only."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from _ui_clients import SAME_ORIGIN
from fastapi import HTTPException
from test_ui_directory_admin_alert import _client, _Sink
from test_ui_directory_admin_alert import _service as _directory_service
from test_uploaded_logs_ui import _app, _landed_notice, _login, _service, _upload

import messagefoundry.uploads as uploads
from messagefoundry.api.auth_models import _TOKEN_MAX
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._auth import COOKIE_NAME
from messagefoundry_webconsole.routes import uploaded_logs as ul

_NEGOTIATE = "Negotiate c3BuZWdvLXRva2Vu"


class _OsWith:
    """``os`` as ``messagefoundry.uploads`` sees it, with ``open`` replaced."""

    def __init__(self, open_: Any) -> None:
        self._open = open_

    def __getattr__(self, name: str) -> Any:
        return self._open if name == "open" else getattr(os, name)


# --- the typed signal ----------------------------------------------------------------------------


def _locked(kind: str | None, detail: str = "synthetic") -> HTTPException:
    exc = HTTPException(423, detail)
    if kind is not None:
        exc.upload_refusal = kind  # type: ignore[attr-defined]
    return exc


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (None, ul.DELETE_LOCKED_CODE),
        ("locked", ul.DELETE_LOCKED_CODE),
        ("damaged", ul.DELETE_DAMAGED_CODE),
        ("denied", ul.DELETE_ACCESS_CODE),
        ("unheard-of", ul.DELETE_LOCKED_CODE),
    ],
)
def test_the_refusal_kind_picks_the_code(kind: str | None, code: str) -> None:
    assert ul._refusal_code(_locked(kind), ul._DELETE_CODES) == code


def test_the_detail_text_alone_no_longer_picks_the_damaged_code() -> None:
    # Review finding 3: the split compared the detail with a copy of the engine's text. The text of
    # a damaged 423, with no kind on it, now keeps the locked code.
    text = (
        "this uploaded file is damaged, so it was not read and is not served. No key and no "
        "command repairs it. An operator may try to delete it, and the delete may be refused too"
    )
    assert ul._refusal_code(_locked(None, text), ul._BROWSE_CODES) == ul.BROWSE_LOCKED_CODE


def test_no_damaged_or_access_notice_names_a_key_and_no_access_notice_invites_a_delete() -> None:
    for notice in (ul.BROWSE_ACCESS_NOTICE, ul.RESEND_ACCESS_NOTICE, ul.DELETE_ACCESS_NOTICE):
        assert "rotate-key" not in notice and "encryption key" not in notice
        assert "not known to be damaged" in notice
        assert "may be deleted" not in notice
    # Review finding 2: the delete notice promised retention removes every damaged file.
    assert "not every one" in ul.DELETE_DAMAGED_NOTICE
    assert "removes it once it is old enough" not in ul.DELETE_DAMAGED_NOTICE


# --- an access refusal lands on its own notice ---------------------------------------------------


async def test_a_file_the_engine_may_not_open_lands_on_the_access_notice(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review finding 3: a PermissionError was answered as damage, whose notice says the file may
    # be deleted. On a sharing violation that would invite deleting a sound upload.
    service = await _service(engine, ("op", Role.OPERATOR), ("root", Role.ADMINISTRATOR))
    app: Any = _app(engine, service, tmp_path)
    transport = httpx.ASGITransport(app=app)
    root = tmp_path / "uploads"
    denied: set[Path] = set()

    def _deny(path: Any, flags: int, *args: Any) -> int:
        if Path(path) in denied:
            raise PermissionError(13, "Permission denied", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_deny))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        body_fid = await _upload(c, "body.hl7")
        meta_fid = await _upload(c, "meta.hl7")
        denied.update({root / f"{body_fid}.blob", root / f"{meta_fid}.meta"})
        browse = await c.get(f"/ui/uploaded-logs/file/{body_fid}", follow_redirects=False)
        page = await _landed_notice(
            c, browse, ul.BROWSE_ACCESS_CODE, "That file could not be opened"
        )
        assert "not known to be damaged" in page and "found the file damaged" not in page
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as a:
        await _login(a, "root")
        delete = await a.post(f"/ui/uploaded-logs/file/{meta_fid}/delete", follow_redirects=False)
        page = await _landed_notice(a, delete, ul.DELETE_ACCESS_CODE, "That delete did not run")
        assert "not known to be damaged" in page
    assert (root / f"{meta_fid}.meta").exists() and (root / f"{meta_fid}.blob").exists()


# --- the SSO and federated legs bound the superseded cookie --------------------------------------


@pytest.mark.parametrize(("length", "passed"), [(_TOKEN_MAX + 1, False), (_TOKEN_MAX, True)])
async def test_sso_passes_on_the_cookie_only_within_the_bound(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, length: int, passed: bool
) -> None:
    # Review finding 5: /ui/sso passed the cookie on as supersedes whatever its length.
    service = await _directory_service(engine, held=None, bind=False)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    seen: list[Any] = []
    real = service.authenticate_kerberos

    async def _spy(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("supersedes"))
        return await real(*args, **kwargs)

    monkeypatch.setattr(service, "authenticate_kerberos", _spy)
    cookie = "a" * length
    async with _client(engine, service, _Sink()) as c:
        c.cookies.set(COOKIE_NAME, cookie)
        r = await c.get("/ui/sso", headers={"Authorization": _NEGOTIATE})
    assert r.status_code == 303, r.text
    assert seen == [cookie if passed else None]


@pytest.mark.parametrize(("length", "passed"), [(_TOKEN_MAX + 1, False), (_TOKEN_MAX, True)])
async def test_the_federated_start_passes_on_the_cookie_only_within_the_bound(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, length: int, passed: bool
) -> None:
    # Review finding 5: /ui/oidc/start passed the cookie on as prior_session whatever its length.
    service = await _directory_service(engine, held=None, bind=True)
    seen: list[Any] = []
    real = service.begin_oidc_login

    async def _spy(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("prior_session"))
        return await real(*args, **kwargs)

    monkeypatch.setattr(service, "begin_oidc_login", _spy)
    cookie = "a" * length
    async with _client(engine, service, _Sink()) as c:
        c.cookies.set(COOKIE_NAME, cookie)
        r = await c.post("/ui/oidc/start", headers=SAME_ORIGIN, follow_redirects=False)
    # The start hands the browser to the IdP through its interstitial.
    assert r.status_code == 200 and "https://idp.example/authorize" in r.text, r.text
    assert seen == [cookie if passed else None]
