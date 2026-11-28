# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5903 added step 1: an interrupted outliving operation on the ``/ui`` approve, upload
and upload-delete routes is answered as a console page, not the engine's raw JSON.

Those routes caught only ``HTTPException``, and ``OperationInterrupted`` is deliberately not one,
so it fell through to the app's JSON 503 handler. The interruption is forced here by replacing the
call that would be cut short with one that raises it, since a real shutdown drain cannot be timed
against a browser request. Synthetic data only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, cookie_login
from test_ui_approvals import _ON, _client, _hold, _status, _two_approvers
from test_uploaded_logs_ui import _app, _landed_notice, _login, _service, _upload

from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.api.outlive import OperationInterrupted, OutlivingOperations
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.routes import uploaded_logs as ul


def _not_json(r: httpx.Response) -> None:
    assert "text/html" in r.headers.get("content-type", ""), r.headers.get("content-type")


async def test_an_interrupted_release_on_the_ui_approve_is_a_page(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _interrupted(self: Any, *_a: Any, **_k: Any) -> Any:
        exc = OperationInterrupted("released dead-letter replay")
        exc.released = True
        raise exc

    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker, _client(engine, service, _ON) as checker:
        await cookie_login(maker, "maker")
        await cookie_login(checker, "checker")
        approval_id = await _hold(maker)
        monkeypatch.setattr(ApprovalGate, "approve", _interrupted)
        r = await checker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
    assert r.status_code == 503, r.text
    _not_json(r)
    assert "Outcome unknown" in r.text
    assert "released dead-letter replay was interrupted before it answered" in r.text
    assert "resolve that approval rather than approving it again" in r.text
    # Not the refusal page, whose 503 says nothing ran.
    assert "nothing ran" not in r.text
    assert await _status(engine, approval_id) == "pending"


def _interrupt_outliving(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run(self: Any, coro: Any, label: str) -> Any:
        coro.close()
        raise OperationInterrupted(label)

    monkeypatch.setattr(OutlivingOperations, "run", _run)


async def test_an_interrupted_upload_on_the_ui_is_the_upload_page(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    app: Any = _app(engine, service, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        _interrupt_outliving(monkeypatch)
        r = await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", b"MSH|^~\\&|A|B\r", "application/octet-stream")},
            follow_redirects=False,
        )
    assert r.status_code == 503, r.text
    _not_json(r)
    assert "was interrupted before it answered, and its outcome is unknown." in r.text
    assert "approval" not in r.text.split("<main", 1)[-1]


async def test_an_interrupted_delete_on_the_ui_lands_on_its_own_notice(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    app: Any = _app(engine, service, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        _interrupt_outliving(monkeypatch)
        r = await c.post(f"/ui/uploaded-logs/file/{fid}/delete", follow_redirects=False)
        page = await _landed_notice(
            c, r, ul.DELETE_INTERRUPTED_CODE, "That delete was interrupted before it answered"
        )
    assert "may or may not be gone" in page
