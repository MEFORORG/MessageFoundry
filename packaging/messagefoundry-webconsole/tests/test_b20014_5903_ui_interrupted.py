# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5903 added step 1: an interrupted outliving operation on a ``/ui`` route is answered as
a console page, not the engine's raw JSON.

The ``/ui`` routes catch at most ``HTTPException``, and ``OperationInterrupted`` is deliberately
not one, so it fell through to the app's JSON 503 handler. That handler now renders the page the
console installs (``app.state.ui_interrupted_render``) for a ``/ui`` path, so no route has to
remember to catch it; a JSON path keeps its JSON. The interruption is forced by replacing the call
that would be cut short with one that raises it, since a real shutdown drain cannot be timed
against a browser request. Synthetic data only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, cookie_login
from test_ui_approvals import _ON, _client, _hold, _status, _two_approvers
from test_uploaded_logs_ui import _app, _login, _service, _upload

from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.api.outlive import OperationInterrupted, OutlivingOperations
from messagefoundry.api.security import public_route
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine

_RELEASE_SENTENCE = "resolve it if it reads interrupted"


def _assert_page(r: httpx.Response, label: str) -> str:
    assert r.status_code == 503, r.text
    assert "text/html" in r.headers.get("content-type", ""), r.headers.get("content-type")
    assert "Outcome unknown" in r.text
    assert f"{label} was interrupted before it answered, and its outcome is unknown." in r.text
    return r.text


def _interrupt_outliving(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run(self: Any, coro: Any, label: str) -> Any:
        coro.close()
        raise OperationInterrupted(label)

    monkeypatch.setattr(OutlivingOperations, "run", _run)


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
    text = _assert_page(r, "released dead-letter replay")
    assert _RELEASE_SENTENCE in text
    # Not the refusal page, whose 503 says nothing ran.
    assert "nothing ran" not in text
    assert await _status(engine, approval_id) == "pending"


async def test_an_interrupted_upload_on_the_ui_is_a_page(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    app: Any = _app(engine, service, tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await _login(c, "op")
        _interrupt_outliving(monkeypatch)
        r = await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", b"MSH|^~\\&|A|B\r", "application/octet-stream")},
            follow_redirects=False,
        )
    # An ungated operation: no approval sentence.
    assert _RELEASE_SENTENCE not in _assert_page(r, "upload.create audit")


async def test_an_interrupted_delete_on_the_ui_is_a_page(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    app: Any = _app(engine, service, tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        _interrupt_outliving(monkeypatch)
        r = await c.post(f"/ui/uploaded-logs/file/{fid}/delete", follow_redirects=False)
    assert _RELEASE_SENTENCE not in _assert_page(r, "upload delete")


async def test_a_json_path_on_the_same_app_keeps_its_json(engine: Engine, tmp_path: Path) -> None:
    """The control: with the console mounted, a path outside /ui still gets the JSON answer."""
    service = await _service(engine)
    app: Any = _app(engine, service, tmp_path)
    assert app.state.ui_interrupted_render is not None

    @app.get("/healthz-5903-console-probe")  # type: ignore[untyped-decorator]
    @public_route("a test probe for BACKLOG #5903")
    async def _probe() -> None:
        raise OperationInterrupted("DR release")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/healthz-5903-console-probe")
    assert r.status_code == 503, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["detail"].startswith("DR release was interrupted before it answered")


async def test_an_interrupted_target_in_a_bulk_control_reads_outcome_unknown(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: a bulk route's capture-and-continue arm caught the interruption as a plain
    "error". It now names the outcome as unknown, and the batch still answers."""
    from test_ui_bulk_control_client import _ALLOWED, _post_pairs, _row_key, _scoped_operator
    from test_ui_bulk_control_client import _client as _bulk_client
    from test_ui_bulk_control_client import _login as _bulk_login
    from test_ui_bulk_control_client import _service as _bulk_service

    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    async def _cut(self: Any, name: str) -> None:
        raise OperationInterrupted("connection stop")

    reg = Registry()
    reg.add_inbound(
        InboundConnection(_ALLOWED, ConnectionSpec(ConnectorType.MLLP, {"port": 2579}), router="r")
    )
    reg.add_router("r", lambda m: [])
    engine.add_registry(reg)
    service = await _bulk_service(engine)
    await _scoped_operator(service)
    monkeypatch.setattr(RegistryRunner, "stop_inbound", _cut)
    async with _bulk_client(engine, service) as c:
        await _bulk_login(c)
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _row_key("source", _ALLOWED))],
        )
    assert r.status_code == 200, r.text
    assert "outcome unknown: connection stop was interrupted before it answered" in r.text
    assert ">error<" not in r.text
