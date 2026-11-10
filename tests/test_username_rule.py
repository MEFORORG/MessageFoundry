# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5521: the username a new local account may take.

``POST /users`` accepted any name up to the length cap: empty, white space alone, control
characters and NUL, and the audit trail's synthetic actor names. The rule now lives in
``messagefoundry/auth/usernames.py``. ``AuthService.create_local_user`` applies it before anything
is generated or written, and ``UserCreateRequest`` mirrors it. Each refusal has a control: a name
next to it that passes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from starlette.requests import Request

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import UserCreateRequest
from messagefoundry.api.validation import PRINTABLE_TEXT_PATTERN
from messagefoundry.auth import Role
from messagefoundry.auth.service import InvalidUsername
from messagefoundry.auth.usernames import username_refusal
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _add, _auth, _login, _reauth, _service

REFUSED = [
    "",
    " ",
    "   ",
    "\t",
    "a\x00b",
    "a\x07b",
    "a\x1bb",
    "a\x7fb",
    "a\x85b",
    "a\x9fb",
    " bob",
    "bob ",
    "bob\n",
    "\xa0bob",
    "system",
    "System",
    "SYSTEM",
    "system:",
    "system:rotate-key",
    "system:cluster-convergence",
    "<oidc>",
    "<kerberos>",
    "<reconciler>",
    "<>",
]

#: The controls: names beside each refused form that the rule must leave alone.
ACCEPTED = [
    "bob",
    "jane.doe",
    "a b",
    "systems",
    "mysystem",
    "system-admin",
    "sys:tem",
    "<bob",
    "bob>",
    "directory",
    "Jos\xe9",
]


@pytest.mark.parametrize("name", REFUSED)
def test_the_rule_refuses(name: str) -> None:
    assert username_refusal(name) is not None


@pytest.mark.parametrize("name", ACCEPTED)
def test_the_rule_accepts(name: str) -> None:
    assert username_refusal(name) is None


def test_the_printable_pattern_is_unchanged_by_the_shared_range() -> None:
    """The API's printable pattern is now built from the shared control range, and still reads as
    the literal it was before, so no field that takes it changed what it accepts."""
    assert PRINTABLE_TEXT_PATTERN == r"^[^\x00-\x1f\x7f-\x9f]+$"


@pytest.mark.parametrize("name", REFUSED)
def test_the_request_model_mirrors_the_rule(name: str) -> None:
    with pytest.raises(ValidationError):
        UserCreateRequest(username=name, email="a@example.org")


@pytest.mark.parametrize("name", ACCEPTED)
def test_the_request_model_accepts_what_the_rule_accepts(name: str) -> None:
    assert UserCreateRequest(username=name, email="a@example.org").username == name


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "usernames.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


@pytest.mark.parametrize("name", ["system", "<oidc>", "a\x00b", "   ", " bob"])
async def test_the_service_refuses_before_anything_is_generated_or_written(
    engine: Engine, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)

    async def no_credential(*args: Any, **kwargs: Any) -> str:
        raise AssertionError("a credential was generated for a refused name")

    monkeypatch.setattr(service, "_generate_issued_credential", no_credential)
    audits_before = len(await engine.store.list_audit(limit=100_000))
    with pytest.raises(InvalidUsername):
        await service.create_local_user(
            username=name, display_name=None, email="a@example.org", roles=[], actor="t"
        )
    assert await engine.store.list_users() == []
    assert len(await engine.store.list_audit(limit=100_000)) == audits_before


async def test_post_users_refuses_a_reserved_name_and_writes_nothing(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        token = (await _login(c, "root")).json()["token"]
        _, token = await _reauth(c, token)
        refused = await c.post(
            "/users", json={"username": "system", "email": "a@example.org"}, headers=_auth(token)
        )
        control = await c.post(
            "/users", json={"username": "sysop", "email": "a@example.org"}, headers=_auth(token)
        )
    assert refused.status_code == 422, refused.text
    assert await engine.store.get_user_by_username("system") is None
    assert control.status_code == 201, control.text


async def test_the_route_answers_the_services_refusal_with_400(engine: Engine) -> None:
    """The request model refuses first on the JSON plane, so the route's own mapping is driven
    past it: a body built without validation reaches the service, which refuses, and the route
    answers 400, not 500."""
    from fastapi import HTTPException
    from fastapi.routing import APIRoute

    service = await _service(engine)
    app = create_app(engine, auth=service)
    endpoint = next(
        r.endpoint
        for r in app.routes
        if isinstance(r, APIRoute) and r.path == "/users" and "POST" in (r.methods or ())
    )
    body = UserCreateRequest.model_construct(
        username="system", display_name=None, email="a@example.org", roles=[]
    )
    request = Request({"type": "http", "client": ("127.0.0.1", 1), "headers": []})
    with pytest.raises(HTTPException) as refused:
        await endpoint(
            body=body, request=request, service=service, identity=SimpleNamespace(username="root")
        )
    assert refused.value.status_code == 400
    assert await engine.store.get_user_by_username("system") is None
