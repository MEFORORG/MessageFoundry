# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The browser sign-in's bounds (BACKLOG #5397 added items 1 and 2).

``_form_fits`` counts only a refusal of a field its caller passed, so a model that later gains a
required field or a whole-model validator does not refuse every console sign-in. The session cookie
a sign-in replaces reaches ``auth.login`` only within the bound the JSON route's model puts on
``supersedes``. Synthetic data only."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest
from _ui_clients import PW, provision, ui_client
from fastapi import Request
from pydantic import Field, model_validator

from messagefoundry.api.auth_models import _NAME_MAX, _TOKEN_MAX, LoginRequest
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._auth import COOKIE_NAME
from messagefoundry_webconsole.routes.core import _form_fits


def _request() -> Request:
    # _form_fits reads only the method and the path, and only to log a refusal.
    return cast(Request, SimpleNamespace(method="POST", url=SimpleNamespace(path="/ui/login")))


class _NeedsMore(LoginRequest):
    """A model with a required field the sign-in form does not carry."""

    passkey_assertion: str = Field(max_length=64)


class _ValidatesTheWhole(LoginRequest):
    """A model with a validator over the whole model, which fails whatever the form passes."""

    @model_validator(mode="after")
    def _never(self) -> _ValidatesTheWhole:
        raise ValueError("a whole-model refusal")


@pytest.mark.parametrize("model", [_NeedsMore, _ValidatesTheWhole], ids=["required", "validator"])
def test_a_refusal_of_a_field_not_passed_does_not_count(model: type[LoginRequest]) -> None:
    # On origin/main every error outside length_only counted, so either model refused every
    # console sign-in.
    assert _form_fits(_request(), model, username="op", password=PW)


@pytest.mark.parametrize("model", [_NeedsMore, _ValidatesTheWhole], ids=["required", "validator"])
def test_a_refusal_of_a_passed_field_still_counts(model: type[LoginRequest]) -> None:
    # Control: the same models still refuse an oversized value of a field the form passed.
    assert not _form_fits(_request(), model, username="a" * (_NAME_MAX + 1), password=PW)


def test_length_only_still_ignores_other_refusals_of_its_field() -> None:
    # Control: LoginRequest's digit pattern on totp_code does not refuse, its length does.
    only = frozenset({"totp_code"})
    fields = {"username": "op", "password": PW}
    assert _form_fits(_request(), LoginRequest, length_only=only, totp_code="ab", **fields)
    assert not _form_fits(_request(), LoginRequest, length_only=only, totp_code="1" * 64, **fields)


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(login_rate_limit_enabled=False, admin_write_min_interval_seconds=0),
    )
    await service.initialize()
    await provision(service, "op", [Role.OPERATOR.value])
    return service


def _spy_login(monkeypatch: pytest.MonkeyPatch, service: AuthService) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real: Callable[..., Awaitable[Any]] = service.login

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return await real(*args, **kwargs)

    monkeypatch.setattr(service, "login", spy)
    return calls


async def test_an_oversized_session_cookie_is_not_passed_on_as_superseded(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On origin/main the cookie reached auth.login whatever its length, so the engine hashed an
    # unbounded value that can name no session. It is dropped, and the sign-in still succeeds.
    service = await _service(engine)
    calls = _spy_login(monkeypatch, service)
    async with ui_client(engine, service) as c:
        c.cookies.set(COOKIE_NAME, "a" * (_TOKEN_MAX + 1))
        r = await c.post("/ui/login", data={"username": "op", "password": PW})
    assert r.status_code == 303 and r.headers["location"] != "/ui/login?e=bad"
    assert [call["supersedes"] for call in calls] == [None]


async def test_a_session_cookie_within_the_bound_is_passed_on(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control: at the bound the cookie is still the session the sign-in replaces.
    service = await _service(engine)
    calls = _spy_login(monkeypatch, service)
    async with ui_client(engine, service) as c:
        c.cookies.set(COOKIE_NAME, "a" * _TOKEN_MAX)
        await c.post("/ui/login", data={"username": "op", "password": PW})
    assert [call["supersedes"] for call in calls] == ["a" * _TOKEN_MAX]
