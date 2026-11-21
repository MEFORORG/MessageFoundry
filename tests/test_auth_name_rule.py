# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The account and custom-role name rule (BACKLOG #5784, #5785), ``api.auth_models.name_refusal``.

A blank name, one of white space alone, or one holding a C0 control (NUL included), DEL or a C1
control is refused with a 422 on ``POST /users`` (``display_name``), ``POST /users/directory``
(``username``), ``PATCH /users/{id}`` (``display_name``) and ``POST``/``PUT /roles/custom``
(``display_name``), and a custom role may not take a built-in role's name.

An edit that re-sends the STORED name is exempt. Engine PR 3110 built the rule without that
exemption and took it off again: a client re-sending a stored name another writer put there would
have had an unrelated save refused, and a stored custom-role name the rule refused blocked every
permission edit on that role. The tests below pin the exemption, and that a changed value still
takes the rule, so a repair to a clean name is accepted.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import (
    DirectoryUserCreateRequest,
    UserCreateRequest,
    changed_name_refusal,
    name_refusal,
)
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"

_REFUSED = [
    "",
    " ",
    "\t",
    "  \u3000 ",
    "jd\x00oe",
    "a\tb",
    "line\nbreak",
    "cr\r",
    "trail\n",
    "del\x7f",
    "c1\x85",
]
_ACCEPTED = ["Bob", "Jane Doe", " edge ", "Zo\u00eb", "\u0645\u06cc\u200c\u0631\u0627"]


@pytest.mark.parametrize("name", _REFUSED)
def test_the_rule_refuses(name: str) -> None:
    assert name_refusal(name) is not None
    with pytest.raises(ValidationError):
        DirectoryUserCreateRequest(username=name)
    with pytest.raises(ValidationError):
        UserCreateRequest(username="newuser", display_name=name, email="n@example.org")


@pytest.mark.parametrize("name", _ACCEPTED)
def test_the_rule_accepts(name: str) -> None:
    """Edge white space passes, and so does a zero-width non-joiner inside a Persian name."""
    assert name_refusal(name) is None
    assert DirectoryUserCreateRequest(username=name).username == name
    assert UserCreateRequest(username="newuser", display_name=name, email="n@example.org")


def test_the_refusal_never_echoes_the_value() -> None:
    for name in _REFUSED:
        refusal = name_refusal(name)
        assert refusal is not None and (not name.strip() or name not in refusal)


def test_an_edit_that_resends_the_stored_name_is_exempt() -> None:
    assert changed_name_refusal("a\tb", "a\tb") is None
    assert changed_name_refusal(None, "a\tb") is None  # a clear
    assert changed_name_refusal("a\tc", "a\tb") is not None  # a changed value takes the rule
    assert changed_name_refusal("ab", "a\tb") is None  # the repair


# --- the routes ------------------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "name_rule.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _setup(engine: Engine) -> tuple[AuthService, str]:
    """An administrator ``boss`` who can sign in, and a target account ``target``. Per-action
    step-up binding is off, so one sign-in covers every write here."""
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False, require_action_step_up=False, admin_write_min_interval_seconds=0
        ),
    )
    await service.initialize()
    boss = await create_local_user_chosen(
        service,
        username="boss",
        password=PW,
        display_name=None,
        email="boss@example.org",
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    await service.set_channel_scope(boss, [ALL_CHANNELS], actor="test")
    row = await service.store.get_user(boss)
    assert row is not None and row.password_hash is not None
    await service.store.set_password(
        boss, password_hash=row.password_hash, must_change_password=False, password_generated=False
    )
    target = await create_local_user_chosen(
        service,
        username="target",
        password=PW,
        display_name=None,
        email="owner@example.org",
        roles=[Role.VIEWER.value],
        actor="test",
    )
    return service, target


async def _calls(
    engine: Engine, service: AuthService, calls: list[tuple[str, str, dict[str, Any]]]
) -> list[httpx.Response]:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/auth/login", json={"username": "boss", "password": PW, "provider": "local"}
        )
        assert r.status_code == 200, r.text
        h = {"Authorization": f"Bearer {r.json()['token']}"}
        return [await c.request(m, url, headers=h, json=body) for m, url, body in calls]


async def test_patch_refuses_a_changed_display_name_the_rule_refuses(engine: Engine) -> None:
    service, target = await _setup(engine)
    url = f"/users/{target}"
    blank, nul, ok = await _calls(
        engine,
        service,
        [
            ("PATCH", url, {"display_name": "   "}),
            ("PATCH", url, {"display_name": "a\x00b"}),
            ("PATCH", url, {"display_name": "Renamed"}),
        ],
    )
    assert blank.status_code == 422, blank.text
    assert "display_name" in blank.json()["detail"]
    assert nul.status_code == 422, nul.text
    assert "\x00" not in nul.text
    assert ok.status_code == 200, ok.text
    user = await service.store.get_user(target)
    assert user is not None and user.display_name == "Renamed"


async def test_patch_resending_a_stored_control_name_saves_another_field(engine: Engine) -> None:
    """The PR 3110 regression: a name another writer stored, re-sent unchanged while another field
    is edited, must not turn the save into a 422. A repair to a clean name is accepted."""
    service, target = await _setup(engine)
    await service.store.update_user_profile(
        target, display_name="Bad\tName", email="owner@example.org", audits=()
    )
    url = f"/users/{target}"
    resent, repaired = await _calls(
        engine,
        service,
        [
            ("PATCH", url, {"display_name": "Bad\tName", "disabled": True}),
            ("PATCH", url, {"display_name": "Bad Name"}),
        ],
    )
    assert resent.status_code == 200, resent.text
    user = await service.store.get_user(target)
    assert user is not None and user.disabled
    assert repaired.status_code == 200, repaired.text
    user = await service.store.get_user(target)
    assert user is not None and user.display_name == "Bad Name"


async def test_the_directory_create_refuses_a_blank_name(engine: Engine) -> None:
    service, _ = await _setup(engine)
    [r] = await _calls(engine, service, [("POST", "/users/directory", {"username": "  "})])
    assert r.status_code == 422, r.text
