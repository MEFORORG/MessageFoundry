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
    custom_role_name_refusal,
    name_refusal,
)
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.permissions import validate_custom_role_permissions
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
    chr(0x200B),  # a zero-width space alone draws nothing
    chr(0x3164) + chr(0x2800),  # a Hangul filler and a Braille blank
    "a" + chr(0x2028) + "b",  # a line separator
    "x" + chr(0x2029),  # a paragraph separator
    chr(0x202E) + "rotartsinimdA",  # a right-to-left override
    "a" + chr(0x2066) + "b",  # an isolate
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


@pytest.mark.parametrize(
    ("stored", "posted"),
    [
        ("\tBad\tName", "Bad\tName"),  # the console strips the edges
        ("a\nb\tc", "ab\tc"),  # a browser drops LF and CR from a text input's value
        ("a\r\nb\x01", "ab\x01"),
        ("jd\x00o\x01e", "jd" + chr(0xFFFD) + "o\x01e"),  # and reads an attribute NUL as U+FFFD
    ],
)
def test_the_stored_name_as_a_console_form_posts_it_is_exempt(stored: str, posted: str) -> None:
    assert name_refusal(posted) is not None  # the exemption is what lets it through
    assert changed_name_refusal(posted, stored) is None
    assert custom_role_name_refusal(posted, stored) is None


def test_the_exemption_cannot_add_a_control_character_to_a_clean_name() -> None:
    """Only the stored-to-posted direction matches, so a clean stored name gains nothing."""
    assert changed_name_refusal("Bob\n", "Bob") is not None
    assert changed_name_refusal(" Bob\t", "Bob") is not None
    assert custom_role_name_refusal("Readers\n", "Readers") is not None


@pytest.mark.parametrize(
    "name",
    [
        "Administrator",
        "administrator",
        "ADMINISTRATOR",
        "  Auditor ",
        "Admin\u200bistrator",  # a zero-width space inside
        "\uff21dministrator",  # a fullwidth A, which NFKC folds
        "viewer",
        "Coding",
        "Administrator" + chr(0xFE0F),  # a variation selector
        "Admini" + chr(0x034F) + "strator",  # a combining grapheme joiner
        "Administrator" + chr(0x3164),  # a Hangul filler
        chr(0x115F) + "Administrator",
        "Administrator" + chr(0x2800),  # a Braille blank
        chr(0x202E) + "rotartsinimdA",  # refused as a bidi override, not by the fold
    ],
)
def test_a_custom_role_may_not_take_a_built_in_role_name(name: str) -> None:
    assert custom_role_name_refusal(name) is not None


def test_a_cross_script_lookalike_is_not_caught() -> None:
    """The documented limit: a letter from another script that only looks alike passes."""
    assert custom_role_name_refusal("\u0410dministrator") is None  # Cyrillic capital A


def test_a_custom_role_save_resending_the_stored_name_is_exempt() -> None:
    assert custom_role_name_refusal("Administrator", "Administrator") is None
    assert custom_role_name_refusal("x\ty", "x\ty") is None
    assert custom_role_name_refusal("Administrator", "Other") is not None
    assert custom_role_name_refusal("Readers", None) is None


def test_a_repeated_permission_is_one_grant() -> None:
    """BACKLOG #5785's duplicate-permission half is not a defect: the service's validator collects
    the list into a set before anything is stored or audited."""
    perms = validate_custom_role_permissions(["monitoring:read", "monitoring:read"])
    assert perms == [Permission.MONITORING_READ]


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


async def test_custom_role_routes_refuse_a_bad_or_built_in_name(engine: Engine) -> None:
    service, _ = await _setup(engine)
    perms = ["monitoring:read"]
    blank, nul, builtin, made = await _calls(
        engine,
        service,
        [
            ("POST", "/roles/custom", {"display_name": " ", "permissions": perms}),
            ("POST", "/roles/custom", {"display_name": "R\x00", "permissions": perms}),
            ("POST", "/roles/custom", {"display_name": "ADMINISTRATOR", "permissions": perms}),
            ("POST", "/roles/custom", {"display_name": "Readers", "permissions": perms}),
        ],
    )
    for refused in (blank, nul, builtin):
        assert refused.status_code == 422, refused.text
        assert "display_name" in refused.json()["detail"]
    assert made.status_code == 201, made.text
    role_url = f"/roles/custom/{made.json()['id']}"
    unknown_url = "/roles/custom/custom:" + "0" * 32
    renamed, kept, unknown = await _calls(
        engine,
        service,
        [
            ("PUT", role_url, {"display_name": "Operator", "permissions": perms}),
            ("PUT", role_url, {"display_name": "Readers", "permissions": perms}),
            ("PUT", unknown_url, {"display_name": "Auditor", "permissions": perms}),
        ],
    )
    assert renamed.status_code == 422, renamed.text
    assert kept.status_code == 200, kept.text
    assert unknown.status_code == 404, unknown.text  # the service's answer, not the name rule's
    assert [r.display_name for r in await service.list_custom_roles()] == ["Readers"]


async def test_a_stored_custom_role_name_the_rule_refuses_does_not_block_a_permission_edit(
    engine: Engine,
) -> None:
    """The PR 3110 regression: a role stored under a name the rule refuses, here a built-in label
    and a control character, can still have its permissions edited under that name, and can be
    renamed to a clean one."""
    service, _ = await _setup(engine)
    perms = ["monitoring:read"]
    stored: list[str] = []
    for name in ("Administrator", "Tab\tRole"):
        role = await service.create_custom_role(
            display_name=name, description=None, permissions=perms, actor="test"
        )
        stored.append(role.id)
    wider = ["monitoring:read", "messages:read"]
    edits = await _calls(
        engine,
        service,
        [
            (
                "PUT",
                f"/roles/custom/{stored[0]}",
                {"display_name": "Administrator", "permissions": wider},
            ),
            (
                "PUT",
                f"/roles/custom/{stored[1]}",
                {"display_name": "Tab\tRole", "permissions": wider},
            ),
            (
                "PUT",
                f"/roles/custom/{stored[1]}",
                {"display_name": "Tab Role", "permissions": wider},
            ),
        ],
    )
    for r in edits:
        assert r.status_code == 200, r.text
    names = {r.id: (r.display_name, r.permissions) for r in await service.list_custom_roles()}
    assert names[stored[0]][0] == "Administrator"
    assert names[stored[1]][0] == "Tab Role"
    assert Permission.MESSAGES_READ in names[stored[0]][1]
