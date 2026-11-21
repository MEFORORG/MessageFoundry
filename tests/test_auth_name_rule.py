# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The account and custom-role name rule (BACKLOG #5784, #5785), ``api.auth_models.name_refusal``.

A name ``name_refusal`` refuses, which states the rule, is refused with a 422 on ``POST /users``
(``display_name``), ``POST /users/directory`` (``username``), ``PATCH /users/{id}``
(``display_name``) and ``POST``/``PUT /roles/custom`` (``display_name``), and a custom role may
not take a built-in role's name (``custom_role_name_refusal``).

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
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import RowSealer
from messagefoundry.store.store import MessageStore
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
    "Bob" + chr(0x200F),  # a right-to-left mark
]
_ACCEPTED = ["Bob", "Jane Doe", " edge ", "Zo\u00eb", "\u0645\u06cc\u200c\u0631\u0627"]


@pytest.mark.parametrize("name", _REFUSED)
def test_the_rule_refuses(name: str) -> None:
    assert name_refusal(name) is not None
    with pytest.raises(ValidationError) as refused:
        DirectoryUserCreateRequest(username=name)
    if name == "":
        expected = "string_too_short"
    elif "\x00" in name:
        expected = "string_pattern_mismatch"
    else:
        expected = "value_error"
    assert [e["type"] for e in refused.value.errors()] == [expected]
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


def test_a_visible_format_character_is_not_blank() -> None:
    """A prepended concatenation mark is a format character that draws a glyph."""
    assert name_refusal(chr(0x06DD)) is None
    assert custom_role_name_refusal("Administrator" + chr(0x06DD)) is None


def test_a_console_variant_of_a_stored_name_cannot_become_a_built_in_name() -> None:
    """A role stored as ``Admin`` + LF + ``istrator`` folds to no built-in name; the variant a
    console posts for it does, so it is not exempt from the built-in check."""
    assert custom_role_name_refusal("Administrator", "Admin\nistrator") is not None
    assert custom_role_name_refusal("Administrator", "Administrator ") is None  # same fold


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
    assert "a\x00b" not in nul.json()["detail"]
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


async def test_the_stored_name_read(engine: Engine) -> None:
    """The name a custom role row stores, and ``None`` for an id no custom role row holds: an
    unknown id, and a built-in role's, so the route leaves both to the service's answer."""
    service, _ = await _setup(engine)
    role = await service.create_custom_role(
        display_name="Administrator", description=None, permissions=["monitoring:read"], actor="t"
    )
    assert await service.custom_role_stored_name(role.id) == "Administrator"
    assert await service.custom_role_stored_name("custom:" + "0" * 32) is None
    assert await service.custom_role_stored_name(Role.ADMINISTRATOR.value) is None


async def test_a_save_under_a_name_the_rule_takes_reads_no_stored_name(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A name the rule takes on its own needs no stored name, so the save reads nothing more than
    it did before the rule; only a refused name is compared with the stored one."""
    service, _ = await _setup(engine)
    perms = ["monitoring:read"]
    role = await service.create_custom_role(
        display_name="Readers", description=None, permissions=perms, actor="t"
    )
    reads: list[str] = []
    original = service.custom_role_stored_name

    async def _counted(role_id: str) -> str | None:
        reads.append(role_id)
        return await original(role_id)

    monkeypatch.setattr(service, "custom_role_stored_name", _counted)
    # The baseline: what the save itself reads, the route's gate read and the service's write.
    ended = await service.sessions_ended_by_custom_role_save(role.id)
    await service.update_custom_role(
        role.id,
        display_name="Readers",
        description=None,
        permissions=perms,
        actor="t",
        ended=ended,
    )
    baseline = len(reads)
    assert baseline >= 1  # control: the counter sees the service's own existence check
    reads.clear()
    url = f"/roles/custom/{role.id}"
    [clean] = await _calls(
        engine, service, [("PUT", url, {"display_name": "Readers", "permissions": perms})]
    )
    assert clean.status_code == 200, clean.text
    assert len(reads) == baseline
    reads.clear()
    [refused] = await _calls(
        engine, service, [("PUT", url, {"display_name": "Auditor", "permissions": perms})]
    )
    assert refused.status_code == 422, refused.text
    assert reads == [role.id]  # the name check's one read; the 422 comes before the write


async def test_a_name_whose_row_fails_its_seal_is_exempt_and_the_save_repairs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a store with an integrity key, a name written outside the store fails the row's seal.
    The save never checked that seal before the rule, and does not now: re-sending the name is
    exempt, the save re-seals the row, and nothing reports a seal failure on the way."""
    store = await MessageStore.open(
        tmp_path / "keyed.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    store._row_sealer = RowSealer(bytes(32))
    keyed = Engine(store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False))
    try:
        service, _ = await _setup(keyed)
        perms = ["monitoring:read"]
        role = await service.create_custom_role(
            display_name="Readers", description=None, permissions=perms, actor="t"
        )
        await store._db.execute(
            "UPDATE roles SET display_name=? WHERE id=?", ("Administrator", role.id)
        )
        await store._db.commit()
        assert await service._load_role(role.id) is None  # control: the row fails its seal
        reports: list[str] = []
        original = service._report_seal_failure

        async def _record(subject: str, *args: Any, **kwargs: Any) -> Any:
            reports.append(subject)
            return await original(subject, *args, **kwargs)

        monkeypatch.setattr(service, "_report_seal_failure", _record)
        [saved] = await _calls(
            keyed,
            service,
            [
                (
                    "PUT",
                    f"/roles/custom/{role.id}",
                    {"display_name": "Administrator", "permissions": perms},
                )
            ],
        )
        assert saved.status_code == 200, saved.text
        assert reports == []
        repaired = await service._load_role(role.id)
        assert repaired is not None and repaired.display_name == "Administrator"
    finally:
        await keyed.stop()


async def test_on_a_keyless_store_a_name_written_outside_the_store_is_exempt(
    engine: Engine,
) -> None:
    """The keyless case: a name written straight into the ``roles`` table is the stored name, and
    a save re-sending it is exempt."""
    service, _ = await _setup(engine)
    assert engine.store.row_sealer() is None  # control: this store has no integrity key
    role = await service.create_custom_role(
        display_name="Readers", description=None, permissions=["monitoring:read"], actor="t"
    )
    store = engine.store
    assert isinstance(store, MessageStore)
    await store._db.execute(
        "UPDATE roles SET display_name=? WHERE id=?", ("Administrator", role.id)
    )
    await store._db.commit()
    stored = await service.custom_role_stored_name(role.id)
    assert stored == "Administrator"
    assert custom_role_name_refusal("Administrator", stored) is None


def test_the_literal_pattern_agrees_with_the_shared_one() -> None:
    """``auth_models._PRINTABLE_NAME`` spells ``validation.PRINTABLE_TEXT_PATTERN`` as a literal so
    the ReDoS scan can read it; the two must be the same pattern."""
    from messagefoundry.api import auth_models
    from messagefoundry.api.validation import PRINTABLE_TEXT_PATTERN

    assert auth_models._PRINTABLE_NAME.pattern == PRINTABLE_TEXT_PATTERN


def test_the_directory_username_schema_is_the_one_origin_main_published() -> None:
    """The field's published schema, as ``DirectoryUserCreateRequest`` declares it."""
    schema = DirectoryUserCreateRequest.model_json_schema()["properties"]["username"]
    assert schema == {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\x00]*$",
        "title": "Username",
        "type": "string",
    }
    with pytest.raises(ValidationError):
        DirectoryUserCreateRequest(username="a\tb")  # control: the runtime rule still refuses
