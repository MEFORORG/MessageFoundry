# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's user and custom-role saves under the name rule (BACKLOG #5784, #5785).

Each form posts the name back on every save. A stored name the rule refuses, re-posted as a
browser posts it, must not turn an unrelated save into an error, and an edit that removes the bad
character must land. Engine PR 3110's build of the rule was taken off for a stored-value repair
that regressed: its console user save of such a repair could silently change nothing, and a stored
custom-role name the rule refused blocked every permission edit on that role.
"""

from __future__ import annotations

import httpx
import pytest
from _webui_support import _add, _boss_client, _mint_action, _post_pairs, _service, _uid

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine

#: A stored name, and what a browser posts back for it: a text input's value loses CR and LF. The
#: console's route then strips the edges.
_STORED_AND_POSTED = [
    ("Bad\tName", "Bad\tName"),
    ("\tBad\tName", "\tBad\tName"),
    ("a\nb\tc ", "ab\tc "),
]


async def _save(c: httpx.AsyncClient, uid: str, form: dict[str, str]) -> httpx.Response:
    await _mint_action(c, f"/ui/users/{uid}")  # BACKLOG #1737: action-bound, single-use
    return await c.post(
        f"/ui/users/{uid}/update", data=form, headers={"Sec-Fetch-Site": "same-origin"}
    )


@pytest.mark.parametrize(("stored", "posted"), _STORED_AND_POSTED)
async def test_the_console_saves_over_a_stored_display_name_the_rule_refuses(
    engine: Engine, stored: str, posted: str
) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        await service.store.update_user_profile(uid, display_name=stored, email=None, audits=())
        r = await _save(c, uid, {"display_name": posted, "email": "", "disabled": "on"})
        assert r.status_code == 303, r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.disabled
        # The repair lands.
        r = await _save(c, uid, {"display_name": "Bad Name", "email": ""})
        assert r.status_code == 303, r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.display_name == "Bad Name"


async def test_the_console_refuses_a_new_display_name_the_rule_refuses(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await _save(c, uid, {"display_name": "a\tb", "email": ""})
        assert r.status_code == 400
        assert "display_name" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.display_name is None


@pytest.mark.parametrize("stored", ["Administrator", "Administrator ", "Tab\tRole"])
async def test_the_console_edits_a_role_stored_under_a_name_the_rule_refuses(
    engine: Engine, stored: str
) -> None:
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name=stored, description=None, permissions=["messages:read"], actor="t"
    )
    async with _boss_client(engine, service) as c:
        url = f"/ui/roles/custom/{role.id}/update"
        pairs = [
            ("display_name", stored),
            ("permissions", "messages:read"),
            ("permissions", "monitoring:read"),
        ]
        r = await _post_pairs(c, url, pairs)
        assert r.status_code == 303, r.text
        [saved] = await service.list_custom_roles()
        assert saved.display_name == stored.strip()
        assert {p.value for p in saved.permissions} == {"messages:read", "monitoring:read"}
        # A new built-in name is still refused, and nothing is written.
        r = await _post_pairs(
            c, url, [("display_name", "Auditor"), ("permissions", "messages:read")]
        )
        assert r.status_code == 400
        [saved] = await service.list_custom_roles()
        assert saved.display_name == stored.strip()
