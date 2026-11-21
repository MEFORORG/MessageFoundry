# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's user save under the account name rule (BACKLOG #5784).

The form posts the display name back on every save. A stored name the rule refuses, re-posted
unchanged, must not turn an unrelated save into an error, and an edit that removes the bad
character must land: engine PR 3110's build of the rule failed both, so it was taken off.
"""

from __future__ import annotations

import httpx
from _webui_support import _add, _boss_client, _mint_action, _service, _uid

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine


async def _save(c: httpx.AsyncClient, uid: str, form: dict[str, str]) -> httpx.Response:
    await _mint_action(c, f"/ui/users/{uid}")  # BACKLOG #1737: action-bound, single-use
    return await c.post(
        f"/ui/users/{uid}/update", data=form, headers={"Sec-Fetch-Site": "same-origin"}
    )


async def test_the_console_saves_over_a_stored_display_name_the_rule_refuses(
    engine: Engine,
) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        await service.store.update_user_profile(
            uid, display_name="Bad\tName", email=None, audits=()
        )
        r = await _save(c, uid, {"display_name": "Bad\tName", "email": "", "disabled": "on"})
        assert r.status_code == 303, r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.disabled and user.display_name == "Bad\tName"
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
