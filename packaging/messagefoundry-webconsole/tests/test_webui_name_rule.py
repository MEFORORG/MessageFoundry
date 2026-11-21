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

import logging
import sqlite3
from pathlib import Path

import httpx
import pytest
from _webui_support import (
    PW,
    _add,
    _boss_client,
    _cookie_login,
    _mint_action,
    _post_pairs,
    _service,
    _uid,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import RowSealer, TransitRowSealer
from messagefoundry.store.store import MessageStore
from tests._transit_seal_fake import FakeBackend, with_version

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


# --- every store state, both routes ----------------------------------------------------------------

#: The store states a custom role save is answered in. ``outage`` is Vault transit down for every
#: call. ``outage_role_only`` is the role row's own seal check failing over to an Outage (its seal
#: names a version Transit refuses, and the key probe fails) while every other call answers: the
#: state where a check of that seal would meet an Outage the save itself never meets.
_STATES = ["keyless", "sealed", "transit", "outage", "outage_role_only"]


async def _save_role_in(
    tmp_path: Path, state: str, route: str, stored: str, posted: str
) -> tuple[httpx.Response, list[str]]:
    """Save a custom role stored as ``stored`` with the name ``posted`` and a wider permission set,
    over ``route``, in ``state``: the answer, and each record logged at WARNING or above while the
    request ran."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "state.db"
    backend = FakeBackend()
    if state == "keyless":
        store = await MessageStore.open(path)
    else:
        store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
        store._row_sealer = RowSealer(bytes(32)) if state == "sealed" else TransitRowSealer(backend)
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        service = await _service(engine)
        await _add(service, "boss", Role.ADMINISTRATOR)
        role = await service.create_custom_role(
            display_name=stored, description=None, permissions=["messages:read"], actor="t"
        )
        app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            headers: dict[str, str] = {}
            if route == "json":
                login = await c.post(
                    "/auth/login", json={"username": "boss", "password": PW, "provider": "local"}
                )
                headers = {"Authorization": f"Bearer {login.json()['token']}"}
            else:
                await _cookie_login(c, "boss")
            if state == "outage":
                backend.down = True
            elif state == "outage_role_only":
                conn = sqlite3.connect(path)
                try:
                    (seal,) = conn.execute(
                        "SELECT seal FROM roles WHERE id=?", (role.id,)
                    ).fetchone()
                    conn.execute(
                        "UPDATE roles SET seal=? WHERE id=?",
                        (with_version(str(seal), "5"), role.id),
                    )
                    conn.commit()
                finally:
                    conn.close()
                backend.probe_down = True
            perms = ["messages:read", "monitoring:read"]
            records: list[logging.LogRecord] = []
            handler = logging.Handler(logging.WARNING)
            handler.emit = records.append  # type: ignore[method-assign]
            root = logging.getLogger()
            root.addHandler(handler)
            try:
                if route == "json":
                    resp = await c.put(
                        f"/roles/custom/{role.id}",
                        json={"display_name": posted, "permissions": perms},
                        headers=headers,
                    )
                else:
                    resp = await _post_pairs(
                        c,
                        f"/ui/roles/custom/{role.id}/update",
                        [("display_name", posted)] + [("permissions", p) for p in perms],
                    )
            finally:
                root.removeHandler(handler)
                backend.down = backend.probe_down = False
        logged = [f"{r.name}:{r.getMessage()}".replace(role.id, "<id>") for r in records]
        return resp, logged
    finally:
        await engine.stop()


@pytest.mark.parametrize("route", ["json", "console"])
@pytest.mark.parametrize("state", _STATES)
async def test_a_re_sent_stored_name_the_rule_refuses_is_answered_as_a_clean_one(
    tmp_path: Path, state: str, route: str
) -> None:
    """The bar for BACKLOG #5785's exemption: in every store state, a save re-sending a stored
    name the rule refuses gets the answer, and logs the lines, that a save re-sending a clean
    stored name gets, which is what the save answered before the rule. A Vault transit Outage is
    met by the save itself, as it was: the rule adds no seal check of its own to meet it first."""
    refused, refused_logs = await _save_role_in(
        tmp_path / "refused", state, route, "Administrator", "Administrator"
    )
    clean, clean_logs = await _save_role_in(tmp_path / "clean", state, route, "Readers", "Readers")
    assert refused.status_code == clean.status_code, (refused.text, clean.text)
    assert refused.headers.get("retry-after") == clean.headers.get("retry-after")
    assert refused_logs == clean_logs
    if state == "outage_role_only":
        # Control: the save never checks the role row's seal, so this state is invisible to it.
        assert clean.status_code in (200, 303)
        assert not [line for line in clean_logs if "row_seal" in line]


@pytest.mark.parametrize("route", ["json", "console"])
@pytest.mark.parametrize("state", ["keyless", "sealed", "transit", "outage_role_only"])
async def test_a_new_name_the_rule_refuses_is_refused_in_every_answering_state(
    tmp_path: Path, state: str, route: str
) -> None:
    resp, logs = await _save_role_in(tmp_path, state, route, "Readers", "Auditor")
    assert resp.status_code == (422 if route == "json" else 400), resp.text
    assert not [line for line in logs if "row_seal" in line]
