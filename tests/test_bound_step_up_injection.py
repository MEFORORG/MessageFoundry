# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2625: injection and bulk export take a step-up proof bound to the action.

Before this, edit-resend, upload resend, resend to another outbound, export, purge and reload all
rode the shared session window, so one live session inside it was enough for any of them. Each now
takes a single-use grant minted for its own action (the ADR 0077 mechanism). Pinned here, on the
JSON plane, with the org opt-out left at its default:

* each of those routes refuses a fresh login's window and names its action;
* each admits a proof minted for its own action, once;
* a proof minted for another action does not open it;
* the rest of the step-up surface still opens on the window, so a dead-letter replay does not cost
  a typed password per message;
* upload resend needs ``messages:edit`` beside ``files:browse``.

The console twins are pinned in ``packaging/messagefoundry-webconsole/tests/test_ui_bound_step_up.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import (
    STEP_UP_ACTION_CONFIG_RELOAD,
    STEP_UP_ACTION_CONNECTION_PURGE,
    STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
    STEP_UP_ACTION_MESSAGE_EXPORT,
    STEP_UP_ACTION_MESSAGE_RESEND,
    STEP_UP_ACTION_UPLOAD_RESEND,
    AuthService,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
#: A well-formed id nothing holds. Every route below answers it past its gate with a 404 or an
#: empty result, so what a test reads is the gate's answer and nothing the handler decided.
NO_SUCH = "0" * 32

#: (action, method, path, json body, query). One row per route vault BACKLOG #2625 binds.
BOUND: list[tuple[str, str, str, dict[str, Any] | None, dict[str, Any] | None]] = [
    (
        STEP_UP_ACTION_MESSAGE_RESEND,
        "POST",
        f"/messages/{NO_SUCH}/resend",
        {"to": "OB_X", "idempotency_key": "k1"},
        None,
    ),
    (
        STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
        "POST",
        f"/messages/{NO_SUCH}/edit-resend",
        {"raw": ADT, "idempotency_key": "k1"},
        None,
    ),
    (
        STEP_UP_ACTION_UPLOAD_RESEND,
        "POST",
        f"/uploads/{NO_SUCH}/resend",
        {"index": 0, "to": "IB_X"},
        None,
    ),
    (STEP_UP_ACTION_MESSAGE_EXPORT, "GET", "/messages/export", None, {"ids": [NO_SUCH]}),
    (STEP_UP_ACTION_MESSAGE_EXPORT, "POST", "/messages/export", {"ids": [NO_SUCH]}, None),
    (STEP_UP_ACTION_CONNECTION_PURGE, "POST", "/connections/OB_X/purge", None, None),
    (STEP_UP_ACTION_CONFIG_RELOAD, "POST", "/config/reload", {"dry_run": True}, None),
]
_IDS = [f"{method} {path}" for _a, method, path, _b, _q in BOUND]


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "bound.db")
    eng = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    yield eng
    await eng.stop()


async def _service(engine: Engine, *, require_action_step_up: bool = True) -> AuthService:
    # require_action_step_up defaults to the shipped default, which is what this file is about.
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            require_action_step_up=require_action_step_up,
        ),
    )
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, roles: list[str]) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


def _client(engine: Engine, service: AuthService, tmp_path: Path) -> httpx.AsyncClient:
    app = create_app(
        engine,
        auth=service,
        store_settings=StoreSettings(uploads_dir=str(tmp_path / "uploads")),
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post("/auth/login", json={"username": username, "password": PW})
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _reauth(c: httpx.AsyncClient, token: str, purpose: str) -> str:
    """Mint a grant for ``purpose`` as a JSON client does. The session is re-keyed."""
    r = await c.post(
        "/me/reauth",
        json={"password": PW, "purpose": purpose},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _call(
    c: httpx.AsyncClient,
    token: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    query: dict[str, Any] | None,
) -> httpx.Response:
    return await c.request(
        method, path, json=body, params=query, headers={"Authorization": f"Bearer {token}"}
    )


def _refused_for(r: httpx.Response, action: str) -> bool:
    return (
        r.status_code == 403
        and r.headers.get("X-Step-Up-Required") == "1"
        and r.headers.get("X-Step-Up-Action") == action
    )


def _past_the_step_up(r: httpx.Response) -> bool:
    return "X-Step-Up-Required" not in r.headers and "X-Step-Up-Action" not in r.headers


@pytest.mark.parametrize(("action", "method", "path", "body", "query"), BOUND, ids=_IDS)
async def test_a_fresh_window_does_not_open_a_bound_route(
    engine: Engine,
    tmp_path: Path,
    action: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    query: dict[str, Any] | None,
) -> None:
    """A local login that owes no factor stamps the window, so the window here is as fresh as it
    gets. The route still refuses, and names the action a client must re-prove for."""
    service = await _service(engine)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, tmp_path) as c:
        token = await _login(c, "adm")
        assert await service.has_recent_step_up(token)  # control: the window IS fresh
        r = await _call(c, token, method, path, body, query)
        assert _refused_for(r, action), (r.status_code, dict(r.headers), r.text)


@pytest.mark.parametrize(("action", "method", "path", "body", "query"), BOUND, ids=_IDS)
async def test_a_bound_route_admits_its_own_proof_once(
    engine: Engine,
    tmp_path: Path,
    action: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    query: dict[str, Any] | None,
) -> None:
    service = await _service(engine)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, tmp_path) as c:
        token = await _reauth(c, await _login(c, "adm"), action)
        first = await _call(c, token, method, path, body, query)
        assert _past_the_step_up(first), (first.status_code, dict(first.headers), first.text)
        again = await _call(c, token, method, path, body, query)
        assert _refused_for(again, action), "the grant must be single-use"


@pytest.mark.parametrize(("action", "method", "path", "body", "query"), BOUND, ids=_IDS)
async def test_a_proof_for_another_action_does_not_open_a_bound_route(
    engine: Engine,
    tmp_path: Path,
    action: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    query: dict[str, Any] | None,
) -> None:
    other = (
        STEP_UP_ACTION_CONNECTION_PURGE
        if action != STEP_UP_ACTION_CONNECTION_PURGE
        else STEP_UP_ACTION_MESSAGE_EXPORT
    )
    service = await _service(engine)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, tmp_path) as c:
        token = await _reauth(c, await _login(c, "adm"), other)
        r = await _call(c, token, method, path, body, query)
        assert _refused_for(r, action)


async def test_the_rest_of_the_step_up_surface_still_opens_on_the_window(
    engine: Engine, tmp_path: Path
) -> None:
    """The row's own limit: do NOT bind every state change. A dead-letter replay, a single replay and
    an upload delete are step-up writes outside the injection and bulk set, so a fresh window still
    opens them with no typed proof per call."""
    service = await _service(engine)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, tmp_path) as c:
        token = await _login(c, "adm")
        for method, path, body in (
            ("POST", f"/messages/{NO_SUCH}/replay", None),
            ("POST", "/dead-letters/replay", {"channel_id": "IB_X"}),
            ("DELETE", f"/uploads/{NO_SUCH}", None),
        ):
            first = await _call(c, token, method, path, body, None)
            second = await _call(c, token, method, path, body, None)
            for r in (first, second):  # twice: nothing here spends a single-use grant
                assert _past_the_step_up(r), (path, r.status_code, dict(r.headers), r.text)


async def test_upload_resend_needs_messages_edit_beside_files_browse(
    engine: Engine, tmp_path: Path
) -> None:
    """``files:browse`` is a read. A role holding it with ``files:upload`` but not ``messages:edit``
    is refused the resend even with a valid proof, and a role holding both gets past the gate."""
    service = await _service(engine)
    narrow = await service.create_custom_role(
        display_name="Log Reader",
        description=None,
        permissions=["files:upload", "files:browse"],
        actor="test",
    )
    both = await service.create_custom_role(
        display_name="Log Reinjector",
        description=None,
        permissions=["files:upload", "files:browse", "messages:edit"],
        actor="test",
    )
    await _add(service, "reader", [narrow.id])
    await _add(service, "injector", [both.id])
    body = {"index": 0, "to": "IB_X"}
    async with _client(engine, service, tmp_path) as c:
        token = await _reauth(c, await _login(c, "reader"), STEP_UP_ACTION_UPLOAD_RESEND)
        r = await _call(c, token, "POST", f"/uploads/{NO_SUCH}/resend", body, None)
        assert r.status_code == 403
        assert r.json()["detail"] == "missing permission: messages:edit"
        token = await _reauth(c, await _login(c, "injector"), STEP_UP_ACTION_UPLOAD_RESEND)
        r = await _call(c, token, "POST", f"/uploads/{NO_SUCH}/resend", body, None)
        assert r.status_code != 403 and _past_the_step_up(r), (r.status_code, r.text)


async def test_the_org_opt_out_puts_the_bound_routes_back_on_the_window(
    engine: Engine, tmp_path: Path
) -> None:
    """``[auth].require_action_step_up = false`` reaches these routes as it reaches every
    action-bound route, so the binding is the setting's to switch and nothing else's."""
    service = await _service(engine, require_action_step_up=False)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, tmp_path) as c:
        token = await _login(c, "adm")
        for _action, method, path, body, query in BOUND:
            r = await _call(c, token, method, path, body, query)
            assert _past_the_step_up(r), (path, r.status_code, dict(r.headers), r.text)
