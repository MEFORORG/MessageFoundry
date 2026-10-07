# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2625 on the console: the injection and bulk lanes take a proof bound to the action.

The console calls the engine handlers by reference, so their action-bound gates never run here and
each ``/ui`` route has to re-assert the same action. Pinned for each lane the console has (export
has none): a fresh login's window is refused and sent to ``/ui/reauth``; the re-auth mints the
lane's grant; one action spends it. The message editor is the one lane that only CHECKS the grant
on its way in, so a re-auth never drops a typed edit, and its resubmit spends the grant after its
own input checks. Upload resend also needs ``messages:edit``. The JSON plane is pinned in
``tests/test_bound_step_up_injection.py``.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx
from _ui_clients import (
    ADT,
    PW,
    SAME_ORIGIN,
    auth_service,
    cookie_login,
    mint_bound_proof,
    provision,
    seed_message,
    ui_client,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.config.settings import StoreSettings
from messagefoundry.pipeline import Engine

NO_SUCH = "0" * 32
EDITED = ADT.replace("DOE^JANE", "DOE^JOHN")


def _reauth_next(r: httpx.Response) -> str | None:
    """The continuation a 303 to ``/ui/reauth`` carries, or ``None`` for any other answer."""
    location = r.headers.get("location", "")
    if r.status_code != 303 or not location.startswith("/ui/reauth?"):
        return None
    return unquote(dict(parse_qsl(urlsplit(location).query))["next"])


async def test_config_reload_takes_its_own_proof(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "adm", [Role.ADMINISTRATOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "adm")  # a fresh window
        refused = await c.post("/ui/config/reload", headers=SAME_ORIGIN)
        assert _reauth_next(refused) == "/ui/config/reload"
        await mint_bound_proof(c, "/ui/config/reload")
        ran = await c.post("/ui/config/reload", headers=SAME_ORIGIN)
        assert _reauth_next(ran) is None, ran.headers
        again = await c.post("/ui/config/reload", headers=SAME_ORIGIN)
        assert _reauth_next(again) == "/ui/config/reload"  # single use


async def test_purge_takes_its_own_proof(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        refused = await c.post("/ui/connections/OB_X/purge/all", headers=SAME_ORIGIN)
        assert _reauth_next(refused) == "/ui/connections/purge-confirm"
        await mint_bound_proof(c, "/ui/connections/purge-confirm")
        ran = await c.post("/ui/connections/OB_X/purge/all", headers=SAME_ORIGIN)
        assert _reauth_next(ran) is None and ran.status_code == 404  # the handler answered
        again = await c.post(
            "/ui/connections/purge-bulk", data={"dest": "OB_X"}, headers=SAME_ORIGIN
        )
        assert _reauth_next(again) == "/ui/connections/purge-confirm"  # spent by the first


async def test_resend_takes_its_own_proof(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    mid = await seed_message(engine)
    post = f"/ui/messages/{mid}/resend?to=OB2&source=archive&idempotency_key=k1"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        refused = await c.post(post, headers=SAME_ORIGIN)
        confirm = _reauth_next(refused)
        assert confirm is not None and confirm.startswith(f"/ui/messages/{mid}/resend-confirm?")
        await mint_bound_proof(c, confirm)
        ran = await c.post(post, headers=SAME_ORIGIN)
        # OB2 is not registered, so the handler refuses in place: the gate let it through.
        assert ran.status_code == 400 and _reauth_next(ran) is None


async def test_upload_resend_needs_messages_edit_and_its_own_proof(
    engine: Engine, tmp_path: Path
) -> None:
    service = await auth_service(engine)
    reader = await service.create_custom_role(
        display_name="Log Reader",
        description=None,
        permissions=["files:upload", "files:browse"],
        actor="test",
    )
    await provision(service, "reader", [reader.id])
    await provision(service, "op", [Role.OPERATOR.value])
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        store_settings=StoreSettings(uploads_dir=str(tmp_path / "uploads")),
    )
    confirm = f"/ui/uploaded-logs/file/{NO_SUCH}/resend-confirm?index=0&to=IB_X"
    post = f"/ui/uploaded-logs/file/{NO_SUCH}/resend?index=0&to=IB_X"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await cookie_login(c, "reader")
        # files:browse alone is a read: the confirm page and the POST both refuse it outright.
        assert (await c.get(confirm)).status_code == 403
        assert (await c.post(post, headers=SAME_ORIGIN)).status_code == 403
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await cookie_login(c, "op")
        refused = await c.post(post, headers=SAME_ORIGIN)
        assert _reauth_next(refused) == confirm
        await mint_bound_proof(c, confirm)
        ran = await c.post(post, headers=SAME_ORIGIN)
        # No such file: the handler's refusal lands on the list page, so the gate let it through.
        assert ran.status_code == 303 and ran.headers["location"].startswith("/ui/uploaded-logs?e=")


async def test_the_editor_asks_before_it_opens_and_the_resubmit_spends_it(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    mid = await seed_message(engine)
    editor = f"/ui/messages/{mid}/edit"
    post = f"/ui/messages/{mid}/edit-resend"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")  # a fresh window does not open the editor
        assert _reauth_next(await c.get(editor)) == editor
        # The re-auth the browser makes next, toward the editor: an unlock page, so it continues.
        r = await c.post("/ui/reauth", data={"next": editor, "password": PW}, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == editor
        # Opening the editor only checks the grant, so a reload of the page keeps it.
        assert (await c.get(editor)).status_code == 200
        assert (await c.get(editor)).status_code == 200
        # A refusal of the route's own input comes before the spend, so it costs no proof.
        bad = await c.post(
            post,
            data={"raw": EDITED, "idempotency_key": "k1", "mode": "direct", "to": ""},
            headers=SAME_ORIGIN,
        )
        assert bad.status_code == 400 and "choose an outbound connection" in bad.text
        assert (await c.get(editor)).status_code == 200
        # A resubmit the engine refuses (ch1 is no registered inbound) has spent the proof.
        sent = await c.post(
            post,
            data={"raw": EDITED, "idempotency_key": "k2", "mode": "reroute"},
            headers=SAME_ORIGIN,
        )
        assert sent.status_code == 400 and _reauth_next(sent) is None
        assert _reauth_next(await c.get(editor)) == editor


async def test_a_replay_still_opens_on_the_window(engine: Engine) -> None:
    """The row's own limit: replay is a step-up write outside the injection and bulk set, so a
    fresh window still opens it, twice, with no typed proof per message."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    mid = await seed_message(engine)
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        for _ in range(2):
            r = await c.post(f"/ui/messages/{mid}/replay", headers=SAME_ORIGIN)
            assert _reauth_next(r) is None, r.headers
