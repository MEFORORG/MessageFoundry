# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2625 on the console: the injection and bulk lanes take a proof bound to the action.

The console calls the engine handlers by reference, so their action-bound gates never run here and
each ``/ui`` route has to re-assert the same action. Pinned for each lane the console has (export
has none): a fresh login's window is refused and sent to ``/ui/reauth``; the re-auth mints the
lane's grant; one action spends it. The message editor is the one lane that only CHECKS the grant
on its way in, so the re-auth comes before the operator types, and its resubmit spends the grant
after its own input checks. Upload resend also needs ``messages:edit``. The JSON plane is pinned in
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
    uploads = StoreSettings(uploads_dir=str(tmp_path / "uploads"))
    confirm = f"/ui/uploaded-logs/file/{NO_SUCH}/resend-confirm?index=0&to=IB_X"
    post = f"/ui/uploaded-logs/file/{NO_SUCH}/resend?index=0&to=IB_X"
    async with ui_client(engine, service, store_settings=uploads) as c:
        await cookie_login(c, "reader")
        # files:browse alone is a read: the confirm page and the POST both refuse it outright.
        assert (await c.get(confirm)).status_code == 403
        assert (await c.post(post, headers=SAME_ORIGIN)).status_code == 403
    async with ui_client(engine, service, store_settings=uploads) as c:
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
        # The refused submit left no spend record, so resubmitting the re-rendered editor with
        # the SAME key asks for a proof again rather than riding on the one it spent.
        again = await c.post(
            post,
            data={"raw": "MSH|other", "idempotency_key": "k2", "mode": "reroute"},
            headers=SAME_ORIGIN,
        )
        assert _reauth_next(again) == editor


async def test_an_edit_resubmit_repeated_with_one_proof_lands_once(
    engine: Engine, tmp_path: Path
) -> None:
    """Vault BACKLOG #2625, the edit-resend twin of the resend double-submit. Two re-route POSTs
    with the same key and one proof: the first re-ingresses a child, the second repeats it and asks
    for no proof, so both land on the same child and only one child exists."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry

    (tmp_path / "in").mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "ch1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    engine.add_registry(reg)
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    mid = await seed_message(engine)
    editor = f"/ui/messages/{mid}/edit"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        await mint_bound_proof(c, editor)  # the one proof
        form = {"raw": EDITED, "idempotency_key": "k1", "mode": "reroute"}
        answers = [
            await c.post(f"/ui/messages/{mid}/edit-resend", data=form, headers=SAME_ORIGIN)
            for _ in range(2)
        ]
        assert [a.status_code for a in answers] == [303, 303]
        assert (
            answers[0].headers["location"]
            == answers[1].headers["location"]
            != f"/ui/messages/{mid}"
        )
        # Control: the repeat rode on no proof, and the first one did spend it. A NEW key asks.
        fresh = {**form, "idempotency_key": "k2"}
        r = await c.post(f"/ui/messages/{mid}/edit-resend", data=fresh, headers=SAME_ORIGIN)
        assert _reauth_next(r) == editor
    rows = await engine.store.list_messages(limit=50, allowed_channels=None)
    children = [m for m in rows if m["id"] != mid]
    assert len(children) == 1


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


def test_the_browse_page_offers_resend_only_to_a_role_that_can_resend() -> None:
    """A resend needs messages:edit, so a role without it is told so in place of the form, rather
    than offered one its confirm page refuses."""
    from messagefoundry.api.models import UploadedMessagesResult
    from messagefoundry_webconsole.pages import uploaded_log_detail

    result = UploadedMessagesResult(
        file_id=NO_SUCH,
        filename="acme.hl7",
        matched=0,
        messages=[],
        scanned=0,
        total_messages=0,
        truncated=False,
    )
    confirm = f"/ui/uploaded-logs/file/{NO_SUCH}/resend-confirm"
    assert confirm in str(uploaded_log_detail(result))  # control: the default offers it
    reader = str(uploaded_log_detail(result, can_resend=False))
    assert confirm not in reader
    assert "messages:edit" in reader
