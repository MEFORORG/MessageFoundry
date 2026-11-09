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

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx
import pytest
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
from fastapi import FastAPI
from starlette.requests import Request

from messagefoundry.auth import Role
from messagefoundry.auth.service import Elevation
from messagefoundry.config.settings import StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import _auth
from messagefoundry_webconsole._auth import (
    _ISSUED_CONTINUATIONS,
    _issue_continuation,
    continuation_issued,
    lookup_ui_action,
)
from messagefoundry_webconsole.routes.connection_writes import _purge_confirm_continuation

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


async def test_a_console_reload_held_by_dual_control_names_its_config_digest(
    tmp_path: Path,
) -> None:
    """Vault BACKLOG #2596, step 3, through the console seam: the console calls the reload core
    with no params of its own, so the core must take the digest the release is checked against."""
    from messagefoundry.config.fingerprint import config_fingerprint
    from messagefoundry.config.settings import ApprovalsSettings, EgressSettings

    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "cfg.py").write_text(
        "from messagefoundry import outbound, File\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(tmp_path / 'out')!r}))\n",
        encoding="utf-8",
    )
    gated = ApprovalsSettings(enabled=True, operations=["config_reload"], min_dwell_seconds=0.0)
    engine = await Engine.create(
        tmp_path / "ui.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await auth_service(engine)
        await provision(service, "adm", [Role.ADMINISTRATOR.value])
        async with ui_client(engine, service, approvals=gated) as c:
            await cookie_login(c, "adm")
            await mint_bound_proof(c, "/ui/config/reload")
            held = await c.post("/ui/config/reload", headers=SAME_ORIGIN)
            assert _reauth_next(held) is None, held.headers
        [pending] = await engine.store.list_pending_approvals(now=0.0)
        assert str(pending["operation"]) == "config_reload"
        params = json.loads(str(pending["params"]))
        assert params["fingerprint"] == config_fingerprint(cfg)
    finally:
        await engine.stop()


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
        # A resubmit the engine refuses with a 409 before its store write (ch1 is no registered
        # inbound) spends the proof (owner ruling 2026-11-07, #3241 added item 1, which supersedes
        # R1's refund for a 403, 404 or 409), so the editor and the next submit ask for a new one.
        sent = await c.post(
            post,
            data={"raw": EDITED, "idempotency_key": "k2", "mode": "reroute"},
            headers=SAME_ORIGIN,
        )
        assert sent.status_code == 400 and _reauth_next(sent) is None
        assert _reauth_next(await c.get(editor)) == editor
        again = await c.post(
            post,
            data={"raw": "MSH|other", "idempotency_key": "k2", "mode": "reroute"},
            headers=SAME_ORIGIN,
        )
        assert _reauth_next(again) == editor


async def test_an_edit_resubmit_the_ingress_guard_refuses_gives_the_proof_back(
    engine: Engine, tmp_path: Path
) -> None:
    """A refusal before the store write that is not a 403, 404 or 409 still gives the proof back
    through the console (owner ruling 2026-10-13, #3241 R1): the guard's 422 for a body that is not
    HL7 leaves the editor open, and the corrected resubmit runs on the same proof and spends it."""
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
    post = f"/ui/messages/{mid}/edit-resend"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        await mint_bound_proof(c, editor)  # the one proof
        refused = await c.post(
            post,
            data={"raw": "not an HL7 message", "idempotency_key": "k1", "mode": "reroute"},
            headers=SAME_ORIGIN,
        )
        assert refused.status_code == 400 and _reauth_next(refused) is None
        # The engine guard refused it after the spend, not the console's own check before it.
        assert "invalid input" not in refused.text
        audit = await engine.store.list_audit()
        assert [a for a in audit if a["action"] == "message_edit_resend_reject"]
        assert (await c.get(editor)).status_code == 200
        done = await c.post(
            post,
            data={"raw": EDITED, "idempotency_key": "k2", "mode": "reroute"},
            headers=SAME_ORIGIN,
        )
        assert done.status_code == 303 and done.headers["location"] != f"/ui/messages/{mid}"
        # Control: the write spent it, so a new key asks again.
        again = await c.post(
            post,
            data={"raw": EDITED, "idempotency_key": "k3", "mode": "reroute"},
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


async def test_an_edit_resubmit_cancelled_after_its_commit_keeps_its_repeat(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #2625. A timeout or a client disconnect can cancel the resubmit after the store
    committed the child. The request then never learns that it ran, and edit-resend has no
    resend_log to fall back on, so dropping its spend record sent the retry to re-auth and a
    fresh-key editor. A request that ends without a refusal keeps its record: the same-key retry
    asks for no proof and lands on the child the first one made, and no second child exists."""
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
    post = f"/ui/messages/{mid}/edit-resend"
    committed = asyncio.Event()
    real_reroute = engine.edit_resend_reroute
    calls = 0

    async def cancelled_after_the_commit(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        outcome = await real_reroute(*args, **kwargs)
        if calls == 1:
            committed.set()
            await asyncio.Event().wait()  # hangs until the request is cancelled
        return outcome

    monkeypatch.setattr(engine, "edit_resend_reroute", cancelled_after_the_commit)
    form = {"raw": EDITED, "idempotency_key": "k1", "mode": "reroute"}
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        await mint_bound_proof(c, editor)  # the one proof
        first = asyncio.create_task(c.post(post, data=form, headers=SAME_ORIGIN))
        await committed.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        retry = await c.post(post, data=form, headers=SAME_ORIGIN)
        assert _reauth_next(retry) is None
        assert retry.status_code == 303 and retry.headers["location"] != f"/ui/messages/{mid}"
        # Control: the first did spend the proof, so a NEW key still asks for one.
        fresh = {**form, "idempotency_key": "k2"}
        assert _reauth_next(await c.post(post, data=fresh, headers=SAME_ORIGIN)) == editor
    assert calls == 2
    rows = await engine.store.list_messages(limit=50, allowed_channels=None)
    assert len(rows) == 2  # the origin and one child
    children = [m for m in rows if m["id"] != mid]
    assert [m["id"] for m in children] == [retry.headers["location"].rsplit("/", 1)[-1]]


async def test_a_refused_edit_resubmit_answers_its_repeat_with_the_edit_kept(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #2625. A double-clicked edit-resend whose first POST the engine refuses after
    the spend. The repeat waits for the first and gets the same refusal: the editor again, with the
    operator's edit in it, rather than a re-auth that would re-open the editor from the stored
    body. Neither runs the engine twice, and the same submit afterwards asks for a proof."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
    from messagefoundry.store.base import ResendError
    from messagefoundry_webconsole import _auth

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
    post = f"/ui/messages/{mid}/edit-resend"
    entered, release, rider_waiting = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = 0

    async def refused_after_the_spend(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        raise ResendError("refused for the test")

    real_await = _auth._SpentForKey.await_settled

    async def noted_await(self: Any, spend: Any) -> bool:
        rider_waiting.set()
        return await real_await(self, spend)

    monkeypatch.setattr(engine, "edit_resend_reroute", refused_after_the_spend)
    monkeypatch.setattr(_auth._SpentForKey, "await_settled", noted_await)
    form = {"raw": EDITED, "idempotency_key": "k1", "mode": "reroute"}
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        await mint_bound_proof(c, editor)  # the one proof
        first = asyncio.create_task(c.post(post, data=form, headers=SAME_ORIGIN))
        await entered.wait()
        rider = asyncio.create_task(c.post(post, data=form, headers=SAME_ORIGIN))
        await rider_waiting.wait()
        release.set()
        for answer in await asyncio.gather(first, rider):
            assert answer.status_code == 400 and _reauth_next(answer) is None
            assert "refused for the test" in answer.text
            assert "DOE^JOHN" in answer.text  # the edit, kept in the editor
        again = await c.post(post, data=form, headers=SAME_ORIGIN)
        assert _reauth_next(again) == editor
    assert calls == 1


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


async def test_the_purge_confirm_page_holds_the_purge_proof(engine: Engine) -> None:
    """Owner ruling 2026-10-13 (#3241 R2): a fresh window no longer opens the purge confirm page,
    because its POST would then ask for a re-auth after the operator confirmed. The page holds the
    proof and spends nothing, so the POST still spends it once."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        assert _reauth_next(await c.get(page)) == page  # the window alone: refused
        await mint_bound_proof(c, page)
        assert (await c.get(page)).status_code == 200
        assert (await c.get(page)).status_code == 200  # held, not spent
        ran = await c.post("/ui/connections/OB_X/purge/all", headers=SAME_ORIGIN)
        assert _reauth_next(ran) is None and ran.status_code == 404
        assert _reauth_next(await c.get(page)) == page  # the POST spent it


async def test_a_crafted_reauth_toward_an_unlock_page_mints_nothing_bound(engine: Engine) -> None:
    """Owner ruling 2026-10-13 (#3241 R3): /ui/reauth mints an unlock page's grant only when a gate
    issued that page to this session. A link straight to /ui/reauth?next=<unlock page> still
    re-authenticates, then ends on the page that says nothing ran, with nothing bound."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        crafted = await c.post(
            "/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN
        )
        assert crafted.status_code == 200 and "Nothing ran" in crafted.text
        # CONTROL: the gate's own refusal issues the page, and the same re-auth then mints.
        assert _reauth_next(await c.get(page)) == page
        issued = await c.post(
            "/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN
        )
        assert issued.status_code == 303 and issued.headers["location"] == page
        assert (await c.get(page)).status_code == 200
        # One issue mints one grant: the password re-auth spent it, so a second crafted re-auth
        # with no new refusal in between ends on the page that says nothing ran.
        again = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
        assert again.status_code == 200 and "Nothing ran" in again.text


async def test_an_unlock_page_issued_during_a_crafted_reauth_keeps_its_issue(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-auth toward an unlock page that was not issued when its POST arrived mints nothing. If
    another tab is issued that page while the password check runs, this re-auth must neither spend
    that issue nor answer with the auto-submit form, which is only for a body-less POST action. The
    other tab's own re-auth then still mints and redirects to the page. This covers the password
    check's await only; an issue made between the form's GET and its POST is read at the POST."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    real_reauth = service.reauth

    async def reauth_while_another_tab_is_issued(*args: Any, **kwargs: Any) -> Any:
        _issue_continuation(_get_request(page, kwargs["token"]), page)
        return await real_reauth(*args, **kwargs)

    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        monkeypatch.setattr(service, "reauth", reauth_while_another_tab_is_issued)
        crafted = await c.post(
            "/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN
        )
        assert crafted.status_code == 200 and "Nothing ran" in crafted.text
        monkeypatch.setattr(service, "reauth", real_reauth)
        # The other tab's issue survived, so its re-auth mints and goes back to the page.
        other = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
        assert other.status_code == 303 and other.headers["location"] == page
        assert (await c.get(page)).status_code == 200


async def test_an_auto_retry_issued_during_a_crafted_reauth_is_not_submitted(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The auto-retry twin of the test above: a crafted re-auth toward a body-less POST action that
    another tab is issued during the password check ends on "nothing ran", not on the auto-submit
    form, and leaves the issue for the other tab."""
    service = await auth_service(engine)
    await provision(service, "adm", [Role.ADMINISTRATOR.value])
    action = "/ui/config/reload"
    real_reauth = service.reauth

    async def reauth_while_another_tab_is_issued(*args: Any, **kwargs: Any) -> Any:
        _ISSUED_CONTINUATIONS.issue(kwargs["token"], action)
        return await real_reauth(*args, **kwargs)

    async with ui_client(engine, service) as c:
        await cookie_login(c, "adm")
        monkeypatch.setattr(service, "reauth", reauth_while_another_tab_is_issued)
        crafted = await c.post(
            "/ui/reauth", data={"next": action, "password": PW}, headers=SAME_ORIGIN
        )
        assert crafted.status_code == 200 and "Nothing ran" in crafted.text
        monkeypatch.setattr(service, "reauth", real_reauth)
        other = await c.post(
            "/ui/reauth", data={"next": action, "password": PW}, headers=SAME_ORIGIN
        )
        assert other.status_code == 200 and "Nothing ran" not in other.text  # the auto-submit


async def test_an_auto_retry_issue_is_taken_before_the_password_check(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3241, added item 9. The re-auth takes the issue before the password check's
    await, so nothing that touches the table during the check can spend it: the re-auth
    auto-submits once, and a second re-auth with no new refusal in between ends on "nothing ran".
    RED when: the issue is still in the table while the password is checked."""
    service = await auth_service(engine)
    await provision(service, "adm", [Role.ADMINISTRATOR.value])
    action = "/ui/config/reload"
    real_reauth = service.reauth
    seen: list[bool] = []

    async def reauth_seeing_the_table(*args: Any, **kwargs: Any) -> Any:
        seen.append(continuation_issued(kwargs["token"], action))
        return await real_reauth(*args, **kwargs)

    async with ui_client(engine, service) as c:
        await cookie_login(c, "adm")
        assert _reauth_next(await c.post(action, headers=SAME_ORIGIN)) == action  # issued
        monkeypatch.setattr(service, "reauth", reauth_seeing_the_table)
        first = await c.post(
            "/ui/reauth", data={"next": action, "password": PW}, headers=SAME_ORIGIN
        )
        assert first.status_code == 200 and "Nothing ran" not in first.text  # the auto-submit
        assert seen == [False]
        again = await c.post(
            "/ui/reauth", data={"next": action, "password": PW}, headers=SAME_ORIGIN
        )
        assert again.status_code == 200 and "Nothing ran" in again.text


async def test_two_reauths_racing_one_unlock_issue_mint_one_grant(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3241, added item 9. Two tabs re-authenticate toward one issued unlock page at
    once. The first takes the issue before its password check; the second, arriving during that
    check, finds nothing and so asks for no grant. RED when: both re-auths ask ``reauth`` for the
    page's action grant."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    real_reauth = service.reauth
    purposes: list[str | None] = []
    second: list[httpx.Response] = []

    async with ui_client(engine, service) as c:

        async def reauth_while_another_tab_reauths(*args: Any, **kwargs: Any) -> Any:
            purposes.append(kwargs.get("purpose"))
            if len(purposes) > 1:
                # The other tab's password check is still running when this one ends; answering
                # it refused keeps its rotation from retiring the first tab's token.
                return Elevation()
            second.append(
                await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
            )
            return await real_reauth(*args, **kwargs)

        await cookie_login(c, "op")
        _issue_continuation(_get_request(page, c.cookies["mf_session"]), page)
        monkeypatch.setattr(service, "reauth", reauth_while_another_tab_reauths)
        first = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)

    bound = lookup_ui_action(page)
    assert bound is not None and bound.action is not None
    assert purposes == [bound.action, None], purposes
    assert first.status_code == 303 and first.headers["location"] == page
    assert second[0].status_code == 200 and "Incorrect password." in second[0].text


async def test_a_wrong_password_gives_the_unlock_issue_back(engine: Engine) -> None:
    """Vault BACKLOG #3241, added item 9. The issue is taken before the password check, so a wrong
    password must put it back: the next, correct re-auth still mints and returns to the page. RED
    when: the wrong password strands the issue and the retry ends on "nothing ran"."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        assert _reauth_next(await c.get(page, headers={"Sec-Fetch-Site": "same-origin"})) == page
        wrong = await c.post(
            "/ui/reauth", data={"next": page, "password": "not-it"}, headers=SAME_ORIGIN
        )
        assert wrong.status_code == 200 and "Incorrect password." in wrong.text
        assert continuation_issued(c.cookies["mf_session"], page)
        right = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
        assert right.status_code == 303 and right.headers["location"] == page


def test_unlock_issues_do_not_evict_a_pending_auto_retry_issue() -> None:
    """Vault BACKLOG #3241, added item 8. Each kind has its own per-session cap, so a run of
    action-bound unlock pages cannot push out an auto-retry action the operator is confirming.
    CONTROL: auto-retry issues past the cap still drop the oldest of their own kind."""
    table = _auth._IssuedContinuations()
    cap = _auth._REAUTH_CONTINUATIONS_PER_SESSION
    table.issue("tok", "/ui/config/reload", unlock=False)
    for n in range(cap + 3):
        table.issue("tok", f"/ui/unlock/{n}", unlock=True)
    assert table.issued("tok", "/ui/config/reload")
    assert not table.issued("tok", "/ui/unlock/0")  # the oldest unlock page went
    assert table.issued("tok", f"/ui/unlock/{cap + 2}")
    for n in range(cap):
        table.issue("tok", f"/ui/messages/{n}/replay", unlock=False)
    assert not table.issued("tok", "/ui/config/reload")  # its own kind pushed it out
    assert table.issued("tok", f"/ui/unlock/{cap + 2}")


def test_a_put_back_entry_does_not_evict_one_issued_after_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A put-back entry keeps its older deadline but lands at the back of the session's entries.
    Past the cap, eviction drops the entry that lapses soonest, so the put-back one goes, never a
    page issued while it was out. RED when eviction follows insertion order."""
    clock = [1000.0]
    monkeypatch.setattr(_auth.time, "monotonic", lambda: clock[0])
    table = _auth._IssuedContinuations()
    cap = _auth._REAUTH_CONTINUATIONS_PER_SESSION
    table.issue("tok", "/ui/unlock/old", unlock=True)
    taken = table.take("tok", "/ui/unlock/old")
    assert taken is not None
    for n in range(cap):
        clock[0] += 1.0
        table.issue("tok", f"/ui/unlock/{n}", unlock=True)
    table.put_back(_auth.hash_token("tok"), "/ui/unlock/old", taken)
    assert not table.issued("tok", "/ui/unlock/old")
    assert all(table.issued("tok", f"/ui/unlock/{n}") for n in range(cap))


def test_a_put_back_follows_a_rotation_made_during_the_reauth() -> None:
    """Tab A takes an issue and awaits its re-proof; tab B rotates the session meanwhile. A's put
    back lands under the rotated session, where the retry with the new cookie finds it, not under the
    retired hash. RED when put_back keys on the hash captured before the await."""
    table = _auth._IssuedContinuations()
    table.issue("old", "/ui/unlock/page", unlock=True)
    taken = table.take("old", "/ui/unlock/page")
    assert taken is not None
    table.rekey("old", "new")
    table.put_back(_auth.hash_token("old"), "/ui/unlock/page", taken)
    assert table.issued("new", "/ui/unlock/page")
    assert not table.issued("old", "/ui/unlock/page")


def test_a_held_flow_claim_counts_as_continuing_and_follows_a_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An issue a federated start holds for its flow is still the session's: the re-auth page's
    read says the re-auth continues, as claim_continuation's take would, and a rotation the console
    sees moves the claim to the new token. CONTROL: once taken, it is neither held nor continuing."""
    monkeypatch.setattr(_auth, "_ISSUED_CONTINUATIONS", _auth._IssuedContinuations())
    monkeypatch.setattr(_auth, "_FLOW_CLAIMS", type(_auth._FLOW_CLAIMS)())
    monkeypatch.setattr(_auth, "_FLOW_CLAIM_IDS", {})
    page = "/ui/unlock/page"
    action = _auth.UiWriteAction(
        re.compile(re.escape(page)),
        None,
        auto_retry=False,
        unlock=True,
        action="config_reload",
        label="a page",
    )
    _auth._ISSUED_CONTINUATIONS.issue("old", page, unlock=True)
    claim = _auth.claim_continuation(action, "old", page)
    assert claim.continues and claim.holds_entry
    _auth.hold_claim_for_flow("flow-1", claim)
    assert not continuation_issued("old", page)  # held for the flow, not in the table
    assert _auth.continues_after_reauth(action, "old", page)
    _auth.rekey_continuations("old", "new")
    assert _auth.continues_after_reauth(action, "new", page)
    assert not _auth.continues_after_reauth(action, "old", page)
    retry = _auth.claim_continuation(action, "new", page)
    assert retry.continues and "flow-1" not in _auth._FLOW_CLAIMS
    assert not _auth.continues_after_reauth(action, "new", page)


def _get_request(path: str, token: str) -> Request:
    """A same-origin GET for ``path`` on the session ``token``, as a gate refusal sees it."""
    return Request(
        {
            "type": "http",
            "app": FastAPI(),  # Sec-Fetch-Site: same-origin settles the origin check
            "method": "GET",
            "scheme": "http",
            "path": path,
            "query_string": b"",
            "server": ("127.0.0.1", 8765),
            "headers": [
                (b"host", b"127.0.0.1:8765"),
                (b"sec-fetch-site", b"same-origin"),
                (b"cookie", f"mf_session={token}".encode()),
            ],
        }
    )


async def test_a_link_opened_from_outside_the_browser_issues_nothing(engine: Engine) -> None:
    """A GET with ``Sec-Fetch-Site: none`` (a typed URL, a bookmark, a link in an email) is refused
    without issuing the page, so a crafted link to the page itself pre-arms nothing. The page asks
    again, and the console's own navigation then issues it."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        outside = await c.get(page, headers={"Sec-Fetch-Site": "none"})
        assert _reauth_next(outside) == page
        r = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
        assert r.status_code == 200 and "Nothing ran" in r.text
        # CONTROL: the same refusal from the console's own navigation issues it.
        inside = await c.get(page, headers={"Sec-Fetch-Site": "same-origin"})
        assert _reauth_next(inside) == page
        r = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == page
        assert (await c.get(page)).status_code == 200


async def test_a_link_opened_from_outside_the_browser_costs_one_reauth(engine: Engine) -> None:
    """Vault BACKLOG #3241, added item 2. A bookmarked or typed link to an action-bound unlock page
    issues nothing, so the re-auth page it lands on must not take a password that mints nothing:
    it links to the page instead, and opening the page from there issues it, so the operator
    re-authenticates once. RED when: the re-auth page asks for a password toward a page it was not
    issued, so a second re-auth is needed."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        outside = await c.get(page, headers={"Sec-Fetch-Site": "none"})
        assert _reauth_next(outside) == page
        form = await c.get("/ui/reauth", params={"next": page}, headers={"Sec-Fetch-Site": "none"})
        assert form.status_code == 200
        assert 'name="password"' not in form.text and f'href="{page}"' in form.text
        # The operator follows the link: a same-origin navigation, so the refusal issues the page.
        inside = await c.get(page, headers={"Sec-Fetch-Site": "same-origin"})
        assert _reauth_next(inside) == page
        issued = await c.get("/ui/reauth", params={"next": page}, headers=SAME_ORIGIN)
        assert 'name="password"' in issued.text
        r = await c.post("/ui/reauth", data={"next": page, "password": PW}, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == page
        assert (await c.get(page)).status_code == 200


async def test_the_purge_selection_survives_the_reauth(engine: Engine) -> None:
    """Vault BACKLOG #3241, step 1 (the purge-selection item engine PR 2142 left unruled). The bulk
    purge confirm page's refusal carries its ``dest`` and ``scope`` query to the re-auth, which
    returns to the page with it, so the operator does not select again. CONTROL: a selection past
    the re-auth's cap on ``next`` is dropped, as before, rather than refused. RED when: the query is
    lost across the re-auth."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    page = "/ui/connections/purge-confirm"
    selected = f"{page}?dest=OB_A&dest=OB_B&scope=top"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        refused = await c.get(selected, headers={"Sec-Fetch-Site": "same-origin"})
        assert _reauth_next(refused) == selected
        r = await c.post("/ui/reauth", data={"next": selected, "password": PW}, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == selected
        assert (await c.get(selected)).status_code == 200
    long_query = "&".join(f"dest=OB_{n:04d}" for n in range(60)).encode()
    assert len(page) + 1 + len(long_query) > 512
    request = _get_request(page, "t" * 43)
    assert _purge_confirm_continuation(request) == page  # no query: the bare page
    request.scope["query_string"] = long_query
    assert _purge_confirm_continuation(request) == page  # too long to ride: dropped
    request.scope["query_string"] = b"dest=OB_A&scope=top"
    assert _purge_confirm_continuation(request) == f"{page}?dest=OB_A&scope=top"


def test_a_window_only_unlock_page_is_never_issued() -> None:
    """A window-only unlock page (one binding no action) always continues, so a gate refusing it
    records nothing: an entry would only fill the per-session cap and evict a pending auto-retry
    issue. CONTROL: the same refusal toward an action-bound unlock page is recorded."""
    token = "t" * 43
    window_only, bound = "/ui/roles/new", "/ui/connections/purge-confirm"
    wo_action, bound_action = lookup_ui_action(window_only), lookup_ui_action(bound)
    assert wo_action is not None and wo_action.unlock and wo_action.action is None
    assert bound_action is not None and bound_action.unlock and bound_action.action is not None

    def _get(path: str) -> Request:
        return _get_request(path, token)

    _issue_continuation(_get(window_only), window_only)
    assert not continuation_issued(token, window_only)
    _issue_continuation(_get(bound), bound)
    assert continuation_issued(token, bound)


def test_a_flow_return_in_progress_keeps_its_issue_from_other_reauths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """While a flow's callback runs, no other re-auth may take the issue the flow holds, and a
    return that consumed nothing leaves the issue with the flow for the real return. RED when: a
    re-auth takes the issue mid-callback, so the flow and that re-auth could each mint, or a
    non-consuming return strands or moves the issue. CONTROL: once settled, a re-auth takes it."""
    monkeypatch.setattr(_auth, "_ISSUED_CONTINUATIONS", _auth._IssuedContinuations())
    monkeypatch.setattr(_auth, "_FLOW_CLAIMS", type(_auth._FLOW_CLAIMS)())
    monkeypatch.setattr(_auth, "_FLOW_CLAIM_IDS", {})
    page = "/ui/connections/purge-confirm"
    action = _auth.lookup_ui_action(page)
    assert action is not None and action.binds_unlock_grant
    _auth._ISSUED_CONTINUATIONS.issue("tok", page, unlock=True)
    _auth.hold_claim_for_flow("flow-1", _auth.claim_continuation(action, "tok", page))

    claim, mint = _auth.take_flow_claim("flow-1", page)
    assert mint and claim is not None
    assert not _auth.claim_continuation(action, "tok", page).continues  # pinned to its flow
    _auth.settle_flow_claim("flow-1", claim, consumed=False, minted=False)
    assert _auth._FLOW_CLAIMS.get("flow-1") is claim and claim.holds_entry

    assert _auth.claim_continuation(action, "tok", page).continues
    claim, mint = _auth.take_flow_claim("flow-1", page)
    assert claim is None and not mint  # its issue was taken: the flow mints no grant


def test_a_lapsed_held_issue_mints_nothing_even_unpruned(monkeypatch: pytest.MonkeyPatch) -> None:
    """A flow whose held issue lapsed before its callback mints no grant, though no later start has
    pruned the issue from the held claims. RED when: the take answers from whether an issue is held
    and not whether it is live, so a lapsed issue mints or not by other sessions' traffic.
    CONTROL: the same flow with its issue still live mints."""
    monkeypatch.setattr(_auth, "_ISSUED_CONTINUATIONS", _auth._IssuedContinuations())
    monkeypatch.setattr(_auth, "_FLOW_CLAIMS", type(_auth._FLOW_CLAIMS)())
    monkeypatch.setattr(_auth, "_FLOW_CLAIM_IDS", {})
    page = "/ui/connections/purge-confirm"
    action = _auth.lookup_ui_action(page)
    assert action is not None and action.binds_unlock_grant
    _auth._ISSUED_CONTINUATIONS.issue("tok", page, unlock=True)
    _auth.hold_claim_for_flow("flow-1", _auth.claim_continuation(action, "tok", page))

    claim, mint = _auth.take_flow_claim("flow-1", page)
    assert mint and claim is not None  # control: live, so it mints
    _auth.settle_flow_claim("flow-1", claim, consumed=False, minted=False)

    claim._entry = _auth._Entry(time.monotonic() - 1.0, unlock=True)  # lapsed, still held
    assert _auth._FLOW_CLAIMS.get("flow-1") is claim and claim.holds_entry
    claim, mint = _auth.take_flow_claim("flow-1", page)
    assert claim is not None and not mint
