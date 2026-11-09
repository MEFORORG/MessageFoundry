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
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings, EgressSettings, StoreSettings
from messagefoundry.config.wiring import ConnectionSpec, OutboundConnection
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore, ResendKeyConflict
from tests._admin_account import create_local_user_chosen
from tests._store_audit import no_operator_audit

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


async def _add(service: AuthService, username: str, roles: list[str]) -> str:
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
    return user_id


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
        # Edit-resend's 404 for the id that names nothing spends the proof too (owner ruling
        # 2026-11-07, #3241 added item 1), so every bound route is single-use here.
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


async def test_prior_resend_answers_only_a_repeat_of_the_same_request(engine: Engine) -> None:
    """The web console asks this before it demands a proof, so it must name a repeat of the SAME
    request and nothing else: an unused key, another message, another target and the other kind of
    request (a resend versus an edit-and-resubmit re-ingress) all answer None."""
    mid = await engine.store.enqueue_message(
        channel_id="IB_A", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
    )
    other = await engine.store.enqueue_message(
        channel_id="IB_A", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG2"
    )
    assert await engine.store.get_resend_record("k-reingress") is None  # control: unused
    outcome = await engine.store.reingress(
        origin_message_id=mid, raw=ADT, idempotency_key="k-reingress", audit=no_operator_audit
    )
    record = await engine.store.get_resend_record("k-reingress")
    assert record is not None and record.message_id == mid
    assert record.outbox_id == outcome.new_message_id  # the child the first call created
    assert await engine.prior_resend("k-reingress", message_id=mid, to=None) == record
    assert await engine.prior_resend("k-reingress", message_id=other, to=None) is None
    assert await engine.prior_resend("k-reingress", message_id=mid, to="OB_X") is None
    assert await engine.prior_resend("unused", message_id=mid, to=None) is None


#: The suites whose subject is what the bound routes DO. They used to switch the proof off, so they
#: ran in a posture the engine does not ship (PR 2142 item 7). They now run with it on, through
#: tests/_bound_proof.py (vault BACKLOG #3241).
_SUITES_ON_THE_SHIPPED_DEFAULT = (
    "test_approvals.py",
    "test_dual_control_reload.py",
    "test_reload_cancellation.py",
    "test_resend_ingress_guards.py",
    "test_upload_api.py",
    "test_message_export.py",
    "test_resend.py",
)


def test_the_bound_route_suites_run_with_the_proof_on() -> None:
    """A suite that switches the bound proof off again reds here. A text check, so it is a tripwire
    and no more: test_message_export.py's org opt-out test passes ``bound=False`` to its own
    service helper, which this does not see, and is the one test there that may."""
    here = Path(__file__).resolve().parent
    for name in _SUITES_ON_THE_SHIPPED_DEFAULT:
        source = (here / name).read_text(encoding="utf-8")
        assert "require_action_step_up=False" not in source, f"{name} switches the bound proof off"
        assert "reproving_transport" in source, f"{name} no longer re-proves as a client does"


# --- which edit-resend refusals give the proof back -----------------------------------------------
# A refusal raised before the store write gives the proof back (owner ruling 2026-10-13, #3241 R1),
# except a 403, 404 or 409, which spends it (owner ruling 2026-11-07, #3241 added item 1).


async def _edit_resend_engine(tmp_path: Path) -> Engine:
    from tests.test_edit_resend import _registry

    engine = await Engine.create(
        tmp_path / "refund.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    registry = _registry(tmp_path)
    # Present in the config but not deployed (ADR 0111), for the direct-mode order test below.
    (tmp_path / "o3").mkdir(exist_ok=True)
    registry.add_outbound(
        OutboundConnection(
            "OB_UNDEPLOYED",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o3")}),
            deployed=False,
        )
    )
    engine.add_registry(registry)
    await engine.start()
    return engine


async def _edit_resend(c: httpx.AsyncClient, token: str, mid: str, **extra: Any) -> httpx.Response:
    return await c.post(
        f"/messages/{mid}/edit-resend",
        json={"raw": ADT, "idempotency_key": extra.pop("key", "k1"), **extra},
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.parametrize(
    ("status", "origin", "scope", "payload"),
    [
        # The direct target is outside the caller's channel scope.
        pytest.param(403, "in1", ["in1", "OB1"], {"to": "OB2"}, id="403-target-out-of-scope"),
        pytest.param(404, "in1", None, {"to": "OB_NOPE"}, id="404-unknown-target"),
        # The origin inbound is not registered on this engine.
        pytest.param(409, "IB_NOT_HERE", None, {"reroute": True}, id="409-origin-not-here"),
    ],
)
async def test_an_edit_resend_refused_403_404_or_409_spends_the_proof(
    tmp_path: Path, status: int, origin: str, scope: list[str] | None, payload: dict[str, Any]
) -> None:
    """Each of these refusals comes before the store write and still spends the proof, so the
    same request sent again asks for a new one rather than answering the same refusal."""
    pytest.importorskip("psutil")
    engine = await _edit_resend_engine(tmp_path)
    try:
        service = await _service(engine)
        # An operator, since the administrator role is unscoped whatever its stored scope says.
        user_id = await _add(service, "op", [Role.OPERATOR.value])
        if scope is not None:
            await service.set_channel_scope(user_id, scope, actor="test")
        mid = await engine.store.enqueue_message(
            channel_id=origin, raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
        )
        async with _client(engine, service, tmp_path) as c:
            token = await _reauth(c, await _login(c, "op"), STEP_UP_ACTION_MESSAGE_EDIT_RESEND)
            refused = await _edit_resend(c, token, mid, **payload)
            assert refused.status_code == status and _past_the_step_up(refused), refused.text
            again = await _edit_resend(c, token, mid, key="k2", **payload)
            assert _refused_for(again, STEP_UP_ACTION_MESSAGE_EDIT_RESEND), (
                again.status_code,
                again.text,
            )
    finally:
        await engine.stop()


async def test_an_edit_resend_refused_otherwise_before_its_store_write_gives_the_proof_back(
    tmp_path: Path,
) -> None:
    """A refusal before the store write that is not a 403, 404 or 409 still gives the proof back
    (owner ruling 2026-10-13, #3241 R1): a 400 for a request with neither a target nor a re-route,
    and the ingress guard's 422 for a body that is not HL7. The edit that follows then runs on the
    SAME proof, and spends it: the write is what single use counts."""
    pytest.importorskip("psutil")
    engine = await _edit_resend_engine(tmp_path)
    try:
        service = await _service(engine)
        await _add(service, "adm", [Role.ADMINISTRATOR.value])
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
        )
        async with _client(engine, service, tmp_path) as c:
            token = await _reauth(c, await _login(c, "adm"), STEP_UP_ACTION_MESSAGE_EDIT_RESEND)
            neither = await _edit_resend(c, token, mid, reroute=False)
            assert neither.status_code == 400 and _past_the_step_up(neither), neither.text
            not_hl7 = await _edit_resend(c, token, mid, raw="not an HL7 message", reroute=True)
            assert not_hl7.status_code == 422 and _past_the_step_up(not_hl7), not_hl7.text
            # The guard's refusal, after the spend, not the framework's 422 before it.
            assert isinstance(not_hl7.json()["detail"], str), not_hl7.text
            audit = await engine.store.list_audit()
            assert [a for a in audit if a["action"] == "message_edit_resend_reject"]
            done = await _edit_resend(c, token, mid, reroute=True)
            assert done.status_code == 200 and done.json()["status"] == "resubmitted", done.text
            # CONTROL: the write spent it, so the next edit asks again.
            again = await _edit_resend(c, token, mid, reroute=True, key="k2")
            assert _refused_for(again, STEP_UP_ACTION_MESSAGE_EDIT_RESEND), again.status_code
    finally:
        await engine.stop()


async def test_an_edit_resend_refused_at_its_store_write_keeps_the_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal from the store call itself may follow a commit, so it gives nothing back."""
    pytest.importorskip("psutil")
    engine = await _edit_resend_engine(tmp_path)
    try:
        service = await _service(engine)
        await _add(service, "adm", [Role.ADMINISTRATOR.value])
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
        )

        async def refused_at_the_store(*_a: Any, **_k: Any) -> Any:
            raise ResendKeyConflict("idempotency key already used for another target")

        monkeypatch.setattr(engine, "edit_resend_reroute", refused_at_the_store)
        async with _client(engine, service, tmp_path) as c:
            token = await _reauth(c, await _login(c, "adm"), STEP_UP_ACTION_MESSAGE_EDIT_RESEND)
            assert (await _edit_resend(c, token, mid, reroute=True)).status_code == 409
            again = await _edit_resend(c, token, mid, reroute=True, key="k2")
            assert _refused_for(again, STEP_UP_ACTION_MESSAGE_EDIT_RESEND), again.status_code
    finally:
        await engine.stop()


# --- direct mode checks the body before it reveals the target (ADR 0197 Amendment D) ----------
#: An edited body the engine-wide guard refuses whatever the target: a NUL is refused 422.
NUL_BODY = ADT + "NTE|1||x\x00\r"


@pytest.mark.parametrize(
    ("to", "status", "patch"),
    [
        pytest.param("OB_NOPE", 404, None, id="unknown"),
        pytest.param("OB_UNDEPLOYED", 409, None, id="not-deployed"),
        pytest.param("OB2", 409, ("destination_owner", "other-shard"), id="another-engine-shard"),
        pytest.param("OB2", 409, ("outbound_running", False), id="stopped"),
    ],
)
async def test_a_direct_edit_resend_with_a_bad_body_does_not_reveal_its_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    to: str,
    status: int,
    patch: tuple[str, object] | None,
) -> None:
    """A body the guard refuses gets the guard's 422 and its proof back, whatever state the target
    is in, so a run of such bodies cannot map which outbounds are registered, deployed, on this
    engine shard or running. The same proof then sends a good body, which meets the target's own
    404 or 409 and spends it: the guard did refund, and the target checks still hold."""
    pytest.importorskip("psutil")
    engine = await _edit_resend_engine(tmp_path)
    try:
        rr = engine.registry_runner
        assert rr is not None
        if patch is not None:
            method, answer = patch
            monkeypatch.setattr(rr, method, lambda _name: answer)
        service = await _service(engine)
        await _add(service, "adm", [Role.ADMINISTRATOR.value])
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
        )
        async with _client(engine, service, tmp_path) as c:
            token = await _reauth(c, await _login(c, "adm"), STEP_UP_ACTION_MESSAGE_EDIT_RESEND)
            bad = await _edit_resend(c, token, mid, raw=NUL_BODY, to=to)
            assert bad.status_code == 422 and _past_the_step_up(bad), (bad.status_code, bad.text)
            assert to not in bad.text, bad.text
            audit = await engine.store.list_audit()
            assert [a for a in audit if a["action"] == "message_edit_resend_reject"]
            good = await _edit_resend(c, token, mid, to=to, key="k2")
            assert good.status_code == status and _past_the_step_up(good), (
                good.status_code,
                good.text,
            )
            again = await _edit_resend(c, token, mid, to=to, key="k3")
            assert _refused_for(again, STEP_UP_ACTION_MESSAGE_EDIT_RESEND), again.status_code
    finally:
        await engine.stop()


async def test_a_direct_edit_resend_with_a_bad_body_out_of_scope_is_still_403(
    tmp_path: Path,
) -> None:
    """The scope check stays ahead of the guard: a bad body to a target outside the caller's scope
    gets the audited 403 and spends the proof, and the guard never runs on it."""
    pytest.importorskip("psutil")
    engine = await _edit_resend_engine(tmp_path)
    try:
        service = await _service(engine)
        # An operator, since the administrator role is unscoped whatever its stored scope says.
        user_id = await _add(service, "op", [Role.OPERATOR.value])
        await service.set_channel_scope(user_id, ["in1", "OB1"], actor="test")
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[], message_type="ADT^A01", control_id="MSG1"
        )
        async with _client(engine, service, tmp_path) as c:
            token = await _reauth(c, await _login(c, "op"), STEP_UP_ACTION_MESSAGE_EDIT_RESEND)
            bad = await _edit_resend(c, token, mid, raw=NUL_BODY, to="OB2")
            assert bad.status_code == 403 and _past_the_step_up(bad), (bad.status_code, bad.text)
            audit = await engine.store.list_audit()
            denied = [a for a in audit if a["action"] == "auth.channel_denied"]
            assert [a["channel_id"] for a in denied] == ["OB2"], denied
            assert not [a for a in audit if a["action"] == "message_edit_resend_reject"]
            again = await _edit_resend(c, token, mid, raw=NUL_BODY, to="OB2", key="k2")
            assert _refused_for(again, STEP_UP_ACTION_MESSAGE_EDIT_RESEND), again.status_code
    finally:
        await engine.stop()


# --- the export spends after its input check (owner ruling 2026-10-13, #3241 R2) ---------------


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_a_malformed_export_costs_no_proof(
    engine: Engine, tmp_path: Path, method: str
) -> None:
    """A criterion the export refuses (400) or the framework refuses (422) is checked before the
    spend, so the same proof then opens a well-formed export, once."""
    service = await _service(engine)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    get = method == "GET"
    malformed: list[tuple[dict[str, Any] | None, dict[str, Any] | None, int]] = (
        [(None, {"field_path": "NOT A PATH"}, 400), (None, {"limit": 0}, 422)]
        if get
        else [({"content": "x", "field_path": "PID-5"}, None, 400), ({"limit": 0}, None, 422)]
    )
    good = (None, {"ids": [NO_SUCH]}) if get else ({"ids": [NO_SUCH]}, None)
    async with _client(engine, service, tmp_path) as c:
        token = await _reauth(c, await _login(c, "adm"), STEP_UP_ACTION_MESSAGE_EXPORT)
        for body, query, expected in malformed:
            r = await _call(c, token, method, "/messages/export", body, query)
            assert r.status_code == expected and _past_the_step_up(r), (body, query, r.status_code)
        ok = await _call(c, token, method, "/messages/export", good[0], good[1])
        assert ok.status_code == 200 and _past_the_step_up(ok), (ok.status_code, ok.text)
        again = await _call(c, token, method, "/messages/export", good[0], good[1])
        assert _refused_for(again, STEP_UP_ACTION_MESSAGE_EXPORT), "the export spent its proof"


async def test_an_edit_resend_body_the_framework_refuses_costs_no_proof(
    engine: Engine, tmp_path: Path
) -> None:
    """The edit-resend proof is spent in the route, after FastAPI validated the body (owner ruling
    2026-10-13, #3241 R1 and R2), so a 422 leaves it for the corrected request."""
    service = await _service(engine)
    await _add(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, tmp_path) as c:
        token = await _reauth(c, await _login(c, "adm"), STEP_UP_ACTION_MESSAGE_EDIT_RESEND)
        bad = await _call(
            c, token, "POST", f"/messages/{NO_SUCH}/edit-resend", {"idempotency_key": "k1"}, None
        )
        assert bad.status_code == 422 and _past_the_step_up(bad), bad.status_code
        # The same proof still opens the route: the unknown message is the handler's 404.
        ok = await _call(
            c,
            token,
            "POST",
            f"/messages/{NO_SUCH}/edit-resend",
            {"raw": ADT, "idempotency_key": "k1"},
            None,
        )
        assert ok.status_code == 404 and _past_the_step_up(ok), ok.status_code
