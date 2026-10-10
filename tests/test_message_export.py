# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""S7b #124 — bulk raw-message-body export from a search result (ADR 0131).

Covers the LARGEST PHI surface in the cluster: GET /messages/export streaming decrypted bodies to a
file. Verifies the step-up gate, the dedicated messages:export permission (distinct from view_raw),
per-row channel scope on every streamed body, the pre-stream messages_export audit counting every
selected body (needle value never recorded), save-all (search filters) and save-selected (explicit ids),
and the 400 on an empty selection. The route loops get_message per id — NO store schema change.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import ExportStopped
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.permissions import BUILTIN_ROLE_PERMISSIONS
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"  # ≥15, satisfies the ASVS policy

ADT_A = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSGA|P|2.5.1\rPID|1||MRN9001^^^H^MR||DOE^JANE\r"
ADT_B = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSGB|P|2.5.1\rPID|1||MRN9002^^^H^MR||ROE^RICHARD\r"


# --- permission catalog ---------------------------------------------------------


def test_messages_export_is_a_distinct_capability() -> None:
    """Bulk export is a DISTINCT capability from view_raw: operator + administrator hold it, viewer does
    not (ADR 0131 §2)."""
    assert Permission.MESSAGES_EXPORT in BUILTIN_ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.MESSAGES_EXPORT in BUILTIN_ROLE_PERMISSIONS[Role.ADMINISTRATOR]
    assert Permission.MESSAGES_EXPORT not in BUILTIN_ROLE_PERMISSIONS[Role.VIEWER]


# --- API fixtures (modelled on tests/test_content_search.py) --------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "export.db", cipher=make_cipher(generate_key()))
    eng = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    yield eng
    await eng.stop()


async def _service(engine: Engine, *, bound: bool = False) -> AuthService:
    # ``bound`` keeps the shipped default, an export proof bound to the action (vault BACKLOG #2625).
    # The other tests here are about what an export selects and records, so they keep the window.
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, require_mfa=False, require_action_step_up=bound
        ),
    )
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, *, raise_app_exceptions: bool = True
) -> httpx.AsyncClient:
    # raise_app_exceptions=False hands back what streamed before the app raised, as a real client
    # sees a broken download, rather than re-raising the app's exception into the test.
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service), raise_app_exceptions=raise_app_exceptions
    )
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add_user(
    service: AuthService, username: str, roles: list[str], *, scope: list[str] | None = None
) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    if scope is not None:
        await service.set_channel_scope(user_id, scope, actor="admin")
    return user_id


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ndjson(text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


async def _seed(engine: Engine) -> tuple[str, str]:
    mid_a = await engine.store.enqueue_message(
        channel_id="IB_A", raw=ADT_A, deliveries=[], message_type="ADT^A01", control_id="MSGA"
    )
    mid_b = await engine.store.enqueue_message(
        channel_id="IB_B", raw=ADT_B, deliveries=[], message_type="ADT^A01", control_id="MSGB"
    )
    return mid_a, mid_b


# --- gating ---------------------------------------------------------------------


async def test_export_requires_step_up(engine: Engine) -> None:
    """A fresh login's window does not reach an export: it takes a proof bound to the export, spent
    by the one request it opens (vault BACKLOG #2625)."""
    service = await _service(engine, bound=True)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        # POST, because a needle-selected save-all sends its criteria in the body (BACKLOG #1184);
        # the gate is the same on both shapes.
        blocked = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
        assert blocked.headers.get("X-Step-Up-Action") == "message_export"
        r = await c.post(
            "/me/reauth",
            json={"password": PW, "purpose": "message_export"},
            headers=_auth(token),
        )
        assert r.status_code == 200, r.text
        token = r.json()["token"]
        ok = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert ok.status_code == 200, ok.text
        # Single use: the next export asks again, before any body streams.
        again = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert again.status_code == 403
        assert again.headers.get("X-Step-Up-Action") == "message_export"


async def test_export_keeps_the_window_under_the_org_opt_out(engine: Engine) -> None:
    """``[auth].require_action_step_up = false`` puts the export back on the session window."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        ok = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert ok.status_code == 200, ok.text
        # Back-date the step-up window → refused with the step-up signal, before any body streams.
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)
        blocked = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"


async def test_export_denied_without_export_permission(engine: Engine) -> None:
    """VIEWER holds neither messages:export nor messages:view_raw → 403."""
    service = await _service(engine)
    await _add_user(service, "view", [Role.VIEWER.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "view")
        r = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert r.status_code == 403


async def test_export_bad_request_no_selection(engine: Engine) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        # No ids AND no search needle → make_spec refuses → 400.
        r = await c.get("/messages/export", headers=_auth(token))
        assert r.status_code == 400


# --- selection + streamed bodies ------------------------------------------------


async def test_export_save_all_streams_decrypted_bodies(engine: Engine) -> None:
    """AC: save-all via search filters streams the DECRYPTED raw bodies as NDJSON, even though the at-rest
    bytes are ciphertext a SQL LIKE would never match."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.post(
            "/messages/export",
            headers=_auth(token),
            json={"content": "ADT", "message_type": "ADT^A01"},
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/x-ndjson")
        assert "attachment" in r.headers.get("content-disposition", "")
        rows = _ndjson(r.text)
        assert len(rows) == 2
        # The raw body (PHI) IS the point of the export — it must be present and decrypted.
        raws = {row["control_id"]: row["raw"] for row in rows}
        assert "DOE^JANE" in str(raws["MSGA"])
        assert str(raws["MSGA"]).startswith("MSH")  # not the mfenc: ciphertext
        # A NEGATIVE leak check, so it must exclude EVERY at-rest marker version: a v1-only spelling
        # would pass silently on a leaked v2 blob instead of failing. Non-vacuous — the synthetic ADT
        # plaintext contains no "mfenc:" at all, and the startswith("MSH") above pins the shape.
        assert MARKER_PREFIX not in str(raws["MSGA"])


async def test_export_save_selected_by_ids(engine: Engine) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    mid_a, _mid_b = await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a]})
        assert r.status_code == 200, r.text
        rows = _ndjson(r.text)
        assert len(rows) == 1 and rows[0]["id"] == mid_a


# --- per-row scope --------------------------------------------------------------


async def test_export_per_row_scope_skips_out_of_scope_ids(engine: Engine) -> None:
    """A channel-scoped operator's save-selected across channels only ever streams IN-scope bodies; the
    out-of-scope id is skipped and audited (ADR 0131 §3) — the load-bearing check on the ids path."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value], scope=["IB_A"])
    mid_a, mid_b = await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a, mid_b]})
        assert r.status_code == 200, r.text
        rows = _ndjson(r.text)
        assert [row["id"] for row in rows] == [mid_a]  # IB_B body never streamed
    audit = [dict(x) for x in await engine.store.list_audit(limit=50)]
    assert any(a["action"] == "auth.channel_denied" for a in audit)


# --- audit ----------------------------------------------------------------------


async def test_export_audited_counts_every_body_without_needle(engine: Engine) -> None:
    """The dedicated messages_export audit records the actor + selection + count BEFORE streaming, and
    never the MRN-shaped needle value (ADR 0131 §4)."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.post(
            "/messages/export",
            headers=_auth(token),
            json={"content": "9001", "channel_id": "IB_A"},
        )
        assert r.status_code == 200, r.text
    rows = [dict(x) for x in await engine.store.list_audit(limit=50)]
    export_rows = [a for a in rows if a["action"] == "messages_export"]
    assert export_rows, "a messages_export audit row must be written"
    detail = export_rows[0]["detail"]
    assert "9001" not in detail  # the needle value is PHI — never recorded
    parsed = json.loads(detail)
    assert parsed["mode"] == "search"
    assert parsed["selected"] == 1  # counts every selected/exposed body
    assert parsed["needle_shape"] == "digits"


async def test_export_charges_the_per_actor_phi_read_budget(engine: Engine) -> None:
    """Export is a step-up GET, and step-up pacing (``_enforce_admin_write_pacing``) is NON-GET only —
    so without an explicit admission charge one actor could stream far more bodies per minute here than
    the per-actor budget allows through ``/messages``. It must draw from the SAME bucket."""
    service = AuthService(
        # The PHI-read budget is the subject; the export keeps the window (vault BACKLOG #2625).
        engine.store,
        AuthSettings(
            require_mfa=False, phi_read_rate_limit_per_actor=2, require_action_step_up=False
        ),
    )
    await service.initialize()
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        h = _auth(await _login(c, "op"))
        for _ in range(2):  # exhaust the per-actor budget on the ordinary PHI-read route
            assert (await c.get("/messages", headers=h)).status_code == 200
        # Stays a GET on purpose: the property under test is that a step-up GET pays the PHI-read
        # budget even though step-up's own pacing is NON-GET only. A POST would be paced by the
        # admin-write bucket too, and the assertion could no longer tell the two apart.
        throttled = await c.get("/messages/export", headers=h, params={"field_path": "PID-3"})
        assert throttled.status_code == 429
        assert "retry-after" in throttled.headers


async def test_export_throttled_at_admission_writes_no_audit_and_streams_nothing(
    engine: Engine,
) -> None:
    """The charge is at ADMISSION — before selection — so a refused export does no store work and
    cannot leave a ``messages_export`` row claiming bodies that were never streamed."""
    service = AuthService(
        # The PHI-read budget is the subject; the export keeps the window (vault BACKLOG #2625).
        engine.store,
        AuthSettings(
            require_mfa=False, phi_read_rate_limit_per_actor=1, require_action_step_up=False
        ),
    )
    await service.initialize()
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        h = _auth(await _login(c, "op"))
        assert (await c.get("/messages", headers=h)).status_code == 200  # budget spent
        r = await c.get("/messages/export", headers=h, params={"field_path": "PID-3"})
        assert r.status_code == 429
        assert "DOE^JANE" not in r.text  # no body escaped with the refusal
    rows = [dict(x) for x in await engine.store.list_audit(limit=50)]
    assert not [a for a in rows if a["action"] == "messages_export"]


async def test_export_ids_mode_audit_counts_selection(engine: Engine) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    mid_a, mid_b = await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a, mid_b]})
        assert r.status_code == 200, r.text
    export_rows = [
        dict(x) for x in await engine.store.list_audit(limit=50) if x["action"] == "messages_export"
    ]
    parsed = json.loads(export_rows[0]["detail"])
    assert parsed["mode"] == "ids" and parsed["selected"] == 2 and parsed["requested"] == 2


# --- BACKLOG #1184 (ASVS 14.2.1): the PHI needle is off the query string --------------------------


async def test_export_get_no_longer_honours_a_needle_on_the_query_string(engine: Engine) -> None:
    """Export's save-all selection may no longer be driven by a needle typed onto the URL.

    Control in the same test: ``field_path`` on the SAME route still selects the seeded rows, so the
    400 is the needle being gone rather than the route being broken."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        stale = await c.get("/messages/export", headers=_auth(token), params={"content": "JANE"})
        assert stale.status_code == 400, (
            f"a query-string needle still selected an export: {stale.status_code} {stale.text}"
        )
        ok = await c.get("/messages/export", headers=_auth(token), params={"field_path": "PID-3"})
        assert ok.status_code == 200, ok.text
        assert len(_ndjson(ok.text)) == 2  # control: the route works, field_path is kept


async def test_export_takes_the_needle_in_a_post_body(engine: Engine) -> None:
    """POST /messages/export selects by criteria carried in the BODY, and streams the same NDJSON."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.post("/messages/export", headers=_auth(token), json={"content": "JANE"})
        assert r.status_code == 200, r.text
        rows = _ndjson(r.text)
        assert [row["control_id"] for row in rows] == ["MSGA"]
        assert "JANE" not in str(r.request.url), f"the needle rode the URL: {r.request.url}"
        assert b"JANE" in r.request.content  # control: it really was sent, in the body
    audits = [dict(a) for a in await engine.store.list_audit(limit=50)]
    detail = next(a["detail"] for a in audits if a["action"] == "messages_export")
    assert "JANE" not in detail  # the needle value is still never recorded


# --- BACKLOG #1154 (ASVS 8.3.2): the caller is re-resolved before every streamed row ----------


def _after_first_read(
    monkeypatch: pytest.MonkeyPatch, engine: Engine, act: Callable[[], Awaitable[None]]
) -> None:
    """Run ``act`` once, right after the export stream has read its FIRST row.

    ``httpx.ASGITransport`` runs the whole response before it returns, so a change "mid-export"
    has to be made from inside the stream. Wrapping the store read does that at a fixed point:
    row one has been read under the old standing, and row two has not been asked for yet."""
    real = engine.store.get_message
    fired = False

    async def wrapped(message_id: str) -> Any:
        nonlocal fired
        row = await real(message_id)
        if not fired:
            fired = True
            await act()
        return row

    monkeypatch.setattr(engine.store, "get_message", wrapped)


async def _stop_rows(engine: Engine) -> list[dict[str, object]]:
    return [
        json.loads(dict(a)["detail"])
        for a in await engine.store.list_audit(limit=50)
        if dict(a)["action"] == "messages_export.stopped"
    ]


async def test_a_session_revoked_mid_export_stops_the_stream(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A revocation that lands after row one stops the export before row two, and records why.
    Before BACKLOG #1154 the stream tested every row against the identity the gate resolved, so it
    ran to the end of the selection."""
    service = await _service(engine)
    uid = await _add_user(service, "op", [Role.OPERATOR.value])
    mid_a, mid_b = await _seed(engine)

    async def revoke() -> None:
        await service.revoke_sessions_for_user(uid, actor="admin")

    async with _client(engine, service, raise_app_exceptions=False) as c:
        token = await _login(c, "op")
        _after_first_read(monkeypatch, engine, revoke)
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a, mid_b]})
    assert r.status_code == 200  # the response had started; the abort is in the body
    assert [row["id"] for row in _ndjson(r.text)] == [mid_a]
    assert await _stop_rows(engine) == [
        {"selected": 2, "streamed": 1, "reason": "standing_changed"}
    ]


async def test_the_stop_reaches_the_server_as_an_abort(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stop must leave the whole app as a raise. If a middleware swallowed it, the server would
    finish the response cleanly and the client would get a short file that looks complete."""
    service = await _service(engine)
    uid = await _add_user(service, "op", [Role.OPERATOR.value])
    mid_a, mid_b = await _seed(engine)

    async def revoke() -> None:
        await service.revoke_sessions_for_user(uid, actor="admin")

    async with _client(engine, service) as c:
        token = await _login(c, "op")
        _after_first_read(monkeypatch, engine, revoke)
        with pytest.raises(ExportStopped):
            await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a, mid_b]})


async def test_an_export_with_nothing_withdrawn_streams_every_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the same mid-stream hook with a harmless act streams both rows and records no
    stop, so a re-check that refused every caller cannot pass the tests above."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    mid_a, mid_b = await _seed(engine)

    async def nothing() -> None:
        return None

    async with _client(engine, service) as c:
        token = await _login(c, "op")
        _after_first_read(monkeypatch, engine, nothing)
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a, mid_b]})
    assert r.status_code == 200, r.text
    assert [row["id"] for row in _ndjson(r.text)] == [mid_a, mid_b]
    assert await _stop_rows(engine) == []


async def test_a_scope_narrowed_mid_export_skips_the_rows_it_no_longer_covers(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scope is narrowed in the store directly, so no session is revoked and only the per-row
    re-resolution can carry the change: row two, on the channel withdrawn, is skipped and audited."""
    service = await _service(engine)
    uid = await _add_user(service, "op", [Role.OPERATOR.value])
    mid_a, mid_b = await _seed(engine)

    async def narrow() -> None:
        await service.store.set_user_channel_scope(uid, '["IB_A"]', source="manual")

    async with _client(engine, service) as c:
        token = await _login(c, "op")
        _after_first_read(monkeypatch, engine, narrow)
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": [mid_a, mid_b]})
    assert r.status_code == 200, r.text
    assert [row["id"] for row in _ndjson(r.text)] == [mid_a]
    denied = [
        dict(a)["channel_id"]
        for a in await engine.store.list_audit(limit=50)
        if dict(a)["action"] == "auth.channel_denied"
    ]
    assert denied == ["IB_B"]


async def test_an_export_longer_than_the_idle_window_does_not_idle_its_own_session_out(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-row re-check must not turn a long download into an idle session. The idle window is
    shrunk to 0.4 s and each row takes 0.15 s, so six rows outlast it. The export moves the idle
    clock every quarter window, so every row streams and the session stays live afterwards."""
    monkeypatch.setattr(AuthService, "session_idle_seconds", property(lambda _self: 0.4))
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    ids = [
        await engine.store.enqueue_message(
            channel_id="IB_A", raw=ADT_A, deliveries=[], message_type="ADT^A01", control_id=f"M{n}"
        )
        for n in range(6)
    ]
    real = engine.store.get_message

    async def slow(message_id: str) -> Any:
        await asyncio.sleep(0.15)
        return await real(message_id)

    async with _client(engine, service, raise_app_exceptions=False) as c:
        token = await _login(c, "op")
        monkeypatch.setattr(engine.store, "get_message", slow)
        r = await c.get("/messages/export", headers=_auth(token), params={"ids": ids})
    assert r.status_code == 200, r.text
    assert [row["id"] for row in _ndjson(r.text)] == ids
    assert await _stop_rows(engine) == []
    assert await service.identity_for_token(token, activity=False) is not None
