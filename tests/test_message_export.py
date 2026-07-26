# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""S7b #124 — bulk raw-message-body export from a search result (ADR 0131).

Covers the LARGEST PHI surface in the cluster: GET /messages/export streaming decrypted bodies to a
file. Verifies the step-up gate, the dedicated messages:export permission (distinct from view_raw),
per-row channel scope on every streamed body, the pre-stream messages_export audit counting every
selected body (needle value never recorded), save-all (search filters) and save-selected (explicit ids),
and the 400 on an empty selection. The route loops get_message per id — NO store schema change.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.permissions import BUILTIN_ROLE_PERMISSIONS
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

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
    eng = Engine(store)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add_user(
    service: AuthService, username: str, roles: list[str], *, scope: list[str] | None = None
) -> str:
    user_id = await service.create_local_user(
        username=username, password=PW, display_name=None, email=None, roles=roles, actor="test"
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
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
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        # Fresh login is within the step-up window → export works.
        ok = await c.get("/messages/export", headers=_auth(token), params={"content": "JANE"})
        assert ok.status_code == 200, ok.text
        # Back-date the step-up window → refused with the step-up signal, before any body streams.
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)
        blocked = await c.get("/messages/export", headers=_auth(token), params={"content": "JANE"})
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"


async def test_export_denied_without_export_permission(engine: Engine) -> None:
    """VIEWER holds neither messages:export nor messages:view_raw → 403."""
    service = await _service(engine)
    await _add_user(service, "view", [Role.VIEWER.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        token = await _login(c, "view")
        r = await c.get("/messages/export", headers=_auth(token), params={"content": "JANE"})
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
        r = await c.get(
            "/messages/export",
            headers=_auth(token),
            params={"content": "ADT", "message_type": "ADT^A01"},
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
        assert PREFIX not in str(raws["MSGA"])


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
        r = await c.get(
            "/messages/export",
            headers=_auth(token),
            params={"content": "9001", "channel_id": "IB_A"},
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
        engine.store, AuthSettings(require_mfa=False, phi_read_rate_limit_per_actor=2)
    )
    await service.initialize()
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        h = _auth(await _login(c, "op"))
        for _ in range(2):  # exhaust the per-actor budget on the ordinary PHI-read route
            assert (await c.get("/messages", headers=h)).status_code == 200
        throttled = await c.get("/messages/export", headers=h, params={"content": "ADT"})
        assert throttled.status_code == 429
        assert "retry-after" in throttled.headers


async def test_export_throttled_at_admission_writes_no_audit_and_streams_nothing(
    engine: Engine,
) -> None:
    """The charge is at ADMISSION — before selection — so a refused export does no store work and
    cannot leave a ``messages_export`` row claiming bodies that were never streamed."""
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, phi_read_rate_limit_per_actor=1)
    )
    await service.initialize()
    await _add_user(service, "op", [Role.OPERATOR.value])
    await _seed(engine)
    async with _client(engine, service) as c:
        h = _auth(await _login(c, "op"))
        assert (await c.get("/messages", headers=h)).status_code == 200  # budget spent
        r = await c.get("/messages/export", headers=h, params={"content": "ADT"})
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
