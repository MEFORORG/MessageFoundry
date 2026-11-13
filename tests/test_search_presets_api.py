# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Saved / layered Log-Search preset API (BACKLOG #151, ADR 0136).

CRUD + the bounded AND-compose layered query over search_messages. SQLite here; server parity on CI."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response

from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore
from messagefoundry.store.cell_tag import PRESET_TAG_FAILED_ACTION
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    CipherUnavailableError,
    UnauthenticatedCipherError,
    generate_key,
    make_cipher,
)
from tests._admin_account import create_local_user_chosen

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN999^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    e = await Engine.create(
        tmp_path / "p.db", poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield e
    finally:
        await e.stop()


async def _user(engine: Engine, role: Role, name: str) -> AuthService:
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
    )
    await service.initialize()
    uid = await create_local_user_chosen(
        service,
        username=name,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="t",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    return service


async def _login(c: httpx.AsyncClient, name: str) -> dict[str, str]:
    r = await c.post("/auth/login", json={"username": name, "password": PW, "provider": "local"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_preset_crud_and_owner_scoping(engine: Engine) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "op")
    await create_local_user_chosen(
        service,
        username="op2",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="t",
    )
    u2 = await service.store.get_user_by_username("op2")
    assert u2 is not None and u2.password_hash is not None
    await service.store.set_password(
        u2.id, password_hash=u2.password_hash, must_change_password=False, password_generated=False
    )

    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        cr = await c.post(
            "/search/presets",
            json={"name": "acme", "criteria": {"content": "MRN999", "message_type": "ADT^A01"}},
            headers=h,
        )
        assert cr.status_code == 200, cr.text
        assert cr.json()["status"] == "created"
        pid = cr.json()["id"]

        lst = await c.get("/search/presets", headers=h)
        assert lst.status_code == 200 and [p["name"] for p in lst.json()["presets"]] == ["acme"]
        # list carries NO criteria (metadata only)
        assert "criteria" not in lst.json()["presets"][0] and "MRN999" not in lst.text

        # save-by-name replaces
        rep = await c.post(
            "/search/presets",
            json={"name": "acme", "criteria": {"content": "OTHER"}},
            headers=h,
        )
        assert (
            rep.status_code == 200
            and rep.json()["status"] == "replaced"
            and rep.json()["id"] == pid
        )

        # another user cannot see or delete op's preset
        h2 = await _login(c, "op2")
        assert (await c.get("/search/presets", headers=h2)).json()["presets"] == []
        assert (await c.delete(f"/search/presets/{pid}", headers=h2)).status_code == 404

        # op deletes their own
        assert (await c.delete(f"/search/presets/{pid}", headers=h)).status_code == 200
        assert (await c.get("/search/presets", headers=h)).json()["presets"] == []

    # CONTAINMENT ONLY: whatever preset.* rows exist carry the needle SHAPE, never the value.
    # BACKLOG #1643: this comment used to read "create + delete were audited", which this assertion
    # is not evidence for -- it passes with both audit writes deleted, because an empty join
    # contains neither needle. The presence claim lives in
    # test_preset_routes_write_an_audit_row_naming_the_acting_user below, which is the test that
    # reddens when a preset.* record_audit call is removed.
    audits = await engine.store.list_audit()
    detail = " ".join(
        str(a["detail"] or "") for a in audits if str(a["action"]).startswith("preset.")
    )
    assert detail, "nothing decoded -- the containment checks below would be vacuous"
    assert "MRN999" not in detail and "OTHER" not in detail


async def test_preset_routes_write_an_audit_row_naming_the_acting_user(engine: Engine) -> None:
    """BACKLOG #1643: list / create / delete each leave an audit row naming the ACTING user.

    RED when any one of the three ``record_audit`` calls in ``api/app.py`` is deleted, or when one
    stops passing ``actor=identity.username``. That was previously unobservable: no file under
    ``tests/`` or ``packaging/messagefoundry-webconsole/tests/`` named ``preset.create``,
    ``preset.delete`` or ``preset.list`` at all, so deleting the ``preset.create`` write left the
    whole preset suite green.

    The actor is asserted per action rather than over the joined set, so a route that audits under
    the wrong identity -- a fixed string, or another request's user -- fails here too.
    """
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "auditee")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "auditee")
        created = await c.post(
            "/search/presets",
            json={"name": "audited", "criteria": {"content": "MRN999"}},
            headers=h,
        )
        assert created.status_code == 200, created.text
        pid = created.json()["id"]
        assert (await c.get("/search/presets", headers=h)).status_code == 200
        assert (await c.delete(f"/search/presets/{pid}", headers=h)).status_code == 200

    for action in ("preset.create", "preset.list", "preset.delete"):
        rows = await engine.store.list_audit(action=action)
        assert rows, f"{action} left no audit row"
        assert [r["actor"] for r in rows] == ["auditee"], (
            f"{action} must be audited under the acting user"
        )


async def test_layered_compose_and_conflicts(engine: Engine) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    # A message that matches the "MRN999" needle, on channel ch1.
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
    )
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")

        async def mk(name: str, criteria: dict[str, object]) -> str:
            r = await c.post(
                "/search/presets", json={"name": name, "criteria": criteria}, headers=h
            )
            assert r.status_code == 200, r.text
            return r.json()["id"]

        a = await mk(
            "needle", {"content": "MRN999", "message_type": "ADT^A01"}
        )  # needle + metadata
        b = await mk("meta_only", {"message_type": "ADT^A01"})  # metadata only, no needle
        cc = await mk("second_needle", {"content": "MRN999"})  # a 2nd content predicate
        e1 = await mk("chan1", {"channel_id": "ch1"})
        e2 = await mk("chan2", {"channel_id": "ch2"})

        # layer needle + metadata-only → composes and matches the seeded message
        r = await c.get("/search/layered", params={"presets": f"{a},{b}"}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["matched"] == 1

        # two content predicates → 400
        assert (
            await c.get("/search/layered", params={"presets": f"{a},{cc}"}, headers=h)
        ).status_code == 400
        # zero content predicates (only metadata) → 400
        assert (await c.get("/search/layered", params={"presets": b}, headers=h)).status_code == 400
        # conflicting metadata (channel_id ch1 vs ch2) around the needle → 400
        assert (
            await c.get("/search/layered", params={"presets": f"{a},{e1},{e2}"}, headers=h)
        ).status_code == 400
        # unknown preset id → 404
        assert (
            await c.get("/search/layered", params={"presets": "nope"}, headers=h)
        ).status_code == 404

    audits = await engine.store.list_audit()
    layered = [a for a in audits if a["action"] == "preset.layered_search"]
    assert layered and "MRN999" not in " ".join(str(a["detail"] or "") for a in layered)


@pytest.mark.parametrize("stored", ['{"content": "MRN999', "[]", "5"], ids=["bad", "list", "int"])
async def test_malformed_stored_criteria_are_still_a_400(engine: Engine, stored: str) -> None:
    """BACKLOG #2085 moved this decode to ``json_loads_or_refusal`` so its 400 chains nothing. The
    chain itself is not visible over HTTP, and the source gate in
    ``tests/test_from_none_is_not_redaction.py`` pins it; this pins that the refusal is unchanged."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        r = await c.post(
            "/search/presets", json={"name": "n", "criteria": {"content": "MRN999"}}, headers=h
        )
        assert r.status_code == 200, r.text
        pid = r.json()["id"]
        assert isinstance(engine.store, MessageStore)  # a SQLite engine: the raw write needs _db
        await engine.store._db.execute(
            "UPDATE search_presets SET criteria=? WHERE id=?", (stored, pid)
        )
        await engine.store._db.commit()
        r = await c.get("/search/layered", params={"presets": pid}, headers=h)
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == f"preset {pid} has malformed criteria"


def _keep_raised(app: FastAPI) -> list[StarletteHTTPException]:
    """Record each HTTPException ``app`` raises, so a refusal's own chain can be read (#1796)."""
    raised: list[StarletteHTTPException] = []

    async def _keep(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, StarletteHTTPException)
        raised.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(StarletteHTTPException, _keep)
    return raised


def _layered_refusal_log(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The route's refusal records, each holding only text (BACKLOG #5523). An exception object
    among a record's args would carry its traceback, and through it the route frame's decrypted
    criteria, to any handler that keeps records unformatted."""
    records = [
        rec
        for rec in caplog.records
        if rec.name == "messagefoundry.api.app" and rec.getMessage().startswith("layered search")
    ]
    assert records, "the refusal was not logged"
    for rec in records:
        assert rec.exc_info is None and isinstance(rec.args, tuple)
        assert all(isinstance(arg, str) for arg in rec.args), [type(arg) for arg in rec.args]
    return records


async def test_a_preset_planted_in_the_callers_account_answers_423(tmp_path: Path) -> None:
    """BACKLOG #2593: criteria bind their owner. Another account's preset moved into the caller's
    account outside the store is refused on the layered recall with a 423, audited and alerted once,
    never a 500, and it is not stamped as used. The caller's own preset moved away answers the
    usual 404, so the answer never says it exists. Control: an intact preset recalls."""
    import sqlite3

    pytest.importorskip("psutil")
    from messagefoundry.api import create_app
    from messagefoundry.store.cell_tag import CellTagError

    db = tmp_path / "keyed.db"
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    store = await MessageStore.open(db, cipher=cipher)
    keyed = Engine(store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False))
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    try:
        service = await _user(keyed, Role.OPERATOR, "op")
        await _user(keyed, Role.OPERATOR, "op2")
        me = await service.store.get_user_by_username("op")
        them = await service.store.get_user_by_username("op2")
        assert me is not None and them is not None
        app = create_app(keyed, auth=service)
        raised = _keep_raised(app)
        transport = httpx.ASGITransport(app=app)
        alerts: list[tuple[str, str]] = []
        cipher.set_tag_failure_hook(lambda table, reason: alerts.append((table, reason)))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            h, h2 = await _login(c, "op"), await _login(c, "op2")

            async def mk(headers: dict[str, str], name: str) -> str:
                r = await c.post(
                    "/search/presets",
                    json={"name": name, "criteria": {"content": "MRN999"}},
                    headers=headers,
                )
                assert r.status_code == 200, r.text
                return str(r.json()["id"])

            mine = await mk(h, "mine")
            r = await c.get("/search/layered", params={"presets": mine}, headers=h)
            assert r.status_code == 200, r.text  # control: an intact preset recalls

            planted = await mk(h2, "theirs")
            side.execute("UPDATE search_presets SET owner_user_id=? WHERE id=?", (me.id, planted))
            side.commit()
            r = await c.get("/search/layered", params={"presets": planted}, headers=h)
            assert r.status_code == 423, r.text
            # Raised after the handler, so neither the CellTagError nor the cipher's error rides on it.
            refusal = raised[-1]
            assert refusal.status_code == 423
            assert refusal.__context__ is None and refusal.__cause__ is None

            gone = await mk(h, "moved away")
            side.execute("UPDATE search_presets SET owner_user_id=? WHERE id=?", (them.id, gone))
            side.commit()
            r = await c.get("/search/layered", params={"presets": gone}, headers=h)
            assert r.status_code == 404, r.text
        stamped = side.execute(
            "SELECT last_used_at FROM search_presets WHERE id=?", (planted,)
        ).fetchone()
        assert stamped == (None,)  # the refused recall was not recorded as a use
        ref = CellTagError("search_presets", "criteria", planted, None).row_ref
        audited = [
            a
            for a in await store.list_audit(action=PRESET_TAG_FAILED_ACTION)
            if ref in str(a["detail"])
        ]
        assert len(audited) == 1
        assert [t for t, reason in alerts if ref in reason] == ["search_presets"]
    finally:
        side.close()
        await keyed.stop()


@pytest.mark.parametrize("stored", ["", None], ids=["empty", "null"])
async def test_a_blanked_criteria_cell_answers_423_rather_than_widening(
    engine: Engine, stored: str | None
) -> None:
    """BACKLOG #5523: a narrowing preset whose criteria cell is blanked outside the store is refused,
    never read as an empty filter. Read as ``{}``, it dropped out of the compose and the layered
    search matched rows the preset would have excluded. Control: before the blanking, the narrowing
    preset excludes the seeded message."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
    )
    service = await _user(engine, Role.OPERATOR, "op")
    app = create_app(engine, auth=service)
    raised = _keep_raised(app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = await _login(c, "op")
        ids = []
        for name, criteria in (
            ("needle", {"content": "MRN999"}),
            ("narrow", {"channel_id": "ch2"}),
        ):
            r = await c.post(
                "/search/presets", json={"name": name, "criteria": criteria}, headers=h
            )
            assert r.status_code == 200, r.text
            ids.append(r.json()["id"])
        needle, narrow = ids
        layered = {"presets": f"{needle},{narrow}"}
        r = await c.get("/search/layered", params=layered, headers=h)
        assert r.status_code == 200 and r.json()["matched"] == 0, r.text  # control: it narrows
        assert isinstance(engine.store, MessageStore)  # a SQLite engine: the raw write needs _db
        await engine.store._db.execute(
            "UPDATE search_presets SET criteria=? WHERE id=?", (stored, narrow)
        )
        await engine.store._db.commit()
        r = await c.get("/search/layered", params=layered, headers=h)
    assert r.status_code == 423, r.text
    assert (
        r.json()["detail"]
        == f"preset {narrow} has blank criteria, written outside the store, and cannot be used"
    )
    assert raised[-1].__context__ is None and raised[-1].__cause__ is None


async def test_a_planted_unmarked_criteria_cell_is_an_audited_integrity_refusal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5523, then #5650: an unmarked value planted in a keyed store's criteria cell escaped
    as a 500, then answered 423 through the route's plain ``CipherError`` arm, unaudited. Since
    #5650 ``open_tagged_cell`` raises ``UnmarkedCellError`` for it, so it takes the integrity arm:
    a 423 naming no cipher detail, chaining nothing, and the tag-failed audit row. The route's
    plain-refusal ERROR does not fire; the cipher's own refusal is its alert. A blanked cell in the
    same keyed store, which the cipher passes through unopened, is refused too."""

    import sqlite3

    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    db = tmp_path / "keyed.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    keyed = Engine(store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False))
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    try:
        service = await _user(keyed, Role.OPERATOR, "op")
        app = create_app(keyed, auth=service)
        raised = _keep_raised(app)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            h = await _login(c, "op")
            r = await c.post(
                "/search/presets", json={"name": "n", "criteria": {"content": "MRN999"}}, headers=h
            )
            assert r.status_code == 200, r.text
            pid = r.json()["id"]
            side.execute(
                "UPDATE search_presets SET criteria=? WHERE id=?", ('{"content": "MRN999"}', pid)
            )
            side.commit()
            caplog.set_level(logging.WARNING, logger="messagefoundry.api.app")
            r = await c.get("/search/layered", params={"presets": pid}, headers=h)
            assert r.status_code == 423, r.text
            assert r.json()["detail"] == (
                f"preset {pid} failed its integrity check and cannot be used"
            )
            assert "unmarked" not in r.text and "MRN999" not in r.text
            assert raised[-1].__context__ is None and raised[-1].__cause__ is None
            logged = [rec for rec in caplog.records if rec.name == "messagefoundry.api.app"]
            assert not [rec for rec in logged if f"refused preset {pid}: " in rec.getMessage()]
            assert all("MRN999" not in rec.getMessage() for rec in caplog.records)
            audits = await store.list_audit(action=PRESET_TAG_FAILED_ACTION)
            assert len(audits) == 1 and pid[:12] in (audits[0]["detail"] or ""), audits

            side.execute("UPDATE search_presets SET criteria='' WHERE id=?", (pid,))
            side.commit()
            r = await c.get("/search/layered", params={"presets": pid}, headers=h)
        assert r.status_code == 423, r.text
        assert r.json()["detail"].startswith(f"preset {pid} has blank criteria")
    finally:
        side.close()
        await keyed.stop()


async def _layered_with_decrypt_raising(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    exc: CipherError,
) -> tuple[httpx.Response, list[StarletteHTTPException], str]:
    """One layered recall of a fresh preset whose criteria ``decrypt`` raises ``exc``: the
    response, the HTTP exceptions the app raised, and the preset id. Vault Transit's cipher has no
    ``holds_key_for``, so ``open_tagged_cell`` re-raises its errors as they are. The keyless
    store's cipher has none either, so its ``decrypt`` stands in for Transit's, and the error takes
    the store's real path."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "op")
    app = create_app(engine, auth=service)
    raised = _keep_raised(app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = await _login(c, "op")
        r = await c.post(
            "/search/presets", json={"name": "n", "criteria": {"content": "MRN999"}}, headers=h
        )
        assert r.status_code == 200, r.text
        pid = str(r.json()["id"])

        assert isinstance(engine.store, MessageStore)
        cipher = engine.store._cipher
        assert not hasattr(cipher, "holds_key_for")  # else open_tagged_cell reads it as drift

        def _raise(stored: str, **_kw: object) -> str:
            raise exc

        caplog.set_level(logging.WARNING, logger="messagefoundry.api.app")
        with monkeypatch.context() as patched:  # undoes the decrypt patch alone
            patched.setattr(cipher, "decrypt", _raise)
            r = await c.get("/search/layered", params={"presets": pid}, headers=h)
    return r, raised, pid


async def test_a_key_service_outage_on_the_criteria_answers_503_with_retry_after(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5523, after #3734: Vault Transit's outage reaches the route as a
    ``CipherUnavailableError``. It is a 503 with Retry-After, not the 423 that would send an
    operator after a preset that is fine, and not a 500. The outage text stays off the response
    and its chain, and is logged at WARNING, as the upload routes log theirs."""
    from messagefoundry.transports.http_listener import TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS

    outage = CipherUnavailableError("Transit unreachable for key mf-store-secret")
    r, raised, pid = await _layered_with_decrypt_raising(engine, monkeypatch, caplog, outage)
    assert r.status_code == 503, r.text
    assert r.headers["Retry-After"] == str(TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS)
    assert "Transit" not in r.text and "mf-store-secret" not in r.text
    assert raised[-1].__context__ is None and raised[-1].__cause__ is None
    assert "mf-store-secret" not in repr(raised[-1].args)
    assert [(rec.levelno, rec.getMessage()) for rec in _layered_refusal_log(caplog)] == [
        (
            logging.WARNING,
            f"layered search answered 503 on preset {pid}: Transit unreachable for key"
            " mf-store-secret",
        )
    ]


async def test_a_transit_refusal_on_the_criteria_is_logged_at_error(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5523: a Transit refusal that is not the value's AEAD tag, a key-version refusal say,
    stays a plain ``CipherError``, not a ``CellTagError``, so it writes no integrity audit row and
    raises no alert, and its log record is the engine's only record of it. It is a 423, logged at
    ERROR with the type name alone: no exception object, cipher text or criteria. The cipher raises
    the error by hand, so this pins the route's arm, not how ``TransitCipher`` classifies a
    refusal. Transit's AEAD refusal takes the integrity arm (BACKLOG #5650; the next test)."""
    refusal = CipherError("Transit decrypt refused (key='mf-store-secret'): MRN999")
    r, raised, pid = await _layered_with_decrypt_raising(engine, monkeypatch, caplog, refusal)
    assert r.status_code == 423, r.text
    assert "mf-store-secret" not in r.text and "MRN999" not in r.text
    assert r.json()["detail"].startswith(f"preset {pid} cannot be opened with the store's keys")
    assert raised[-1].__context__ is None and raised[-1].__cause__ is None
    assert "mf-store-secret" not in repr(raised[-1].args) and "MRN999" not in repr(raised[-1].args)
    # _layered_refusal_log also checks no record carries exc_info or a non-str arg.
    assert [(rec.levelno, rec.getMessage()) for rec in _layered_refusal_log(caplog)] == [
        (logging.ERROR, f"layered search refused preset {pid}: CipherError")
    ]


async def test_a_transit_tag_refusal_on_the_criteria_is_an_audited_integrity_refusal(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5650: under Vault Transit, a criteria cell planted across owners fails its AEAD tag
    inside Transit, which the cipher now raises as ``UnauthenticatedCipherError``. Before, a cipher
    with no ``holds_key_for`` kept every error as is, so the route answered through its plain arm,
    unaudited and unalerted. Now it is a ``CellTagError``: the integrity 423, chaining nothing, and
    the tag-failed audit row. The decrypt is patched, as above, on a cipher with no
    ``holds_key_for``, which is Transit's shape."""
    refusal = UnauthenticatedCipherError("Transit decrypt failed (key='mf-store-secret'): MRN999")
    # Transit only ever decrypts a marked value; the keyless cipher stands in, so it says so too.
    assert isinstance(engine.store, MessageStore)
    monkeypatch.setattr(engine.store._cipher, "is_encrypted", lambda _stored: True)
    r, raised, pid = await _layered_with_decrypt_raising(engine, monkeypatch, caplog, refusal)
    assert r.status_code == 423, r.text
    assert r.json()["detail"] == f"preset {pid} failed its integrity check and cannot be used"
    assert "mf-store-secret" not in r.text and "MRN999" not in r.text
    assert raised[-1].__context__ is None and raised[-1].__cause__ is None
    assert not [
        rec
        for rec in caplog.records
        if rec.name == "messagefoundry.api.app" and "refused preset" in rec.getMessage()
    ]
    audits = await engine.store.list_audit(action=PRESET_TAG_FAILED_ACTION)
    assert len(audits) == 1 and pid[:12] in (audits[0]["detail"] or ""), audits


async def test_layered_search_feeds_the_summary_access_audit(engine: Engine) -> None:
    """BACKLOG #5523: a layered recall that returns summaries is coalesced into ``summary_access``
    like ``/messages/search`` (review M-5), so it is no way round the harvest signal. Control: a
    recall that returns no row notes nothing, so the audit cannot be amplified by empty reads."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        summary="DOE^JANE",
    )
    service = await _user(engine, Role.OPERATOR, "op")
    app = create_app(engine, auth=service)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = await _login(c, "op")
        ids = []
        for name, needle in (("miss", "NOSUCHNEEDLE"), ("hit", "MRN999")):
            r = await c.post(
                "/search/presets", json={"name": name, "criteria": {"content": needle}}, headers=h
            )
            assert r.status_code == 200, r.text
            ids.append(r.json()["id"])
        miss, hit = ids
        r = await c.get("/search/layered", params={"presets": miss}, headers=h)
        assert r.status_code == 200 and r.json()["matched"] == 0, r.text
        await app.state.summary_auditor.flush(engine.store)
        assert await engine.store.list_audit(action="summary_access") == []  # control
        r = await c.get("/search/layered", params={"presets": hit}, headers=h)
        assert r.status_code == 200 and r.json()["matched"] == 1, r.text
        await app.state.summary_auditor.flush(engine.store)
    rows = await engine.store.list_audit(action="summary_access")
    assert [a["actor"] for a in rows] == ["op"]


async def test_layered_requires_read_permission(engine: Engine) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    # AUDITOR holds neither messages:read nor a preset surface.
    service = await _user(engine, Role.AUDITOR, "aud")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "aud")
        assert (await c.get("/search/presets", headers=h)).status_code == 403
        assert (
            await c.post(
                "/search/presets", json={"name": "x", "criteria": {"content": "y"}}, headers=h
            )
        ).status_code == 403


async def test_a_recreated_username_does_not_inherit_the_departed_operators_presets(
    engine: Engine,
) -> None:
    """BACKLOG #1225: preset ownership binds to the immutable ``Identity.user_id``.

    The existing owner-scoping test compares two operators who are BOTH live, and it passes on the
    defective code -- so it was never evidence about this. The defect needs an account to go away and
    its name to come back, and the enabling half is that ``delete_user`` deletes user_roles, sessions
    and webauthn_credentials but NEVER preset rows, so a departed operator's presets outlive the
    account under a name that is now free to reissue.

    Copies the uploads model (#1152), which abandoned username-keying for exactly this reason.
    """
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "alice")
    app = create_app(engine, auth=service)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "alice")
        created = await c.post(
            "/search/presets",
            json={"name": "mine", "criteria": {"content": "MRN999", "target": "raw"}},
            headers=h,
        )
        assert created.status_code == 200, created.text
        pid = created.json()["id"]
        assert [
            p["name"] for p in (await c.get("/search/presets", headers=h)).json()["presets"]
        ] == ["mine"]

        # alice leaves.
        alice = await service.store.get_user_by_username("alice")
        assert alice is not None
        assert isinstance(engine.store, MessageStore)  # a SQLite engine: the raw reads need _db
        # Capture the row FIRST. BACKLOG #1233 makes delete_user purge it, and this test needs it
        # back afterwards -- see the two-controls note below.
        raw = await engine.store._db.execute(
            "SELECT * FROM search_presets WHERE owner_user_id=?", (alice.id,)
        )
        captured = [dict(r) for r in await raw.fetchall()]
        assert captured, "precondition: alice's preset exists before she is deleted"

        await service.store.delete_user(alice.id)

        # BACKLOG #1233: delete_user now PURGES preset rows. This assertion replaces a precondition
        # that asserted the exact opposite -- "delete_user does not purge preset rows" -- which was
        # true when written and is the defect #1233 fixes. Retraction recorded rather than the old
        # line quietly deleted.
        assert not await engine.store.list_search_presets(alice.id)
        assert not await engine.store.list_search_presets("alice")

        # TWO INDEPENDENT CONTROLS, AND #1233 WOULD OTHERWISE RETIRE THE OTHER ONE'S ONLY TEST.
        # #1233 purges the row; #1225 keys it to an id that cannot be reissued. With the row purged,
        # the assertions below would pass TRIVIALLY -- nothing to inherit -- and would stop being
        # evidence about the KEY at all. So the captured row is put back, which is not artificial:
        # it is exactly the state of a database upgraded from before #1233, where orphan rows already
        # exist and only the key protects them.
        for row in captured:
            cols = ", ".join(row)
            marks = ", ".join("?" for _ in row)
            await engine.store._db.execute(
                f"INSERT INTO search_presets ({cols}) VALUES ({marks})", tuple(row.values())
            )
        await engine.store._db.commit()
        assert await engine.store.list_search_presets(alice.id), (
            "the orphan row is restored, so what follows tests the KEY and not the purge"
        )

        # A NEW person is given the freed username.
        new_id = await create_local_user_chosen(
            service,
            username="alice",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="t",
        )
        # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
        # fixture still stands for an operator who has been provisioned; the channel axis itself
        # is exercised in tests/test_channel_rbac.py.
        await service.set_channel_scope(new_id, [ALL_CHANNELS], actor="test")
        fresh = await service.store.get_user(new_id)
        assert fresh is not None and fresh.password_hash is not None
        await service.store.set_password(
            new_id,
            password_hash=fresh.password_hash,
            must_change_password=False,
            password_generated=False,
        )
        assert new_id != alice.id, "same name, different principal -- that is the whole point"

        h2 = await _login(c, "alice")
        assert (await c.get("/search/presets", headers=h2)).json()["presets"] == [], (
            "the recycled account must not inherit the departed operator's saved searches"
        )
        assert (await c.delete(f"/search/presets/{pid}", headers=h2)).status_code == 404
        # ...and the layered compose, which is the route that returns the PHI-shaped criteria.
        layered = await c.get("/search/layered", params={"presets": pid}, headers=h2)
        assert layered.status_code == 404, layered.text


async def test_a_lone_field_value_is_refused_not_saved_unread(engine: Engine) -> None:
    """BACKLOG #6700: create_search_preset ran make_spec only beside content or field_path, so a
    criteria holding only field_value was saved and never applied. Control: beside a field path it
    saves, and an all-whitespace content beside a field path audits as a field-path needle."""
    pytest.importorskip("psutil")
    import json

    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        lone = await c.post(
            "/search/presets", json={"name": "n", "criteria": {"field_value": "MRN999"}}, headers=h
        )
        assert lone.status_code == 400, lone.text
        assert "field_value needs an HL7 field path" in lone.json()["detail"]
        ok = await c.post(
            "/search/presets",
            json={
                "name": "p",
                "criteria": {"content": "   ", "field_path": "PID-3", "field_value": "MRN999"},
            },
            headers=h,
        )
        assert ok.status_code == 200, ok.text
        # A blank field_value is not a needle: a metadata-only preset still saves.
        meta_only = await c.post(
            "/search/presets",
            json={"name": "m", "criteria": {"channel_id": "IB_A", "field_value": "   "}},
            headers=h,
        )
        assert meta_only.status_code == 200, meta_only.text
        # A content of only spaces is refused, as on origin/main, not saved as a needle never applied.
        spaces = await c.post(
            "/search/presets", json={"name": "s", "criteria": {"content": "   "}}, headers=h
        )
        assert spaces.status_code == 400, spaces.text
        # A stored lone field_value (saved before the refusal existed) is refused on the layered
        # read rather than dropped by the compose.
        pid = meta_only.json()["id"]
        assert isinstance(engine.store, MessageStore)  # a SQLite engine: the raw write needs _db
        await engine.store._db.execute(
            "UPDATE search_presets SET criteria=? WHERE id=?",
            (json.dumps({"field_value": "MRN999"}), pid),
        )
        await engine.store._db.commit()
        r = await c.get("/search/layered", params={"presets": pid}, headers=h)
        assert r.status_code == 400, r.text
        assert "field_value needs an HL7 field path" in r.json()["detail"]
    rows = await engine.store.list_audit(action="preset.create")
    shapes = sorted(json.loads(r["detail"])["needle_shape"] or "" for r in rows)
    assert shapes == ["", "field_path"]


async def test_a_non_str_stored_field_value_beside_the_needle_is_not_a_500(engine: Engine) -> None:
    """The compose reads every preset's field_value to find a lone one (BACKLOG #6700). A stored
    non-str field_value on a preset that is NOT the needle was never read on origin/main, so it must
    not become a 500 now. Control: the same layering with an intact second preset also answers 200."""
    pytest.importorskip("psutil")
    import json

    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ids = []
        for name, criteria in (("a", {"content": "MRN999"}), ("b", {"channel_id": "ch1"})):
            r = await c.post(
                "/search/presets", json={"name": name, "criteria": criteria}, headers=h
            )
            assert r.status_code == 200, r.text
            ids.append(r.json()["id"])
        control = await c.get("/search/layered", params={"presets": ",".join(ids)}, headers=h)
        assert control.status_code == 200, control.text
        assert isinstance(engine.store, MessageStore)  # a SQLite engine: the raw write needs _db
        await engine.store._db.execute(
            "UPDATE search_presets SET criteria=? WHERE id=?",
            (json.dumps({"channel_id": "ch1", "field_value": 5}), ids[1]),
        )
        await engine.store._db.commit()
        r = await c.get("/search/layered", params={"presets": ",".join(ids)}, headers=h)
        assert r.status_code == 200, r.text
        # On the NEEDLE preset the same malformed field_value is read by make_spec, which refuses a
        # non-text needle value: a 400, never an AttributeError's 500.
        await engine.store._db.execute(
            "UPDATE search_presets SET criteria=? WHERE id=?",
            (json.dumps({"content": "MRN999", "field_value": 5}), ids[0]),
        )
        await engine.store._db.commit()
        r = await c.get("/search/layered", params={"presets": ",".join(ids)}, headers=h)
        assert r.status_code == 400, r.text
        assert "field_value must be text" in r.json()["detail"]


async def test_a_blank_stored_content_on_a_non_needle_preset_is_not_a_second_needle(
    engine: Engine,
) -> None:
    """The compose counts needles on stripped values, as on origin/main: a stored content of only
    spaces beside a channel filter is not a second content predicate, so the layered search runs
    the other preset's DOE search inside IB_A (BACKLOG #6700)."""
    pytest.importorskip("psutil")
    import json

    from messagefoundry.api import create_app

    await engine.store.enqueue_message(
        channel_id="IB_A", raw=ADT, deliveries=[("o", ADT)], control_id="MSG1"
    )
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ids = []
        for name, criteria in (("doe", {"content": "DOE"}), ("ch", {"channel_id": "IB_A"})):
            r = await c.post(
                "/search/presets", json={"name": name, "criteria": criteria}, headers=h
            )
            assert r.status_code == 200, r.text
            ids.append(r.json()["id"])
        assert isinstance(engine.store, MessageStore)  # a SQLite engine: the raw write needs _db
        await engine.store._db.execute(
            "UPDATE search_presets SET criteria=? WHERE id=?",
            (json.dumps({"content": "   ", "channel_id": "IB_A"}), ids[1]),
        )
        await engine.store._db.commit()
        r = await c.get("/search/layered", params={"presets": ",".join(ids)}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["matched"] == 1
