# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""/ui saved / layered search-preset smoke tests (BACKLOG #151, ADR 0136)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN999^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    e = await Engine.create(tmp_path / "pu.db", poll_interval=0.02)
    try:
        yield e
    finally:
        await e.stop()


async def _op(engine: Engine, *, per_actor: int = 120) -> AuthService:
    # per_actor mirrors AuthSettings' default (120); pass a smaller value to exercise the per-actor
    # PHI-read budget in a single test (see test_webui.py:616 test_edit_editor_charges_the_phi_read_budget).
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, phi_read_rate_limit_per_actor=per_actor)
    )
    await service.initialize()
    uid = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="t",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return service


async def test_preset_save_and_layer_ui(engine: Engine) -> None:
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
    )
    service = await _op(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})

        # search page renders the (empty) presets section
        r = await c.get("/ui/messages/search")
        assert r.status_code == 200 and "Saved presets" in r.text

        # save a preset from the current search state
        s = await c.post(
            "/ui/messages/search/presets",
            data={"name": "acme", "content": "MRN999", "message_type": "ADT^A01"},
        )
        assert s.status_code in (200, 303), s.text

        # it now appears on the search page
        r = await c.get("/ui/messages/search")
        assert "acme" in r.text
        # find its id from the delete form action
        marker = "/ui/messages/search/presets/"
        pid = r.text.split(marker, 1)[1].split("/delete", 1)[0]

        # run a layered search over it → matches the seeded message
        lay = await c.get("/ui/messages/search/layered", params={"presets": pid})
        assert lay.status_code == 200, lay.text
        assert "match(es)" in lay.text

        # delete it
        d = await c.post(f"/ui/messages/search/presets/{pid}/delete")
        assert d.status_code in (200, 303)
        r = await c.get("/ui/messages/search")
        assert "acme" not in r.text


async def test_search_message_search_charges_the_phi_read_budget(engine: Engine) -> None:
    # BACKLOG #1025: GET /ui/messages/search's SHORT-CIRCUIT path. A criteria-bearing search already
    # charges the budget inside core.search_messages, but the bare-form render (no criteria) returns
    # before that handler runs. The route charges enforce_phi_read_pacing INLINE on that branch, so
    # even the bare-form 200 spends a token; a second one over budget 429s. Without the fix a deploying
    # instance would leave this bare-form render path outside the per-actor read budget.
    service = await _op(engine, per_actor=1)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        first = await c.get("/ui/messages/search")
        assert first.status_code == 200, first.text  # bare-form render still charges token 1
        second = await c.get("/ui/messages/search")
        assert second.status_code == 429
        assert second.headers["Retry-After"]


async def test_search_layered_charges_the_phi_read_budget(engine: Engine) -> None:
    # BACKLOG #1025: GET /ui/messages/search/layered's SHORT-CIRCUIT path. A composed run already
    # charges inside core.layered_search, but the no-presets 400 re-render returns before that handler
    # runs. The route charges enforce_phi_read_pacing INLINE on that branch, so the second over-budget
    # request 429s rather than 400ing again. Without the fix a deploying instance would leave this
    # no-presets render path outside the read budget.
    service = await _op(engine, per_actor=1)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        first = await c.get("/ui/messages/search/layered")
        assert first.status_code == 400, first.text  # no-presets re-render, token 1 already spent
        second = await c.get("/ui/messages/search/layered")
        assert second.status_code == 429
        assert second.headers["Retry-After"]


async def test_search_message_search_criteria_charges_once(engine: Engine) -> None:
    # BACKLOG #1025 DOUBLE-CHARGE guard (the regression the earlier gate-level phi= introduced): a
    # REAL, criteria-bearing search already charges the per-actor read budget exactly once inside
    # core.search_messages (its body calls enforce_phi_read_pacing). The console must NOT charge it a
    # second time. At per_actor=1 the single criteria search spends its one token and returns 200; a
    # gate-level phi= on require_ui_step_up would spend a second token and 429 the FIRST real search
    # before it runs. Synthetic needle only (matches nothing in an empty store -> 200, empty results).
    service = await _op(engine, per_actor=1)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        r = await c.get("/ui/messages/search", params={"content": "MRN999"})
        # charged once by the handler, not twice by gate+handler
        assert r.status_code == 200, r.text


async def test_search_layered_criteria_charges_once(engine: Engine) -> None:
    # BACKLOG #1025 DOUBLE-CHARGE guard for the layered route: a composed run over a real preset
    # charges once inside core.layered_search. per_actor=2 budgets exactly: the bare-form render that
    # extracts the preset id spends token 1 (its inline short-circuit charge) and the composed run
    # spends token 2 -> 200. A gate-level phi= would make the composed run spend token 2 AND token 3
    # (gate + handler), overrunning the budget and 429ing it. Synthetic HL7 only (reuses ADT/MRN999).
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
    )
    service = await _op(engine, per_actor=2)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        s = await c.post(
            "/ui/messages/search/presets",
            data={"name": "acme", "content": "MRN999", "message_type": "ADT^A01"},
        )
        assert s.status_code in (200, 303), s.text  # preset save is not phi-paced (no token)
        r = await c.get("/ui/messages/search")  # bare-form render: spends token 1, carries the id
        marker = "/ui/messages/search/presets/"
        pid = r.text.split(marker, 1)[1].split("/delete", 1)[0]
        lay = await c.get("/ui/messages/search/layered", params={"presets": pid})
        # composed run charges token 2 only -> within budget
        assert lay.status_code == 200, lay.text
        assert "match(es)" in lay.text
