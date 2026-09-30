# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1743 step 2: the dead-letter replay controls cover every channel, not the drawn page.

``pages.messages.dead_letters`` used to build its per-channel and per-destination replay buttons
from the rows it rendered. A channel whose dead deliveries all sat past the first page had no
button. It now builds them from ``DeadLetterList.replay_targets``, which the engine computes over
the whole filtered dead set inside the caller's channel scope.

Each test drives the real ``/ui/dead-letters`` route and first asserts the CONTROL: the old channel
is absent from the rendered rows. Only then does its button prove anything.

"Replay all dead (every channel)" is global by decision and keeps its every-channel label. It shows
whenever the caller's scope holds a dead delivery, whatever the page filter, and hides only when
the scope holds none.
"""

from __future__ import annotations

import httpx
from _ui_clients import create_local_user_chosen

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

REPLAY_ALL = 'action="/ui/dead-letters/replay-all"'
OLD_CHANNEL = 'action="/ui/dead-letters/IB_OLD/replay"'
OLD_PAIR = 'action="/ui/dead-letters/IB_OLD/OB_OLD/replay"'
NEW_CHANNEL = 'action="/ui/dead-letters/IB_NEW/replay"'


async def _service(
    engine: Engine, channels: list[str], role: Role = Role.ADMINISTRATOR
) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    user_id = await create_local_user_chosen(
        service,
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, channels, actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _login(client: httpx.AsyncClient) -> None:
    r = await client.post("/ui/login", data={"username": "op", "password": PW})
    assert r.status_code in (200, 303), r.text


async def _dead(engine: Engine, channel: str, destination: str, *, now: float) -> None:
    message_id = await engine.store.enqueue_message(
        channel_id=channel,
        raw=ADT,
        deliveries=[(destination, ADT)],
        message_type="ADT^A01",
        source_type="file",
        now=now,
    )
    # Dead-letter only THIS message's delivery, never whatever else is due.
    mine = {row["id"] for row in await engine.store.outbox_for(message_id)}
    for item in await engine.store.claim_ready(now=now):
        if item.id in mine:
            await engine.store.dead_letter_now(item.id, "permanent reject", now=now)


async def _seed(engine: Engine) -> None:
    """One OLD dead delivery on IB_OLD, then three newer ones on IB_NEW, so a one-row page is all
    IB_NEW and IB_OLD is reachable only through the engine's target set."""
    await _dead(engine, "IB_OLD", "OB_OLD", now=10.0)
    for n in range(3):
        await _dead(engine, "IB_NEW", "OB_NEW", now=20.0 + n)


def _rendered_rows_hold(html: str, channel: str) -> bool:
    """Whether a rendered table CELL carries ``channel``. A button's label also names it, so the
    check reads the cells only."""
    return f"<td>{channel}</td>" in html


async def test_a_channel_off_the_rendered_page_still_gets_its_replay_controls(
    engine: Engine,
) -> None:
    await _seed(engine)
    service = await _service(engine, [ALL_CHANNELS])
    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/dead-letters", params={"limit": 1})
        assert r.status_code == 200, r.text
        # CONTROL: the page drew IB_NEW only. The old code would have drawn no IB_OLD button.
        assert _rendered_rows_hold(r.text, "IB_NEW")
        assert not _rendered_rows_hold(r.text, "IB_OLD")

        assert OLD_CHANNEL in r.text and OLD_PAIR in r.text
        assert NEW_CHANNEL in r.text
        assert REPLAY_ALL in r.text and "Replay all dead (every channel)" in r.text


async def test_a_filtered_page_draws_only_the_filtered_channel_but_keeps_replay_all(
    engine: Engine,
) -> None:
    await _seed(engine)
    service = await _service(engine, [ALL_CHANNELS])
    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/dead-letters", params={"channel_id": "IB_NEW"})
        assert r.status_code == 200, r.text
        assert NEW_CHANNEL in r.text
        assert OLD_CHANNEL not in r.text and OLD_PAIR not in r.text
        # Global by decision, with a label that says so.
        assert REPLAY_ALL in r.text and "Replay all dead (every channel)" in r.text

        # A filter matching nothing: no per-channel control, but replay-all still shows because
        # the caller's scope holds dead deliveries elsewhere.
        empty = await c.get("/ui/dead-letters", params={"channel_id": "IB_NONE"})
        assert empty.status_code == 200, empty.text
        assert NEW_CHANNEL not in empty.text and OLD_CHANNEL not in empty.text
        assert REPLAY_ALL in empty.text


async def test_nothing_dead_in_scope_draws_no_replay_control_at_all(engine: Engine) -> None:
    service = await _service(engine, [ALL_CHANNELS])
    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/dead-letters")
        assert r.status_code == 200, r.text
        assert REPLAY_ALL not in r.text
        assert "/ui/dead-letters/" not in r.text.replace(REPLAY_ALL, "")


async def test_a_channel_scoped_caller_gets_controls_for_its_own_channels_only(
    engine: Engine,
) -> None:
    await _seed(engine)
    # An OPERATOR, because the ADMINISTRATOR role is the whole estate whatever its scope row says.
    service = await _service(engine, ["IB_OLD"], Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/dead-letters", params={"limit": 1})
        assert r.status_code == 200, r.text
        assert OLD_CHANNEL in r.text and OLD_PAIR in r.text
        assert NEW_CHANNEL not in r.text, "a control leaked a channel outside the caller's scope"
