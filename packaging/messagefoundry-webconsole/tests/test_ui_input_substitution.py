# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1744: two /ui routes SUBSTITUTED a value where the JSON twin refuses the input.

``POST /ui/alerts/{id}/suspend`` answered 303 for a window the JSON route 422s, muted 60 minutes
instead, and wrote ``"minutes": 60.0`` into the ``alert_suspend`` audit row as if that had been the
request. ``GET /ui/messages`` DROPPED a received-date bound it could not read, so the page came back
carrying a filter the operator had typed and the engine had not applied.

Both now refuse with 400 and re-render the page with the error, the shape ``routes/search.py`` uses.
Each refusal test is paired with a positive control, so a gate broken to deny everything fails here
rather than passing by lockout.
"""

from __future__ import annotations

import time

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
SFS = {"Sec-Fetch-Site": "same-origin"}

#: 1900-01-01 is BEFORE the epoch and 9999-12-31 is past the 2100-01-01 ceiling, so both fall outside
#: the ``EpochSeconds`` window the JSON ``/messages`` route declares -- the bound this page now shares.
OUT_OF_WINDOW = ("1900-01-01T00:00", "9999-12-31T23:59")


async def _service(engine: Engine) -> AuthService:
    # require_mfa=False for the same reason as the rest of this suite: these tests exercise input
    # validation, and the fixtures never enroll an authenticator.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _provision(service: AuthService, username: str, roles: list[str]) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope DENIES; grant the estate explicitly.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str) -> None:
    r = await c.post("/ui/login", data={"username": username, "password": PW})
    assert r.status_code in (200, 303)


async def _bearer(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    """A native bearer token, so a test can ask the JSON twin the SAME question. The /ui cookie is
    confined to /ui and is rejected on the JSON API, so it cannot stand in for this."""
    token = (await c.post("/auth/login", json={"username": username, "password": PW})).json()[
        "token"
    ]
    return {"Authorization": f"Bearer {token}"}


async def _open_alert(engine: Engine, now: float) -> int:
    await engine.store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="critical", now=now
    )
    rows = await engine.store.list_active_alert_instances()
    assert rows, "the seeded alert instance must be on the active list"
    return rows[0].id


async def _suspend_audit(engine: Engine) -> list[str]:
    return [
        r["detail"] or ""
        for r in await engine.store.list_audit(limit=200)
        if r["action"] == "alert_suspend"
    ]


async def _suspended_until(engine: Engine, alert_id: int) -> float | None:
    row = await engine.store.get_alert_instance(alert_id)
    assert row is not None
    return row.suspended_until


async def _seed_message(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


# --- half one: the alert suspend window --------------------------------------


@pytest.mark.parametrize("minutes", ["999999", "0", "-5", "not-a-number", "nan", "inf"])
async def test_console_suspend_refuses_a_window_the_json_route_refuses(
    engine: Engine, minutes: str
) -> None:
    """400 + the alerts page carrying the error, no mute, no audit row. Pre-fix each of these
    answered 303, muted 60 minutes, and audited ``"minutes": 60.0`` as the request."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    now = time.time()
    alert_id = await _open_alert(engine, now)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await c.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": minutes}, headers=SFS)
        assert r.status_code == 400
        assert "the suspend window must be a number of minutes" in r.text
        # The refusal re-renders the page it came from, rather than 303ing to a success view.
        assert "Alerts" in r.text and "Active" in r.text
        assert await _suspended_until(engine, alert_id) is None  # nothing was muted
        assert await _suspend_audit(engine) == []  # and nothing was recorded as if it had been


async def test_console_suspend_still_mutes_a_valid_window(engine: Engine) -> None:
    """Positive control for the test above: a window inside the model's bounds still suspends, still
    redirects, and audits the minutes the operator actually asked for."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    now = time.time()
    alert_id = await _open_alert(engine, now)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await c.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": "240"}, headers=SFS)
        assert r.status_code == 303 and r.headers["location"] == "/ui/alerts"
        until = await _suspended_until(engine, alert_id)
        assert until is not None and 240 * 60 - 5 < until - now < 240 * 60 + 5
        assert await _suspend_audit(engine) == [f'{{"alert_id": {alert_id}, "minutes": 240.0}}']


async def test_console_suspend_refusal_matches_the_json_route(engine: Engine) -> None:
    """The parity claim, measured on both surfaces in one test: the console 400s exactly where the
    JSON route 422s, and both leave the instance unmuted."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    alert_id = await _open_alert(engine, time.time())
    async with _client(engine, service) as c:
        await _login(c, "op")
        headers = await _bearer(c, "op")
        for value in (999999, 0, -5):
            assert (
                await c.post(
                    f"/alerts/{alert_id}/suspend", json={"minutes": value}, headers=headers
                )
            ).status_code == 422
            console = await c.post(
                f"/ui/alerts/{alert_id}/suspend", data={"minutes": str(value)}, headers=SFS
            )
            assert console.status_code == 400
        assert await _suspended_until(engine, alert_id) is None


async def test_suspend_refusal_omits_the_rules_a_diagnose_only_caller_cannot_read(
    engine: Engine,
) -> None:
    """The refusal re-renders /ui/alerts, whose Rules half is gated on ``monitoring:read`` -- and the
    suspend route holds ``monitoring:diagnose`` only. A custom role holding diagnose WITHOUT read must
    get the refusal without that section, so fixing this route does not widen what it can read."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Alert Suspender",
        description=None,
        permissions=["monitoring:diagnose"],
        actor="test",
    )
    await _provision(service, "diagnoser", [role.id])
    await _provision(service, "op", [Role.OPERATOR.value])
    alert_id = await _open_alert(engine, time.time())
    async with _client(engine, service) as c:
        await _login(c, "diagnoser")
        r = await c.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": "0"}, headers=SFS)
        assert r.status_code == 400
        assert "the suspend window must be a number of minutes" in r.text
        assert ">Rules<" not in r.text
        assert "Re-alert after" not in r.text
    async with _client(engine, service) as c:
        # Positive control on the SAME assertion: an operator holds read, so it does see the section.
        await _login(c, "op")
        r = await c.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": "0"}, headers=SFS)
        assert r.status_code == 400
        assert ">Rules<" in r.text and "Re-alert after" in r.text


# --- half two: the message-log received-date bounds --------------------------


@pytest.mark.parametrize("field", ["received_from", "received_to"])
@pytest.mark.parametrize("value", ["not-a-date", "2026-13-45T99:99", "yesterday"])
async def test_console_messages_refuses_an_unreadable_bound(
    engine: Engine, field: str, value: str
) -> None:
    """400 + the filter form carrying the error and the value the operator typed. Pre-fix this
    answered 200 and searched with the bound DROPPED, so the page showed rows the filter excluded."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    await _seed_message(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await c.get("/ui/messages", params={field: value})
        assert r.status_code == 400
        assert "the received-date bounds must be UTC datetime-local values" in r.text
        assert value in r.text  # echoed back into the form so the operator can correct it
        assert "MSG1" not in r.text  # and NOT searched under a bound that was quietly dropped


@pytest.mark.parametrize("field", ["received_from", "received_to"])
@pytest.mark.parametrize("value", OUT_OF_WINDOW)
async def test_console_messages_refuses_a_bound_outside_the_json_window(
    engine: Engine, field: str, value: str
) -> None:
    """An instant the JSON route would 422 is refused here too, instead of reaching the store query."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    await _seed_message(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await c.get("/ui/messages", params={field: value})
        assert r.status_code == 400
        assert "the received-date bounds must be UTC datetime-local values" in r.text


async def test_out_of_window_bounds_are_the_ones_the_json_route_refuses(engine: Engine) -> None:
    """Pins the pairing above: the two instants are refused by the JSON route as epoch seconds, so the
    console is now enforcing that route's rule rather than a rule of its own invention."""
    from datetime import UTC, datetime

    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        headers = await _bearer(c, "op")
        for value in OUT_OF_WINDOW:
            epoch = datetime.fromisoformat(value).replace(tzinfo=UTC).timestamp()
            r = await c.get("/messages", params={"received_from": epoch}, headers=headers)
            assert r.status_code == 422


async def test_console_messages_refuses_a_bound_carrying_its_own_offset(engine: Engine) -> None:
    """A datetime-local field never sends an offset, so only a hand-built URL gets here -- and the old
    ``replace(tzinfo=UTC)`` re-stamped it as a DIFFERENT instant without saying so."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    await _seed_message(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await c.get("/ui/messages", params={"received_from": "2026-09-16T10:00+05:00"})
        assert r.status_code == 400
        assert "the received-date bounds must be UTC datetime-local values" in r.text


async def test_console_messages_still_filters_on_a_valid_bound(engine: Engine) -> None:
    """Positive control for the three refusals above: a readable, in-window, offset-free bound is still
    APPLIED -- present when the window contains the row, absent when it does not."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    await _seed_message(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        past = await c.get("/ui/messages", params={"received_from": "2020-01-01T00:00"})
        assert past.status_code == 200 and "MSG1" in past.text
        future = await c.get("/ui/messages", params={"received_from": "2099-01-01T00:00"})
        assert future.status_code == 200 and "MSG1" not in future.text
        bounded = await c.get("/ui/messages", params={"received_to": "2020-01-01T00:00"})
        assert bounded.status_code == 200 and "MSG1" not in bounded.text


async def test_deferred_landing_still_renders_its_prefilled_form(engine: Engine) -> None:
    """The ``defer=1`` landing (#4b) fills both bounds server-side and renders the form without
    searching. Validation now runs before that branch, so this pins that the generated values pass."""
    service = await _service(engine)
    await _provision(service, "op", [Role.OPERATOR.value])
    await _seed_message(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await c.get("/ui/messages", params={"defer": "1", "channel_id": "ch1"})
        assert r.status_code == 200
        assert "Adjust the filters and click Search to run." in r.text
        assert "MSG1" not in r.text  # deferred means not run
