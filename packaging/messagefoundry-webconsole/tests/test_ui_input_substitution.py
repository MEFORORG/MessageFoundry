# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1744: two /ui routes SUBSTITUTED a value where the JSON twin refuses the input.

``POST /ui/alerts/{id}/suspend`` answered 303 for a window the JSON route 422s, muted 60 minutes
instead, and wrote ``"minutes": 60.0`` into the ``alert_suspend`` audit row as if that had been the
request. ``GET /ui/messages`` DROPPED a received-date bound it could not read, so the page came back
carrying a filter the operator had typed and the engine had not applied.

Both now refuse with 400 and re-render the page with the error, the shape ``routes/search.py`` uses.
Each refusal test is paired with a positive control, so a gate broken to deny everything fails here
rather than passing by lockout. Two tests assert EQUIVALENCE WITH THE TWIN rather than the console's
behaviour alone -- that is the seam written as an executable claim, so a future drift between the two
surfaces fails a test instead of going unnoticed.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from _ui_clients import (
    SAME_ORIGIN as SFS,
)
from _ui_clients import (
    auth_service,
    bearer,
    cookie_login,
    provision,
    seed_message,
    ui_client,
)

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine

SUSPEND_REFUSAL = "the suspend window must be a positive number of minutes"
BOUND_REFUSAL = "the received-date bounds must be UTC datetime-local values"

#: 1900-01-01 is BEFORE the epoch and 9999-12-31 is past the 2100-01-01 ceiling, so both fall outside
#: the ``EpochSeconds`` window the JSON ``/messages`` route declares -- the bound this page now shares.
OUT_OF_WINDOW = ("1900-01-01T00:00", "9999-12-31T23:59")

#: Every received-date bound the console must refuse, in one list because the refusal is identical for
#: all of them: unreadable, outside that window, and carrying its own UTC offset (which the pre-fix
#: ``replace(tzinfo=UTC)`` re-stamped as a DIFFERENT instant -- reachable only from a hand-built URL,
#: since a ``datetime-local`` field never sends an offset).
REFUSED_BOUNDS = (
    "not-a-date",
    "2026-13-45T99:99",
    "yesterday",
    *OUT_OF_WINDOW,
    "2026-09-16T10:00+05:00",
)


@pytest.fixture
async def op(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    """A browser client already signed in as an OPERATOR -- the setup ~10 of these tests share. The
    custom-role test builds its own client instead, because its whole point is a different role."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        yield c


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


# --- half one: the alert suspend window --------------------------------------


@pytest.mark.parametrize("minutes", ["999999", "0", "-5", "not-a-number", "nan", "inf"])
async def test_console_suspend_refuses_a_window_the_json_route_refuses(
    engine: Engine, op: httpx.AsyncClient, minutes: str
) -> None:
    """400 + the alerts page carrying the error, no mute, no audit row. Pre-fix each of these
    answered 303, muted 60 minutes, and audited ``"minutes": 60.0`` as the request."""
    now = time.time()
    alert_id = await _open_alert(engine, now)
    r = await op.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": minutes}, headers=SFS)
    assert r.status_code == 400
    assert SUSPEND_REFUSAL in r.text
    # The refusal re-renders the page it came from, rather than 303ing to a success view.
    assert "Alerts" in r.text and "Active" in r.text
    assert await _suspended_until(engine, alert_id) is None  # nothing was muted
    assert await _suspend_audit(engine) == []  # and nothing was recorded as if it had been


async def test_console_suspend_still_mutes_a_valid_window(
    engine: Engine, op: httpx.AsyncClient
) -> None:
    """Positive control for the test above: a window inside the model's bounds still suspends, still
    redirects, and audits the minutes the operator actually asked for."""
    now = time.time()
    alert_id = await _open_alert(engine, now)
    r = await op.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": "240"}, headers=SFS)
    assert r.status_code == 303 and r.headers["location"] == "/ui/alerts"
    until = await _suspended_until(engine, alert_id)
    assert until is not None and 240 * 60 - 5 < until - now < 240 * 60 + 5
    assert await _suspend_audit(engine) == [f'{{"alert_id": {alert_id}, "minutes": 240.0}}']


async def test_console_suspend_refusal_matches_the_json_route(
    engine: Engine, op: httpx.AsyncClient
) -> None:
    """The parity claim, measured on both surfaces against the SAME input: the console 400s exactly
    where the JSON route 422s, and neither mutes the instance."""
    alert_id = await _open_alert(engine, time.time())
    headers = await bearer(op, "op")
    for value in (999999, 0, -5):
        json_twin = await op.post(
            f"/alerts/{alert_id}/suspend", json={"minutes": value}, headers=headers
        )
        console = await op.post(
            f"/ui/alerts/{alert_id}/suspend", data={"minutes": str(value)}, headers=SFS
        )
        assert (json_twin.status_code, console.status_code) == (422, 400)
    assert await _suspended_until(engine, alert_id) is None


async def test_suspend_refusal_omits_the_rules_a_diagnose_only_caller_cannot_read(
    engine: Engine,
) -> None:
    """The refusal re-renders /ui/alerts, whose Rules half is gated on ``monitoring:read`` -- and the
    suspend route holds ``monitoring:diagnose`` only. A custom role holding diagnose WITHOUT read must
    get the refusal without that section, so fixing this route does not widen what it can read."""
    service = await auth_service(engine)
    role = await service.create_custom_role(
        display_name="Alert Suspender",
        description=None,
        permissions=["monitoring:diagnose"],
        actor="test",
    )
    await provision(service, "diagnoser", [role.id])
    await provision(service, "reader", [Role.OPERATOR.value])
    alert_id = await _open_alert(engine, time.time())
    async with ui_client(engine, service) as c:
        await cookie_login(c, "diagnoser")
        r = await c.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": "0"}, headers=SFS)
        assert r.status_code == 400 and SUSPEND_REFUSAL in r.text
        assert ">Rules<" not in r.text
        assert "Re-alert after" not in r.text
    async with ui_client(engine, service) as c:
        # Positive control on the SAME assertion: an operator holds read, so it does see the section.
        await cookie_login(c, "reader")
        r = await c.post(f"/ui/alerts/{alert_id}/suspend", data={"minutes": "0"}, headers=SFS)
        assert r.status_code == 400
        assert ">Rules<" in r.text and "Re-alert after" in r.text


# --- half two: the message-log received-date bounds --------------------------


@pytest.mark.parametrize("field", ["received_from", "received_to"])
@pytest.mark.parametrize("value", REFUSED_BOUNDS)
async def test_console_messages_refuses_a_bound_the_engine_would_not_apply(
    engine: Engine, op: httpx.AsyncClient, field: str, value: str
) -> None:
    """400 + the filter form carrying the error and the value the operator typed. Pre-fix an unreadable
    bound answered 200 with the filter DROPPED, so the page showed rows that filter excluded, and an
    out-of-window or offset-bearing one reached the store query as an instant nobody asked for."""
    await seed_message(engine)
    r = await op.get("/ui/messages", params={field: value})
    assert r.status_code == 400
    assert BOUND_REFUSAL in r.text
    assert value in r.text  # echoed back into the form so the operator can correct it
    assert "MSG1" not in r.text  # and NOT searched under a bound that was quietly dropped


async def test_out_of_window_bounds_are_the_ones_the_json_route_refuses(
    engine: Engine, op: httpx.AsyncClient
) -> None:
    """Pins the pairing above: the two instants are refused by the JSON route as epoch seconds, so the
    console is now enforcing that route's rule rather than a rule of its own invention."""
    headers = await bearer(op, "op")
    for value in OUT_OF_WINDOW:
        epoch = datetime.fromisoformat(value).replace(tzinfo=UTC).timestamp()
        r = await op.get("/messages", params={"received_from": epoch}, headers=headers)
        assert r.status_code == 422


async def test_console_messages_still_filters_on_a_valid_bound(
    engine: Engine, op: httpx.AsyncClient
) -> None:
    """Positive control for the refusals above: a readable, in-window, offset-free bound is still
    APPLIED -- present when the window contains the row, absent when it does not."""
    await seed_message(engine)
    past = await op.get("/ui/messages", params={"received_from": "2020-01-01T00:00"})
    assert past.status_code == 200 and "MSG1" in past.text
    future = await op.get("/ui/messages", params={"received_from": "2099-01-01T00:00"})
    assert future.status_code == 200 and "MSG1" not in future.text
    bounded = await op.get("/ui/messages", params={"received_to": "2020-01-01T00:00"})
    assert bounded.status_code == 200 and "MSG1" not in bounded.text


async def test_deferred_landing_still_renders_its_prefilled_form(
    engine: Engine, op: httpx.AsyncClient
) -> None:
    """The ``defer=1`` landing (#4b) fills both bounds server-side and renders the form without
    searching. Validation now runs before that branch, so this pins that the generated values pass."""
    await seed_message(engine)
    r = await op.get("/ui/messages", params={"defer": "1", "channel_id": "ch1"})
    assert r.status_code == 200
    assert "Adjust the filters and click Search to run." in r.text
    assert "MSG1" not in r.text  # deferred means not run
