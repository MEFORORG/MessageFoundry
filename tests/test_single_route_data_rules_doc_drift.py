# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1151 -- the single-route data rules, executed and documented.

``docs/SECURITY.md`` carries a blockquote headed *Single-route data rules*. It states at least
thirteen data rules that each sit on one route, or one family of routes, and that the route rows
themselves only point to. This file keeps that blockquote true in the same two halves as
``tests/test_monitoring_scope_doc_drift.py``, on the same seeded estate (inbounds ``IB_A`` and
``IB_B``, shared outbound ``OB_X``):

* one measurement per rule EXECUTES the route against a channel-scoped operator, with an
  all-channels operator in the same run as the positive control. The security-event feed has no
  channel axis: it is keyed on the caller's own account, and its control is the raw audit log. The
  approval release narrows its REQUESTER's scope, and its control is a release that runs. The
  suspend refusal page's rules gate is a permission fact, and its control is a ``monitoring:read``
  holder;
* :func:`test_security_doc_states_each_single_route_rule` reads the blockquote and requires each
  rule's routes and key facts in that rule's own bullet, every bullet to belong to a rule, and each
  route's row in the route map to point at the blockquote.

``_RULES`` is the one list both halves read. So a bullet cannot name a route that no measurement
executes, and a measured rule cannot drop out of the doc without a red.

WHAT THIS DOES NOT DO. It is not a census of the data rules the code enforces: a rule nobody has
documented is invisible to it. A bullet's facts are checked by presence and by a short list of
forbidden contradictions, not parsed, and a measurement covers the facts it names, not every clause
of the bullet. The console paragraph of the blockquote is read from the code and not executed.
"""

from __future__ import annotations

import contextlib
import functools
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import (
    STEP_UP_ACTION_CONNECTION_PURGE,
    STEP_UP_ACTION_MESSAGE_EXPORT,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import no_audit_row
from tests._doc_blockquote import blockquote_lines, plant_in_blockquote, route_tokens, unwrap
from tests.test_approvals import ON, _add, _token
from tests.test_approvals import _client as _approvals_client

# The shared fixture and helpers, imported rather than copied, as
# tests/test_route_channel_scope_classification.py does.
from tests.test_monitoring_scope_doc_drift import (  # noqa: F401
    PW,
    _login,
    _operator,
    engine,
)
from tests.test_route_channel_scope_classification import (
    ADMINISTRATOR_ONLY,
    NOT_CHANNEL_BEARING,
    ROUTES,
    SCOPED,
)

_DOC = Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md"

#: The blockquote's bold open. Pinned to the name, not to the punctuation after it.
_MARKER = "**Single-route data rules"

#: What every route row of a rule must carry, so a reader of the route map finds the rule.
_ROW_POINTER = "*Single-route data rules*"


# =====================================================================================================
# The measurement -- executed against a live app, scoped caller vs all-channels positive control
# =====================================================================================================


@dataclass
class _Callers:
    """A channel-scoped operator (``IB_A`` only) and an all-channels operator, both logged in."""

    engine: Engine
    c: httpx.AsyncClient
    scoped: dict[str, str]
    wide: dict[str, str]
    monkeypatch: pytest.MonkeyPatch
    service: AuthService
    scoped_id: str
    wide_id: str

    async def denials(self) -> int:
        rows = await self.engine.store.list_audit(
            action="auth.channel_denied", actor="scoped", limit=500
        )
        return len(rows)

    def prove(self, headers: dict[str, str], action: str) -> None:
        """Mint the single-use step-up proof an action-bound route spends. These measurements are
        about scope, so the proof is granted directly, as the classification probe does."""
        self.service._grant_action_step_up(
            hash_token(headers["Authorization"].removeprefix("Bearer ")), action
        )

    def quiesce_outbounds(self) -> None:
        """Make every outbound read as stopped and drained, the purge precondition. The fixture never
        starts the engine; the rule under test is the scope check, not the lane state."""
        rr = self.engine.registry_runner
        assert rr is not None
        self.monkeypatch.setattr(rr, "outbound_quiesced", lambda name: True)

    async def message_ids(self) -> dict[str, str]:
        """``{channel_id: message_id}`` for the fixture's one message per inbound."""
        r = await self.c.get("/messages", headers=self.wide)
        assert r.status_code == 200, r.text
        return {m["channel_id"]: m["id"] for m in r.json()["messages"]}


async def _measure_layered_search_owner(k: _Callers) -> None:
    async def preset(headers: dict[str, str]) -> str:
        r = await k.c.post(
            "/search/presets", json={"name": "p", "criteria": {"content": "MSG1"}}, headers=headers
        )
        assert r.status_code == 200, r.text
        return str(r.json()["id"])

    mine, theirs = await preset(k.scoped), await preset(k.wide)
    own = await k.c.get("/search/layered", params={"presets": mine}, headers=k.scoped)
    # The owner's run is narrowed to its channel scope: one of the two seeded messages...
    assert own.status_code == 200 and own.json()["matched"] == 1, own.text
    # ...where the same criteria in the wide caller's own preset match both.
    wide = await k.c.get("/search/layered", params={"presets": theirs}, headers=k.wide)
    assert wide.status_code == 200 and wide.json()["matched"] == 2, wide.text
    # Another user's preset answers 404, and so does an id that exists nowhere.
    for pid in (mine, "nope"):
        r = await k.c.get("/search/layered", params={"presets": pid}, headers=k.wide)
        assert r.status_code == 404, (pid, r.text)


async def _measure_statistics_reset(k: _Callers) -> None:
    before = await k.denials()
    everything = await k.c.post("/statistics/reset", json={"all": True}, headers=k.scoped)
    assert everything.status_code == 403, everything.text
    in_scope = {"role": "source", "channel_id": "IB_A"}
    mixed = await k.c.post(
        "/statistics/reset",
        json={"targets": [in_scope, {"role": "source", "channel_id": "IB_B"}]},
        headers=k.scoped,
    )
    assert mixed.status_code == 403, mixed.text
    assert await k.denials() == before + 2
    # The refused batch reset nothing, not even its in-scope target. The baselines are what a reset
    # moves, so they are read directly rather than inferred from the audit trail.
    eng = k.engine
    assert eng._inbound_stat_offsets == {} and eng._outbound_stat_offsets == {}
    edge = {"role": "destination", "channel_id": "IB_A", "destination": "OB_X"}
    for target in (in_scope, edge):
        r = await k.c.post("/statistics/reset", json={"targets": [target]}, headers=k.scoped)
        assert r.status_code == 200 and r.json()["reset"] == 1, (target, r.text)
    # The edge reset moved IB_A's edge into OB_X and no other inbound's edge into it.
    assert set(eng._inbound_stat_offsets) == {"IB_A"}
    assert set(eng._outbound_stat_offsets) == {("IB_A", "OB_X")}
    # Control: the all-channels caller may reset everything.
    wide = await k.c.post("/statistics/reset", json={"all": True}, headers=k.wide)
    assert wide.status_code == 200, wide.text


async def _measure_status_per_field(k: _Callers) -> None:
    rr = k.engine.registry_runner
    assert rr is not None
    # Both inbounds report a start failure. This stands in for ADR 0031's bind failure, which needs
    # a started engine; the rule under test is the narrowing in the handler, not the detection.
    k.monkeypatch.setattr(rr, "inbound_failed", lambda name: "bind failed")
    scoped_body = (await k.c.get("/status", headers=k.scoped)).json()
    wide_body = (await k.c.get("/status", headers=k.wide)).json()
    scoped, wide = scoped_body["engine"], wide_body["engine"]
    assert sorted(wide["channels_failed_names"]) == ["IB_A", "IB_B"]
    assert scoped["channels_failed_names"] == ["IB_A"]
    for field in ("channels_failed", "channels_total", "outbox_by_status"):
        assert scoped[field] == wide[field], f"{field} is estate-wide"
    assert scoped["channels_failed"] == 2
    # messages_per_second is a live rate and could tick between the two reads; the counts cannot.
    for field in ("messages_total", "connections_total", "connections_running"):
        assert scoped_body["kpis"][field] == wide_body["kpis"][field], f"kpis.{field}"
    for field in ("messages", "events"):
        assert scoped_body["db"][field] == wide_body["db"][field], f"db.{field}"
    assert wide_body["db"]["messages"] == 2


async def _measure_alert_writes(k: _Callers) -> None:
    # The shared fixture holds one open alert per connection.
    ids = {
        a.connection: a.id
        for a in await k.engine.store.list_active_alert_instances(allowed_channels=None)
    }
    writes: tuple[tuple[str, dict[str, float] | None], ...] = (
        ("ack", None),
        ("suspend", {"minutes": 5.0}),
        ("resume", None),
        ("resolve", None),
    )
    store = k.engine.store

    async def states() -> list[object]:
        return [await store.get_alert_instance(i, allowed_channels=None) for i in ids.values()]

    async def audit_rows() -> list[str]:
        # The paced gate writes auth.permission_granted at admission, before the handler runs; the
        # doc says so. Every OTHER action is the handler's, and the refusal must write none.
        rows = await store.list_audit(limit=10_000)
        return [r["action"] for r in rows if r["action"] != "auth.permission_granted"]

    for verb, body in writes:
        audited, before = await audit_rows(), await states()
        # IB_B is out of scope; OB_X is the shared outbound IB_A feeds, and is out of scope too.
        for alert_id in (ids["IB_B"], ids["OB_X"], 999_999):
            r = await k.c.post(f"/alerts/{alert_id}/{verb}", json=body, headers=k.scoped)
            assert r.status_code == 404, (verb, alert_id, r.text)
        # Refused before any state change, and with no audit row of ANY action.
        assert await states() == before, verb
        assert await audit_rows() == audited, verb
        own = await k.c.post(f"/alerts/{ids['IB_A']}/{verb}", json=body, headers=k.scoped)
        assert own.status_code == 200, (verb, own.text)
        # Control: the all-channels caller reaches the alert the scoped caller could not.
        wide = await k.c.post(f"/alerts/{ids['IB_B']}/{verb}", json=body, headers=k.wide)
        assert wide.status_code == 200, (verb, wide.text)


async def _measure_events_connection_filter(k: _Callers) -> None:
    before = await k.denials()
    out = await k.c.get("/events", params={"connection": "IB_B"}, headers=k.scoped)
    assert out.status_code == 403, out.text
    assert await k.denials() == before + 1
    own = await k.c.get("/events", params={"connection": "IB_A"}, headers=k.scoped)
    assert own.status_code == 200 and {e["connection"] for e in own.json()["events"]} == {"IB_A"}
    wide = await k.c.get("/events", params={"connection": "IB_B"}, headers=k.wide)
    assert wide.status_code == 200 and {e["connection"] for e in wide.json()["events"]} == {"IB_B"}


async def _purge(k: _Callers, name: str, headers: dict[str, str]) -> httpx.Response:
    k.prove(headers, STEP_UP_ACTION_CONNECTION_PURGE)
    return await k.c.post(f"/connections/{name}/purge", headers=headers)


async def _measure_purge(k: _Callers) -> None:
    k.quiesce_outbounds()
    # A caller whose scope lists EVERY inbound that feeds OB_X is still a scoped caller.
    both_id = await _operator(k.service, "both")
    await k.service.set_channel_scope(both_id, ["IB_A", "IB_B"], actor="admin")
    both = await _login(k.c, "both")
    before = await k.denials()
    for name in ("OB_X", "NO_SUCH_OUTBOUND"):
        r = await _purge(k, name, k.scoped)
        assert r.status_code == 403 and "cannot purge" in r.text, (name, r.text)
    assert await k.denials() == before + 2
    r = await _purge(k, "OB_X", both)
    assert r.status_code == 403 and "cannot purge" in r.text, r.text
    # Control: the all-channels caller purges the same outbound, and an unknown name is a 404.
    wide = await _purge(k, "OB_X", k.wide)
    assert wide.status_code == 200 and wide.json()["cancelled"] == 2, wide.text
    assert (await _purge(k, "NO_SUCH_OUTBOUND", k.wide)).status_code == 404


async def _measure_dead_letter_replay(k: _Callers) -> None:
    before = await k.denials()
    for body in ({}, {"channel_id": "IB_B"}, {"channel_id": None, "destination_name": "OB_X"}):
        r = await k.c.post("/dead-letters/replay", json=body, headers=k.scoped)
        assert r.status_code == 403, (body, r.text)
    assert await k.denials() == before + 3
    for body in ({"channel_id": "IB_A"}, {"channel_id": "IB_A", "destination_name": "OB_X"}):
        r = await k.c.post("/dead-letters/replay", json=body, headers=k.scoped)
        assert r.status_code == 200 and "requeued" in r.json(), (body, r.text)
    # Control: the all-channels caller may replay every channel at once.
    wide = await k.c.post("/dead-letters/replay", json={}, headers=k.wide)
    assert wide.status_code == 200, wide.text


async def _measure_export_skip(k: _Callers) -> None:
    ids = await k.message_ids()
    # A well-formed id that names no message: ids carry a 32-hex shape rule.
    asked = [ids["IB_A"], ids["IB_B"], "0" * 32]

    async def export(method: str, headers: dict[str, str]) -> list[str]:
        k.prove(headers, STEP_UP_ACTION_MESSAGE_EXPORT)
        if method == "GET":
            r = await k.c.get("/messages/export", params={"ids": asked}, headers=headers)
        else:
            r = await k.c.post("/messages/export", json={"ids": asked}, headers=headers)
        assert r.status_code == 200, (method, r.text)
        return [json.loads(line)["id"] for line in r.text.splitlines() if line]

    for method in ("GET", "POST"):
        before = await k.denials()
        # Skipped, not refused: IB_B's message is left out, and so is the unknown id.
        assert await export(method, k.scoped) == [ids["IB_A"]], method
        # One denial row for the out-of-scope message, none for the id that exists nowhere.
        assert await k.denials() == before + 1, method
        # Control: the all-channels caller gets both messages.
        assert await export(method, k.wide) == [ids["IB_A"], ids["IB_B"]], method
    # The export's own audit row counts every selected id, the skipped ones included.
    rows = await k.engine.store.list_audit(action="messages_export", actor="scoped", limit=10)
    assert rows and all(json.loads(str(r["detail"]))["selected"] == 3 for r in rows)


async def _measure_approval_release_scope(k: _Callers) -> None:
    k.quiesce_outbounds()
    await _add(k.service, "checker", Role.ADMINISTRATOR)
    async with _approvals_client(k.engine, k.service, ON) as c:
        checker = await _token(c, "checker")  # _add provisions with its own module's password

        async def held(r: httpx.Response) -> str:
            assert r.status_code == 202, r.text
            return str(r.json()["approval_id"])

        async def approve(approval_id: str) -> httpx.Response:
            return await c.post(f"/approvals/{approval_id}/approve", headers=checker)

        async def refusal_reasons() -> list[str]:
            rows = await k.engine.store.list_audit(action="approval.stale_requester", limit=50)
            return [json.loads(str(r["detail"]))["reason"] for r in rows]

        replay = "/dead-letters/replay"
        scoped_replay = await held(
            await c.post(replay, json={"channel_id": "IB_A"}, headers=k.scoped)
        )
        wide_replay = await held(await c.post(replay, json={"channel_id": "IB_B"}, headers=k.wide))
        k.prove(k.wide, STEP_UP_ACTION_CONNECTION_PURGE)
        wide_purge = await held(await c.post("/connections/OB_X/purge", headers=k.wide))
        # Control: a release whose requester still holds the scope runs.
        assert (await approve(wide_replay)).status_code == 200
        # The scoped requester's scope moves off the channel its held replay names.
        await k.service.set_channel_scope(k.scoped_id, ["IB_B"], actor="admin")
        r = await approve(scoped_replay)
        assert r.status_code == 409 and "no longer holds" in r.text, r.text
        # The purge requester keeps every inbound that feeds OB_X, and is still no longer unscoped.
        await k.service.set_channel_scope(k.wide_id, ["IB_A", "IB_B"], actor="admin")
        r = await approve(wide_purge)
        assert r.status_code == 409 and "no longer holds" in r.text, r.text
        assert await refusal_reasons() == ["requester_out_of_scope"] * 2
        for approval_id in (scoped_replay, wide_purge):
            row = await k.engine.store.get_pending_approval(approval_id)
            assert row is not None and str(row["status"]) == "pending", approval_id


async def _measure_security_events_birth_bound(k: _Callers) -> None:
    # A failed sign-in against a name no account holds yet is recorded under that name.
    r = await k.c.post(
        "/auth/login", json={"username": "latecomer", "password": "wrong", "provider": "local"}
    )
    assert r.status_code == 401, r.text
    early = await k.engine.store.list_audit(actor="latecomer", limit=50)
    assert early and all(str(row["action"]).startswith("auth.") for row in early)
    early_ts = {float(row["ts"]) for row in early}
    await _operator(k.service, "latecomer")
    feed = await k.c.get("/me/security-events", headers=await _login(k.c, "latecomer"))
    assert feed.status_code == 200, feed.text
    shown = feed.json()["events"]
    # The account's own sign-in shows, so the feed is not merely empty...
    assert any(e["action"] == "auth.login_success" for e in shown), shown
    # ...and the row written under its name before the account existed does not.
    assert not early_ts & {float(e["ts"]) for e in shown}, shown
    # Control: the raw audit log still holds that row; the feed bound is a read filter.
    kept = await k.engine.store.list_audit(actor="latecomer", limit=50)
    assert early_ts <= {float(row["ts"]) for row in kept}


async def _measure_ui_connection_page(k: _Callers) -> None:
    pytest.importorskip("messagefoundry_webconsole")
    app = create_app(k.engine, auth=k.service, serve_ui=True, webauthn_rp_from_request=True)

    async def page(username: str, names: tuple[str, ...]) -> list[int]:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            r = await c.post("/ui/login", data={"username": username, "password": PW})
            assert r.status_code == 303 and c.cookies.get("mf_session"), r.text
            return [(await c.get(f"/ui/connection/{name}")).status_code for name in names]

    # The page name is the dashboard row's display name: an inbound's source row, then the edge row
    # from the in-scope IB_A into the shared outbound OB_X, then a name that exists nowhere.
    # Built from its code point, so the source carries no glyph; the dashboard joins with U+25B8.
    sep = f" {chr(0x25B8)} "
    names = (f"IB_A{sep}in", f"IB_B{sep}in", f"IB_A{sep}OB_X", f"NOPE{sep}in")
    before = await k.denials()
    assert await page("scoped", names) == [200, 404, 404, 404]
    # A 404, and no denial row: unlike the JSON per-name routes, nothing is audited.
    assert await k.denials() == before
    # Control: the all-channels caller opens both rows the scoped caller could not.
    assert await page("allchannels", names) == [200, 200, 200, 404]


@contextlib.asynccontextmanager
async def _ui_sessions(k: _Callers, *usernames: str) -> AsyncIterator[dict[str, httpx.AsyncClient]]:
    """One console client per user, each signed in ONCE through the cookie flow, so a measurement's
    run of requests does not trip the sign-in rate limit."""
    app = create_app(k.engine, auth=k.service, serve_ui=True, webauthn_rp_from_request=True)
    async with contextlib.AsyncExitStack() as stack:
        clients: dict[str, httpx.AsyncClient] = {}
        for username in usernames:
            c = await stack.enter_async_context(
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
            )
            r = await c.post("/ui/login", data={"username": username, "password": PW})
            assert r.status_code == 303 and c.cookies.get("mf_session"), (username, r.text)
            clients[username] = c
        yield clients


async def _measure_ui_resend_done(k: _Callers) -> None:
    pytest.importorskip("messagefoundry_webconsole")
    ids = await k.message_ids()
    # A resend of IB_A's message, copied from its OB_X body, to the target OB_Y under one key. The
    # store call the JSON resend makes; the route under test reads only its record, so the lane
    # state, and whether OB_Y is registered, is not part of the rule. Source and target differ, so
    # a page that named the source would show a name the target does not.
    outcome = await k.engine.store.resend_to(
        message_id=ids["IB_A"],
        to="OB_Y",
        from_="OB_X",
        idempotency_key="k-ran",
        audit=no_audit_row,
    )
    assert (outcome.status, outcome.from_destination) == ("resent", "OB_X"), outcome
    path, ran = f"/ui/messages/{ids['IB_A']}/resend-done", {"to": "OB_Y", "key": "k-ran"}
    # Scoped to the target alone, with no scope on the origin IB_A.
    target_only = await _operator(k.service, "target_only")
    await k.service.set_channel_scope(target_only, ["OB_Y"], actor="admin")
    async with _ui_sessions(k, "scoped", "allchannels", "target_only") as ui:
        # Scoped to IB_A, the ORIGIN channel, but not to the target OB_Y: no record, as for a bad
        # key.
        hidden = await ui["scoped"].get(path, params=ran)
        assert hidden.status_code == 404 and "No such resend" in hidden.text, hidden.status_code
        # Control: the all-channels caller sees the page; a key, a target or a message the record
        # does not name is "No such resend" for it too.
        shown = await ui["allchannels"].get(path, params=ran)
        assert shown.status_code == 200 and "OB_Y" in shown.text, shown.status_code
        for p, to, key in (
            (path, "OB_Y", "never-used"),
            (path, "OB_X", "k-ran"),
            (f"/ui/messages/{ids['IB_B']}/resend-done", "OB_Y", "k-ran"),
        ):
            r = await ui["allchannels"].get(p, params={"to": to, "key": key})
            assert r.status_code == 404 and "No such resend" in r.text, (p, to, key)
        # A target that fails the connection-name rule is refused before any lookup.
        bad = await ui["allchannels"].get(path, params={"to": "<b>x</b>", "key": "k-ran"})
        assert bad.status_code == 422, bad.status_code
        # The origin channel is not checked: the target-only caller is shown the page, which
        # names the target and neither the origin channel nor the source lane.
        alone = await ui["target_only"].get(path, params=ran)
        assert alone.status_code == 200 and "OB_Y" in alone.text, alone.status_code
        assert "IB_A" not in alone.text and "OB_X" not in alone.text


async def _measure_ui_suspend_refusal(k: _Callers) -> None:
    pytest.importorskip("messagefoundry_webconsole")
    # The fixture's one open alert per connection, so the page's list is scoped against a known set.
    ids = {
        a.connection: a.id
        for a in await k.engine.store.list_active_alert_instances(allowed_channels=None)
    }
    # A suspender holding monitoring:diagnose WITHOUT monitoring:read, scoped to IB_A like "scoped".
    role = await k.service.create_custom_role(
        display_name="Alert Suspender",
        description=None,
        permissions=["monitoring:diagnose"],
        actor="test",
    )
    suspender = await _operator(k.service, "suspender")
    await k.service.set_roles(suspender, [role.id], actor="admin")
    await k.service.set_channel_scope(suspender, ["IB_A"], actor="admin")
    store = k.engine.store

    async def suspended() -> list[float | None]:
        rows = [await store.get_alert_instance(i, allowed_channels=None) for i in ids.values()]
        return [row.suspended_until if row is not None else None for row in rows]

    async def suspend_minutes() -> list[float]:
        rows = await store.list_audit(action="alert_suspend", limit=500)
        return sorted(json.loads(r["detail"])["minutes"] for r in rows)

    async def granted() -> int:
        return len(await store.list_audit(action="auth.permission_granted", limit=10_000))

    # The JSON route refuses the same bad windows with 422, before it reads the alert: an
    # out-of-scope id and an unknown one get the 422 too. A missing window is refused as well.
    for alert_id in (ids["IB_B"], 999_999):
        for body in ({"minutes": 0}, {}):
            r = await k.c.post(f"/alerts/{alert_id}/suspend", json=body, headers=k.scoped)
            assert r.status_code == 422, (alert_id, body, r.text)

    before, rows_before = await suspended(), await suspend_minutes()
    async with _ui_sessions(k, "suspender", "scoped", "allchannels") as ui:

        async def post(username: str, alert_id: int, form: dict[str, str]) -> httpx.Response:
            return await ui[username].post(
                f"/ui/alerts/{alert_id}/suspend",
                data=form,
                headers={"Sec-Fetch-Site": "same-origin"},
            )

        # Refused before the alert is read: an in-scope id, an out-of-scope one and an unknown
        # one alike.
        pages: dict[tuple[str, int], str] = {}
        for alert_id in (ids["IB_A"], ids["IB_B"], 999_999):
            for username in ("suspender", "scoped", "allchannels"):
                r = await post(username, alert_id, {"minutes": "0"})
                assert r.status_code == 400 and "suspend window" in r.text, (username, alert_id)
                pages[username, alert_id] = r.text
        # A window of only whitespace does not parse, so it is refused, not read as 60.
        r = await post("suspender", ids["IB_A"], {"minutes": "  "})
        assert r.status_code == 400 and "suspend window" in r.text, r.status_code
        # No refusal muted an alert or wrote a suspend audit row.
        assert await suspended() == before and await suspend_minutes() == rows_before
        # A valid window reaches the JSON handler, which reads the alert through the scope: an
        # out-of-scope id and an unknown one answer its 404, with no state change and no audit
        # row, and require_ui writes no admission row either.
        granted_before = await granted()
        for alert_id in (ids["IB_B"], ids["OB_X"], 999_999):
            r = await post("suspender", alert_id, {"minutes": "5"})
            assert r.status_code == 404, (alert_id, r.status_code)
        assert await suspended() == before and await suspend_minutes() == rows_before
        assert await granted() == granted_before
        # Control for the row count: the JSON gate's admission row is counted.
        r = await k.c.post("/alerts/999999/suspend", json={"minutes": 5}, headers=k.scoped)
        assert r.status_code == 404 and await granted() > granted_before, r.text
        # Control for the scope read: the scoped suspender reaches its own alert.
        r = await post("suspender", ids["IB_A"], {"minutes": "5"})
        assert r.status_code == 303, r.status_code
        # The open defect the bullet names: an empty window and a missing one are read as 60
        # minutes, and the audit row records 60 as if it were the request.
        started = time.time()
        for alert_id, form in ((ids["IB_A"], {"minutes": ""}), (ids["IB_B"], {})):
            r = await post("allchannels", alert_id, form)
            assert r.status_code == 303, (form, r.status_code)
        assert await suspend_minutes() == sorted([*rows_before, 5.0, 60.0, 60.0])
        after = dict(zip(ids, await suspended(), strict=True))
        for name in ("IB_A", "IB_B"):
            until = after[name]
            assert until is not None and started + 3540 <= until <= time.time() + 3600, name
        assert after["OB_X"] == dict(zip(ids, before, strict=True))["OB_X"]
        narrow = pages["suspender", ids["IB_A"]]
        # The list is the caller's scoped one, which leaves out the shared outbound IB_A feeds, and
        # without monitoring:read the rules are left out.
        assert "IB_A" in narrow and "IB_B" not in narrow and "OB_X" not in narrow
        assert ">Rules<" not in narrow
        # Control: an operator holds monitoring:read, so the same refusal shows the rules; the
        # all-channels operator's list carries the alerts the scoped one's does not.
        assert ">Rules<" in pages["scoped", ids["IB_A"]]
        wide = pages["allchannels", ids["IB_A"]]
        assert "IB_B" in wide and "OB_X" in wide


class _Rule(NamedTuple):
    #: The routes its bullet must name, written as the doc backticks them, compared as exact tokens.
    routes: tuple[str, ...]
    #: The facts its bullet must state: plain substrings of the unwrapped bullet.
    facts: tuple[str, ...]
    measure: Callable[[_Callers], Awaitable[None]]
    #: What its bullet must NOT say. A presence check alone passes "answers 403 (it used to answer
    #: 404)", so the status code a bullet must not give is named here.
    forbidden: tuple[str, ...] = ()
    #: The class ``tests/test_route_channel_scope_classification.py`` must give each JSON route.
    scope_class: str = SCOPED


_RULES: dict[str, _Rule] = {
    "layered-search-owner": _Rule(
        ("GET /search/layered",),
        ("`user_id`", "404", "channel scope"),
        _measure_layered_search_owner,
        forbidden=("403",),
    ),
    "statistics-reset": _Rule(
        ("POST /statistics/reset",),
        (
            "`all`",
            "403",
            "`channel_id`",
            "nothing resets",
            "only that edge",
            "`auth.channel_denied`",
        ),
        _measure_statistics_reset,
        forbidden=("404",),
    ),
    "status-per-field": _Rule(
        ("GET /status",),
        (
            "`channels_failed_names`",
            "`channels_failed`",
            "`outbox_by_status`",
            "`kpis`",
            "are not narrowed",
        ),
        _measure_status_per_field,
        forbidden=("counts are narrowed",),
    ),
    "alert-writes": _Rule(
        (
            "POST /alerts/{alert_id}/ack",
            "POST /alerts/{alert_id}/resolve",
            "POST /alerts/{alert_id}/suspend",
            "POST /alerts/{alert_id}/resume",
        ),
        ("404", "shared outbound", "no audit row", "`auth.permission_granted`"),
        _measure_alert_writes,
        forbidden=("403",),
    ),
    "events-connection-filter": _Rule(
        ("GET /events",),
        ("`connection=`", "403", "`auth.channel_denied`"),
        _measure_events_connection_filter,
        forbidden=("404",),
    ),
    "purge": _Rule(
        ("POST /connections/{name}/purge",),
        ("403", "any outbound", "every inbound that feeds", "`auth.channel_denied`"),
        _measure_purge,
        forbidden=("404", "shared outbound"),
    ),
    "dead-letter-replay": _Rule(
        ("POST /dead-letters/replay",),
        ("`channel_id`", "no `channel_id`", "403", "`destination_name`", "`auth.channel_denied`"),
        _measure_dead_letter_replay,
        forbidden=("404",),
    ),
    "export-skip": _Rule(
        ("GET /messages/export", "POST /messages/export"),
        ("skipped, not refused", "200", "`auth.channel_denied`", "unknown id", "`selected`"),
        _measure_export_skip,
        forbidden=("404", "403"),
    ),
    "approval-release-scope": _Rule(
        ("POST /approvals/{approval_id}/approve",),
        ("`channel_id`", "all-channels", "409", "pending", "`requester_out_of_scope`"),
        _measure_approval_release_scope,
        scope_class=ADMINISTRATOR_ONLY,
    ),
    "security-events-birth-bound": _Rule(
        ("GET /me/security-events",),
        ("`auth.*`", "username", "`created_at`"),
        _measure_security_events_birth_bound,
        scope_class=NOT_CHANNEL_BEARING,
    ),
    "ui-connection-page": _Rule(
        ("GET /ui/connection/{name}",),
        ("404", "any outbound", "writes no", "`auth.channel_denied`"),
        _measure_ui_connection_page,
        # The bullet names the JSON routes' 403 to contrast with, so the contradiction is the verb.
        forbidden=("answers 403",),
    ),
    "ui-resend-done": _Rule(
        ("GET /ui/messages/{message_id}/resend-done",),
        (
            "404",
            "`key`",
            "422",
            "outside the caller's channel scope",
            "does not check scope on the message's origin channel",
            "target alone",
            "no source",
        ),
        _measure_ui_resend_done,
        # Vault BACKLOG #4776 item 1 is open: the route does not check the origin channel today.
        # A bare "answers 403" is not forbidden here: the gate does answer 403 to a caller without
        # messages:resend. The scope refusal is the 404 the measurement executes.
        forbidden=("scope answers 403", "checks scope on the origin", "origin channel is checked"),
    ),
    "ui-suspend-refusal": _Rule(
        ("POST /ui/alerts/{alert_id}/suspend",),
        (
            "400",
            "only whitespace",
            "422",
            "before they read the alert",
            "unknown one",
            "60 minutes",
            "open defect",
            "the alert-writes rule above applies, its 404 included",
            "`require_ui`, which writes no `auth.permission_granted` row",
            "channel scope",
            "`monitoring:read`",
            "`monitoring:diagnose`",
        ),
        _measure_ui_suspend_refusal,
        # A valid window can 404 in the handler, so only the refusal's 404 is wrong. A whitespace
        # window is refused, so "blank" would claim what only an empty one does.
        forbidden=("the same 404", "blank"),
    ),
}


@pytest.mark.parametrize("rule", sorted(_RULES))
async def test_single_route_rule_is_measured_against_a_live_app(
    rule: str,
    engine: Engine,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pacing off: several measurements send a run of paced writes as one actor.
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_write_min_interval_seconds=0,
            admin_write_rate_limit_enabled=False,
        ),
    )
    await service.initialize()
    scoped_id = await _operator(service, "scoped")
    await service.set_channel_scope(scoped_id, ["IB_A"], actor="admin")
    # Deny-by-default (BACKLOG #1152): the control is granted the estate rather than left unset.
    wide_id = await _operator(service, "allchannels")
    await service.set_channel_scope(wide_id, [ALL_CHANNELS], actor="admin")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        callers = _Callers(
            engine=engine,
            c=c,
            scoped=await _login(c, "scoped"),
            wide=await _login(c, "allchannels"),
            monkeypatch=monkeypatch,
            service=service,
            scoped_id=scoped_id,
            wide_id=wide_id,
        )
        await _RULES[rule].measure(callers)


def test_every_rule_route_carries_its_channel_scope_class() -> None:
    """The channel-scope classification table must agree with each rule's class: scoped for a
    channel rule, and the two owner and administrator rules as that table files them. A ``/ui``
    route is left out because that table covers the JSON API only."""
    for rule in _RULES.values():
        for route in rule.routes:
            if route.split(" ", 1)[1].startswith("/ui"):
                continue
            assert ROUTES[route][0] == rule.scope_class, (
                f"{route} is classified {ROUTES[route][0]}, not {rule.scope_class}"
            )


# =====================================================================================================
# The doc binding -- the same rules, read out of docs/SECURITY.md
# =====================================================================================================


@functools.cache
def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _bullet_spans(lines: list[str]) -> list[tuple[int, int]]:
    """``(start, end)`` line spans of each ``- `` bullet; a continuation line is indented 3."""
    spans: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if line[1:].strip().startswith("- "):
            spans.append((i, i + 1))
        elif spans and spans[-1][1] == i and line.startswith(">   "):
            spans[-1] = (spans[-1][0], i + 1)
    return spans


def _unwrap_bullet(lines: list[str]) -> str:
    """The bullet as one string, without its ``- `` lead."""
    return unwrap(lines).removeprefix("- ")


def _problems(text: str) -> list[str]:
    problems: list[str] = []
    lines = text.splitlines()
    block = blockquote_lines(text, _MARKER)
    bullets = [_unwrap_bullet(block[a:b]) for a, b in _bullet_spans(block)]
    claimed = [route_tokens(b) for b in bullets]
    for i, tokens in enumerate(claimed):
        # Every route a bullet names must belong to the ONE rule that measures it, or an extra,
        # unexecuted route could ride along inside a measured bullet.
        if not tokens or not any(tokens <= set(rule.routes) for rule in _RULES.values()):
            problems.append(
                f"bullet {i + 1} names a route no measurement executes: {sorted(tokens)}"
            )
    for name, rule in _RULES.items():
        home = [b for b, tokens in zip(bullets, claimed, strict=True) if tokens & set(rule.routes)]
        if len(home) != 1:
            problems.append(f"{name}: expected one bullet naming {rule.routes}, found {len(home)}")
            continue
        bullet, tokens = home[0], route_tokens(home[0])
        for route in rule.routes:
            if route not in tokens:
                problems.append(f"{name}: its bullet omits {route}")
            method, path = route.split(" ", 1)
            prefix = f"| `{method}` | `{path}` |"
            row = next((line for line in lines if line.startswith(prefix)), "")
            if _ROW_POINTER not in row:
                problems.append(f"{name}: the route-map row for {route} does not point here")
        for fact in rule.facts:
            if fact not in bullet:
                problems.append(f"{name}: its bullet no longer states {fact!r}")
        for wrong in rule.forbidden:
            if wrong in bullet:
                problems.append(f"{name}: its bullet says {wrong!r}, which the code does not do")
    return problems


def test_security_doc_states_each_single_route_rule() -> None:
    assert _problems(_doc_text()) == []


@pytest.mark.parametrize("route", sorted(r for rule in _RULES.values() for r in rule.routes))
def test_guard_detects_a_planted_route_omission(route: str) -> None:
    planted = plant_in_blockquote(_doc_text(), _MARKER, f"`{route}`", "`GET /nowhere`")
    assert _problems(planted), f"deleting {route} from the blockquote did not red the guard"


def _rewrite_bullet(rule: str, edit: Callable[[str], str]) -> str:
    """The doc with ``rule``'s bullet re-emitted as one line after ``edit``, so a fact split across
    a wrap is planted too."""
    text = _doc_text()
    block = blockquote_lines(text, _MARKER)
    start, end = next(
        (a, b) for a, b in _bullet_spans(block) if route_tokens(block[a]) & set(_RULES[rule].routes)
    )
    bullet = _unwrap_bullet(block[start:end])
    planted = text.replace("\n".join(block[start:end]), "> - " + edit(bullet), 1)
    assert planted != text, f"the edit did not change the {rule} bullet"
    return planted


@pytest.mark.parametrize(
    ("rule", "fact"), sorted((name, f) for name, rule in _RULES.items() for f in rule.facts)
)
def test_guard_detects_a_planted_fact_deletion(rule: str, fact: str) -> None:
    # Every occurrence: the reset bullet says 403 twice, and planting one would leave the other.
    planted = _rewrite_bullet(rule, lambda b: b.replace(fact, "REDACTED-FACT"))
    assert any(p.startswith(f"{rule}:") for p in _problems(planted)), (
        f"deleting {fact!r} did not red {rule}"
    )


@pytest.mark.parametrize(
    ("rule", "wrong"), sorted((name, w) for name, rule in _RULES.items() for w in rule.forbidden)
)
def test_guard_detects_a_planted_contradiction(rule: str, wrong: str) -> None:
    """A contradiction that keeps the true token, such as the alert writes' 404 turned into the 403
    the other refusals give, "(it used to answer 404)" and all."""
    planted = _rewrite_bullet(rule, lambda b: f"{b} It answers {wrong} instead.")
    assert any(p.startswith(f"{rule}:") for p in _problems(planted)), (
        f"adding {wrong!r} did not red {rule}"
    )


def test_guard_detects_an_extra_route_in_a_measured_bullet() -> None:
    planted = _rewrite_bullet(
        "events-connection-filter", lambda b: f"{b} So does `GET /connections/{{name}}/events`."
    )
    assert any("no measurement executes" in p for p in _problems(planted))


def test_guard_detects_an_unmeasured_bullet() -> None:
    """The other direction: a bullet no rule claims is a documented rule nothing executes."""
    anchor = "> - `GET /status`"
    planted = _doc_text().replace(anchor, "> - `GET /nowhere` is a new rule.\n" + anchor, 1)
    assert planted != _doc_text()
    assert any("no measurement executes" in p for p in _problems(planted))


def test_guard_detects_a_dropped_row_pointer() -> None:
    text = _doc_text()
    row = next(line for line in text.splitlines() if line.startswith("| `GET` | `/status` |"))
    assert _ROW_POINTER in row
    planted = text.replace(row, row.replace(_ROW_POINTER, "nothing here"), 1)
    assert any("does not point here" in p for p in _problems(planted))
