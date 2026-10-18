# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui connection and status surfaces. Among them: the terminate re-proof, dead-letter replay-all, the
events kind filter, the status page, the connections fragment and nav-status, and the server-side
bulk connection controls (bulk-control, reset-many and bulk purge)."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from _webui_support import (
    _GIB,
    ADT,
    PW,
    _add,
    _boss_client,
    _client,
    _cookie_login,
    _mint_action,
    _post_pairs,
    _service,
    _start_two_out,
    _sysinfo,
    _uid,
    _wait_quiesced,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

# --- 7.5.2: /ui terminate now requires a password re-proof (require_ui_reauth_only) --------------


async def test_revoke_one_stale_bounces_to_reauth(engine: Engine) -> None:
    # A stale window 303s the terminate POST to /ui/reauth carrying its OWN path as next, and
    # nothing is revoked until the retry actually runs (the registration makes the continuation work).
    #
    # NOT the require_mfa=False shape of the step-up twins (BACKLOG #1850): this route rides
    # require_ui_reauth_only_action, whose base passes allow_mfa_pending=True, so there is no MFA leg
    # to take out and require_mfa=False would pin nothing. Under ADR 0077 the gate reads
    # has_action_step_up -- never has_recent_step_up -- so the negative window is load-bearing only
    # through the GRANT minted below, which _grant_action_step_up deadlines at
    # now + step_up_max_age_seconds, i.e. already expired. The mint is the CONTROL, not setup: drop
    # it and the POST bounces for want of ANY grant, which it does under any window (BACKLOG #1851).
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    other = await service.login("op", PW)  # the target 2nd session
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        op_id = await _uid(service, "op")
        other_id = hash_token(other.token or "")
        path = f"/ui/account/sessions/{other_id}/revoke"
        # No ungranted arm here, deliberately: test_sessions_revoke_one already asserts that
        # refusal under a DEFAULT window, which is also the proof that the -1 above changed nothing
        # before this mint existed. Do not re-add a grant-less POST. Why the grant is evidenced by
        # the re-auth response rather than read back, and why both halves are checked:
        # test_stale_reauth_only_bounces_to_reauth.
        minted = await _mint_action(c, path)
        assert minted.status_code == 200
        assert f'action="{path}"' in minted.text
        r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        # The LOCATION carries the property: a SUCCESSFUL revoke also answers 303, to
        # /ui/account/sessions?m=revoked, so the status alone would not say the gate refused.
        assert r.status_code == 303
        assert r.headers["location"] == f"/ui/reauth?next={path}"
        remaining = {s.token_hash for s in await service.store.list_sessions(op_id)}
        assert other_id in remaining  # nothing revoked yet


async def test_revoke_others_stale_bounces_to_reauth(engine: Engine) -> None:
    # The revoke-others twin of the per-session test above, and the same correction applies: the
    # negative window bites through the ADR 0077 GRANT's TTL, not through has_recent_step_up, so the
    # _mint_action below is what puts the window under test (BACKLOG #1851). Reasoning: that twin.
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    await service.login("op", PW)  # a 2nd session
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        op_id = await _uid(service, "op")
        path = "/ui/account/sessions/revoke-others"
        # Ungranted arm: test_sessions_revoke_others, under a default window. See the twin above.
        minted = await _mint_action(c, path)
        assert minted.status_code == 200
        assert f'action="{path}"' in minted.text
        r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        # The LOCATION, again: a SUCCESSFUL revoke-others also answers 303, to
        # /ui/account/sessions?m=signed_out_others.
        assert r.status_code == 303
        assert r.headers["location"] == f"/ui/reauth?next={path}"
        assert len(await service.store.list_sessions(op_id)) == 2  # both still present


def test_session_terminate_actions_registered_password_only() -> None:
    # Both terminate POSTs are registered auto_retry continuations (so /ui/reauth can re-POST them),
    # step_up=False (password-only) so a no-factor session is never deadlocked out of revoking.
    from messagefoundry_webconsole import is_safe_ui_action, lookup_ui_action

    assert is_safe_ui_action("/ui/account/sessions/revoke-others") is True
    assert is_safe_ui_action("/ui/account/sessions/S1/revoke") is True
    a1 = lookup_ui_action("/ui/account/sessions/revoke-others")
    a2 = lookup_ui_action("/ui/account/sessions/S1/revoke")
    assert a1 is not None and a1.step_up is False
    assert a2 is not None and a2.step_up is False
    assert is_safe_ui_action("/ui/account/sessions/../revoke") is False  # traversal rejected
    assert is_safe_ui_action("/ui/account/sessions/revoke-others/extra") is False  # extra segment


async def test_revoke_reauth_only_no_mfa_deadlock(engine: Engine) -> None:
    # A require_mfa but UNENROLLED cookie session under a stale window: GET /ui/reauth?next=<terminate>
    # renders the PASSWORD reauth form (200), NOT the enroll_first divert — the step_up=False
    # registration keeps a no-factor user out of the enroll-loop so they can still revoke.
    service = AuthService(engine.store, AuthSettings(require_mfa=True, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/reauth", params={"next": "/ui/account/sessions/revoke-others"})
        assert r.status_code == 200 and 'name="code"' not in r.text


# Gap 4 — replay ALL dead letters (every channel) --------------------------------------------------


async def _seed_dead(
    engine: Engine, *, channel: str = "IB_ACME_ADT", dest: str = "OB_ARCHIVE"
) -> None:
    mid = await engine.store.enqueue_message(
        channel_id=channel,
        raw=ADT,
        deliveries=[(dest, ADT)],
        control_id="DL1",
        message_type="ADT^A01",
        source_type="file",
    )
    outbox = await engine.store.outbox_for(mid)
    await engine.store.dead_letter_now(outbox[0]["id"], "boom")


async def test_dead_letters_shows_replay_all_button(engine: Engine) -> None:
    service = await _service(engine)
    await _seed_dead(engine)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/dead-letters")
        assert r.status_code == 200
        assert 'action="/ui/dead-letters/replay-all"' in r.text
        assert "Replay all dead (every channel)" in r.text


async def test_replay_all_dead_letters_registered_and_gated(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action

    # The new action is in the auto-retry allow-list (so a stale step-up can continue it).
    assert is_safe_ui_action("/ui/dead-letters/replay-all")
    service = await _service(engine)
    await _seed_dead(engine)
    async with _boss_client(engine, service) as c:
        # Cross-site is rejected before any work (assert_same_origin).
        r = await c.post("/ui/dead-letters/replay-all", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403
        # boss is admin (replay + fresh step-up from login) → the all-channels replay runs (303
        # back to the list — the literal replay-all route, NOT captured by the {channel_id} routes).
        r = await c.post("/ui/dead-letters/replay-all", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/dead-letters"


# Gap 5 — event-log kind filter --------------------------------------------------------------------


def test_events_filter_renders_kind_dropdown() -> None:
    from messagefoundry.api.models import ConnectionEventList
    from messagefoundry_webconsole.pages import events

    empty = ConnectionEventList(total=0, limit=100, offset=0, before_id=None, events=[])
    html = str(events(empty, connection="", kind="peer_reset"))
    assert 'name="kind"' in html
    assert "All kinds" in html
    # Every canonical kind is an option, and the selected one is marked.
    for k in ("established", "closed", "idle_timeout", "peer_not_allowlisted", "framing_error"):
        assert f'value="{k}"' in html
    assert 'value="peer_reset" selected' in html


async def test_events_kind_filter_applies(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/events", params={"kind": "established"})
        assert r.status_code == 200
        assert 'value="established" selected' in r.text  # the filter round-trips into the form


# Gap 2 — update-available banner on /ui/status ----------------------------------------------------


def _sys_status(*, update: object = None) -> object:
    from messagefoundry.api.models import DbInfo, EngineInfo, SystemStatus

    return SystemStatus(
        engine=EngineInfo(
            version="0.2.14",
            uptime_seconds=1.0,
            pid=1,
            channels_total=1,
            channels_running=1,
            channels_stopped=0,
            outbox_by_status={},
        ),
        db=DbInfo(
            path="/x",
            size_bytes=1,
            disk_free_bytes=1,
            journal_mode="wal",
            messages=0,
            events=0,
            audit=0,
        ),
        update=update,
    )


def _status_html(sys_status: object, security: dict[str, object] | None = None) -> str:
    from messagefoundry.api.models import (
        ClusterNodeList,
        ClusterStatus,
        DrStatus,
        SecurityPosture,
        ServiceStatusInfo,
    )
    from messagefoundry_webconsole.pages import status

    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=False,
        key_source="none",
        key_id=None,
        require_encryption=False,
        allow_unencrypted_phi=True,
        security=security or {},
    )
    cluster = ClusterStatus(
        node_id="n1", clustered=False, is_leader=True, role="single-node", config_version=0
    )
    dr = DrStatus(enabled=False, active=False, threshold="P1", activation_mode="manual")
    svc = ServiceStatusInfo(enabled=False, state="disabled", service_name="")
    nodes = ClusterNodeList(nodes=[], leader_node_id=None, lease_owner=None, lease_expires_at=None)
    return str(status(sys_status, posture, cluster, nodes, dr, svc))


def test_status_page_gives_each_retention_acknowledgement_its_own_row() -> None:
    """Vault BACKLOG #2280: the posture table showed ``allow_keeping_phi_indefinitely`` only.

    The switches are read off the engine's classification, so a tier given one there reds here
    until the page shows it. A distinct marker per switch proves each row reads ITS key."""
    from messagefoundry.config.retention_classification import PHI_RETENTION_WINDOWS

    switches = [w.acknowledged_by for w in PHI_RETENTION_WINDOWS if w.acknowledged_by]
    assert len(switches) >= 4  # a floor, so an emptied classification cannot pass this vacuously
    labels = {s: "Allow " + s.removeprefix("allow_").replace("_", " ") for s in switches}
    sys_status = _sys_status(update=None)
    marked = _status_html(sys_status, {s: f"marker-{s}" for s in switches})
    unset = _status_html(sys_status)
    for switch, label in labels.items():
        assert f"{label}</td><td>marker-{switch}<" in marked, switch
        # The control: with no value the row is still there, and shows the dash.
        assert f"{label}</td><td>—<" in unset, switch


def test_status_update_banner() -> None:
    from messagefoundry.api.models import UpdateInfo

    # update_available True → the banner renders with both version strings.
    html = _status_html(
        _sys_status(
            update=UpdateInfo(
                current_version="0.2.13", pinned_version="0.2.14", update_available=True
            )
        )
    )
    assert "newer MessageFoundry version is installed" in html
    assert "0.2.13" in html and "0.2.14" in html and "Restart the engine" in html
    # No update / not available → no banner.
    assert "newer MessageFoundry version" not in _status_html(_sys_status(update=None))
    assert "newer MessageFoundry version" not in _status_html(
        _sys_status(
            update=UpdateInfo(
                current_version="0.2.14", pinned_version="0.2.14", update_available=False
            )
        )
    )


def test_status_page_renders_a_failed_inbound_as_failed_in_the_hearts_words() -> None:
    """BACKLOG #1816: a start failure used to read as an ordinary stopped inbound on /ui/status.

    The page must say "failed to start" and must say it in the SAME sentence the nav heart shows,
    so the reason is taken from ``_derive_health`` itself rather than restated here. The failure
    is a subset of the stopped count, so the count line says "of which" and never adds a term."""
    from messagefoundry_webconsole.routes.status import _derive_health

    failed = _sysinfo(50 * _GIB, channels=3, failed_names=["IB_ACME_ADT"])
    _health, reason = _derive_health(failed, None, None, None)
    assert reason == "inbound IB_ACME_ADT failed to start"
    html = _status_html(failed)
    assert "2/3 running (1 stopped, of which 1 failed to start)" in html
    assert reason in html
    assert 'class="status status-failed"' in html

    # A channel-scoped caller sees the count and no names; the page must not invent any.
    scoped = _sysinfo(50 * _GIB, channels=3, failed_count=2)
    _health, scoped_reason = _derive_health(scoped, None, None, None)
    assert scoped_reason == "2 inbound connections failed to start"
    assert scoped_reason in _status_html(scoped)

    # A connection name is free text, so it goes through the escaping builder like any other value.
    hostile = _status_html(_sysinfo(50 * _GIB, channels=1, failed_names=["<b>IB</b>"]))
    assert "<b>IB</b>" not in hostile and "&lt;b&gt;IB&lt;/b&gt;" in hostile


def test_status_page_without_a_failed_inbound_keeps_the_plain_stopped_line() -> None:
    """The #1816 control: an ordinary stop is not a failure, and the page must not call it one."""
    html = _status_html(_sysinfo(50 * _GIB, channels=3, channels_running=2))
    assert "2/3 running (1 stopped)" in html
    assert "failed to start" not in html
    assert "Inbound start failures" not in html


# Gap 3 — per-connection stats reset ---------------------------------------------------------------


def _conn_row(
    role: str, channel_id: str, *, destination: str | None = None, name: str = ""
) -> object:
    from messagefoundry.api.models import ConnectionRow

    return ConnectionRow(
        role=role,
        channel_id=channel_id,
        channel_name=channel_id,
        destination=destination,
        name=name or destination or channel_id,
        status="running",
        direction="out" if role == "destination" else "in",
        method="File",
        peer=None,
        port=None,
        queue_depth=0,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=0 if role == "source" else None,
        written=0,
        backlog_seconds=None,
        delivered_age_seconds=None,
    )


def test_connections_fragment_has_no_per_row_control_forms() -> None:
    from messagefoundry_webconsole.pages import connections_fragment

    html = str(
        connections_fragment(
            [
                _conn_row("source", "IB_ACME_ADT"),
                _conn_row("destination", "IB_ACME_ADT", destination="OB_ARCHIVE"),
            ]
        )
    )
    # Each row exposes a single selection checkbox (both roles); NO per-row start/stop/restart/purge/reset
    # forms survive in the polled fragment — those actions moved to the un-polled dashboard toolbar.
    assert html.count("data-mf-conns-cb") == 2
    assert 'data-role="source"' in html
    assert 'data-role="destination"' in html
    assert "/ui/statistics/reset-one" not in html
    assert "Reset stats" not in html
    assert ">Start<" not in html and ">Stop<" not in html and ">Restart<" not in html
    assert "Purge top" not in html and "Purge all" not in html
    assert 'id="conns"' in html


def test_dashboard_renders_bulk_toolbar_outside_conns_fragment() -> None:
    from messagefoundry_webconsole.pages import connections_fragment, dashboard

    rows = [_conn_row("source", "IB_ACME_ADT")]
    page_html = str(dashboard(rows))
    fragment_html = str(connections_fragment(rows))
    # The toolbar hook, its action <select> options, Apply button, and feedback span live in the shell.
    assert "data-mf-conns-toolbar" in page_html
    assert "data-mf-conns-action" in page_html
    assert "data-mf-conns-apply" in page_html
    assert "data-mf-conns-feedback" in page_html
    for label in ("Start", "Stop", "Restart", "Reset stats", "Purge top", "Purge all"):
        assert f">{label}<" in page_html
    for value in ("start", "stop", "restart", "reset", "purge-top", "purge-all"):
        assert f'value="{value}"' in page_html
    # The toolbar is OUTSIDE the polled #conns fragment (a 5s / ~1s swap must never wipe it) and renders
    # BEFORE the live table in the DOM (an un-polled shell sibling).
    assert "data-mf-conns-toolbar" not in fragment_html
    assert page_html.index("data-mf-conns-toolbar") < page_html.index('id="conns"')


async def test_reset_one_statistics_route(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/statistics/reset-one",
            content=urlencode([("role", "source"), ("channel_id", "IB_ACME_ADT")]),
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        # A malformed role bounces back to /ui without error (never a 500).
        r = await c.post(
            "/ui/statistics/reset-one",
            content=urlencode([("role", "bogus"), ("channel_id", "X")]),
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        # Cross-site rejected.
        r = await c.post("/ui/statistics/reset-one", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


# --- Phase-2 (server side) connection controls: dual-role bulk-control, reset-many, bulk purge ------
#
# The presentation (checkbox column + dropdown toolbar + app.js) lands in a later phase; these cover the
# SERVER endpoints + the escaping result/confirm page builders + the require-quiesced/dual-control seams.


def _rowkey(role: str, channel_id: str, destination: str = "") -> str:
    """Mint a checkbox _row_key exactly as pages.connections._row_key does (the server-minted identity
    the bulk endpoints decode): role|b64url(channel_id)|b64url(destination)."""

    def b(value: str) -> str:
        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")

    return f"{role}|{b(channel_id)}|{b(destination)}"


async def test_connection_details_route_renders(engine: Engine, tmp_path: Path) -> None:
    """#4a route end-to-end: GET /ui/connection/<name> must render (not 500). The events handler is
    called DIRECTLY (not over HTTP), so every FastAPI Query(...) param must be passed explicitly — a
    regression guard for the 'Query object is not iterable' 500. The name is the composite display
    string ('in1 ▸ in'); the page strips it to 'in1' for the heading."""
    await _start_two_out(engine, tmp_path)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/connection/in1 ▸ in")
        assert r.status_code == 200, r.text
        assert "<h1>in1</h1>" in r.text  # stripped display name in the heading


async def test_nav_status_route_operator_sees_health_and_alerts(engine: Engine) -> None:
    """GET /ui/nav-status: the metadata-only rollup the nav heart + bell poll (~15s, every page). A fresh
    engine on a temp DB is reachable (store OK) with no active alerts, so an operator (monitoring:read +
    diagnose) gets a valid health verdict AND an alerts object with count 0 — never a 500, never any PHI."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/nav-status")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["health"] in ("ok", "warn", "down")
        assert body["alerts"] == {"count": 0, "severity": None}


async def test_nav_status_route_hides_alert_count_without_diagnose(engine: Engine) -> None:
    """A viewer has monitoring:read (so the endpoint is allowed and health is reported) but NOT
    monitoring:diagnose — the alert count is withheld (alerts=null) so the bell hides itself rather than
    imply 'no alerts' to a viewer who can't see them. Guards the direct-call gate-bypass (the handler's own
    Depends(require(diagnose)) is skipped when called in-process, so the route gates on identity.has())."""
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/nav-status")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["health"] in ("ok", "warn", "down")
        assert body["alerts"] is None


async def test_nav_status_route_counts_active_alerts_worst_severity(engine: Engine) -> None:
    """With active alerts seeded, an operator's nav-status returns the count + the WORST severity (the bell
    colors by it) — exercising the non-empty diagnose-gated count path, not just the zero case."""
    await engine.store.upsert_alert_instance(
        event_type="queue_depth", connection="in1", severity="warning"
    )
    await engine.store.upsert_alert_instance(
        event_type="dead_letter", connection="in2", severity="critical"
    )
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/nav-status")
        assert r.status_code == 200, r.text
        assert r.json()["alerts"] == {
            "count": 2,
            "severity": "critical",
        }  # worst of warning+critical


async def test_nav_status_sees_a_critical_past_the_first_page_of_alerts(engine: Engine) -> None:
    """BACKLOG #1564, measured through the real route. The bell derived its count AND its severity from
    ``list_active_alerts(limit=200)``, so 200 warnings plus one OLDER critical reported
    ``count=200, severity=warning`` -- the critical fell off the newest-first page, and the label said
    nothing about having truncated. Both numbers now come from the store's scoped aggregate, so the
    page limit cannot bound either one."""
    await engine.store.upsert_alert_instance(
        event_type="dead_letter", connection="in1", severity="critical", now=1.0
    )
    for i in range(200):
        await engine.store.upsert_alert_instance(
            event_type=f"queue_depth_{i}", connection="in2", severity="warning", now=100.0 + i
        )
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/nav-status")
        assert r.status_code == 200, r.text
        assert r.json()["alerts"] == {"count": 201, "severity": "critical"}


# --- bulk-control (dual-role start/stop/restart over a selection) ----------------------------------


async def test_bulk_control_requires_control_permission(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # no connections:control
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _rowkey("source", "in1"))],
        )
        assert r.status_code == 403


async def test_bulk_control_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/connections/bulk-control",
            content=urlencode([("action", "stop")]),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        assert r.status_code == 403


async def test_bulk_control_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    # Confinement: the underlying JSON control route with only the cookie still 401s (header-only).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/connections/in1/stop")).status_code == 401


async def test_bulk_control_dispatches_both_roles_and_dedupes(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # 3 sels -> 2 unique control targets: an inbound (in1) + an outbound (out1) reached via TWO edge
        # rows (in1->out1, in2->out1), which dedupe to one control by destination.
        sels = [
            ("action", "stop"),
            ("sel", _rowkey("source", "in1")),
            ("sel", _rowkey("destination", "in1", "out1")),
            ("sel", _rowkey("destination", "in2", "out1")),
        ]
        r = await _post_pairs(c, "/ui/connections/bulk-control", sels)
        assert r.status_code == 200
        assert "2 target(s) processed" in r.text  # dedupe fired (not 3)
        assert "in1" in r.text and "out1" in r.text
    assert rr.inbound_running("in1") is False  # inbound stopped
    assert rr.outbound_running("out1") is False  # outbound paused (once)
    assert rr.outbound_running("out2") is True  # never selected


async def _start_dual_name(engine: Engine, tmp_path: Path) -> None:
    """Attach a connection name 'shared' that is BOTH an inbound AND an outbound (separate registry
    tables permit it), then start the runner — so the role-aware bulk-control disambiguation (a
    destination row targets the OUTBOUND, not the same-named inbound) is exercisable."""
    for name in ("shared_in", "shared_out"):
        (tmp_path / name).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "shared",
            ConnectionSpec(
                ConnectorType.FILE,
                {
                    "directory": str(tmp_path / "shared_in"),
                    "pattern": "*.hl7",
                    "poll_seconds": 0.05,
                },
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "shared",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "shared_out")}),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("shared", m)])
    engine.add_registry(reg)
    await engine.start()


async def test_bulk_control_same_name_source_and_destination_disambiguated(
    engine: Engine, tmp_path: Path
) -> None:
    # A name declared as BOTH an inbound and an outbound must be role-disambiguated: a destination row
    # for "shared" controls the OUTBOUND (not the same-named inbound, which the old inbound-first resolve
    # would have hit), and selecting BOTH the same-named source + destination dispatches to BOTH (two
    # distinct (role, name) targets, never deduped to one).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_dual_name(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # A destination row for "shared" → the OUTBOUND is paused; the same-named inbound is untouched.
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _rowkey("destination", "shared", "shared"))],
        )
        assert r.status_code == 200
        assert "1 target(s) processed" in r.text
    assert rr.outbound_running("shared") is False  # the OUTBOUND was controlled
    assert (
        rr.inbound_running("shared") is True
    )  # the same-named INBOUND was NOT (role disambiguation)

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # Both the same-named source AND destination selected → BOTH dispatched (not deduped to one).
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [
                ("action", "stop"),
                ("sel", _rowkey("source", "shared")),
                ("sel", _rowkey("destination", "shared", "shared")),
            ],
        )
        assert r.status_code == 200
        assert "2 target(s) processed" in r.text  # NOT deduped by bare name to one
    assert rr.inbound_running("shared") is False  # the inbound stopped this time
    assert rr.outbound_running("shared") is False  # the outbound stays paused


async def test_bulk_control_forbidden_target_does_not_abort_batch(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "op"), ["in1"], actor="admin")
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # A channel-scoped user can't control the shared outbound out1 (403), but their in-scope inbound
        # in1 still applies -- put the forbidden target FIRST to prove the batch is not aborted.
        sels = [
            ("action", "stop"),
            ("sel", _rowkey("destination", "in1", "out1")),
            ("sel", _rowkey("source", "in1")),
        ]
        r = await _post_pairs(c, "/ui/connections/bulk-control", sels)
        assert r.status_code == 200
        assert "403" in r.text and "out1" in r.text  # the forbidden target is enumerated
    assert rr.inbound_running("in1") is False  # the in-scope target still applied (batch continued)
    assert rr.outbound_running("out1") is True  # the forbidden target was NOT stopped


async def test_bulk_control_answers_an_in_scope_unknown_name_with_the_audited_403(
    engine: Engine, tmp_path: Path
) -> None:
    """BACKLOG #3031 finding 1: the bulk page always passes a ``role``, and the JSON routes never do,
    so this is the only test of the refusal on the role-keyed path.

    A scoped operator whose scope lists names no connection uses must get the same audited 403 for
    them as for an out-of-scope connection, on both roles. A 404 there would tell it which listed
    names exist (BACKLOG #2640). The mutant this kills applied the early refusal only when ``role``
    was ``None`` or the name was an outbound: both selections below then answered 404."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(
        await _uid(service, "op"), ["in1", "ghost_in", "ghost_out"], actor="admin"
    )
    await _start_two_out(engine, tmp_path)

    async def denied() -> list[str | None]:
        rows = await engine.store.list_audit(limit=100, action="auth.channel_denied")
        return sorted(r["channel_id"] for r in rows)

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [
                ("action", "stop"),
                ("sel", _rowkey("source", "ghost_in")),
                ("sel", _rowkey("destination", "in1", "ghost_out")),
            ],
        )
        assert r.status_code == 200, r.text
        assert r.text.count("403: not authorized for this connection") == 2, r.text
        assert "404" not in r.text and "no such connection" not in r.text
    assert await denied() == ["ghost_in", "ghost_out"]


async def test_bulk_routes_audit_a_scoped_malformed_name_without_writing_it(
    engine: Engine,
) -> None:
    """BACKLOG #3031 finding 5: a scoped actor's malformed name is still a recorded denial, but the
    row carries no channel. The name is caller-chosen text bounded only by the request body, and it
    used to be written whole to ``audit_log.channel_id``."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "op"), ["in1"], actor="admin")
    long_bad = "bad name " + "x" * 5000
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _rowkey("source", long_bad))],
        )
        assert r.status_code == 200, r.text
        assert "not applied: not a valid connection name" in r.text
        assert long_bad not in r.text
    rows = await engine.store.list_audit(limit=100, action="auth.channel_denied")
    assert [(row["actor"], row["channel_id"]) for row in rows] == [("op", None)]
    assert all("xxxxx" not in str(dict(row)) for row in rows)


async def test_a_failed_malformed_name_audit_does_not_abort_the_batch(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3031: the malformed-name denial is written outside the per-target capture, so a
    failed write must still leave the batch to run and render its result table."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "op"), ["in1"], actor="admin")
    await _start_two_out(engine, tmp_path)
    real = engine.store.record_audit

    async def failing(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "auth.channel_denied":
            raise RuntimeError("synthetic audit failure")
        return await real(action, *args, **kwargs)

    monkeypatch.setattr(engine.store, "record_audit", failing)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [
                ("action", "stop"),
                ("sel", _rowkey("source", "bad name")),
                ("sel", _rowkey("source", "in1")),
            ],
        )
    assert r.status_code == 200, r.text
    assert "not applied: not a valid connection name" in r.text
    assert "applied (running=False)" in r.text


async def test_bulk_control_bad_action_404(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "delete"), ("sel", _rowkey("source", "in1"))],
        )
        assert r.status_code == 404


async def test_bulk_control_labels_both_kinds_of_bad_selection(engine: Engine) -> None:
    # Two shapes, two fixed labels, neither reflecting the submitted bytes. An UNDECODABLE key gets
    # 'unrecognized selection'. A key that decodes to a name the connection-name rule refuses gets the
    # not-a-valid-name label (BACKLOG #1740) -- this used to render the name ESCAPED instead, which was
    # sound but weaker: the value now never reaches the page at all. That moved the escaping claim to
    # test_outcomes_table_escapes_a_name_it_is_handed below, where the page builder still owns it.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        xss = _rowkey("source", "<script>alert(1)</script>")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "start"), ("sel", "not-a-key"), ("sel", xss)],
        )
        assert r.status_code == 200
        assert "unrecognized selection" in r.text
        assert "not applied: not a valid connection name" in r.text
        # Neither raw NOR escaped: a refused name is not placed on the page in any form.
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;" not in r.text


def test_outcomes_table_escapes_a_name_it_is_handed() -> None:
    """The escaping claim, at the level that still owns it. The two bulk ROUTES now refuse a name
    carrying markup before it reaches a render, so a route-level test can no longer exercise this --
    but ``_outcomes_table`` escapes every target it is given, and deleting the route assertion
    without putting this here would have dropped the property silently."""
    from messagefoundry_webconsole.pages.connections import bulk_control_result, purge_result

    outcomes = [("<script>alert(1)</script>", "applied"), (None, "not applied")]
    for markup in (bulk_control_result("start", outcomes), purge_result("all", outcomes)):
        assert "<script>alert(1)</script>" not in markup
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markup
        assert "unrecognized selection" in markup


# --- reset-many (bulk counter reset) ---------------------------------------------------------------


async def test_reset_many_multi_target(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    # Seed NONZERO cumulative counters so a reset that fires is observable (not the near-tautological
    # zero-traffic case): one message bumps the source "in1" read counter and, once delivered, the
    # destination ("in1","out1") written counter.
    await engine.store.enqueue_message(
        channel_id="in1", raw=ADT, deliveries=[("out1", ADT)], now=10.0
    )
    item = (await engine.store.claim_ready(now=10.0))[0]
    await engine.store.mark_done(item.id, now=12.0)
    before = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert before.inbound["in1"].read == 1
    assert before.destinations[("in1", "out1")].written == 1

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # An undecodable sel FIRST proves it is DROPPED (skipped), never turning the batch into a no-op —
        # the source + destination targets after it still reset.
        sels = [
            ("sel", "not-a-key"),
            ("sel", _rowkey("source", "in1")),
            ("sel", _rowkey("destination", "in1", "out1")),
        ]
        r = await _post_pairs(c, "/ui/statistics/reset-many", sels)
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        cross = await c.post("/ui/statistics/reset-many", headers={"Sec-Fetch-Site": "cross-site"})
        assert cross.status_code == 403

    # BOTH targets' visible counters are now zeroed — the reset baseline captured the live counts.
    after = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert after.inbound["in1"].read == 0  # source reset
    assert (
        after.destinations[("in1", "out1")].written == 0
    )  # destination reset (despite the bad sel)


async def test_reset_many_requires_diagnose(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # no monitoring:diagnose
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await _post_pairs(c, "/ui/statistics/reset-many", [("sel", _rowkey("source", "in1"))])
        assert r.status_code == 403


# --- bulk purge: unlock confirm page + body-carrying step-up + dual-control POST --------------------


async def test_purge_confirm_registered_as_unlock(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    assert is_unlock_action(
        "/ui/connections/purge-confirm"
    )  # GET form the re-auth may 303-redirect to
    assert not is_safe_ui_action(
        "/ui/connections/purge-confirm"
    )  # never a body-less auto-retry POST
    assert not is_safe_ui_action("/ui/connections/purge-confirm?dest=x")  # query rejected


async def test_purge_confirm_requires_purge_permission(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # no messages:purge
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/connections/purge-confirm", params={"scope": "all"})
        assert r.status_code == 403


async def test_purge_confirm_channel_scoped_forbidden(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "op"), ["in1"], actor="admin")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # The page holds the purge proof (owner ruling 2026-10-13, #3241 R2).
        await _mint_action(c, "/ui/connections/purge-confirm")
        r = await c.get("/ui/connections/purge-confirm", params={"scope": "all", "dest": "out1"})
        assert (
            r.status_code == 403
        )  # a shared outbound spans channels -- a scoped user can't purge it


async def test_purge_confirm_lists_only_quiesced_and_validates_scope(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")  # quiesce out1; leave out2 running
    await _wait_quiesced(engine, "out1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # The page holds the purge proof (owner ruling 2026-10-13, #3241 R2).
        await _mint_action(c, "/ui/connections/purge-confirm")
        r = await c.get(
            "/ui/connections/purge-confirm",
            params=[("scope", "all"), ("dest", "out1"), ("dest", "out2")],
        )
        assert r.status_code == 200
        assert "out1" in r.text  # quiesced -> listed for confirmation
        assert "out2" not in r.text  # running -> dropped (re-derived from live quiescence)
        assert "/ui/connections/purge-bulk" in r.text  # the confirm form targets the bulk POST
        # A bad scope 404s (not a 422) -- matching the per-name purge route.
        bad = await c.get("/ui/connections/purge-confirm", params={"scope": "some", "dest": "out1"})
        assert bad.status_code == 404


async def test_purge_confirm_stale_stepup_redirects_to_reauth(engine: Engine) -> None:
    # require_mfa=False takes the MFA leg out of the gate, so the stale window below is what
    # redirects; without it this unenrolled fixture session is refused first with the SAME 303 and
    # the window measured nothing (BACKLOG #1850). Reasoning, and the third new-IP leg that stays
    # unpinned: the docstring of test_purge_stale_stepup_redirects_to_reauth (BACKLOG #1700).
    # -1 replaces a 0 that sat exactly on has_recent_step_up's `elapsed <= max_age` boundary.
    service = AuthService(engine.store, AuthSettings(require_mfa=False, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # negative window -> the fresh login is already stale
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True  # the MFA leg is NOT what refuses here
        assert await service.has_recent_step_up(tok) is False  # the stale window is
        r = await c.get("/ui/connections/purge-confirm", params={"scope": "all", "dest": "out1"})
        assert r.status_code == 303
        # The EXACT continuation: this GET passes no reauth_next, so _reauth_redirect falls back to
        # quote(request.url.path), which drops scope/dest -- the operator re-picks after re-auth.
        assert r.headers["location"] == "/ui/reauth?next=/ui/connections/purge-confirm"


async def test_purge_bulk_per_dest_409_unknown_and_scope(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")  # quiesced (empty queue -> purges 0)
    await _wait_quiesced(engine, "out1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, "/ui/connections/purge-confirm")  # vault BACKLOG #2625
        r = await _post_pairs(
            c,
            "/ui/connections/purge-bulk",
            [("scope", "all"), ("dest", "out1"), ("dest", "out2"), ("dest", "nope")],
        )
        assert r.status_code == 200
        assert "purged 0" in r.text  # out1 quiesced -> cleanly purged (nothing queued)
        assert "409" in r.text  # out2 running -> require-stopped, per-dest, batch not aborted
        assert "404" in r.text  # nope unknown -> captured, not fatal
        # Bad scope 404s BEFORE any fan-out (a directly-called purge_connection skips its own pattern).
        # The batch above spent its proof, so this one needs its own (vault BACKLOG #2625).
        await _mint_action(c, "/ui/connections/purge-confirm")
        bad = await _post_pairs(
            c, "/ui/connections/purge-bulk", [("scope", "wat"), ("dest", "out1")]
        )
        assert bad.status_code == 404


async def test_purge_bulk_dual_control_aggregates_pending(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")
    await _wait_quiesced(engine, "out1")
    app = create_app(
        engine,
        auth=service,
        approvals=ApprovalsSettings(enabled=True, operations=["connection_purge"]),
        serve_ui=True,
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await _cookie_login(c, "op")
        await _mint_action(c, "/ui/connections/purge-confirm")  # vault BACKLOG #2625
        r = await _post_pairs(c, "/ui/connections/purge-bulk", [("scope", "all"), ("dest", "out1")])
        assert r.status_code == 200
        assert (
            "held for approval" in r.text
        )  # dual-control per dest (out1 quiesced -> reaches the gate)


async def test_purge_bulk_refuses_a_markup_dest(engine: Engine) -> None:
    # A posted dest carrying markup is REFUSED by the connection-name rule and becomes its own outcome
    # row, so the value is never placed on the result page -- raw or escaped (BACKLOG #1740). It used to
    # be rendered escaped, which was sound but put an unvetted body value on the page; the page-builder
    # escaping it relied on is pinned by test_outcomes_table_escapes_a_name_it_is_handed.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, "/ui/connections/purge-confirm")  # vault BACKLOG #2625
        r = await _post_pairs(
            c, "/ui/connections/purge-bulk", [("scope", "all"), ("dest", "<script>x</script>")]
        )
        assert r.status_code == 200
        assert "not applied: not a valid connection name" in r.text
        assert "<script>x</script>" not in r.text
        assert "&lt;script&gt;" not in r.text
