# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui monitoring pages and write ops, queue purge, config deploy, the write-action registry and the
step-up-to-unlock primitive (BACKLOG #75 phases 1 and 3)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from _webui_support import (
    ADT,
    PW,
    _add,
    _boss_client,
    _client,
    _cookie_login,
    _mint_action,
    _service,
    _start_two_out,
    _wait_quiesced,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

# --- L1a: read-only monitoring pages (alerts + event log), BACKLOG #75 phase 1 ----------------


async def test_alerts_page_renders_for_operator(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/alerts")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        body = r.text
        assert "Active" in body and "Rules" in body
        assert "No active alerts." in body  # empty state (no seeded alert instances)


async def test_events_page_renders_for_viewer(engine: Engine) -> None:
    # VIEWER holds monitoring:read (not diagnose) — the event log is read-only monitoring, so it renders.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/events")
        assert r.status_code == 200
        assert "No events." in r.text  # empty state


async def test_alerts_requires_diagnose(engine: Engine) -> None:
    # The alerts page requires monitoring:diagnose (active instances). A VIEWER (read-only) is 403'd,
    # but the same VIEWER can still reach the event log — the read/diagnose split is enforced per page.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        assert (await c.get("/ui/alerts")).status_code == 403
        assert (await c.get("/ui/events")).status_code == 200


async def test_alerts_unauthenticated_redirects_to_login(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/alerts")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login"


def test_alerts_builder_escapes_hostile() -> None:
    # Alert metadata (connection label, scrubbed reason) is attacker-influenceable — never live markup.
    from messagefoundry.api.models import (
        AlertInstanceInfo,
        AlertInstanceList,
        AlertsConfig,
    )
    from messagefoundry_webconsole.pages import alerts

    instances = AlertInstanceList(
        alerts=[
            AlertInstanceInfo(
                id=1,
                event_type="queue_depth",
                connection="IB_ACME",
                severity="critical",
                status="open",
                first_seen=0.0,
                last_seen=0.0,
                count=3,
                reason="<script>alert(1)</script>",
            )
        ],
        total=1,
        worst_severity="critical",
    )
    config = AlertsConfig(
        webhook_configured=False,
        webhook_timeout=5.0,
        webhook_allowed_hosts=[],
        email_configured=False,
        email_smtp_port=25,
        email_use_tls=True,
        email_recipient_count=0,
        smtp_allowed_hosts=[],
        realert_seconds=300.0,
        rules=[],
    )
    html = str(alerts(instances, config, limit=200))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_events_builder_escapes_hostile() -> None:
    from messagefoundry.api.models import ConnectionEventInfo, ConnectionEventList
    from messagefoundry_webconsole.pages import events

    rows = [
        ConnectionEventInfo(
            id=1,
            ts=0.0,
            connection="IB_ACME",
            transport="mllp",
            direction="inbound",
            kind="conn_open",
            peer_host="<script>",
            reason="<b>boom</b>",
        )
    ]
    html = str(
        events(ConnectionEventList(total=1, limit=100, offset=0, before_id=None, events=rows))
    )
    assert "<b>boom</b>" not in html
    assert "&lt;b&gt;boom&lt;/b&gt;" in html
    assert "&lt;script&gt;" in html  # hostile peer_host escaped


# --- L1b: read-only engine status page, BACKLOG #75 phase 1 -----------------------------------


async def test_status_page_renders_for_viewer(engine: Engine) -> None:
    # monitoring:read is enough for the whole status page (engine/store/posture/cluster/DR).
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/status")
        assert r.status_code == 200
        body = r.text
        assert "Engine" in body and "Store" in body
        assert "Cluster" in body and "Disaster recovery" in body
        # Effective posture is surfaced (SQLite backend on the test engine).
        assert "sqlite" in body


async def test_status_unauthenticated_redirects_to_login(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/status")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login"


def test_status_builder_escapes_and_formats() -> None:
    # Server-controlled fields, but render through the escaping builders + confirm helper formatting.
    from messagefoundry.api.models import (
        ClusterNode,
        ClusterNodeList,
        ClusterStatus,
        DbInfo,
        DrStatus,
        EngineInfo,
        SecurityPosture,
        SystemStatus,
    )
    from messagefoundry_webconsole.pages import status

    sys_status = SystemStatus(
        engine=EngineInfo(
            version="0.2.14",
            uptime_seconds=90.0,
            pid=123,
            channels_total=2,
            channels_running=1,
            channels_stopped=1,
            outbox_by_status={"queued": 4},
        ),
        db=DbInfo(
            path="/data/mf.db",
            size_bytes=2_500_000,
            disk_free_bytes=10_000_000_000,
            journal_mode="wal",
            messages=10,
            events=5,
            audit=7,
        ),
    )
    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=True,
        key_source="auto",
        key_id="abc123",
        require_encryption=True,
        allow_unencrypted_phi=False,
        kex_groups="inherited (test read-out)",  # #338 report-only KEX read-out
    )
    cluster = ClusterStatus(
        node_id="n1", clustered=False, is_leader=True, role="single-node", config_version=0
    )
    nodes = ClusterNodeList(
        nodes=[
            ClusterNode(
                node_id="n1",
                host="<b>host</b>",
                pid=1,
                status="active",
                started_at=None,
                last_seen=None,
                is_leader=True,
            )
        ],
        leader_node_id="n1",
        lease_owner=None,
        lease_expires_at=None,
    )
    dr = DrStatus(enabled=False, active=False, threshold="P1", activation_mode="manual")
    from messagefoundry.api.models import ServiceStatusInfo

    svc = ServiceStatusInfo(enabled=True, state="running", service_name="MEFOR_Engine")
    html = str(status(sys_status, posture, cluster, nodes, dr, svc))
    assert "2.4 MiB" in html  # _bytes formatting
    assert "yes" in html and "single-node" in html  # _yn + role
    assert "<b>host</b>" not in html  # hostile node host escaped
    assert "&lt;b&gt;host&lt;/b&gt;" in html
    # #338: the report-only TLS key-exchange read-out row renders (label + the inherited value).
    assert "key-exchange" in html and "inherited" in html
    # L6a: the hosting-service badge renders the state + name.
    assert "Hosting service" in html and "MEFOR_Engine" in html and "running" in html
    # When reporting is off, the badge says so (no state leaked).
    off = ServiceStatusInfo(enabled=False, state="disabled", service_name="")
    assert "reporting is off" in str(status(sys_status, posture, cluster, nodes, dr, off))
    # BACKLOG #3189: a narrowed or blind loosenings list says so, even when it is empty.
    assert "Loosenings listed:" not in html
    narrowed = posture.model_copy(update={"loosenings_scope": "narrowed to your channel scope"})
    shown = str(status(sys_status, narrowed, cluster, nodes, dr, svc))
    assert "Loosenings listed: narrowed to your channel scope" in shown


# --- L0b: register_ui_action write-action registry (the extensible step-up allow-list) ---------


def test_register_ui_action_extends_the_stepup_allowlist() -> None:
    # A write-page lane extends the auto-retry allow-list by REGISTERING its action — never by editing
    # is_safe_ui_action. The migrated replay actions still resolve (behavior-preserving); a freshly
    # registered action becomes auto-retryable; the ".." reject still holds; registration is idempotent.
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import is_safe_ui_action, register_ui_action
    from messagefoundry_webconsole._auth import _UI_WRITE_ACTIONS

    # Migrated phase-0 replay actions are still allowed.
    assert is_safe_ui_action("/ui/messages/M1/replay")
    assert is_safe_ui_action("/ui/dead-letters/CH/OB_DEST/replay")

    # A not-yet-registered path is not auto-retryable.
    pat = r"^/ui/alerts/[^/?#]+/ack$"
    assert not is_safe_ui_action("/ui/alerts/7/ack")
    register_ui_action(pat, Permission.MONITORING_DIAGNOSE, label="Acknowledge an alert")
    assert is_safe_ui_action("/ui/alerts/7/ack")  # now allowed
    assert not is_safe_ui_action("/ui/alerts/7/../ack")  # .. still rejected

    # A body-carrying action (auto_retry=False) never rides the URL auto-retry.
    register_ui_action(
        r"^/ui/users/create$", Permission.USERS_MANAGE, auto_retry=False, label="Create a user"
    )
    assert not is_safe_ui_action("/ui/users/create")

    # Idempotent by pattern.
    register_ui_action(pat, Permission.MONITORING_DIAGNOSE, label="Acknowledge an alert")
    assert sum(1 for a in _UI_WRITE_ACTIONS if a.path_re.pattern == pat) == 1


# --- L3a: monitoring write ops (ack/resolve, stats reset, integrity, DR), BACKLOG #75 phase 3 -----


async def test_stats_reset_same_origin_reaches_handler(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/statistics/reset", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/status"


async def test_monitoring_write_requires_diagnose(engine: Engine) -> None:
    # A VIEWER (monitoring:read, no diagnose) is refused on every monitoring write — require_ui enforces
    # the permission the direct handler call would otherwise skip.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        h = {"Sec-Fetch-Site": "same-origin"}
        assert (await c.post("/ui/statistics/reset", headers=h)).status_code == 403
        assert (await c.post("/ui/alerts/1/ack", headers=h)).status_code == 403
        assert (await c.post("/ui/alerts/1/resolve", headers=h)).status_code == 403
        assert (await c.post("/ui/status/integrity-check", headers=h)).status_code == 403


async def test_monitoring_write_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/statistics/reset", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_integrity_check_renders_result(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/status/integrity-check", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200
        assert "Integrity check" in r.text and "OK" in r.text  # fresh SQLite passes quick_check


async def test_dr_activate_requires_dr_operate(engine: Engine) -> None:
    # OPERATOR does NOT hold dr:operate (only ADMINISTRATOR does) — the /ui DR route enforces it.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/dr/activate", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


@pytest.mark.parametrize("path", ["/ui/dr/activate", "/ui/dr/release"])
async def test_dr_routes_send_a_stale_step_up_to_reauth(engine: Engine, path: str) -> None:
    """Vault BACKLOG #2581: the console DR pair re-asserts the step-up its JSON twin carries. The
    /ui route calls the handler directly, which skips the handler's own gate.

    RED when the route goes back to ``require_ui``: the stale session then reaches the handler and
    answers 503 (this engine is not a DR standby) in place of the redirect.

    The re-auth lands on the status page, never back on the POST: a promotion or a release is not
    re-POSTed across a re-auth, so a link to ``/ui/reauth`` cannot carry one.

    require_mfa=False takes the MFA leg out, so the stale window is what redirects (BACKLOG #1851).
    """
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = AuthService(engine.store, AuthSettings(require_mfa=False, step_up_max_age_seconds=-1))
    await service.initialize()
    async with _boss_client(engine, service) as c:
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True
        assert await service.has_recent_step_up(tok) is False
        r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/status"
        assert is_unlock_action("/ui/status")
        assert not is_safe_ui_action(path) and not is_unlock_action(path)


@pytest.mark.parametrize("path", ["/ui/dr/activate", "/ui/dr/release"])
async def test_dr_routes_pass_a_fresh_step_up_through_to_the_handler(
    engine: Engine, path: str
) -> None:
    # The control for the test above: inside the window the login opened, the same administrator
    # reaches the handler, which answers 503 because this engine is not a DR standby.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 503
        assert "not a DR standby" in r.text


def test_alerts_builder_renders_write_controls() -> None:
    from messagefoundry.api.models import (
        AlertInstanceInfo,
        AlertInstanceList,
        AlertsConfig,
    )
    from messagefoundry_webconsole.pages import alerts

    instances = AlertInstanceList(
        alerts=[
            AlertInstanceInfo(
                id=42,
                event_type="queue_depth",
                connection="IB_ACME",
                severity="critical",
                status="open",
                first_seen=0.0,
                last_seen=0.0,
                count=1,
            )
        ],
        total=1,
        worst_severity="critical",
    )
    config = AlertsConfig(
        webhook_configured=False,
        webhook_timeout=5.0,
        webhook_allowed_hosts=[],
        email_configured=False,
        email_smtp_port=25,
        email_use_tls=True,
        email_recipient_count=0,
        smtp_allowed_hosts=[],
        realert_seconds=300.0,
        rules=[],
    )
    html = str(alerts(instances, config, limit=200))
    assert "/ui/alerts/42/ack" in html and "Ack" in html
    assert "/ui/alerts/42/resolve" in html and "Resolve" in html


def _alert_list(shown: int, total: int) -> object:
    """``shown`` active alert rows beside a store ``total`` that may differ from it (BACKLOG #1821)."""
    from messagefoundry.api.models import AlertInstanceInfo, AlertInstanceList

    return AlertInstanceList(
        alerts=[
            AlertInstanceInfo(
                id=i,
                event_type="queue_depth",
                connection="IB_ACME",
                severity="warning",
                status="open",
                first_seen=0.0,
                last_seen=0.0,
                count=1,
            )
            for i in range(1, shown + 1)
        ],
        total=total,
        worst_severity="warning" if total else None,
    )


def test_alerts_page_states_the_count_when_the_list_is_capped() -> None:
    """BACKLOG #1821: the bell reports every active alert, and the page beneath it listed the newest
    ``limit`` with no sign that more existed. The line is the capped-listing footer, not a pager:
    ``GET /alerts`` takes no offset, so a Next link would lead nowhere."""
    from messagefoundry_webconsole.pages import alerts

    html = str(alerts(_alert_list(3, 214), None, limit=3))
    assert "3 of 214 alert(s) shown, capped at the newest 3." in html
    assert 'class="pager"' not in html and "offset=" not in html


def test_alerts_page_count_line_claims_no_cap_when_nothing_is_missing() -> None:
    """The #1821 control: a complete list says so and states no cap. ``total`` is a second read
    beside the rows, so a smaller one (a concurrent resolve) is floored rather than printed."""
    from messagefoundry_webconsole.pages import alerts

    complete = str(alerts(_alert_list(3, 3), None, limit=200))
    assert "3 of 3 alert(s) shown." in complete and "capped" not in complete
    raced = str(alerts(_alert_list(3, 2), None, limit=200))
    assert "3 of 3 alert(s) shown." in raced and "3 of 2" not in raced
    # A total above a window that is NOT full is rows that arrived between the two reads.
    grew = str(alerts(_alert_list(5, 7), None, limit=200))
    assert "5 of 7 alert(s) shown." in grew and "capped" not in grew
    empty = str(alerts(_alert_list(0, 0), None, limit=200))
    assert "No active alerts." in empty and "alert(s) shown" not in empty


# --- L3b: queue purge (step-up + dual-control), BACKLOG #75 phase 3 -------------------------------


async def test_purge_requires_purge_permission(engine: Engine) -> None:
    # A VIEWER (no messages:purge) is refused before any step-up/CSRF logic.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post(
            "/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 403


async def test_purge_rejects_cross_site(engine: Engine) -> None:
    # A fresh login is a recent step-up, so require_ui_step_up passes and the cross-site guard fires.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_purge_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/connections/OB_X/purge")).status_code == 401


async def test_purge_after_login_stepup_reaches_handler(engine: Engine) -> None:
    # A same-origin operator (stepped up by the fresh login) passes auth + step-up + CSRF and reaches
    # purge_connection, which 404s on the unknown outbound — proving the gate lets it through.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, "/ui/connections/purge-confirm")  # vault BACKLOG #2625
        r = await c.post(
            "/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_purge_action_not_registered_in_stepup_allowlist(engine: Engine) -> None:
    # Vault BACKLOG #2764: the per-name purge was once an auto-retry continuation, but no page renders
    # a form to it, so the re-auth auto-submit had become its only browser entry point. Even with the
    # /ui app mounted (every registration fired), the re-auth flow may not continue to it.
    from messagefoundry_webconsole import is_safe_ui_action, lookup_ui_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    for scope in ("all", "top"):
        assert not is_safe_ui_action(f"/ui/connections/OB_X/purge/{scope}")
        assert lookup_ui_action(f"/ui/connections/OB_X/purge/{scope}") is None
    # The confirm page the console actually purges through stays an unlock continuation.
    confirm = lookup_ui_action("/ui/connections/purge-confirm")
    assert confirm is not None and confirm.unlock


async def test_purge_stale_stepup_redirects_to_reauth(engine: Engine) -> None:
    """A stale step-up window must stop the single-connection purge before it reaches the handler.

    BACKLOG #1700. ``require_ui_step_up``'s own docstring names THREE checks it re-applies: MFA
    satisfied, a recent password step-up, and new-client-IP contextual risk. This drives the SECOND.
    The MFA leg is driven by ``test_ui_mfa_denial_audit.py`` (the purge is a row on its factory-shape
    table); the new-IP leg is driven nowhere, and saying so is the point of counting them here.

    The twin of ``test_purge_after_login_stepup_reaches_handler``: that one proves the gate LETS a
    stepped-up operator through, which stays true with the gate deleted, so it can only ever fail
    open. This is the arm that fails closed.

    RED when the route's gate is SWAPPED for one without the freshness check -- measured with plain
    ``require_ui``, which reaches ``purge_connection`` and 404s on the unknown outbound. Stated as a
    swap rather than a deletion because deleting the ``Depends`` also deletes the ``identity`` the
    handler passes on, so the route would fail to build and prove nothing.

    ``require_mfa=False`` is a control, not a convenience: it makes ``mfa_satisfied`` True so the MFA
    leg cannot be what redirects. The third, new-IP leg is inert because login and request share
    the test client's one address, so the session never sees a new host. That default was flipped
    to True under BACKLOG #288, so this test also pins ``admin_new_ip_step_up=False``; the sibling
    tests that cite this docstring rely on the shared address alone. The two asserts below pin the
    split that is pinnable today.
    """
    # -1, not 0: has_recent_step_up compares `elapsed <= max_age`, so 0 needs elapsed to be strictly
    # positive and a backwards clock step would flip it. -1 is unconditionally stale, and is what the
    # sibling stale-window tests in this file already use.
    service = AuthService(
        engine.store,
        AuthSettings(require_mfa=False, admin_new_ip_step_up=False, step_up_max_age_seconds=-1),
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # negative window -> the fresh login is already stale
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True  # the MFA leg is NOT what refuses here
        assert await service.has_recent_step_up(tok) is False  # the stale window is
        r = await c.post(
            "/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "same-origin"}
        )
        # The LOCATION is the assertion that carries the property: a SUCCESSFUL purge also answers
        # 303 (RedirectResponse("/ui")), so the status alone would not say the gate refused. The
        # exact continuation, not just the /ui/reauth prefix: the purge is NOT a registered
        # continuation (vault BACKLOG #2764), so the operator lands back on the confirm page the
        # console purges through, never on an auto-submitted purge.
        assert r.headers.get("location") == "/ui/reauth?next=/ui/connections/purge-confirm", (
            "a stale step-up was not sent to re-auth carrying the purge confirm page"
        )
        assert r.status_code == 303


async def test_console_purge_writes_the_connection_purge_row(
    engine: Engine, tmp_path: Path
) -> None:
    """BACKLOG #1641, the console path: a /ui purge leaves a ``connection_purge`` outcome row.

    The row is written in ``purge_connection``'s body so both planes carry it; the JSON plane is
    pinned in tests/test_api.py. The console reaches that handler BY REFERENCE across the seam, and
    its own gate audits denials only, so before the handler wrote the row a browser purge left no
    trace at all. This pins that the console call really lands on the audited body.

    RED when the ``record_audit("connection_purge", ...)`` call is removed from ``purge_connection``.
    The 303 alone cannot carry this: a purge that cancelled and wrote nothing redirects the same way.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")
    await _wait_quiesced(engine, "out1")
    # Queued AFTER the stop, so the paused lane cannot deliver it and the purge has one row to cancel.
    await engine.store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[("out1", ADT)])
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # a fresh login is a recent step-up
        await _mint_action(c, "/ui/connections/purge-confirm")  # vault BACKLOG #2625
        assert await engine.store.list_audit(action="connection_purge") == []  # control
        r = await c.post(
            "/ui/connections/out1/purge/all", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui", r.text

    rows = await engine.store.list_audit(action="connection_purge")
    assert len(rows) == 1, f"expected one connection_purge row, got {len(rows)}"
    assert rows[0]["actor"] == "op"
    assert json.loads(str(rows[0]["detail"])) == {
        "connection": "out1",
        "scope": "all",
        "cancelled": 1,
    }
    # The console hands purge_connection its live request, so the row names the browser's host too.
    # "127.0.0.1" is httpx ASGITransport's default peer, which _client leaves in place.
    assert rows[0]["client"] == "127.0.0.1"


def test_connections_fragment_renders_selection_checkbox() -> None:
    from messagefoundry.api.models import ConnectionRow
    from messagefoundry_webconsole.pages import connections_fragment
    from messagefoundry_webconsole.pages.connections import _row_key

    dest = ConnectionRow(
        role="destination",
        channel_id="IB_ACME_ADT",
        channel_name="ACME ADT",
        destination="OB_ARCHIVE",
        name="OB_ARCHIVE",
        status="stopped",
        direction="out",
        method="File",
        peer=None,
        port=None,
        queue_depth=0,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=None,
        written=0,
        backlog_seconds=None,
        delivered_age_seconds=None,
        paused=True,
    )
    html = str(connections_fragment([dest]))
    # Per-row selection checkbox keyed by the stable _row_key, carrying live role/state data-* for the
    # toolbar's JS partitioning; data-paused (paused AND quiesced) gates purge eligibility.
    assert "data-mf-conns-cb" in html
    assert f'value="{_row_key(dest)}"' in html
    assert 'data-role="destination"' in html
    assert 'data-status="stopped"' in html
    assert 'data-paused="1"' in html
    assert 'data-dest="OB_ARCHIVE"' in html


def test_connections_fragment_failed_but_paused_row_is_purge_eligible() -> None:
    from messagefoundry.api.models import ConnectionRow
    from messagefoundry_webconsole.pages import connections_fragment

    # A destination whose lane FAILED to build (collapsed status "failed") but is ALSO operator-paused-
    # AND-quiesced: the checkbox still carries data-paused="1", so the toolbar keeps it purge-eligible.
    # Purge eligibility (paused) is INDEPENDENT of the collapsed display status — never gated behind it.
    row = ConnectionRow(
        role="destination",
        channel_id="IB_ACME_ADT",
        channel_name="ACME ADT",
        destination="OB_ARCHIVE",
        name="OB_ARCHIVE",
        status="failed",
        direction="out",
        method="File",
        peer=None,
        port=None,
        queue_depth=0,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=None,
        written=0,
        backlog_seconds=None,
        delivered_age_seconds=None,
        paused=True,
    )
    html = str(connections_fragment([row]))
    assert 'data-status="failed"' in html  # collapsed status is failed
    assert 'data-paused="1"' in html  # yet still purge-eligible (paused independent of status)
    # Select-all header checkbox present; the fragment keeps its #conns id (the poll target).
    assert "data-mf-conns-all" in html
    assert 'id="conns"' in html
    # The old per-row control/purge/reset forms are gone (they moved to the un-polled toolbar).
    assert "/ui/connections/OB_ARCHIVE/purge/" not in html
    assert "/ui/statistics/reset-one" not in html
    assert 'class="ctl"' not in html and 'class="ctls"' not in html


# --- L3c: config-deploy (reload the startup graph, #26 bright line), BACKLOG #75 phase 3 ----------


async def test_config_page_renders(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/config")
        assert r.status_code == 200
        body = r.text
        assert "Reload configuration" in body
        assert "VS Code extension" in body  # the #26 bright-line note (authoring stays in the IDE)
        # The bright line: no filesystem picker / config-dir input on the page.
        assert 'name="config_dir"' not in body and 'type="file"' not in body


async def test_config_reload_requires_deploy_permission(engine: Engine) -> None:
    # A VIEWER (no config:deploy) is refused before any step-up/CSRF logic.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post("/ui/config/reload", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_config_reload_rejects_cross_site(engine: Engine) -> None:
    # A deployment user (config:deploy) with a fresh-login step-up still fails a cross-site POST.
    service = await _service(engine)
    await _add(service, "deployer", Role.DEPLOYMENT)
    async with _client(engine, service) as c:
        await _cookie_login(c, "deployer")
        r = await c.post("/ui/config/reload", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_config_reload_registered_in_stepup_allowlist(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    assert is_safe_ui_action("/ui/config/reload")
    assert not is_safe_ui_action("/ui/config/reload?dir=/etc")  # query rejected (no path injection)


def test_the_reload_result_page_says_what_the_reload_left_undone() -> None:
    """BACKLOG #3015: the page shows a degraded step and a changed trust anchor that takes a
    restart. Before it, both reached only the JSON answer. The control is a clean reload."""
    from messagefoundry.api.models import ReloadResult
    from messagefoundry_webconsole import pages

    def render(**fields: object) -> str:
        counts = {"inbound": 1, "outbound": 1, "routers": 1, "handlers": 1, "running": True}
        return str(pages.reload_result(ReloadResult.model_validate({**counts, **fields})))

    clean = render(restart_required=[])
    assert "Restart the engine" not in clean and "follow-on step failed" not in clean
    restart = render(restart_required=["[auth].ad_tls_ca_cert_file"])
    assert "Restart the engine" in restart and "[auth].ad_tls_ca_cert_file" in restart
    degraded = render(degraded=True, failures=["reference_sync"])
    assert "follow-on step failed: reference_sync" in degraded
    assert "Restart the engine" not in render(restart_required=None)  # a dry run did not check


async def test_write_action_method_matches_its_continuation(engine: Engine) -> None:
    # R1 (refined for L0c): the re-auth continuation branches on a registered action's flags, so the HTTP
    # method serving each action MUST match its continuation style, or the branch is a hazard:
    #   * an ``auto_retry`` action is a body-less POST the re-auth re-POSTs — it must never be a
    #     side-effecting GET (CSRF / idempotency).
    #   * an ``unlock`` action is a GET admin form page the re-auth 303-GET-redirects to — it must never
    #     be a POST (a GET-redirect to a state-changing POST would be an open-POST gadget).
    from messagefoundry_webconsole._auth import _UI_WRITE_ACTIONS

    service = await _service(engine)
    app = create_app(engine, auth=service, serve_ui=True)
    ui_routes = [
        (route.path, getattr(route, "methods", set()))
        for route in app.routes
        if getattr(route, "path", "").startswith("/ui")
    ]
    for action in _UI_WRITE_ACTIONS:
        for path, methods in ui_routes:
            if not action.path_re.fullmatch(path):
                continue
            if action.auto_retry:
                assert "GET" not in methods, (
                    f"{path} is a GET but matches auto_retry action {action.path_re.pattern}"
                )
            if action.unlock:
                assert "POST" not in methods, (
                    f"{path} is a POST but matches unlock action {action.path_re.pattern}"
                )


# --- L0c: step-up-to-unlock primitive (confirm-after-step-up for body-carrying admin forms) --------
#
# The stateless confirm-after-step-up path: an admin FORM GET is registered as an ``unlock`` action, so
# a stale step-up 303s to /ui/reauth and — after a successful re-verification — 303-GET-redirects BACK
# to the form (which re-opens inside a fresh window). The body-carrying POST (incl. a create-user
# password) is then submitted in a single request that never crosses /ui/reauth, so no body — and no
# password — is ever preserved across the redirect. These tests exercise the primitive in isolation
# (PR1); the L4a admin pages that register real unlock actions land in PR2.

_UNLOCK_PAT = r"^/ui/testunlock/[^/?#]+$"  # a synthetic unlock form path, namespaced to the tests
_UNLOCK_LABEL = "Open the test unlock form"


def test_is_unlock_action_gate() -> None:
    # is_unlock_action is the GET-form analogue of is_safe_ui_action: it matches ONLY registered
    # ``unlock`` entries, is ``..``-guarded, and is disjoint from the auto-retry (POST) allow-list.
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import (
        is_safe_ui_action,
        is_unlock_action,
        register_ui_action,
    )

    assert not is_unlock_action("/ui/testunlock/new")  # not yet registered
    register_ui_action(
        _UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True, label=_UNLOCK_LABEL
    )
    assert is_unlock_action("/ui/testunlock/new")  # now an unlock target
    assert not is_safe_ui_action("/ui/testunlock/new")  # but NOT an auto-retry (POST) target
    assert not is_unlock_action("/ui/testunlock/../new")  # .. still rejected
    assert not is_unlock_action("/ui/testunlock/a/b")  # two segments — anchored pattern rejects
    assert not is_unlock_action(None) and not is_unlock_action("")
    # A replay auto_retry action is not an unlock target (the two allow-lists are disjoint).
    assert not is_unlock_action("/ui/messages/M1/replay")
    assert is_safe_ui_action("/ui/messages/M1/replay")


def test_register_ui_action_rejects_auto_retry_and_unlock() -> None:
    # A /ui action can be a body-less POST auto-retry OR a GET-form unlock, never both — the re-auth
    # continuation branches on exactly these flags, so an action that is both is a mis-registration.
    import re

    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import register_ui_action
    from messagefoundry_webconsole._auth import UiWriteAction

    with pytest.raises(ValueError, match="auto_retry"):
        register_ui_action(
            r"^/ui/bad$", Permission.USERS_MANAGE, auto_retry=True, unlock=True, label="Bad"
        )
    with pytest.raises(ValueError, match="auto_retry"):
        UiWriteAction(
            re.compile(r"^/ui/bad$"), Permission.USERS_MANAGE, True, True, True, label="Bad"
        )


async def test_reauth_form_renders_for_unlock_next(engine: Engine) -> None:
    # The re-auth form accepts an ``unlock`` next (a GET admin form), exactly as it accepts a replay next.
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import register_ui_action

    register_ui_action(
        _UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True, label=_UNLOCK_LABEL
    )
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        r = await c.get("/ui/reauth", params={"next": "/ui/testunlock/new"})
        assert r.status_code == 200
        assert 'name="password"' in r.text and 'name="next"' in r.text
        assert "/ui/testunlock/new" in r.text  # the unlock target rides the hidden next field


async def test_reauth_get_unlock_redirects_after_stepup(engine: Engine) -> None:
    # THE primitive: a successful step-up whose next is an ``unlock`` form 303-GET-redirects BACK to the
    # form (so it re-opens fresh) — it does NOT render the POST auto-submit page. No body is carried.
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import register_ui_action

    register_ui_action(
        _UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True, label=_UNLOCK_LABEL
    )
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")  # a fresh login satisfies the password step-up
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/testunlock/new", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/testunlock/new"
        # It is a GET redirect, NOT the auto-submit POST page — the password never rides a re-POST.
        assert "data-autosubmit" not in r.text


async def test_reauth_post_rejects_unregistered_next(engine: Engine) -> None:
    # The POST-side gate end-to-end: a next that is neither a registered auto-retry POST nor a
    # registered unlock form bounces to /ui BEFORE any credential is examined — even with a valid
    # password in the body (anti open-redirect / open-POST on the branch PR1 touched).
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        for bad in ("https://evil.example/x", "//evil.example", "/ui/unregistered", "/ui"):
            r = await c.post(
                "/ui/reauth",
                data={"next": bad, "password": PW},
                headers={"Sec-Fetch-Site": "same-origin"},
            )
            assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_reauth_failed_stepup_rerenders_form_not_redirect(engine: Engine) -> None:
    # A WRONG password on an unlock next must re-render the reauth form (with the hidden next), never
    # 303 to the unlock target — the GET-redirect happens only after a successful re-verification.
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import register_ui_action

    register_ui_action(
        _UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True, label=_UNLOCK_LABEL
    )
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/testunlock/new", "password": "wrong-password-xyz"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200  # the form again, not a redirect
        assert "Incorrect password." in r.text
        assert 'name="next"' in r.text and "/ui/testunlock/new" in r.text


async def _stale_window_service(engine: Engine) -> AuthService:
    """A service whose step-up window is always stale, so every step-up POST is refused and its
    gate issues the continuation. -1 rather than 0 for the reason the purge test below gives."""
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_new_ip_step_up=False,
            step_up_max_age_seconds=-1,
            admin_write_min_interval_seconds=0,
        ),
    )
    await service.initialize()
    return service


_REPLAY_ALL = "/ui/dead-letters/replay-all"
_REPLAY_ONE = "/ui/messages/abc/replay"
_SFS_SAME = {"Sec-Fetch-Site": "same-origin"}


async def _reauth(c: httpx.AsyncClient, next_path: str) -> httpx.Response:
    return await c.post("/ui/reauth", data={"next": next_path, "password": PW}, headers=_SFS_SAME)


def _nothing_ran(r: httpx.Response, label: str) -> bool:
    """The re-auth succeeded and said, by name, that the action did not run (no auto-submit)."""
    return (
        r.status_code == 200
        and "Nothing ran" in r.text
        and label in r.text
        and "data-autosubmit" not in r.text
        and '<a href="/ui">Return to the console</a>' in r.text
    )


async def test_reauth_auto_submits_an_issued_continuation_once(engine: Engine) -> None:
    """Vault BACKLOG #2764: the continuation the step-up gate issued auto-submits ONCE.

    RED when POST /ui/reauth auto-submits without consuming the record (the second POST would
    auto-submit again), or when the gate stops recording what it hands out (the first would not)."""
    service = await _stale_window_service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        refused = await c.post(_REPLAY_ALL, headers=_SFS_SAME)
        assert refused.status_code == 303
        assert refused.headers["location"] == f"/ui/reauth?next={_REPLAY_ALL}"
        form = await c.get(refused.headers["location"])
        assert "you to: " in form.text
        assert "Replay all dead letters" in form.text  # the page NAMES the action
        assert "nothing will run" not in form.text
        first = await _reauth(c, _REPLAY_ALL)
        assert first.status_code == 200
        assert "data-autosubmit" in first.text  # the same-origin auto-submit POST form
        assert f'action="{_REPLAY_ALL}"' in first.text
        assert "Replay all dead letters" in first.text  # the continuation names it too
        second = await _reauth(c, _REPLAY_ALL)
        assert _nothing_ran(second, "Replay all dead letters")


async def test_reauth_does_not_auto_submit_a_next_the_server_did_not_issue(engine: Engine) -> None:
    """Vault BACKLOG #2764, the finding itself: a typed, bookmarked or clicked
    ``/ui/reauth?next=<registered destructive action>`` (Sec-Fetch-Site: none) still lets the operator
    re-authenticate, says nothing will run, and ends on a page saying nothing ran, with no
    auto-submit."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        form = await c.get(
            "/ui/reauth", params={"next": _REPLAY_ALL}, headers={"Sec-Fetch-Site": "none"}
        )
        assert form.status_code == 200
        assert "Replay all dead letters" in form.text
        assert "nothing will run" in form.text
        assert "data-autosubmit" not in form.text
        assert _nothing_ran(await _reauth(c, _REPLAY_ALL), "Replay all dead letters")


async def test_reauth_no_purpose_grant_for_an_unissued_factor_next(engine: Engine) -> None:
    """A forged ``next`` naming an ADR 0077 action-bound lane mints NO grant for it (#2764): the
    grant's purpose comes from ``next``, so it would otherwise attach to the forged action."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _reauth(c, "/ui/account/sessions/revoke-others")
        assert _nothing_ran(r, "Sign out all your other sessions")
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.has_action_step_up(tok, "session_terminate") is False


async def test_another_session_cannot_consume_an_issued_continuation(engine: Engine) -> None:
    """The record is keyed by the session that was refused, so a second session of the SAME user
    presenting the same ``next`` gets no auto-submit, and the first session's record survives."""
    service = await _stale_window_service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as a, _client(engine, service) as b:
        await _cookie_login(a, "op")
        await _cookie_login(b, "op")
        refused = await a.post(_REPLAY_ALL, headers=_SFS_SAME)
        assert refused.status_code == 303
        assert _nothing_ran(await _reauth(b, _REPLAY_ALL), "Replay all dead letters")
        own = await _reauth(a, _REPLAY_ALL)
        assert own.status_code == 200 and "data-autosubmit" in own.text


async def test_a_sessions_other_continuations_follow_its_rotation(engine: Engine) -> None:
    """Two tabs of one session, each refused for its own action, share one cookie. The first tab's
    re-auth rotates the token, so the second tab's issued entry must move with it, or its
    re-auth would end with nothing run after a page that said it would continue."""
    service = await _stale_window_service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post(_REPLAY_ALL, headers=_SFS_SAME)).status_code == 303
        assert (await c.post(_REPLAY_ONE, headers=_SFS_SAME)).status_code == 303
        before = c.cookies.get("mf_session")
        tab_a = await _reauth(c, _REPLAY_ALL)
        assert tab_a.status_code == 200 and "data-autosubmit" in tab_a.text
        assert c.cookies.get("mf_session") != before  # the password leg rotated the session
        tab_b = await _reauth(c, _REPLAY_ONE)
        assert tab_b.status_code == 200 and f'action="{_REPLAY_ONE}"' in tab_b.text


async def test_an_unlock_reauth_in_one_tab_does_not_strand_another_tabs_action(
    engine: Engine,
) -> None:
    """The unlock branch returns its 303 too, and the password leg rotated the session on the way.
    The other tab's issued action must have followed that rotation before the branch returned."""
    service = await _stale_window_service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        assert (await c.post(_REPLAY_ALL, headers=_SFS_SAME)).status_code == 303
        unlock = await _reauth(c, "/ui/users/new")
        assert unlock.status_code == 303 and unlock.headers["location"] == "/ui/users/new"
        tab_a = await _reauth(c, _REPLAY_ALL)
        assert tab_a.status_code == 200 and "data-autosubmit" in tab_a.text


def test_the_issued_table_prunes_lapsed_sessions_and_evicts_the_least_recent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prune drops a session whose newest entry lapsed even when a re-key moved it behind a live
    one, and the session cap drops the least recently issued session, not the newest."""
    from messagefoundry_webconsole import _auth

    clock = [1000.0]
    monkeypatch.setattr(_auth.time, "monotonic", lambda: clock[0])
    table = _auth._IssuedContinuations()
    table.issue("a", "/ui/x")  # deadline 1300
    clock[0] = 1100.0
    table.issue("b", "/ui/x")  # deadline 1400
    clock[0] = 1150.0
    table.rekey("a", "a2")  # a2 now sits BEHIND b, still with deadline 1300
    clock[0] = 1350.0
    table.issue("c", "/ui/x")  # prunes: a2 lapsed although it is not at the front
    assert hash_token("a2") not in table._sessions
    assert table.issued("b", "/ui/x")
    cap = _auth._REAUTH_CONTINUATION_SESSIONS_MAX
    for n in range(cap):
        table.issue(f"s{n}", "/ui/x")
    assert not table.issued("b", "/ui/x")  # the least recently issued went first
    assert table.issued(f"s{cap - 1}", "/ui/x")


async def test_a_same_site_refusal_issues_no_continuation(engine: Engine) -> None:
    """A sibling host's POST carries the SameSite=Strict cookie, so a gate can see it. A browser that
    sends fetch metadata is refused by the /ui fetch-metadata middleware before any route runs; one
    that sends only ``Origin`` (an older browser) reaches the route. On an MFA-PENDING session the
    factor gate refuses it before ``require_ui`` asserts provenance, so the origin check inside the
    issuing itself is what keeps that page from minting the record that authorises an auto-submit.
    The same-origin control shows the instrument can see an issue."""
    from messagefoundry_webconsole._auth import continuation_issued

    service = AuthService(engine.store, AuthSettings(require_mfa=True, admin_new_ip_step_up=False))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        tok = c.cookies.get("mf_session")
        assert tok is not None and await service.mfa_satisfied(tok) is False  # pending
        fetch_metadata = await c.post(_REPLAY_ALL, headers={"Sec-Fetch-Site": "same-site"})
        assert fetch_metadata.status_code == 403  # the middleware, before any route
        assert continuation_issued(tok, _REPLAY_ALL) is False
        cross = await c.post(_REPLAY_ALL, headers={"Origin": "http://sibling.t"})
        assert cross.status_code == 303
        assert cross.headers["location"] == f"/ui/reauth?next={_REPLAY_ALL}"  # the MFA refusal
        assert continuation_issued(tok, _REPLAY_ALL) is False
        own = await c.post(_REPLAY_ALL, headers=_SFS_SAME)
        assert own.status_code == 303
        assert continuation_issued(tok, _REPLAY_ALL) is True


def test_the_issued_table_bounds_each_session() -> None:
    """A session that keeps getting refused holds at most the per-session cap, oldest dropped, so
    it cannot crowd out another session's entries."""
    from messagefoundry_webconsole import _auth

    table = _auth._IssuedContinuations()
    cap = _auth._REAUTH_CONTINUATIONS_PER_SESSION
    table.issue("other-session", "/ui/messages/keep/replay")
    for n in range(cap + 5):
        table.issue("noisy-session", f"/ui/messages/{n}/replay")
    assert not table.issued("noisy-session", "/ui/messages/0/replay")
    assert table.issued("noisy-session", f"/ui/messages/{cap + 4}/replay")
    assert table.issued("other-session", "/ui/messages/keep/replay")
