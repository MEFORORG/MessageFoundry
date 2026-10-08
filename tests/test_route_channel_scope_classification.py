# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every route of the engine API is classified for per-channel scope (BACKLOG #2627, ASVS 8.2.2).

THE GAP THIS CLOSES. Per-channel access is applied by hand in each route. The monitoring-plane test
(``tests/test_monitoring_scope_doc_drift.py``) executes a FIXED list of routes, so a new route that
forgot the scope lines was covered by nothing. Here every route of a ``create_app()`` app must sit in
exactly one class of :data:`ROUTES`, and a route nobody classified reds the run.

Calling every route generically was rejected: it needs fabricated parameters for each one and breaks
on every signature change. So the table is the contract, and the live probe below EXECUTES the part
of it that can be measured without inventing anything:

* every ``scoped`` GET with no path parameter, called by a channel-scoped caller and by an
  all-channels caller with the same roles, the second as the per-route positive control;
* every by-id message route, aimed at a message on a channel the scoped caller cannot see, which
  must answer 404.

THE CLASSES.

* ``scoped`` -- channel-bearing, and the route narrows or refuses per channel.
* ``not_channel_bearing`` -- returns and changes nothing per channel: the caller's own account,
  aggregate counters, node-level state, or the caller's own objects.
* ``administrator_only`` -- gated by a permission only the Administrator role holds, and an
  Administrator is always all-channels, so no caller of it is channel-scoped. Checked, not asserted:
  :func:`test_administrator_only_routes_admit_no_scoped_caller`.
* ``known_unscoped_1152`` -- channel-bearing and NOT narrowed, tracked under BACKLOG #1152.
* ``unscoped_unfiled`` -- channel-bearing and NOT narrowed, and on no backlog row this change could
  find. Listed so the gap is visible rather than silent. Filing them is not this test's job.

NOT-DEPLOYED beta: an unscoped route here is a gap a first deployment would carry, not a live
exposure.

SCOPE OF THE WALK. The default ``create_app()`` app: no web console (``serve_ui``), no OpenAPI pages.
The ``/ui`` routes are clients of these handlers through the console seam and are not classified here.
"""

from __future__ import annotations

import functools
import time

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    CUSTOM_ROLE_FORBIDDEN_PERMISSIONS,
    Permission,
)
from messagefoundry.auth.service import (
    STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
    STEP_UP_ACTION_MESSAGE_EXPORT,
    STEP_UP_ACTION_MESSAGE_RESEND,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from scripts.security.route_gates import route_rows
from tests._admin_account import create_local_user_chosen

# The shared fixture and helpers, imported rather than copied, so this probe and the monitoring-plane
# probe stand on one seeded estate: inbounds IB_A and IB_B, and the shared outbound OB_X.
from tests.test_monitoring_scope_doc_drift import (  # noqa: F401
    PW,
    _client,
    _login,
    engine,
)

SCOPED = "scoped"
NOT_CHANNEL_BEARING = "not_channel_bearing"
ADMINISTRATOR_ONLY = "administrator_only"
KNOWN_UNSCOPED_1152 = "known_unscoped_1152"
UNSCOPED_UNFILED = "unscoped_unfiled"

_CLASSES = {SCOPED, NOT_CHANNEL_BEARING, ADMINISTRATOR_ONLY, KNOWN_UNSCOPED_1152, UNSCOPED_UNFILED}

#: Every route of the default app, keyed ``"METHOD /path"``, with its class and why. A dict key
#: appears once, so a route cannot sit in two classes; the walk below checks it is in one.
ROUTES: dict[str, tuple[str, str]] = {
    # --- the caller's own session and account ---------------------------------------------------
    "GET /auth/providers": (NOT_CHANNEL_BEARING, "the sign-in providers, before any identity"),
    "POST /auth/login": (NOT_CHANNEL_BEARING, "opens the caller's own session"),
    "POST /auth/negotiate": (NOT_CHANNEL_BEARING, "opens the caller's own session"),
    "POST /auth/logout": (NOT_CHANNEL_BEARING, "ends the caller's own session"),
    "GET /auth/me": (NOT_CHANNEL_BEARING, "the caller's own identity"),
    "POST /me/password": (NOT_CHANNEL_BEARING, "the caller's own credential"),
    "POST /me/notify-email": (NOT_CHANNEL_BEARING, "the caller's own notice address"),
    "POST /me/reauth": (NOT_CHANNEL_BEARING, "the caller's own step-up"),
    "POST /auth/mfa-verify": (NOT_CHANNEL_BEARING, "the caller's own second factor"),
    "GET /me/mfa": (NOT_CHANNEL_BEARING, "the caller's own second factor"),
    "POST /me/mfa/enroll": (NOT_CHANNEL_BEARING, "the caller's own second factor"),
    "POST /me/mfa/confirm": (NOT_CHANNEL_BEARING, "the caller's own second factor"),
    "DELETE /me/mfa": (NOT_CHANNEL_BEARING, "the caller's own second factor"),
    "GET /me/sessions": (NOT_CHANNEL_BEARING, "the caller's own sessions"),
    "GET /me/security-events": (
        NOT_CHANNEL_BEARING,
        "the caller's own authentication events; a channel named there is one the caller itself "
        "asked for (the username keying is a separate #1152 limb, not a channel-scope one)",
    ),
    "DELETE /me/sessions/{session_id}": (NOT_CHANNEL_BEARING, "the caller's own session"),
    "DELETE /me/sessions": (NOT_CHANNEL_BEARING, "the caller's own sessions"),
    # --- roles and users ------------------------------------------------------------------------
    "GET /roles": (NOT_CHANNEL_BEARING, "role definitions: permissions, no channel"),
    "GET /roles/custom": (NOT_CHANNEL_BEARING, "role definitions: permissions, no channel"),
    "POST /roles/custom": (ADMINISTRATOR_ONLY, "users:manage"),
    "PUT /roles/custom/{role_id}": (ADMINISTRATOR_ONLY, "users:manage"),
    "DELETE /roles/custom/{role_id}": (ADMINISTRATOR_ONLY, "users:manage"),
    "GET /users": (
        UNSCOPED_UNFILED,
        "returns every account's channel_scope to a users:read holder, and users:read can be "
        "minted into a custom role, which can be channel-scoped",
    ),
    "GET /users/{user_id}/permissions": (NOT_CHANNEL_BEARING, "roles and permissions, no channel"),
    "POST /users": (ADMINISTRATOR_ONLY, "users:manage"),
    "POST /users/directory": (ADMINISTRATOR_ONLY, "users:manage"),
    "PATCH /users/{user_id}": (ADMINISTRATOR_ONLY, "users:manage"),
    "DELETE /users/{user_id}": (ADMINISTRATOR_ONLY, "users:manage"),
    "DELETE /users/{user_id}/sessions": (ADMINISTRATOR_ONLY, "users:manage"),
    "PUT /users/{user_id}/roles": (ADMINISTRATOR_ONLY, "users:manage"),
    "POST /users/{user_id}/reset-password": (ADMINISTRATOR_ONLY, "users:manage"),
    "POST /users/{user_id}/reset-mfa": (ADMINISTRATOR_ONLY, "users:manage"),
    "GET /users/{user_id}/federated-identity": (ADMINISTRATOR_ONLY, "users:manage"),
    "PUT /users/{user_id}/federated-identity": (ADMINISTRATOR_ONLY, "users:manage"),
    "DELETE /users/{user_id}/federated-identity": (ADMINISTRATOR_ONLY, "users:manage"),
    "GET /users/{user_id}/channel-scope": (ADMINISTRATOR_ONLY, "users:manage"),
    "PUT /users/{user_id}/channel-scope": (ADMINISTRATOR_ONLY, "users:manage"),
    "GET /ad-group-map": (ADMINISTRATOR_ONLY, "users:manage"),
    "PUT /ad-group-map": (ADMINISTRATOR_ONLY, "users:manage"),
    "GET /ad-group-scope-map": (ADMINISTRATOR_ONLY, "users:manage"),
    "PUT /ad-group-scope-map": (ADMINISTRATOR_ONLY, "users:manage"),
    # --- audit ----------------------------------------------------------------------------------
    "GET /audit": (KNOWN_UNSCOPED_1152, "#1152: the audit trail is not narrowed to the caller"),
    "GET /audit/export": (KNOWN_UNSCOPED_1152, "#1152: same read as GET /audit, as a file"),
    # --- health, AI, posture --------------------------------------------------------------------
    "GET /health": (NOT_CHANNEL_BEARING, "a liveness boolean"),
    "GET /ai/policy": (NOT_CHANNEL_BEARING, "the AI policy for this environment"),
    "POST /ai/chat": (NOT_CHANNEL_BEARING, "sends code to the assistant, never a message body"),
    "GET /security/posture": (
        UNSCOPED_UNFILED,
        "names connections in its loosenings and static_credential_hops, to any "
        "monitoring:read holder, not narrowed",
    ),
    # --- connections ----------------------------------------------------------------------------
    "GET /channels": (SCOPED, "narrowed to the caller's inbounds"),
    "GET /connections": (SCOPED, "narrowed; shared outbounds suppressed"),
    "POST /connections/{name}/start": (SCOPED, "scope checked before the name is looked up"),
    "POST /connections/{name}/stop": (SCOPED, "scope checked before the name is looked up"),
    "POST /connections/{name}/restart": (SCOPED, "scope checked before the name is looked up"),
    "POST /connections/{name}/flag": (
        KNOWN_UNSCOPED_1152,
        "#1152: the connection-flag object check is not built",
    ),
    "GET /connections/{name}/metadata": (SCOPED, "403 outside the caller's scope"),
    "POST /connections/{name}/test": (SCOPED, "403 outside the caller's scope"),
    "POST /connections/{name}/test-credential": (SCOPED, "403 outside the caller's scope"),
    "POST /connections/{name}/purge": (SCOPED, "a scoped caller cannot purge a shared outbound"),
    "POST /statistics/reset": (SCOPED, "each target is checked against the caller's scope"),
    "GET /events": (SCOPED, "narrowed; outbound events dropped"),
    "GET /connections/{name}/events": (SCOPED, "403 outside the caller's scope"),
    # --- alerts ---------------------------------------------------------------------------------
    "GET /alerts/active": (SCOPED, "narrowed to the caller's connections"),
    "POST /alerts/{alert_id}/ack": (SCOPED, "the instance is read through the caller's scope"),
    "POST /alerts/{alert_id}/resolve": (SCOPED, "the instance is read through the caller's scope"),
    "POST /alerts/{alert_id}/suspend": (SCOPED, "the instance is read through the caller's scope"),
    "POST /alerts/{alert_id}/resume": (SCOPED, "the instance is read through the caller's scope"),
    "POST /alerts/test-email": (NOT_CHANNEL_BEARING, "sends a fixed test notice"),
    "GET /alerts/rules": (KNOWN_UNSCOPED_1152, "#1152: every rule's connection, unfiltered"),
    # --- dead letters and approvals -------------------------------------------------------------
    "GET /dead-letters": (SCOPED, "narrowed to the caller's channels"),
    "POST /dead-letters/replay": (SCOPED, "the requested channel is checked against the scope"),
    "GET /approvals": (ADMINISTRATOR_ONLY, "approvals:approve"),
    "POST /approvals/{approval_id}/approve": (ADMINISTRATOR_ONLY, "approvals:approve"),
    "POST /approvals/{approval_id}/reject": (ADMINISTRATOR_ONLY, "approvals:approve"),
    "POST /approvals/{approval_id}/resolve": (ADMINISTRATOR_ONLY, "approvals:approve"),
    # --- config ---------------------------------------------------------------------------------
    "POST /config/reload": (
        UNSCOPED_UNFILED,
        "reloads every connection's config for a config:deploy holder, which the deployment role "
        "can be while channel-scoped; no ruling says whether it should be narrowed",
    ),
    "GET /config/provenance": (NOT_CHANNEL_BEARING, "a fingerprint and a commit, no connection"),
    # --- messages -------------------------------------------------------------------------------
    "GET /messages": (SCOPED, "allowed_channels on the store read"),
    "GET /messages/search": (SCOPED, "allowed_channels on the store read"),
    "POST /messages/search": (SCOPED, "allowed_channels on the store read"),
    "GET /messages/export": (SCOPED, "allowed_channels, then a per-row scoped read"),
    "POST /messages/export": (SCOPED, "allowed_channels, then a per-row scoped read"),
    "GET /messages/{message_id}": (SCOPED, "get_scoped_message"),
    "GET /messages/{message_id}/raw": (SCOPED, "get_scoped_message"),
    "GET /messages/{message_id}/attachments/{attachment_id}": (SCOPED, "get_scoped_message"),
    "GET /messages/{message_id}/responses": (SCOPED, "get_scoped_message"),
    "GET /messages/{message_id}/outbound": (SCOPED, "get_scoped_message"),
    "POST /messages/{message_id}/replay": (SCOPED, "get_scoped_message"),
    "POST /messages/{message_id}/resend": (SCOPED, "get_scoped_message, then the target's scope"),
    "POST /messages/{message_id}/edit-resend": (SCOPED, "get_scoped_message, then the target"),
    # --- uploads and presets: the caller's own objects ------------------------------------------
    "POST /uploads": (NOT_CHANNEL_BEARING, "the caller's own file, not a channel row"),
    "GET /uploads": (NOT_CHANNEL_BEARING, "owner-scoped files, not channel rows"),
    "GET /uploads/{file_id}/messages": (NOT_CHANNEL_BEARING, "an owner-scoped file's contents"),
    "POST /uploads/{file_id}/messages/search": (NOT_CHANNEL_BEARING, "an owner-scoped file"),
    "POST /uploads/{file_id}/resend": (SCOPED, "the target inbound is checked against the scope"),
    "DELETE /uploads/{file_id}": (NOT_CHANNEL_BEARING, "an owner-scoped file"),
    "GET /search/presets": (NOT_CHANNEL_BEARING, "the caller's own presets"),
    "POST /search/presets": (NOT_CHANNEL_BEARING, "the caller's own presets"),
    "DELETE /search/presets/{preset_id}": (NOT_CHANNEL_BEARING, "the caller's own presets"),
    "GET /search/layered": (SCOPED, "allowed_channels on the store read"),
    # --- monitoring -----------------------------------------------------------------------------
    "GET /stats": (NOT_CHANNEL_BEARING, "aggregate queue counters, measured global"),
    "GET /metrics": (KNOWN_UNSCOPED_1152, "#1152: the metrics-exposition scoping"),
    "GET /metrics/history": (NOT_CHANNEL_BEARING, "aggregate queue counters, measured global"),
    "GET /graph/edges": (SCOPED, "the subgraph reachable from the caller's inbounds"),
    "GET /status": (SCOPED, "failed-inbound names narrowed; the counts are aggregates"),
    "WS /ws/stats": (SCOPED, "connections_html narrowed; outbox_by_status is an aggregate"),
    # --- logging, service, cluster, DR ----------------------------------------------------------
    "GET /logging/level": (NOT_CHANNEL_BEARING, "a log level name"),
    "PATCH /logging/level": (NOT_CHANNEL_BEARING, "a log level name"),
    "GET /logs/tail": (KNOWN_UNSCOPED_1152, "#1152: the log tail is not narrowed"),
    "GET /service/identity": (NOT_CHANNEL_BEARING, "echoes the certificate's principal"),
    "GET /cluster/status": (NOT_CHANNEL_BEARING, "node-level state"),
    "GET /cluster/nodes": (NOT_CHANNEL_BEARING, "node-level state"),
    "POST /cluster/stepdown": (ADMINISTRATOR_ONLY, "cluster:control"),
    "GET /dr/status": (NOT_CHANNEL_BEARING, "node-level state"),
    "GET /service/status": (NOT_CHANNEL_BEARING, "node-level state"),
    "POST /dr/activate": (ADMINISTRATOR_ONLY, "dr:operate"),
    "POST /dr/release": (ADMINISTRATOR_ONLY, "dr:operate"),
    "POST /status/integrity-check": (NOT_CHANNEL_BEARING, "a database integrity verdict"),
}


@functools.cache
def _routes_of_the_app() -> dict[str, tuple[str, ...]]:
    """``"METHOD /path"`` to the permissions it requires, for every route of a default app."""
    rows: dict[str, tuple[str, ...]] = {}
    for row in route_rows(create_app()):
        rows[f"{row.method} {row.path}"] = row.permissions
    return rows


def test_every_route_is_classified_exactly_once() -> None:
    """A route added to the app reds this until someone decides its class, and a route removed
    reds it until its row goes. The dict key makes two classes for one route impossible."""
    app_routes = set(_routes_of_the_app())
    unclassified = sorted(app_routes - ROUTES.keys())
    stale = sorted(ROUTES.keys() - app_routes)
    assert not unclassified, (
        f"routes with no channel-scope class (add them to ROUTES): {unclassified}"
    )
    assert not stale, f"ROUTES names routes the app no longer has: {stale}"
    assert {cls for cls, _reason in ROUTES.values()} <= _CLASSES
    assert all(reason.strip() for _cls, reason in ROUTES.values())


def test_the_walk_sees_every_class_it_claims() -> None:
    """The positive control for the walk: an instrument that found no route would leave every row
    stale and say nothing about coverage, so pin that it finds routes in every class."""
    app_routes = _routes_of_the_app()
    assert len(app_routes) >= 100
    for cls in _CLASSES:
        assert any(ROUTES[key][0] == cls for key in app_routes if key in ROUTES), cls


def test_known_unscoped_rows_cite_1152() -> None:
    for key, (cls, reason) in ROUTES.items():
        if cls == KNOWN_UNSCOPED_1152:
            assert "#1152" in reason, key


def test_administrator_only_routes_admit_no_scoped_caller() -> None:
    """``administrator_only`` is a claim about who can call the route, so check it: the route needs
    a permission no custom role may hold and no built-in role but Administrator holds. An
    Administrator resolves to every channel, so no caller of the route is channel-scoped."""
    admin_only = {
        p
        for p in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
        if {r for r, perms in BUILTIN_ROLE_PERMISSIONS.items() if p in perms}
        == {Role.ADMINISTRATOR}
    }
    assert admin_only, "no permission is administrator-only any more; this class cannot hold"
    app_routes = _routes_of_the_app()
    for key, (cls, _reason) in ROUTES.items():
        if cls != ADMINISTRATOR_ONLY:
            continue
        needs = {Permission(p) for p in app_routes[key]}
        assert needs & admin_only, f"{key} is not gated by an administrator-only permission"


# =====================================================================================================
# The live probe: a channel-scoped caller against an all-channels caller with the same roles
# =====================================================================================================

#: The roles both probe callers hold: every built-in role but Administrator, which is always
#: all-channels and so could never be the scoped caller.
_PROBE_ROLES = [r.value for r in Role if r is not Role.ADMINISTRATOR]

#: Synthetic MSH-only HL7 with a control id the probe can find in a body. No PID, no PHI.
_ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|{ctrl}|P|2.5.1\r"

#: The query a scoped GET needs before it answers 200 at all. The export's ``ids`` and the layered
#: search's preset id exist only once the test has made them, so ``query`` below adds those two.
#: Every other scoped GET is called bare.
_QUERY: dict[str, tuple[tuple[str, str], ...]] = {
    "/messages/search": (("field_path", "MSH-10"),),
}

#: Scoped GETs on which this fixture gives the all-channels caller nothing to see, so the scoped
#: side's silence there proves nothing. Named so the gap is visible; the test checks the set exactly.
_QUIET_HERE = {
    "/status": "no inbound failed to start, so there is no failed-inbound name to narrow",
}

#: What the scoped caller may legitimately see, and what it must never see. ``OB_X`` is the shared
#: outbound both inbounds deliver to: docs/SECURITY.md says a scoped caller sees no shared outbound
#: at all, so its name is a leak on these reads even though IB_A's own message goes there.
#: ``OB_DEAD`` takes only IB_B's dead-lettered delivery. IB_B's message ids are added at run time.
#: The probe seeds from these names, so the self-check below reads what the probe actually uses.
#: Nothing asserts the scoped caller SEES its in-scope data; an over-narrowed empty 200 passes.
_IN_CHANNEL, _IN_CTRL = "IB_A", "CTRLAAA"
_OUT_CHANNEL, _SHARED_OUT, _DEAD_OUT, _OUT_CTRL = "IB_B", "OB_X", "OB_DEAD", "CTRLBBB"
_IN_SCOPE_TOKENS = (_IN_CHANNEL, _IN_CTRL)
_OUT_OF_SCOPE_TOKENS = (_OUT_CHANNEL, _SHARED_OUT, _DEAD_OUT, _OUT_CTRL)


async def _probe_user(service: AuthService, username: str, scope: list[str]) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=_PROBE_ROLES,
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    await service.set_channel_scope(user_id, scope, actor="admin")


def _scoped_get_paths() -> list[str]:
    return sorted(
        key.split(" ", 1)[1]
        for key, (cls, _reason) in ROUTES.items()
        if cls == SCOPED and key.startswith("GET ") and "{" not in key
    )


def _by_id_message_routes() -> list[str]:
    return sorted(
        key
        for key, (cls, _reason) in ROUTES.items()
        if cls == SCOPED and "/messages/{message_id}" in key
    )


async def test_scoped_routes_are_measured_against_a_live_app(engine: Engine) -> None:  # noqa: F811
    """Every ``scoped`` GET with no path parameter shows the scoped caller no out-of-scope marker,
    while the all-channels caller, on the same request, sees one; and every by-id message route
    answers 404 for a message on a channel outside the scoped caller's scope."""
    ids = {
        channel: await engine.store.enqueue_message(
            channel_id=channel,
            raw=_ADT.format(ctrl=ctrl),
            deliveries=[(_SHARED_OUT, _ADT.format(ctrl=ctrl))],
            control_id=ctrl,
            now=time.time(),
        )
        for channel, ctrl in ((_IN_CHANNEL, _IN_CTRL), (_OUT_CHANNEL, _OUT_CTRL))
    }
    # One dead letter on IB_B, through a destination nothing else uses, so /dead-letters has a row
    # the all-channels caller sees and the scoped caller must not.
    dead_mid = await engine.store.enqueue_message(
        channel_id=_OUT_CHANNEL,
        raw=_ADT.format(ctrl=_OUT_CTRL),
        deliveries=[(_DEAD_OUT, _ADT.format(ctrl=_OUT_CTRL))],
        control_id=_OUT_CTRL,
        now=time.time(),
    )
    out_of_scope = (*_OUT_OF_SCOPE_TOKENS, ids[_OUT_CHANNEL], dead_mid)
    assert len(out_of_scope) >= 6
    (dead,) = await engine.store.claim_ready(now=time.time(), destination_name=_DEAD_OUT)
    await engine.store.mark_failed(dead.id, "probe", RetryPolicy(max_attempts=1), now=time.time())
    # The pacing floor is a separate control with its own tests; off here so a probe that sends
    # several writes in a row measures scope, not the throttle.
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, admin_write_rate_limit_enabled=False)
    )
    await service.initialize()
    await _probe_user(service, "scoped", ["IB_A"])
    await _probe_user(service, "wide", [ALL_CHANNELS])

    async with _client(engine, service) as c:
        s = await _login(c, "scoped")
        w = await _login(c, "wide")
        presets: dict[str, str] = {}
        for who, headers in (("scoped", s), ("wide", w)):
            r = await c.post(
                "/search/presets",
                headers=headers,
                json={"name": "probe", "criteria": {"content": "MSH"}},
            )
            assert r.status_code == 200, (who, r.status_code, r.text)
            presets[who] = r.json()["id"]

        def query(path: str, who: str) -> httpx.QueryParams:
            if path == "/messages/export":
                return httpx.QueryParams([("ids", ids["IB_A"]), ("ids", ids["IB_B"])])
            if path == "/search/layered":
                return httpx.QueryParams([("presets", presets[who])])
            return httpx.QueryParams(_QUERY.get(path, ()))

        paths = _scoped_get_paths()
        assert "/messages" in paths and "/channels" in paths, paths  # the walk found the reads
        quiet: set[str] = set()

        def prove(headers: dict[str, str], action: str) -> None:
            # Export and the two resend lanes take a single-use proof bound to the action (vault
            # BACKLOG #2625). This probe measures channel scope, so it mints the proof directly
            # rather than re-authenticating.
            token = headers["Authorization"].removeprefix("Bearer ")
            service._grant_action_step_up(hash_token(token), action)

        for path in paths:
            if path == "/messages/export":
                prove(s, STEP_UP_ACTION_MESSAGE_EXPORT)
                prove(w, STEP_UP_ACTION_MESSAGE_EXPORT)
            rs = await c.get(path, headers=s, params=query(path, "scoped"))
            rw = await c.get(path, headers=w, params=query(path, "wide"))
            assert rw.status_code == 200, (path, rw.status_code, rw.text[:300])
            assert rs.status_code == 200, (path, rs.status_code, rs.text[:300])
            leaked = [m for m in out_of_scope if m in rs.text]
            assert not leaked, f"{path} showed a channel-scoped caller {leaked}"
            if not any(m in rw.text for m in out_of_scope):
                quiet.add(path)
        # A count can leak where no name does: a total over the whole estate beside a narrowed page.
        # The fixture fits on one page, so each caller's total must equal the rows it was shown.
        for path, rows_key in (("/dead-letters", "dead_letters"), ("/messages", "messages")):
            for headers in (s, w):
                body = (await c.get(path, headers=headers)).json()
                assert body["total"] == len(body[rows_key]), (path, body["total"])
        assert quiet == _QUIET_HERE.keys(), (
            "the scoped GETs this fixture cannot discriminate changed; a route that is quiet here "
            f"proves nothing about scope: {sorted(quiet)}"
        )

        # --- by-id message routes: 404 for a message outside the scope, 200-class for the control
        bodies: dict[str, dict[str, object]] = {
            "resend": {"to": "OB_X", "idempotency_key": "probe-1"},
            "edit-resend": {"raw": _ADT.format(ctrl="CTRLEDIT"), "idempotency_key": "probe-2"},
        }
        bound = {
            "resend": STEP_UP_ACTION_MESSAGE_RESEND,
            "edit-resend": STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
        }
        routes = _by_id_message_routes()
        assert len(routes) == 8, routes
        for key in routes:
            method, template = key.split(" ", 1)
            path = template.replace("{message_id}", ids["IB_B"]).replace(
                "{attachment_id}", "0" * 64
            )
            body = bodies.get(path.rsplit("/", 1)[-1])
            if (action := bound.get(path.rsplit("/", 1)[-1])) is not None:
                prove(s, action)
                prove(w, action)
            before = await _denials_on_ib_b(engine)
            rs = await c.request(method, path, headers=s, json=body)
            assert rs.status_code == 404, (key, rs.status_code, rs.text[:300])
            assert rs.json() == {"detail": f"no such message: {ids['IB_B']}"}, key
            # The refusal is on the record, not only answered: exactly one row for this request.
            assert await _denials_on_ib_b(engine) == before + 1, key
            # The control: the same request from the all-channels caller is not the scope's 404. It
            # may still be refused for its own reason (no attachment, nothing to replay), never as
            # "no such message".
            rw = await c.request(method, path, headers=w, json=body)
            assert f"no such message: {ids['IB_B']}" not in rw.text, (key, rw.status_code)


async def _denials_on_ib_b(engine: Engine) -> int:  # noqa: F811
    rows = await engine.store.list_audit(limit=1000, actor="scoped", action="auth.channel_denied")
    return sum(1 for r in rows if r["channel_id"] == "IB_B")


def test_the_probe_markers_cannot_match_an_in_scope_token() -> None:
    """A marker hit must mean the out-of-scope estate. Checked on the tuples the probe uses, both
    ways: no out-of-scope token is a substring of an in-scope one, or the reverse."""
    for out in _OUT_OF_SCOPE_TOKENS:
        for ok in _IN_SCOPE_TOKENS:
            assert out not in ok and ok not in out, (out, ok)
