# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L1b: read-only engine status page (engine/store metrics, security posture, cluster + DR state).

Also serves ``GET /ui/nav-status`` — the metadata-only health rollup polled by the nav's engine-health
heart + alerts bell (app.js, every page). Worst issue wins; it never raises (a health probe that crashed
would blank the nav — a store failure IS the "down" signal).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    ClusterNodeList,
    ClusterStatus,
    DrStatus,
    SystemStatus,
)
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    require_ui,
)

_log = logging.getLogger(__name__)

# Free-space thresholds for the engine-health heart (absolute — total disk size isn't exposed, only free
# bytes). The store's DB grows on this drive, so "DB space" and "local drive space" collapse to one check on
# the default/embedded backend. Sensible defaults; tune if a deployment wants a different floor.
_DISK_WARN_BYTES = 5 * 1024**3  # < 5 GiB free → warn (orange)
_DISK_CRIT_BYTES = 1 * 1024**3  # < 1 GiB free → critical (blinking red)

# ADR 0014 operator-alert severities (store.py: "info|warning|critical"), ranked worst-last for the bell.
_SEVERITY_RANK = {"info": 1, "warning": 2, "critical": 3}


# At most this many failed inbounds are named in the heart's reason; the rest become "and N more".
# The reason renders into a title= attribute, so an estate-wide outage must not produce a tooltip
# hundreds of names long.
_MAX_NAMED_FAILURES = 3


def _worst_severity(severities: list[str]) -> str | None:
    """The highest-ranked severity among active alerts, or ``None`` for an empty list (drives the bell's
    color: critical→red, warning→orange, info→accent, none→gray)."""
    worst: str | None = None
    rank = 0
    for s in severities:
        r = _SEVERITY_RANK.get(s, 0)
        if r > rank:
            rank, worst = r, s
    return worst


def _failed_inbound_reason(count: int, names: list[str]) -> str:
    """The heart's tooltip for ``count`` failed inbounds, naming the ones the caller may see.

    ``names`` is the caller-visible SUBSET (``EngineInfo.channels_failed_names``), so it can be
    shorter than ``count`` or empty — a channel-scoped operator still learns that something is down
    without learning whose feed it is. Connection NAMES only: the engine's failure reason is a raw
    exception string, and this text lands in a ``title=`` attribute.
    """
    shown = names[:_MAX_NAMED_FAILURES]
    if count == 1:
        # The scoped caller's single hidden failure takes the second form: "1 inbound connections"
        # is what a shared plural head would produce, and an operator reading a tooltip notices.
        if shown:
            return f"inbound {shown[0]} failed to start"
        return "1 inbound connection failed to start"
    head = f"{count} inbound connections failed to start"
    if not shown:
        return head
    hidden = count - len(shown)
    listed = ", ".join(shown)
    return f"{head}: {listed}, and {hidden} more" if hidden > 0 else f"{head}: {listed}"


def _derive_health(
    sysinfo: SystemStatus | None,
    dr: DrStatus | None,
    cluster: ClusterStatus | None,
    nodes: ClusterNodeList | None,
) -> tuple[str, str | None]:
    """Roll infrastructure signals into one engine-health verdict — ``ok`` < ``warn`` < ``down``, worst
    issue wins — plus a short reason for the worst issue (the heart's tooltip). Pure: takes already-fetched
    models (``None`` = that probe failed / not applicable), so it's unit-testable without an engine.

    - ``sysinfo is None``  → store unreachable → **down** (the strongest "unhealthy").
    - disk free (DB drive, and log drive if metered) < 1 GiB → **down**, < 5 GiB → **warn**. A
      measured 0 still alarms; an UNMEASURABLE drive (``disk_free_bytes is None``) is not compared,
      because "I could not measure this" is not "this is full" (BACKLOG #1563).
    - a configured log directory the engine could not measure at all → **warn**. Unlike the DB
      figure, which is legitimately unmeasurable on a remote server backend, a null log figure has
      only one cause: a path the operator configured that could not be read.
    - server DB connection pool saturated (``idle == 0``) → **warn**.
    - running on the DR failover box (``dr.active``) → **warn**; a clustered engine with no leader → **down**.
    - any deployed inbound that failed to start → **warn**, naming it (BACKLOG #1741).
    - zero deployed inbounds on a STARTED engine → **warn** (BACKLOG #1741).

    The last two are why connection state belongs here at all: without them the heart read ``ok``
    over an empty configuration and over an inbound that never got its port, while the dashboard row
    beside it already said ``failed``. Both are ``warn``, not ``down`` — an ADR 0031 start failure is
    isolated by design, so the rest of the graph is genuinely still serving.
    """
    issues: list[tuple[int, str]] = []  # (level, reason); 1 = warn, 2 = down
    if sysinfo is None:
        issues.append((2, "store unreachable"))
    else:
        eng = sysinfo.engine
        # Both connection rules are appended FIRST, and ``reason`` below takes the first issue at
        # the worst level — so at equal severity a connection problem wins the tooltip over low
        # disk, a saturated pool or DR-active. Deliberate: a feed that is not listening is the more
        # actionable message. Insertion order IS the warn-level tie-break; moving these moves it.
        if eng.channels_failed:
            issues.append(
                (1, _failed_inbound_reason(eng.channels_failed, eng.channels_failed_names))
            )
        # channels_total (DEPLOYED inbounds), never channels_running: a cluster standby binds no
        # listeners by design, so running == 0 is correct there and keying on it would paint every
        # standby permanently warn. uptime_seconds is the started gate — /status reports 0.0 until
        # engine.started_at is set, and an engine that has not started yet is not "listening on
        # nothing", it is still coming up.
        if eng.channels_total == 0 and eng.uptime_seconds > 0:
            issues.append((1, "no inbound connections deployed"))
        frees: list[tuple[str, int | None]] = [("db", sysinfo.db.disk_free_bytes)]
        if sysinfo.logs is not None:
            frees.append(("logs", sysinfo.logs.disk_free_bytes))
        for label, free in frees:
            if free is None:
                # Unmeasurable (BACKLOG #1563), and what that MEANS differs by drive, so the two are
                # not treated alike. A DB figure is None on the server backends as well, where the
                # engine is not meant to see that disk at all -- it cannot tell "not applicable"
                # from "the probe broke", so it claims nothing rather than pin a permanent warning
                # on every healthy Postgres and SQL Server deployment. A LOG drive has no
                # not-applicable case: the operator configured that path, so a null there is always
                # a failed probe on a directory that should have been readable, and going quiet
                # about it would just trade #1563's loud wrong answer for a silent one.
                if label == "logs":
                    issues.append((1, "log directory missing or unreadable"))
                continue
            if free < _DISK_CRIT_BYTES:
                issues.append((2, f"low disk ({label}): {free / 1024**3:.1f} GiB free"))
            elif free < _DISK_WARN_BYTES:
                issues.append((1, f"low disk ({label}): {free / 1024**3:.1f} GiB free"))
        if sysinfo.pool is not None and sysinfo.pool.idle == 0:
            issues.append((1, "DB connection pool saturated"))
    if dr is not None and dr.enabled and dr.active:
        issues.append((1, "running on the DR failover box"))
    if (
        cluster is not None
        and cluster.clustered
        and nodes is not None
        and nodes.leader_node_id is None
    ):
        issues.append((2, "cluster has no leader"))

    level = max((lvl for lvl, _ in issues), default=0)
    reason = next((msg for lvl, msg in issues if lvl == level), None)
    return {0: "ok", 1: "warn", 2: "down"}[level], reason


def register(app: FastAPI, deps: UiDeps) -> None:
    """L1b: read-only engine status page (engine/store metrics, effective security posture,
    cluster + DR state). Reuses the monitoring:read JSON handlers — no PHI, no step-up."""
    core = deps.core

    @app.get("/ui/status", response_class=HTMLResponse)
    async def ui_status(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        sys_status = await core.system_status(request, engine=engine, _user=identity)
        posture = await core.security_posture(request, engine=engine, identity=identity)
        cluster = await core.cluster_status(engine=engine, _user=identity)
        nodes = await core.cluster_nodes(engine=engine, _user=identity)
        dr = await core.dr_status(engine=engine, _user=identity)
        svc = await core.service_status(request, _user=identity)
        return HTMLResponse(pages.status(sys_status, posture, cluster, nodes, dr, svc))

    @app.get("/ui/nav-status")
    async def ui_nav_status(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # activity=False (ASVS 14.3.1): a TIMER-driven background poll on every navved page, not user
        # activity. Refreshing the idle clock here kept an abandoned tab — including every PHI page —
        # signed in indefinitely, which defeated automatic logoff outright.
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ, activity=False)),
    ) -> JSONResponse:
        # The nav heart + alerts bell poll this ~every 15s from every page. Metadata only — disk/pool/
        # cluster posture + an alert COUNT (no bodies, no PHI). It must NEVER raise: a crash would blank the
        # nav, and an unreachable store is itself the "down" verdict, so each probe is guarded and a broad
        # failure degrades to the worst signal rather than a 500.
        try:
            sysinfo: SystemStatus | None = await core.system_status(
                request, engine=engine, _user=identity
            )
        except HTTPException:
            raise  # a real authz failure — let require_ui-style semantics surface (never seen as "down")
        except Exception:  # noqa: BLE001 - a store/metrics read failure IS the "down" health signal
            _log.warning("nav-status: system_status failed; reporting engine down", exc_info=True)
            sysinfo = None

        dr: DrStatus | None = None
        cluster: ClusterStatus | None = None
        nodes: ClusterNodeList | None = None
        try:
            dr = await core.dr_status(engine=engine, _user=identity)
            cluster = await core.cluster_status(engine=engine, _user=identity)
            if cluster.clustered:
                nodes = await core.cluster_nodes(engine=engine, _user=identity)
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 - HA/DR posture is best-effort; absence must not fake a problem
            _log.warning("nav-status: HA/DR probe failed; skipping failover checks", exc_info=True)

        health, reason = _derive_health(sysinfo, dr, cluster, nodes)

        # Alerts count/severity needs monitoring:diagnose (the ack/resolve tier). The handler is called
        # DIRECTLY here, which skips its own Depends(require(...)) gate — so gate it explicitly on the
        # identity (the /ui/alerts page re-asserts at the route level the same way). Without diagnose,
        # alerts=null so the bell HIDES itself rather than showing a gray "no alerts" the viewer can't trust.
        alerts: dict[str, object] | None = None
        if identity.has(Permission.MONITORING_DIAGNOSE):
            try:
                instances = await core.list_active_alerts(
                    engine=engine, identity=identity, limit=200
                )
                active = instances.alerts
                alerts = {
                    "count": len(active),
                    "severity": _worst_severity([a.severity for a in active]),
                }
            except HTTPException:
                raise
            except Exception:  # noqa: BLE001 - a best-effort count; a query failure must not crash the probe
                _log.warning("nav-status: list_active_alerts failed; omitting count", exc_info=True)
                alerts = None

        return JSONResponse({"health": health, "reason": reason, "alerts": alerts})
