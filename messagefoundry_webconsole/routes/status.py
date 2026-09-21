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

# ``DbStatus.journal_mode`` already carries the backend on the wire — Postgres reports the literal
# "postgres", SQL Server its recovery model, SQLite the PRAGMA journal mode — which is what lets this
# rollup tell "not applicable" from "the probe broke" with no second field. Only the SERVER modes are
# listed: anything unrecognised counts as a local disk, so a null from an unknown backend ALARMS
# rather than going quiet. That direction is deliberate — silence is the failure this rule exists to
# prevent, and a new backend added here is louder than it should be (visible, and fixed on sight)
# rather than quieter (never noticed). SQLite's modes (delete/truncate/persist/memory/wal/off) share
# no spelling with these, so the two vocabularies cannot collide.
#
# ONE case lands on the loud side by judgement rather than by evidence: the EMPTY string. Both
# stores fall back to "" when their own mode read comes back empty, so it names no backend. SQLite
# reaches it only if `PRAGMA journal_mode` returns no row, which a live connection does not do;
# SQL Server reaches it if the `sys.databases` recovery read returns nothing. So "" is in practice
# a SQL Server tell, and treating it as local means a server whose recovery probe failed warns
# about a disk that was never ours to see. That is accepted here: both paths are near-unreachable,
# and of the two wrong answers a visible one beats a silent one. Resolving it properly needs the
# backend stated outright rather than inferred, which is the deferred `disk_free_status` field.
#
# `PoolInfo.backend` was considered and declined, though naming the backend is literally its job:
# `pool` is None on SQLite (no pool) and DEFAULTED None on the wire, so it cannot separate "SQLite"
# from "a server backend that reported no pool" -- the same conflation this rule exists to end, and
# `DbInfo.synchronous` is defaulted the same way. `journal_mode` is the only backend-bearing field
# on `DbInfo` that is REQUIRED and never defaulted, which is why an imperfect discriminator on a
# required field beats a cleaner one that may be absent.
_SERVER_DB_JOURNAL_MODES = frozenset({"postgres", "full", "bulk_logged", "simple"})

# At most this many failed inbounds are named in the heart's reason; the rest become "and N more".
# The reason renders into a title= attribute, so an estate-wide outage must not produce a tooltip
# hundreds of names long.
_MAX_NAMED_FAILURES = 3


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


def _db_disk_free_is_self_measured(journal_mode: str) -> bool:
    """Whether the engine measures the DB's free space ITSELF, read from the backend discriminator
    already on the wire (:attr:`DbInfo.journal_mode`). That is the question the caller has: it
    decides whether a null ``disk_free_bytes`` is a failed probe or a reading never taken.

    True on the default SQLite backend, where ``disk_free_bytes`` comes from a ``shutil.disk_usage``
    the engine ran, and is ``None`` for exactly one reason: that call raised. There is no
    not-applicable reading, so a null is a FAILED probe on a path that should have been readable.

    False on the server backends, whose disk the engine never looks at — a null is "not applicable"
    and claims nothing. An unrecognised mode answers True on purpose; see
    :data:`_SERVER_DB_JOURNAL_MODES`. Compared case-folded, because SQLite reports its mode
    lowercase and SQL Server reports its recovery model uppercase.

    Named for the measurement and NOT for the disk being local: a SQLite store on an SMB or NFS
    share sits on a remote disk and must still answer True, because the engine still stats it.
    """
    return journal_mode.strip().lower() not in _SERVER_DB_JOURNAL_MODES


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
      measured 0 still alarms; an UNMEASURABLE drive (``disk_free_bytes is None``) is never
      COMPARED against a threshold, because "I could not measure this" is not "this is full"
      (BACKLOG #1563).
    - a drive whose FREE SPACE the engine could not measure but should have been able to →
      **warn**, naming it. That is a configured log directory, and the DB drive on the default
      SQLite backend — for both, a null ``disk_free_bytes`` has one cause, a probe that failed on a
      path that should have been readable. On a server backend the DB null means "not applicable"
      instead and stays silent; ``journal_mode`` tells the two apart. Not comparing is not the same
      as saying nothing, and collapsing them let a SQLite DB drive that stopped being stattable
      read green.

      Scoped to the free-space half on purpose, because that is all this rollup reads. ``LogInfo``
      meters size and free space INDEPENDENTLY, so a log directory that is unlistable but sits on a
      stattable drive (``log_dir`` naming a file, or a directory the service account cannot list)
      arrives as ``size_bytes=None`` with a real free figure and is not caught here. Pre-existing
      and untouched by #1563; ``SystemStatus.log_sinks`` already carries a purpose-built
      ``unwritable`` state for it that nothing in this function reads yet.
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
        # (label, free bytes, the reason to raise if a null HERE means a failed probe rather than a
        # disk the engine was never meant to see). The third element carries the rule with the entry
        # that owns it, so the loop never has to infer health policy from a display label.
        frees: list[tuple[str, int | None, str | None]] = [
            (
                "db",
                sysinfo.db.disk_free_bytes,
                "db directory missing or unreadable"
                if _db_disk_free_is_self_measured(sysinfo.db.journal_mode)
                else None,
            )
        ]
        if sysinfo.logs is not None:
            frees.append(
                ("logs", sysinfo.logs.disk_free_bytes, "log directory missing or unreadable")
            )
        for label, free, unmeasurable_reason in frees:
            if free is None:
                # BACKLOG #1563. WHETHER a null here means "the probe failed" or "not applicable"
                # is decided at the `frees` entry above (`_db_disk_free_is_self_measured`); this
                # branch only acts on it. Staying quiet on a FAILED probe would trade #1563's wrong
                # answer for a silent one, and the SQLite shape is reachable: the store holds its
                # file handle open, so queries keep succeeding while the parent directory's ACL or
                # mount goes bad -- nothing else in this rollup would notice.
                if unmeasurable_reason is not None:
                    issues.append((1, unmeasurable_reason))
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
                # The store-computed aggregate, never this page (BACKLOG #1564) — see
                # AlertInstanceList.total. limit=1 because no row is read here at all.
                instances = await core.list_active_alerts(engine=engine, identity=identity, limit=1)
                alerts = {
                    "count": instances.total,
                    "severity": instances.worst_severity,
                }
            except HTTPException:
                raise
            except Exception:  # noqa: BLE001 - a best-effort count; a query failure must not crash the probe
                _log.warning("nav-status: list_active_alerts failed; omitting count", exc_info=True)
                alerts = None

        return JSONResponse({"health": health, "reason": reason, "alerts": alerts})
