# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Monitoring-area page builders for the /ui ops dashboard (ADR 0065).

Read-only monitoring surfaces (BACKLOG #75 phase 1). Each builder returns escaped :class:`.._html.Markup`
and reuses the metadata-only JSON handlers (no PHI). A lane adding a page here appends its builder + the
name in ``__all__`` and registers its nav entry via :func:`.._html.register_nav` co-located below.
"""

from __future__ import annotations

import datetime

from messagefoundry.api.models import (
    AlertInstanceInfo,
    AlertInstanceList,
    AlertsConfig,
    ClusterNodeList,
    ClusterStatus,
    ConnectionEventInfo,
    DrStatus,
    IntegrityResult,
    SecurityPosture,
    ServiceStatusInfo,
    SystemStatus,
)

from .._html import Markup, el, page, register_nav, rows_table

__all__ = ["alerts", "events", "integrity_result", "status"]


def _post_button(action: str, label: str) -> Markup:
    """A tiny same-origin POST form for one state-changing /ui action (redirect-back on success)."""
    return el(
        "form",
        el("button", label, type="submit"),
        method="post",
        action=action,
        class_="ctl",
    )


def _ts(value: float) -> str:
    """Render an epoch-seconds timestamp as a compact UTC string."""
    return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%SZ"
    )


def _opt(value: object) -> str:
    """Render an optional scalar/None as text ('—' for None)."""
    return "—" if value is None else str(value)


def _yn(value: bool | None) -> str:
    """Render a tri-state flag: '—' for None, else 'yes'/'no'."""
    return "—" if value is None else ("yes" if value else "no")


def _bytes(n: int) -> str:
    """Render a byte count in a compact binary unit (KiB/MiB/GiB)."""
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover - unreachable (loop always returns)


def _alert_controls(a: AlertInstanceInfo) -> Markup:
    """Ack (open only) + Resolve (open/acknowledged) POST forms for one alert instance (L3a).

    Shown to every viewer; the JSON handlers enforce ``monitoring:diagnose`` on submit (a read-only
    viewer gets a 403), matching the connection-control button convention.
    """
    forms: list[object] = []
    if a.status == "open":
        forms.append(_post_button(f"/ui/alerts/{a.id}/ack", "Ack"))
    if a.status in ("open", "acknowledged"):
        forms.append(_post_button(f"/ui/alerts/{a.id}/resolve", "Resolve"))
    return el("div", *forms, class_="ctls") if forms else Markup("")


def alerts(instances: AlertInstanceList, config: AlertsConfig) -> Markup:
    """The operator-alerts page: active (open + acknowledged) instances + the loaded rules (ADR 0044/0014).

    Metadata only — no PHI, no secrets (transports are reported present-or-not by the JSON handler).
    """
    inst_rows = [
        [
            el("span", a.severity, class_=f"sev sev-{a.severity}"),
            el("span", a.status, class_=f"status status-{a.status}"),
            a.event_type,
            a.connection,
            a.count,
            _ts(a.first_seen),
            _ts(a.last_seen),
            a.reason,
            _opt(a.acked_by),
            _alert_controls(a),
        ]
        for a in instances.alerts
    ]
    inst_table = rows_table(
        [
            "Severity",
            "Status",
            "Type",
            "Connection",
            "Count",
            "First seen",
            "Last seen",
            "Reason",
            "Acked by",
            "Actions",
        ],
        inst_rows,
    )
    empty = el("p", "No active alerts.", class_="muted") if not instances.alerts else Markup("")

    transports = ", ".join(
        [
            t
            for t, on in (
                ("webhook", config.webhook_configured),
                ("email", config.email_configured),
            )
            if on
        ]
    )
    summary = rows_table(
        ["Setting", "Value"],
        [
            ["Transports configured", transports or "none"],
            ["Email recipients", config.email_recipient_count],
            ["Re-alert after", f"{config.realert_seconds:.0f}s"],
        ],
        adjustable=False,
    )
    rule_rows = [
        [
            r.event_type,
            r.connection,
            el("span", r.severity, class_=f"sev sev-{r.severity}"),
            _opt(r.min_depth),
            _opt(None if r.min_oldest_seconds is None else f"{r.min_oldest_seconds:.0f}s"),
            _opt(None if not r.transports else ", ".join(r.transports)),
            _opt(None if r.cooldown_seconds is None else f"{r.cooldown_seconds:.0f}s"),
        ]
        for r in config.rules
    ]
    rules_table = rows_table(
        [
            "Event type",
            "Connection",
            "Severity",
            "Min depth",
            "Min oldest",
            "Transports",
            "Cooldown",
        ],
        rule_rows,
    )
    return page(
        "Alerts",
        el("h1", "Alerts"),
        el("h2", "Active"),
        empty,
        inst_table,
        el("h2", "Rules"),
        summary,
        rules_table,
        active="alerts",
    )


#: The bounded connection-event vocabulary (mirrors the engine's emit kinds + the desktop
#: event_log_page.py filter) for the /ui event-log kind dropdown (L6b, #75 parity).
_EVENT_KINDS = (
    "established",
    "closed",
    "idle_timeout",
    "peer_not_allowlisted",
    "at_capacity",
    "frame_oversize",
    "peer_reset",
    "framing_error",
    "connection_lost",
    "connection_restored",
)


def _event_filter(connection: str, kind: str = "") -> Markup:
    """A GET filter form for the event log (reuses the /events connection + kind query params)."""
    options = [el("option", "All kinds", value="")] + [
        el("option", k, value=k, selected=(k == kind) or None) for k in _EVENT_KINDS
    ]
    return el(
        "form",
        el("input", name="connection", value=connection or None, placeholder="connection"),
        el("select", *options, name="kind"),
        el("button", "Filter", type="submit"),
        method="get",
        action="/ui/events",
        class_="filters",
    )


def events(rows: list[ConnectionEventInfo], *, connection: str = "", kind: str = "") -> Markup:
    """The connection/transport event log (Corepoint-style, #46) — metadata only, newest first."""
    headers = ["When", "Connection", "Transport", "Dir", "Kind", "Peer", "Reason"]
    body = [
        [
            _ts(e.ts),
            e.connection,
            e.transport,
            e.direction,
            el("span", e.kind, class_=f"evt evt-{e.kind}"),
            _opt(e.peer_host),
            e.reason,
        ]
        for e in rows
    ]
    empty = el("p", "No events.", class_="muted") if not rows else Markup("")
    return page(
        "Events",
        el("h1", "Events"),
        _event_filter(connection, kind),
        empty,
        rows_table(headers, body),
        active="events",
    )


def status(
    sys: SystemStatus,
    posture: SecurityPosture,
    cluster: ClusterStatus,
    nodes: ClusterNodeList,
    dr: DrStatus,
    service: ServiceStatusInfo,
) -> Markup:
    """The engine status page: engine + store metrics, effective security posture, cluster + DR state.

    Metadata only — no PHI. The security posture carries NO secret material (``key_id`` is a one-way
    fingerprint, ``key_source`` a provider name), so it renders as-is.
    """
    e = sys.engine
    db = sys.db
    engine_tbl = rows_table(
        ["Field", "Value"],
        [
            ["Version", e.version],
            ["Uptime", f"{e.uptime_seconds:.0f}s"],
            ["PID", e.pid],
            [
                "Connections",
                f"{e.channels_running}/{e.channels_total} running ({e.channels_stopped} stopped)",
            ],
            [
                "Outbox by status",
                ", ".join(f"{k}: {v}" for k, v in e.outbox_by_status.items()) or "—",
            ],
        ],
        adjustable=False,
    )
    store_tbl = rows_table(
        ["Field", "Value"],
        [
            ["Backend", posture.backend],
            ["Encryption at rest", _yn(posture.encryption_enabled)],
            ["Key source", posture.key_source],
            ["Key fingerprint", _opt(posture.key_id)],
            ["Data class", _opt(posture.data_class)],
            ["Production", _yn(posture.production)],
            ["Environment", _opt(posture.environment)],
            ["Path", db.path],
            ["Size", _bytes(db.size_bytes)],
            ["Disk free", _bytes(db.disk_free_bytes)],
            ["Journal mode", db.journal_mode],
            ["Messages", db.messages],
            ["Events", db.events],
            ["Audit rows", db.audit],
        ],
        adjustable=False,
    )
    cluster_tbl = rows_table(
        ["Field", "Value"],
        [
            ["Role", cluster.role],
            ["Clustered", _yn(cluster.clustered)],
            ["This node is leader", _yn(cluster.is_leader)],
            ["Node id", cluster.node_id],
            ["Config version", cluster.config_version],
            ["Leader", _opt(nodes.leader_node_id)],
            ["Lease owner", _opt(nodes.lease_owner)],
        ],
        adjustable=False,
    )
    node_rows = [
        [
            n.node_id,
            _opt(n.host),
            _opt(n.pid),
            n.status,
            _yn(n.is_leader),
            _ts(n.last_seen) if n.last_seen is not None else "—",
        ]
        for n in nodes.nodes
    ]
    node_tbl = rows_table(
        ["Node", "Host", "PID", "Status", "Leader", "Last seen"], node_rows, adjustable=False
    )
    dr_tbl = rows_table(
        ["Field", "Value"],
        [
            ["DR box", _yn(dr.enabled)],
            ["Active", _yn(dr.active)],
            ["Threshold", dr.threshold],
            ["Activation", dr.activation_mode],
        ],
        adjustable=False,
    )
    dr_actions: list[object] = []
    if dr.active:
        dr_actions.append(_post_button("/ui/dr/release", "Release DR"))
    elif dr.enabled:
        dr_actions.append(_post_button("/ui/dr/activate", "Activate DR"))
    actions = el(
        "div",
        _post_button("/ui/statistics/reset", "Reset statistics"),
        _post_button("/ui/status/integrity-check", "Run integrity check"),
        *dr_actions,
        class_="ctls",
    )
    # Hosting-service (NSSM) badge (L6a) — only meaningful when [service].report_status is on; a
    # good/warn/bad class drives the badge colour. Read-only (no control buttons — restart is cut).
    _SERVICE_CLASS = {"running": "ok", "stopped": "error", "not_installed": "error"}
    service_section: list[object] = [el("h2", "Hosting service")]
    if not service.enabled:
        service_section.append(
            el("p", "Service-status reporting is off ([service].report_status).", class_="muted")
        )
    else:
        badge = el(
            "span",
            service.state,
            class_=f"status status-{_SERVICE_CLASS.get(service.state, 'warn')}",
        )
        service_section.append(
            rows_table(
                ["Field", "Value"],
                [["Service", _opt(service.service_name)], ["State", badge]],
                adjustable=False,
            )
        )
    # L6b (#75 parity): the no-network update-available signal (#30, ADR 0026) — the desktop shows
    # it as a persistent banner; the web renders a prominent line on the status page. Present only
    # when [update_check] is enabled and a newer version was found (version strings only, no PHI).
    update_banner: Markup = Markup("")
    if sys.update is not None and sys.update.update_available:
        update_banner = el(
            "p",
            "A newer MessageFoundry version is installed — running "
            f"{sys.update.current_version}; {sys.update.pinned_version or '(newer)'} is installed. "
            "Restart the engine to apply.",
            class_="banner",
        )
    return page(
        "Status",
        el("h1", "Status"),
        update_banner,
        el("h2", "Engine"),
        engine_tbl,
        el("h2", "Store"),
        store_tbl,
        el("h2", "Cluster"),
        cluster_tbl,
        node_tbl,
        el("h2", "Disaster recovery"),
        dr_tbl,
        *service_section,
        el("h2", "Actions"),
        actions,
        active="status",
    )


def integrity_result(result: IntegrityResult) -> Markup:
    """The outcome of an on-demand DB integrity check (L3a) — ok/failed + the detail, escaped."""
    verdict = el(
        "span",
        "OK" if result.ok else "FAILED",
        class_=f"status status-{'ok' if result.ok else 'error'}",
    )
    body = el(
        "div",
        el("h1", "Integrity check"),
        el("p", verdict),
        el("pre", result.detail, class_="raw"),
        el("p", el("a", "← Status", href="/ui/status")),
        class_="card",
    )
    return page("Integrity check", body, active="status")


# Nav registration (append-at-tail; core order preserved). Co-located with the builders so this lane
# never edits the central nav literal (ADR 0065 §multi-session-build).
register_nav("status", "/ui/status", "Status")
register_nav("alerts", "/ui/alerts", "Alerts")
register_nav("events", "/ui/events", "Events")
