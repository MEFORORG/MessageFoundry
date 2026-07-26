# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Monitoring-area page builders for the /ui ops dashboard (ADR 0065).

Read-only monitoring surfaces (BACKLOG #75 phase 1). Each builder returns escaped :class:`.._html.Markup`
and reuses the metadata-only JSON handlers (no PHI). A lane adding a page here appends its builder + the
name in ``__all__`` and registers its nav entry via :func:`.._html.register_nav` co-located below.
"""

from __future__ import annotations

import datetime
import time

from messagefoundry.api.models import (
    AlertInstanceInfo,
    AlertInstanceList,
    AlertsConfig,
    ClusterNodeList,
    ClusterStatus,
    ConnectionEventInfo,
    DrStatus,
    GraphResponse,
    IntegrityResult,
    MetricsHistoryResponse,
    SecurityPosture,
    ServiceStatusInfo,
    SystemStatus,
)

from .._html import Markup, el, page, register_nav, rows_table

__all__ = [
    "alerts",
    "events",
    "flow_and_trends",
    "flow_and_trends_fragment",
    "integrity_result",
    "status",
]


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
    return datetime.datetime.fromtimestamp(value, tz=datetime.UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _opt(value: object) -> str:
    """Render an optional scalar/None as text ('—' for None)."""
    return "—" if value is None else str(value)


def _yn(value: bool | None) -> str:
    """Render a tri-state flag: '—' for None, else 'yes'/'no'."""
    return "—" if value is None else ("yes" if value else "no")


def _fips(value: bool | None) -> str:
    """Render the report-only FIPS-provider attestation (#73). Deliberately worded 'reported', never
    'certified': the boolean attests the interpreter's ssl/_hashlib OpenSSL provider state, not a FIPS-140
    certification (ADR 0120). None = undeterminable (a non-OpenSSL build with no get_fips_mode)."""
    if value is None:
        return "undeterminable"
    return "reported active" if value else "reported inactive"


def _memenc(value: bool | None) -> str:
    """Render one leg of the platform memory-encryption read-out (ADR 0152 Phase 1).

    Worded "self-reported" in every state, never "enabled"/"compliant"/"verified": the value comes
    from what the host OS says about itself (/proc/cpuinfo flags, guest device presence), and ASVS
    11.7.1 exists because that host may be the adversary. None = undeterminable, which is what
    Windows reports today (the in-guest attestation path is an ADR 0152 spike that has not landed)."""
    if value is None:
        return "undeterminable"
    return "self-reported yes" if value else "self-reported no"


def _contradiction(value: bool | None) -> str:
    """Render the tri-state read-out-vs-declaration check (ADR 0152 rung 2).

    The three states must never render alike. A bare "no" beside a "yes" declaration reads as
    CORROBORATED, which is exactly the compliance-questionnaire screenshot this row layout exists to
    prevent — and on Windows nothing is ever measured, so a two-state rendering would print that
    reassuring "no" on the primary deployment platform by vacuity. Hence an explicit
    "nothing measured" for None, and wording that names which side did the contradicting."""
    if value is None:
        return "nothing measured that could contradict it"
    return "YES — the read-out contradicts it" if value else "no — the read-out agrees"


def _bytes(n: int) -> str:
    """Render a byte count in a compact binary unit (KiB/MiB/GiB)."""
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover - unreachable (loop always returns)


def _suspend_form(a: AlertInstanceInfo) -> Markup:
    """A small same-origin POST form to suspend an alert's NOTIFICATIONS for a chosen window (#143).

    Notification-only: suspending mutes re-alerts for the window while the instance stays open/counted.
    """
    return el(
        "form",
        el(
            "select",
            el("option", "15 min", value="15"),
            el("option", "1 hour", value="60", selected=True),
            el("option", "4 hours", value="240"),
            el("option", "24 hours", value="1440"),
            name="minutes",
        ),
        el("button", "Suspend", type="submit"),
        method="post",
        action=f"/ui/alerts/{a.id}/suspend",
        class_="ctl",
    )


def _alert_controls(a: AlertInstanceInfo, *, now: float) -> Markup:
    """Ack (open only) + Resolve + windowed Suspend/Resume (#143) POST forms for one alert instance (L3a).

    Shown to every viewer; the JSON handlers enforce ``monitoring:diagnose`` on submit (a read-only
    viewer gets a 403), matching the connection-control button convention. Suspend gates NOTIFICATION
    only — a suspended instance stays open/counted/visible; only re-alerts are muted for the window.
    """
    forms: list[object] = []
    suspended = a.suspended_until is not None and a.suspended_until > now
    if a.status == "open":
        forms.append(_post_button(f"/ui/alerts/{a.id}/ack", "Ack"))
    if a.status in ("open", "acknowledged"):
        forms.append(_post_button(f"/ui/alerts/{a.id}/resolve", "Resolve"))
        if suspended:
            forms.append(_post_button(f"/ui/alerts/{a.id}/resume", "Resume"))
        else:
            forms.append(_suspend_form(a))
    return el("div", *forms, class_="ctls") if forms else Markup("")


def alerts(instances: AlertInstanceList, config: AlertsConfig) -> Markup:
    """The operator-alerts page: active (open + acknowledged) instances + the loaded rules (ADR 0044/0014).

    Metadata only — no PHI, no secrets (transports are reported present-or-not by the JSON handler).
    """
    now = time.time()
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
            # #143: show the active NOTIFICATION-mute window end (— when not suspended / already elapsed).
            _ts(a.suspended_until)
            if a.suspended_until is not None and a.suspended_until > now
            else "—",
            _alert_controls(a, now=now),
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
            "Suspended",
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
    kpi = sys.kpis
    engine_tbl = rows_table(
        ["Field", "Value"],
        [
            ["Version", e.version],
            ["Uptime", f"{e.uptime_seconds:.0f}s"],
            ["PID", e.pid],
            [
                "Inbound",
                f"{e.channels_running}/{e.channels_total} running ({e.channels_stopped} stopped)",
            ],
            # #93 engine-wide KPI headline: combined inbound+outbound endpoint count + engine-wide
            # msg/s (reusing the recent_done rate window) — the single-glance roll-up no per-connection
            # row gives. Metadata only (counts + a rate), no PHI.
            [
                "Endpoints (in+out)",
                f"{kpi.connections_running}/{kpi.connections_total} running "
                f"({kpi.connections_stopped} stopped)",
            ],
            ["Messages (total)", kpi.messages_total],
            ["Throughput", f"{kpi.messages_per_second:.1f} msg/s"],
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
            # FIPS-provider attestation (report-only, #73 / ADR 0120). Scoped wording: this is the
            # interpreter's ssl/_hashlib OpenSSL, REPORTED — never "FIPS-140 certified", and separate from
            # the cryptography-wheel OpenSSL that encrypts PHI at rest. Metadata only (no secrets). Read via
            # getattr is defensive, NOT cross-seam compat: SUPPORTED_ENGINE_SEAMS holds exactly one
            # seam (BACKLOG #279), so the field is always present on a mountable engine. It is kept
            # because a None/absent value must render as a dash rather than raise mid-page.
            [
                "FIPS mode (ssl/_hashlib OpenSSL, reported)",
                _fips(getattr(posture, "fips_mode", None)),
            ],
            ["OpenSSL version (ssl/_hashlib)", _opt(getattr(posture, "openssl_version", None))],
            # Platform memory-encryption read-out (report-only, ADR 0152 Phase 1 / ASVS 11.7.1).
            # Wording is a security property here: every label says "self-reported", and capability
            # ("this silicon can") is a SEPARATE row from activation ("this guest is"), because a
            # single fused "memory encryption: yes" row is exactly what would get screenshotted into
            # a compliance questionnaire. The operator's declaration is labelled as an unverified
            # claim (never "attestation" — that word means a CPU-signed quote here, which is not
            # built), the read-out-vs-declaration check renders its three states distinctly, and the
            # engine's own disclaimer sentence is rendered verbatim so the screenshot carries it.
            [
                "Memory encryption — CPU capability (self-reported)",
                _memenc(getattr(posture, "memory_encryption_self_reported_capability", None)),
            ],
            [
                "Memory encryption — this guest (self-reported, NOT attestation)",
                _memenc(getattr(posture, "memory_encryption_self_reported_active", None)),
            ],
            [
                "Memory encryption — mechanism / read-out source",
                f"{_opt(getattr(posture, 'memory_encryption_self_reported_mechanism', None))}"
                f" / {_opt(getattr(posture, 'memory_encryption_readout_source', None))}",
            ],
            [
                "Memory encryption — operator declaration (unverified, not attestation)",
                _yn(getattr(posture, "memory_encryption_operator_declared", False)),
            ],
            [
                "Memory encryption — read-out vs that declaration",
                _contradiction(
                    getattr(posture, "memory_encryption_readout_contradicts_declaration", None)
                ),
            ],
            [
                "Memory encryption — what this does and does not mean",
                _opt(getattr(posture, "memory_encryption_note", None)),
            ],
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
    # ADR 0118: the effective [security] posture — the plain-language switches, any active loosenings,
    # and the synthetic-relaxation notice. Read-only (the IDE is the sole authoring surface); booleans/
    # ints only, no secret material.
    sec = posture.security

    def _sec(key: str, none_label: str = "—") -> object:
        v = sec.get(key)
        if v is None:
            return none_label
        if isinstance(v, bool):
            return _yn(v)
        return str(v)

    security_tbl = rows_table(
        ["Setting", "Value"],
        [
            ["Local access only", _sec("local_access_only")],
            ["Require encryption for remote", _sec("require_encryption_for_remote")],
            ["Serve web console", _sec("serve_web_console")],
            ["Encrypt stored data", _sec("encrypt_stored_data")],
            ["Allow unencrypted PHI", _sec("allow_unencrypted_phi")],
            ["Require sign-in", _sec("require_sign_in")],
            ["Require MFA", _sec("require_mfa")],
            ["Sign out after idle (min)", _sec("sign_out_after_idle_minutes")],
            ["Max session (hours)", _sec("max_session_hours")],
            ["Block unlisted outbound", _sec("block_unlisted_outbound")],
            ["Delete message bodies after (days)", _sec("delete_message_bodies_after_days")],
            ["Allow keeping PHI indefinitely", _sec("allow_keeping_phi_indefinitely")],
            ["Audit all authz decisions", _sec("audit_all_authorization_decisions")],
            [
                "Handles real patient data",
                _sec("handles_real_patient_data", "(derived from environment)"),
            ],
            ["Production instance", _sec("production_instance", "(derived from environment)")],
        ],
        adjustable=False,
    )
    security_section: list[object] = [el("h2", "Security posture"), security_tbl]
    if posture.synthetic_relaxation:
        security_section.append(el("p", posture.synthetic_relaxation, class_="muted"))
    if posture.loosenings:
        security_section.append(
            el("p", "Protections loosened from the secure defaults:", class_="banner")
        )
        security_section.append(
            el(
                "ul",
                *[el("li", f"{lo.switch} — {lo.risk}") for lo in posture.loosenings],
            )
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
        *security_section,
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


# --- Flow & trends (BACKLOG #76, ADR 0065 amendment) -----------------------------------------------
# The status-colored by-name data-flow graph + historical queue-trend charts, both rendered as INLINE
# SVG server-side (CSP script-src 'self'; no chart-library CDN) from the read-only monitoring:read
# endpoints GET /graph/edges + GET /metrics/history. Every dynamic value (connection name, status, count)
# is placed through the escaping ``el`` builder, so a hostile connection name renders inert. Metadata
# only — no message body. The graph is the by-name Registry edge set: there is NO channel/route object.

#: The graph's column order + display label per node kind (inbound → router → handler → outbound), the
#: visual left-to-right message-flow direction.
_GRAPH_COLUMNS: tuple[tuple[str, str], ...] = (
    ("inbound", "Inbound"),
    ("router", "Routers"),
    ("handler", "Handlers"),
    ("outbound", "Outbound"),
)
_NODE_W = 150
_NODE_H = 30
_ROW_GAP = 46
_COL_GAP = 210
_MARGIN = 12
_HEAD_Y = 24
_TOP = 40


def _short(name: str, limit: int = 20) -> str:
    """Truncate a long connection/element name for the fixed-width node box (the full name rides an SVG
    ``<title>`` tooltip). Escaping happens in ``el`` — this only bounds the visible length."""
    return name if len(name) <= limit else name[: limit - 1] + "…"


def _flow_graph(graph: GraphResponse) -> Markup:
    """The status-colored by-name data-flow graph as inline SVG (a layered inbound→router→handler→
    outbound layout). Node colour is CSS-driven off the live ``status`` class (theme tokens), never an
    operator-assigned colour. Edges are lines; a ``heuristic``-provenance edge renders dashed."""
    if not graph.nodes:
        return el("p", "No connections in the graph.", class_="muted")
    columns: dict[str, list[str]] = {kind: [] for kind, _label in _GRAPH_COLUMNS}
    status_by: dict[tuple[str, str], str | None] = {}
    for node in graph.nodes:
        if node.kind in columns:
            columns[node.kind].append(node.name)
            status_by[(node.kind, node.name)] = node.status
    for names in columns.values():
        names.sort()

    pos: dict[tuple[str, str], tuple[int, int]] = {}
    for ci, (kind, _label) in enumerate(_GRAPH_COLUMNS):
        x = _MARGIN + ci * _COL_GAP
        for ri, name in enumerate(columns[kind]):
            pos[(kind, name)] = (x, _TOP + ri * _ROW_GAP)

    max_rows = max((len(names) for names in columns.values()), default=1)
    width = _MARGIN + (len(_GRAPH_COLUMNS) - 1) * _COL_GAP + _NODE_W + _MARGIN
    height = _TOP + max(1, max_rows) * _ROW_GAP + _MARGIN

    parts: list[object] = []
    for ci, (_kind, label) in enumerate(_GRAPH_COLUMNS):
        parts.append(el("text", label, x=_MARGIN + ci * _COL_GAP, y=_HEAD_Y, class_="gcolhead"))
    # Edges first (drawn behind the node boxes). A target the static extractor couldn't resolve simply
    # has no edge here (its source is flagged dynamic separately) — never a fabricated line.
    for edge in graph.edges:
        s = pos.get((edge.source_kind, edge.source))
        t = pos.get((edge.target_kind, edge.target))
        if s is None or t is None:
            continue
        parts.append(
            el(
                "line",
                x1=s[0] + _NODE_W,
                y1=s[1] + _NODE_H // 2,
                x2=t[0],
                y2=t[1] + _NODE_H // 2,
                class_=f"gedge gedge-{edge.provenance}",
            )
        )
    # Node boxes, coloured by live status class (router/handler nodes have no status → the neutral
    # "logic" class). The full name + status ride an SVG <title> tooltip.
    for kind, _label in _GRAPH_COLUMNS:
        for name in columns[kind]:
            x, y = pos[(kind, name)]
            status = status_by.get((kind, name))
            cls = f"gnode gnode-{status}" if status else "gnode gnode-logic"
            tip = f"{name} — {status}" if status else name
            parts.append(
                el(
                    "g",
                    el("title", tip),
                    el("rect", x=x, y=y, width=_NODE_W, height=_NODE_H, rx=5, class_=cls),
                    el(
                        "text",
                        _short(name),
                        x=x + 8,
                        y=y + _NODE_H // 2 + 4,
                        class_="gnodelabel",
                    ),
                )
            )
    svg = el(
        "svg",
        *parts,
        xmlns="http://www.w3.org/2000/svg",
        viewBox=f"0 0 {width} {height}",
        width=width,
        height=height,
        class_="flowgraph",
        role="img",
        aria_label="Status-colored data-flow graph",
    )
    dynamic_note: Markup = Markup("")
    if graph.dynamic:
        # AC-3 (config.graph): an element whose full target set isn't statically resolvable — surfaced,
        # never silently dropped, so an operator knows the drawn edges may be incomplete for it.
        dynamic_note = el(
            "p",
            "Some elements route dynamically (computed targets) — their edges may be incomplete: "
            + ", ".join(sorted(graph.dynamic)),
            class_="muted",
        )
    return el("div", el("div", svg, class_="flowgraph-wrap"), dynamic_note)


def _hms(ts: float) -> str:
    """A compact HH:MM:SS UTC label for the trend chart's time axis."""
    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime("%H:%M:%S")


#: Max overlaid series on the trend chart (colour classes series-0..series-5 in app.css).
_MAX_SERIES = 6


def _trend_chart(history: MetricsHistoryResponse) -> Markup:
    """The historical queue-by-status trend as an inline-SVG multi-line chart (one polyline per outbound
    status). Counts only — no PHI. Renders a friendly notice until at least two samples have accrued
    (the ring fills while the Connections dashboard's ~1s /ws/stats socket is open)."""
    samples = history.samples
    if len(samples) < 2:
        return el(
            "p",
            "No trend data yet — keep the Connections dashboard open to accumulate history.",
            class_="muted",
        )
    keys = sorted({k for s in samples for k in s.outbox_by_status})[:_MAX_SERIES]
    if not keys:
        return el("p", "No queued outbound activity has been recorded yet.", class_="muted")

    width, height = 720, 200
    pad_l, pad_r, pad_t, pad_b = 42, 12, 12, 26
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(samples)
    maxv = max(
        (max((s.outbox_by_status.get(k, 0) for k in keys), default=0) for s in samples),
        default=0,
    )
    maxv = max(maxv, 1)

    def sx(i: int) -> float:
        return pad_l + (plot_w * i / (n - 1))

    def sy(v: int) -> float:
        return pad_t + plot_h - (plot_h * v / maxv)

    parts: list[object] = [
        el("line", x1=pad_l, y1=pad_t, x2=pad_l, y2=pad_t + plot_h, class_="axis"),
        el(
            "line", x1=pad_l, y1=pad_t + plot_h, x2=pad_l + plot_w, y2=pad_t + plot_h, class_="axis"
        ),
        el("text", "0", x=pad_l - 6, y=pad_t + plot_h, class_="axislabel", text_anchor="end"),
        el("text", str(maxv), x=pad_l - 6, y=pad_t + 8, class_="axislabel", text_anchor="end"),
        el(
            "text",
            _hms(samples[0].ts),
            x=pad_l,
            y=height - 8,
            class_="axislabel",
            text_anchor="start",
        ),
        el(
            "text",
            _hms(samples[-1].ts),
            x=pad_l + plot_w,
            y=height - 8,
            class_="axislabel",
            text_anchor="end",
        ),
    ]
    for si, key in enumerate(keys):
        points = " ".join(
            f"{sx(i):.1f},{sy(s.outbox_by_status.get(key, 0)):.1f}" for i, s in enumerate(samples)
        )
        parts.append(el("polyline", points=points, fill="none", class_=f"series series-{si}"))
    svg = el(
        "svg",
        *parts,
        xmlns="http://www.w3.org/2000/svg",
        viewBox=f"0 0 {width} {height}",
        width=width,
        height=height,
        class_="trendchart",
        role="img",
        aria_label="Queue-by-status trend chart",
    )
    legend = el(
        "div",
        *[
            el("span", el("span", "", class_=f"swatch series-{si}"), key, class_="legend-item")
            for si, key in enumerate(keys)
        ],
        class_="chart-legend",
    )
    return el("div", el("div", svg, class_="trendchart-wrap"), legend)


def _flow_and_trends_body(graph: GraphResponse, history: MetricsHistoryResponse) -> Markup:
    """The live-refreshed inner body (graph + chart) — the poll target ``app.js`` swaps in."""
    return el(
        "div",
        el("h2", "Data-flow graph"),
        _flow_graph(graph),
        el("h2", "Queue trend"),
        _trend_chart(history),
        id="mon-live",
    )


def flow_and_trends_fragment(graph: GraphResponse, history: MetricsHistoryResponse) -> Markup:
    """Just the graph + chart body — fetched by ``app.js`` from ``/ui/monitoring/live`` on an interval."""
    return _flow_and_trends_body(graph, history)


def flow_and_trends(graph: GraphResponse, history: MetricsHistoryResponse) -> Markup:
    """The Flow & trends page (BACKLOG #76): the status-colored data-flow graph over the by-name Registry
    edges + the historical queue-trend chart, both inline SVG. The ``[data-mf-fragment]`` container is
    refreshed by ``app.js`` from ``/ui/monitoring/live`` (server-rendered, already-escaped) so the graph's
    status colours + the trend stay live without a WebSocket."""
    live = el(
        "div",
        _flow_and_trends_body(graph, history),
        data_mf_fragment=True,
        data_fragment_url="/ui/monitoring/live",
        data_fragment_ms="5000",
    )
    return page(
        "Flow & trends",
        el("h1", "Flow & trends"),
        el(
            "p",
            "Live status-colored data-flow graph over the wired connections, plus the historical "
            "queue-by-status trend. Metadata only — no message content.",
            class_="muted",
        ),
        live,
        active="flow",
    )


# Nav registration (append-at-tail; core order preserved). Co-located with the builders so this lane
# never edits the central nav literal (ADR 0065 §multi-session-build).
register_nav("status", "/ui/status", "Status")
register_nav("alerts", "/ui/alerts", "Alerts")
register_nav("events", "/ui/events", "Events")
register_nav("flow", "/ui/monitoring", "Flow & trends")
