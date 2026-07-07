# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Config-deploy page for the /ui ops dashboard (ADR 0065).

STRICTLY within BACKLOG #26 (no visual/template authoring): the only action is to **reload** the
engine's already-configured code-first graph from its **own startup directory** — never a user-supplied
path — showing pass/fail. There is deliberately NO module-content editor, NO filesystem picker, and NO
dry-run diff here; authoring lives in the VS Code extension. Every value is escaped by the builders.
"""

from __future__ import annotations

from messagefoundry.api.models import ConfigProvenance, ReloadResult

from .._html import Markup, el, page, register_nav, rows_table, text

__all__ = ["config_page", "reload_pending", "reload_result"]


def _provenance_badge(prov: ConfigProvenance | None) -> Markup:
    """A small 'running commit — clean|DRIFTED' pill (ADR 0041 D1). Empty when the engine hasn't loaded
    a graph yet or provenance is unavailable, so the page renders unchanged on an older engine."""
    if prov is None or not prov.loaded:
        return Markup("")
    if prov.git_head:
        ident = f"commit {prov.git_head[:7]}"
    elif prov.fingerprint:
        ident = f"fingerprint {prov.fingerprint[:12]}"
    else:
        ident = "loaded"
    drifted = bool(prov.drift)
    pill = el(
        "span",
        "DRIFTED" if drifted else "clean",
        class_=f"status status-{'error' if drifted else 'running'}",
    )
    note = (
        " — the config on disk differs from the running graph; reload to apply"
        if drifted
        else " — the running graph matches the config on disk"
    )
    return el("p", text(f"Running config: {ident} "), pill, text(note), class_="muted")


def config_page(prov: ConfigProvenance | None = None) -> Markup:
    """The config-deploy page: a single 'Reload configuration' action (server's startup dir only), with
    a read-only provenance badge (running commit + clean/DRIFTED) when available (ADR 0041 D1)."""
    reload_form = el(
        "form",
        el("button", "Reload configuration", type="submit"),
        method="post",
        action="/ui/config/reload",
        class_="ctl",
    )
    return page(
        "Configuration",
        el("h1", "Configuration"),
        _provenance_badge(prov),
        el(
            "p",
            "Reload the engine's code-first graph from its configured startup directory "
            "(quiesce-and-swap; in-flight deliveries keep draining). Authoring lives in the VS Code "
            "extension — this only redeploys what is already staged. Reload is step-up-gated and may be "
            "held for a second approver (dual-control).",
            class_="muted",
        ),
        reload_form,
        active="config",
    )


def reload_result(result: ReloadResult) -> Markup:
    """The outcome of a successful config reload — the element counts of the now-live graph."""
    tbl = rows_table(
        ["Element", "Count"],
        [
            ["Inbound connections", result.inbound],
            ["Outbound connections", result.outbound],
            ["Routers", result.routers],
        ],
    )
    body = el(
        "div",
        el("h1", "Configuration reloaded"),
        el("p", "The code-first graph is now live.", class_="muted"),
        tbl,
        el("p", el("a", "← Configuration", href="/ui/config")),
        class_="card",
    )
    return page("Reloaded", body, active="config")


def reload_pending(pending: object) -> Markup:
    """Shown when a config reload is held for a second approver (dual-control, ADR 0041)."""
    approval_id = getattr(pending, "approval_id", "")
    body = el(
        "div",
        el("h1", "Reload held for approval"),
        el(
            "p",
            "This configuration reload is held for a second approver (dual-control).",
            class_="muted",
        ),
        el("p", text(f"Approval id: {approval_id}"), class_="muted"),
        el("p", el("a", "← Configuration", href="/ui/config")),
        class_="card",
    )
    return page("Pending approval", body, active="config")


# Nav registration (append-at-tail). Co-located with the builders (ADR 0065 §multi-session-build).
register_nav("config", "/ui/config", "Configuration")
