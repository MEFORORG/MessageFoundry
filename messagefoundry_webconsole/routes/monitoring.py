# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L1a: read-only monitoring pages (alerts + event log)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    register_ui_action,
    require_ui,
)
from ._common import (
    ACTIVE_ALERTS_LIMIT,
    UI_BODY_FILTER_RULES,
    blank_to_none,
    check_filters,
    for_echo,
)

# The two reason reveals are PHI pages (`phi=True`), so a read from a host the session has not
# verified from goes to /ui/reauth and comes back here. Registered for the reason routes/core.py
# gives beside its own PHI pages (vault BACKLOG #2620).
register_ui_action(
    r"^/ui/alerts/[^/?#]+/reason(\?[^#]*)?$",
    Permission.MESSAGES_VIEW_SUMMARY,
    auto_retry=False,
    unlock=True,
)
register_ui_action(
    r"^/ui/events/[^/?#]+/reason(\?[^#]*)?$",
    Permission.MESSAGES_VIEW_SUMMARY,
    auto_retry=False,
    unlock=True,
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L1a: read-only monitoring pages (alerts + event log). Reuses the monitoring JSON handlers
    (no step-up) — ADR 0065, BACKLOG #75 phase 1. Not PHI-free: both pages show a scrubbed free-text
    ``reason`` that ``docs/PHI.md`` section 2 gives a protection level. That reason arrives masked,
    or null without ``messages:view_summary``, and each page has a per-item reveal route (BACKLOG
    #2443): the route is the act, as ``UI_MESSAGE_REVEALS`` makes it for a message's error text."""
    core = deps.core

    async def _alerts_page(
        request: Request, engine: Any, identity: Identity, *, reveal: int | None
    ) -> HTMLResponse:
        # Active instances need monitoring:diagnose, rules need monitoring:read — the page
        # requires BOTH (fail-closed), then calls the handlers directly (their own gates are
        # skipped, so require_ui re-asserts the permissions the same way the other /ui routes do).
        # Pass every param explicitly: calling the handler directly (not via Depends) leaves
        # its Query(...) defaults unresolved, so limit must be a real int here.
        instances = await core.list_active_alerts(
            request=request,
            engine=engine,
            identity=identity,
            limit=ACTIVE_ALERTS_LIMIT,
            reveal=reveal,
        )
        config = await core.alerts_rules(request, _user=identity)
        return HTMLResponse(
            pages.alerts(instances, config, limit=ACTIVE_ALERTS_LIMIT, revealed=reveal)
        )

    @app.get("/ui/alerts", response_class=HTMLResponse)
    async def ui_alerts(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui(Permission.MONITORING_READ, Permission.MONITORING_DIAGNOSE)
        ),
    ) -> HTMLResponse:
        return await _alerts_page(request, engine, identity, reveal=None)

    # The per-alert reveal (BACKLOG #2443, ASVS 14.2.6, owner ruling R12). The page's "Reveal" link
    # beside a masked reason lands here, so the request is the act: it returns that one alert's
    # reason whole, the engine audits it as ``alert_reveal``, and the next bare load is masked
    # again. It asserts messages:view_summary, which unlocks the reason, and phi=True, because it
    # is a PHI read that the in-process handler call does not charge for itself.
    @app.get("/ui/alerts/{alert_id}/reason", response_class=HTMLResponse)
    async def ui_alert_reason(
        alert_id: int,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui(
                Permission.MONITORING_READ,
                Permission.MONITORING_DIAGNOSE,
                Permission.MESSAGES_VIEW_SUMMARY,
                phi=True,
            )
        ),
    ) -> HTMLResponse:
        return await _alerts_page(request, engine, identity, reveal=alert_id)

    @app.get("/ui/events", response_class=HTMLResponse)
    async def ui_events(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
        # Body-validated rather than annotated, as on ui_messages: `connection` is a free-text input
        # on this page's own filter form, so a refusal has to come back as the form carrying what the
        # operator typed. `kind` rides the same request from a select, and splitting the two shapes
        # across one form is what BACKLOG #1740 avoided here.
        connection: str | None = Query(None, max_length=256),
        kind: str | None = Query(None, max_length=64),
    ) -> HTMLResponse:
        return await _events_page(
            request, engine, identity, connection=connection, kind=kind, reveal=None
        )

    # The per-event reveal (BACKLOG #2443), on the terms ui_alert_reason gives. It carries the
    # page's two filters, checked by the same rules, so the operator lands back on the list they
    # were reading.
    @app.get("/ui/events/{event_id}/reason", response_class=HTMLResponse)
    async def ui_event_reason(
        event_id: int,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui(Permission.MONITORING_READ, Permission.MESSAGES_VIEW_SUMMARY, phi=True)
        ),
        connection: str | None = Query(None, max_length=256),
        kind: str | None = Query(None, max_length=64),
    ) -> HTMLResponse:
        return await _events_page(
            request, engine, identity, connection=connection, kind=kind, reveal=event_id
        )

    async def _events_page(
        request: Request,
        engine: Any,
        identity: Identity,
        *,
        connection: str | None,
        kind: str | None,
        reveal: int | None,
    ) -> HTMLResponse:
        # L6b (#75 parity): expose the JSON handler's event-kind filter (a single kind from
        # the fixed dropdown → a one-element kinds list; blank/unknown = no filter).
        # BACKLOG #1740: both filters, against the rules GET /events declares for the same two
        # items -- judged on what ARRIVED, not on the for_echo'd copy below, which has had its
        # control characters stripped and would therefore pass a rule the raw value fails.
        # Each route checks against its OWN row, so the declared table says what each one enforces.
        route = "/ui/events" if reveal is None else "/ui/events/{event_id}/reason"
        refusal = check_filters(
            UI_BODY_FILTER_RULES[route], {"connection": connection, "kind": kind}
        )
        conn, evt_kind = for_echo(connection), for_echo(kind)
        if refusal is not None:
            # No rows: the filter was never applied, and a table under a refusal banner would read
            # as the result of the filter the operator typed.
            return HTMLResponse(
                pages.events([], connection=conn, kind=evt_kind, error=refusal), status_code=400
            )
        kinds = [kind] if kind else None
        rows = await core.list_connection_events(
            engine=engine,
            identity=identity,
            # blank_to_none: the handler's channel guard runs on any value that is not None,
            # so a submitted-but-empty connection box made a channel-scoped operator 403 and wrote
            # a false auth.channel_denied row naming them, every time they used this form.
            connection=blank_to_none(connection),
            kind=kinds,
            since=None,
            limit=100,
            request=request,
            reveal=reveal,
        )
        return HTMLResponse(pages.events(rows, connection=conn, kind=evt_kind, revealed=reveal))

    async def _flow_data(request: Request, engine: Any, identity: Identity) -> tuple[Any, Any]:
        """Fetch the two read-only monitoring:read sources for the Flow & trends page (BACKLOG #76):
        the status-colored graph (from the Registry edges) + the metrics-history ring. Their own
        ``Depends`` gates are skipped on a direct call, so ``require_ui`` re-asserted the permission."""
        graph = await core.graph_edges(engine=engine, identity=identity)
        history = await core.metrics_history(request, _user=identity)
        return graph, history

    @app.get("/ui/monitoring", response_class=HTMLResponse)
    async def ui_monitoring(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        # #76: the status-colored by-name data-flow graph + the historical queue-trend chart, both
        # inline SVG (CSP script-src 'self'). Read-only, metadata only — no message body.
        graph, history = await _flow_data(request, engine, identity)
        return HTMLResponse(pages.flow_and_trends(graph, history))

    @app.get("/ui/monitoring/live", response_class=HTMLResponse)
    async def ui_monitoring_live(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # activity=False (ASVS 14.3.1): the Flow page's auto-refresh is timer-driven, not user activity.
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ, activity=False)),
    ) -> HTMLResponse:
        # The poll target app.js swaps into the page's [data-mf-fragment] container (server-rendered,
        # already-escaped) so the graph's live status colours + the trend refresh without a WebSocket.
        graph, history = await _flow_data(request, engine, identity)
        return HTMLResponse(pages.flow_and_trends_fragment(graph, history))
