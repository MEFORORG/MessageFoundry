# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The High Availability page and its stepdown control (ADR 0056, BACKLOG #1495)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    ClusterNodeList,
    ClusterStatus,
    ClusterStepdownRequest,
    ClusterStepdownResult,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.redaction import safe_exc

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
)

# The two confirm pages are step-up-UNLOCK GET forms, the purge-confirm shape: a stale step-up 303s to
# /ui/reauth, which GET-redirects back once re-verified, so the operator confirms inside a fresh window.
# Neither POST is registered. A stepdown is never auto-re-POSTed across a re-auth; a stale POST maps back
# to its confirm page instead (reauth_next below), so the operator reads the consequence again first.
register_ui_action(
    r"^/ui/cluster/stepdown-confirm$",
    Permission.CLUSTER_CONTROL,
    auto_retry=False,
    unlock=True,
    label="Open the cluster step-down confirmation",
)
register_ui_action(
    r"^/ui/cluster/force-stepdown-confirm$",
    Permission.CLUSTER_CONTROL,
    auto_retry=False,
    unlock=True,
    label="Open the forced cluster step-down confirmation",
)

_log = logging.getLogger(__name__)


def register(app: FastAPI, deps: UiDeps) -> None:
    """The High Availability page (read-mostly, ``monitoring:read``) and the stepdown control.

    The two POSTs call the JSON ``cluster_stepdown`` handler directly, which skips its
    ``require_step_up(CLUSTER_CONTROL)`` gate, so each re-asserts it through ``require_ui_step_up``. The
    confirm pages also read cluster state through the ``monitoring:read`` handlers, so they assert that
    permission as well and fail closed on either."""
    core = deps.core
    # Whether the current run of failed membership reads has been logged at WARNING. The live
    # fragment polls every few seconds per open tab, so an outage logs one warning, not one per poll,
    # and a read that succeeds again starts a new run.
    outage_logged = False

    async def _state(
        engine: Any, identity: Identity
    ) -> tuple[ClusterStatus, ClusterNodeList | None]:
        """The in-memory status, and the membership and lease rows, or ``None`` for the rows when
        their store read raised (BACKLOG #5932). That read is the only one here that touches the
        store, so a store timeout or outage degrades these pages instead of answering an error body."""
        nonlocal outage_logged
        cluster = await core.cluster_status(engine=engine, _user=identity)
        try:
            nodes = await core.cluster_nodes(engine=engine, _user=identity)
        except HTTPException:
            raise
        except Exception as exc:
            # As broad as the JSON stepdown handler's membership read, for its reason: the store's
            # driver exceptions are not importable here without the optional extras.
            # CancelledError is not an Exception, so a request deadline still unwinds.
            _log.log(
                logging.DEBUG if outage_logged else logging.WARNING,
                "cluster page: node %s could not read cluster membership: %s",
                cluster.node_id,
                safe_exc(exc),
            )
            outage_logged = True
            return cluster, None
        outage_logged = False
        return cluster, nodes

    @app.get("/ui/cluster", response_class=HTMLResponse)
    async def ui_cluster(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
        m: str = Query("", max_length=16),
    ) -> HTMLResponse:
        cluster, nodes = await _state(engine, identity)
        if nodes is None:
            return HTMLResponse(
                pages.high_availability_unreadable(cluster, notice=m), status_code=503
            )
        can_control = identity.has(Permission.CLUSTER_CONTROL)
        return HTMLResponse(
            pages.high_availability(cluster, nodes, can_control=can_control, notice=m)
        )

    @app.get("/ui/cluster/live", response_class=HTMLResponse)
    async def ui_cluster_live(
        engine: Any = Depends(deps.get_engine),
        # activity=False (ASVS 14.3.1): the page's auto-refresh is timer-driven, not user activity.
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ, activity=False)),
    ) -> HTMLResponse:
        cluster, nodes = await _state(engine, identity)
        if nodes is None:
            # 200, not 503: app.js swaps a fragment in only on an ok response, so a refusal here
            # would leave the last good view, with its lease state and control, on screen.
            return HTMLResponse(pages.high_availability_unreadable_fragment(cluster))
        can_control = identity.has(Permission.CLUSTER_CONTROL)
        return HTMLResponse(
            pages.high_availability_fragment(cluster, nodes, can_control=can_control)
        )

    @app.get("/ui/cluster/stepdown-confirm", response_class=HTMLResponse)
    async def ui_cluster_stepdown_confirm(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(Permission.CLUSTER_CONTROL, Permission.MONITORING_READ)
        ),
    ) -> HTMLResponse:
        cluster, nodes = await _state(engine, identity)
        if nodes is None:
            return HTMLResponse(pages.stepdown_confirm_unreadable(force=False), status_code=503)
        return HTMLResponse(pages.stepdown_confirm(cluster, nodes, force=False))

    @app.get("/ui/cluster/force-stepdown-confirm", response_class=HTMLResponse)
    async def ui_cluster_force_stepdown_confirm(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(Permission.CLUSTER_CONTROL, Permission.MONITORING_READ)
        ),
    ) -> HTMLResponse:
        cluster, nodes = await _state(engine, identity)
        if nodes is None:
            return HTMLResponse(pages.stepdown_confirm_unreadable(force=True), status_code=503)
        return HTMLResponse(pages.stepdown_confirm(cluster, nodes, force=True))

    async def _stepdown(
        request: Request, engine: Any, identity: Identity, *, force: bool
    ) -> Response:
        assert_same_origin(request)
        try:
            result: ClusterStepdownResult = await core.cluster_stepdown(
                request, engine=engine, identity=identity, body=ClusterStepdownRequest(force=force)
            )
        except HTTPException as exc:
            # Each refusal the handler raises gets its own page, keyed by the engine's status, with the
            # engine's detail (node ids only) rendered beneath the guidance.
            return HTMLResponse(
                pages.stepdown_refused(exc.status_code, str(exc.detail)),
                status_code=exc.status_code,
            )
        # Keyed on new_leader_eligible, not on force: a forced call that still found a live sibling is
        # an ordinary handover, and only the drain of the last promotable node needs the harder notice.
        notice = "released" if result.new_leader_eligible else "drained"
        return RedirectResponse(f"/ui/cluster?m={notice}", status_code=303)

    @app.post("/ui/cluster/stepdown")
    async def ui_cluster_stepdown(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.CLUSTER_CONTROL,
                reauth_next=lambda _r: "/ui/cluster/stepdown-confirm",
            )
        ),
    ) -> Response:
        return await _stepdown(request, engine, identity, force=False)

    @app.post("/ui/cluster/force-stepdown")
    async def ui_cluster_force_stepdown(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.CLUSTER_CONTROL,
                reauth_next=lambda _r: "/ui/cluster/force-stepdown-confirm",
            )
        ),
    ) -> Response:
        return await _stepdown(request, engine, identity, force=True)
