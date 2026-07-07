# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L3a: monitoring write actions (alert ack/resolve, statistics reset, integrity check, DR activate/release)."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    StatsResetRequest,
    StatsResetTarget,
)
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    assert_same_origin,
    require_ui,
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L3a: monitoring write actions (alert ack/resolve, statistics reset, DB integrity check,
    DR activate/release). Permission-gated to MATCH the JSON handlers (no step-up — they are not
    require_step_up), CSRF-guarded by assert_same_origin, each redirecting back to its page.

    These deliberately do NOT call register_ui_action(): that registry only gates the
    step-up re-auth AUTO-RETRY allow-list (is_safe_ui_action), and these use plain require_ui —
    they never route through /ui/reauth, so they have nothing to register."""
    core = deps.core

    @app.post("/ui/alerts/{alert_id}/ack")
    async def ui_ack_alert(
        alert_id: int,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_DIAGNOSE)),
    ) -> Response:
        assert_same_origin(request)
        await core.ack_alert(alert_id, engine=engine, identity=identity)
        return RedirectResponse("/ui/alerts", status_code=303)

    @app.post("/ui/alerts/{alert_id}/resolve")
    async def ui_resolve_alert(
        alert_id: int,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_DIAGNOSE)),
    ) -> Response:
        assert_same_origin(request)
        await core.resolve_alert(alert_id, engine=engine, identity=identity)
        return RedirectResponse("/ui/alerts", status_code=303)

    @app.post("/ui/statistics/reset")
    async def ui_reset_statistics(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_DIAGNOSE)),
    ) -> Response:
        assert_same_origin(request)
        # The status-page "Reset statistics" button zeroes ALL cumulative counters.
        await core.reset_statistics(StatsResetRequest(all=True), engine=engine, identity=identity)
        return RedirectResponse("/ui/status", status_code=303)

    @app.post("/ui/statistics/reset-one")
    async def ui_reset_statistics_one(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_DIAGNOSE)),
    ) -> Response:
        # L6b (#75 parity): reset ONE connection's counters from its dashboard row (the
        # desktop's per-row/selected reset). role/channel_id/destination arrive as hidden
        # form fields (names aren't path-safe); build a single-target request. The finer
        # per-channel scope check runs inside core.reset_statistics (403 for an out-of-scope
        # user), exactly like the reset-all path.
        assert_same_origin(request)
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        role: Literal["source", "destination"]
        if form.get("role") == "source":
            role = "source"
        elif form.get("role") == "destination":
            role = "destination"
        else:
            return RedirectResponse("/ui", status_code=303)
        channel_id = form.get("channel_id", "")
        destination = form.get("destination") or None
        if not channel_id:
            return RedirectResponse("/ui", status_code=303)
        try:
            target = StatsResetTarget(role=role, channel_id=channel_id, destination=destination)
        except ValidationError:
            return RedirectResponse("/ui", status_code=303)
        await core.reset_statistics(
            StatsResetRequest(targets=[target]), engine=engine, identity=identity
        )
        return RedirectResponse("/ui", status_code=303)

    @app.post("/ui/statistics/reset-many")
    async def ui_reset_statistics_many(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_DIAGNOSE)),
    ) -> Response:
        # Bulk counter reset over a selection of dashboard rows (both roles). Each `sel` is an
        # encoded _row_key (role|b64url(channel_id)|b64url(destination)); build ONE
        # StatsResetRequest and call reset_statistics directly — its per-channel scope check runs
        # per target (a single out-of-scope target 403s the batch, matching reset-one). Undecodable
        # sels are dropped (never reflected). require_ui already re-asserted MONITORING_DIAGNOSE.
        assert_same_origin(request)
        pairs = parse_qsl((await request.body()).decode("utf-8", "replace"))
        targets: list[StatsResetTarget] = []
        seen: set[tuple[str, str, str]] = set()
        for key, value in pairs:
            if key != "sel":
                continue
            decoded = pages.decode_row_key(value)
            if decoded is None or decoded in seen:
                continue
            seen.add(decoded)
            role, channel_id, destination = decoded
            try:
                targets.append(
                    StatsResetTarget(
                        role=role,
                        channel_id=channel_id,
                        destination=destination or None,
                    )
                )
            except ValidationError:
                continue
        await core.reset_statistics(
            StatsResetRequest(targets=targets), engine=engine, identity=identity
        )
        return RedirectResponse("/ui", status_code=303)

    @app.post("/ui/status/integrity-check")
    async def ui_integrity_check(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_DIAGNOSE)),
    ) -> HTMLResponse:
        assert_same_origin(request)
        result = await core.integrity_check(engine=engine, _user=identity)
        return HTMLResponse(pages.integrity_result(result))

    @app.post("/ui/dr/activate")
    async def ui_dr_activate(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.DR_OPERATE)),
    ) -> Response:
        assert_same_origin(request)
        await core.dr_activate(engine=engine, identity=identity, body=None)
        return RedirectResponse("/ui/status", status_code=303)

    @app.post("/ui/dr/release")
    async def ui_dr_release(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.DR_OPERATE)),
    ) -> Response:
        assert_same_origin(request)
        await core.dr_release(engine=engine, identity=identity)
        return RedirectResponse("/ui/status", status_code=303)
