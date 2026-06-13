"""Localhost FastAPI surface for the console.

This is the *only* boundary a client uses, so in-process / local-daemon / remote
deployments are indistinguishable to the UI. Routes resolve the live :class:`Engine`
from ``app.state`` at request time (not at construction), which lets the same app object
be driven two ways:

* :func:`create_app(engine)` — bind an engine the caller already manages (embedding, and
  the async test client).
* :func:`create_managed_app(...)` — own the engine via an ASGI lifespan (the CLI server,
  and anything driven by a synchronous test client).

Authentication + RBAC are enforced whenever an enabled :class:`AuthService` is attached (the
``serve`` path always attaches one). With **no** auth attached the routes are **fail-closed** (403)
unless the app explicitly opts out via ``allow_no_auth=True`` (embedding / dev), in which case
requests run as the full-access system identity (SYS-1). The API still binds localhost by default;
remote exposure (TLS) is later.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from messagefoundry import __version__
from messagefoundry.api.models import (
    AiPolicy,
    ChannelInfo,
    ConnectionRow,
    DbInfo,
    DeadLetterList,
    DeadLetterReplayRequest,
    DeadLetterReplayResult,
    DeadLetterRow,
    EngineInfo,
    EventInfo,
    Health,
    IntegrityResult,
    MessageDetail,
    MessageList,
    MessageSummary,
    OutboxInfo,
    PurgeResult,
    ReloadRequest,
    ReloadResult,
    ReplayResult,
    StatsResponse,
    SystemStatus,
)
from messagefoundry.api.auth_routes import add_auth_routes
from messagefoundry.api.field_authz import count_exposed, redact_unauthorized
from messagefoundry.api.security import (
    authorize_ws,
    optional_identity,
    require,
    require_phi_read,
    ws_token,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.service import AuthService, BootstrapAdmin
from messagefoundry.config.ai_policy import resolve_effective_policy
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
)
from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    AuthSettings,
    EgressSettings,
    RetentionSettings,
    StoreSettings,
)
from messagefoundry.config.wiring import EnvRef, WiringError, load_config
from messagefoundry.pipeline import ConfigReloadDenied, Engine
from messagefoundry.pipeline.alert_sinks import notifier_from_settings
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import Row, open_store, sqlite_settings
from messagefoundry.store.base import Store
from messagefoundry.store.store import _secure_file

__all__ = ["create_app", "create_managed_app"]

_RATE_WINDOW = 60.0  # seconds; window for the backlog throughput estimate
_MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB cap on HTTP request bodies (API-INPUT)
_MAX_WS_CONNECTIONS = 64  # cap concurrent /ws/stats sockets (API-WS)
_WS_REVALIDATE_SECONDS = 30.0  # re-check the session on an open /ws/stats this often (API-WS)
_log = logging.getLogger(__name__)


def _peer_display(value: Any) -> str | None:
    """Render a connector address field for the dashboard: a literal, or an ``env()`` reference shown
    symbolically (``env:<key>``). The live value is resolved per-instance; the spec only holds the ref."""
    if value is None:
        return None
    if isinstance(value, EnvRef):
        return f"env:{value.key}"
    return str(value)


def _peer_port(type_value: str, settings: dict[str, Any]) -> tuple[str | None, int | None]:
    """Best-effort (peer, port) for a connector: MLLP host+port, or a file directory."""
    if type_value == "mllp":
        port = settings.get("port")
        port_int = None if port is None or isinstance(port, EnvRef) else int(port)
        return (_peer_display(settings.get("host")), port_int)
    if type_value == "file":
        return (_peer_display(settings.get("directory")), None)
    return (None, None)


# Display labels for the connection method/protocol. Includes types not yet built so the
# column reads well the moment a connector lands; unknown types fall back to upper-case.
_METHOD_LABELS = {
    "mllp": "MLLP",
    "file": "File",
    "tcp": "TCP",
    "soap": "SOAP",
    "rest": "REST",
    "http": "HTTP",
    "sftp": "SFTP",
    "db": "Database",
}


def _method_label(type_value: str) -> str:
    return _METHOD_LABELS.get(type_value, type_value.upper())


def _backlog(depth: int, recent: int) -> float | None:
    """Estimated seconds to clear the queue: 0 if empty, None if queued but nothing draining."""
    if depth == 0:
        return 0.0
    return depth * _RATE_WINDOW / recent if recent > 0 else None


def _get_engine(request: Request) -> Engine:
    engine: Engine | None = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="engine not started")
    return engine


def _summary(row: Row) -> MessageSummary:
    # dict() so optional columns (last_event on list rows; summary/metadata) read via .get,
    # letting the same builder serve list rows and SELECT * detail rows.
    d = dict(row)
    return MessageSummary(
        id=d["id"],
        channel_id=d["channel_id"],
        received_at=d["received_at"],
        source_type=d.get("source_type"),
        control_id=d.get("control_id"),
        message_type=d.get("message_type"),
        status=d["status"],
        error=d.get("error"),
        event=d.get("last_event"),
        summary=d.get("summary"),
        metadata=d.get("metadata"),
    )


def _dead_row(row: Row) -> DeadLetterRow:
    d = dict(row)
    return DeadLetterRow(
        outbox_id=d["outbox_id"],
        message_id=d["message_id"],
        channel_id=d["channel_id"],
        destination_name=d["destination_name"],
        attempts=d["attempts"],
        last_error=d.get("last_error"),
        failed_at=d["updated_at"],
        control_id=d.get("control_id"),
        message_type=d.get("message_type"),
        received_at=d["received_at"],
        summary=d.get("summary"),
    )


def _scope(identity: Identity) -> list[str] | None:
    """The caller's per-channel allow-list for store filters (None = all channels)."""
    return None if identity.allowed_channels is None else sorted(identity.allowed_channels)


async def _audit_channel_denied(engine: Engine, identity: Identity, channel: str | None) -> None:
    """Audit a per-channel RBAC denial (mirrors auth.permission_denied)."""
    await engine.store.record_audit(
        "auth.channel_denied",
        actor=identity.username,
        channel_id=channel,
        detail=json.dumps({"channel": channel}),
    )


class _SummaryAuditCoalescer:
    """Coalesces PHI-summary access auditing into ONE ``summary_access`` audit row per
    ``(actor, channel-scope, hour)`` window, carrying the running count of summaries exposed in that
    window (review M-5).

    Auditing is **server-enforced**: every list response that returns non-redacted summaries is
    counted, regardless of any client flag — so a scripted bulk fetch can't harvest the patient census
    unaudited. Coalescing keeps routine console polling to one row/hour while a bulk harvest shows a
    large count. A window's total is flushed when a later summary access rolls into a new hour (the
    keyed window, plus a sweep so a *different* actor's later access also flushes stragglers); the
    active window is also flushed on :meth:`flush` (engine shutdown). The in-process dict is safe
    because the engine is a single uvicorn worker (single-connection store + ``asyncio.Lock``)."""

    def __init__(self) -> None:
        # (actor, scope) -> {"hour": int, "count": int}; scope is the channel filter ("" = all channels)
        self._windows: dict[tuple[str | None, str], dict[str, int]] = {}

    def _roll(
        self, actor: str | None, scope: str, count: int, hour: int
    ) -> list[tuple[str | None, str, int, int]]:
        """Accumulate ``count`` into the ``(actor, scope)`` window for ``hour`` and return any windows
        to flush now — every window whose hour has passed. Synchronous (no ``await``), so the dict is
        mutated atomically w.r.t. the event loop and a window can't be double-emitted."""
        emit: list[tuple[str | None, str, int, int]] = []
        for (a, sc), win in list(self._windows.items()):
            if win["hour"] != hour:
                emit.append((a, sc, win["hour"], win["count"]))
                del self._windows[(a, sc)]
        self._windows.setdefault((actor, scope), {"hour": hour, "count": 0})["count"] += count
        return emit

    async def note(
        self, store: Store, actor: str | None, scope: str | None, count: int, now: float
    ) -> None:
        """Count ``count`` exposed summaries for ``actor``; emit a coalesced audit row for any window
        that just rolled over. No-op when nothing was exposed."""
        if count <= 0:
            return
        for a, sc, win_hour, win_count in self._roll(actor, scope or "", count, int(now // 3600)):
            await self._emit(store, a, sc, win_hour, win_count)

    async def flush(self, store: Store) -> None:
        """Emit every pending window (e.g. on engine shutdown) so an active window isn't lost."""
        windows = list(self._windows.items())
        self._windows.clear()
        for (a, sc), win in windows:
            await self._emit(store, a, sc, win["hour"], win["count"])

    @staticmethod
    async def _emit(store: Store, actor: str | None, scope: str, hour: int, count: int) -> None:
        await store.record_audit(
            "summary_access",
            actor=actor,
            channel_id=(scope or None),
            detail=json.dumps({"count": count, "window_start": hour * 3600}),
        )


def create_app(
    engine: Engine | None = None,
    *,
    lifespan: object | None = None,
    auth: AuthService | None = None,
    ai_settings: AiSettings | None = None,
    expose_docs: bool = False,
    allow_no_auth: bool = False,
    ws_allowed_origins: Sequence[str] = (),
) -> FastAPI:
    # The interactive docs (/docs, /redoc) and the OpenAPI schema (/openapi.json) are off by
    # default: they widen the attack surface and disclose the schema, which matters the moment the
    # API binds off-loopback. Opt in with [api] expose_docs = true. See docs/PHI.md §10.
    app = FastAPI(
        title="MessageFoundry",
        version=__version__,
        lifespan=lifespan,  # type: ignore[arg-type]
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
    )
    if engine is not None:
        app.state.engine = engine
    if auth is not None:
        app.state.auth = auth
    if ai_settings is not None:
        app.state.ai = ai_settings
    # Fail-closed when no auth is attached unless explicitly opted out (embedding/dev) — SYS-1.
    app.state.allow_no_auth = allow_no_auth
    app.state.ws_count = 0  # live /ws/stats connection count (API-WS cap)
    app.state.ws_allowed_origins = tuple(
        ws_allowed_origins
    )  # browser Origins for /ws/stats (4.4.2)
    app.state.summary_auditor = _SummaryAuditCoalescer()  # coalesced PHI-summary access audit (M-5)
    add_auth_routes(app)

    @app.exception_handler(Exception)
    async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        # Catch-all so an unexpected error returns a generic 500 — never a stack trace or internal
        # detail to the client (ASVS 16.5.1). The real cause is logged server-side only; we log the
        # exception TYPE + route, not str(exc), to avoid a stray PHI fragment reaching the general
        # log (the "never log bodies" rule; centralized redaction is the WP-6c follow-up).
        _log.error(
            "unhandled error on %s %s: %s", request.method, request.url.path, type(exc).__name__
        )
        return JSONResponse({"detail": "internal error"}, status_code=500)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Any) -> Any:
        # Defense-in-depth response headers (ASVS 3.4.4 / 3.4.5 / 3.2.1). The shipped client is a
        # desktop app, but these are mandatory the moment a browser/off-loopback client appears and
        # cost nothing on a JSON API. HSTS is only meaningful over TLS, so it is emitted only when the
        # request actually arrived over https (wired when API TLS lands — WP-13a).
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.middleware("http")
    async def _limit_request_body(request: Request, call_next: Any) -> Any:
        # The HTTP API carries only small JSON (HL7 payloads arrive via MLLP/file, not here), so a
        # generous cap rejects oversized/abusive bodies early (API-INPUT).
        # Rejections are logged (ASVS 16.3.3) — these are control-bypass attempts (a pre-auth memory
        # DoS probe) and were previously dropped silently. We log to the rotating general log rather
        # than the audit_log: it's pre-auth (no actor) and a flood must not grow the audit DB.
        client = request.client.host if request.client else None
        length = request.headers.get("content-length")
        if length is None:
            # No Content-Length means a chunked body (HTTP/1.1 requires one or the other), which the
            # Content-Length cap can't bound up front — Starlette would buffer it unbounded, a pre-auth
            # memory DoS. We only accept small JSON, so require a Content-Length (review M-19).
            if "chunked" in request.headers.get("transfer-encoding", "").lower():
                _log.warning(
                    "rejected chunked request body on %s from %s", request.url.path, client
                )
                return JSONResponse(
                    {"detail": "chunked request bodies are not accepted; send a Content-Length"},
                    status_code=411,
                )
            return await call_next(request)
        try:
            too_big = int(length) > _MAX_REQUEST_BODY_BYTES
        except ValueError:
            _log.warning("rejected invalid Content-Length on %s from %s", request.url.path, client)
            return JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
        if too_big:
            _log.warning("rejected oversized request body on %s from %s", request.url.path, client)
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/health", response_model=Health)
    async def health() -> Health:
        return Health(version=__version__)

    @app.get("/ai/policy", response_model=AiPolicy)
    async def ai_policy(
        request: Request, identity: Identity | None = Depends(optional_identity)
    ) -> AiPolicy:
        """The central AI-assistance policy (mode/scope/environment) plus the caller's
        ``assist_permitted`` bit, for the IDE gate.

        Intentionally NOT behind ``require()``: the install policy is non-sensitive operational
        config and must be readable even by a tokenless client, so a central ``off`` is honored.
        ``assist_permitted`` carries the identity-dependent bit (``None`` = RBAC not evaluable, i.e.
        no/invalid token under enabled auth). Policy reads are not audited in this MVP."""
        ai = getattr(request.app.state, "ai", None) or AiSettings()
        eff = resolve_effective_policy(
            mode=ai.mode, data_scope=ai.data_scope, environment=ai.environment
        )
        permitted = None if identity is None else identity.has(Permission.AI_ASSIST)
        return AiPolicy(
            mode=eff.mode,
            data_scope=eff.data_scope,
            environment=eff.environment,
            assist_permitted=permitted,
            reason=eff.reason,
        )

    # --- connections list (inbound connections, for the Log Search filter) ---

    @app.get("/channels", response_model=list[ChannelInfo])
    async def list_channels(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> list[ChannelInfo]:
        """Inbound connections as ChannelInfo (id = connection name) for the Log Search filter."""
        runner = engine.registry_runner
        if runner is None:
            return []
        return [
            ChannelInfo(
                id=name,
                name=name,
                enabled=True,
                running=runner.inbound_running(name),
                source_type=ic.spec.type.value,
                destinations=[],
            )
            for name, ic in runner.registry.inbound.items()
        ]

    # --- connections (per-endpoint dashboard) --------------------------------

    @app.get("/connections", response_model=list[ConnectionRow])
    async def list_connections(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> list[ConnectionRow]:
        now = time.time()
        metrics = await engine.store.connection_metrics(
            since=engine.started_at, now=now, rate_window=_RATE_WINDOW
        )
        rows: list[ConnectionRow] = []

        # A source row per inbound connection, and a destination row per (inbound → outbound)
        # edge that has carried traffic (the outbox metrics are keyed that way).
        rr = engine.registry_runner
        if rr is not None:
            reg = rr.registry
            rstatus = "running" if rr.running else "stopped"
            for iname, ic in reg.inbound.items():
                inb = metrics.inbound.get(iname)
                speer, sport = _peer_port(ic.spec.type.value, ic.spec.settings)
                rows.append(
                    ConnectionRow(
                        role="source",
                        channel_id=iname,
                        channel_name=iname,
                        destination=None,
                        name=f"{iname} ▸ in",
                        status="running" if rr.inbound_running(iname) else "stopped",
                        direction="in",
                        method=_method_label(ic.spec.type.value),
                        peer=speer,
                        port=sport,
                        queue_depth=None,
                        idle_seconds=(now - inb.last_at) if inb and inb.last_at else None,
                        alerts_active=0,
                        errored=inb.errored if inb else 0,
                        read=inb.read if inb else 0,
                        written=None,
                        backlog_seconds=None,
                        delivered_age_seconds=None,
                    )
                )
            for (cid, dname), dm in metrics.destinations.items():
                if cid not in reg.inbound:
                    continue  # a declarative-channel edge, already emitted above
                oc = reg.outbound.get(dname)
                # An outbound the live graph no longer declares (removed by a reload) keeps draining
                # its queued rows — report it honestly as "draining" with an unknown method, rather
                # than mislabeling it as a running File connector.
                if oc is not None:
                    dmethod = _method_label(oc.spec.type.value)
                    dpeer, dport = _peer_port(oc.spec.type.value, oc.spec.settings)
                    dstatus = rstatus
                else:
                    dmethod, dpeer, dport, dstatus = "—", None, None, "draining"
                rows.append(
                    ConnectionRow(
                        role="destination",
                        channel_id=cid,
                        channel_name=cid,
                        destination=dname,
                        name=f"{cid} ▸ {dname}",
                        status=dstatus,
                        direction="out",
                        method=dmethod,
                        peer=dpeer,
                        port=dport,
                        queue_depth=dm.queue_depth,
                        idle_seconds=(now - dm.last_done_at) if dm.last_done_at else None,
                        alerts_active=0,
                        errored=dm.dead,
                        read=None,
                        written=dm.written,
                        backlog_seconds=_backlog(dm.queue_depth, dm.recent_done),
                        delivered_age_seconds=(
                            (now - dm.oldest_pending_at) if dm.oldest_pending_at else None
                        ),
                    )
                )
        return rows

    # --- code-first connection operations ------------------------------------

    def _inbound(engine: Engine, name: str) -> RegistryRunner:
        rr = engine.registry_runner
        if rr is None or name not in rr.registry.inbound:
            raise HTTPException(404, f"no such inbound connection: {name}")
        return rr

    async def _control_guard(engine: Engine, identity: Identity, name: str) -> None:
        # Controlling an inbound connection is scoped per-channel (the connection IS the channel).
        if not identity.can_access_channel(name):
            await _audit_channel_denied(engine, identity, name)
            raise HTTPException(403, "not authorized for this connection")

    @app.post("/connections/{name}/start")
    async def start_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        await _control_guard(engine, identity, name)
        rr = _inbound(engine, name)
        await rr.start_inbound(name)
        return {"name": name, "running": rr.inbound_running(name)}

    @app.post("/connections/{name}/stop")
    async def stop_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        await _control_guard(engine, identity, name)
        rr = _inbound(engine, name)
        await rr.stop_inbound(name)
        return {"name": name, "running": rr.inbound_running(name)}

    @app.post("/connections/{name}/restart")
    async def restart_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        await _control_guard(engine, identity, name)
        rr = _inbound(engine, name)
        await rr.restart_inbound(name)
        return {"name": name, "running": rr.inbound_running(name)}

    @app.post("/connections/{name}/purge", response_model=PurgeResult)
    async def purge_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        scope: str = Query("all", pattern="^(top|all)$"),
        identity: Identity = Depends(require(Permission.MESSAGES_PURGE)),
    ) -> PurgeResult:
        """Soft-cancel queued deliveries to an outbound connection (across all inbounds)."""
        # Purge targets an outbound and spans every inbound feeding it, so it can't be confined to a
        # per-(inbound-)channel scope — a channel-scoped user may not purge a shared outbound.
        if identity.allowed_channels is not None:
            await _audit_channel_denied(engine, identity, name)
            raise HTTPException(
                403, "channel-scoped users cannot purge a shared outbound connection"
            )
        rr = engine.registry_runner
        if rr is None or name not in rr.registry.outbound:
            raise HTTPException(404, f"no such outbound connection: {name}")
        cancelled = await engine.store.cancel_queued(None, name, top_only=(scope == "top"))
        return PurgeResult(cancelled=cancelled)

    # --- dead letters (verify + recover) -------------------------------------

    @app.get("/dead-letters", response_model=DeadLetterList)
    async def list_dead_letters(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_READ)),
        channel_id: str | None = None,
        destination_name: str | None = None,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> DeadLetterList:
        """Dead-lettered deliveries (newest first), optionally scoped to an inbound/outbound."""
        allowed = _scope(
            identity
        )  # per-channel RBAC: restrict to the caller's channels (None = all)
        rows = await engine.store.list_dead(
            channel_id=channel_id,
            destination_name=destination_name,
            limit=limit,
            offset=offset,
            allowed_channels=allowed,
        )
        total = await engine.store.count_dead(
            channel_id=channel_id, destination_name=destination_name, allowed_channels=allowed
        )
        dead = [_dead_row(r) for r in rows]
        # Same centralized per-property PHI gate as /messages (WP-9): messages:view_summary unlocks the
        # patient-identifying `summary` and the delivery `last_error` (which can quote field values —
        # review low-8); a caller without it gets them nulled. Exposure audited server-side (M-5).
        dead = [redact_unauthorized(d, identity) for d in dead]
        exposed = count_exposed(dead)
        if exposed:
            await request.app.state.summary_auditor.note(
                engine.store, identity.username, channel_id, exposed, time.time()
            )
        return DeadLetterList(total=total, limit=limit, offset=offset, dead_letters=dead)

    @app.post("/dead-letters/replay", response_model=DeadLetterReplayResult)
    async def replay_dead_letters(
        req: DeadLetterReplayRequest,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MESSAGES_REPLAY)),
    ) -> DeadLetterReplayResult:
        """Re-queue dead-lettered deliveries (optionally scoped). Already-delivered rows are left
        alone; each affected message reverts from ``error`` to ``received`` and re-drains."""
        # A channel-scoped user must target one of their channels (replay isn't channel-filtered at
        # the engine level, so an unscoped "replay all" would cross channels).
        if identity.allowed_channels is not None and not identity.can_access_channel(
            req.channel_id
        ):
            await _audit_channel_denied(engine, identity, req.channel_id)
            raise HTTPException(403, "specify a channel within your scope to replay")
        requeued = await engine.replay_dead(
            channel_id=req.channel_id, destination_name=req.destination_name
        )
        if requeued:  # only when PHI was actually re-transmitted (review M-4)
            await engine.store.record_audit(
                "dead_letter_replay",
                actor=identity.username,
                channel_id=req.channel_id,
                detail=json.dumps({"destination_name": req.destination_name, "requeued": requeued}),
            )
        return DeadLetterReplayResult(requeued=requeued)

    # --- config promote / reload ---------------------------------------------

    @app.post("/config/reload", response_model=ReloadResult)
    async def reload_config(
        req: ReloadRequest,
        engine: Engine = Depends(_get_engine),
        user: Identity = Depends(require(Permission.CONFIG_DEPLOY)),
    ) -> ReloadResult:
        """Load the code-first graph and atomically apply it to the running engine (quiesce-and-swap;
        in-flight outbox deliveries keep draining). ``config_dir`` defaults to the server's startup
        --config dir and must resolve within an allowed reload root — the loader executes Python, so
        an arbitrary path is refused (403). A bad/empty config is rejected and the running graph is
        left untouched. Every reload (and dry-run) is audited. Requires ``config:deploy``.

        ``dry_run=true`` is the promote pre-flight: it validates the graph against THIS environment's
        values (a missing ``env()`` value → 422) and reports the would-be graph **without** swapping.

        Error responses are intentionally generic (the detail is logged server-side, not returned)
        so a config:deploy holder can't probe the filesystem via reload error text."""
        try:
            registry = await engine.reload(req.config_dir, dry_run=req.dry_run)
        except ConfigReloadDenied as exc:
            await engine.store.record_audit(
                "config_reload_denied",
                actor=user.username,
                detail=json.dumps({"requested": req.config_dir, "dry_run": req.dry_run}),
            )
            raise HTTPException(403, "config directory is not an allowed reload root") from exc
        except FileNotFoundError as exc:
            _log.warning("config reload failed (missing dir): %s", exc)
            await engine.store.record_audit(
                "config_reload_failed",
                actor=user.username,
                detail=json.dumps(
                    {"requested": req.config_dir, "dry_run": req.dry_run, "reason": "not_found"}
                ),
            )
            raise HTTPException(404, "config directory not found") from exc
        except WiringError as exc:
            _log.warning("config reload failed (invalid config): %s", exc)
            await engine.store.record_audit(
                "config_reload_failed",
                actor=user.username,
                detail=json.dumps(
                    {
                        "requested": req.config_dir,
                        "dry_run": req.dry_run,
                        "reason": "invalid_config",
                    }
                ),
            )
            raise HTTPException(422, "invalid configuration") from exc
        await engine.store.record_audit(
            "config_reload_check" if req.dry_run else "config_reload",
            actor=user.username,
            detail=json.dumps(
                {
                    "dir": str(engine.last_reload_dir) if engine.last_reload_dir else None,
                    "inbound": len(registry.inbound),
                    "outbound": len(registry.outbound),
                    "dry_run": req.dry_run,
                }
            ),
        )
        rr = engine.registry_runner
        return ReloadResult(
            inbound=len(registry.inbound),
            outbound=len(registry.outbound),
            routers=len(registry.routers),
            handlers=len(registry.handlers),
            running=bool(rr and rr.running),
            dry_run=req.dry_run,
        )

    # --- messages ------------------------------------------------------------

    @app.get("/messages", response_model=MessageList)
    async def list_messages(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_READ)),
        channel_id: str | None = Query(None, max_length=256),
        status: str | None = Query(None, max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> MessageList:
        filters = dict(
            channel_id=channel_id,
            status=status,
            message_type=message_type,
            control_id=control_id,
        )
        allowed = _scope(identity)  # per-channel RBAC: only the caller's channels (None = all)
        rows = await engine.store.list_messages(
            limit=limit, offset=offset, allowed_channels=allowed, **filters
        )
        total = await engine.store.count_messages(allowed_channels=allowed, **filters)
        messages = [_summary(r) for r in rows]
        # Per-property PHI gate, centralized in api/field_authz (WP-9, ASVS 8.2.3): a caller without
        # messages:view_summary gets `summary` AND `error` (handler exception text can quote field
        # values — review low-8) nulled; the detail endpoint keeps them, gated instead by
        # messages:view_raw which already exposes the body.
        messages = [redact_unauthorized(m, identity) for m in messages]
        # Every patient-identifying value actually returned is audited SERVER-SIDE (coalesced per
        # actor/hour) — never gated on a client flag, so a scripted bulk fetch can't harvest the
        # patient census unaudited (review M-5). Counted post-redaction = exactly what's returned.
        exposed = count_exposed(messages)
        if exposed:
            await request.app.state.summary_auditor.note(
                engine.store, identity.username, channel_id, exposed, time.time()
            )
        return MessageList(total=total, limit=limit, offset=offset, messages=messages)

    @app.get("/messages/{message_id}", response_model=MessageDetail)
    async def get_message(
        message_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_VIEW_RAW)),
    ) -> MessageDetail:
        row = await engine.store.get_message(message_id)
        # 404 (not 403) when the message is outside the caller's channel scope — don't reveal that a
        # message exists in another tenant's channel (per-channel RBAC).
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")
        # Opening a body is PHI access — record it (with the viewer) before returning. record_view
        # gives the per-message timeline; record_audit puts it in the tamper-evident, GET /audit-visible
        # compliance chain (docs/PHI.md §6 names message_view as audited — review M-3).
        await engine.store.record_view(message_id, actor=identity.username)
        await engine.store.record_audit(
            "message_view",
            actor=identity.username,
            channel_id=row["channel_id"],
            detail=json.dumps({"message_id": message_id}),
        )
        outbox = await engine.store.outbox_for(message_id)
        events = await engine.store.events_for(message_id)
        return MessageDetail(
            **_summary(row).model_dump(),
            raw=row["raw"],
            outbox=[
                OutboxInfo(
                    id=o["id"],
                    destination_name=o["destination_name"],
                    status=o["status"],
                    attempts=o["attempts"],
                    next_attempt_at=o["next_attempt_at"],
                    last_error=o["last_error"],
                )
                for o in outbox
            ],
            events=[
                EventInfo(
                    ts=e["ts"],
                    event=e["event"],
                    destination=e["destination"],
                    detail=e["detail"],
                )
                for e in events
            ],
        )

    @app.post("/messages/{message_id}/replay", response_model=ReplayResult)
    async def replay_message(
        message_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MESSAGES_REPLAY)),
    ) -> ReplayResult:
        row = await engine.store.get_message(message_id)
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")
        requeued = await engine.replay(message_id)
        if requeued == 0:
            # The message exists (checked above) but has no re-queueable outbox rows — it errored,
            # was filtered, or routed nowhere. Replaying is a no-op there; say so rather than report
            # a misleading 200/requeued=0 (and the store leaves its disposition intact — review M-2).
            raise HTTPException(
                409,
                f"message {message_id} has no deliveries to replay "
                "(it errored, was filtered, or routed nowhere)",
            )
        # An actual re-transmission of PHI: record who did it in the tamper-evident chain (review M-4).
        await engine.store.record_audit(
            "message_replay",
            actor=identity.username,
            channel_id=row["channel_id"],
            detail=json.dumps({"message_id": message_id, "requeued": requeued}),
        )
        return ReplayResult(message_id=message_id, requeued=requeued)

    # --- stats ---------------------------------------------------------------

    @app.get("/stats", response_model=StatsResponse)
    async def stats(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> StatsResponse:
        return StatsResponse(outbox_by_status=await engine.store.stats())

    # --- engine + DB status --------------------------------------------------

    @app.get("/status", response_model=SystemStatus)
    async def system_status(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> SystemStatus:
        total = running = 0
        rr = engine.registry_runner
        if rr is not None:  # one "channel" per inbound connection
            total = len(rr.registry.inbound)
            running = sum(1 for name in rr.registry.inbound if rr.inbound_running(name))
        db = await engine.store.db_status()
        return SystemStatus(
            engine=EngineInfo(
                version=__version__,
                uptime_seconds=max(0.0, time.time() - engine.started_at)
                if engine.started_at
                else 0.0,
                pid=os.getpid(),
                channels_total=total,
                channels_running=running,
                channels_stopped=total - running,
                outbox_by_status=await engine.store.stats(),
            ),
            db=DbInfo(
                path=db.path,
                size_bytes=db.size_bytes,
                disk_free_bytes=db.disk_free_bytes,
                journal_mode=db.journal_mode,
                messages=db.messages,
                events=db.events,
                audit=db.audit,
            ),
        )

    @app.post("/status/integrity-check", response_model=IntegrityResult)
    async def integrity_check(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
    ) -> IntegrityResult:
        """Run a database integrity check on demand (PRAGMA quick_check)."""
        ok, detail = await engine.store.integrity_check()
        return IntegrityResult(ok=ok, detail=detail)

    @app.websocket("/ws/stats")
    async def ws_stats(websocket: WebSocket) -> None:
        """Push queue-depth stats to the console roughly once a second until it disconnects — the
        live monitor feed. The session is re-validated periodically so a revoked/expired/downgraded
        token can't keep streaming forever, and concurrent sockets are capped (API-WS)."""
        identity = await authorize_ws(websocket, Permission.MONITORING_READ)
        if identity is None:
            await websocket.close(code=1008)  # policy violation (unauthenticated/forbidden)
            return
        engine_obj: Engine | None = getattr(websocket.app.state, "engine", None)
        if engine_obj is None:
            await websocket.close(code=1011)
            return
        state = websocket.app.state
        if getattr(state, "ws_count", 0) >= _MAX_WS_CONNECTIONS:
            await websocket.close(code=1013)  # try again later — too many live monitor sockets
            return
        auth = getattr(state, "auth", None)
        token = ws_token(websocket)
        await websocket.accept()
        state.ws_count = getattr(state, "ws_count", 0) + 1
        elapsed = 0.0
        try:
            while True:
                await websocket.send_json({"outbox_by_status": await engine_obj.store.stats()})
                await asyncio.sleep(1.0)
                elapsed += 1.0
                if auth is not None and auth.enabled and elapsed >= _WS_REVALIDATE_SECONDS:
                    elapsed = 0.0
                    # activity=False: this keepalive must not reset the session's idle clock.
                    current = await auth.identity_for_token(token, activity=False)
                    if current is None or not current.has(Permission.MONITORING_READ):
                        await websocket.close(code=1008)
                        return
        except WebSocketDisconnect:
            return
        finally:
            state.ws_count = max(0, getattr(state, "ws_count", 1) - 1)

    return app


def _emit_bootstrap_admin(bootstrap: BootstrapAdmin, store_settings: StoreSettings) -> None:
    """Persist the one-time bootstrap password to a restricted file — never the rotating log.

    Until rotated it is a standing Administrator credential, so it must not land in NSSM's broadly
    readable stdout capture. Write it to an owner-only file the operator consumes and deletes; log
    only the location. Paired with server-side must_change_password enforcement, it dies at first login.
    """
    base = Path(store_settings.path or ".").resolve()
    secret_file = base.parent / "bootstrap-admin.txt"
    secret_file.write_text(
        f"username: {bootstrap.username}\npassword: {bootstrap.password}\n", encoding="utf-8"
    )
    # Reuse the store's platform-correct primitive: os.chmod(0o600) is a no-op on Windows (the NSSM
    # deployment target), so _secure_file sets an owner-only DACL via icacls there, chmod on POSIX.
    _secure_file(secret_file)
    _log.warning(
        "Created bootstrap admin %r; one-time password written to %s — sign in, change it, then "
        "delete that file.",
        bootstrap.username,
        secret_file,
    )


_SESSION_REAP_INTERVAL = 3600.0  # purge expired/idle sessions hourly to bound the sessions table


async def _session_reaper(store: Store) -> None:
    """Drop expired session rows (immediately, then on an interval) until the task is cancelled.

    A transient store error must not kill the reaper for the process lifetime (it would let the
    sessions table grow unbounded, and its stored exception could later abort lifespan shutdown) —
    log and retry next interval (review M-33)."""
    while True:
        try:
            await store.purge_expired_sessions()
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("session reaper: purge failed; will retry next interval")
        await asyncio.sleep(_SESSION_REAP_INTERVAL)


def create_managed_app(
    *,
    db_path: str | Path | None = None,
    store_settings: StoreSettings | None = None,
    config_dir: str | Path | None = None,
    config_reload_roots: Sequence[str] = (),
    poll_interval: float = 0.25,
    synchronous: str = "NORMAL",
    inbound_bind_host: str = "127.0.0.1",
    delivery_defaults: RetryPolicy | None = None,
    ordering_default: OrderingMode | None = None,
    internal_error_default: InternalErrorPolicy | None = None,
    buildup_default: BuildupThreshold | None = None,
    ack_after_default: AckAfter | None = None,
    env_values: Mapping[str, Any] | None = None,
    env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
    auth_settings: AuthSettings | None = None,
    ai_settings: AiSettings | None = None,
    alerts_settings: AlertsSettings | None = None,
    retention_settings: RetentionSettings | None = None,
    egress_settings: EgressSettings | None = None,
    expose_docs: bool = False,
    ws_allowed_origins: Sequence[str] = (),
) -> FastAPI:
    """Build an app that owns its engine for its whole lifespan (CLI server / sync tests).

    Pass ``store_settings`` for full backend selection (the service path), or ``db_path`` (+optional
    ``synchronous``) as a SQLite shortcut. ``config_dir`` loads the code-first Connection/Router/
    Handler graph. ``auth_settings`` (when enabled) attaches an :class:`AuthService`, seeds the
    built-in roles, and creates a bootstrap admin on first run. The store is opened via the
    backend-agnostic :func:`~messagefoundry.store.open_store`.
    """
    if store_settings is None:
        if db_path is None:
            raise ValueError("create_managed_app requires either store_settings or db_path")
        store_settings = sqlite_settings(db_path, synchronous=synchronous)
    resolved = store_settings

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        store = await open_store(resolved)
        # Operational alert notifier (webhook/email). None when no transport is configured → the
        # engine falls back to the logging sink. Its background dispatch task is owned by this
        # lifespan: started here, drained + stopped after the engine in the finally below.
        notifier = notifier_from_settings(alerts_settings) if alerts_settings is not None else None
        if notifier is not None:
            notifier.start()
        engine = Engine(
            store,
            poll_interval=poll_interval,
            config_dir=config_dir,
            config_reload_roots=config_reload_roots,
            inbound_bind_host=inbound_bind_host,
            delivery_defaults=delivery_defaults,
            ordering_default=ordering_default,
            internal_error_default=internal_error_default,
            buildup_default=buildup_default,
            ack_after_default=ack_after_default,
            alert_sink=notifier,
            retention_settings=retention_settings,
            egress_settings=egress_settings,
            env_values=env_values,
            env_values_provider=env_values_provider,
        )
        if config_dir is not None:
            engine.add_registry(load_config(config_dir))
        await engine.start()
        app.state.engine = engine
        reaper: asyncio.Task[None] | None = None
        if auth_settings is not None and auth_settings.enabled:
            auth = AuthService(store, auth_settings)
            bootstrap = await auth.initialize()
            app.state.auth = auth
            if bootstrap is not None:
                _emit_bootstrap_admin(bootstrap, resolved)
            reaper = asyncio.create_task(_session_reaper(store))
        try:
            yield
        finally:
            if reaper is not None:
                reaper.cancel()
                # gather(return_exceptions): absorbs both our cancellation AND any exception a
                # previously-died reaper stored, so it can't propagate here and skip engine.stop()
                # (review M-33).
                await asyncio.gather(reaper, return_exceptions=True)
            await engine.stop()
            if notifier is not None:
                # Stop accepting alerts last (after the engine quiesces) so any final
                # connection_stopped/queue_buildup still drains; bounded by the transport timeouts.
                await notifier.aclose()

    # Auth disabled (or unset) → explicitly run open (dev/loopback; __main__ refuses a non-loopback
    # serve when auth is off). Auth enabled → fail-closed until the lifespan attaches the service.
    allow_no_auth = auth_settings is None or not auth_settings.enabled
    return create_app(
        lifespan=lifespan,
        ai_settings=ai_settings,
        expose_docs=expose_docs,
        allow_no_auth=allow_no_auth,
        ws_allowed_origins=ws_allowed_origins,
    )
