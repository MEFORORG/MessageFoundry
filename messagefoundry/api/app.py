# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse

from messagefoundry import __version__
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.api.models import (
    AiPolicy,
    AlertRuleInfo,
    AlertsConfig,
    ApprovalDecisionResult,
    ApprovalList,
    CapturedResponseInfo,
    ChannelInfo,
    ClusterNode,
    ClusterNodeList,
    ClusterStatus,
    ConnectionEventInfo,
    ConnectionMetadata,
    ConnectionRow,
    ConnectionTestResult,
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
    MessageResponses,
    MessageSummary,
    OutboundPayloadInfo,
    OutboundPayloads,
    OutboxInfo,
    PendingApprovalInfo,
    PendingApprovalResponse,
    PurgeResult,
    ReloadRequest,
    ReloadResult,
    ReplayResult,
    SecurityPosture,
    StatsResetRequest,
    StatsResetResult,
    StatsResponse,
    SystemStatus,
)
from messagefoundry.api.auth_routes import add_auth_routes
from messagefoundry.api.field_authz import count_exposed, redact_unauthorized
from messagefoundry.api.metrics import METRICS_CONTENT_TYPE, render_metrics
from messagefoundry.api.security import (
    authorize_ws,
    optional_identity,
    require,
    require_phi_read,
    require_step_up,
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
    ApprovalsSettings,
    AuthSettings,
    CertMonitorSettings,
    ClusterSettings,
    EgressSettings,
    ReferenceSettings,
    RetentionSettings,
    ShadowSettings,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.config.wiring import EnvRef, WiringError, load_config, redacted_settings
from messagefoundry.last_resort import install_loop_exception_handler
from messagefoundry.pipeline import ConfigReloadDenied, Engine
from messagefoundry.pipeline.alert_sinks import notifier_from_settings
from messagefoundry.pipeline.security_notify import security_notifier_from_settings
from messagefoundry.pipeline.cluster import build_coordinator
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    TestNotSupportedError,
)
from messagefoundry.store import Row, open_store, sqlite_settings
from messagefoundry.store.base import Store
from messagefoundry.store.store import _secure_file

__all__ = ["create_app", "create_managed_app"]

_RATE_WINDOW = 60.0  # seconds; window for the backlog throughput estimate
_MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB cap on HTTP request bodies (API-INPUT)
_CONNECTION_TEST_TIMEOUT = 35.0  # overall cap for a POST /connections/{name}/test probe (seconds)
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


def _get_gate(request: Request) -> ApprovalGate | None:
    """The dual-control approval gate (ASVS 2.3.5), or ``None`` when no engine is bound — then gated
    endpoints execute inline and the ``/approvals`` routes report 503."""
    return getattr(request.app.state, "approval_gate", None)


def _build_approval_gate(engine: Engine, settings: ApprovalsSettings) -> ApprovalGate:
    """Build the approval gate and register the high-value operations dual-control can hold. Each
    executor re-runs its captured operation on approval (params are JSON, persisted at request time)."""
    gate = ApprovalGate(engine.store, settings)

    async def _replay(p: Mapping[str, Any]) -> dict[str, Any]:
        requeued = await engine.replay_dead(
            channel_id=p.get("channel_id"), destination_name=p.get("destination_name")
        )
        return {"requeued": requeued}

    async def _purge(p: Mapping[str, Any]) -> dict[str, Any]:
        cancelled = await engine.store.cancel_queued(
            None, str(p["name"]), top_only=(p.get("scope") == "top")
        )
        return {"cancelled": cancelled}

    gate.register("dead_letter_replay", "Replay dead-lettered deliveries", _replay)
    gate.register("connection_purge", "Purge queued deliveries to an outbound connection", _purge)
    return gate


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


#: PHI-bearing columns that stay UNENCRYPTED at rest on the SQL Server backend even when a key is
#: configured. RETIRED (empty) as of H4 (S5): error/last_error/message_events.detail now route through
#: the same store cipher on SQL Server as on SQLite/Postgres, so SQL Server is at full at-rest parity and
#: GET /security/posture reports no residual. Kept as an explicit empty tuple (rather than deleting the
#: surface) so the posture route still emits the per-backend coverage field with a documented anchor.
_SQLSERVER_PLAINTEXT_RESIDUAL: tuple[str, ...] = ()


def _plaintext_columns(backend: str, *, encryption_enabled: bool) -> list[str]:
    """The PHI-bearing columns NOT encrypted at rest on ``backend`` (M5). Empty when encryption is off
    (N/A — every column is plaintext, which the ``encryption_enabled=false`` bit already conveys), and
    now empty on EVERY backend: SQLite, Postgres, and (as of H4) SQL Server all have full at-rest
    coverage of the PHI-bearing columns."""
    if not encryption_enabled:
        return []
    if backend == StoreBackend.SQLSERVER.value:
        return list(_SQLSERVER_PLAINTEXT_RESIDUAL)  # () since H4 — full parity, no residual
    return []


async def _audit_channel_denied(engine: Engine, identity: Identity, channel: str | None) -> None:
    """Audit a per-channel RBAC denial (mirrors auth.permission_denied)."""
    await engine.store.record_audit(
        "auth.channel_denied",
        actor=identity.username,
        channel_id=channel,
        detail=json.dumps({"channel": channel}),
    )


async def _run_connection_test(
    rr: RegistryRunner, name: str, direction: str
) -> ConnectionTestResult:
    """Build a fresh connector for ``name`` and probe its reachability, never disturbing the live one.
    Reports a config (bad ``env()``/egress) or connectivity failure in the result rather than raising —
    only an unexpected bug would 500. Closes the test connector afterward."""

    def _result(
        *, supported: bool, success: bool, ms: float, detail: str | None
    ) -> ConnectionTestResult:
        return ConnectionTestResult(
            name=name,
            direction=direction,
            supported=supported,
            success=success,
            duration_ms=round(ms, 1),
            detail=detail,
        )

    try:
        _direction, connector = rr.build_test_connector(name)
    except WiringError as exc:
        return _result(supported=True, success=False, ms=0.0, detail=str(exc))
    start = time.monotonic()
    supported, success, detail = True, False, None
    try:
        await asyncio.wait_for(connector.test_connection(), _CONNECTION_TEST_TIMEOUT)
        success = True
    except TestNotSupportedError as exc:
        supported, detail = False, str(exc)
    except asyncio.TimeoutError:
        detail = f"timed out after {_CONNECTION_TEST_TIMEOUT:.0f}s"
    except DeliveryError as exc:
        detail = str(exc)
    except Exception as exc:  # noqa: BLE001 - any probe failure is reported in the result, never a 500
        detail = f"{type(exc).__name__}: {exc}"
    finally:
        with suppress(Exception):  # closing a test connector must never mask the result
            if isinstance(connector, DestinationConnector):
                await connector.aclose()
            else:
                await connector.stop()
    return _result(
        supported=supported, success=success, ms=(time.monotonic() - start) * 1000.0, detail=detail
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
    store_settings: StoreSettings | None = None,
    approvals: ApprovalsSettings | None = None,
    alerts_settings: AlertsSettings | None = None,
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
        app.state.approval_gate = _build_approval_gate(engine, approvals or ApprovalsSettings())
    if auth is not None:
        app.state.auth = auth
    if ai_settings is not None:
        app.state.ai = ai_settings
    # Store settings back the M5 GET /security/posture view (backend, key_provider source,
    # require_encryption / allow_unencrypted_phi). The managed-app lifespan sets the live value once the
    # store opens; here it supports the direct-construction (test) path.
    if store_settings is not None:
        app.state.store_settings = store_settings
    # Fail-closed when no auth is attached unless explicitly opted out (embedding/dev) — SYS-1.
    app.state.allow_no_auth = allow_no_auth
    # Loaded [alerts] config for the read-only /alerts/rules view (independent of engine; may be None,
    # in which case the route falls back to all-off defaults). The lifespan path sets the live value.
    app.state.alerts_settings = alerts_settings
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
        transfer_encoding = request.headers.get("transfer-encoding", "").lower()
        # A request carrying BOTH Content-Length and Transfer-Encoding is ambiguously framed (RFC 9112
        # §6.1 — TE overrides CL) and is the classic CL.TE request-smuggling vector. Our single h11
        # parser doesn't desync on the default loopback bind, but reject it outright so a future front
        # proxy can never disagree with us about where the message ends (ASVS 4.2.1).
        if length is not None and "chunked" in transfer_encoding:
            _log.warning(
                "rejected request with both Content-Length and Transfer-Encoding on %s from %s",
                request.url.path,
                client,
            )
            return JSONResponse(
                {
                    "detail": "ambiguous framing: Content-Length with Transfer-Encoding is not accepted"
                },
                status_code=400,
            )
        if length is None:
            # No Content-Length means a chunked body (HTTP/1.1 requires one or the other), which the
            # Content-Length cap can't bound up front — Starlette would buffer it unbounded, a pre-auth
            # memory DoS. We only accept small JSON, so require a Content-Length (review M-19).
            if "chunked" in transfer_encoding:
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
    async def health(identity: Identity | None = Depends(optional_identity)) -> Health:
        # Liveness is always answerable (tokenless), but the build version is fingerprinting info, so
        # it is disclosed only to an authenticated caller (WP-L3-07 / ASVS 13.4.6). When auth is
        # disabled-with-allow_no_auth, optional_identity returns the system identity → version shown.
        return Health(version=__version__ if identity is not None else None)

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
        data_class, prod = ai.derived_posture()
        production = True if prod is None else prod  # unresolved posture -> strictest ceiling
        eff = resolve_effective_policy(
            mode=ai.mode, data_scope=ai.data_scope, production=production
        )
        permitted = None if identity is None else identity.has(Permission.AI_ASSIST)
        return AiPolicy(
            mode=eff.mode,
            data_scope=eff.data_scope,
            environment=ai.environment,
            data_class=data_class,
            production=production,
            assist_permitted=permitted,
            reason=eff.reason,
        )

    @app.get("/security/posture", response_model=SecurityPosture)
    async def security_posture(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> SecurityPosture:
        """The instance's **effective** PHI-at-rest security posture (M5) — what protection is *actually*
        in effect, so an EF-3-class accidental-dangerous-deploy is visible to an operator.

        Authenticated + permission-gated (``MONITORING_READ``), deliberately NOT ``GET /health`` (that
        stays a liveness boolean). The access is audited. **No key material is ever returned**
        (SECRET-1): ``encryption_enabled`` and the key **fingerprint** are read from the *live* store
        cipher via the public ``store.cipher_info()`` accessor (never the private ``_cipher``), and
        ``key_source`` is the provider *name*. ``plaintext_columns`` reports any PHI column left
        unencrypted on the active backend — empty on every backend now (the SQL Server residual was
        retired by H4; SQLite/Postgres/SQL Server all have full at-rest coverage)."""
        # The live cipher posture (on/off + key fingerprint only). cipher_info() is the public Store
        # accessor — the route never touches engine.store._cipher.
        info = engine.store.cipher_info()
        # Store config: backend + key SOURCE (provider name) + the two keyless-gate flags. From app.state
        # (the lifespan/managed-app stashes the resolved StoreSettings); fall back to defaults if absent.
        store = getattr(request.app.state, "store_settings", None) or StoreSettings()
        ai = getattr(request.app.state, "ai", None) or AiSettings()
        data_class, production = ai.derived_posture()
        backend = store.backend.value
        await engine.store.record_audit(
            "security.posture_view",
            actor=identity.username,
            detail=json.dumps(
                {
                    "backend": backend,
                    "encryption_enabled": info.encrypts,
                    "key_source": store.key_provider,
                }
            ),
        )
        return SecurityPosture(
            data_class=data_class,
            production=production,
            environment=ai.environment,
            backend=backend,
            encryption_enabled=info.encrypts,
            key_source=store.key_provider,
            key_id=info.active_key_id,  # FINGERPRINT only, never key bytes
            require_encryption=store.require_encryption,
            allow_unencrypted_phi=store.allow_unencrypted_phi,
            plaintext_columns=_plaintext_columns(backend, encryption_enabled=info.encrypts),
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
        # Offset-adjusted: subtracts any operator stats-resets (in-memory baselines). Identical to the
        # raw store metrics when nothing has been reset.
        metrics = await engine.connection_metrics_view(now=now, rate_window=_RATE_WINDOW)
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
                ifail = rr.connection_failed(iname)  # ADR 0031: start failed → not listening
                rows.append(
                    ConnectionRow(
                        role="source",
                        channel_id=iname,
                        channel_name=iname,
                        destination=None,
                        name=f"{iname} ▸ in",
                        status=(
                            "failed"
                            if ifail
                            else ("running" if rr.inbound_running(iname) else "stopped")
                        ),
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
                        error=ifail,
                    )
                )
            emitted_dests: set[str] = set()
            for (cid, dname), dm in metrics.destinations.items():
                if cid not in reg.inbound:
                    continue  # a declarative-channel edge, already emitted above
                emitted_dests.add(dname)
                oc = reg.outbound.get(dname)
                dfail = rr.connection_failed(dname)  # ADR 0031: built? or degraded?
                # An outbound the live graph no longer declares (removed by a reload) keeps draining
                # its queued rows — report it honestly as "draining" with an unknown method, rather
                # than mislabeling it as a running File connector.
                if oc is not None:
                    dmethod = _method_label(oc.spec.type.value)
                    dpeer, dport = _peer_port(oc.spec.type.value, oc.spec.settings)
                    dstatus = "failed" if dfail else rstatus
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
                        # Effective simulate flag — queried even for a draining (removed) outbound,
                        # whose suppression persists in the runner until full shutdown (#15).
                        simulated=rr.outbound_simulated(dname),
                        error=dfail if oc is not None else None,
                    )
                )
            # ADR 0031: an outbound that failed to build at start has no metrics edge until traffic is
            # routed to it, so it would be invisible above. Emit a standalone row for every still-failed
            # outbound not already shown, so a degraded lane is never silently hidden from the dashboard.
            for dname, reason in rr.degraded_connections().items():
                oc = reg.outbound.get(dname)
                if oc is None or dname in emitted_dests:
                    continue  # inbound failures appear as their source row; shown dests are covered
                dmethod = _method_label(oc.spec.type.value)
                dpeer, dport = _peer_port(oc.spec.type.value, oc.spec.settings)
                rows.append(
                    ConnectionRow(
                        role="destination",
                        channel_id=dname,
                        channel_name=dname,
                        destination=dname,
                        name=f"{dname} ▸ out",
                        status="failed",
                        direction="out",
                        method=dmethod,
                        peer=dpeer,
                        port=dport,
                        queue_depth=None,
                        idle_seconds=None,
                        alerts_active=0,
                        errored=None,
                        read=None,
                        written=None,
                        backlog_seconds=None,
                        delivered_age_seconds=None,
                        simulated=rr.outbound_simulated(dname),
                        error=reason,
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

    @app.get("/connections/{name}/metadata", response_model=ConnectionMetadata)
    async def connection_metadata(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> ConnectionMetadata:
        """Static metadata for one connection (operability Tier 4): operator labels + a secret-scrubbed
        settings view. No live probe — see ``POST /connections/{name}/test``."""
        rr = engine.registry_runner
        if rr is None:
            raise HTTPException(503, "engine not started")
        ic = rr.registry.inbound.get(name)
        if ic is not None:
            await _control_guard(engine, identity, name)  # inbound config is per-channel
            return ConnectionMetadata(
                name=name,
                direction="in",
                method=ic.spec.type.value,
                running=rr.inbound_running(name),
                router=ic.router,
                metadata=dict(ic.metadata) if ic.metadata else None,
                settings=redacted_settings(ic.spec.settings),
                error=rr.connection_failed(name),  # ADR 0031
            )
        oc = rr.registry.outbound.get(name)
        if oc is not None:
            if identity.allowed_channels is not None:
                # An outbound spans channels, so a channel-scoped user can't read a shared one — the
                # same boundary /test and /purge enforce (don't disclose shared-outbound topology).
                await _audit_channel_denied(engine, identity, name)
                raise HTTPException(
                    403, "channel-scoped users cannot read a shared outbound connection"
                )
            return ConnectionMetadata(
                name=name,
                direction="out",
                method=oc.spec.type.value,
                running=rr.running,
                metadata=dict(oc.metadata) if oc.metadata else None,
                settings=redacted_settings(oc.spec.settings),
                simulated=rr.outbound_simulated(name),
                error=rr.connection_failed(name),  # ADR 0031
            )
        raise HTTPException(404, f"no such connection: {name}")

    @app.post("/connections/{name}/test", response_model=ConnectionTestResult)
    async def connection_test(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_TEST)),
    ) -> ConnectionTestResult:
        """Probe a connection's reachability (operability Tier 4) — builds a **fresh** connector
        (never the live one), honors the ``[egress]`` allowlist, and sends NO real data. Audited."""
        rr = engine.registry_runner
        if rr is None:
            raise HTTPException(503, "engine not started")
        is_inbound = name in rr.registry.inbound
        if not is_inbound and name not in rr.registry.outbound:
            raise HTTPException(404, f"no such connection: {name}")
        direction = "in" if is_inbound else "out"
        if is_inbound:
            await _control_guard(engine, identity, name)  # inbound test is per-channel
        elif identity.allowed_channels is not None:
            # An outbound spans channels, so a channel-scoped user can't probe a shared one (like purge).
            await _audit_channel_denied(engine, identity, name)
            raise HTTPException(
                403, "channel-scoped users cannot test a shared outbound connection"
            )

        result = await _run_connection_test(rr, name, direction)
        await engine.store.record_audit(
            "connection_test",
            actor=identity.username,
            channel_id=name if direction == "in" else None,
            detail=json.dumps(
                {
                    "connection": name,
                    "direction": direction,
                    "supported": result.supported,
                    "success": result.success,
                    "detail": result.detail,
                }
            ),
        )
        return result

    @app.post("/connections/{name}/purge", response_model=PurgeResult | PendingApprovalResponse)
    async def purge_connection(
        name: str,
        response: Response,
        engine: Engine = Depends(_get_engine),
        scope: str = Query("all", pattern="^(top|all)$"),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_PURGE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> PurgeResult | PendingApprovalResponse:
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
        if (
            gate is not None
        ):  # dual-control: hold for a second approver when [approvals] gates purge
            pending = await gate.guard(
                "connection_purge", {"name": name, "scope": scope}, requester=identity.username
            )
            if pending is not None:
                response.status_code = 202
                return PendingApprovalResponse(
                    approval_id=pending,
                    operation="connection_purge",
                    detail="held for a second approver (dual-control)",
                )
        cancelled = await engine.store.cancel_queued(None, name, top_only=(scope == "top"))
        return PurgeResult(cancelled=cancelled)

    @app.post("/statistics/reset", response_model=StatsResetResult)
    async def reset_statistics(
        req: StatsResetRequest,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
    ) -> StatsResetResult:
        """Zero the connections-dashboard cumulative counters (inbound read/errored, outbound
        written/dead) for the selected connections, or all of them. This moves an in-memory baseline —
        message rows (the PHI/audit record) and the Prometheus ``/metrics`` counters are untouched, as
        are live gauges (queue depth, ages)."""
        inbound: list[str] = []
        outbound: list[tuple[str, str]] = []
        if req.all:
            # "Reset all" spans every channel, so a channel-scoped user may not run it (mirror purge).
            if identity.allowed_channels is not None:
                await _audit_channel_denied(engine, identity, None)
                raise HTTPException(403, "channel-scoped users cannot reset all statistics")
        else:
            for t in req.targets:
                # Per-channel RBAC: a scoped user may reset only endpoints of their own inbound channels
                # (a destination row is the channel_id->destination edge, so the same scope applies).
                if identity.allowed_channels is not None and not identity.can_access_channel(
                    t.channel_id
                ):
                    await _audit_channel_denied(engine, identity, t.channel_id)
                    raise HTTPException(403, "connection is outside your channel scope")
                if t.role == "source":
                    if t.channel_id not in inbound:
                        inbound.append(t.channel_id)
                else:
                    if t.destination is None:
                        raise HTTPException(422, "destination rows require a destination name")
                    key = (t.channel_id, t.destination)
                    if key not in outbound:
                        outbound.append(key)
        count = await engine.reset_stats(
            all_connections=req.all, inbound=inbound, outbound=outbound, now=time.time()
        )
        await engine.store.record_audit(
            "stats_reset",
            actor=identity.username,
            detail=json.dumps(
                {
                    "all": req.all,
                    "inbound": inbound,
                    "outbound": [list(k) for k in outbound],
                    "reset": count,
                }
            ),
        )
        return StatsResetResult(reset=count)

    # --- dead letters (verify + recover) -------------------------------------

    def _conn_event_info(e: Any) -> ConnectionEventInfo:
        return ConnectionEventInfo(
            id=e.id,
            ts=e.ts,
            connection=e.connection,
            transport=e.transport,
            direction=e.direction,
            kind=e.kind,
            peer_host=e.peer_host,
            message_id=e.message_id,
            reason=e.reason,
        )

    @app.get("/events", response_model=list[ConnectionEventInfo])
    async def list_connection_events(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
        connection: str | None = Query(None, max_length=256),
        kind: list[str] | None = Query(None),
        since: float | None = Query(None, ge=0),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[ConnectionEventInfo]:
        """The Corepoint-style connection/transport event log (#46), newest first — **metadata only,
        no PHI**, so it is gated by ``monitoring:read`` (not the PHI-read tier). Optionally filtered by
        ``connection``, one-or-more event ``kind``s, and a ``since`` epoch timestamp."""
        rows = await engine.store.list_connection_events(
            connection=connection, kinds=kind, since=since, limit=limit
        )
        return [_conn_event_info(r) for r in rows]

    @app.get("/connections/{name}/events", response_model=list[ConnectionEventInfo])
    async def list_connection_events_for(
        name: str,
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
        kind: list[str] | None = Query(None),
        since: float | None = Query(None, ge=0),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[ConnectionEventInfo]:
        """The connection/transport event log scoped to one connection (#46), newest first."""
        rows = await engine.store.list_connection_events(
            connection=name, kinds=kind, since=since, limit=limit
        )
        return [_conn_event_info(r) for r in rows]

    @app.get("/dead-letters", response_model=DeadLetterList)
    async def list_dead_letters(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_READ)),
        channel_id: str | None = Query(None, max_length=256),
        destination_name: str | None = Query(None, max_length=256),
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

    @app.post(
        "/dead-letters/replay", response_model=DeadLetterReplayResult | PendingApprovalResponse
    )
    async def replay_dead_letters(
        req: DeadLetterReplayRequest,
        response: Response,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_REPLAY)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> DeadLetterReplayResult | PendingApprovalResponse:
        """Re-queue dead-lettered deliveries (optionally scoped). Already-delivered rows are left
        alone; each affected message reverts from ``error`` to ``received`` and re-drains."""
        # A channel-scoped user must target one of their channels (replay isn't channel-filtered at
        # the engine level, so an unscoped "replay all" would cross channels).
        if identity.allowed_channels is not None and not identity.can_access_channel(
            req.channel_id
        ):
            await _audit_channel_denied(engine, identity, req.channel_id)
            raise HTTPException(403, "specify a channel within your scope to replay")
        if (
            gate is not None
        ):  # dual-control: hold for a second approver when [approvals] gates replay
            pending = await gate.guard(
                "dead_letter_replay",
                {"channel_id": req.channel_id, "destination_name": req.destination_name},
                requester=identity.username,
            )
            if pending is not None:
                response.status_code = 202
                return PendingApprovalResponse(
                    approval_id=pending,
                    operation="dead_letter_replay",
                    detail="held for a second approver (dual-control)",
                )
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

    # --- dual-control approvals (ASVS 2.3.5) ---------------------------------

    @app.get("/approvals", response_model=ApprovalList)
    async def list_approvals(
        _: Identity = Depends(require(Permission.APPROVALS_APPROVE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> ApprovalList:
        """Open (still-pending, unexpired) high-value actions awaiting a second approver."""
        if gate is None:
            raise HTTPException(503, "approval workflow is not available")
        return ApprovalList(approvals=[PendingApprovalInfo(**a) for a in await gate.list_pending()])

    @app.post("/approvals/{approval_id}/approve", response_model=ApprovalDecisionResult)
    async def approve_action(
        approval_id: str,
        identity: Identity = Depends(require(Permission.APPROVALS_APPROVE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> ApprovalDecisionResult:
        """Release a pending action: re-executes the captured operation and audits both identities. A
        requester can never approve their own request (dual-control, 2.3.5)."""
        if gate is None:
            raise HTTPException(503, "approval workflow is not available")
        try:
            outcome = await gate.approve(approval_id, approver=identity.username)
        except ApprovalError as exc:
            raise HTTPException(exc.status, exc.detail) from exc
        return ApprovalDecisionResult(**outcome)

    @app.post("/approvals/{approval_id}/reject", response_model=ApprovalDecisionResult)
    async def reject_action(
        approval_id: str,
        identity: Identity = Depends(require(Permission.APPROVALS_APPROVE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> ApprovalDecisionResult:
        """Decline a pending action without executing it (audited)."""
        if gate is None:
            raise HTTPException(503, "approval workflow is not available")
        try:
            outcome = await gate.reject(approval_id, approver=identity.username)
        except ApprovalError as exc:
            raise HTTPException(exc.status, exc.detail) from exc
        return ApprovalDecisionResult(**outcome)

    # --- config promote / reload ---------------------------------------------

    @app.post("/config/reload", response_model=ReloadResult)
    async def reload_config(
        req: ReloadRequest,
        engine: Engine = Depends(_get_engine),
        user: Identity = Depends(require_step_up(Permission.CONFIG_DEPLOY)),
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
            # propagate=True on the real apply so an operator reload on one node bumps the cluster-wide
            # config version and every other node converges (Track B Step 6); a dry_run never propagates
            # (it doesn't apply anything) and single-node ignores it (is_clustered() False).
            registry = await engine.reload(
                req.config_dir, dry_run=req.dry_run, propagate=not req.dry_run
            )
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
        request: Request,
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
        outbox_rows = await engine.store.outbox_for(message_id)
        event_rows = await engine.store.events_for(message_id)
        detail = MessageDetail(
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
                for o in outbox_rows
            ],
            events=[
                EventInfo(
                    ts=e["ts"],
                    event=e["event"],
                    destination=e["destination"],
                    detail=e["detail"],
                )
                for e in event_rows
            ],
        )
        # Per-property PHI gate (#120): the patient `summary`, the exception `error`, every delivery
        # `last_error`, and every event `detail` gate on messages:view_summary. Redaction keys on the
        # EXACT type (no MRO walk), so the MessageDetail wrapper and each nested OutboxInfo/EventInfo are
        # redacted individually. The raw body stays on this route's view_raw gate. Exposure is audited
        # server-side, mirroring the list endpoints (count after redaction = what's actually returned).
        outbox = [redact_unauthorized(o, identity) for o in detail.outbox]
        events = [redact_unauthorized(e, identity) for e in detail.events]
        detail = redact_unauthorized(detail, identity).model_copy(
            update={"outbox": outbox, "events": events}
        )
        exposed = count_exposed([detail, *outbox, *events])
        if exposed:
            await request.app.state.summary_auditor.note(
                engine.store, identity.username, row["channel_id"], exposed, time.time()
            )
        return detail

    @app.get("/messages/{message_id}/responses", response_model=MessageResponses)
    async def get_message_responses(
        message_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_READ)),
    ) -> MessageResponses:
        """The captured request/response replies for a message (ADR 0013). ``outcome``/``detail`` need
        the message-read permission; the PHI ``body`` is included only for a caller that also holds the
        raw-body permission (``MESSAGES_VIEW_RAW``). Every access is audited (``response.read``)."""
        row = await engine.store.get_message(message_id)
        # 404 (not 403) outside the caller's channel scope — don't reveal a message in another tenant's
        # channel (per-channel RBAC), mirroring get_message.
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")
        captured = await engine.store.correlate_response(message_id)
        include_body = identity.has(Permission.MESSAGES_VIEW_RAW)
        # Reading captured replies is PHI access — audit it. If bodies are exposed, also record the
        # per-message PHI view timeline (record_view), exactly like opening a raw body.
        await engine.store.record_audit(
            "response.read",
            actor=identity.username,
            channel_id=row["channel_id"],
            detail=json.dumps(
                {"message_id": message_id, "count": len(captured), "body": include_body}
            ),
        )
        if include_body and captured:
            await engine.store.record_view(message_id, actor=identity.username)
        # `detail` can embed a reply fragment (e.g. an unparseable-ACK note), so it gates on
        # messages:view_summary like every other disposition text (#120) — a bare messages:read caller
        # (Viewer) reaches this endpoint but gets `detail` nulled. The PHI `body` stays on view_raw above.
        return MessageResponses(
            message_id=message_id,
            responses=[
                redact_unauthorized(
                    CapturedResponseInfo(
                        destination_name=c.destination_name,
                        response_seq=c.response_seq,
                        outcome=c.outcome,
                        detail=c.detail,
                        captured_at=c.captured_at,
                        body=c.body if include_body else None,
                    ),
                    identity,
                )
                for c in captured
            ],
        )

    @app.get("/messages/{message_id}/outbound", response_model=OutboundPayloads)
    async def get_message_outbound(
        message_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_VIEW_RAW)),
    ) -> OutboundPayloads:
        """The **transformed outbound payloads** MEFOR routed for a message — one entry per
        destination (#14 parity tool). The PHI bodies are returned in full, so the route requires
        ``MESSAGES_VIEW_RAW`` outright (unlike ``/responses``, where the body is conditional). Works on
        both simulate/shadow and live runs — the transformed payload is retained on the done outbound
        row in either mode. Every access is audited (``outbound.read`` + a per-message ``viewed``
        event when bodies are returned)."""
        row = await engine.store.get_message(message_id)
        # 404 (not 403) outside the caller's channel scope — don't reveal a message in another tenant's
        # channel (per-channel RBAC), mirroring get_message.
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")
        payload_rows = await engine.store.outbox_payloads_for(message_id)
        # Returning transformed bodies is PHI access — audit the read, and (when bodies are actually
        # returned) record the per-message PHI view timeline, exactly like opening a raw body.
        await engine.store.record_audit(
            "outbound.read",
            actor=identity.username,
            channel_id=row["channel_id"],
            detail=json.dumps({"message_id": message_id, "count": len(payload_rows)}),
        )
        if payload_rows:
            await engine.store.record_view(message_id, actor=identity.username)
        return OutboundPayloads(
            message_id=message_id,
            payloads=[
                OutboundPayloadInfo(
                    destination_name=o["destination_name"],
                    status=o["status"],
                    payload=o["payload"],
                )
                for o in payload_rows
            ],
        )

    @app.post("/messages/{message_id}/replay", response_model=ReplayResult)
    async def replay_message(
        message_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_REPLAY)),
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
        return StatsResponse(
            outbox_by_status=await engine.store.stats(),
            in_pipeline=await engine.store.in_pipeline_depth(),
        )

    @app.get("/metrics")
    async def metrics_endpoint(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> Response:
        """Prometheus exposition (text/plain). Gated by monitoring:read like /stats — a scraper
        authenticates with a service token. Contains only aggregate counts/latency keyed by
        connection name + status — no PHI."""
        return Response(content=await render_metrics(engine), media_type=METRICS_CONTENT_TYPE)

    # --- alerts config (read-only) -------------------------------------------

    @app.get("/alerts/rules", response_model=AlertsConfig)
    async def alerts_rules(
        request: Request,
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> AlertsConfig:
        """Read-only view of the loaded [alerts] rules + transport config (ADR 0014). No engine/DB
        access. No secrets: the webhook URL, SMTP password and username are never returned —
        transports are reported present-or-not. Gated by monitoring:read like /stats."""
        alerts: AlertsSettings = (
            getattr(request.app.state, "alerts_settings", None) or AlertsSettings()
        )
        return AlertsConfig(
            webhook_configured=bool(alerts.webhook_url),
            webhook_timeout=alerts.webhook_timeout,
            webhook_allowed_hosts=list(alerts.webhook_allowed_hosts),
            email_configured=bool(alerts.email_smtp_host and alerts.email_from and alerts.email_to),
            email_smtp_port=alerts.email_smtp_port,
            email_use_tls=alerts.email_use_tls,
            email_recipient_count=len(alerts.email_to),
            smtp_allowed_hosts=list(alerts.smtp_allowed_hosts),
            realert_seconds=alerts.realert_seconds,
            rules=[
                AlertRuleInfo(
                    event_type=r.event_type,
                    connection=r.connection,
                    min_depth=r.min_depth,
                    min_oldest_seconds=r.min_oldest_seconds,
                    severity=r.severity.value,
                    transports=r.transports,
                    cooldown_seconds=r.cooldown_seconds,
                )
                for r in alerts.rules
            ],
        )

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

    # --- cluster observability (Track B Step 7) ------------------------------

    @app.get("/cluster/status", response_model=ClusterStatus)
    async def cluster_status(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> ClusterStatus:
        """This node's cluster posture: id, whether it's clustered, whether it's the leader, its
        active-passive role, and the cached config version. All cheap in-memory coordinator gates — no DB
        round-trip. Single-node (NullCoordinator) reports clustered=false, is_leader=true,
        role="single-node", config_version=0."""
        c = engine.coordinator
        clustered = c.is_clustered()
        is_leader = c.is_leader()
        role = "single-node" if not clustered else ("primary" if is_leader else "standby")
        return ClusterStatus(
            node_id=c.node_id,
            clustered=clustered,
            is_leader=is_leader,
            role=role,
            config_version=c.config_version_cached(),
        )

    @app.get("/cluster/nodes", response_model=ClusterNodeList)
    async def cluster_nodes(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> ClusterNodeList:
        """Cluster membership: one row per known node with liveness + derived leadership, plus the single
        leader's node_id and the authoritative leadership-lease state (owner + expiry). One-to-two DB
        reads on a real cluster (the shared ``nodes`` table + the ``leader_lease`` row); single-node
        synthesizes one self-entry with no DB."""
        c = engine.coordinator
        members = await c.cluster_members()
        nodes = [
            ClusterNode(
                node_id=m.node_id,
                host=m.host,
                pid=m.pid,
                status=m.status,
                started_at=m.started_at,
                last_seen=m.last_seen,
                is_leader=m.is_leader,
            )
            for m in members
        ]
        leader = next((n.node_id for n in nodes if n.is_leader), None)
        lease_owner, lease_expires_at = await c.leadership_lease()
        return ClusterNodeList(
            nodes=nodes,
            leader_node_id=leader,
            lease_owner=lease_owner,
            lease_expires_at=lease_expires_at,
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
    allow_insecure_bind: bool = False,
    delivery_defaults: RetryPolicy | None = None,
    ordering_default: OrderingMode | None = None,
    internal_error_default: InternalErrorPolicy | None = None,
    buildup_default: BuildupThreshold | None = None,
    ack_after_default: AckAfter | None = None,
    max_correlation_depth: int = 8,
    connection_events: bool = True,
    response_sent_default: bool = True,
    env_values: Mapping[str, Any] | None = None,
    env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
    auth_settings: AuthSettings | None = None,
    ai_settings: AiSettings | None = None,
    alerts_settings: AlertsSettings | None = None,
    retention_settings: RetentionSettings | None = None,
    cert_monitor_settings: CertMonitorSettings | None = None,
    api_tls_cert_file: str | None = None,
    api_listener: tuple[str, int] | None = None,
    reference_settings: ReferenceSettings | None = None,
    egress_settings: EgressSettings | None = None,
    shadow_settings: ShadowSettings | None = None,
    cluster_settings: ClusterSettings | None = None,
    approvals_settings: ApprovalsSettings | None = None,
    expose_docs: bool = False,
    ws_allowed_origins: Sequence[str] = (),
) -> FastAPI:
    """Build an app that owns its engine for its whole lifespan (CLI server / sync tests).

    Pass ``store_settings`` for full backend selection (the service path), or ``db_path`` (+optional
    ``synchronous``) as a SQLite shortcut. ``config_dir`` loads the code-first Connection/Router/
    Handler graph. ``auth_settings`` (when enabled) attaches an :class:`AuthService`, seeds the
    built-in roles, and creates a bootstrap admin on first run. The store is opened via the
    backend-agnostic :func:`~messagefoundry.store.open_store`. ``api_listener`` is the engine's own
    ``(host, port)`` (from ``[api]``), reserved so no inbound listener can be wired onto the API's port
    — the CLI server passes it; in-process/test callers omit it (no separate API socket is bound).
    """
    if store_settings is None:
        if db_path is None:
            raise ValueError("create_managed_app requires either store_settings or db_path")
        store_settings = sqlite_settings(db_path, synchronous=synchronous)
    resolved = store_settings

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Process-level last-resort: route any otherwise-unhandled asyncio task/callback exception
        # through safe_exc → the log, so it can't escape as a raw traceback (possible PHI) or die
        # silently (ASVS 16.5.4). Here because set_exception_handler needs the running loop.
        install_loop_exception_handler()
        store = await open_store(resolved)
        # Operational alert notifier (webhook/email). None when no transport is configured → the
        # engine falls back to the logging sink. Its background dispatch task is owned by this
        # lifespan: started here, drained + stopped after the engine in the finally below.
        notifier = notifier_from_settings(alerts_settings) if alerts_settings is not None else None
        if notifier is not None:
            notifier.start()
        # Cluster coordinator (Track B Step 3) — built from the opened store so a Postgres-backed
        # store can reach its pool. Returns the no-op NullCoordinator unless [cluster].enabled on a
        # Postgres store, so single-node is byte-identical. The Engine owns its lifecycle (start/stop
        # in engine.start()/stop()), so the lifespan only constructs + passes it here.
        coordinator = build_coordinator(store, cluster_settings)
        engine = Engine(
            store,
            poll_interval=poll_interval,
            max_correlation_depth=max_correlation_depth,
            connection_events=connection_events,
            response_sent_default=response_sent_default,
            config_dir=config_dir,
            config_reload_roots=config_reload_roots,
            inbound_bind_host=inbound_bind_host,
            allow_insecure_bind=allow_insecure_bind,
            delivery_defaults=delivery_defaults,
            ordering_default=ordering_default,
            internal_error_default=internal_error_default,
            buildup_default=buildup_default,
            ack_after_default=ack_after_default,
            alert_sink=notifier,
            retention_settings=retention_settings,
            cert_monitor_settings=cert_monitor_settings,
            api_tls_cert_file=api_tls_cert_file,
            api_listener=api_listener,
            reference_settings=reference_settings,
            egress_settings=egress_settings,
            shadow_settings=shadow_settings,
            active_environment=ai_settings.environment if ai_settings else None,
            env_values=env_values,
            env_values_provider=env_values_provider,
            coordinator=coordinator,
            cluster_settings=cluster_settings,
        )
        if config_dir is not None:
            engine.add_registry(load_config(config_dir))
        await engine.start()
        app.state.engine = engine
        app.state.store_settings = resolved  # back GET /security/posture (M5)
        app.state.alerts_settings = alerts_settings
        app.state.approval_gate = _build_approval_gate(
            engine, approvals_settings or ApprovalsSettings()
        )
        reaper: asyncio.Task[None] | None = None
        security_notifier = None
        if auth_settings is not None and auth_settings.enabled:
            # Out-of-band security-event email (ASVS 6.3.5/6.3.7) — reuses the [alerts] SMTP transport,
            # sent to each affected user's own address. None when disabled or no SMTP configured; the
            # /me/security-events feed still records events. Its background task is owned by this
            # lifespan (started here, drained + closed after the engine in the finally below).
            if auth_settings.notify_security_events and alerts_settings is not None:
                security_notifier = security_notifier_from_settings(alerts_settings)
                if security_notifier is not None:
                    security_notifier.start()
            auth = AuthService(store, auth_settings, security_notifier=security_notifier)
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
            if security_notifier is not None:
                await (
                    security_notifier.aclose()
                )  # drain queued user emails, bounded by SMTP timeout
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
