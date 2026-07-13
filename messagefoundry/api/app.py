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
import base64
import binascii
import json
import logging
import mimetypes
import os
import re
import shutil
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import (
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from messagefoundry import __version__
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.api.models import (
    AiPolicy,
    AlertInstanceInfo,
    AlertInstanceList,
    AlertRuleInfo,
    AlertsConfig,
    ApprovalDecisionResult,
    ApprovalList,
    AttachmentInfo,
    CapturedResponseInfo,
    ChannelInfo,
    ClusterNode,
    ClusterNodeList,
    ClusterStatus,
    ConfigProvenance,
    ConnectionEventInfo,
    ConnectionMetadata,
    ConnectionRow,
    ConnectionTestResult,
    DbInfo,
    DeadLetterList,
    DeadLetterReplayRequest,
    DeadLetterReplayResult,
    DeadLetterRow,
    DrActionResult,
    DrActivateRequest,
    DrStatus,
    EngineInfo,
    EngineKpis,
    EventInfo,
    Health,
    IntegrityResult,
    LogInfo,
    MessageDetail,
    MessageList,
    MessageResponses,
    MessageSearchResults,
    MessageSummary,
    OutboundPayloadInfo,
    OutboundPayloads,
    EditResendRequest,
    EditResendResult,
    OutboxInfo,
    PendingApprovalInfo,
    PendingApprovalResponse,
    PoolInfo,
    PoolWaitInfo,
    PurgeResult,
    ReloadRequest,
    ReloadResult,
    ReplayResult,
    ResendRequest,
    ResendResult,
    SecurityPosture,
    StatsResetRequest,
    StatsResetResult,
    StatsResponse,
    ServiceStatusInfo,
    SystemStatus,
    UpdateInfo,
)
from messagefoundry.api._ui_seam import ENGINE_UI_SEAM, CoreHandlers, UiDeps
from messagefoundry.api.auth_routes import add_auth_routes
from messagefoundry.api.field_authz import count_exposed, redact_unauthorized
from messagefoundry.api.metrics import METRICS_CONTENT_TYPE, render_metrics
from messagefoundry.api.security import (
    authorize_ws,
    optional_identity,
    require,
    require_phi_read,
    require_service_cert,
    require_step_up,
    ws_token,
)

# NOTE: the web console (messagefoundry_webconsole) is deliberately NOT imported at module scope
# (ADR 0065 / Option B). It is a GUARDED import inside create_app's serve_ui tail (mounted via
# mount_ui), so the engine imports + boots + serves the JSON API with the console ABSENT. serve_ui-on
# behavior is preserved via three seams the console installs: app.state.ui_csp,
# app.state.ui_ws_authorize, app.state.ui_connections_render (read by the always-on middleware/routes).
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.service import AuthService, BootstrapAdmin
from messagefoundry.config.ai_policy import resolve_effective_policy
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    Priority,
    RetryPolicy,
    SaturationThreshold,
    StallThreshold,
)
from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    ClusterSettings,
    DrSettings,
    EgressSettings,
    IntegritySettings,
    ReferenceSettings,
    RetentionSettings,
    SandboxSettings,
    SecretRotationSettings,
    SecretsSettings,
    ServiceStatusSettings,
    ShadowSettings,
    StoreBackend,
    StoreSettings,
    TlsSettings,
    UpdateCheckSettings,
    hop_posture_from_ai,
)
from messagefoundry.config.fingerprint import config_fingerprint_detail
from messagefoundry.config.secretprovider import resolve_secret_provider
from messagefoundry.config.wiring import (
    EnvRef,
    Registry,
    WiringError,
    load_config,
    redacted_settings,
)
from messagefoundry.integrity import run_startup_attestation
from messagefoundry.service_status import query_service_state
from messagefoundry.last_resort import install_loop_exception_handler
from messagefoundry.pipeline import ConfigReloadDenied, Engine
from messagefoundry.pipeline.connscale_shim import maybe_install_executor_shim
from messagefoundry.pipeline.dr import DrActivationError
from messagefoundry.pipeline.alert_sinks import notifier_from_settings
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.security_notify import security_notifier_from_settings
from messagefoundry.pipeline.cluster import build_coordinator
from messagefoundry.pipeline.wiring_runner import RegistryRunner, ShardLaneOwnershipError
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    TestNotSupportedError,
)
from messagefoundry.store import Row, open_store, sqlite_settings
from messagefoundry.store.base import ResendError
from messagefoundry.store.content_search import (
    DEFAULT_SCAN_LIMIT as DEFAULT_CONTENT_SCAN_LIMIT,
)
from messagefoundry.store.content_search import (
    MAX_SCAN_LIMIT as MAX_CONTENT_SCAN_LIMIT,
)
from messagefoundry.store.content_search import (
    ContentSearchError,
    SearchSpec,
    SearchTarget,
    make_spec,
)
from messagefoundry.store.base import Store
from messagefoundry.store.metadata import user_metadata
from messagefoundry.store.store import _secure_file

__all__ = ["create_app", "create_managed_app"]

_RATE_WINDOW = 60.0  # seconds; window for the backlog throughput estimate
_MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB cap on HTTP request bodies (API-INPUT)
_CONNECTION_TEST_TIMEOUT = 35.0  # overall cap for a POST /connections/{name}/test probe (seconds)
_MAX_WS_CONNECTIONS = 64  # cap concurrent /ws/stats sockets (API-WS)
_WS_REVALIDATE_SECONDS = 3.0  # re-check the session on an open /ws/stats this often (API-WS)
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


def _log_storage(log_dir: str | None) -> LogInfo | None:
    """Meter the configured app-log directory (#50): its regular-file byte total (one level, non-
    recursive — supervisors like NSSM rotate flat into one dir) plus the free space on its filesystem,
    mirroring :class:`DbInfo`'s ``size_bytes`` / ``disk_free_bytes``. **Metadata only — no file
    content is ever read** (no PHI). Returns ``None`` when no directory is configured (stdout-only) or
    the directory is missing/unreadable, so ``/status`` degrades gracefully and never raises. Blocking
    (``stat`` per entry + ``disk_usage``) — the caller runs it off the event loop."""
    if not log_dir:
        return None
    path = Path(log_dir)
    try:
        free = shutil.disk_usage(path).free
    except OSError:
        return None  # directory absent/unreadable → absent, never raise
    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue  # a vanished/locked rotation file is skipped, not fatal
    except OSError:
        return None
    return LogInfo(path=str(path), size_bytes=total, disk_free_bytes=free)


def _cookie_secure(request: Request) -> bool:
    """Whether the session cookie ships with ``Secure`` (L5b, ADR 0068 §8): the per-request
    scheme is https, OR the operator declared the browser-facing scheme https via
    ``exposure_protected`` — the flag is computed ONCE at login, so a proxy that omits
    ``X-Forwarded-Proto`` on that one request would otherwise poison the whole session's cookie."""
    return request.url.scheme == "https" or bool(
        getattr(request.app.state, "exposure_protected", False)
    )


def _get_engine(request: Request) -> Engine:
    engine: Engine | None = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="engine not started")
    return engine


def _executor_gauges(app: FastAPI) -> tuple[int | None, int | None]:
    """The B11 default-executor submit-queue depth + busy count, or ``(None, None)`` when the
    harness's instrumented boot-shim is not installed (production / every non-connscale run). Read-only
    observability for ``/stats`` wall #1; never raises."""
    executor = getattr(app.state, "connscale_executor", None)
    if executor is None:
        return None, None
    return executor.queue_depth, executor.busy


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
        # Load-bearing dual-control guard (findings #1/#4/#11): ApprovalGate.approve runs THIS executor
        # directly (purge_connection is NOT re-entered on the release path), and it flips the row to
        # 'approved' BEFORE executing — so the require-quiesced precondition must be re-checked HERE, and
        # a failure must NOT raise (a raise would strand the row approved-but-unexecuted). A non-quiesced
        # (running/stopping) outbound could have an INFLIGHT row cancel_queued cannot cancel, so purging
        # it would mis-fire; skip fail-closed and record cancelled=0/skipped in the approval audit. The
        # operator re-Stops (lets it quiesce) and re-requests.
        rr = engine.registry_runner
        if rr is not None:
            # ADR 0073: a non-owning shard's quiesced signal is vacuous (it never runs the lane), so
            # an ownership miss must skip fail-closed here exactly like the non-quiesced case.
            owner = rr.destination_owner(str(p["name"]))
            if owner is not None and owner != rr.registry.shard_id:
                return {"cancelled": 0, "skipped": f"outbound owned by shard {owner}"}
            if not rr.outbound_quiesced(str(p["name"])):
                return {"cancelled": 0, "skipped": "outbound running"}
        cancelled = await engine.store.cancel_queued(
            None, str(p["name"]), top_only=(p.get("scope") == "top")
        )
        return {"cancelled": cancelled}

    async def _config_reload(p: Mapping[str, Any]) -> dict[str, Any]:
        # ADR 0041 D2: a held config:deploy is re-executed here, on the second approver's release. It
        # is a NON-dry-run reload (a dry_run is never held — it swaps nothing), so propagate=True bumps
        # the cluster config version exactly like the inline path. The captured config_dir is replayed
        # verbatim; the loader re-confines it to an allowed reload root (ConfigReloadDenied -> the
        # gate surfaces it). The same fingerprint-bearing config_reload audit row is written so the
        # released reload is bound to the bytes that actually loaded (defeating attribution-laundering).
        config_dir = p.get("config_dir")
        registry = await engine.reload(config_dir, dry_run=False, propagate=True)
        await _record_reload_audit(engine, actor=str(p["requester"]), dir_arg=config_dir)
        return {
            "inbound": len(registry.inbound),
            "outbound": len(registry.outbound),
        }

    gate.register("dead_letter_replay", "Replay dead-lettered deliveries", _replay)
    gate.register("connection_purge", "Purge queued deliveries to an outbound connection", _purge)
    gate.register("config_reload", "Reload the live config graph (config:deploy)", _config_reload)
    return gate


async def _record_reload_audit(engine: Engine, *, actor: str, dir_arg: object) -> None:
    """Write the ``config_reload`` audit row with the ADR 0041 D1 content fingerprint of what loaded.

    Shared by the inline reload endpoint and the dual-control executor so a held-then-approved reload
    records the same fingerprint-bearing row as an ungated one. The fingerprint is computed off the
    event loop and is best-effort — a fingerprint failure must never block the audit of a successful
    reload. ``dir_arg`` is the requested config_dir (advisory; the row keys on engine.last_reload_dir)."""
    fingerprint: dict[str, object] = {}
    if engine.last_reload_dir is not None:
        try:
            fingerprint = await asyncio.to_thread(config_fingerprint_detail, engine.last_reload_dir)
        except OSError as exc:  # unreadable dir mid-reload — degrade, don't fail the audit
            _log.warning("config fingerprint failed for %s: %s", engine.last_reload_dir, exc)
    rr = engine.registry_runner
    await engine.store.record_audit(
        "config_reload",
        actor=actor,
        detail=json.dumps(
            {
                "dir": str(engine.last_reload_dir) if engine.last_reload_dir else None,
                "inbound": len(rr.registry.inbound) if rr else 0,
                "outbound": len(rr.registry.outbound) if rr else 0,
                "dry_run": False,
                **fingerprint,
            }
        ),
    )


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
        # Surface ONLY the operator/handler user bag (ADR 0081, #150) — user_metadata strips the
        # engine-internal ADR-0013 correlation-lineage keys so they never leak to the API.
        metadata=user_metadata(d.get("metadata")),
    )


#: A conservative MIME type — ``type/subtype`` of RFC-2045 token chars only, no structural characters
#: (``;``/space/CR/LF/``"``) that could inject or split the ``Content-Type`` header. An attachment's
#: ``content_type`` originates from an attacker-influenced OBX-5.2 label, so a value failing this is
#: served as the generic binary type below rather than trusted into the response header.
_SAFE_MIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$")
_DEFAULT_ATTACHMENT_MIME = "application/octet-stream"


def _safe_attachment_content_type(content_type: str | None) -> str:
    """The download ``Content-Type``: the stored ``content_type`` when it is a clean ``type/subtype``
    MIME, else ``application/octet-stream`` (never an attacker-influenced value verbatim in the header)."""
    ct = (content_type or "").strip()
    return ct if _SAFE_MIME_RE.match(ct) else _DEFAULT_ATTACHMENT_MIME


def _attachment_filename(attachment_id: str, content_type: str) -> str:
    """A header-safe download filename. ``attachment_id`` is a 64-hex sha256 (safe by construction); a
    short prefix keeps it readable and a ``mimetypes`` extension (when the MIME is known) hints the type.
    No user/attacker text reaches the ``Content-Disposition`` header."""
    ext = mimetypes.guess_extension(content_type) or ""
    return f"attachment-{attachment_id[:16]}{ext}"


def _needle_shape(needle: str) -> str:
    """A PHI-safe, coarse classifier of a search needle's *shape* for the audit (NEVER its value).

    An operator's needle may itself be PHI — an MRN, a patient name (ADR 0046 §4/AC-6). The audit must
    record *that a content search ran and roughly what kind of term*, never the term verbatim. We emit
    only a structural class (all-digits / alphanumeric / has-separators / other) — not the characters —
    so even a 9-digit MRN logs as ``digits`` with a length, never the number itself."""
    if needle.isdigit():
        return "digits"
    if needle.isalnum():
        return "alnum"
    if needle.isalpha():
        return "alpha"
    return "mixed"


def _search_audit_detail(
    spec: SearchSpec, result: object, *, filters: dict[str, str | None]
) -> dict[str, object]:
    """Build the ``message_search`` audit detail — metadata filters + needle SHAPE + scan counts, with
    **no** needle value (AC-6). The HL7 ``field_path`` (e.g. ``PID-3``) is a structural locator, not PHI,
    so it is recorded; the matched VALUE is never recorded."""
    # `result` is a MessageSearchResult (kept loosely-typed to avoid importing the store dataclass here).
    scanned = getattr(result, "scanned", None)
    matched = getattr(result, "matched", None)
    truncated = getattr(result, "truncated", None)
    detail: dict[str, object] = {
        "filters": {k: v for k, v in filters.items() if v is not None},
        "scanned": scanned,
        "matched": matched,
        "truncated": truncated,
        "scan_limit": spec.scan_limit,
        "target": spec.target.value,
    }
    if spec.substring is not None:
        detail["needle_kind"] = "substring"
        detail["needle_shape"] = _needle_shape(spec.substring)
        detail["needle_len"] = len(spec.substring)
    else:
        detail["needle_kind"] = "field_path"
        detail["field_path"] = spec.field_path  # structural locator, not PHI
        # Whether a value predicate was supplied (presence-test vs value-contains), but never the value.
        detail["field_value_present"] = spec.field_value is not None
        if spec.field_value is not None:
            detail["needle_shape"] = _needle_shape(spec.field_value)
            detail["needle_len"] = len(spec.field_value)
    return detail


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
    service_settings: ServiceStatusSettings | None = None,
    expose_docs: bool = False,
    allow_no_auth: bool = False,
    ws_allowed_origins: Sequence[str] = (),
    serve_ui: bool = False,
    public_origin: str | None = None,
    webauthn_rp_from_request: bool = True,
    exposure_protected: bool = False,
    tls_terminated_upstream: bool = False,
    tls_client_cert_identities: Mapping[str, str] | None = None,
    log_dir: str | None = None,
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
    # [service] service-status reporting (L6a): default-off; the managed lifespan sets the live value,
    # here it backs the direct-construction (test) path.
    app.state.service_settings = service_settings
    # Configured [logging].log_dir for the GET /status app-log metering (#50). None = stdout-only (no
    # metering). The managed-app lifespan sets the live value; here it backs the direct-construction path.
    app.state.log_dir = log_dir
    app.state.ws_count = 0  # live /ws/stats connection count (API-WS cap)
    app.state.ws_allowed_origins = tuple(
        ws_allowed_origins
    )  # browser Origins for /ws/stats (4.4.2)
    # The /ui external origin for the same-origin CSRF/CSWSH checks when off-loopback behind a proxy
    # that doesn't preserve Host (ADR 0065). None = loopback / Host-preserving-proxy behavior.
    app.state.public_origin = public_origin
    # WebAuthn RP fallback (ADR 0068 §7): when public_origin is unset, the request URL may anchor
    # the rp_id ONLY on a loopback bind with no reverse proxy declared (the serve path computes
    # this from [api]; the default True preserves the loopback dev/test posture). Behind a declared
    # proxy the Host header is client-forwardable — ceremonies fail closed instead (webauthn_rp).
    app.state.webauthn_rp_from_request = webauthn_rp_from_request
    # L5b off-loopback hardening (ADR 0068 §8 — the fill1 proxy-scheme trap): exposure_protected
    # is the OPERATOR'S declaration that the browser-facing scheme is https (in-process TLS or a
    # declared terminator). It forces the session cookie's Secure flag and HSTS regardless of the
    # per-request scheme — the scheme is computed ONCE at login and a proxy that omits
    # X-Forwarded-Proto would otherwise poison the cookie for the whole session.
    # tls_terminated_upstream additionally arms the one-shot /ui cleartext-scheme tripwire.
    app.state.exposure_protected = exposure_protected
    app.state.tls_terminated_upstream = tls_terminated_upstream
    # mTLS client-cert → principal allow-list (#200, ADR 0002). Read by security.resolve_client_cert_
    # identity to map a VERIFIED peer cert's subject/SAN to an Identity (deny-by-default). Empty (the
    # default) disables cert-identity — byte-identical to the pre-#200 mTLS-for-transport-only path.
    app.state.tls_client_cert_identities = dict(tls_client_cert_identities or {})
    app.state.summary_auditor = _SummaryAuditCoalescer()  # coalesced PHI-summary access audit (M-5)
    # add_auth_routes registers the auth/user-admin JSON routes and RETURNS an AdminHandlers bundle of
    # its nested handlers; the /ui admin pages that reuse them now live in messagefoundry_webconsole and
    # are wired via mount_ui in the serve_ui tail below (Option B, ADR 0065). It runs UNCONDITIONALLY, so
    # its returned bundle's type lives in the engine leaf api._ui_seam (never the console package).
    admin = add_auth_routes(app)

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

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # PHI-safe 422 (ADR 0090 §9 / BACKLOG #153, ASVS 16.5.1). FastAPI's default validation handler
        # echoes each error's ``input`` (the offending value) and ``ctx``. For a body-carrying PHI route
        # — the edit-and-resubmit ``raw`` — that would surface the edited message body verbatim in the
        # 4xx response AND in any client/proxy access log. Strip ``input``/``ctx`` so only the location,
        # message, and type remain (enough to fix a bad request, never the PHI). The offending value is
        # NOT logged either (the "never log bodies" rule) — we log the field locations only.
        safe = [{k: v for k, v in err.items() if k not in ("input", "ctx")} for err in exc.errors()]
        _log.info(
            "request validation failed on %s %s: %d field error(s)",
            request.method,
            request.url.path,
            len(safe),
        )
        return JSONResponse({"detail": jsonable_encoder(safe)}, status_code=422)

    # One-shot XFP-omission tripwire state (L5b, ADR 0068 §8): fires at most once per process.
    xfp_tripwire_fired = False

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Any) -> Any:
        # Defense-in-depth response headers (ASVS 3.4.4 / 3.4.5 / 3.2.1). The shipped client is a
        # desktop app, but these are mandatory the moment a browser/off-loopback client appears and
        # cost nothing on a JSON API. HSTS is emitted over https OR when the operator declared the
        # browser-facing scheme https (exposure_protected — L5b, ADR 0068 §8: the per-request
        # scheme is unreliable behind a proxy that omits X-Forwarded-Proto).
        nonlocal xfp_tripwire_fired
        if (
            tls_terminated_upstream
            and not xfp_tripwire_fired
            and request.url.scheme == "http"
            and (request.url.path == "/ui" or request.url.path.startswith("/ui/"))
        ):
            # A /ui request arrived with a cleartext scheme while a TLS-terminating proxy is
            # DECLARED — either the proxy is not sending X-Forwarded-Proto, or its peer address
            # is not matched by [api].trusted_proxies (including the ::1-vs-127.0.0.1 mismatch).
            # Cookie Secure/HSTS are forced by exposure_protected regardless, but the source-IP
            # chain (audit, rate limits, new-IP step-up) is degraded until this is fixed.
            xfp_tripwire_fired = True
            _log.warning(
                "a /ui request arrived scheme=http while [api].tls_terminated_upstream is set — "
                "the proxy is not sending X-Forwarded-Proto, or its peer IP is not matched by "
                "[api].trusted_proxies (check ::1 vs 127.0.0.1). See "
                "docs/security/OFF-LOOPBACK-DEPLOYMENT.md."
            )
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.scheme == "https" or exposure_protected:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        # /ui browser surface (ADR 0065 §5): a strict CSP (no unsafe-*) and no-store on every HTML
        # response; the vendored /ui/static assets keep StaticFiles' own cache. PHI JSON reads also get
        # no-store so a browser/proxy never caches a message body. These are SET (override) so a stale
        # cache directive can't slip through. nosniff/frame-deny/HSTS above still apply.
        path = request.url.path
        if (path == "/ui" or path.startswith("/ui/")) and not path.startswith("/ui/static"):
            # The /ui CSP is co-versioned with the app.js/app.css it governs, so the web console owns
            # it and installs it as an app.state hook in the serve_ui path (Option B Phase 0). Absent
            # (JSON-only) → apply no /ui-specific CSP; the JSON API serves no HTML. Cache-Control
            # no-store still applies to any /ui path so a browser/proxy never caches HTML.
            ui_csp = getattr(request.app.state, "ui_csp", None)
            if ui_csp is not None:
                response.headers["Content-Security-Policy"] = ui_csp
            response.headers["Cache-Control"] = "no-store"
        elif path.startswith("/messages") or path.startswith("/dead-letters"):
            response.headers["Cache-Control"] = "no-store"
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
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> list[ChannelInfo]:
        """Inbound connections as ChannelInfo (id = connection name) for the Log Search filter."""
        runner = engine.registry_runner
        if runner is None:
            return []
        # Per-channel RBAC: a channel-scoped caller sees only their own inbound connections (the same
        # tenant-isolation boundary connection_metadata/test/purge enforce); an unscoped caller sees all.
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
            if identity.can_access_channel(name)
        ]

    # --- connections (per-endpoint dashboard) --------------------------------

    @app.get("/connections", response_model=list[ConnectionRow])
    async def list_connections(
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> list[ConnectionRow]:
        now = time.time()
        # Per-channel RBAC: a channel-scoped caller sees only the source rows of their own inbound
        # connections; shared-outbound (destination/degraded) rows are suppressed entirely, since an
        # outbound spans channels — the same boundary connection_metadata/test/purge enforce. An
        # unscoped caller (allowed_channels is None) sees the full estate, unchanged.
        scoped = identity.allowed_channels is not None
        # Offset-adjusted: subtracts any operator stats-resets (in-memory baselines). Identical to the
        # raw store metrics when nothing has been reset.
        metrics = await engine.connection_metrics_view(now=now, rate_window=_RATE_WINDOW)
        # ADR 0044 (#56): the real open-alert count per connection, joined to the rows below by name.
        # One grouped read on the lockfree path, replacing the stubbed alerts_active=0. A connection with
        # no open instances is simply absent from the map (→ 0).
        open_alerts = await engine.store.count_open_alerts_by_connection()
        rows: list[ConnectionRow] = []

        # A source row per inbound connection, and a destination row per (inbound → outbound)
        # edge that has carried traffic (the outbox metrics are keyed that way).
        rr = engine.registry_runner
        if rr is not None:
            reg = rr.registry
            for iname, ic in reg.inbound.items():
                if not identity.can_access_channel(iname):
                    continue  # per-channel RBAC: hide an inbound outside the caller's scope
                inb = metrics.inbound.get(iname)
                speer, sport = _peer_port(ic.spec.type.value, ic.spec.settings)
                ifail = rr.connection_failed(iname)  # ADR 0031: start failed → not listening
                ifiltered = rr.connection_filtered(iname)  # #61 ADR 0048: DR-parked below threshold
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
                            else (
                                "filtered"
                                if ifiltered
                                else ("running" if rr.inbound_running(iname) else "stopped")
                            )
                        ),
                        direction="in",
                        method=_method_label(ic.spec.type.value),
                        peer=speer,
                        port=sport,
                        queue_depth=None,
                        idle_seconds=(now - inb.last_at) if inb and inb.last_at else None,
                        alerts_active=open_alerts.get(iname, 0),
                        errored=inb.errored if inb else 0,
                        read=inb.read if inb else 0,
                        written=None,
                        backlog_seconds=None,
                        delivered_age_seconds=None,
                        # The failure reason (ADR 0031) or the DR-parked reason (#61) — whichever set
                        # the status; ifail takes precedence (a failed connection is never also parked).
                        error=ifail or ifiltered,
                    )
                )
            emitted_dests: set[str] = set()
            for (cid, dname), dm in metrics.destinations.items():
                if cid not in reg.inbound:
                    continue  # a declarative-channel edge, already emitted above
                if scoped:
                    # A channel-scoped user must not see shared-outbound topology (peer IP/port/state) —
                    # the same denial connection_metadata/test/purge apply to a shared outbound.
                    continue
                emitted_dests.add(dname)
                oc = reg.outbound.get(dname)
                dfail = rr.connection_failed(dname)  # ADR 0031: built? or degraded?
                dfiltered = rr.connection_filtered(dname)  # #61 ADR 0048: DR-parked below threshold
                # An outbound the live graph no longer declares (removed by a reload) keeps draining
                # its queued rows — report it honestly as "draining" with an unknown method, rather
                # than mislabeling it as a running File connector.
                if oc is not None:
                    dmethod = _method_label(oc.spec.type.value)
                    dpeer, dport = _peer_port(oc.spec.type.value, oc.spec.settings)
                    # The collapsed display status: failed/filtered take precedence, else the live
                    # per-outbound tri-state (running/stopping/stopped) — no longer the whole-engine state.
                    dstatus = (
                        "failed"
                        if dfail
                        else ("filtered" if dfiltered else rr.outbound_status(dname))
                    )
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
                        alerts_active=open_alerts.get(dname, 0),
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
                        # Purge-eligibility, INDEPENDENT of the collapsed display status: True only once
                        # the outbound is operator-paused AND fully quiesced (so a failed/filtered-but-
                        # paused outbound stays purgeable even though it shows "failed"/"filtered").
                        paused=rr.outbound_quiesced(dname),
                        error=(dfail or dfiltered) if oc is not None else None,
                        owner_shard=rr.destination_owner(dname),  # ADR 0073; None unsharded
                    )
                )
            # ADR 0031 / #61 ADR 0048: an outbound that FAILED to build (0031) or was DR-PARKED below the
            # threshold (0048) has no metrics edge until traffic is routed to it, so it would be invisible
            # above. Emit a standalone row for every still-failed/filtered outbound not already shown, so
            # a degraded or parked lane is never silently hidden from the dashboard. A failed connection
            # is also in degraded_connections; a filtered one is in filtered_connections — the two reasons
            # map to the distinct "failed" vs "filtered" status (a connection is never in both).
            standalone: dict[str, tuple[str, str | None]] = {
                name: ("failed", reason) for name, reason in rr.degraded_connections().items()
            }
            for name, reason in rr.filtered_connections().items():
                standalone.setdefault(name, ("filtered", reason))
            # Also surface any operator-paused outbound with no failed/filtered/edge row yet, so a paused
            # idle/no-edge lane stays visible + selectable (its purge-eligibility is the `paused` field
            # below; the status is the live tri-state stopping/stopped, reason None — no failure).
            for oname in reg.outbound:
                if oname in standalone or oname in emitted_dests:
                    continue
                ostatus = rr.outbound_status(oname)
                if ostatus in ("stopping", "stopped"):
                    standalone[oname] = (ostatus, None)
            for dname, (dstatus, dreason) in standalone.items():
                if scoped:
                    continue  # channel-scoped users never see shared-outbound topology (see above)
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
                        status=dstatus,
                        direction="out",
                        method=dmethod,
                        peer=dpeer,
                        port=dport,
                        queue_depth=None,
                        idle_seconds=None,
                        alerts_active=open_alerts.get(dname, 0),
                        errored=None,
                        read=None,
                        written=None,
                        backlog_seconds=None,
                        delivered_age_seconds=None,
                        simulated=rr.outbound_simulated(dname),
                        paused=rr.outbound_quiesced(dname),
                        error=dreason,
                        owner_shard=rr.destination_owner(dname),  # ADR 0073; None unsharded
                    )
                )
        return rows

    # --- code-first connection operations ------------------------------------

    async def _control_guard(engine: Engine, identity: Identity, name: str) -> None:
        # Controlling an inbound connection is scoped per-channel (the connection IS the channel).
        if not identity.can_access_channel(name):
            await _audit_channel_denied(engine, identity, name)
            raise HTTPException(403, "not authorized for this connection")

    async def _dual_role_control(
        engine: Engine, identity: Identity, name: str, action: str, *, role: str | None = None
    ) -> dict[str, object]:
        """Start/stop/restart on an INBOUND *or* an OUTBOUND (the shared primitive behind both the JSON
        and /ui control routes). An inbound → per-channel ``_control_guard`` + ``rr.<action>_inbound``
        (stopping an inbound halts intake, its delivery keeps draining). A shared outbound → a
        channel-scoped user is denied (an outbound spans channels; mirrors purge), else
        ``rr.<action>_outbound`` (stopping an outbound PAUSES delivery, retaining the queue). A name that
        is neither still runs the per-channel guard first, so a scoped user gets a 403 for an out-of-scope
        name rather than learning it doesn't exist, then 404. Returns ``{"name", "running"}``.

        ``role`` disambiguates a name declared as BOTH an inbound and an outbound: ``"source"`` targets
        only the inbound, ``"destination"`` only the outbound. ``None`` (the bare-name JSON/legacy
        callers) keeps the inbound-first resolution — a name that is both hits the inbound, unchanged."""
        rr = engine.registry_runner
        want_in = role in (None, "source")
        want_out = role in (None, "destination")
        if rr is not None and want_in and name in rr.registry.inbound:
            await _control_guard(engine, identity, name)
            if action == "start":
                await rr.start_inbound(name)
            elif action == "stop":
                await rr.stop_inbound(name)
            else:
                await rr.restart_inbound(name)
            return {"name": name, "running": rr.inbound_running(name)}
        if rr is not None and want_out and name in rr.registry.outbound:
            # A shared outbound spans channels, so a channel-scoped user can't control one (mirrors purge).
            if identity.allowed_channels is not None:
                await _audit_channel_denied(engine, identity, name)
                raise HTTPException(
                    403, "channel-scoped users cannot control a shared outbound connection"
                )
            try:
                if action == "start":
                    await rr.start_outbound(name)
                elif action == "stop":
                    await rr.stop_outbound(name)
                else:
                    await rr.restart_outbound(name)
            except ShardLaneOwnershipError as exc:
                # ADR 0073: this shard never runs the lane, so acting here would only produce a
                # vacuous 'stopped' (and unlock purge) while the owner keeps delivering.
                raise HTTPException(409, str(exc)) from None
            return {"name": name, "running": rr.outbound_running(name)}
        # Neither an inbound nor an outbound (or no runner). Run the per-channel guard first so a scoped
        # user is 403'd for a name outside their scope (don't disclose existence), then 404.
        await _control_guard(engine, identity, name)
        raise HTTPException(404, f"no such connection: {name}")

    @app.post("/connections/{name}/start")
    async def start_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        return await _dual_role_control(engine, identity, name, "start")

    @app.post("/connections/{name}/stop")
    async def stop_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        return await _dual_role_control(engine, identity, name, "stop")

    @app.post("/connections/{name}/restart")
    async def restart_connection(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        return await _dual_role_control(engine, identity, name, "restart")

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
                # ADR 0031 failure reason, or the #61 (ADR 0048) DR-parked reason — whichever applies.
                error=rr.connection_failed(name) or rr.connection_filtered(name),
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
                # ADR 0031 failure reason, or the #61 (ADR 0048) DR-parked reason — whichever applies.
                error=rr.connection_failed(name) or rr.connection_filtered(name),
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
        # ADR 0073: purge is owner-only on a sharded engine — a non-owning shard's quiesced signal is
        # vacuous (it never runs the lane), so it would green-light a purge racing the owner's claims.
        owner = rr.destination_owner(name)
        if owner is not None and owner != rr.registry.shard_id:
            raise HTTPException(
                409,
                f"outbound {name!r} is owned by engine shard {owner!r} — stop and purge it on that "
                "shard's API",
            )
        # require-stopped-before-purge (after the 404, before any approval is held for a doomed purge):
        # a running/still-"stopping" outbound may have a claimed INFLIGHT row cancel_queued cannot cancel,
        # so purge must wait until the lane is paused AND fully quiesced. The load-bearing dual-control
        # re-check lives in the `_purge` approval executor (the release path never re-enters this handler).
        if not rr.outbound_quiesced(name):
            raise HTTPException(
                409, "stop the outbound and let it quiesce before purging its queue"
            )
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
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
        connection: str | None = Query(None, max_length=256),
        kind: list[str] | None = Query(None),
        since: float | None = Query(None, ge=0),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[ConnectionEventInfo]:
        """The Corepoint-style connection/transport event log (#46), newest first — **metadata only,
        no PHI**, so it is gated by ``monitoring:read`` (not the PHI-read tier). Optionally filtered by
        ``connection``, one-or-more event ``kind``s, and a ``since`` epoch timestamp."""
        # Per-channel RBAC: an explicit out-of-scope connection= is denied (and audited), matching the
        # /dead-letters/replay boundary; otherwise the store filters to the caller's inbound events.
        if connection is not None and not identity.can_access_channel(connection):
            await _audit_channel_denied(engine, identity, connection)
            raise HTTPException(403, "connection is outside your channel scope")
        rows = await engine.store.list_connection_events(
            connection=connection,
            kinds=kind,
            since=since,
            limit=limit,
            allowed_channels=_scope(identity),
        )
        return [_conn_event_info(r) for r in rows]

    @app.get("/connections/{name}/events", response_model=list[ConnectionEventInfo])
    async def list_connection_events_for(
        name: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
        kind: list[str] | None = Query(None),
        since: float | None = Query(None, ge=0),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[ConnectionEventInfo]:
        """The connection/transport event log scoped to one connection (#46), newest first."""
        # Per-channel RBAC: 403 + audit an out-of-scope name (an outbound name isn't a channel a scoped
        # user can access, so this also denies shared-outbound topology); the store scope is defense-in-
        # depth on top of the guard.
        await _control_guard(engine, identity, name)
        rows = await engine.store.list_connection_events(
            connection=name,
            kinds=kind,
            since=since,
            limit=limit,
            allowed_channels=_scope(identity),
        )
        return [_conn_event_info(r) for r in rows]

    # --- operator alert-state (ADR 0044, #56) --------------------------------

    def _alert_instance_info(a: Any) -> AlertInstanceInfo:
        return AlertInstanceInfo(
            id=a.id,
            event_type=a.event_type,
            connection=a.connection,
            severity=a.severity,
            status=a.status,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            count=a.count,
            reason=a.reason,
            acked_by=a.acked_by,
            acked_at=a.acked_at,
            resolved_at=a.resolved_at,
        )

    @app.get("/alerts/active", response_model=AlertInstanceList)
    async def list_active_alerts(
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
        limit: int = Query(200, ge=1, le=1000),
    ) -> AlertInstanceList:
        """The open + acknowledged operator-alert instances (ADR 0044, #56), newest ``last_seen`` first —
        **metadata only, no PHI**. Diagnostic operator state, so gated by ``monitoring:diagnose`` (the
        ack/resolve tier), with the same per-channel RBAC scope as ``GET /events``."""
        rows = await engine.store.list_active_alert_instances(
            limit=limit, allowed_channels=_scope(identity)
        )
        return AlertInstanceList(alerts=[_alert_instance_info(r) for r in rows])

    @app.post("/alerts/{alert_id}/ack", response_model=AlertInstanceInfo)
    async def ack_alert(
        alert_id: int,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
    ) -> AlertInstanceInfo:
        """Acknowledge an open alert instance (ADR 0044): set ``acknowledged`` + ``acked_by``/``acked_at``
        and exclude it from ``alerts_active``. Writes one metadata-only ``alert_ack`` audit row (no
        message content). 404 if the id is unknown or already resolved."""
        # AC-7: a channel-scoped operator may only mutate instances within its scope. Resolve the
        # instance scoped FIRST so an out-of-scope id is refused with no state change and no audit row
        # (a scoped read returns None for an instance on another connection). This mirrors the mutating-
        # route convention (replay_dead_letters pre-checks scope + raises 403 before mutating).
        await _require_alert_scope(engine, identity, alert_id)
        ok = await engine.store.ack_alert_instance(alert_id, actor=identity.username)
        if not ok:
            raise HTTPException(404, "alert instance not found or already resolved")
        await engine.store.record_audit(
            "alert_ack", actor=identity.username, detail=json.dumps({"alert_id": alert_id})
        )
        return await _alert_instance_echo(engine, identity, alert_id)

    @app.post("/alerts/{alert_id}/resolve", response_model=AlertInstanceInfo)
    async def resolve_alert(
        alert_id: int,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
    ) -> AlertInstanceInfo:
        """Resolve an open/acknowledged alert instance (ADR 0044): set ``resolved`` + ``resolved_at``.
        Writes one metadata-only ``alert_resolve`` audit row. 404 if the id is unknown or already
        resolved."""
        # AC-7: scope-check before mutating (see ack_alert) — an out-of-scope id is refused with no
        # state change and no audit row.
        await _require_alert_scope(engine, identity, alert_id)
        ok = await engine.store.resolve_alert_instance(alert_id)
        if not ok:
            raise HTTPException(404, "alert instance not found or already resolved")
        await engine.store.record_audit(
            "alert_resolve", actor=identity.username, detail=json.dumps({"alert_id": alert_id})
        )
        return await _alert_instance_echo(engine, identity, alert_id)

    async def _require_alert_scope(engine: Engine, identity: Identity, alert_id: int) -> None:
        # AC-7 pre-mutation RBAC gate for ack/resolve: a scoped read of the instance must succeed before
        # any state change. get_alert_instance returns None for both an unknown id AND an in-existence-but-
        # out-of-scope id (its connection isn't in the caller's channels), so we 404 either way — refusing
        # the mutation without leaking whether the id exists outside the caller's scope, and (because we
        # raise before any UPDATE or record_audit) writing no state change and no audit row. An unscoped
        # caller (allowed_channels is None) passes through. Already-resolved ids are still surfaced as 404
        # by the mutating store call itself (this read includes any status).
        if identity.allowed_channels is None:
            return
        a = await engine.store.get_alert_instance(alert_id, allowed_channels=_scope(identity))
        if a is None:
            raise HTTPException(404, "alert instance not found")

    async def _alert_instance_echo(
        engine: Engine, identity: Identity, alert_id: int
    ) -> AlertInstanceInfo:
        # Echo the just-mutated instance's new state. RBAC-scoped to the caller's channels (defense in
        # depth on top of the mutation having already succeeded). A resolved instance is no longer in the
        # active list, so the read includes any status.
        a = await engine.store.get_alert_instance(alert_id, allowed_channels=_scope(identity))
        if a is None:  # vanished (e.g. concurrent retention purge of a just-resolved row)
            raise HTTPException(404, "alert instance not found")
        return _alert_instance_info(a)

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

    @app.post("/config/reload", response_model=ReloadResult | PendingApprovalResponse)
    async def reload_config(
        req: ReloadRequest,
        response: Response,
        engine: Engine = Depends(_get_engine),
        user: Identity = Depends(require_step_up(Permission.CONFIG_DEPLOY)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> ReloadResult | PendingApprovalResponse:
        """Load the code-first graph and atomically apply it to the running engine (quiesce-and-swap;
        in-flight outbox deliveries keep draining). ``config_dir`` defaults to the server's startup
        --config dir and must resolve within an allowed reload root — the loader executes Python, so
        an arbitrary path is refused (403). A bad/empty config is rejected and the running graph is
        left untouched. Every reload (and dry-run) is audited. Requires ``config:deploy``.

        ``dry_run=true`` is the promote pre-flight: it validates the graph against THIS environment's
        values (a missing ``env()`` value → 422) and reports the would-be graph **without** swapping.

        Dual-control (ADR 0041 D2): WHERE ``config_reload`` is in ``[approvals].operations`` and
        ``[approvals].enabled``, a NON-dry-run reload is **held** (202) for a *distinct* second approver
        — the requester can never release their own — rather than swapping the live graph inline. A
        dry_run is never held (it swaps nothing). Deny-by-default: ungated deployments reload inline.

        Error responses are intentionally generic (the detail is logged server-side, not returned)
        so a config:deploy holder can't probe the filesystem via reload error text."""
        # Hold a real (non-dry-run) reload for a second approver when dual-control gates it. A dry_run
        # is a read-only pre-flight (no swap), so it is never held. The guard runs AFTER the caller's
        # own step-up + config:deploy check (above) — the second approver is an additional control, not
        # a replacement. On hold, 202 + the pending id; the captured config_dir is replayed on release.
        if gate is not None and not req.dry_run:
            pending = await gate.guard(
                "config_reload",
                {"config_dir": req.config_dir, "requester": user.username},
                requester=user.username,
            )
            if pending is not None:
                response.status_code = 202
                return PendingApprovalResponse(
                    approval_id=pending,
                    operation="config_reload",
                    detail="held for a second approver (dual-control)",
                )
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
        # Bind "what loaded" to a reviewable content digest (ADR 0041 D1): the prior detail recorded
        # only counts, so two reloads of the same dir with different on-disk code were
        # indistinguishable. Computed off the event loop (it reads files) and best-effort — a
        # fingerprint failure must never block the audit of a successful reload. The non-dry-run path
        # shares _record_reload_audit with the dual-control executor so a held-then-approved reload
        # records the identical fingerprint-bearing row.
        if req.dry_run:
            fingerprint: dict[str, object] = {}
            if engine.last_reload_dir is not None:
                try:
                    fingerprint = await asyncio.to_thread(
                        config_fingerprint_detail, engine.last_reload_dir
                    )
                except OSError as exc:  # unreadable dir mid-reload — degrade, don't fail the audit
                    _log.warning(
                        "config fingerprint failed for %s: %s", engine.last_reload_dir, exc
                    )
            await engine.store.record_audit(
                "config_reload_check",
                actor=user.username,
                detail=json.dumps(
                    {
                        "dir": str(engine.last_reload_dir) if engine.last_reload_dir else None,
                        "inbound": len(registry.inbound),
                        "outbound": len(registry.outbound),
                        "dry_run": True,
                        **fingerprint,
                    }
                ),
            )
        else:
            await _record_reload_audit(engine, actor=user.username, dir_arg=req.config_dir)
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
        received_from: float | None = Query(None, ge=0),
        received_to: float | None = Query(None, ge=0),
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
            limit=limit,
            offset=offset,
            allowed_channels=allowed,
            received_from=received_from,
            received_to=received_to,
            **filters,
        )
        total = await engine.store.count_messages(
            allowed_channels=allowed,
            received_from=received_from,
            received_to=received_to,
            **filters,
        )
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

    @app.get("/messages/search", response_model=MessageSearchResults)
    async def search_messages(
        request: Request,
        engine: Engine = Depends(_get_engine),
        # Step-up (NOT just require_phi_read): content search decrypts bodies the caller never explicitly
        # "opened" — a bulk-PHI operation, like replay (ADR 0046 D1 §4). It therefore demands a fresh
        # re-verification + the second factor on top of the MESSAGES_READ permission.
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_READ)),
        content: str | None = Query(None, max_length=512),
        field_path: str | None = Query(None, max_length=32),
        field_value: str | None = Query(None, max_length=512),
        target: str = Query("both", pattern="^(raw|summary|both)$"),
        channel_id: str | None = Query(None, max_length=256),
        status: str | None = Query(None, max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=500),
        scan_limit: int = Query(DEFAULT_CONTENT_SCAN_LIMIT, ge=1, le=MAX_CONTENT_SCAN_LIMIT),
    ) -> MessageSearchResults:
        """Search messages by what is *in* them — an HL7 field path (``PID-3``) or a raw/summary
        substring (ADR 0046 #51). Because the store is encrypted at rest, this scans-and-decrypts: it
        pre-filters on the indexed metadata, then decrypts + matches each candidate body in memory off
        the event loop, bounded by ``scan_limit`` decrypts and ``limit`` matches (truncate-and-tell). It
        sits behind step-up (a bulk-PHI read), inherits the ``view_summary`` redaction, and writes a
        dedicated ``message_search`` audit row that never records an MRN-shaped needle."""
        try:
            spec = make_spec(
                content=content,
                field_path=field_path,
                field_value=field_value,
                target=SearchTarget(target),
                scan_limit=scan_limit,
            )
        except ContentSearchError as exc:
            raise HTTPException(400, str(exc)) from exc
        allowed = _scope(identity)  # per-channel RBAC: only the caller's channels (None = all)
        result = await engine.store.search_messages(
            spec,
            channel_id=channel_id,
            status=status,
            message_type=message_type,
            control_id=control_id,
            limit=limit,
            allowed_channels=allowed,
        )
        messages = [_summary(r) for r in result.rows]
        # Same per-property PHI redaction as /messages: a caller without view_summary gets summary/error
        # nulled. The result rows are metadata-only (no body), so the exposure equals the metadata list.
        messages = [redact_unauthorized(m, identity) for m in messages]
        # A dedicated, tamper-evident message_search audit row — the actor + metadata filters + the
        # needle's SHAPE (never its value; an MRN needle is PHI, ADR 0046 §4/AC-6) + how much it touched.
        await engine.store.record_audit(
            "message_search",
            actor=identity.username,
            channel_id=channel_id,
            detail=json.dumps(
                _search_audit_detail(
                    spec,
                    result,
                    filters=dict(
                        channel_id=channel_id,
                        status=status,
                        message_type=message_type,
                        control_id=control_id,
                    ),
                )
            ),
        )
        # The summary exposure (matched rows actually carrying a summary) is ALSO coalesced into the
        # standard summary_access audit, mirroring /messages — so a search-then-harvest can't dodge it.
        exposed = count_exposed(messages)
        if exposed:
            await request.app.state.summary_auditor.note(
                engine.store, identity.username, channel_id, exposed, time.time()
            )
        return MessageSearchResults(
            messages=messages,
            scanned=result.scanned,
            matched=result.matched,
            truncated=result.truncated,
            limit=limit,
            scan_limit=spec.scan_limit,
        )

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
        # Metadata-only list of the very-large documents detached from this message (#149, ADR 0105
        # Phase 3b) — id/content_type/total_bytes, never the bytes. No extra PHI exposure over the raw
        # body this route already gated: it just tells the operator a detached document exists + how to
        # pull it (the audited /attachments/{id} download). Empty for a normal (non-streaming) message.
        attachment_rows = await engine.store.attachments_for(message_id)
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
            attachments=[
                AttachmentInfo(
                    id=a["attachment_id"],
                    content_type=a["content_type"],
                    total_bytes=a["total_bytes"],
                )
                for a in attachment_rows
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

    @app.get("/messages/{message_id}/attachments/{attachment_id}")
    async def download_attachment(
        message_id: str,
        attachment_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.MESSAGES_VIEW_RAW)),
    ) -> Response:
        """Download the reconstructed bytes of a very-large document detached from ``message_id`` (#149,
        ADR 0105 Phase 3b). A detached document is the **same PHI** as the raw body, so this rides the
        SAME ``MESSAGES_VIEW_RAW`` gate + per-channel scope guard as :func:`get_message` (no separate
        permission, no step-up).

        The **security crux** is the linkage check: content-addressing means one physical attachment can
        be shared across many messages/tenants, so an operator must never pull a document by guessing a
        content address that is not linked to a message IN THEIR CHANNEL SCOPE. This verifies the
        ``(message_id, attachment_id)`` pair exists in ``message_attachment`` (404 otherwise) AFTER the
        channel-scope guard, so access is scoped to the message the operator may already read.

        Approach B stored the OBX-5.5 value VERBATIM (base64), so the bytes are reconstructed by
        concatenating the attachment's chunks and base64-decoding once (buffer-once, mirroring the
        delivery buffer-once posture). Every download is audited (``record_view`` + an
        ``attachment_download`` row in the tamper-evident chain, docs/PHI.md §6) BEFORE the bytes leave.
        The document bytes/base64 are **never logged**."""
        row = await engine.store.get_message(message_id)
        # 404 (not 403) outside the caller's channel scope — don't reveal a message in another tenant's
        # channel (per-channel RBAC), mirroring get_message.
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")
        # SECURITY CRUX: only serve an attachment that is LINKED to this message. Content-addressing
        # shares one physical blob across messages/tenants, so the linkage + the channel guard above are
        # what scope access — a guessed content address unlinked to an in-scope message is a 404.
        linked = await engine.store.attachments_for(message_id)
        match = next((a for a in linked if a["attachment_id"] == attachment_id), None)
        if match is None:
            raise HTTPException(404, f"no such attachment for message: {attachment_id}")
        # Reconstruct the verbatim base64 (Approach B) then base64-decode ONCE to the original document
        # bytes. read_attachment raises KeyError only on a corrupt/GC'd blob a live linkage points at.
        try:
            verbatim = "".join(
                [chunk async for chunk in engine.store.read_attachment(attachment_id)]
            )
        except KeyError as exc:
            raise HTTPException(404, f"attachment content unavailable: {attachment_id}") from exc
        try:
            body = base64.b64decode("".join(verbatim.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            # A stored value that isn't clean base64 is corruption — surface it, never the bytes.
            raise HTTPException(422, "attachment content is not decodable") from exc
        # Audit the PHI access BEFORE the bytes leave: record_view for the per-message timeline +
        # attachment_download in the tamper-evident chain (with the acting user + the id pair, NO bytes).
        await engine.store.record_view(message_id, actor=identity.username)
        await engine.store.record_audit(
            "attachment_download",
            actor=identity.username,
            channel_id=row["channel_id"],
            detail=json.dumps({"message_id": message_id, "attachment_id": attachment_id}),
        )
        content_type = _safe_attachment_content_type(match["content_type"])
        filename = _attachment_filename(attachment_id, content_type)
        return Response(
            content=body,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

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

    @app.post("/messages/{message_id}/resend", response_model=ResendResult)
    async def resend_message(
        message_id: str,
        body: ResendRequest,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_RESEND)),
    ) -> ResendResult:
        """Resend a stored message's transformed body to an ALTERNATE outbound connection (ADR 0090,
        BACKLOG #123). Ships exactly what we sent (the retained transformed body) — never a re-run
        transform. Requires ``MESSAGES_RESEND`` step-up **and** per-channel access to BOTH the origin's
        channel AND the alternate outbound's channel, so PHI can't be diverted to a partner the caller
        otherwise can't reach. The alternate outbound must be a registered, owned-by-this-shard, running
        connection. Audited (``message.resend``, actor + from→to) — never the body."""
        row = await engine.store.get_message(message_id)
        # 404 (not 403) outside the caller's channel scope — don't reveal a message in another tenant's
        # channel (mirrors replay/get_message).
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")
        # Cross-channel authorization: the caller must ALSO be scoped to the alternate outbound (its name
        # is treated as a channel for per-channel RBAC), so a channel-scoped operator cannot push PHI to
        # an outbound they can't reach. 403 (not 404) — the message IS visible; the target is denied.
        if not identity.can_access_channel(body.to):
            await _audit_channel_denied(engine, identity, body.to)
            raise HTTPException(403, f"not authorized to resend to outbound {body.to!r}")
        # Target validation (must-fix #7): registered + owned-by-this-shard + running, else the row would
        # sit permanently pending (a silent drop).
        rr = engine.registry_runner
        if rr is None or body.to not in rr.registry.outbound:
            raise HTTPException(404, f"no such outbound connection: {body.to}")
        owner = rr.destination_owner(body.to)
        if owner is not None and owner != rr.registry.shard_id:
            raise HTTPException(
                409,
                f"outbound {body.to!r} is owned by engine shard {owner!r} — resend on that shard's API",
            )
        try:
            if not rr.outbound_running(body.to):
                raise HTTPException(
                    409, f"outbound {body.to!r} is not running — start it before resending"
                )
        except KeyError:  # neither declared nor draining (mirrors the control handlers)
            raise HTTPException(404, f"no such outbound connection: {body.to}") from None
        try:
            outcome = await engine.resend(
                message_id, to=body.to, idempotency_key=body.idempotency_key, source=body.source
            )
        except ResendError as exc:
            # No delivered source body / retention-nulled body / ambiguous source / idempotency-key
            # reused for a different message-or-target → 409 (ADR 0090 §4/§5/§7).
            raise HTTPException(409, str(exc)) from None
        # An actual re-transmission of PHI to a new partner: attribute it (from→to), NEVER the body.
        if outcome.status == "resent":
            await engine.store.record_audit(
                "message_resend",
                actor=identity.username,
                channel_id=row["channel_id"],
                detail=json.dumps(
                    {
                        "message_id": message_id,
                        "from": outcome.from_destination,
                        "to": outcome.to_destination,
                        "outbox_id": outcome.outbox_id,
                    }
                ),
            )
        return ResendResult(
            message_id=message_id,
            status=outcome.status,
            to=outcome.to_destination,
            source=outcome.from_destination,
            outbox_id=outcome.outbox_id,
        )

    @app.post("/messages/{message_id}/edit-resend", response_model=EditResendResult)
    async def edit_resend_message(
        message_id: str,
        body: EditResendRequest,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_EDIT)),
    ) -> EditResendResult:
        """Edit a stored message and resubmit the EDITED body (ADR 0090 §9, BACKLOG #153). The edit is
        client-side + ephemeral (no server draft); this endpoint receives the final edited ``raw``. By
        default (``reroute``, no ``to``) it re-ingresses the edited body as a fresh, correlated
        ``RECEIVED`` message on the ORIGIN channel — the normal router→transform→outbound pipeline. With
        ``to`` set it delivers the edited body DIRECTLY to that alternate outbound (reusing #123's resend
        seam). The ORIGINAL message stays byte-identical (count-and-log) — the resubmit is a new,
        correlated message. Requires ``MESSAGES_EDIT`` step-up (implies ``MESSAGES_VIEW_RAW``); the direct
        path additionally requires access to the alternate outbound's channel. Audited
        (``message.edit_resend``, actor + original→new correlation) — NEVER the edited body."""
        row = await engine.store.get_message(message_id)
        # 404 (not 403) outside the caller's channel scope (mirrors resend/replay/get_message).
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"])
            raise HTTPException(404, f"no such message: {message_id}")

        if body.to is not None:
            # DIRECT power-path: deliver the edited body straight to an alternate outbound. Same cross-
            # channel authorization + target validation as #123's resend (registered/owned/running).
            if not identity.can_access_channel(body.to):
                await _audit_channel_denied(engine, identity, body.to)
                raise HTTPException(403, f"not authorized to resend to outbound {body.to!r}")
            rr = engine.registry_runner
            if rr is None or body.to not in rr.registry.outbound:
                raise HTTPException(404, f"no such outbound connection: {body.to}")
            owner = rr.destination_owner(body.to)
            if owner is not None and owner != rr.registry.shard_id:
                raise HTTPException(
                    409,
                    f"outbound {body.to!r} is owned by engine shard {owner!r} —"
                    " resend on that shard's API",
                )
            try:
                if not rr.outbound_running(body.to):
                    raise HTTPException(
                        409, f"outbound {body.to!r} is not running — start it before resending"
                    )
            except KeyError:
                raise HTTPException(404, f"no such outbound connection: {body.to}") from None
            try:
                direct = await engine.edit_resend_direct(
                    message_id, to=body.to, raw=body.raw, idempotency_key=body.idempotency_key
                )
            except ResendError as exc:
                # Empty edited body / idempotency-key reused for a different target → 409. str(exc)
                # carries ids only (never the body — the messages don't interpolate ``raw``).
                raise HTTPException(409, str(exc)) from None
            if direct.status == "resent":
                await engine.store.record_audit(
                    "message_edit_resend",
                    actor=identity.username,
                    channel_id=row["channel_id"],
                    detail=json.dumps(
                        {
                            "message_id": message_id,
                            "mode": "direct",
                            "to": direct.to_destination,
                            "outbox_id": direct.outbox_id,
                        }
                    ),
                )
            return EditResendResult(
                message_id=message_id,
                status=direct.status,
                reroute=False,
                to=direct.to_destination,
                outbox_id=direct.outbox_id,
            )

        # RE-ROUTE (default): re-ingress the edited body on the origin channel. `reroute` must be set
        # (guards against a request that supplied neither a target nor an explicit reroute intent).
        if not body.reroute:
            raise HTTPException(
                400,
                "set reroute=true to re-ingress on the origin channel, or provide a target 'to'",
            )
        try:
            outcome = await engine.edit_resend_reroute(
                message_id, raw=body.raw, idempotency_key=body.idempotency_key
            )
        except ResendError as exc:
            raise HTTPException(409, str(exc)) from None
        if outcome.status == "resubmitted":
            await engine.store.record_audit(
                "message_edit_resend",
                actor=identity.username,
                channel_id=row["channel_id"],
                detail=json.dumps(
                    {
                        "message_id": message_id,
                        "mode": "reroute",
                        "new_message_id": outcome.new_message_id,
                        "channel_id": outcome.channel_id,
                    }
                ),
            )
        return EditResendResult(
            message_id=message_id,
            status=outcome.status,
            reroute=True,
            new_message_id=outcome.new_message_id,
        )

    # --- stats ---------------------------------------------------------------

    @app.get("/stats", response_model=StatsResponse)
    async def stats(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> StatsResponse:
        # B11 (read-only, additive): the runner's empty-claim counters (idle-poll vs wake-fanout herd)
        # for the connection-scale harness. Default-zero when no runner is attached (graph-less engine).
        rr = engine.registry_runner
        ec = rr.empty_claims if rr is not None else None
        # Executor saturation (B11 wall #1): only populated when the harness installs the default-sized
        # boot-shim executor; None/absent otherwise, so production /stats is byte-identical.
        exec_depth, exec_busy = _executor_gauges(app)
        return StatsResponse(
            outbox_by_status=await engine.store.stats(),
            in_pipeline=await engine.store.in_pipeline_depth(),
            empty_claims=ec.total if ec is not None else 0,
            empty_claims_idle_poll=ec.idle_poll if ec is not None else 0,
            empty_claims_wake_fanout=ec.wake_fanout if ec is not None else 0,
            executor_queue_depth=exec_depth,
            executor_busy=exec_busy,
            # A1 live cost counters (read-only, additive). getattr-with-default so a backend without them
            # (or a future one) reports 0 rather than 500ing the stats read.
            committed_txns=getattr(engine.store, "committed_txns", 0),
            body_copies=getattr(engine.store, "body_copies", 0),
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

    # --- config provenance ---------------------------------------------------

    @app.get("/config/provenance", response_model=ConfigProvenance)
    async def config_provenance(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> ConfigProvenance:
        """Read-only provenance of the loaded config graph (ADR 0041 D1, item C): the content
        fingerprint + best-effort git commit captured at load, and whether the on-disk config has since
        DRIFTED. No PHI/secrets — a one-way hash + a commit sha; gated by ``monitoring:read`` like
        ``/status`` (no step-up). ``drift`` recomputes the on-disk fingerprint off the event loop and
        compares it to the loaded baseline; it degrades to clean when the baseline is missing or the
        config dir is unreadable, so a read never raises."""
        loaded = engine.loaded_config_fingerprint
        fp = loaded.get("fingerprint") if loaded else None
        if not isinstance(fp, str) or not fp:
            return ConfigProvenance(loaded=False)  # no graph loaded yet, or fingerprint unavailable
        drift = False
        target = engine.last_reload_dir or engine.config_dir
        if target is not None:
            try:
                current = await asyncio.to_thread(config_fingerprint_detail, target)
                drift = current.get("fingerprint") != fp
            except OSError:  # dir unreadable now — report clean rather than a false DRIFT alarm
                drift = False
        git_head = loaded.get("git_head") if loaded else None
        files = loaded.get("files") if loaded else None
        return ConfigProvenance(
            loaded=True,
            fingerprint=fp,
            git_head=git_head if isinstance(git_head, str) else None,
            files=files if isinstance(files, int) else None,
            drift=drift,
        )

    # --- engine + DB status --------------------------------------------------

    @app.get("/status", response_model=SystemStatus)
    async def system_status(
        request: Request,
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> SystemStatus:
        now = time.time()
        total = running = 0
        # Engine-wide KPI roll-up (#93): combined inbound + outbound endpoint counts with a
        # running/stopped breakdown (vs channels_*, which count inbound only).
        conn_total = conn_running = 0
        rr = engine.registry_runner
        if rr is not None:  # one "channel" per inbound connection
            total = len(rr.registry.inbound)
            running = sum(1 for name in rr.registry.inbound if rr.inbound_running(name))
            # outbound_running (not outbound_status) so the running/stopped split gates on the engine
            # actually running AND the lane not operator-paused — consistent with inbound_running's
            # actually-started semantics (outbound_status reports "running" for any non-paused lane even
            # before start, which would over-count a built-but-not-started runner).
            out_running = sum(1 for name in rr.registry.outbound if rr.outbound_running(name))
            conn_total = total + len(rr.registry.outbound)
            conn_running = running + out_running
        db = await engine.store.db_status()
        # Engine-wide msg/s: REUSE the recent_done rate window that already powers backlog_seconds — sum
        # every destination's completions in the last _RATE_WINDOW seconds, no second sampler. The view
        # is offset-adjusted (subtracts operator stats-resets) exactly like /connections.
        cm = await engine.connection_metrics_view(now=now, rate_window=_RATE_WINDOW)
        recent_done_total = sum(dm.recent_done for dm in cm.destinations.values())
        msgs_per_second = (recent_done_total / _RATE_WINDOW) if _RATE_WINDOW > 0 else 0.0
        kpis = EngineKpis(
            messages_total=db.messages,
            connections_total=conn_total,
            connections_running=conn_running,
            connections_stopped=conn_total - conn_running,
            messages_per_second=msgs_per_second,
        )
        # B11 connection-scale observability: the server-only connection-pool snapshot (acquire-wait
        # percentiles + size/idle occupancy). None on SQLite (no pool), so the payload is unchanged on
        # the default backend. Synchronous + cheap (cached counters + a histogram snapshot, no DB I/O).
        pool_status = engine.store.pool_status()
        pool = (
            PoolInfo(
                backend=pool_status.backend,
                max_size=pool_status.max_size,
                size=pool_status.size,
                idle=pool_status.idle,
                acquire_wait=PoolWaitInfo(
                    count=pool_status.acquire_wait.count,
                    p50_ms=pool_status.acquire_wait.p50_ms,
                    p95_ms=pool_status.acquire_wait.p95_ms,
                    p99_ms=pool_status.acquire_wait.p99_ms,
                    max_ms=pool_status.acquire_wait.max_ms,
                    mean_ms=pool_status.acquire_wait.mean_ms,
                ),
            )
            if pool_status is not None
            else None
        )
        # App-log disk metering (#50), alongside the DB metrics — only when a log dir is configured.
        # Run the blocking stat()s off the event loop (the DB metering is itself off-loop in the store);
        # None when stdout-only or the directory is unreadable, so /status never raises on it.
        logs = await asyncio.to_thread(_log_storage, getattr(request.app.state, "log_dir", None))
        # No-network version-update signal (#30, ADR 0026): the engine's latest local diff (version
        # strings only, no PHI). None when [update_check] is disabled / no pass has run — additive, so
        # the existing payload is unchanged when off.
        uc = engine.update_check_result
        update = (
            UpdateInfo(
                current_version=uc.current_version,
                pinned_version=uc.pinned_version,
                update_available=uc.update_available,
            )
            if uc is not None
            else None
        )
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
            kpis=kpis,
            db=DbInfo(
                path=db.path,
                size_bytes=db.size_bytes,
                disk_free_bytes=db.disk_free_bytes,
                journal_mode=db.journal_mode,
                messages=db.messages,
                events=db.events,
                audit=db.audit,
                synchronous=db.synchronous,
            ),
            logs=logs,
            update=update,
            pool=pool,
        )

    # --- attested service-to-service identity (ADR 0083, #200 activation) ----
    # The ONLY route authenticated by a verified mTLS client cert instead of a bearer token: it lets a
    # peer service confirm the principal its certificate maps to (a service-mesh "whoami"). It is
    # deliberately non-PHI and non-step-up — require_service_cert admits the cert-identity plane, which
    # carries no second factor and must never reach the interactive / PHI surface. Under stock uvicorn (no
    # mTLS + no cert-identity map) no cert ever surfaces, so this 401s: byte-identical to before.

    @app.get("/service/identity")
    async def service_identity(
        identity: Identity = Depends(require_service_cert(Permission.MONITORING_READ)),
    ) -> dict[str, object]:
        """Echo the MessageFoundry principal that this request's verified client certificate maps to
        (username + granted roles). Non-PHI, read-only; used by a peer service to confirm its cert-identity
        wiring end-to-end. Returns 401 when no mapped/verified client cert is presented (deny-by-default)."""
        return {
            "username": identity.username,
            "roles": sorted(role.value for role in identity.roles),
            "auth": "mtls-client-cert",
        }

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
                acquire_delay_seconds=m.acquire_delay_seconds,
                promotable=m.promotable,
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

    # --- third-tier DR standby (#61, ADR 0048) -------------------------------

    @app.get("/dr/status", response_model=DrStatus)
    async def dr_status(
        engine: Engine = Depends(_get_engine),
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> DrStatus:
        """This box's third-tier DR posture (#61, ADR 0048): whether it is a DR standby at all
        (``[dr].enabled``), whether it is currently serving under the DR run-profile, the priority
        threshold, and the activation mode (always ``manual`` this slice). Read-only — gated by
        ``monitoring:read`` (carries no PHI)."""
        dr = engine.dr_settings
        return DrStatus(
            enabled=dr.enabled,
            active=engine.dr_active,
            threshold=dr.priority_threshold.value,
            activation_mode=dr.activation_mode.value,
        )

    @app.get("/service/status", response_model=ServiceStatusInfo)
    async def service_status(
        request: Request,
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> ServiceStatusInfo:
        """The engine's own hosting-service (NSSM) run state (L6a, ADR 0065). Default OFF: when
        ``[service].report_status`` is false, no ``sc query`` runs and ``state='disabled'``. When on,
        runs a **read-only, unprivileged** ``sc query <validated name>`` **off the event loop** — no
        control, no path input, no shell, no elevation. Read-only, ``monitoring:read``; no PHI."""
        cfg: ServiceStatusSettings = (
            getattr(request.app.state, "service_settings", None) or ServiceStatusSettings()
        )
        if not cfg.report_status:
            return ServiceStatusInfo(enabled=False, state="disabled", service_name=cfg.service_name)
        state = await query_service_state(cfg.service_name)
        return ServiceStatusInfo(enabled=True, state=state, service_name=cfg.service_name)

    @app.post("/dr/activate", response_model=DrActionResult)
    async def dr_activate(
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.DR_OPERATE)),
        body: DrActivateRequest | None = Body(default=None),
    ) -> DrActionResult:
        """**Manually promote** this DR standby (#61, ADR 0048). Gated by the dedicated ``dr:operate``
        permission (held by ADMINISTRATOR — NOT a reuse of ``connections:control``) and audited (every
        action + every abort via ``auth/service.py``'s ``record_audit``). The fixed ordering is
        cold-seed restore-verify (**fail-closed** if the KeyProvider/DEK is unavailable at the DR site) →
        a new audit-chain segment → acquire-VIP-or-abort → serve under the DR run-profile. An optional
        ``{"archive": "<path>"}`` body overrides ``[dr].seed_archive`` (the runbook may pass the chosen
        #60 backup); ``{"dba_attests_restored": true}`` is the operator's per-activation attestation that
        the DBA restored the server-DB ``mefor`` database (REQUIRED on postgres/sqlserver, ignored on
        SQLite — BACKLOG #102). Aborts return a 4xx/5xx with the failing phase; the box stays passive."""
        coord = engine.dr_coordinator
        if coord is None:
            raise HTTPException(503, "this deployment is not a DR standby ([dr].enabled is false)")
        # BACKLOG #102: dba_attests_restored is the operator's explicit, per-activation attestation that
        # the server-DB 'mefor' database was restored (required on postgres/sqlserver, ignored on SQLite).
        archive = body.archive if body is not None else None
        dba_attests_restored = body.dba_attests_restored if body is not None else False
        try:
            result = await coord.activate(
                archive=archive,
                dba_attests_restored=dba_attests_restored,
                actor=identity.username,
            )
        except DrActivationError as exc:
            # The coordinator already recorded a dr_activation_aborted audit row. Map the failing phase
            # to an HTTP status: a missing/unverified seed or a not-this-box state is the client's input
            # (409/422); a key-unavailable / VIP-not-acquired / profile failure is an environment
            # condition (503 — retry once the cause is fixed). Never echo a body (the message is scrubbed).
            status_code = {"state": 409, "seed": 422}.get(exc.kind, 503)
            raise HTTPException(status_code, str(exc)) from exc
        return DrActionResult(
            action=result.action,
            active=result.active,
            threshold=result.threshold,
            archive=result.archive,
            verify_status=result.verify_status,
            seed_segment=result.seed_segment,
            vip_hook_ran=result.vip_hook_ran,
        )

    @app.post("/dr/release", response_model=DrActionResult)
    async def dr_release(
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.DR_OPERATE)),
    ) -> DrActionResult:
        """**Fail back** from this DR standby to the recovered primary (#61, ADR 0048) — drain-then-hand-
        back, gated by ``dr:operate`` and audited. Releases the VIP (the optional release hook / the
        passive LB returns it to the primary), unbinds all inbound listeners, and drains the staged queue
        to completion before returning success (no dual-accept window while the VIP moves). Cross-store
        reconciliation with the recovered primary is operator-verified per the runbook (the engine gives
        no cross-store loss/duplicate guarantee)."""
        coord = engine.dr_coordinator
        if coord is None:
            raise HTTPException(503, "this deployment is not a DR standby ([dr].enabled is false)")
        try:
            result = await coord.release(actor=identity.username)
        except DrActivationError as exc:
            raise HTTPException(503, str(exc)) from exc
        return DrActionResult(
            action=result.action,
            active=result.active,
            threshold=result.threshold,
            vip_hook_ran=result.vip_hook_ran,
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
        # Browser (same-origin mf_session cookie) OR native (Authorization header) auth (ADR 0065). A
        # browser cannot set the WS Authorization header, so a same-origin browser handshake
        # authenticates via the cookie (the web console's authorize_ui_ws — CSWSH-guarded by a same-
        # origin Origin check + SameSite=Strict), installed as the app.state.ui_ws_authorize hook in
        # the serve_ui path (Option B Phase 0). Absent (JSON-only) → only the native header path runs.
        # A native client sends no Origin, so even with the hook present it falls through to the header
        # path (authorize_ws) unchanged. `token` (cookie or header) backs the periodic revalidation.
        identity: Identity | None = None
        token: str | None = None
        ui_ws_authorize = getattr(websocket.app.state, "ui_ws_authorize", None)
        if ui_ws_authorize is not None:
            identity, token = await ui_ws_authorize(websocket, Permission.MONITORING_READ)
        if identity is None:
            identity = await authorize_ws(websocket, Permission.MONITORING_READ)
            token = ws_token(websocket)
        if identity is None:
            await websocket.close(code=1008)  # policy violation (unauthenticated/forbidden)
            return
        handshake_identity: Identity = identity  # non-None past the guard; used on the no-auth path
        engine_obj: Engine | None = getattr(websocket.app.state, "engine", None)
        if engine_obj is None:
            await websocket.close(code=1011)
            return
        state = websocket.app.state
        if getattr(state, "ws_count", 0) >= _MAX_WS_CONNECTIONS:
            await websocket.close(code=1013)  # try again later — too many live monitor sockets
            return
        auth: AuthService | None = getattr(state, "auth", None)
        # Server-rendered connections fragment for the browser dashboard, installed by the web console
        # in the serve_ui path. Absent → counts-only push (see the send loop below).
        ui_connections_render = getattr(state, "ui_connections_render", None)
        await websocket.accept()
        state.ws_count = getattr(state, "ws_count", 0) + 1

        async def _reauthorize() -> Identity | None:
            """Re-validate the open socket's session (revocation/expiry/disable/downgrade/password-
            change) WITHOUT resetting the idle clock, and return the CURRENT identity (or None → close).

            The enriched connections push is rendered with THIS identity, so a narrowed channel scope
            takes effect within one revalidation window — not only when the socket eventually drops.
            When no auth is enforced (embedding/dev), the handshake identity stands."""
            if auth is None or not auth.enabled:
                return handshake_identity
            # activity=False: this keepalive must not reset the session's idle clock.
            current = await auth.identity_for_token(token, activity=False)
            if (
                current is None
                or not current.has(Permission.MONITORING_READ)
                or current.must_change_password
            ):
                return None
            return current

        try:
            # Re-check BEFORE the first push: a token revoked between the handshake authorize and
            # accept() must not get even one frame (close the pre-first-send window — SEC-018).
            current = await _reauthorize()
            if current is None:
                await websocket.close(code=1008)
                return
            last_revalidate = time.monotonic()
            while True:
                # Enriched push for the browser dashboard (ADR 0065 M-ws follow-up): the queue-by-status
                # counts PLUS the SERVER-RENDERED, already-escaped connections fragment, so the /ui table
                # updates live over the socket (the client swaps it in and stops polling; the poll is the
                # fallback if the socket drops). Rendering server-side reuses the same escaping as the
                # poll path — no client-side table building, no XSS. connections_html is scoped to the
                # CURRENT (revalidated) identity's per-channel RBAC — a narrowed scope is reflected within
                # one revalidation window; a native client that only reads outbox_by_status ignores it.
                # The counts frame is built unconditionally; connections_html is attached only when the
                # web console's render hook (app.state.ui_connections_render) is installed (serve_ui on,
                # Option B Phase 0). Absent (JSON-only) → a counts-only push, native clients unaffected.
                frame: dict[str, Any] = {"outbox_by_status": await engine_obj.store.stats()}
                if ui_connections_render is not None:
                    rows = await list_connections(engine=engine_obj, identity=current)
                    frame["connections_html"] = str(ui_connections_render(rows))
                await websocket.send_json(frame)
                await asyncio.sleep(1.0)
                # Revalidate on an elapsed-time cadence (independent of the per-second send), so a
                # revoked/downgraded token stops streaming (and a narrowed scope takes effect) within
                # ~_WS_REVALIDATE_SECONDS.
                if time.monotonic() - last_revalidate >= _WS_REVALIDATE_SECONDS:
                    last_revalidate = time.monotonic()
                    current = await _reauthorize()
                    if current is None:
                        await websocket.close(code=1008)
                        return
        except WebSocketDisconnect:
            return
        finally:
            state.ws_count = max(0, getattr(state, "ws_count", 1) - 1)

    # --- /ui: read-only browser ops dashboard (ADR 0065, BACKLOG #75) ----------
    # Registered ONLY when [api].serve_ui is on (a JSON-only deployment is byte-identical otherwise).
    # The web console — its /ui routes, rendering, the confined mf_session cookie auth, and the write-
    # action registry — lives in the separately-versioned messagefoundry_webconsole package, mounted
    # same-origin in-process via one mount_ui(app, deps) call (Option B, ADR 0065). The /ui routes are
    # CLIENTS of the JSON handlers above — mount_ui wires them to the reused handlers through the typed
    # UiDeps bundle, so the single audited PHI path + per-channel RBAC + view_summary redaction are
    # reused verbatim (no second PHI path). serve_ui-off deployments never import the package.
    if serve_ui:
        # GUARDED import (Option B): the web console is an optional package, so the engine imports +
        # boots + serves the JSON API without it. It is required only when serve_ui is on, and a missing
        # install fails LOUD at startup here — never a mid-request 500. (The absent path is exercised by
        # tests/test_webconsole_absent.py, which shadows the import.)
        try:
            from messagefoundry_webconsole import assert_engine_seam, mount_ui
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "serve_ui requires the web console — install it: "
                "pip install messagefoundry[webconsole]"
            ) from exc

        # Assert the seam BEFORE building the deps bundle (review fix): a package that changed the
        # UiDeps/CoreHandlers shape for a new seam would otherwise trip at construction with a raw
        # kwargs TypeError; this raises a clear UiSeamMismatch first.
        assert_engine_seam(ENGINE_UI_SEAM)
        deps = UiDeps(
            engine_seam=ENGINE_UI_SEAM,
            get_engine=_get_engine,
            get_gate=_get_gate,
            cookie_secure=_cookie_secure,
            default_scan_limit=DEFAULT_CONTENT_SCAN_LIMIT,
            core=CoreHandlers(
                list_connections=list_connections,
                list_messages=list_messages,
                get_message=get_message,
                download_attachment=download_attachment,
                list_dead_letters=list_dead_letters,
                start_connection=start_connection,
                stop_connection=stop_connection,
                restart_connection=restart_connection,
                replay_message=replay_message,
                edit_resend_message=edit_resend_message,
                replay_dead_letters=replay_dead_letters,
                list_active_alerts=list_active_alerts,
                alerts_rules=alerts_rules,
                list_connection_events=list_connection_events,
                system_status=system_status,
                security_posture=security_posture,
                cluster_status=cluster_status,
                cluster_nodes=cluster_nodes,
                dr_status=dr_status,
                service_status=service_status,
                ack_alert=ack_alert,
                resolve_alert=resolve_alert,
                reset_statistics=reset_statistics,
                integrity_check=integrity_check,
                dr_activate=dr_activate,
                dr_release=dr_release,
                dual_role_control=_dual_role_control,
                purge_connection=purge_connection,
                config_provenance=config_provenance,
                reload_config=reload_config,
                search_messages=search_messages,
                audit_channel_denied=_audit_channel_denied,
            ),
            admin=admin,
        )
        mount_ui(app, deps)

    return app


def _emit_bootstrap_admin(bootstrap: BootstrapAdmin, store_settings: StoreSettings) -> None:
    """Persist the one-time bootstrap password to a restricted file — never the rotating log.

    Until rotated it is a standing Administrator credential, so it must not land in NSSM's broadly
    readable stdout capture. Write it to an owner-only file the operator consumes and deletes; log
    only the location. Paired with server-side must_change_password enforcement, it dies at first login.
    """
    base = Path(store_settings.path or ".").resolve()
    secret_file = base.parent / "bootstrap-admin.txt"
    body = f"username: {bootstrap.username}\npassword: {bootstrap.password}\n"
    # Create the file owner-only from the instant it exists, closing the POSIX create-then-chmod TOCTOU
    # (SEC-020): O_EXCL + 0o600 means the secret is never group/world-readable even momentarily, and
    # O_EXCL also refuses to follow a pre-planted symlink/file at that path. A second service start
    # before the operator deletes the prior file would hit FileExistsError — remove the stale file we
    # own, then re-create exclusively.
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_TRUNC
    try:
        fd = os.open(str(secret_file), flags, 0o600)
    except FileExistsError:
        secret_file.unlink()  # the prior owner-only file we wrote; replace it under the same mode
        fd = os.open(str(secret_file), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    # On Windows os.open's mode is minimal, so still apply the icacls owner-only DACL (the store's
    # platform-correct primitive: chmod on POSIX is a no-op here since O_EXCL already set 0o600).
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
    stall_default: StallThreshold | None = None,
    saturation_default: SaturationThreshold | None = None,
    ack_after_default: AckAfter | None = None,
    stream_inflight_budget_bytes: int = 0,  # #149 ADR 0105: [inbound].stream_inflight_budget_bytes
    max_correlation_depth: int = 8,
    per_lane_wake: bool = False,  # B12 (ADR 0061): per-lane wake events; default-OFF singleton wake
    claim_mode: str = "pooled",  # ADR 0066/#744: "pooled" (default) | "per_lane" (byte-identical opt-out)
    pooled_claimers_per_stage: int = 1,
    pooled_sweep_interval: float = 0.25,
    pooled_claim_lane_chunk: int = 256,
    pooled_max_processing_lanes: int = 256,
    require_rcsi_for_pooled: bool = True,
    infra_fault_policy: str = "stop",  # ADR 0070: "stop" (default) | "retry_forever"
    infra_fault_stop_after: int = 10,
    infra_fault_backoff_cap: float = 60.0,
    credential_fault_policy: str = "stop",  # #109 (ADR 0095): "stop" (default) | "dead_letter"
    schedule_tick_seconds: float = 30.0,  # #147 (ADR 0095): active-window scheduler tick
    fuse_thread_hops: bool = False,  # ADR 0071 B5: SQL-Server-only thread-hop fusion (default-OFF)
    pooled_fusing_workers: int = 8,
    batch_handoff_statements: bool = False,  # ADR 0075: SQL-Server-only per-hop batching (default-OFF)
    snapshot_on_send: bool = False,  # ADR 0104: copy-on-Send at Send construction (default-OFF)
    connection_events: bool = True,
    response_sent_default: bool = True,
    message_events: str = "all",  # #63 [diagnostics].message_events verbosity → open_store
    env_values: Mapping[str, Any] | None = None,
    env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
    auth_settings: AuthSettings | None = None,
    ai_settings: AiSettings | None = None,
    alerts_settings: AlertsSettings | None = None,
    secrets_settings: SecretsSettings | None = None,
    priority_default: Priority | None = None,
    retention_settings: RetentionSettings | None = None,
    cert_monitor_settings: CertMonitorSettings | None = None,
    secret_rotation_settings: SecretRotationSettings | None = None,
    update_check_settings: UpdateCheckSettings | None = None,
    backup_settings: BackupSettings | None = None,
    dr_settings: DrSettings | None = None,
    api_tls_cert_file: str | None = None,
    api_listener: tuple[str, int] | None = None,
    reference_settings: ReferenceSettings | None = None,
    egress_settings: EgressSettings | None = None,
    tls_settings: TlsSettings | None = None,
    shadow_settings: ShadowSettings | None = None,
    sandbox_settings: SandboxSettings | None = None,
    cluster_settings: ClusterSettings | None = None,
    approvals_settings: ApprovalsSettings | None = None,
    integrity_settings: IntegritySettings | None = None,
    service_settings: ServiceStatusSettings | None = None,
    expose_docs: bool = False,
    ws_allowed_origins: Sequence[str] = (),
    serve_ui: bool = False,
    public_origin: str | None = None,
    webauthn_rp_from_request: bool = True,
    exposure_protected: bool = False,
    tls_terminated_upstream: bool = False,
    tls_client_cert_identities: Mapping[str, str] | None = None,
    registry_filter: Callable[[Registry], Registry] | None = None,
    log_dir: str | None = None,
) -> FastAPI:
    """Build an app that owns its engine for its whole lifespan (CLI server / sync tests).

    Pass ``store_settings`` for full backend selection (the service path), or ``db_path`` (+optional
    ``synchronous``) as a SQLite shortcut. ``config_dir`` loads the code-first Connection/Router/
    Handler graph. ``auth_settings`` (when enabled) attaches an :class:`AuthService`, seeds the
    built-in roles, and creates a bootstrap admin on first run. The store is opened via the
    backend-agnostic :func:`~messagefoundry.store.open_store`. ``api_listener`` is the engine's own
    ``(host, port)`` (from ``[api]``), reserved so no inbound listener can be wired onto the API's port
    — the CLI server passes it; in-process/test callers omit it (no separate API socket is bound).
    ``registry_filter`` (L3 sharding) is an optional pure transform applied to the loaded graph at
    startup AND on every reload — ``serve --shard X`` passes ``filter_registry_for_shard(.., X)`` so
    this process owns only shard X's inbounds; ``None`` = the whole graph (unchanged default).
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
        # B11 connection-scale measurement hook (harness-only, env-gated): when the harness sets the
        # gate env var, install a DEFAULT-SIZED instrumented ThreadPoolExecutor as the loop's default
        # executor so the route/transform to_thread pool's queue-depth/busy become observable on /stats
        # WITHOUT changing capacity. A no-op returning None in production / every other test, so the
        # engine is byte-identical when the gate is unset. Stashed for /stats + shut down in finally.
        app.state.connscale_executor = maybe_install_executor_shim(asyncio.get_running_loop())
        # #200 (ADR 0092 decision 2): thread the derived instance posture so the engine<->store weakened-
        # TLS refusal (connection_string / _build_ssl) clamps MEFOR_ALLOW_INSECURE_TLS — the escape can
        # never relax a production-PHI store hop. None when no [ai] (SQLite/test) → unclamped, unchanged.
        store = await open_store(
            resolved,
            message_events=message_events,
            posture=hop_posture_from_ai(ai_settings) if ai_settings else None,
        )
        # Operational alert notifier (webhook/email). None when no transport is configured → the
        # engine falls back to the logging sink. Its background dispatch task is owned by this
        # lifespan: started here, drained + stopped after the engine in the finally below.
        # Connector SecretProvider (ADR 0019 §5, BACKLOG #196): built once from [secrets] and threaded to
        # every credential point (SMTP password → notifier/security-notifier, AD bind password →
        # AuthService). None = [secrets].provider unset/'none' → env-sourced credentials, byte-identical.
        # An unknown provider / missing extra fails closed HERE (resolve_secret_provider raises), refusing
        # startup rather than degrading to a blank credential.
        secret_provider = (
            resolve_secret_provider(secrets_settings) if secrets_settings is not None else None
        )
        notifier = (
            notifier_from_settings(alerts_settings, secret_provider=secret_provider)
            if alerts_settings is not None
            else None
        )
        if notifier is not None:
            # Durable operator alert-state (ADR 0044, #56): wire the open store so every emit upserts a
            # resolvable alert instance (GET /alerts/active) and an inverse signal auto-resolves it. A
            # pure side observer off the emit path — never gates a disposition, never blocks a worker.
            notifier.set_store(store)
            notifier.start()
        # Startup self-attestation of the installed engine wheel (ADR 0041 D3) — runs BEFORE the engine
        # binds listeners. On drift it records a hash-chained `startup_integrity` audit row + alerts;
        # under [integrity].fail_closed_on_drift it raises IntegrityError here (refusing to start) so
        # the store is closed in the except below and no listener ever binds. A no-op off an editable
        # install (no RECORD baseline), so dev is never bricked. Off only if [integrity].enabled=false.
        integ = integrity_settings or IntegritySettings()
        if integ.enabled:
            try:
                await run_startup_attestation(
                    store,
                    notifier or LoggingAlertSink(),
                    fail_closed_on_drift=integ.fail_closed_on_drift,
                )
            except BaseException:
                # Fail-closed drift (or an unexpected error) before the engine starts: tear down what we
                # already brought up (the notifier task + the open store) so we don't leak them, then
                # re-raise to abort the lifespan startup (uvicorn exits non-zero).
                if notifier is not None:
                    await notifier.aclose()
                await store.close()
                raise
        # Cluster coordinator (Track B Step 3) — built from the opened store so a Postgres-backed
        # store can reach its pool. Returns the no-op NullCoordinator unless [cluster].enabled on a
        # Postgres store, so single-node is byte-identical. The Engine owns its lifecycle (start/stop
        # in engine.start()/stop()), so the lifespan only constructs + passes it here.
        coordinator = build_coordinator(store, cluster_settings)
        engine = Engine(
            store,
            poll_interval=poll_interval,
            max_correlation_depth=max_correlation_depth,
            per_lane_wake=per_lane_wake,
            claim_mode=claim_mode,
            pooled_claimers_per_stage=pooled_claimers_per_stage,
            pooled_sweep_interval=pooled_sweep_interval,
            pooled_claim_lane_chunk=pooled_claim_lane_chunk,
            pooled_max_processing_lanes=pooled_max_processing_lanes,
            require_rcsi_for_pooled=require_rcsi_for_pooled,
            infra_fault_policy=infra_fault_policy,
            infra_fault_stop_after=infra_fault_stop_after,
            infra_fault_backoff_cap=infra_fault_backoff_cap,
            credential_fault_policy=credential_fault_policy,
            schedule_tick_seconds=schedule_tick_seconds,
            fuse_thread_hops=fuse_thread_hops,
            pooled_fusing_workers=pooled_fusing_workers,
            batch_handoff_statements=batch_handoff_statements,
            snapshot_on_send=snapshot_on_send,
            connection_events=connection_events,
            response_sent_default=response_sent_default,
            audit_verify_on_start=integ.audit_verify_on_start,
            config_dir=config_dir,
            config_reload_roots=config_reload_roots,
            inbound_bind_host=inbound_bind_host,
            allow_insecure_bind=allow_insecure_bind,
            delivery_defaults=delivery_defaults,
            ordering_default=ordering_default,
            internal_error_default=internal_error_default,
            buildup_default=buildup_default,
            stall_default=stall_default,
            saturation_default=saturation_default,
            ack_after_default=ack_after_default,
            stream_inflight_budget_bytes=stream_inflight_budget_bytes,
            priority_default=priority_default,
            alert_sink=notifier,
            retention_settings=retention_settings,
            # [logging].log_dir for application-log-file retention (#120) in the RetentionRunner.
            log_dir=log_dir,
            cert_monitor_settings=cert_monitor_settings,
            secret_rotation_settings=secret_rotation_settings,
            update_check_settings=update_check_settings,
            backup_settings=backup_settings,
            # [dr] third-tier DR standby run-profile + cold-seed (#61, ADR 0048). When dr.enabled AND
            # dr.activate, the engine binds only connections at/above dr.priority_threshold this boot.
            dr_settings=dr_settings,
            # [backup] DR archive is encrypted under the store DEK (its KEY SOURCE) and bundles the
            # config dir; pass the resolved store settings (the KeyProvider seam) + version metadata.
            store_settings=resolved,
            engine_version=__version__,
            api_tls_cert_file=api_tls_cert_file,
            api_listener=api_listener,
            reference_settings=reference_settings,
            egress_settings=egress_settings,
            # #200 (ADR 0092): the derived (PHI? production?) posture the connector-construction gate keys
            # its posture-keyed insecure-hop refusal on. Derived from [ai] here (the one place ai_settings
            # is in scope) so every runner this engine builds refuses/warns identically. None when the
            # instance declares no [ai] (test/embedding) — a cell then fail-closes.
            hop_posture=hop_posture_from_ai(ai_settings) if ai_settings else None,
            # #190 (ADR 0093): the [tls] client trust-anchor policy (internal-CA fallback for internal
            # outbound hops). None ([tls] unset) → the default system/no-op policy (byte-identical).
            trust_anchor_policy=tls_settings.policy() if tls_settings else None,
            shadow_settings=shadow_settings,
            sandbox_settings=sandbox_settings,
            active_environment=ai_settings.environment if ai_settings else None,
            env_values=env_values,
            env_values_provider=env_values_provider,
            coordinator=coordinator,
            cluster_settings=cluster_settings,
            registry_filter=registry_filter,
        )
        if config_dir is not None:
            loaded = load_config(config_dir)
            # L3 sharding: a `serve --shard X` process owns only shard X's inbounds (the filter is
            # re-applied on every reload inside the engine). None = the whole graph (unchanged default).
            if registry_filter is not None:
                loaded = registry_filter(loaded)
            engine.add_registry(loaded)
        await engine.start()
        app.state.engine = engine
        app.state.store_settings = resolved  # back GET /security/posture (M5)
        app.state.alerts_settings = alerts_settings
        app.state.service_settings = service_settings  # back GET /service/status (L6a)
        app.state.log_dir = log_dir  # back GET /status app-log metering (#50)
        app.state.approval_gate = _build_approval_gate(
            engine, approvals_settings or ApprovalsSettings()
        )
        reaper: asyncio.Task[None] | None = None
        security_notifier = None
        if auth_settings is not None and auth_settings.enabled:
            # Out-of-band security-event push (#188, ASVS 6.3.5/6.3.7) — reuses the [alerts] SMTP
            # transport, sent to each affected user's own address. The notifier is wired only when the
            # [auth].notify_security_events kill-switch is on AND a transport can be built (SMTP
            # configured): security_notifier_from_settings returns None when SMTP is unset, so we never
            # fabricate a transport — then only the audited /me/security-events pull feed records events.
            # The effective-by-default guarantee (an exposed PHI instance MUST have a real push channel,
            # or opt out in writing via [alerts].security_notifications_required) is enforced fail-closed
            # at startup by the serve gate (messagefoundry/__main__.py), which checks these SAME two
            # conditions — not here. This task is owned by the lifespan (started here, drained + closed
            # after the engine in the finally below).
            if auth_settings.notify_security_events and alerts_settings is not None:
                security_notifier = security_notifier_from_settings(
                    alerts_settings, secret_provider=secret_provider
                )
                if security_notifier is not None:
                    security_notifier.start()
            auth = AuthService(
                store,
                auth_settings,
                security_notifier=security_notifier,
                secret_provider=secret_provider,
            )
            bootstrap = await auth.initialize()
            app.state.auth = auth
            if bootstrap is not None:
                _emit_bootstrap_admin(bootstrap, resolved)
            if not auth.webauthn_available() and await store.any_webauthn_credentials():
                # L5b (ADR 0068 decision 5): enrolled passkeys exist but the [webauthn] extra is
                # not installed (engine moved/reinstalled, same DB) — affected users stay
                # MFA-required while every assertion path is unavailable. The reauth page renders
                # a legible notice; this is the loud operator-facing half.
                _log.warning(
                    "WebAuthn passkeys are enrolled in this store but the [webauthn] extra is "
                    "NOT installed — affected users cannot complete passkey step-up on this "
                    "install. pip install messagefoundry[webauthn], or clear a stranded user's "
                    "factors with POST /users/{id}/reset-mfa (admin_reset_mfa)."
                )
            if auth.kerberos_enabled:
                # L5c (ADR 0068 §9): boot-once SPNEGO acceptor preflight — a missing keytab/SPN
                # credential degrades browser SSO legibly (providers kerberos=false, the login
                # link hidden, /ui/sso -> e=sso_unavailable) instead of failing per-request. The
                # JSON /auth/negotiate deliberately keeps its per-request attempt (additive-only).
                from messagefoundry.auth.ldap import LdapError, kerberos_acceptor_preflight

                try:
                    await asyncio.to_thread(kerberos_acceptor_preflight, auth_settings)
                except LdapError as exc:
                    _log.warning(
                        "Kerberos SSO acceptor preflight failed — browser SSO is disabled until "
                        "restart (the JSON /auth/negotiate still attempts per-request). Check the "
                        "HTTP/<fqdn> SPN + keytab/service identity (see "
                        "docs/security/OFF-LOOPBACK-DEPLOYMENT.md): %s",
                        exc,
                    )
                    auth.mark_kerberos_unavailable(str(exc))
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
            # B11: shut down the harness-only instrumented executor (None in production / other tests).
            # The engine is stopped (no more to_thread work), so a non-blocking shutdown is clean.
            shim_executor = getattr(app.state, "connscale_executor", None)
            if shim_executor is not None:
                shim_executor.shutdown(wait=False)
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
        serve_ui=serve_ui,
        public_origin=public_origin,
        webauthn_rp_from_request=webauthn_rp_from_request,
        exposure_protected=exposure_protected,
        tls_terminated_upstream=tls_terminated_upstream,
        tls_client_cert_identities=tls_client_cert_identities,
    )
