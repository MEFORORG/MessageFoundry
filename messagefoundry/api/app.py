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
import datetime
import json
import logging
import mimetypes
import os
import re
import shutil
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

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
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from messagefoundry import __version__
from messagefoundry.api._ui_seam import ENGINE_UI_SEAM, CoreHandlers, UiDeps
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.api.auth_routes import add_auth_routes
from messagefoundry.api.client_networks import ClientNetworkMiddleware
from messagefoundry.api.field_authz import count_exposed, redact_unauthorized
from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    HSTS_HEADER,
    HSTS_VALUE,
    SecurityHeaderFloorMiddleware,
    hsts_applies,
)
from messagefoundry.api.metrics import (
    METRICS_CONTENT_TYPE,
    MetricsHistory,
    render_metrics,
)
from messagefoundry.api.models import (
    AiChatRequest,
    AiChatResponse,
    AiPolicy,
    AlertInstanceInfo,
    AlertInstanceList,
    AlertRuleInfo,
    AlertsConfig,
    AlertSuspendRequest,
    AlertTestEmailRequest,
    AlertTestEmailResult,
    ApprovalDecisionResult,
    ApprovalList,
    AttachmentInfo,
    CapturedResponseInfo,
    ChannelInfo,
    ClaimPoolInfo,
    ClaimProcInfo,
    ClusterNode,
    ClusterNodeList,
    ClusterStatus,
    ConfigProvenance,
    ConnectionEventInfo,
    ConnectionFlagRequest,
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
    EditResendRequest,
    EditResendResult,
    EngineInfo,
    EngineKpis,
    EventInfo,
    GraphEdge,
    GraphNode,
    GraphResponse,
    Health,
    IntegrityResult,
    LogInfo,
    LogLevelInfo,
    LogLevelUpdate,
    LogTailPage,
    MessageDetail,
    MessageList,
    MessageResponses,
    MessageSearchResults,
    MessageSummary,
    MetricsHistoryResponse,
    MetricsHistorySample,
    OutboundPayloadInfo,
    OutboundPayloads,
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
    SearchPresetCreateRequest,
    SearchPresetCreateResult,
    SearchPresetDeleteResult,
    SearchPresetInfo,
    SearchPresetList,
    SecurityLoosening,
    SecurityPosture,
    ServiceStatusInfo,
    StatsResetRequest,
    StatsResetResult,
    StatsResponse,
    SystemStatus,
    UpdateInfo,
    UploadDeleteResult,
    UploadedFileInfo,
    UploadedFileList,
    UploadedMessagesResult,
    UploadedMessageSummary,
    UploadResendRequest,
    UploadResendResult,
)
from messagefoundry.api.multipart import (
    MultipartError,
    MultipartTooLargeError,
    parse_single_file_upload,
)
from messagefoundry.api.request_timeout import RequestTimeoutMiddleware
from messagefoundry.api.security import (
    authorize_ws,
    client_ip,
    enforce_phi_read_hop,
    enforce_phi_read_pacing,
    optional_identity,
    require,
    require_paced,
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
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.service import AuthService, BootstrapAdmin
from messagefoundry.auth.trust_anchors import (
    AnchorSpec,
    TrustAnchorError,
    run_anchor_preflight,
)
from messagefoundry.config.ai_policy import (
    AiDataScope,
    AiMode,
    DataClass,
    resolve_effective_policy,
)
from messagefoundry.config.connections_file import CONNECTIONS_FILE_NAME
from messagefoundry.config.fingerprint import config_fingerprint_detail
from messagefoundry.config.memory_encryption import (
    READOUT_DISCLAIMER,
    platform_memory_encryption_readout,
)
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    ConnectorType,
    InternalErrorPolicy,
    OrderingMode,
    Priority,
    RetryPolicy,
    SaturationThreshold,
    StallThreshold,
)
from messagefoundry.config.secretprovider import (
    resolve_connector_secret,
    resolve_secret_provider,
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
    SecurityEnforcement,
    SecuritySettings,
    ServiceStatusSettings,
    ShadowSettings,
    StoreBackend,
    StoreSettings,
    TlsSettings,
    UpdateCheckSettings,
    hop_insecure_escape_downgrades,
    hop_posture_from_ai,
    security_loosenings,
)
from messagefoundry.config.tls_policy import (
    fips_attestation,
    kex_groups_report,
    phi_read_hop_disposition,
)
from messagefoundry.config.wiring import (
    EnvRef,
    Registry,
    WiringError,
    accepted_cleartext_hops,
    expiry_relaxed_hops,
    load_config,
    redacted_settings,
    unverified_generic_db_hops,
)
from messagefoundry.integrity import run_startup_attestation
from messagefoundry.last_resort import install_loop_exception_handler
from messagefoundry.logging_setup import LOG_LEVELS, current_log_level, set_runtime_level
from messagefoundry.parsing.sniff import attachment_mime_agrees, nontext_upload_reason
from messagefoundry.pipeline import ConfigReloadDenied, Engine
from messagefoundry.pipeline.alert_sinks import EmailTransport, notifier_from_settings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import build_coordinator
from messagefoundry.pipeline.connscale_shim import maybe_install_executor_shim
from messagefoundry.pipeline.dr import DrActivationError
from messagefoundry.pipeline.security_notify import security_notifier_from_settings
from messagefoundry.pipeline.wiring_runner import (
    NotDeployedError,
    RegistryRunner,
    ShardLaneOwnershipError,
)
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.service_status import query_service_state
from messagefoundry.store import Row, open_store, sqlite_settings
from messagefoundry.store.base import ResendError, Store, build_store_cipher
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
from messagefoundry.store.metadata import user_metadata
from messagefoundry.store.store import _secure_file
from messagefoundry.transports.ai_broker import AiBrokerError, ai_broker_from_settings
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    TestNotSupportedError,
)
from messagefoundry.uploads import (
    UploadContentError,
    UploadedFileMeta,
    UploadNotFoundError,
    UploadPathError,
    UploadQuotaError,
    UploadRetentionRunner,
    UploadStore,
    UploadTooLargeError,
    browse_messages,
    sanitize_filename,
    split_uploaded,
)

__all__ = ["create_app", "create_managed_app"]

_RATE_WINDOW = 60.0  # seconds; window for the backlog throughput estimate
_MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB cap on HTTP request bodies (API-INPUT)
# The uploaded-logs upload routes (ADR 0134) carry a whole diagnostic file, so the 1 MiB body cap is
# raised to [store].max_upload_bytes for these paths ONLY (every other route stays at 1 MiB). Both the
# JSON-API path and the same-origin /ui path route through this one middleware.
_UPLOAD_BODY_PATHS = frozenset({"/uploads", "/ui/uploaded-logs/upload"})
# The most saved presets a single layered query may AND-compose (ADR 0136, BACKLOG #151). Bounds the
# per-preset decrypt loop + keeps the composition tractable.
_MAX_PRESET_LAYERS = 8
_CONNECTION_TEST_TIMEOUT = 35.0  # overall cap for a POST /connections/{name}/test probe (seconds)
_MAX_WS_CONNECTIONS = 64  # cap concurrent /ws/stats sockets (API-WS)
_WS_REVALIDATE_SECONDS = 3.0  # re-check the session on an open /ws/stats this often (API-WS)
#: Path prefixes whose JSON responses are served ``Cache-Control: no-store`` (ASVS 14.2.2). These are
#: the PHI-read route families — every route gated by ``require_phi_read`` and every step-up GET that
#: charges the PHI-read hop/pacing budget lives under one of them, so a browser, a proxy or any other
#: intermediary is directed never to retain a message body, a search hit, a log line or an uploaded
#: file's split messages. It is a PREFIX set on purpose: it covers a family's future members (the three
#: routes this closed — ``/search/layered``, ``/logs/tail``, ``/uploads/{file_id}/messages`` — each
#: shipped as a new member of a family whose siblings were already covered), and
#: ``tests/test_no_store_phi_coverage.py`` walks ``app.routes`` and fails if a PHI read ever lands
#: outside it. Non-GET routes under these prefixes pick the header up too, which is harmless.
#: The ``/ui`` HTML surface is covered by its own branch in the middleware below.
_NO_STORE_PREFIXES = ("/messages", "/dead-letters", "/search", "/logs", "/uploads")
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


def _is_toml_managed(source_file: str | None) -> bool:
    """Whether a connection was authored in ``connections.toml`` (vs a code-first ``.py``), from its
    registry ``source_file`` (#131). The console shows the flag TOGGLE only on a TOML-managed row; the
    API's flag write refuses a non-TOML connection regardless (the guard of record)."""
    return source_file is not None and source_file.endswith(CONNECTIONS_FILE_NAME)


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


def _read_log_tail(log_dir: str | None, *, limit: int, offset: int) -> tuple[list[str], int, bool]:
    """A **redacted** page of the newest app-log file's tail for the in-console viewer (#171, ADR 0130).

    Returns ``(redacted_lines, total_lines, available)``. ``offset`` counts lines back from the END of the
    newest ``.log``/``.txt`` file (``offset=0`` = the most recent ``limit`` lines); the page is returned in
    file order (oldest-first within the window). Every line is passed through
    :func:`~messagefoundry.support.redact.redact_log_line` — the SAME redactor the support bundle uses — so
    the browser sees identical PHI/secret coverage; the redaction is best-effort (a residual single-token
    identifier can survive), which is why the route is RBAC-gated + audited. ``available`` is False when no
    ``[logging].log_dir`` is configured or no readable log file exists, so ``/logs/tail`` degrades
    gracefully. **Blocking** (a file read + redaction pass) — the caller runs it off the event loop — and
    **never raises** (an unreadable dir/file yields an empty, unavailable page)."""
    from messagefoundry.support.redact import redact_log_line

    if not log_dir:
        return [], 0, False
    directory = Path(log_dir)
    try:
        files = [p for p in directory.iterdir() if p.is_file() and p.suffix in (".log", ".txt")]
    except OSError:
        return [], 0, False
    if not files:
        return [], 0, False
    try:
        newest = max(files, key=lambda p: p.stat().st_mtime)
        # Tolerant decode of a legacy codepage; redaction runs on the decoded text.
        text = newest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], 0, False
    all_lines = text.splitlines()
    total = len(all_lines)
    end = max(0, total - offset)  # exclusive upper bound of this page (from the end)
    start = max(0, end - limit)
    page = all_lines[start:end]
    return [redact_log_line(line) for line in page], total, True


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
        # a failure should NOT raise. (Since ASVS 2.3.3 the gate compensates a raise by rolling the row
        # to 'failed' and auditing it, so a raise no longer strands it approved-but-unexecuted; skipping
        # is still the better outcome HERE, because a non-quiesced outbound is a retryable precondition
        # miss the operator can clear, not a failed operation.) A non-quiesced
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


async def _record_reload_audit(
    engine: Engine, *, actor: str, dir_arg: object, client: str | None = None
) -> None:
    """Write the ``config_reload`` audit row with the ADR 0041 D1 content fingerprint of what loaded.

    Shared by the inline reload endpoint and the dual-control executor so a held-then-approved reload
    records the same fingerprint-bearing row as an ungated one. The fingerprint is computed off the
    event loop and is best-effort — a fingerprint failure must never block the audit of a successful
    reload. ``dir_arg`` is the requested config_dir (advisory; the row keys on engine.last_reload_dir).

    ``client`` (ADR 0150) is the address of the actor named in the row. The inline endpoint passes the
    requester's own address. The dual-control executor deliberately does NOT: there the row's ``actor``
    is the original *requester*, while the request in flight belongs to the *approver*, so stamping the
    approver's address would attribute one person's action to another's host — worse than NULL."""
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
        client=client,
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


def _export_ndjson_line(row: Row) -> bytes:
    """One NDJSON line for the bulk body export (#124, ADR 0131): the message metadata + the **decrypted
    raw body** (the PHI egress). ``json.dumps`` escapes the CR-delimited HL7 / binary ``mfb64:`` markers
    safely so a body can never break the one-object-per-line framing."""
    d = dict(row)
    obj = {
        "id": d["id"],
        "channel_id": d["channel_id"],
        "received_at": d.get("received_at"),
        "message_type": d.get("message_type"),
        "control_id": d.get("control_id"),
        "status": d.get("status"),
        "raw": d["raw"],
    }
    return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")


#: A conservative MIME *shape* — ``type/subtype`` of RFC-2045 token chars only, no structural characters
#: (``;``/space/CR/LF/``"``) that could inject or split the ``Content-Type`` header. An attachment's
#: ``content_type`` originates from an attacker-influenced OBX-5.2 label, so a value failing this is
#: served as the generic binary type below rather than trusted into the response header. This is a
#: shape screen ONLY — it admits ``image/svg+xml``/``text/html``; the browser-active downgrade below is
#: what makes the served type inert (ASVS 1.3.4).
_SAFE_MIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$")
#: Length bound on the served ``Content-Type``. The token grammar above is unbounded and the stored
#: label has no column check, so an arbitrarily long attacker string would otherwise be echoed into a
#: response header; no registered media type comes close to this.
_MAX_ATTACHMENT_MIME_LEN = 255
_DEFAULT_ATTACHMENT_MIME = "application/octet-stream"

#: Case-folded subtype tokens that make a media type **browser-active** — a representation a browser may
#: execute, or render as markup, rather than treat as opaque bytes. Matched as SUBSTRINGS of the
#: case-folded subtype, deliberately wider than exact-subtype equality or a ``+xml``-suffix test:
#: ``application/x-javascript``, ``text/x-html``, ``image/svg`` (no ``+xml``) and ``application/xml-dtd``
#: are all browser-active and every one of them slips past an equality/suffix check. ``script`` also
#: catches ``ecmascript``/``vbscript``/``jscript``; the only benign type it sweeps up is
#: ``application/postscript``, which no browser renders and which is not a pass-through requirement.
_BROWSER_ACTIVE_SUBTYPE_TOKENS = ("html", "xml", "script", "svg")
#: Top-level types that are browser-active whatever the subtype (``multipart/x-mixed-replace`` renders).
_BROWSER_ACTIVE_TYPES = ("multipart",)

#: The attachment download's Content-Security-Policy (ASVS 1.3.4). ``default-src 'none'`` denies every
#: subresource and fetch; ``sandbox`` with NO ``allow-*`` token drops the response into a unique opaque
#: origin with scripts, forms, popups and same-origin access all disabled. Layered UNDER the MIME
#: downgrade, the unconditional ``Content-Disposition: attachment`` and the global ``nosniff``, so even
#: a representation a browser would otherwise treat as markup cannot execute in the application origin.
_ATTACHMENT_CSP = "default-src 'none'; sandbox"
#: ``GET /messages/{message_id}/attachments/{attachment_id}`` and the web console's same-handler
#: delegate ``GET /ui/messages/...`` — see :class:`AttachmentSecurityHeadersMiddleware`.
_ATTACHMENT_PATH_RE = re.compile(r"^(?:/ui)?/messages/[^/]+/attachments/[^/]+$")


def _is_browser_active_mime(mime: str) -> bool:
    """True when ``mime`` (already shape-screened ``type/subtype``) names a representation a browser may
    execute or render as markup.

    **Case-folded, deliberately.** The token grammar admits uppercase and browsers match media types
    case-insensitively, so ``Image/SVG+XML`` is exactly the threat ``image/svg+xml`` is (``mimetypes``
    lower-cases internally too, so the mixed-case form even yields a ``.svg`` download name)."""
    top, _, subtype = mime.casefold().partition("/")
    if top in _BROWSER_ACTIVE_TYPES:
        return True
    return any(token in subtype for token in _BROWSER_ACTIVE_SUBTYPE_TOKENS)


def _safe_attachment_content_type(content_type: str | None) -> str:
    """The download ``Content-Type``: the stored ``content_type`` when it is a clean, bounded
    ``type/subtype`` MIME that is **not browser-active**, else ``application/octet-stream``.

    The stored value is a verbatim, attacker-influenced OBX-5.2 label, so it is never trusted into the
    response header (header-splitting shapes) and never trusted into the *browser* either: an
    ``image/svg+xml`` or ``text/html`` label is downgraded to the inert binary type, which also stops
    :func:`_attachment_filename` from deriving a ``.svg``/``.html`` download name (ASVS 1.3.4).

    **Why downgrade rather than sanitize.** Attachment bytes are verbatim clinical payloads — ADR 0105
    Approach B stores the OBX-5.5 value untouched and the preserve-the-original invariant forbids
    rewriting them — so the control is *neutralize at serve* (inert MIME + attachment disposition +
    nosniff + the sandbox CSP), never a sanitizing rewrite of the stored document. Inert types
    (``application/pdf``, ``image/png``, …) still pass through under their own type."""
    ct = (content_type or "").strip()
    if len(ct) > _MAX_ATTACHMENT_MIME_LEN or not _SAFE_MIME_RE.match(ct):
        return _DEFAULT_ATTACHMENT_MIME
    return _DEFAULT_ATTACHMENT_MIME if _is_browser_active_mime(ct) else ct


def _attachment_filename(attachment_id: str, content_type: str) -> str:
    """A header-safe download filename. ``attachment_id`` is a 64-hex sha256 (safe by construction); a
    short prefix keeps it readable and a ``mimetypes`` extension (when the MIME is known) hints the type.
    No user/attacker text reaches the ``Content-Disposition`` header. Callers pass the ALREADY-downgraded
    :func:`_safe_attachment_content_type` result, so a browser-active label can never source the
    extension."""
    ext = mimetypes.guess_extension(content_type) or ""
    return f"attachment-{attachment_id[:16]}{ext}"


def _is_attachment_download_path(path: str) -> bool:
    """True for the JSON attachment download route and the web console's ``/ui`` delegate of it."""
    return _ATTACHMENT_PATH_RE.match(path) is not None


class AttachmentSecurityHeadersMiddleware:
    """Re-assert :data:`_ATTACHMENT_CSP` on every attachment download response (ASVS 1.3.4).

    The route sets the header on its own ``Response``, which is enough on the JSON API path. It is NOT
    enough on the console's ``GET /ui/messages/{id}/attachments/{id}`` delegate, which re-serves the very
    same ``Response`` object: two ``/ui``-scoped writers **assign** (not ``setdefault``) a
    ``Content-Security-Policy`` on any non-static ``/ui`` path — the engine's own ``_security_headers``
    overlay and the console's ``UiSecurityHeadersMiddleware`` nonce CSP — so a route-level header there
    is silently overwritten with a console CSP that has no ``sandbox``. Neither of those may be relaxed
    globally without neutering the console's own hardening.

    So this middleware is registered **after** ``mount_ui`` and therefore sits OUTSIDE both writers: on
    the response path an outer ``send`` wrapper runs last, and last writer wins. It is scoped to the two
    attachment paths, is a strict pass-through for everything else, and is a pure-ASGI middleware (not
    ``BaseHTTPMiddleware``) so it adds no task hop. It stays INSIDE ``ClientNetworkMiddleware``, whose
    address denial short-circuits with its own headers before reaching here.

    ``tests/test_attachment_download_api.py`` asserts the SERVED header on both paths, so a middleware
    re-ordering that puts a ``/ui`` CSP writer back on top fails there rather than silently."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_attachment_download_path(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Content-Security-Policy"] = _ATTACHMENT_CSP
            await send(message)

        await self.app(scope, receive, send_wrapper)


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


def _compose_preset_layers(
    criterias: list[dict[str, Any]],
) -> tuple[SearchSpec, dict[str, str | None]]:
    """AND-compose N saved-preset criteria into one ``(SearchSpec, metadata-filters)`` for
    ``search_messages`` (ADR 0136 §5, BACKLOG #151). Each metadata scalar
    (``channel_id``/``status``/``message_type``/``control_id``) takes the first non-empty value and
    **rejects a conflicting second** (400). **Exactly one** preset may carry a content needle (a
    ``content`` substring or a ``field_path``[+``field_value``]); >1 or 0 → 400. Raises
    :class:`HTTPException` (400) on a conflict / missing-or-duplicate needle; the caller maps the
    ``ContentSearchError`` from a malformed field path likewise."""
    meta_keys = ("channel_id", "status", "message_type", "control_id")
    meta: dict[str, str | None] = dict.fromkeys(meta_keys)
    needle: dict[str, Any] | None = None
    for crit in criterias:
        for key in meta_keys:
            value = crit.get(key)
            value = value.strip() if isinstance(value, str) else value
            if value:
                if meta[key] is not None and meta[key] != value:
                    raise HTTPException(
                        400, f"layered presets conflict on {key!r}: {meta[key]!r} vs {value!r}"
                    )
                meta[key] = value
        has_needle = bool((crit.get("content") or "").strip()) or bool(
            (crit.get("field_path") or "").strip()
        )
        if has_needle:
            if needle is not None:
                raise HTTPException(
                    400, "layered search allows at most one content predicate across presets"
                )
            needle = crit
    if needle is None:
        raise HTTPException(
            400,
            "layered search needs exactly one preset carrying a content term (substring or field)",
        )
    try:
        spec = make_spec(
            content=(needle.get("content") or None),
            field_path=(needle.get("field_path") or None),
            field_value=(needle.get("field_value") or None),
            target=SearchTarget(needle.get("target") or "both"),
        )
    except (ContentSearchError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return spec, meta


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


async def _audit_channel_denied(
    engine: Engine, identity: Identity, channel: str | None, client: str | None = None
) -> None:
    """Audit a per-channel RBAC denial (mirrors auth.permission_denied).

    ``client`` (ADR 0150) is the caller's address — a denial is exactly the record an investigator
    wants a host for. It is OPTIONAL because this helper is also handed to the console seam as a bare
    callback (``audit_channel_denied=``), which has no request in hand; there it stays NULL rather than
    inheriting some other caller's address."""
    await engine.store.record_audit(
        "auth.channel_denied",
        actor=identity.username,
        channel_id=channel,
        detail=json.dumps({"channel": channel}),
        client=client,
    )


async def _run_connection_test(
    rr: RegistryRunner, name: str, direction: str
) -> ConnectionTestResult:
    """Build a fresh connector for ``name`` and probe its reachability, never disturbing the live one.
    Reports a config (bad ``env()``/egress) or connectivity failure in the result rather than raising —
    only an unexpected bug would 500. Closes the test connector afterward.

    Every ``detail`` here is scrubbed and length-bounded, because it does not stay in the response: the
    route JSON-dumps it into ``audit_log.detail``, the one at-rest error column written **without** the
    store cipher and teed **off-box** to syslog/SIEM. ``safe_*`` redacts PHI shapes and bounds the
    length; it has no notion of a credential, so what actually keeps a secret out of here is the rule
    that a connector's exceptions never interpolate a credential *value* — this is depth, not the seal."""

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

    # A not-deployed connection (#233, ADR 0111) has no live endpoint to reach, and its env() must
    # NEVER be resolved — so short-circuit BEFORE build_test_connector, which would resolve env()
    # (raising on absent secrets), build a throwaway connector, and open a probe socket to the peer.
    # The route has already enforced RBAC, so this can't disclose the not-deployed state to an
    # unauthorized caller. supported=False (not success=False): there is nothing here to probe, which
    # is a different answer from "probed and it failed" — it mirrors the not-testable listen-source case.
    conn = rr.registry.inbound.get(name) or rr.registry.outbound.get(name)
    if conn is not None and not conn.deployed:
        return _result(
            supported=False,
            success=False,
            ms=0.0,
            detail="connection is not deployed (deployed=false) — nothing to test",
        )

    try:
        _direction, connector = rr.build_test_connector(name)
    except WiringError as exc:
        return _result(supported=True, success=False, ms=0.0, detail=safe_text(str(exc)))
    start = time.monotonic()
    supported, success, detail = True, False, None
    try:
        await asyncio.wait_for(connector.test_connection(), _CONNECTION_TEST_TIMEOUT)
        success = True
    except TestNotSupportedError as exc:
        supported, detail = False, safe_text(str(exc))
    except TimeoutError:
        detail = f"timed out after {_CONNECTION_TEST_TIMEOUT:.0f}s"
    except DeliveryError as exc:
        detail = safe_text(str(exc))
    except Exception as exc:  # noqa: BLE001 - any probe failure is reported in the result, never a 500
        detail = safe_exc(exc)
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
    security_settings: SecuritySettings | None = None,
    approvals: ApprovalsSettings | None = None,
    alerts_settings: AlertsSettings | None = None,
    service_settings: ServiceStatusSettings | None = None,
    expose_docs: bool = False,
    allow_no_auth: bool = False,
    audit_all_authz: bool = False,
    ws_allowed_origins: Sequence[str] = (),
    serve_ui: bool = False,
    public_origin: str | None = None,
    # ADR 0142: passed as CONFIG so the /ui/oidc registrar can gate at MOUNT time. It cannot read
    # app.state.auth -- create_managed_app attaches the service in the lifespan, AFTER mount_ui
    # has already fixed the route table.
    oidc_enabled: bool = False,
    # ASVS 3.7.3 (seam v17): the configured IdP authorization endpoint, for the interstitial's
    # DISPLAY host. Config, never request input — see UiDeps.oidc_authorization_host.
    oidc_authorization_endpoint: str = "",
    webauthn_rp_from_request: bool = True,
    exposure_protected: bool = False,
    loopback: bool = False,
    tls_terminated_upstream: bool = False,
    tls_client_cert_identities: Mapping[str, str] | None = None,
    trusted_proxies: Sequence[str] = (),
    phi_read_hop_secure: bool = True,
    log_dir: str | None = None,
    configured_log_level: str | None = None,
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
    # Offline uploaded-logs store (BACKLOG #125/#126, ADR 0134). Filesystem-backed, encrypted at rest
    # under the SAME store DEK. DISABLED (None) unless [store].uploads_dir is set — so no PHI-at-rest
    # surface exists unless an operator opts in; every uploaded-logs route 503s when None.
    #
    # ASVS 11.3.4: prefer the LIVE store's cipher INSTANCE whenever one exists (an engine is bound here;
    # the managed-serve lifespan rebinds this from its own open store). Its AES-GCM invocation bound is
    # per-instance state, so a second cipher over the same DEK would charge nothing to the key's
    # persisted count and would keep encrypting past the fail-closed 2**32 ceiling. `build_store_cipher`
    # is the fallback for the genuinely store-LESS construction path only (embedding / tests), where
    # there is no bound to share and nothing durable to charge.
    app.state.upload_store = None
    if store_settings is not None and store_settings.uploads_dir:
        upload_cipher = (
            engine.store.cipher() if engine is not None else build_store_cipher(store_settings)
        )
        app.state.upload_store = UploadStore(
            store_settings.uploads_dir,
            upload_cipher,
            max_bytes=store_settings.max_upload_bytes,
            # Per-user quotas + retention (ASVS 5.2.4) — defaults-ON, enforced in save() / prune.
            max_files_per_user=store_settings.max_upload_files_per_user,
            max_total_bytes_per_user=store_settings.max_upload_total_bytes_per_user,
            retention_days=store_settings.uploads_retention_days,
            # ASVS 2.3.4: the quota's cross-PROCESS half. The per-uploader lock inside UploadStore is
            # an asyncio.Lock and so is per-event-loop; N engine shards over one uploads_dir hold N
            # of them. Every shard shares this ONE unified store (ADR 0063), so it is the decision
            # point that spans them. None here is the genuinely store-LESS path (embedding / tests) —
            # the same path that falls back to build_store_cipher above.
            store=engine.store if engine is not None else None,
        )
    # ADR 0118: the EFFECTIVE [security] switch values (serve syncs the gate-flipped egress/retention back
    # in) back the read-only GET /security/posture view. None → the secure defaults for the test/embedding
    # path. There is NO settings-write route; the IDE is the sole authoring surface.
    app.state.security = security_settings or SecuritySettings()
    # [security].allowed_client_networks, pre-parsed + normalized once at construction. EMPTY (the
    # default) = no restriction: ClientNetworkMiddleware short-circuits on the first branch, so every
    # existing deployment and test is behaviourally identical. See api/client_networks.py for WHICH
    # address is evaluated and why.
    app.state.client_networks = app.state.security.client_networks
    # [api].trusted_proxies, for the address-monoculture tripwire only (a DECLARED proxy is the
    # supported way for the engine to see real client addresses, so the tripwire stands down).
    app.state.trusted_proxies = tuple(trusted_proxies)
    # Network-denial observability (the control must be visible or an operator cannot tell a lockout
    # from an outage): a monotonic counter + the last refused address, published by
    # GET /security/posture.
    app.state.client_denials = 0
    app.state.client_denied_last = None
    app.state.client_address_monoculture = False
    # Fail-closed when no auth is attached unless explicitly opted out (embedding/dev) — SYS-1.
    app.state.allow_no_auth = allow_no_auth
    # ASVS 16.3.2 (#244): audit every authorization grant, not just the sensitive set (off by default).
    app.state.audit_all_authz = audit_all_authz
    # Loaded [alerts] config for the read-only /alerts/rules view (independent of engine; may be None,
    # in which case the route falls back to all-off defaults). The lifespan path sets the live value.
    app.state.alerts_settings = alerts_settings
    # [service] service-status reporting (L6a): default-off; the managed lifespan sets the live value,
    # here it backs the direct-construction (test) path.
    app.state.service_settings = service_settings
    # Configured [logging].log_dir for the GET /status app-log metering (#50). None = stdout-only (no
    # metering). The managed-app lifespan sets the live value; here it backs the direct-construction path.
    app.state.log_dir = log_dir
    # BACKLOG #171 (ADR 0130): the startup [logging].level baseline GET /logging/level reports next to the
    # (possibly runtime-overridden, ephemeral) effective level. None when unknown (embedding/test path).
    app.state.configured_log_level = configured_log_level
    app.state.ws_count = 0  # live /ws/stats connection count (API-WS cap)
    # BACKLOG #76 (ADR 0065 amendment): the in-memory metrics-history ring the console trend charts read
    # from GET /metrics/history. Fed by the ~1s /ws/stats sampler below (no new task, no extra store I/O);
    # bounded + process-local (a durable table would flip store_schema — out of scope for this first slice).
    app.state.metrics_history = MetricsHistory()
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
    # ADR 0143: whether the API binds a loopback host (http://127.0.0.1 — a W3C potentially-trustworthy
    # origin). Read-only by the web console's UiSecurityHeadersMiddleware (via _auth.security_headers_
    # context) to engage the http-SAFE browser hardening (nonce-CSP / COOP / CORP / Reporting) over a
    # cleartext loopback secure-context WITHOUT auto-TLS. The session cookie's Secure / __Host- prefix
    # still keys on effective_https (real https), so login is not broken over cleartext loopback; HSTS
    # stays off here (the security-headers middleware emits it only over https / exposure_protected).
    app.state.loopback = loopback
    app.state.tls_terminated_upstream = tls_terminated_upstream
    # mTLS client-cert → principal allow-list (#200, ADR 0002). Read by security.resolve_client_cert_
    # identity to map a VERIFIED peer cert's subject/SAN to an Identity (deny-by-default). Empty (the
    # default) disables cert-identity — byte-identical to the pre-#200 mTLS-for-transport-only path.
    app.state.tls_client_cert_identities = dict(tls_client_cert_identities or {})
    # #200 residual (ADR 0092): the API PHI-read DATA-PATH guard. The serve-start exposed-gate refuses a
    # prod-PHI cleartext bind, but the posture-keyed refusal was never applied to the PHI-read RESPONSE
    # path itself — so this derives the API serve-hop disposition ONCE (mirroring how the transport cells
    # stamp active_hop_posture) and stashes it for require_phi_read + the search route to enforce before
    # PHI leaves. A production-PHI instance whose serve hop is NOT proven secure (not loopback / TLS /
    # proxy-terminated) REFUSES rather than silently emitting PHI; the production-PHI clamp
    # (hop_insecure_escape_downgrades) stays the single authority for the global escape. posture=None (no
    # [ai], embedding/test) or a secure serve hop → ALLOW, so the loopback/dev default is byte-identical.
    _phi_read_enforcement = (security_settings or SecuritySettings()).enforcement
    _phi_read_posture = (
        hop_posture_from_ai(ai_settings, enforcement=_phi_read_enforcement)
        if ai_settings is not None
        else None
    )
    app.state.phi_read_hop_disposition = phi_read_hop_disposition(
        _phi_read_posture,
        serve_hop_secure=phi_read_hop_secure,
        audited_opt_out=(
            hop_insecure_escape_downgrades(enforcing=_phi_read_posture.enforcing)
            if _phi_read_posture is not None
            else False
        ),
    )
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
        # The baseline security headers are set HERE, not left to the middleware that sets them on
        # every other response. Starlette routes a handler registered for Exception/500 to
        # ServerErrorMiddleware, which build_middleware_stack places OUTSIDE user_middleware by
        # construction — so neither _security_headers below nor the outermost
        # SecurityHeaderFloorMiddleware is in this response's path, and a 500 shipped with none of
        # them. Status and body are unchanged: this adds headers only.
        headers = dict(BASELINE_SECURITY_HEADERS)
        if hsts_applies(request.url.scheme, exposure_protected):
            headers[HSTS_HEADER] = HSTS_VALUE
        return JSONResponse({"detail": "internal error"}, status_code=500, headers=headers)

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
        # The header names/values and the HSTS condition come from api/header_floor.py so this
        # middleware and the outermost floor that backstops it cannot drift apart. This one still
        # exists for the PATH-CONDITIONAL work below, which the floor deliberately does not duplicate.
        for name, value in BASELINE_SECURITY_HEADERS:
            response.headers.setdefault(name, value)
        if hsts_applies(request.url.scheme, exposure_protected):
            response.headers.setdefault(HSTS_HEADER, HSTS_VALUE)
        # /ui browser surface (ADR 0065 §5): a strict CSP (no unsafe-*) and no-store on every HTML
        # response; the vendored /ui/static assets keep StaticFiles' own cache. PHI JSON reads also get
        # no-store (every _NO_STORE_PREFIXES family, ASVS 14.2.2) so a browser/proxy never caches a
        # message body, a search hit, a log line or an uploaded file's split messages. These are SET
        # (override) so a stale cache directive can't slip through. nosniff/frame-deny/HSTS still apply.
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
        elif path.startswith(_NO_STORE_PREFIXES):
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
        # ADR 0134: the uploaded-logs upload routes admit up to [store].max_upload_bytes; all else 1 MiB.
        upload_store = getattr(request.app.state, "upload_store", None)
        cap = (
            upload_store.max_bytes
            if upload_store is not None and request.url.path in _UPLOAD_BODY_PATHS
            else _MAX_REQUEST_BODY_BYTES
        )
        try:
            too_big = int(length) > cap
        except ValueError:
            _log.warning("rejected invalid Content-Length on %s from %s", request.url.path, client)
            return JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
        if too_big:
            _log.warning("rejected oversized request body on %s from %s", request.url.path, client)
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/health", response_model=Health)
    async def health(
        request: Request, identity: Identity | None = Depends(optional_identity)
    ) -> Health:
        # Liveness is always answerable (tokenless), but the build version is fingerprinting info, so
        # it is disclosed only to an authenticated caller (WP-L3-07 / ASVS 13.4.6). When auth is
        # disabled-with-allow_no_auth, optional_identity returns the system identity → version shown.
        #
        # observed_client is echoed ONLY when [security].allowed_client_networks is in use, so the
        # default deployment's /health payload is byte-identical. This route is EXEMPT from the network
        # gate (api/client_networks.py), which is what lets a locked-out operator curl it and discover
        # which address the engine is matching — the difference between a diagnosable 403 and a
        # console that looks dead.
        networks = getattr(request.app.state, "client_networks", ())
        observed = (request.client.host if request.client else None) if networks else None
        return Health(
            version=__version__ if identity is not None else None, observed_client=observed
        )

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

    @app.post("/ai/chat", response_model=AiChatResponse)
    async def ai_chat(
        body: AiChatRequest,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.AI_ASSIST)),
    ) -> AiChatResponse:
        """Broker one **code_only** AI-assist prompt to the customer-managed / self-hosted LLM (ADR 0135,
        BACKLOG #95).

        **The SERVER is the sole enforcement point.** It RE-RESOLVES the effective policy server-side from
        the loaded ``[ai]`` settings — it NEVER trusts the IDE-supplied ``data_scope`` — and serves this
        route only under the engine-broker mode. The MVP boundary is **code_only regardless of mode**: an
        IDE claim above the server-enforced scope is DENIED (403). RBAC is deny-by-default via
        ``AI_ASSIST``; the auth dependency shares the same session / CSRF posture as every other
        authenticated mutating route (bearer for the native IDE client, ``SameSite`` cookie for a browser).
        Every use is audited on the EXISTING hash-chained ``audit_log`` with **PHI-safe metadata only** —
        never the prompt, the reply, or the provider key."""
        ai = getattr(request.app.state, "ai", None) or AiSettings()
        _data_class, prod = ai.derived_posture()
        production = True if prod is None else prod  # unresolved posture -> strictest ceiling
        # RE-RESOLVE server-side. NEVER trust the IDE-claimed mode/scope — the policy comes from [ai].
        eff = resolve_effective_policy(
            mode=ai.mode, data_scope=ai.data_scope, production=production
        )
        # This route serves ONLY the engine-broker mode. Any other central choice (off / byo / the P1/P2
        # managed_claude paths) means the broker path is not the configured one — 409 = config conflict.
        if eff.mode is not AiMode.MANAGED_ENDPOINT:
            raise HTTPException(
                409,
                "engine-brokered AI assistance is not enabled (set [ai].mode = managed_endpoint)",
            )
        # code_only enforcement: the engine-broker MVP operates strictly at code_only regardless of mode
        # (never PHI). A request CLAIMING a broader scope than the server enforces is DENIED — the IDE
        # cannot obtain more than the re-resolved server policy grants (managed_endpoint never reaches phi).
        enforced_scope = AiDataScope.CODE_ONLY
        if body.data_scope is not enforced_scope:
            raise HTTPException(
                403,
                "engine-brokered AI assistance is code_only in this release; the requested data_scope "
                "exceeds what the server policy permits",
            )
        # Build the broker from the SERVER's settings (never the request body). The SSRF endpoint-allowlist
        # + cleartext-credential checks run in the constructor; a misconfiguration is an operator error.
        # #329: thread the derived instance posture (the same _phi_read_posture derived at create_app time
        # from ai_settings, which == app.state.ai == `ai` on the managed path) so the broker's cleartext-
        # http credential refusal is clamped on an enforcing-PHI instance — the escape can no longer put
        # the api_key on the wire. Without this the route would build the broker with an unclamped escape
        # (green and inert), the exact failure mode #329 exists to close.
        try:
            broker = ai_broker_from_settings(ai, posture=_phi_read_posture)
        except AiBrokerError as exc:
            _log.warning("engine AI broker misconfigured: %s", exc)
            raise HTTPException(503, "engine-brokered AI assistance is not available") from exc
        try:
            reply = await broker.chat_async(body.prompt)
        except AiBrokerError as exc:
            _log.warning("engine AI broker call failed: %s", exc)
            raise HTTPException(502, "the AI provider request failed") from exc
        # Per-use audit — reuse the EXISTING hash-chained audit_log (record_audit). PHI-safe metadata ONLY:
        # never the prompt, the reply, or the api_key. Character counts are volumes, not content.
        await engine.store.record_audit(
            "ai.assist",
            actor=identity.username,
            detail=json.dumps(
                {
                    "mode": eff.mode.value,
                    "data_scope": enforced_scope.value,
                    "provider": ai.provider,
                    "model": ai.model,
                    "endpoint_host": broker.endpoint_host,
                    "prompt_chars": len(body.prompt),
                    "reply_chars": len(reply),
                }
            ),
            client=client_ip(request),
        )
        return AiChatResponse(reply=reply, model=ai.model, data_scope=enforced_scope)

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
        retired by H4; SQLite/Postgres/SQL Server all have full at-rest coverage).

        **Engine-shard scope (ADR 0037).** The connection-scoped part of ``loosenings`` (the ADR 0153
        ``cleartext_accepted`` declarations) is read off THIS process's registry, which in a sharded
        deployment is the shard-filtered graph — so each shard reports its own declared set, not the
        estate's. ``messagefoundry check`` reads the whole config dir and is the estate-wide surface.
        ``loosenings_scope`` is non-``None`` when this engine has no loaded graph at all."""
        # The live cipher posture (on/off + key fingerprint only). cipher_info() is the public Store
        # accessor — the route never touches engine.store._cipher.
        info = engine.store.cipher_info()
        # Store config: backend + key SOURCE (provider name) + the two keyless-gate flags. From app.state
        # (the lifespan/managed-app stashes the resolved StoreSettings); fall back to defaults if absent.
        store = getattr(request.app.state, "store_settings", None) or StoreSettings()
        ai = getattr(request.app.state, "ai", None) or AiSettings()
        data_class, production = ai.derived_posture()
        backend = store.backend.value
        # ADR 0118: the effective [security] switch values + active loosenings + the synthetic-relaxation
        # notice. security is the resolved SecuritySettings the serve path stashed (defaults on the
        # test/embedding path). No secret material — these are booleans/ints only.
        security = getattr(request.app.state, "security", None) or SecuritySettings()
        # [store]/[auth] carry posture switches too (ADR 0148: one posture, loosen only), so the registry
        # needs them to report a COMPLETE list. Same stash-or-default pattern as `store` above.
        auth_settings = getattr(request.app.state, "auth_settings", None) or AuthSettings()
        # #323 layer 3: [alerts] carries the SMTP-hop deviation (cleartext / verification off). Same
        # stash-or-default pattern — settings-scoped, so this route reports it completely even with no
        # graph loaded, unlike the connection-scoped cleartext_accepted set below.
        alerts_settings = getattr(request.app.state, "alerts_settings", None) or AlertsSettings()
        # ADR 0153 + #333: the THREE connection-scoped deviations. Read LIVE off the running graph (so a
        # reload is reflected) — this route is where an operator learns a cleartext hop is being crossed
        # by declaration, an expired certificate is being honoured, or a generic DB hop has no verifying
        # TLS keyword, and a stale or absent list would understate the posture. An engine with no
        # registry runner (an embedding, or an app queried before start) cannot see them at all, so it
        # DECLARES that in `loosenings_scope` rather than returning a settings-only subset that reads as
        # the whole posture — the same discipline `messagefoundry security show` follows.
        runner = engine.registry_runner
        if runner is not None:
            cleartext_hops = [name for name, _ in accepted_cleartext_hops(runner.registry)]
            expired_hops = [name for name, _ in expiry_relaxed_hops(runner.registry)]
            db_hops = [name for name, _ in unverified_generic_db_hops(runner.registry)]
        else:
            cleartext_hops, expired_hops, db_hops = [], [], []
        loosenings_scope = (
            None
            if runner is not None
            else (
                "settings only — no connection graph is loaded on this engine, so the per-connection "
                "cleartext_accepted / tls_allow_expired / generic-ODBC-DATABASE-TLS declarations are "
                "NOT included (see `messagefoundry check`)"
            )
        )
        loosenings = [
            SecurityLoosening(switch=name, risk=risk)
            for name, risk in security_loosenings(
                security,
                store,
                auth_settings,
                alerts_settings,
                cleartext_hops,
                expired_hops,
                db_hops,
            )
        ]
        synthetic_relaxation = (
            "strict PHI-only controls (at-rest-encryption refusal, deny-by-default egress, bounded "
            "retention) are relaxed: this instance is marked synthetic "
            "(handles_real_patient_data=false), so it carries no ePHI"
            if data_class is not None and data_class is not DataClass.PHI
            else None
        )
        # FIPS-provider attestation of the interpreter's ssl/_hashlib OpenSSL (report-only, #73 / ADR 0120):
        # metadata (a boolean + version string), never key material, never enforced.
        fips_mode, openssl_version = fips_attestation()
        # TLS key-exchange groups read-out (report-only, #338). Pure helper over a throwaway probe
        # context; reflects/changes NO live TLS behaviour, reports "inherited" until Python 3.15.
        kex_groups = kex_groups_report()
        # Platform memory-encryption READ-OUT (report-only, ADR 0152 Phase 1). Pure platform read
        # (/proc/cpuinfo flags + guest device presence on Linux; all-None everywhere else), no engine
        # state, never raises. It reports what the HOST SAYS ABOUT ITSELF and therefore satisfies
        # NOTHING — 11.7.1 exists because that host may be the adversary. Capability and activation
        # stay separate fields; the route never fuses them.
        memenc = platform_memory_encryption_readout()
        memory_declared = security.memory_encryption_operator_declared
        await engine.store.record_audit(
            "security.posture_view",
            actor=identity.username,
            detail=json.dumps(
                {
                    "backend": backend,
                    "encryption_enabled": info.encrypts,
                    "key_source": store.key_provider,
                    # Reuse the list computed above rather than recomputing it: a second call could
                    # observe a different graph after a concurrent reload, and the audit row must record
                    # exactly what the response reports.
                    "loosenings": [entry.switch for entry in loosenings],
                }
            ),
            client=client_ip(request),
        )
        return SecurityPosture(
            data_class=data_class,
            production=production,
            enforcement=security.enforcement,
            environment=ai.environment,
            backend=backend,
            encryption_enabled=info.encrypts,
            key_source=store.key_provider,
            key_id=info.active_key_id,  # FINGERPRINT only, never key bytes
            require_encryption=store.require_encryption,
            allow_unencrypted_phi=store.allow_unencrypted_phi,
            plaintext_columns=_plaintext_columns(backend, encryption_enabled=info.encrypts),
            security=security.model_dump(),
            loosenings=loosenings,
            loosenings_scope=loosenings_scope,
            synthetic_relaxation=synthetic_relaxation,
            fips_mode=fips_mode,  # interpreter ssl/_hashlib OpenSSL FIPS-provider state; None=undeterminable
            openssl_version=openssl_version,  # that OpenSSL's version string (public metadata)
            kex_groups=kex_groups,  # report-only: are the approved KEX groups pinned or inherited (#338)?
            # ADR 0152: a SELF-REPORT plus the operator's claim. Neither satisfies ASVS 11.7.1 at any
            # value — see the field comments on SecurityPosture. The disclaimer ships IN THE BODY
            # (memory_encryption_note), unconditionally: this endpoint is the designated evidence
            # artifact, and a disclaimer that lives only in a docstring never reaches its reader.
            memory_encryption_self_reported_capability=memenc.capability,
            memory_encryption_self_reported_active=memenc.active,
            memory_encryption_self_reported_mechanism=memenc.mechanism,
            memory_encryption_readout_source=memenc.source,
            memory_encryption_operator_declared=memory_declared,
            # Tri-state: None whenever nobody declared (there is nothing to contradict) or the
            # read-out cannot tell. Never collapsed to False, which would read as "corroborated".
            memory_encryption_readout_contradicts_declaration=(
                memenc.contradicts_declaration if memory_declared else None
            ),
            memory_encryption_note=READOUT_DISCLAIMER,
            # [security].allowed_client_networks observability (process-local counters, not persisted):
            # is the source-network gate firing, at whom, and is it silently inert (R3)?
            client_network_denials=getattr(request.app.state, "client_denials", 0),
            client_denied_last=getattr(request.app.state, "client_denied_last", None),
            client_address_monoculture=bool(
                getattr(request.app.state, "client_address_monoculture", False)
            ),
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
                        # deployed=False (#233, ADR 0111) WINS the ladder: a not-deployed inbound is
                        # never wired, so it is neither failed nor merely stopped — it must read
                        # "not_deployed" so an operator can tell it from a "stopped" lane that SHOULD
                        # be running. (Never a live-state read: the flag is a REGISTRY fact.)
                        status=(
                            "not_deployed"
                            if not ic.deployed
                            else (
                                "failed"
                                if ifail
                                else (
                                    "filtered"
                                    if ifiltered
                                    else ("running" if rr.inbound_running(iname) else "stopped")
                                )
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
                        flagged=ic.flagged,  # #131: object-of-interest marker (display-only)
                        toml_managed=_is_toml_managed(ic.source_file),
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
                    # The collapsed display status: not-deployed (#233) WINS (never wired — not failed,
                    # not merely paused/"stopped"), then failed/filtered, else the live per-outbound
                    # tri-state (running/stopping/stopped) — no longer the whole-engine state. A
                    # not-deployed lane is parked (paused+quiesced) exactly like a start-disabled one, so
                    # outbound_status alone would report "stopped"; the flag disambiguates the two.
                    dstatus = (
                        "not_deployed"
                        if not oc.deployed
                        else (
                            "failed"
                            if dfail
                            else ("filtered" if dfiltered else rr.outbound_status(dname))
                        )
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
                        # #131: object-of-interest marker; a draining (removed) outbound has no oc → False.
                        flagged=oc.flagged if oc is not None else False,
                        toml_managed=_is_toml_managed(oc.source_file) if oc is not None else False,
                        # #136: per-message "Waiting for Reply" display state (live connector, past its
                        # display delay). Duck-typed → False for non-ACK-waiting / draining outbounds.
                        waiting_for_reply=rr.outbound_waiting_for_reply(dname),
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
            # Also surface any operator-paused OR not-deployed outbound with no failed/filtered/edge row
            # yet, so a paused idle/no-edge lane stays visible + selectable (its purge-eligibility is the
            # `paused` field below; the status is the live tri-state stopping/stopped, reason None — no
            # failure). A not-deployed lane (#233, ADR 0111) is parked (paused+quiesced) just like a
            # start-disabled one, so outbound_status reports "stopped" for it too — but it must surface as
            # "not_deployed", never a silent "stopped", or a never-trafficked not-deployed lane is
            # invisible (or worse, indistinguishable from a lane that SHOULD be running). Checked FIRST so
            # deployed=False wins over the tri-state.
            for oname, oc in reg.outbound.items():
                if oname in standalone or oname in emitted_dests:
                    continue
                if not oc.deployed:
                    standalone[oname] = ("not_deployed", None)
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
                        flagged=oc.flagged,  # #131: object-of-interest marker (display-only)
                        toml_managed=_is_toml_managed(oc.source_file),
                        # #136: per-message "Waiting for Reply" display state (live connector).
                        waiting_for_reply=rr.outbound_waiting_for_reply(dname),
                    )
                )
        return rows

    # --- code-first connection operations ------------------------------------

    async def _control_guard(
        engine: Engine, identity: Identity, name: str, client: str | None = None
    ) -> None:
        # Controlling an inbound connection is scoped per-channel (the connection IS the channel).
        # `client` (ADR 0150) is the denied caller's address, threaded from the route's request.
        if not identity.can_access_channel(name):
            await _audit_channel_denied(engine, identity, name, client)
            raise HTTPException(403, "not authorized for this connection")

    async def _dual_role_control(
        engine: Engine,
        identity: Identity,
        name: str,
        action: str,
        *,
        role: str | None = None,
        client: str | None = None,
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
            await _control_guard(engine, identity, name, client)
            try:
                if action == "start":
                    await rr.start_inbound(name)
                elif action == "stop":
                    await rr.stop_inbound(name)
                else:
                    await rr.restart_inbound(name)
            except NotDeployedError as exc:
                # #233 (ADR 0111): start/restart of a not-deployed connection is refused — deploying it
                # is a CONFIG change (flip deployed=true + reload + supply its env() values), not a
                # runtime action. (stop never raises: an already-parked lane is a no-op.)
                raise HTTPException(409, str(exc)) from None
            return {"name": name, "running": rr.inbound_running(name)}
        if rr is not None and want_out and name in rr.registry.outbound:
            # A shared outbound spans channels, so a channel-scoped user can't control one (mirrors purge).
            if identity.allowed_channels is not None:
                await _audit_channel_denied(engine, identity, name, client)
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
            except NotDeployedError as exc:
                # #233 (ADR 0111): start/restart of a not-deployed outbound is refused — there is no
                # connector to build and no worker to resume; deploying it is a config change, not a
                # runtime action. (stop never raises: an already-parked lane is a no-op.)
                raise HTTPException(409, str(exc)) from None
            return {"name": name, "running": rr.outbound_running(name)}
        # Neither an inbound nor an outbound (or no runner). Run the per-channel guard first so a scoped
        # user is 403'd for a name outside their scope (don't disclose existence), then 404.
        await _control_guard(engine, identity, name, client)
        raise HTTPException(404, f"no such connection: {name}")

    @app.post("/connections/{name}/start")
    async def start_connection(
        name: str,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        return await _dual_role_control(engine, identity, name, "start", client=client_ip(request))

    @app.post("/connections/{name}/stop")
    async def stop_connection(
        name: str,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        return await _dual_role_control(engine, identity, name, "stop", client=client_ip(request))

    @app.post("/connections/{name}/restart")
    async def restart_connection(
        name: str,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.CONNECTIONS_CONTROL)),
    ) -> dict[str, object]:
        return await _dual_role_control(
            engine, identity, name, "restart", client=client_ip(request)
        )

    @app.post("/connections/{name}/flag")
    async def set_connection_flag(
        name: str,
        req: ConnectionFlagRequest,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.CONFIG_DEPLOY)),
    ) -> dict[str, object]:
        """Set the object-of-interest flag (#131, ADR 0007 amendment) on a ``connections.toml``-managed
        connection — the FIRST console→connections.toml write seam. Persists ``flagged`` through the
        comment-preserving, validate-before-persist writer (``connections_edit``) and reflects it on the
        live registry **without a reload** (a cosmetic-field replace — no connector rebuild, no delivery
        change). A **code-first** connection has no TOML home and is refused **409** (the scope fork).
        Gated by ``config:deploy`` (deny-by-default, paced) and audited — the console→TOML mutation path."""
        try:
            await engine.set_connection_flag(name, direction=req.direction, flagged=req.flagged)
        except WiringError as exc:
            # Not TOML-managed (scope fork) OR a validate-before-persist failure — the edit never landed.
            raise HTTPException(409, str(exc)) from exc
        await engine.store.record_audit(
            "connection_flag_set",
            actor=identity.username,
            detail=json.dumps(
                {"connection": name, "direction": req.direction, "flagged": req.flagged}
            ),
            client=client_ip(request),
        )
        return {"name": name, "direction": req.direction, "flagged": req.flagged}

    @app.get("/connections/{name}/metadata", response_model=ConnectionMetadata)
    async def connection_metadata(
        name: str,
        request: Request,
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
            await _control_guard(
                engine, identity, name, client_ip(request)
            )  # inbound config is per-channel
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
                await _audit_channel_denied(engine, identity, name, client_ip(request))
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
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.CONNECTIONS_TEST)),
    ) -> ConnectionTestResult:
        """Probe a connection's reachability (operability Tier 4) — builds a **fresh** connector
        (never the live one), honors the ``[egress]`` allowlist, and sends NO real data. Audited.

        Paced by the #193 per-actor floor (ASVS 2.4.2): the probe fires a **live outbound dial** (a
        reachability connect), so an unpaced actor could amplify it into an SSRF/port-scan sweep. It
        draws from the same shared admin-write bucket as the other mutating flows."""
        rr = engine.registry_runner
        if rr is None:
            raise HTTPException(503, "engine not started")
        is_inbound = name in rr.registry.inbound
        if not is_inbound and name not in rr.registry.outbound:
            raise HTTPException(404, f"no such connection: {name}")
        direction = "in" if is_inbound else "out"
        if is_inbound:
            await _control_guard(
                engine, identity, name, client_ip(request)
            )  # inbound test is per-channel
        elif identity.allowed_channels is not None:
            # An outbound spans channels, so a channel-scoped user can't probe a shared one (like purge).
            await _audit_channel_denied(engine, identity, name, client_ip(request))
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
            client=client_ip(request),
        )
        return result

    @app.post("/connections/{name}/test-credential", response_model=ConnectionTestResult)
    async def connection_test_credential(
        name: str,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.CONNECTIONS_TEST)),
    ) -> ConnectionTestResult:
        """Probe a **File** endpoint's reachability **under its configured alternate Windows / UNC-share
        credential** (ADR 0132, #111) — the credentialed endpoint tester #111 asks for.

        Same RBAC + pacing + fresh-connector probe as ``POST /connections/{name}/test`` (the probe dials
        the share **under the impersonated identity**, sending no real data), but **400s unless** the
        connection is a File endpoint with a ``credential_*`` identity configured — so an operator wiring
        an alternate-credential share gets a clear, *targeted* "the credential reaches the share / does
        not" answer rather than the generic connection test. Disjoint from ``/test`` (a separate route);
        audited as ``connection_credential_test``."""
        rr = engine.registry_runner
        if rr is None:
            raise HTTPException(503, "engine not started")
        conn = rr.registry.inbound.get(name) or rr.registry.outbound.get(name)
        if conn is None:
            raise HTTPException(404, f"no such connection: {name}")
        is_inbound = name in rr.registry.inbound
        # Authorize BEFORE disclosing anything about the connection's type / credential config — so an
        # out-of-scope channel-scoped caller gets a UNIFORM 403 regardless of whether the connection is a
        # File endpoint with an alt credential (which would otherwise leak via the 400 below). Matches the
        # sibling /test route and the _dual_role_control "guard first so a scoped user gets 403 rather than
        # learning about an out-of-scope name" convention.
        if is_inbound:
            await _control_guard(
                engine, identity, name, client_ip(request)
            )  # inbound test is per-channel
        elif identity.allowed_channels is not None:
            # An outbound spans channels, so a channel-scoped user can't probe a shared one (like /test).
            await _audit_channel_denied(engine, identity, name, client_ip(request))
            raise HTTPException(
                403, "channel-scoped users cannot test a shared outbound connection"
            )
        if (
            conn.spec.type is not ConnectorType.FILE
            or "credential_username" not in conn.spec.settings
        ):
            # No alt credential to test — a clear 400, not a generic probe (don't silently fall back to
            # an uncredentialed test, which would answer a different question). Reached only by an
            # AUTHORIZED caller, so it discloses config only to someone already in scope.
            raise HTTPException(
                400,
                f"connection {name!r} has no alternate Windows credential configured "
                "(set File credential_username / credential_password)",
            )
        direction = "in" if is_inbound else "out"
        result = await _run_connection_test(rr, name, direction)
        await engine.store.record_audit(
            "connection_credential_test",
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
            client=client_ip(request),
        )
        return result

    @app.post("/connections/{name}/purge", response_model=PurgeResult | PendingApprovalResponse)
    async def purge_connection(
        name: str,
        response: Response,
        request: Request,
        engine: Engine = Depends(_get_engine),
        scope: str = Query("all", pattern="^(top|all)$"),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_PURGE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> PurgeResult | PendingApprovalResponse:
        """Soft-cancel queued deliveries to an outbound connection (across all inbounds)."""
        # Purge targets an outbound and spans every inbound feeding it, so it can't be confined to a
        # per-(inbound-)channel scope — a channel-scoped user may not purge a shared outbound.
        if identity.allowed_channels is not None:
            await _audit_channel_denied(engine, identity, name, client_ip(request))
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
                "connection_purge",
                {"name": name, "scope": scope},
                requester=identity.username,
                client=client_ip(request),
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
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.MONITORING_DIAGNOSE)),
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
                await _audit_channel_denied(engine, identity, None, client_ip(request))
                raise HTTPException(403, "channel-scoped users cannot reset all statistics")
        else:
            for t in req.targets:
                # Per-channel RBAC: a scoped user may reset only endpoints of their own inbound channels
                # (a destination row is the channel_id->destination edge, so the same scope applies).
                if identity.allowed_channels is not None and not identity.can_access_channel(
                    t.channel_id
                ):
                    await _audit_channel_denied(engine, identity, t.channel_id, client_ip(request))
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
            client=client_ip(request),
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
        request: Request,
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
            await _audit_channel_denied(engine, identity, connection, client_ip(request))
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
        request: Request,
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
        await _control_guard(engine, identity, name, client_ip(request))
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
            suspended_until=a.suspended_until,
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
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.MONITORING_DIAGNOSE)),
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
            "alert_ack",
            actor=identity.username,
            detail=json.dumps({"alert_id": alert_id}),
            client=client_ip(request),
        )
        return await _alert_instance_echo(engine, identity, alert_id)

    @app.post("/alerts/{alert_id}/resolve", response_model=AlertInstanceInfo)
    async def resolve_alert(
        alert_id: int,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.MONITORING_DIAGNOSE)),
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
            "alert_resolve",
            actor=identity.username,
            detail=json.dumps({"alert_id": alert_id}),
            client=client_ip(request),
        )
        echo = await _alert_instance_echo(engine, identity, alert_id)
        # #81 (ADR 0133): a resolved condition is closed — drop the running notifier's in-memory suspend +
        # escalation state for the key, so a later re-open starts un-suspended at the base tier (matching
        # the fresh durable instance). Best-effort (no notifier in a JSON-only deployment).
        _notifier_forget(request, echo.event_type, echo.connection)
        return echo

    @app.post("/alerts/{alert_id}/suspend", response_model=AlertInstanceInfo)
    async def suspend_alert(
        alert_id: int,
        body: AlertSuspendRequest,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.MONITORING_DIAGNOSE)),
    ) -> AlertInstanceInfo:
        """Windowed suspend (#143, ADR 0044 amendment): mute an alert instance's NOTIFICATIONS for
        ``minutes`` (the window end is ``now + minutes·60``). **Notification-only** (AC-3) — the instance
        stays ``open``/counted/visible; only re-alerts are silenced for the window, and it auto-un-mutes
        at the window end (no timer). Durable in the store; the running notifier's suspend cache is
        updated so the mute takes effect immediately. Writes one metadata-only ``alert_suspend`` audit row
        (no message content). 404 if the id is unknown or already resolved."""
        # AC-7 (parity with ack/resolve): scope-check before mutating — an out-of-scope id is refused with
        # no state change and no audit row.
        await _require_alert_scope(engine, identity, alert_id)
        until = time.time() + body.minutes * 60.0
        info = await engine.store.suspend_alert_instance(alert_id, until=until)
        if info is None:
            raise HTTPException(404, "alert instance not found or already resolved")
        # Update the running notifier's in-memory suspend cache so the mute is honored immediately (the
        # durable suspended_until is the cross-restart record; the sink primes from it at startup). Best-
        # effort: absent in a JSON-only/no-transport deployment (the durable state still governs).
        _notifier_suspend(request, info.event_type, info.connection, until=until)
        await engine.store.record_audit(
            "alert_suspend",
            actor=identity.username,
            detail=json.dumps({"alert_id": alert_id, "minutes": body.minutes}),
            client=client_ip(request),
        )
        return _alert_instance_info(info)

    @app.post("/alerts/{alert_id}/resume", response_model=AlertInstanceInfo)
    async def resume_alert(
        alert_id: int,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_paced(Permission.MONITORING_DIAGNOSE)),
    ) -> AlertInstanceInfo:
        """Clear a windowed suspend (#143) so re-alerts resume immediately. Writes one metadata-only
        ``alert_resume`` audit row. 404 if the id is unknown or already resolved."""
        await _require_alert_scope(engine, identity, alert_id)
        info = await engine.store.resume_alert_instance(alert_id)
        if info is None:
            raise HTTPException(404, "alert instance not found or already resolved")
        _notifier_resume(request, info.event_type, info.connection)
        await engine.store.record_audit(
            "alert_resume",
            actor=identity.username,
            detail=json.dumps({"alert_id": alert_id}),
            client=client_ip(request),
        )
        return _alert_instance_info(info)

    @app.post("/alerts/test-email", response_model=AlertTestEmailResult)
    async def test_alert_email(
        request: Request,
        body: AlertTestEmailRequest | None = None,
        identity: Identity = Depends(require(Permission.SERVICE_CONFIGURE)),
    ) -> AlertTestEmailResult:
        """Send a synthetic, **PHI-free** test event through the configured ``[alerts]`` email transport
        so an operator can verify the alert mail server end-to-end (BACKLOG #118). This is the SAME code
        path a real alert takes (``EmailTransport.send`` → ``send_plain_email``: subject/body render,
        STARTTLS, the ``smtp_allowed_hosts`` egress allowlist), but it bypasses the fire-and-forget
        notifier queue so the send's success/failure is reported synchronously.

        Admin-gated (``service:configure``): it fires a live outbound SMTP dial, so it is service/settings
        administration, not the diagnostic ack/resolve tier. The result carries **no** email addresses —
        only a configured/success flag, the duration, the recipient count, and a ``safe_exc``-scrubbed
        failure detail. One metadata-only ``alert_test_email`` audit row is written (best-effort; skipped
        when no engine is bound). Never touches the message pipeline / staged queue."""
        alerts: AlertsSettings = (
            getattr(request.app.state, "alerts_settings", None) or AlertsSettings()
        )
        # Email is "configured" iff the notifier would build an EmailTransport (same triple as
        # notifier_from_settings / the /alerts/rules view) — refuse cleanly rather than 500 when it isn't.
        if not (alerts.email_smtp_host and alerts.email_from and alerts.email_to):
            return AlertTestEmailResult(
                configured=False,
                success=False,
                duration_ms=0.0,
                recipient_count=0,
                detail="no alert email transport configured ([alerts].email_smtp_host + "
                "email_from + email_to)",
            )
        # #146 parity: an explicit override redirects THIS test send to one alternate address; else the
        # configured email_to. Addresses are operator config (never PHI) and are never echoed back.
        override = body.recipient_override if body is not None else None
        recipients = [override] if override else list(alerts.email_to)
        # Resolve the SMTP password exactly as notifier_from_settings does: a [secrets].provider ref when
        # set (fail-closed), else the env-sourced literal. secret_provider is present only on the serve
        # path; the embedded path has none, so a provider-ref would fail closed (correct) and a plain
        # env password works with None.
        secret_provider = getattr(request.app.state, "secret_provider", None)
        success = False
        detail: str | None = None
        start = time.perf_counter()
        try:
            smtp_password = resolve_connector_secret(
                secret_provider,
                ref=alerts.email_password_secret,
                literal=alerts.email_password,
                label="[alerts].email_password",
            )
            transport = EmailTransport(
                host=alerts.email_smtp_host,
                port=alerts.email_smtp_port,
                sender=alerts.email_from,
                recipients=recipients,
                use_tls=alerts.email_use_tls,
                username=alerts.email_username,
                password=smtp_password,
                timeout=alerts.email_timeout,
                allowed_hosts=tuple(alerts.smtp_allowed_hosts),
                subject_template=alerts.email_subject_template,
                body_template=alerts.email_body_template,
                html_template=alerts.email_html_template,
                # #323 layer 3: the test send MUST use the same TLS posture as a real alert, or this
                # diagnostic passes against a relay that live alerts would refuse (or vice versa) — a
                # compensating control resting on a false premise, which is the defect class #323 is
                # about. Same fields, same source, same factory.
                tls_verify=alerts.email_tls_verify,
                tls_ca_file=alerts.email_tls_ca_file,
                trust_anchor_policy=(
                    tls_settings.policy()
                    if (tls_settings := getattr(request.app.state, "tls_settings", None))
                    is not None
                    else None
                ),
            )
            # A fixed synthetic event — carries only a type/severity/connection label + a static detail
            # string; NO message body, NO PHI. The template-value allowlist maps these safely too.
            await transport.send(
                {
                    "type": "test_email",
                    "connection": "alert-configuration-test",
                    "severity": "info",
                    "detail": "MessageFoundry alert email connectivity test",
                }
            )
            success = True
        except Exception as exc:  # noqa: BLE001 — any SMTP/config failure is a test FAILURE, not a 500
            # safe_exc scrubs + bounds the message so no SMTP server banner / internal detail (possible
            # host/credential hints) escapes to the caller.
            detail = safe_exc(exc)
        duration_ms = (time.perf_counter() - start) * 1000.0
        # Best-effort metadata-only audit (no addresses, no bodies) — mirrors connection_test. Skipped in
        # a no-engine (embedded/test) deployment where there is no store to record into.
        engine = getattr(request.app.state, "engine", None)
        if engine is not None:
            await engine.store.record_audit(
                "alert_test_email",
                actor=identity.username,
                detail=json.dumps({"success": success, "recipient_count": len(recipients)}),
                client=client_ip(request),
            )
        return AlertTestEmailResult(
            configured=True,
            success=success,
            duration_ms=duration_ms,
            recipient_count=len(recipients),
            detail=detail,
        )

    def _notifier_suspend(
        request: Request, event_type: str, connection: str, *, until: float
    ) -> None:
        # Reach the running NotifierAlertSink (wired into app.state by the serve lifespan) to update its
        # in-memory suspend cache. None in a JSON-only/no-transport/test app — a no-op then (the durable
        # store state governs; the sink primes from it at startup). Never raises into the route.
        notifier = getattr(request.app.state, "notifier", None)
        if notifier is not None:
            notifier.suspend(event_type, connection, until=until)

    def _notifier_resume(request: Request, event_type: str, connection: str) -> None:
        notifier = getattr(request.app.state, "notifier", None)
        if notifier is not None:
            notifier.resume(event_type, connection)

    def _notifier_forget(request: Request, event_type: str, connection: str) -> None:
        # #81: drop the notifier's suspend + escalation state for a resolved key (see resolve_alert).
        notifier = getattr(request.app.state, "notifier", None)
        if notifier is not None:
            notifier.forget(event_type, connection)

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
        request: Request,
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
            await _audit_channel_denied(engine, identity, req.channel_id, client_ip(request))
            raise HTTPException(403, "specify a channel within your scope to replay")
        if (
            gate is not None
        ):  # dual-control: hold for a second approver when [approvals] gates replay
            pending = await gate.guard(
                "dead_letter_replay",
                {"channel_id": req.channel_id, "destination_name": req.destination_name},
                requester=identity.username,
                client=client_ip(request),
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
                client=client_ip(request),
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
        request: Request,
        identity: Identity = Depends(require_paced(Permission.APPROVALS_APPROVE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> ApprovalDecisionResult:
        """Release a pending action: re-executes the captured operation and audits both identities. A
        requester can never approve their own request (dual-control, 2.3.5)."""
        if gate is None:
            raise HTTPException(503, "approval workflow is not available")
        try:
            outcome = await gate.approve(
                approval_id, approver=identity.username, client=client_ip(request)
            )
        except ApprovalError as exc:
            raise HTTPException(exc.status, exc.detail) from exc
        return ApprovalDecisionResult(**outcome)

    @app.post("/approvals/{approval_id}/reject", response_model=ApprovalDecisionResult)
    async def reject_action(
        approval_id: str,
        request: Request,
        identity: Identity = Depends(require_paced(Permission.APPROVALS_APPROVE)),
        gate: ApprovalGate | None = Depends(_get_gate),
    ) -> ApprovalDecisionResult:
        """Decline a pending action without executing it (audited)."""
        if gate is None:
            raise HTTPException(503, "approval workflow is not available")
        try:
            outcome = await gate.reject(
                approval_id, approver=identity.username, client=client_ip(request)
            )
        except ApprovalError as exc:
            raise HTTPException(exc.status, exc.detail) from exc
        return ApprovalDecisionResult(**outcome)

    # --- config promote / reload ---------------------------------------------

    @app.post("/config/reload", response_model=ReloadResult | PendingApprovalResponse)
    async def reload_config(
        req: ReloadRequest,
        response: Response,
        request: Request,
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
                client=client_ip(request),
            )
            if pending is not None:
                response.status_code = 202
                return PendingApprovalResponse(
                    approval_id=pending,
                    operation="config_reload",
                    detail="held for a second approver (dual-control)",
                )
        # #285 (ASVS 6.7.1): re-verify the operator-supplied trust anchors on every real deploy, BEFORE
        # the graph swap — the on-disk PEMs are re-read, so a swapped anchor is audited (auth.trust_anchor)
        # and a pinned-but-substituted / (under enforce) newly group-writable anchor REFUSES the deploy
        # (422) rather than converging onto a tampered CA. Dormant (no-op) when no anchor is configured.
        anchor_specs = getattr(request.app.state, "trust_anchor_specs", ())
        if anchor_specs and not req.dry_run:
            try:
                await run_anchor_preflight(
                    anchor_specs,
                    engine.store,
                    enforcing=getattr(request.app.state, "trust_anchors_enforcing", True),
                )
            except (TrustAnchorError, OSError) as exc:
                _log.warning("config reload refused (trust anchor): %s", exc)
                await engine.store.record_audit(
                    "config_reload_failed",
                    actor=user.username,
                    detail=json.dumps(
                        {"requested": req.config_dir, "dry_run": False, "reason": "trust_anchor"}
                    ),
                    client=client_ip(request),
                )
                raise HTTPException(422, "invalid configuration") from exc
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
                client=client_ip(request),
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
                client=client_ip(request),
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
                client=client_ip(request),
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
                client=client_ip(request),
            )
        else:
            await _record_reload_audit(
                engine, actor=user.username, dir_arg=req.config_dir, client=client_ip(request)
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
        received_from: float | None = Query(None, ge=0),
        received_to: float | None = Query(None, ge=0),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> MessageList:
        filters = dict(  # noqa: C408
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
        # #200 residual (ADR 0092): search is a bulk-PHI read behind require_step_up, NOT require_phi_read,
        # so it doesn't inherit the folded data-path guard — apply it explicitly before any decrypt.
        enforce_phi_read_hop(request)
        enforce_phi_read_pacing(request, identity)  # step-up paces NON-GET only; this is a GET
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
                    filters=dict(  # noqa: C408
                        channel_id=channel_id,
                        status=status,
                        message_type=message_type,
                        control_id=control_id,
                    ),
                )
            ),
            client=client_ip(request),
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

    @app.get("/messages/export")
    async def export_messages(
        request: Request,
        engine: Engine = Depends(_get_engine),
        # LARGEST PHI surface in the cluster (bulk raw bodies → a file): the strongest interactive gate —
        # a fresh step-up + second factor over BOTH messages:view_raw AND a dedicated messages:export
        # capability (ADR 0131 §2). Bulk egress is a distinct privilege from opening one message.
        identity: Identity = Depends(
            require_step_up(Permission.MESSAGES_EXPORT, Permission.MESSAGES_VIEW_RAW)
        ),
        ids: list[str] = Query(default=[]),  # noqa: B006 — FastAPI repeated ?ids= (save-selected)
        content: str | None = Query(None, max_length=512),
        field_path: str | None = Query(None, max_length=32),
        field_value: str | None = Query(None, max_length=512),
        target: str = Query("both", pattern="^(raw|summary|both)$"),
        channel_id: str | None = Query(None, max_length=256),
        status: str | None = Query(None, max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(1000, ge=1, le=100_000),
        scan_limit: int = Query(DEFAULT_CONTENT_SCAN_LIMIT, ge=1, le=MAX_CONTENT_SCAN_LIMIT),
    ) -> StreamingResponse:
        """Stream a batch of message bodies to a downloadable NDJSON file (#124, ADR 0131) — the
        Corepoint-parity bulk export a one-at-a-time ``/messages/{id}`` raw view can't provide.

        Selection is either an explicit ``ids`` set (the UI's *save-selected*) or the **basic**
        ``/messages/search`` filters (the UI's *save-all* — reusing ``search_messages`` for the id set);
        it then LOOPS ``get_message`` per id (no bulk store iterator — no store schema change). Each
        streamed body is re-checked against the caller's per-channel scope (load-bearing for the
        attacker-suppliable ``ids`` path); an out-of-scope id is skipped + audited (``auth.channel_denied``).
        The whole export is recorded as ONE ``messages_export`` audit row **before streaming** — actor +
        selection mode + basic filters + needle SHAPE (never the value) + the count of selected bodies — so
        a scripted save-all cannot pull a body that was not first counted in a durable audit row. The
        PHI-safe destination is the operator's responsibility."""
        # #200 (ADR 0092): a bulk-PHI read behind step-up (NOT require_phi_read), so apply the data-path
        # hop guard explicitly before any body is decrypted — exactly as the step-up search route does.
        enforce_phi_read_hop(request)
        # Charged BEFORE selection: export is a step-up GET, and step-up pacing is NON-GET only, so
        # without this a single actor can stream far more bodies per minute here than the per-actor
        # budget allows through /messages/{id}. Admission-time so a refused call does no store work.
        enforce_phi_read_pacing(request, identity)
        allowed = _scope(identity)  # per-channel RBAC (None = all)
        if ids:
            selected = ids[:limit]
            selection: dict[str, object] = {"mode": "ids", "requested": len(ids)}
        else:
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
            result = await engine.store.search_messages(
                spec,
                channel_id=channel_id,
                status=status,
                message_type=message_type,
                control_id=control_id,
                limit=limit,
                allowed_channels=allowed,
            )
            selected = [str(r["id"]) for r in result.rows]
            selection = {
                "mode": "search",
                **_search_audit_detail(
                    spec,
                    result,
                    filters=dict(  # noqa: C408
                        channel_id=channel_id,
                        status=status,
                        message_type=message_type,
                        control_id=control_id,
                    ),
                ),
            }
        # The dedicated tamper-evident audit, written BEFORE any body streams (mirroring /audit/export):
        # it counts EVERY selected body, so a scripted save-all can't harvest unaudited (ADR 0131 §4).
        await engine.store.record_audit(
            "messages_export",
            actor=identity.username,
            channel_id=channel_id,
            detail=json.dumps({"selected": len(selected), **selection}),
            client=client_ip(request),
        )

        async def _iter_ndjson() -> AsyncIterator[bytes]:
            for mid in selected:
                row = await engine.store.get_message(mid)
                if row is None:
                    continue
                # Per-row channel scope on EVERY streamed body (load-bearing for the ids path); an
                # out-of-scope id is skipped + audited, never exposed (ADR 0131 §3, mirrors get_message).
                if not identity.can_access_channel(row["channel_id"]):
                    await _audit_channel_denied(
                        engine, identity, row["channel_id"], client_ip(request)
                    )
                    continue
                yield _export_ndjson_line(row)

        return StreamingResponse(
            _iter_ndjson(),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": 'attachment; filename="messages-export.ndjson"'},
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
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
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
            client=client_ip(request),
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
        request: Request,
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
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
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
            client=client_ip(request),
        )
        # Neutralize at serve (ASVS 1.3.4): a browser-active OBX-5.2 label (svg/html/xml/script) is
        # downgraded to the inert binary type, which also keeps the .svg/.html extension out of the
        # download name, and the response carries a sandbox CSP so no served representation can execute
        # in the application origin. The stored bytes are NEVER rewritten (ADR 0105 Approach B keeps the
        # OBX-5.5 value verbatim). AttachmentSecurityHeadersMiddleware re-asserts the CSP from outside
        # the /ui CSP writers so the console delegate serves it too.
        content_type = _safe_attachment_content_type(match["content_type"])
        # Belt-and-braces MIME-vs-magic downgrade (ASVS 1.3.4/5.2.2): even a token-clean, stored MIME is
        # sender-influenced (OBX-5.2), so if it names a sniffable family whose magic the actual bytes
        # contradict, serve the generic octet-stream. Detach already downgrades on contradiction; this
        # re-checks against the reconstructed bytes at serve time.
        if not attachment_mime_agrees(content_type, body[:32]):
            content_type = _DEFAULT_ATTACHMENT_MIME
        filename = _attachment_filename(attachment_id, content_type)
        return Response(
            content=body,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Security-Policy": _ATTACHMENT_CSP,
            },
        )

    @app.get("/messages/{message_id}/responses", response_model=MessageResponses)
    async def get_message_responses(
        message_id: str,
        request: Request,
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
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
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
            client=client_ip(request),
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
        request: Request,
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
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
            raise HTTPException(404, f"no such message: {message_id}")
        payload_rows = await engine.store.outbox_payloads_for(message_id)
        # Returning transformed bodies is PHI access — audit the read, and (when bodies are actually
        # returned) record the per-message PHI view timeline, exactly like opening a raw body.
        await engine.store.record_audit(
            "outbound.read",
            actor=identity.username,
            channel_id=row["channel_id"],
            detail=json.dumps({"message_id": message_id, "count": len(payload_rows)}),
            client=client_ip(request),
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
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_REPLAY)),
    ) -> ReplayResult:
        row = await engine.store.get_message(message_id)
        if row is None or not identity.can_access_channel(row["channel_id"]):
            if row is not None:
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
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
            client=client_ip(request),
        )
        return ReplayResult(message_id=message_id, requeued=requeued)

    @app.post("/messages/{message_id}/resend", response_model=ResendResult)
    async def resend_message(
        message_id: str,
        body: ResendRequest,
        request: Request,
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
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
            raise HTTPException(404, f"no such message: {message_id}")
        # Cross-channel authorization: the caller must ALSO be scoped to the alternate outbound (its name
        # is treated as a channel for per-channel RBAC), so a channel-scoped operator cannot push PHI to
        # an outbound they can't reach. 403 (not 404) — the message IS visible; the target is denied.
        if not identity.can_access_channel(body.to):
            await _audit_channel_denied(engine, identity, body.to, client_ip(request))
            raise HTTPException(403, f"not authorized to resend to outbound {body.to!r}")
        # Target validation (must-fix #7): registered + owned-by-this-shard + running, else the row would
        # sit permanently pending (a silent drop).
        rr = engine.registry_runner
        if rr is None or body.to not in rr.registry.outbound:
            raise HTTPException(404, f"no such outbound connection: {body.to}")
        # THE BACK DOOR (#233, ADR 0111): resend inserts an outbound-stage row DIRECTLY (store.resend_to),
        # never passing through transform_one, so the transform-time decline that keeps a not-deployed
        # lane empty does NOT cover this path. Refuse here — otherwise an operator could hand-queue a row
        # into a lane with no connector, where it can only sit forever. 409 with the deploy-is-a-config-
        # change prose (not the generic "not running", which invites a start that also 409s).
        if not rr.registry.outbound[body.to].deployed:
            raise HTTPException(409, str(NotDeployedError(body.to)))
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
                client=client_ip(request),
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
        request: Request,
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
                await _audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
            raise HTTPException(404, f"no such message: {message_id}")

        if body.to is not None:
            # DIRECT power-path: deliver the edited body straight to an alternate outbound. Same cross-
            # channel authorization + target validation as #123's resend (registered/owned/running).
            if not identity.can_access_channel(body.to):
                await _audit_channel_denied(engine, identity, body.to, client_ip(request))
                raise HTTPException(403, f"not authorized to resend to outbound {body.to!r}")
            rr = engine.registry_runner
            if rr is None or body.to not in rr.registry.outbound:
                raise HTTPException(404, f"no such outbound connection: {body.to}")
            # THE BACK DOOR (#233, ADR 0111): the direct path reuses #123's resend seam, which inserts an
            # outbound-stage row DIRECTLY (store.resend_to) without transform_one — so, exactly like
            # /resend above, the transform-time not-deployed decline does not cover it. Refuse a
            # not-deployed target so an operator can't hand-queue a row into a lane with no connector.
            if not rr.registry.outbound[body.to].deployed:
                raise HTTPException(409, str(NotDeployedError(body.to)))
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
                    client=client_ip(request),
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
                client=client_ip(request),
            )
        return EditResendResult(
            message_id=message_id,
            status=outcome.status,
            reroute=True,
            new_message_id=outcome.new_message_id,
        )

    # --- offline uploaded logs (BACKLOG #125/#126, ADR 0134) -----------------

    def _require_upload_store(request: Request) -> UploadStore:
        """The configured :class:`UploadStore`, or 503 when ``[store].uploads_dir`` is unset (the whole
        uploaded-logs feature is opt-in, so no PHI-at-rest surface exists unless configured)."""
        us: UploadStore | None = getattr(request.app.state, "upload_store", None)
        if us is None:
            raise HTTPException(503, "uploaded logs are not configured (set [store].uploads_dir)")
        return us

    def _may_access_upload(identity: Identity, meta: UploadedFileMeta) -> bool:
        """Object-level authorization for ONE uploaded file (ASVS 8.2.2): owner-only, plus an explicit
        cross-operator override (``files:access_any``, an ADMINISTRATOR grant).

        The owner key is ``Identity.user_id`` — the account's immutable ``uuid4`` hex — and NOT the
        username. A username is unique among live accounts but reusable: deleting a user frees the
        name, and recreating it mints a NEW ``user_id``, so a name comparison would hand the recycled
        account the departed operator's uploaded PHI. The exact same value keys the per-uploader quota
        (``uploads.py`` ``save()``), so ownership and the budget can never disagree about who a file
        belongs to — a recycled account is neither billed for nor able to read the old files.

        **WHAT THIS DOES NOT REACH, and it is the primary enterprise path.** ``_upsert_ad_user``
        (``auth/service.py``) resolves an AD principal by ``sAMAccountName`` and mints a fresh
        ``user_id`` ONLY when no mirror row survives — i.e. only after a MessageFoundry
        ``delete_user``. On the DEFAULT path the surviving row is adopted and **its ``user_id`` is
        re-bound**, so a deploying site that recycles a ``sAMAccountName`` in the directory without
        also deleting the MessageFoundry user would give the new person the old person's id, and this
        check would match. No better key exists here: ``AdPrincipal`` carries no ``objectGUID`` or
        ``objectSid``. Closing it means binding AD to a directory-immutable id the way OIDC binds
        ``(issuer, sub)`` — tracked as BACKLOG #1143, not solvable inside this function.

        The channel axis is deliberately NOT used: ``Identity.allowed_channels`` defaults to ``None``
        (= every channel) and an uploaded file carries no channel at all, so a channel-scoped rule
        would protect nobody on a default install and would deny every scoped operator their own file.

        FAIL CLOSED on a sidecar with no ``uploader_id``. ``save()`` refuses to write one, but the
        tolerant loader yields ``""`` for a sidecar missing the key (a hand-placed one under the no-key
        identity cipher), and ``""`` matches no real ``user_id``. Such a file is reachable ONLY by an
        override holder — never by "everyone", which is what an equality test alone would give it if
        the caller's id were ever empty too."""
        if identity.has(Permission.FILES_ACCESS_ANY):
            return True
        return bool(meta.uploader_id) and meta.uploader_id == identity.user_id

    async def _authorized_upload_meta(
        request: Request, engine: Engine, us: UploadStore, identity: Identity, file_id: str, op: str
    ) -> UploadedFileMeta:
        """Load one uploaded file's metadata and enforce :func:`_may_access_upload` (ASVS 8.2.2).

        A denial answers **404 "no such uploaded file"** — the same status and the same response BODY
        as a malformed or absent id. That is a bound on the response, not on the whole observation: the
        denied path additionally reads and decrypts the sidecar and writes an ``upload.denied`` audit
        row, so it is distinguishable by timing and permanently distinguishable in the audit log. What
        makes the by-id routes non-enumerable is the id itself — a ``file_id`` is 128 bits of
        ``secrets.token_hex(16)`` and the listing no longer hands out another operator's — not the
        indistinguishability of the answer. The denial is audited: the acting username, the acting
        ``user_id``, the ``file_id`` and the operation — never the filename, the owner or any content.

        Every by-id route calls this BEFORE it decrypts a body or unlinks anything, which is the point:
        the check has to sit in the handler BODY, not in a ``Depends`` gate, because the web console
        invokes these handlers directly through the CoreHandlers seam and never runs their gates."""
        try:
            meta = await us.get_meta(file_id)
        except (UploadPathError, UploadNotFoundError):
            raise HTTPException(404, "no such uploaded file") from None
        if not _may_access_upload(identity, meta):
            await engine.store.record_audit(
                "upload.denied",
                actor=identity.username,
                # ``actor`` stays the username — that is the codebase-wide audit convention and every
                # reader/query already assumes it. But this control exists precisely BECAUSE a username
                # is reusable, so the column alone cannot say WHICH principal was refused: after a name
                # is recycled, two different accounts wear the same string and the departed operator's
                # denials read as the successor's. The immutable id disambiguates them, and it is an
                # account identifier, not PHI. Nothing else joins it: no filename, no owner name, no
                # content — the audit is not a PHI sink.
                detail=json.dumps(
                    {
                        "file_id": file_id,
                        "operation": op,
                        "reason": "not_owner",
                        "actor_user_id": identity.user_id,
                    }
                ),
                client=client_ip(request),
            )
            raise HTTPException(404, "no such uploaded file")
        return meta

    def _upload_info(meta: UploadedFileMeta) -> UploadedFileInfo:
        return UploadedFileInfo(
            file_id=meta.file_id,
            filename=meta.filename,
            uploader=meta.uploader,
            content_type=meta.content_type,
            size=meta.size,
            sha256=meta.sha256,
            uploaded_at=meta.uploaded_at,
            message_count=meta.message_count,
        )

    @app.post("/uploads", response_model=UploadedFileInfo)
    async def upload_file(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.FILES_UPLOAD)),
    ) -> UploadedFileInfo:
        """Import an external message file for offline browsing (BACKLOG #125). The multipart body is
        hand-parsed with stdlib (NO python-multipart, ADR 0134). Writes real HL7 PHI at rest (encrypted
        under the store DEK when a key is set); step-up-gated + audited (metadata only).

        **Text-only (ASVS 14.2.8).** This feature accepts only plain-text diagnostic logs (``.hl7`` /
        ``.txt`` / ``.xml``). A metadata-bearing binary container (JPEG/PNG/PDF/ZIP incl. DOCX) or any
        non-text body is refused with **HTTP 415** before anything is written — so no embedded metadata
        (EXIF/XMP/docProps) can ever be stored.

        **Consent (ASVS 14.2.8).** The original filename you supply and your username are stored and shown
        to you and to authorized operators holding ``files:access_any`` (administrators), and recorded in
        the audit log; submitting an upload is your consent. The file itself is **owner-only** (ASVS
        8.2.2): only you and an override holder can list, browse, resend or delete it."""
        us = _require_upload_store(request)
        body = await request.body()
        try:
            part = parse_single_file_upload(
                request.headers.get("content-type"), body, max_file_bytes=us.max_bytes
            )
        except MultipartTooLargeError as exc:
            raise HTTPException(413, str(exc)) from None
        except MultipartError as exc:
            raise HTTPException(400, str(exc)) from None
        # ASVS 14.2.8: enforce the feature's text-only format contract at the route, BEFORE save. A binary
        # container (JPEG/PNG/PDF/ZIP incl. DOCX) or a non-text body (NUL / control-dense) is refused with
        # 415 + a metadata-only upload.reject audit — nothing is written, so no embedded-metadata container
        # can reach the store (closes "no metadata stripping" without a stripping engine). Covers both
        # POST /uploads and POST /ui/uploaded-logs/upload (this handler backs both).
        nontext = nontext_upload_reason(part.data)
        if nontext is not None:
            await engine.store.record_audit(
                "upload.reject",
                actor=identity.username,
                detail=json.dumps(
                    {"filename": sanitize_filename(part.filename), "reason": nontext}
                ),
                client=client_ip(request),
            )
            raise HTTPException(415, nontext) from None
        try:
            # uploader_id (the immutable account id) is the ownership + quota key; uploader (the
            # username) rides along as the display/audit label. See uploads.UploadedFileMeta.
            meta = await us.save(
                data=part.data,
                filename=part.filename,
                uploader=identity.username,
                uploader_id=identity.user_id,
            )
        except UploadTooLargeError as exc:
            raise HTTPException(413, str(exc)) from None
        except UploadContentError as exc:
            # ASVS 5.2.2: disallowed extension or content/extension mismatch. Refuse with 400 and a
            # metadata-only audit (the sanitized filename + the reason string — NEVER any content). Covers
            # both POST /uploads and POST /ui/uploaded-logs/upload (this handler backs both).
            await engine.store.record_audit(
                "upload.reject",
                actor=identity.username,
                detail=json.dumps(
                    {"filename": sanitize_filename(part.filename), "reason": str(exc)}
                ),
                client=client_ip(request),
            )
            raise HTTPException(400, str(exc)) from None
        except UploadQuotaError as exc:
            # ASVS 5.2.4: the uploader's file-count or aggregate-byte quota would be exceeded. Refuse with
            # 409 (Conflict — the state, not the request, is at fault) and a metadata-only audit; nothing
            # was written. Covers both upload surfaces.
            await engine.store.record_audit(
                "upload.reject_quota",
                actor=identity.username,
                detail=json.dumps(
                    {"filename": sanitize_filename(part.filename), "reason": str(exc)}
                ),
                client=client_ip(request),
            )
            raise HTTPException(409, str(exc)) from None
        await engine.store.record_audit(
            "upload.create",
            actor=identity.username,
            detail=json.dumps(
                {
                    "file_id": meta.file_id,
                    "filename": meta.filename,
                    "size": meta.size,
                    "message_count": meta.message_count,
                }
            ),
            client=client_ip(request),
        )
        # ASVS 5.2.4: opportunistic age-based retention sweep at save time (off-loop, best-effort). A prune
        # error must never fail the upload the operator just made — it is logged and retried by the
        # periodic task. Each pruned file is audited (file_id + uploader, never content).
        #
        # BACKLOG #1224: the sweep is AUTOMATED and owner-blind, so it is attributed to the system,
        # not to the pruned file's uploader. `prune_expired()` is deliberately UNSCOPED (it has to be:
        # the per-uploader quota and the sweep both need to see every file), so the operator whose
        # upload triggered this pass is in general NOT the owner of what it prunes. Naming the owner
        # as actor while stamping the TRIGGERING operator's address made the row assert that X deleted
        # their own file from Y's host. `client` is dropped for the same reason rather than as tidying:
        # _record_reload_audit's contract is that `client` is the address OF THE ACTOR NAMED IN THE
        # ROW, and once the actor is the system principal no address is in scope (ADR 0150 decision 4
        # rejects exactly this pairing for dual-control config reload). The owner survives as DATA in
        # `detail.uploader`, which is where it belongs.
        try:
            for pruned in await us.prune_expired():
                await engine.store.record_audit(
                    "upload.prune",
                    actor="system",
                    detail=json.dumps(
                        {
                            "file_id": pruned.file_id,
                            "uploader": pruned.uploader,
                            # The IMMUTABLE owner key beside the display name. A prune row is a
                            # permanent record of a deletion whose subject cannot be recovered
                            # afterwards -- the file is gone -- and a username is reassignable
                            # (BACKLOG #1225), so a row read later could name a different person
                            # than it meant. UploadedFileMeta carries both deliberately
                            # (uploads.py:116); this records both.
                            "uploader_id": pruned.uploader_id,
                        }
                    ),
                )
        except OSError:
            _log.warning("opportunistic uploaded-logs retention prune failed", exc_info=True)
        return _upload_info(meta)

    @app.get("/uploads", response_model=UploadedFileList)
    async def list_uploaded_files(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.FILES_BROWSE)),
    ) -> UploadedFileList:
        """List the caller's OWN uploaded files (metadata only — no bodies). Audited.

        Object-level authorization (ASVS 8.2.2): the listing is owner-scoped, so one operator never
        sees another's filenames, sizes, digests or ``file_id`` s — the ``file_id`` being the token the
        browse/resend/delete routes accept. ``files:access_any`` widens it to every uploader's files.
        The scope is returned in the response AND recorded in the audit row — computed once, here — so
        a count means the same thing to every reader and no consumer has to re-derive whose files it
        is holding. The web console renders the sentence that matches it rather than asserting the
        owner-scoped case at an override holder, for whom it is false."""
        us = _require_upload_store(request)
        # Filtered HERE, not in UploadStore.list_files(): the store's unscoped scan is what the
        # per-uploader quota and the age-based retention sweep are built on, and both must keep seeing
        # every uploader's sidecars (uploads.py save()/prune_expired()).
        files = [m for m in await us.list_files() if _may_access_upload(identity, m)]
        scope: Literal["own", "any_owner"] = (
            "any_owner" if identity.has(Permission.FILES_ACCESS_ANY) else "own"
        )
        await engine.store.record_audit(
            "upload.list",
            actor=identity.username,
            detail=json.dumps({"count": len(files), "scope": scope}),
            client=client_ip(request),
        )
        return UploadedFileList(
            total=len(files), files=[_upload_info(m) for m in files], scope=scope
        )

    @app.get("/uploads/{file_id}/messages", response_model=UploadedMessagesResult)
    async def browse_uploaded_file(
        request: Request,
        file_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.FILES_BROWSE)),
        content: str | None = Query(None, max_length=512),
        field_path: str | None = Query(None, max_length=32),
        field_value: str | None = Query(None, max_length=512),
        target: str = Query("both", pattern="^(raw|summary|both)$"),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> UploadedMessagesResult:
        """Browse an uploaded file's split messages as a filterable log (BACKLOG #125). Decrypts + splits
        real PHI, so it is step-up-gated + PHI-read-hop-guarded (like content search) and audited with the
        needle SHAPE only (never its value). Returns metadata only — never a decrypted body.

        Owner-only (ASVS 8.2.2): a file the caller did not upload answers 404. The response shape does
        not bound what this route releases — ``matched`` plus the per-message metadata answer "does this
        needle occur in that file", so an unscoped browse is a content oracle over another operator's
        PHI, which is why the check runs BEFORE the body is decrypted."""
        enforce_phi_read_hop(request)
        enforce_phi_read_pacing(request, identity)  # bulk decrypt+split on a step-up GET
        us = _require_upload_store(request)
        spec: SearchSpec | None = None
        if content or field_path:
            try:
                spec = make_spec(
                    content=content,
                    field_path=field_path,
                    field_value=field_value,
                    target=SearchTarget(target),
                )
            except ContentSearchError as exc:
                raise HTTPException(400, str(exc)) from exc
        meta = await _authorized_upload_meta(request, engine, us, identity, file_id, "browse")
        try:
            data = await us.read_bytes(file_id)
        except (UploadPathError, UploadNotFoundError):
            raise HTTPException(404, "no such uploaded file") from None
        result = await asyncio.to_thread(
            browse_messages,
            data,
            spec=spec,
            message_type=message_type,
            control_id=control_id,
            limit=limit,
            offset=offset,
        )
        needle = None
        if spec is not None:
            needle = (
                {"kind": "substring", "shape": _needle_shape(spec.substring)}
                if spec.substring is not None
                else {"kind": "field_path", "field_path": spec.field_path}
            )
        await engine.store.record_audit(
            "upload.browse",
            actor=identity.username,
            detail=json.dumps(
                {
                    "file_id": file_id,
                    "needle": needle,
                    "message_type": message_type,
                    "control_id": control_id,
                    "matched": result.matched,
                    "scanned": result.scanned,
                }
            ),
            client=client_ip(request),
        )
        return UploadedMessagesResult(
            file_id=file_id,
            filename=meta.filename,
            messages=[
                UploadedMessageSummary(
                    index=m.index,
                    message_type=m.message_type,
                    control_id=m.control_id,
                    size=m.size,
                )
                for m in result.messages
            ],
            total_messages=result.total_messages,
            scanned=result.scanned,
            matched=result.matched,
            truncated=result.truncated,
        )

    @app.post("/uploads/{file_id}/resend", response_model=UploadResendResult)
    async def resend_uploaded_message(
        request: Request,
        file_id: str,
        body: UploadResendRequest,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.FILES_BROWSE)),
    ) -> UploadResendResult:
        """Inject one message from an uploaded file INTO a chosen inbound connection (BACKLOG #125). Uses
        the DISTINCT inject path ``engine.inject_message`` (``enqueue_ingress``) — a fresh ``RECEIVED`` on
        the target inbound's channel — NOT ``reingress`` (which presupposes an origin row an uploaded file
        never had). The target inbound must be registered + running, and the caller channel-scoped to it.
        Step-up-gated + audited.

        TWO authorization axes, both enforced: the TARGET (per-channel ``can_access_channel`` on the
        inbound, 403) and the SOURCE file (owner-only, ASVS 8.2.2, 404). Without the source check the
        route is a two-step read of another operator's bodies — inject their message into an inbound you
        are authorized for, then read it as an ordinary message on your own channel."""
        us = _require_upload_store(request)
        # Cross-channel authorization: the inbound name is treated as a channel for per-channel RBAC, so a
        # scoped operator cannot inject PHI into an inbound they can't reach. 403 (target denied).
        if not identity.can_access_channel(body.to):
            await _audit_channel_denied(engine, identity, body.to, client_ip(request))
            raise HTTPException(403, f"not authorized to inject into inbound {body.to!r}")
        rr = engine.registry_runner
        if rr is None or body.to not in rr.registry.inbound:
            raise HTTPException(404, f"no such inbound connection: {body.to}")
        try:
            if not rr.inbound_running(body.to):
                raise HTTPException(
                    409, f"inbound {body.to!r} is not running — start it before resending"
                )
        except KeyError:
            raise HTTPException(404, f"no such inbound connection: {body.to}") from None
        # Object-level authorization on the SOURCE file, in ADDITION to the target-channel check above.
        await _authorized_upload_meta(request, engine, us, identity, file_id, "resend")
        try:
            data = await us.read_bytes(file_id)
        except (UploadPathError, UploadNotFoundError):
            raise HTTPException(404, "no such uploaded file") from None
        parts = await asyncio.to_thread(split_uploaded, data)
        if body.index >= len(parts):
            raise HTTPException(
                404, f"no message at index {body.index} (file has {len(parts)} messages)"
            )
        mid = await engine.inject_message(
            channel_id=body.to,
            raw=parts[body.index],
            source_type="upload",
            metadata=json.dumps({"upload_file_id": file_id, "upload_index": body.index}),
        )
        await engine.store.record_audit(
            "upload.resend",
            actor=identity.username,
            channel_id=body.to,
            detail=json.dumps(
                {"file_id": file_id, "index": body.index, "to": body.to, "message_id": mid}
            ),
            client=client_ip(request),
        )
        return UploadResendResult(
            file_id=file_id, index=body.index, to=body.to, message_id=mid, status="injected"
        )

    @app.delete("/uploads/{file_id}", response_model=UploadDeleteResult)
    async def delete_uploaded_file(
        request: Request,
        file_id: str,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.FILES_DELETE)),
    ) -> UploadDeleteResult:
        """Delete an uploaded file from the server (BACKLOG #126) — destructive + irreversible. Guarded
        by the path-traversal-safe ``file_id`` (a bad id 404s without a filesystem touch), step-up, an
        owner-only object check (ASVS 8.2.2 — another operator's file answers 404, and is never
        unlinked), and an ``upload.delete`` audit row.

        The check reads the metadata FIRST, because ``UploadStore.delete`` returns the metadata only
        after it has already unlinked both sidecars — a check bolted onto that call would fire too
        late. The age-based retention sweep is deliberately owner-blind and unaffected."""
        us = _require_upload_store(request)
        await _authorized_upload_meta(request, engine, us, identity, file_id, "delete")
        try:
            meta = await us.delete(file_id)
        except (UploadPathError, UploadNotFoundError):
            raise HTTPException(404, "no such uploaded file") from None
        await engine.store.record_audit(
            "upload.delete",
            actor=identity.username,
            detail=json.dumps(
                {"file_id": meta.file_id, "filename": meta.filename, "size": meta.size}
            ),
            client=client_ip(request),
        )
        return UploadDeleteResult(file_id=meta.file_id, filename=meta.filename, deleted=True)

    # --- saved / layered Log-Search filter presets (BACKLOG #151, ADR 0136) --

    @app.get("/search/presets", response_model=SearchPresetList)
    async def list_search_presets(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MESSAGES_READ)),
    ) -> SearchPresetList:
        """List the caller's saved presets — names + timestamps only (NEVER the criteria; the
        PHI-shaped content term is returned only by the step-up-gated layered compose). Audited."""
        rows = await engine.store.list_search_presets(identity.user_id)
        await engine.store.record_audit(
            "preset.list",
            actor=identity.username,
            detail=json.dumps({"count": len(rows)}),
            client=client_ip(request),
        )
        return SearchPresetList(
            total=len(rows),
            presets=[
                SearchPresetInfo(
                    id=r["id"],
                    name=r["name"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
                for r in rows
            ],
        )

    @app.post("/search/presets", response_model=SearchPresetCreateResult)
    async def create_search_preset(
        body: SearchPresetCreateRequest,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_READ)),
    ) -> SearchPresetCreateResult:
        """Create-or-replace a named preset for the caller. Persists a possibly-PHI-shaped criteria
        (encrypted at rest), so it is step-up-gated + audited (needle shape only). A malformed content
        needle is rejected up front (make_spec) so a bad preset can't be saved."""
        crit = body.criteria
        needle_shape: str | None = None
        if crit.content or crit.field_path:
            try:
                make_spec(
                    content=crit.content,
                    field_path=crit.field_path,
                    field_value=crit.field_value,
                    target=SearchTarget(crit.target),
                )
            except ContentSearchError as exc:
                raise HTTPException(400, str(exc)) from exc
            needle_shape = _needle_shape(crit.content) if crit.content else "field_path"
        effective_id, replaced = await engine.store.upsert_search_preset(
            preset_id=uuid4().hex,
            # BACKLOG #1225: the OWNER KEY is the immutable Identity.user_id, never the reassignable
            # username. This is the WRITE the other three sites read; re-keying only the readers
            # would make every newly created preset invisible to its own creator.
            owner=identity.user_id,
            name=body.name,
            criteria=crit.model_dump_json(),
        )
        await engine.store.record_audit(
            "preset.create",
            actor=identity.username,
            detail=json.dumps(
                {
                    "id": effective_id,
                    "name": body.name,
                    "replaced": replaced,
                    "needle_shape": needle_shape,  # coarse class only — never the value
                }
            ),
            client=client_ip(request),
        )
        return SearchPresetCreateResult(
            id=effective_id, name=body.name, status="replaced" if replaced else "created"
        )

    @app.delete("/search/presets/{preset_id}", response_model=SearchPresetDeleteResult)
    async def delete_search_preset(
        preset_id: str,
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MESSAGES_READ)),
    ) -> SearchPresetDeleteResult:
        """Delete one of the caller's presets (owner-scoped). Audited."""
        deleted = await engine.store.delete_search_preset(
            preset_id=preset_id, owner=identity.user_id
        )
        if not deleted:
            raise HTTPException(404, f"no such preset: {preset_id}")
        await engine.store.record_audit(
            "preset.delete",
            actor=identity.username,
            detail=json.dumps({"id": preset_id}),
            client=client_ip(request),
        )
        return SearchPresetDeleteResult(id=preset_id, deleted=True)

    @app.get("/search/layered", response_model=MessageSearchResults)
    async def layered_search(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_step_up(Permission.MESSAGES_READ)),
        presets: str = Query(..., max_length=1024),
        limit: int = Query(50, ge=1, le=500),
        scan_limit: int = Query(DEFAULT_CONTENT_SCAN_LIMIT, ge=1, le=MAX_CONTENT_SCAN_LIMIT),
    ) -> MessageSearchResults:
        """Recall + **layer** several of the caller's presets into one combined content search (ADR
        0136 §5). ``presets`` is a comma-separated list of the caller's preset ids (≤ 8). Their typed
        params AND-compose (metadata conflict → 400; exactly one content predicate) over the ADR 0046
        ``search_messages`` seam. Step-up-gated + PHI-hop-guarded + audited (needle shape only). The
        content term is loaded server-side from the encrypted preset column — it never round-trips."""
        enforce_phi_read_hop(request)
        enforce_phi_read_pacing(request, identity)  # step-up paces NON-GET only; this is a GET
        ids = [p.strip() for p in presets.split(",") if p.strip()]
        if not ids:
            raise HTTPException(400, "provide at least one preset id")
        if len(ids) > _MAX_PRESET_LAYERS:
            raise HTTPException(400, f"at most {_MAX_PRESET_LAYERS} presets may be layered")
        criterias: list[dict[str, Any]] = []
        for preset_id in ids:
            row = await engine.store.get_search_preset(preset_id=preset_id, owner=identity.user_id)
            if row is None:
                raise HTTPException(404, f"no such preset: {preset_id}")
            try:
                criterias.append(json.loads(row["criteria"] or "{}"))
            except (ValueError, TypeError) as exc:
                raise HTTPException(400, f"preset {preset_id} has malformed criteria") from exc
        spec, meta = _compose_preset_layers(criterias)
        # Re-clamp the scan against the request bound (the composed spec used make_spec's default).
        spec = make_spec(
            content=spec.substring,
            field_path=spec.field_path,
            field_value=spec.field_value,
            target=spec.target,
            scan_limit=scan_limit,
        )
        allowed = _scope(identity)
        result = await engine.store.search_messages(
            spec,
            channel_id=meta["channel_id"],
            status=meta["status"],
            message_type=meta["message_type"],
            control_id=meta["control_id"],
            limit=limit,
            allowed_channels=allowed,
        )
        messages = [_summary(r) for r in result.rows]
        messages = [redact_unauthorized(m, identity) for m in messages]
        await engine.store.record_audit(
            "preset.layered_search",
            actor=identity.username,
            channel_id=meta["channel_id"],
            detail=json.dumps(
                {
                    "presets": len(ids),
                    **_search_audit_detail(spec, result, filters=dict(meta)),
                }
            ),
            client=client_ip(request),
        )
        return MessageSearchResults(
            messages=messages,
            scanned=result.scanned,
            matched=result.matched,
            truncated=result.truncated,
            limit=limit,
            scan_limit=spec.scan_limit,
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
            fenced_writes=getattr(engine.store, "fenced_writes", 0),
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

    @app.get("/metrics/history", response_model=MetricsHistoryResponse)
    async def metrics_history(
        request: Request,
        _user: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> MetricsHistoryResponse:
        """The in-memory metrics-history ring for the console trend charts (BACKLOG #76, ADR 0065
        amendment). Oldest-first samples of the outbound-row-by-status counts, fed by the ~1s /ws/stats
        sampler — **aggregate counts only, no PHI**, and no durable table (``store_schema`` stays false).
        Gated by ``monitoring:read`` like ``/stats``/``/metrics``."""
        history: MetricsHistory | None = getattr(request.app.state, "metrics_history", None)
        if history is None:
            return MetricsHistoryResponse(samples=[], capacity=0)
        return MetricsHistoryResponse(
            samples=[
                MetricsHistorySample(ts=s.ts, outbox_by_status=dict(s.outbox_by_status))
                for s in history.samples()
            ],
            capacity=history.capacity,
        )

    @app.get("/graph/edges", response_model=GraphResponse)
    async def graph_edges(
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_READ)),
    ) -> GraphResponse:
        """The by-name data-flow graph (BACKLOG #76, ADR 0065 amendment): the **static Registry edge
        set** (:func:`messagefoundry.config.graph.build_wiring_graph` — the same inbound → router →
        handler → outbound extractor the ``graph --json`` CLI uses) joined with each connection node's
        **live status** from the ``RegistryRunner``. Read-only + ``monitoring:read``; it constructs **no**
        ``channel``/``route`` bundling object (CLAUDE.md §1), imports no ``pipeline/`` for the derivation,
        and carries **no** message body. A **channel-scoped** caller sees ONLY the inbound → router →
        handler subgraph reachable from their accessible inbound connections: every **shared-outbound**
        node, its live status, and every edge to/from it are **dropped entirely** — matching the
        connections dashboard, which shows a scoped user no destination (outbound) rows (an outbound
        spans channels, so its state can reflect another channel's downstream). An unscoped caller sees
        the whole estate."""
        # Local import: config.graph is a pure, stdlib-only tooling module (imports config only, never
        # api/ or pipeline/), so this stays a one-way api → config read with no pipeline dependency.
        from messagefoundry.config.graph import build_wiring_graph

        rr = engine.registry_runner
        if rr is None:
            return GraphResponse()
        reg = rr.registry
        # Off the event loop (#76 review): build_wiring_graph does blocking file open()+read()+ast.parse
        # over every router/handler defining module (a fresh cache per call), which must not stall the
        # loop on the 5s /ui/monitoring/live poll path. It only reads the Registry + the on-disk source
        # (no engine state), so it is thread-safe; the live per-node status is read via rr.* on the loop
        # AFTER the build (mirrors this file's asyncio.to_thread convention).
        graph = await asyncio.to_thread(build_wiring_graph, reg)

        def _inbound_status(name: str) -> str:
            ic = reg.inbound[name]
            if not ic.deployed:
                return "not_deployed"
            if rr.connection_failed(name):
                return "failed"
            if rr.connection_filtered(name):
                return "filtered"
            return "running" if rr.inbound_running(name) else "stopped"

        def _outbound_status(name: str) -> str:
            oc = reg.outbound[name]
            if not oc.deployed:
                return "not_deployed"
            if rr.connection_failed(name):
                return "failed"
            if rr.connection_filtered(name):
                return "filtered"
            return rr.outbound_status(name)

        # Node set: every inbound/outbound connection + every router/handler, keyed by (kind, name).
        nodes: dict[tuple[str, str], GraphNode] = {}
        for name in reg.inbound:
            nodes[("inbound", name)] = GraphNode(
                name=name, kind="inbound", status=_inbound_status(name)
            )
        for name in reg.outbound:
            nodes[("outbound", name)] = GraphNode(
                name=name, kind="outbound", status=_outbound_status(name)
            )
        for name in reg.routers:
            nodes[("router", name)] = GraphNode(name=name, kind="router", status=None)
        for name in reg.handlers:
            nodes[("handler", name)] = GraphNode(name=name, kind="handler", status=None)

        edges = list(graph.edges)

        # Per-channel RBAC (#76 review — SECURITY): a channel-scoped caller must NOT see shared-outbound
        # topology or its live status — an outbound spans channels, so its running/failed/filtered state
        # can reflect ANOTHER channel's downstream. This mirrors the connections dashboard EXACTLY, which
        # shows a scoped user NO destination (outbound) rows at all (see list_connections: `if scoped:
        # continue`). So a scoped user sees only the inbound → router → handler subgraph reachable from
        # their accessible inbound connections: the BFS never traverses INTO an outbound node (dropping
        # every shared-outbound node AND its handler→outbound edges), nor into a pass-through inbound the
        # caller can't access. An unscoped caller (allowed_channels is None) sees the whole estate.
        if identity.allowed_channels is not None:
            accessible_inbounds = {
                name for name in reg.inbound if identity.can_access_channel(name)
            }

            def _traversable(node: tuple[str, str]) -> bool:
                # Never cross into a shared outbound (the topology boundary); a router/handler is shared
                # code with no live status; a pass-through inbound target is only visible if accessible.
                kind, name = node
                if kind == "outbound":
                    return False
                if kind == "inbound":
                    return name in accessible_inbounds
                return True

            adjacency: dict[tuple[str, str], list[tuple[str, str]]] = {}
            for e in edges:
                adjacency.setdefault((e.source_kind, e.source), []).append(
                    (e.target_kind, e.target)
                )
            reachable: set[tuple[str, str]] = {("inbound", name) for name in accessible_inbounds}
            frontier = list(reachable)
            while frontier:
                node = frontier.pop()
                for nxt in adjacency.get(node, ()):
                    if nxt not in reachable and _traversable(nxt):
                        reachable.add(nxt)
                        frontier.append(nxt)
            # Outbound nodes are never in `reachable`, so both the outbound nodes AND every edge with an
            # outbound (or out-of-scope inbound) endpoint are dropped — no dangling edge to a hidden node.
            nodes = {key: node for key, node in nodes.items() if key in reachable}
            edges = [
                e
                for e in edges
                if (e.source_kind, e.source) in reachable and (e.target_kind, e.target) in reachable
            ]

        return GraphResponse(
            nodes=list(nodes.values()),
            edges=[
                GraphEdge(
                    source=e.source,
                    source_kind=e.source_kind,
                    target=e.target,
                    target_kind=e.target_kind,
                    provenance=e.provenance,
                )
                for e in edges
            ],
            dynamic=sorted(
                f"{kind}:{name}"
                for kind, name in graph.dynamic
                if identity.allowed_channels is None or (kind, name) in nodes
            ),
        )

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
            # #138: report each alert-email template present-or-not (never the text in this allowlist view).
            email_subject_template_configured=bool(alerts.email_subject_template),
            email_body_template_configured=bool(alerts.email_body_template),
            email_html_template_configured=bool(alerts.email_html_template),
            rules=[
                AlertRuleInfo(
                    event_type=r.event_type,
                    connection=r.connection,
                    min_depth=r.min_depth,
                    min_oldest_seconds=r.min_oldest_seconds,
                    severity=r.severity.value,
                    transports=r.transports,
                    cooldown_seconds=r.cooldown_seconds,
                    # #146: report the COUNT of per-rule recipients, never the addresses (secret-guard parity).
                    recipient_count=len(r.recipients) if r.recipients else 0,
                    id=r.id,  # #138 — the operator rule label ({rule_id})
                    control_action=r.control_action,  # #144 — auto-remediation action
                    control_target=r.control_target,
                    mute=r.mute,  # #143 — static per-rule notification mute
                    escalate_tiers=len(r.escalate),  # #81 — occurrence-driven escalation tier count
                    schedule_configured=r.schedule
                    is not None,  # #81 — schedule-gated (present-or-not)
                    content_label=r.content_label,  # #81 — content_match label this rule routes by
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
        conn_total = conn_running = conn_not_deployed = 0
        rr = engine.registry_runner
        if rr is not None:  # one "channel" per inbound connection
            # #233 (ADR 0111): a not-deployed connection is present in the registry but is NOT a lane
            # (never wired, never running). It is counted in its OWN bucket and EXCLUDED from the
            # running/stopped totals, so the split counts only lanes and the invariant
            # connections_stopped == connections_total - connections_running keeps meaning "deployed but
            # not up". A deliberately-not-deployed connection must never be tallied as a stopped one —
            # that is the exact confusion this state removes. channels_* (inbound-only) filters the same
            # way for the same reason.
            in_deployed = [name for name, ic in rr.registry.inbound.items() if ic.deployed]
            out_deployed = [name for name, oc in rr.registry.outbound.items() if oc.deployed]
            total = len(in_deployed)
            running = sum(1 for name in in_deployed if rr.inbound_running(name))
            # outbound_running (not outbound_status) so the running/stopped split gates on the engine
            # actually running AND the lane not operator-paused — consistent with inbound_running's
            # actually-started semantics (outbound_status reports "running" for any non-paused lane even
            # before start, which would over-count a built-but-not-started runner).
            out_running = sum(1 for name in out_deployed if rr.outbound_running(name))
            conn_total = total + len(out_deployed)
            conn_running = running + out_running
            conn_not_deployed = (len(rr.registry.inbound) - len(in_deployed)) + (
                len(rr.registry.outbound) - len(out_deployed)
            )
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
            connections_not_deployed=conn_not_deployed,
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
                # ADR 0114 sub-lever B: the out-of-pool dedicated claim holders (None unless
                # fifo_claim_prepared is effectively active) — additive, keeps the B11
                # connection-budget arithmetic honest about the store's real footprint.
                claim_pool=(
                    ClaimPoolInfo(
                        open=pool_status.claim_pool.open,
                        idle=pool_status.claim_pool.idle,
                        opened_total=pool_status.claim_pool.opened_total,
                        discarded_total=pool_status.claim_pool.discarded_total,
                    )
                    if pool_status.claim_pool is not None
                    else None
                ),
            )
            if pool_status is not None
            else None
        )
        # ADR 0114 AC-7's degraded gauge. Until this field existed the ONLY signal that the proc
        # claim path had fallen back to the shipped batch was a WARNING at store open — which is a
        # load-bearing part of why the gate could degrade in every deployment unnoticed. None unless
        # [store].fifo_claim_proc is on and the backend has the lever, so the payload is unchanged
        # by default. Synchronous + free (attributes the gate recorded once at open).
        cps = engine.store.claim_proc_status()
        claim_proc = (
            ClaimProcInfo(
                effective=cps.effective,
                degraded_reason=cps.degraded_reason,
                head_forms=dict(cps.head_forms),
            )
            if cps is not None
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
            claim_proc=claim_proc,
        )

    # --- runtime log verbosity + redacted log-tail viewer (BACKLOG #171, ADR 0130) ----

    @app.get("/logging/level", response_model=LogLevelInfo)
    async def get_logging_level(
        request: Request,
        _: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
    ) -> LogLevelInfo:
        """The current effective root log level, the startup ``[logging].level`` baseline a restart returns
        to, and the accepted level set — the read half of the runtime verbosity control (#171, ADR 0130).
        **Not PHI** (level names only); gated by ``monitoring:diagnose`` (the diagnostic tier)."""
        return LogLevelInfo(
            level=current_log_level(),
            configured=getattr(request.app.state, "configured_log_level", None),
            levels=list(LOG_LEVELS),
        )

    @app.patch("/logging/level", response_model=LogLevelInfo)
    async def set_logging_level(
        request: Request,
        body: LogLevelUpdate,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require(Permission.MONITORING_DIAGNOSE)),
    ) -> LogLevelInfo:
        """Change the live root + uvicorn log level WITHOUT a restart (#171, ADR 0130). The override is
        **ephemeral**: a process restart re-asserts ``[logging].level``, and a ``/config/reload`` does NOT
        reset it (``configure_logging`` does not re-run there), so it survives a reload and resets only on
        restart. Gated by ``monitoring:diagnose``; an invalid level is a 400. The change is recorded as a
        ``logging_level_change`` audit row (old → new, actor) — level names only, no PHI."""
        previous = current_log_level()
        try:
            applied = set_runtime_level(body.level)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await engine.store.record_audit(
            "logging_level_change",
            actor=identity.username,
            detail=json.dumps({"from": previous, "to": applied}),
            client=client_ip(request),
        )
        return LogLevelInfo(
            level=applied,
            configured=getattr(request.app.state, "configured_log_level", None),
            levels=list(LOG_LEVELS),
        )

    @app.get("/logs/tail", response_model=LogTailPage)
    async def get_logs_tail(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_phi_read(Permission.LOGS_VIEW)),
        limit: int = Query(200, ge=1, le=2000),
        offset: int = Query(0, ge=0),
    ) -> LogTailPage:
        """A paginated, **redacted** page of the newest application-log file's tail (#171, ADR 0130) — the
        in-console viewer over the same redacted tail the support bundle produces. ``offset`` counts lines
        back from the END (``offset=0`` = the most recent ``limit`` lines).

        This is a genuine **new PHI read surface**: the app log is best-effort-redacted (a residual
        single-token identifier can survive), so it rides ``require_phi_read`` — folding the ADR 0092
        ``enforce_phi_read_hop`` data-path guard (a prod-PHI instance on an unproven-secure serve hop
        refuses to emit) + the per-actor anti-automation throttle — under the new ``logs:view`` permission,
        exactly like a message-detail read. Each served page writes a ``logs_view`` audit row counting how
        many lines were exposed (**metadata only, never the content**). Degrades gracefully to an empty,
        ``available=false`` page when no ``[logging].log_dir`` is configured or the file is unreadable."""
        log_dir = getattr(request.app.state, "log_dir", None)
        # Blocking file read + redaction pass — off the event loop, like /status app-log metering.
        lines, total, available = await asyncio.to_thread(
            _read_log_tail, log_dir, limit=limit, offset=offset
        )
        # Audit the redacted-log read like a message view (#171): actor + how many lines were exposed, never
        # the content. Only when something was actually served, so a poll of an empty/unconfigured tail
        # doesn't flood the chain.
        if lines:
            await engine.store.record_audit(
                "logs_view",
                actor=identity.username,
                detail=json.dumps({"lines": len(lines), "offset": offset, "total": total}),
                client=client_ip(request),
            )
        return LogTailPage(
            lines=lines, total_lines=total, offset=offset, limit=limit, available=available
        )

    # --- attested service-to-service identity (ADR 0083, #200 activation) ----
    # The ONLY route authenticated by a verified mTLS client cert instead of a bearer token: it lets a
    # peer service confirm the principal its certificate maps to (a service-mesh "whoami"). It is
    # deliberately non-PHI and non-step-up — require_service_cert admits the cert-identity plane, which
    # carries no second factor and must never reach the interactive / PHI surface. Under stock uvicorn (no
    # mTLS + no cert-identity map) no cert ever surfaces, so this 401s: byte-identical to before.

    @app.get("/service/identity")
    async def service_identity(
        request: Request,
        engine: Engine = Depends(_get_engine),
        identity: Identity = Depends(require_service_cert(Permission.MONITORING_READ)),
    ) -> dict[str, object]:
        """Echo the MessageFoundry principal that this request's verified client certificate maps to
        (username + granted roles). Non-PHI, read-only; used by a peer service to confirm its cert-identity
        wiring end-to-end. Returns 401 when no mapped/verified client cert is presented (deny-by-default).

        #200 residual (ADR 0083/0092): a successful mTLS cert authentication is recorded in the tamper-
        evident audit chain (``service_cert_auth``) so intra-service auth is not a silent admission — an
        operator can see which principal a peer service's certificate authenticated as, and when. The
        audit carries only the mapped username + the auth plane (never a cert body / PHI)."""
        await engine.store.record_audit(
            "service_cert_auth",
            actor=identity.username,
            detail=json.dumps({"auth": "mtls-client-cert", "route": "/service/identity"}),
            client=client_ip(request),
        )
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
        identity: Identity = Depends(require_paced(Permission.DR_OPERATE)),
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
        identity: Identity = Depends(require_paced(Permission.DR_OPERATE)),
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
        _user: Identity = Depends(require_paced(Permission.MONITORING_DIAGNOSE)),
    ) -> IntegrityResult:
        """Run a database integrity check on demand (PRAGMA quick_check).

        Paced by the #193 per-actor floor (ASVS 2.4.2): a full-scan integrity check is a costly write-
        surface operation, so it draws from the shared admin-write pacing bucket like the other mutating
        POSTs rather than being callable in an unthrottled loop."""
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
                outbox_by_status = await engine_obj.store.stats()
                frame: dict[str, Any] = {"outbox_by_status": outbox_by_status}
                # BACKLOG #76: feed the metrics-history ring from the counts we ALREADY fetched (zero
                # extra store I/O); record() dedupes on its ~1s min-interval so several open sockets never
                # double-append the same instant. Metadata only (aggregate counts, no message body).
                history = getattr(state, "metrics_history", None)
                if history is not None:
                    history.record(time.time(), outbox_by_status)
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
            # ASVS 15.2.4: this string is an INSTALL INSTRUCTION the operator will paste. It named a
            # `webconsole` EXTRA that does not exist (pyproject deliberately withholds it until the
            # wheel is published — see the note beside [project.optional-dependencies]),
            # so the command failed; and an instruction to fetch an UNPUBLISHED distribution name from
            # a public index is the dependency-confusion surface this cell is about. Point at the path
            # install, which is what actually works today and resolves no index at all.
            raise RuntimeError(
                "serve_ui requires the web console, which is not installed. It ships as a separate "
                "distribution: `pip install messagefoundry-webconsole`, or set [api].serve_ui=false "
                "to run JSON-only."
            ) from exc

        # Assert the seam BEFORE building the deps bundle (review fix): a package that changed the
        # UiDeps/CoreHandlers shape for a new seam would otherwise trip at construction with a raw
        # kwargs TypeError; this raises a clear UiSeamMismatch first.
        assert_engine_seam(ENGINE_UI_SEAM)
        # Either source may know: create_managed_app passes the config flag; a caller that
        # constructs with auth= directly (tests, embedders) gets it from the live service.
        ui_oidc_enabled = oidc_enabled or bool(getattr(auth, "oidc_enabled", False))
        # ASVS 3.7.3 (seam v17). Read off security_settings when present; the fallbacks are the
        # STRICT position, so a caller that constructs without them gets the interstitial on every
        # absolute destination rather than silently getting none.
        _sec = security_settings

        def _oidc_authorization_host(endpoint: str) -> str:
            """ASCII/punycode host of the configured IdP endpoint, for DISPLAY only.

            Local rather than imported from ``messagefoundry_webconsole._external``: the console is
            deliberately not imported at module scope here (see the note above ``create_app``). An
            unparseable endpoint yields ``""``, which the console treats as *unknown destination* and
            therefore as a reason to SHOW the interstitial, never to skip it.
            """
            from urllib.parse import urlsplit

            try:
                host = (urlsplit(endpoint).hostname or "").strip().lower()
                return host.encode("idna").decode("ascii").lower() if host else ""
            except (ValueError, UnicodeError):
                return ""

        deps = UiDeps(
            engine_seam=ENGINE_UI_SEAM,
            oidc_enabled=ui_oidc_enabled,
            organization_domains=tuple(getattr(_sec, "organization_domains", ()) or ()),
            external_link_interstitial=bool(getattr(_sec, "external_link_interstitial", True)),
            external_link_allowlist=tuple(getattr(_sec, "external_link_allowlist", ()) or ()),
            oidc_authorization_host=_oidc_authorization_host(oidc_authorization_endpoint),
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
                suspend_alert=suspend_alert,
                resume_alert=resume_alert,
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
                upload_file=upload_file,
                list_uploaded_files=list_uploaded_files,
                browse_uploaded_file=browse_uploaded_file,
                resend_uploaded_message=resend_uploaded_message,
                delete_uploaded_file=delete_uploaded_file,
                list_search_presets=list_search_presets,
                create_search_preset=create_search_preset,
                delete_search_preset=delete_search_preset,
                layered_search=layered_search,
                metrics_history=metrics_history,
                graph_edges=graph_edges,
                set_connection_flag=set_connection_flag,
            ),
            admin=admin,
        )
        mount_ui(app, deps)

    # ASVS 1.3.4 — registered AFTER mount_ui so Starlette puts it OUTSIDE the console's
    # UiSecurityHeadersMiddleware as well as the engine's own /ui CSP overlay (add_middleware inserts at
    # index 0, so a later registration is further out and its response-path send wrapper runs LAST).
    # Both of those ASSIGN a /ui CSP on any non-static /ui path, which includes the console's attachment
    # delegate — without this the route's sandbox CSP would be silently replaced there. Registered
    # OUTSIDE the serve_ui guard so the JSON-only deployment is covered identically.
    app.add_middleware(AttachmentSecurityHeadersMiddleware)

    # ASVS 15.1.3/15.2.2 (BACKLOG #1044) — the server-side deadline on BUILDING a response. Nothing
    # bounded a handler before this: the only asyncio.wait_for in api/ caps the connection-test
    # probe, so a slow handler held its worker for as long as it ran and the client's own timeout
    # was the only thing that ever gave up (which does not free the server).
    #
    # Registered here so it lands OUTSIDE every earlier registration — the attachment CSP re-assert,
    # the console's UiSecurityHeadersMiddleware, the body cap, the security-headers middleware and
    # every auth dependency are all inside the deadline, which is what makes it a bound on the whole
    # request rather than on the route function alone. It stays INSIDE ClientNetworkMiddleware
    # (registered after it, so further out): a refused address must be rejected before it can occupy
    # a deadline at all. The clock is cancelled at http.response.start, so a response that has begun
    # streaming is never cut mid-body — see api/request_timeout.py.
    app.add_middleware(RequestTimeoutMiddleware)

    # [security].allowed_client_networks — registered so that only the response-header floor below is
    # further out. It therefore runs above the attachment CSP re-assert, the console's
    # UiSecurityHeadersMiddleware, the body cap, the security-headers middleware, the /ui/static mount
    # and every auth dependency — a refused address reaches no route, no dependency and no body buffer.
    # The floor does not weaken that: it runs NOTHING on the request path (it wraps `send` only), so it
    # adds no reachable surface ahead of the gate. Registered OUTSIDE serve_ui so a JSON-only deployment
    # is equally covered, and unconditionally so the control can never be silently missing after a
    # config edit (an empty list short-circuits inside it).
    #
    # It must stay INSIDE uvicorn's ProxyHeadersMiddleware, which it is automatically by being part of
    # the app uvicorn wraps. Do NOT wrap the app in __main__ before uvicorn.run: that would put the
    # gate OUTSIDE the XFF rewrite, where scope["client"] is still the raw socket peer, and the
    # declared-proxy topology (R2) would break completely — every client would look like the proxy.
    app.add_middleware(ClientNetworkMiddleware)

    # ASVS 3.4.4/3.4.5 — registered LAST, so Starlette makes it the OUTERMOST user middleware
    # (add_middleware inserts at index 0; the stack is built from reversed(user_middleware)) and its
    # response-path send wrapper runs after every other emitter. That position is the whole point:
    # _security_headers is the INNERMOST user middleware, so the body cap's four short-circuits above
    # shipped with no baseline headers at all, and both middlewares that hand-copy the baseline
    # (client_networks._DENIAL_HEADERS, request_timeout._TIMEOUT_HEADERS) omit HSTS. The floor
    # setdefaults, never assigns, so the attachment sandbox CSP re-asserted above and every other
    # last-writer-wins header is untouched. See api/header_floor.py — including why it CANNOT cover the
    # unhandled 500 (ServerErrorMiddleware sits outside user_middleware; _unhandled_exception sets the
    # same baseline itself) and why the path-conditional Cache-Control/CSP is deliberately not copied.
    app.add_middleware(SecurityHeaderFloorMiddleware)

    return app


async def _assert_security_notice_is_deliverable(
    store: Store,
    *,
    auth_settings: AuthSettings | None,
    alerts_settings: AlertsSettings | None,
    ai_settings: AiSettings | None,
    security_settings: SecuritySettings | None,
) -> None:
    """BACKLOG #1020: refuse to serve a PHI instance whose security notices reach NOBODY.

    The serve gate in ``messagefoundry/__main__.py`` already refuses without a notification channel,
    but it computes readiness from ``notify_security_events`` + ``email_smtp_host`` + ``email_from``
    -- **SMTP wiring alone**. That asks *"is a transport configured"* and never *"can the account
    that matters actually receive"*: the instrument answering the adjacent question (SDS-3.8). On a
    first run the only account that exists is the bootstrap administrator, created with no address,
    so the gate passes green while every one of the ten notice types about the account holding
    ``frozenset(Permission)`` silently no-ops -- including ``LOGIN_AFTER_FAILURES``, the classic
    someone-guessed-it signal.

    **This check must live here and not beside the transport gate.** ``_serve`` is synchronous and
    opens no store, so at that point there is no user table to ask. The ASGI lifespan is the only
    place the store and the freshly minted bootstrap admin are both in hand -- which is why the
    owner's ruling (option (b), 2026-08-13) corrected the item's own stated fix location.

    **Why deliverability rather than "require an email at creation".** ``update_user_profile`` issues
    ``UPDATE users SET display_name=?, email=?`` unconditionally on every directory login, so any
    address a human sets on an AD or OIDC account is overwritten at that holder's next sign-in. A fix
    resting on an OPERATOR ACTION cannot cover that population; a startup assertion about the state
    of the table can.

    Deliberately narrow: it asks only whether SOME enabled administrator carries an address, not
    whether mail to it would arrive. Proving actual delivery needs an SMTP round trip at startup,
    which is a different and much larger change.
    """
    auth_settings = auth_settings or AuthSettings()
    if not auth_settings.enabled or not auth_settings.notify_security_events:
        return  # no notices to deliver; the transport gate already governs whether that is allowed
    alerts = alerts_settings or AlertsSettings()
    if not alerts.security_notifications_required:
        return  # the audited, in-writing opt-out -- the pull-only feed is accepted
    data_class, _production = (ai_settings or AiSettings()).derived_posture()
    if data_class is not DataClass.PHI:
        return
    for user in await store.list_users():
        if user.disabled or not user.email:
            continue
        if Role.ADMINISTRATOR.value in await store.get_user_role_ids(user.id):
            return
    detail = (
        "no enabled Administrator has an email address, so every out-of-band security notice about "
        "the most privileged accounts would be silently dropped (SecurityEventNotifier returns "
        "early when the recipient has no address). The [alerts] SMTP transport being configured "
        "does not make a notice deliverable -- on a first run the bootstrap administrator is created "
        "without one. Set an address on at least one enabled Administrator, or accept the pull-only "
        "/me/security-events feed in writing via [alerts].security_notifications_required=false."
    )
    enforcement = (security_settings or SecuritySettings()).enforcement
    if enforcement is SecurityEnforcement.ENFORCE:
        raise RuntimeError(f"refusing to start a PHI instance: {detail}")
    _log.warning("PHI instance with no deliverable security-notice recipient: %s", detail)


def _emit_bootstrap_admin(bootstrap: BootstrapAdmin, store_settings: StoreSettings) -> None:
    """Persist the one-time bootstrap password to a restricted file — never the rotating log.

    Until rotated it is a standing Administrator credential, so it must not land in NSSM's broadly
    readable stdout capture. Write it to an owner-only file the operator consumes and deletes; log
    only the location. Paired with server-side must_change_password enforcement, it dies at first login.
    """
    base = Path(store_settings.path or ".").resolve()
    secret_file = base.parent / "bootstrap-admin.txt"
    body = f"username: {bootstrap.username}\npassword: {bootstrap.password}\n"
    # ASVS 6.4.5: state the renewal deadline WITH the credential — an unclaimed bootstrap is
    # auto-disabled at this instant, so the "sign in and change it before then" instruction ships
    # alongside the secret rather than being an out-of-band assumption. None when expiry is off.
    deadline = (
        datetime.datetime.fromtimestamp(bootstrap.expires_at, tz=datetime.UTC).isoformat()
        if bootstrap.expires_at is not None
        else None
    )
    if deadline is not None:
        body += (
            f"expires: {deadline} — sign in and change this password before then, "
            "or the unclaimed credential is disabled.\n"
        )
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
        "delete that file%s.",
        bootstrap.username,
        secret_file,
        f" (expires {deadline} unless claimed)" if deadline is not None else "",
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


async def _directory_reconciler(auth: AuthService, interval: float) -> None:
    """Re-resolve directory principals holding live sessions, revoking those AD has disabled or
    deleted (ADR 0079 mechanism 2). Created only when ``[auth].ad_session_recheck_seconds`` is set
    AND AD is wired — at the default 0 no task exists and the upgrade is byte-identical.

    Sleeps FIRST: a pass at startup would probe every session restored from the store before the
    directory connection has been exercised even once, and a boot-time DC hiccup is the least
    informative moment to run a control whose whole job is telling a real disable from a blip.

    A transient failure must not kill the loop for the process lifetime (that would silently disable
    the control until restart) — log and retry next interval, the session-reaper precedent."""
    while True:
        await asyncio.sleep(interval)
        try:
            await auth.reconcile_directory_sessions()
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("directory reconcile: pass failed; will retry next interval")


_BOOTSTRAP_EXPIRY_REMINDER_INTERVAL = 3600.0  # re-check the bootstrap warn window hourly


async def _bootstrap_expiry_reminder(auth: AuthService, sink: AlertSink) -> None:
    """Remind an operator, ONCE, that an UNCLAIMED first-run bootstrap admin is nearing its auto-disable
    deadline (ASVS 6.4.5 arm 2). API-lifespan-owned (like :func:`_session_reaper`), NOT engine-owned — it
    reaches the :class:`AuthService` directly. ``auth.bootstrap_expiry_warning()`` evaluates the warn
    window and latches once-per-process; a non-None result is the fresh reminder to emit as the PHI-free
    ``bootstrap_admin_expiring`` alert (the ISO deadline + whole hours remaining — never the password).

    A transient store error must not kill the loop for the process lifetime (that would silently drop the
    reminder) — log and retry next interval, the session-reaper precedent."""
    while True:
        try:
            warning = await auth.bootstrap_expiry_warning()
            if warning is not None:
                expires_at, hours_remaining = warning
                iso = datetime.datetime.fromtimestamp(expires_at, tz=datetime.UTC).isoformat()
                sink.bootstrap_admin_expiring(
                    "bootstrap-admin", expires_at=iso, hours_remaining=hours_remaining
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("bootstrap expiry reminder: pass failed; will retry next interval")
        await asyncio.sleep(_BOOTSTRAP_EXPIRY_REMINDER_INTERVAL)


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
    audit_all_authz: bool = False,  # #244 [diagnostics].audit_all_authz (ASVS 16.3.2) → app.state
    env_values: Mapping[str, Any] | None = None,
    env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
    auth_settings: AuthSettings | None = None,
    ai_settings: AiSettings | None = None,
    security_settings: SecuritySettings | None = None,
    alerts_settings: AlertsSettings | None = None,
    secrets_settings: SecretsSettings | None = None,
    priority_default: Priority | None = None,
    retention_settings: RetentionSettings | None = None,
    cert_monitor_settings: CertMonitorSettings | None = None,
    secret_rotation_settings: SecretRotationSettings | None = None,
    security_enforcement: SecurityEnforcement | None = None,
    update_check_settings: UpdateCheckSettings | None = None,
    backup_settings: BackupSettings | None = None,
    dr_settings: DrSettings | None = None,
    api_tls_cert_file: str | None = None,
    api_tls_client_cert_files: Sequence[str] = (),
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
    loopback: bool = False,
    tls_terminated_upstream: bool = False,
    tls_client_cert_identities: Mapping[str, str] | None = None,
    trusted_proxies: Sequence[str] = (),
    phi_read_hop_secure: bool = True,
    registry_filter: Callable[[Registry], Registry] | None = None,
    log_dir: str | None = None,
    configured_log_level: str | None = None,
    trust_anchor_specs: Sequence[AnchorSpec] = (),
    trust_anchors_enforcing: bool = True,
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
        # #329: the derived instance hop posture, computed ONCE here for the OUT-OF-GATE cells this
        # lifespan builds — the alerts webhook sink (notifier_from_settings) and the LDAPS bind
        # (AuthService → LdapAuthenticator). Neither is built inside an active_hop_posture scope, so
        # current_hop_posture() is None there and their weakened-TLS escape would ship UNCLAMPED (green
        # and inert) without an explicit posture; threading this makes the ADR-0092 clamp apply on first
        # deployment. None when the instance declares no [ai] (SQLite/test) → the unclamped escape,
        # byte-identical. Reuses the same hop_posture_from_ai derivation the store hop and the runner use.
        _hop_posture = (
            hop_posture_from_ai(
                ai_settings, enforcement=(security_settings or SecuritySettings()).enforcement
            )
            if ai_settings is not None
            else None
        )
        # #200 (ADR 0092 decision 2): thread the derived instance posture so the engine<->store weakened-
        # TLS refusal (connection_string / _build_ssl) clamps MEFOR_ALLOW_INSECURE_TLS — the escape can
        # never relax a production-PHI store hop. None when no [ai] (SQLite/test) → unclamped, unchanged.
        store = await open_store(
            resolved,
            message_events=message_events,
            posture=_hop_posture,
        )
        # Offline uploaded-logs store (BACKLOG #125/#126, ADR 0134), on the LIVE store's cipher instance.
        # DISABLED (None) unless [store].uploads_dir is set, so no PHI-at-rest surface exists unless an
        # operator opts in; every uploaded-logs route 503s when None.
        #
        # ASVS 11.3.4 — it MUST share the store's cipher object, not build a second one over the same
        # DEK: the AES-GCM invocation bound is per-instance state, so a second instance would charge
        # nothing to the key's persisted `cipher_meta` row (an under-count in the unsafe direction) and
        # would keep encrypting under a key the store's cipher had already fail-closed on at 2**32.
        if resolved.uploads_dir:
            app.state.upload_store = UploadStore(
                resolved.uploads_dir,
                store.cipher(),
                max_bytes=resolved.max_upload_bytes,
                # ASVS 5.2.4: thread the operator's per-user quota + retention values into the SERVE
                # path too. This lifespan rebuild exists to share the store's cipher (the 11.3.4 GCM
                # bound); it must NOT drop the quota/retention knobs, or serve silently falls back to the
                # 100/250 MiB/30 d UploadStore defaults and ignores operator [store] config (create_app
                # wires them at build time; only this rebind was missing them).
                max_files_per_user=resolved.max_upload_files_per_user,
                max_total_bytes_per_user=resolved.max_upload_total_bytes_per_user,
                retention_days=resolved.uploads_retention_days,
                # ASVS 2.3.4: bind the cross-shard quota ledger to the SAME store this lifespan just
                # opened — this is the serve path, so it is the one that actually runs sharded.
                store=store,
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
            notifier_from_settings(
                alerts_settings,
                secret_provider=secret_provider,
                # #323 layer 3: the instance [tls] internal-CA policy reaches the alerts SMTP hop too, so
                # an estate on a private CA needs no per-alert CA path.
                trust_anchor_policy=tls_settings.policy() if tls_settings else None,
                # #329: clamp the webhook sink's cleartext-http escape to the derived instance posture.
                posture=_hop_posture,
            )
            if alerts_settings is not None
            else None
        )
        if notifier is not None:
            # Durable operator alert-state (ADR 0044, #56): wire the open store so every emit upserts a
            # resolvable alert instance (GET /alerts/active) and an inverse signal auto-resolves it. A
            # pure side observer off the emit path — never gates a disposition, never blocks a worker.
            notifier.set_store(store)
            notifier.start()
            # #143 (ADR 0044 amendment): seed the sink's windowed-suspend cache from durable
            # alert_instance.suspended_until so an operator suspend set before this process started is
            # honored from the first emit. Best-effort (a store error is swallowed; notify path unaffected).
            await notifier.prime_suspensions()
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
        # #285 (ASVS 6.7.1): preflight every operator-supplied auth-path trust anchor (OIDC / AD /
        # api-mTLS client CA) BEFORE any listener binds — a group/world-writable anchor refuses (at
        # enforce) or warns+audits, a configured SHA-256 pin mismatch always refuses, and a fingerprint
        # change since the last load is audited (auth.trust_anchor). Dormant (no store call, no audit)
        # when no anchor is configured. On a fatal violation it raises, so we tear down like attestation.
        if trust_anchor_specs:
            try:
                await run_anchor_preflight(
                    trust_anchor_specs, store, enforcing=trust_anchors_enforcing
                )
            except BaseException:
                if notifier is not None:
                    await notifier.aclose()
                await store.close()
                raise
        # Cluster coordinator (Track B Step 3) — built from the opened store so a Postgres-backed
        # store can reach its pool. Returns the no-op NullCoordinator unless [cluster].enabled on a
        # Postgres store, so single-node is byte-identical. The Engine owns its lifecycle (start/stop
        # in engine.start()/stop()), so the lifespan only constructs + passes it here.
        # #145: thread the alert notifier so a leadership transition (HA failover / election) pages via
        # leadership_acquired/lost. None → the coordinator's default LoggingAlertSink logs the transition.
        coordinator = build_coordinator(store, cluster_settings, alert_sink=notifier)
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
            security_enforcement=security_enforcement,
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
            api_tls_client_cert_files=api_tls_client_cert_files,
            api_listener=api_listener,
            reference_settings=reference_settings,
            egress_settings=egress_settings,
            # #200 (ADR 0092): the derived (PHI? production?) posture the connector-construction gate keys
            # its posture-keyed insecure-hop refusal on. Derived from [ai] here (the one place ai_settings
            # is in scope) so every runner this engine builds refuses/warns identically. None when the
            # instance declares no [ai] (test/embedding) — a cell then fail-closes.
            hop_posture=(
                hop_posture_from_ai(
                    ai_settings, enforcement=(security_settings or SecuritySettings()).enforcement
                )
                if ai_settings
                else None
            ),
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
        # #1257: hoisted above the try because the finally below now guards STARTUP too, and it
        # reaches these names before it reaches engine.stop(). Left in place inside the span, a
        # failure before they were bound raises UnboundLocalError IN THE TEARDOWN, which aborts it
        # early -- so the store never closes and the process hangs exactly as it did before the
        # fix, with the real startup error replaced by the UnboundLocalError. Measured by removing
        # one of these five: the hang came straight back. They are load-bearing, not tidiness.
        upload_retention_runner: UploadRetentionRunner | None = None
        reaper: asyncio.Task[None] | None = None
        reconciler: asyncio.Task[None] | None = None
        bootstrap_reminder: asyncio.Task[None] | None = None
        security_notifier = None
        # The teardown guards this ENTIRE span, not just the yield. Everything started below --
        # the engine, both notifiers, the retention runner, the three tasks -- was otherwise
        # abandoned in place on a startup failure. engine.stop() ends in store.close(), and
        # aiosqlite's connection worker is NON-DAEMON, so skipping it left the process unable to
        # exit: uvicorn refused correctly, printed 'Exiting.', and then hung forever.
        try:
            await engine.start()
            # #144 (ADR 0128): inject the connection-control callback INTO the notifier (the sink never imports
            # RegistryRunner). A rule's control_action then auto-remediates via restart_inbound/restart_outbound;
            # re-reading engine.registry_runner each call keeps it correct across a config reload that swaps the
            # runner. The sink dispatches this off-worker + never-raise, so exceptions here are logged, not fatal.
            if notifier is not None:

                async def _alert_control(action: str, target: str) -> None:
                    rr = engine.registry_runner
                    if rr is None:
                        return
                    if action == "restart_inbound":
                        await rr.restart_inbound(target)
                    elif action == "restart_outbound":
                        await rr.restart_outbound(target)

                notifier.set_control_callback(_alert_control)
            app.state.engine = engine
            # #285: stash the trust anchors so /config/reload re-verifies the on-disk PEMs (a swapped anchor
            # is caught + audited, a pinned-but-substituted anchor refuses the deploy) — the reload seam.
            app.state.trust_anchor_specs = tuple(trust_anchor_specs)
            app.state.trust_anchors_enforcing = trust_anchors_enforcing
            app.state.store_settings = resolved  # back GET /security/posture (M5)
            app.state.alerts_settings = alerts_settings
            # #143: expose the running notifier so POST /alerts/{id}/suspend|resume can update its in-memory
            # suspend cache live (None here in a JSON-only/no-transport deployment — the durable store governs).
            app.state.notifier = notifier
            # ASVS 6.4.5: the cert-identity resolver reads [cert_monitor].warn_days off app.state to decide
            # whether a service caller's client cert, observed at the mTLS handshake, is inside the warn
            # window. None (the direct create_app / embedding path) leaves that check inert — deny-by-default
            # for a monitoring signal, and byte-identical to before.
            app.state.cert_monitor_settings = cert_monitor_settings
            # #118: expose the connector SecretProvider so POST /alerts/test-email can resolve an
            # email_password_secret reference (fail-closed) exactly as notifier_from_settings does. None on
            # the embedded/test path — then only a plain env-sourced email_password can be tested.
            app.state.secret_provider = secret_provider
            # #323 layer 3: expose the [tls] trust-anchor policy so POST /alerts/test-email builds its
            # EmailTransport with the SAME anchors as the live notifier. None on the embedded/test path.
            app.state.tls_settings = tls_settings
            app.state.service_settings = service_settings  # back GET /service/status (L6a)
            app.state.log_dir = log_dir  # back GET /status app-log metering (#50)
            app.state.approval_gate = _build_approval_gate(
                engine, approvals_settings or ApprovalsSettings()
            )
            # ASVS 5.2.4: age-based retention prune for the uploaded-logs surface. Owned by this lifespan
            # (started here, stopped in the finally) — the runner pattern of cert_expiry, but wired where the
            # UploadStore lives (built in create_app from store_settings). None when [store].uploads_dir is
            # unset (the subsystem is opt-in), so a deployment without uploaded logs spawns no task. The audit
            # callback closes over the opened store so the leaf uploads module never imports it.
            _upload_store: UploadStore | None = getattr(app.state, "upload_store", None)
            if _upload_store is not None:

                async def _audit_upload_prune(meta: UploadedFileMeta) -> None:
                    # BACKLOG #1224: the retention runner has no operator and no request behind it, so
                    # the row is attributed to the system principal (matching pipeline/retention.py's
                    # `retention_purge`) rather than to the pruned file's uploader. The uploader is
                    # carried as DATA in `detail`, where a reader can still see whose file went. Both
                    # this site and the request-path sweep had to change together: fixing one would have
                    # left the same false attribution reachable by the other path.
                    await store.record_audit(
                        "upload.prune",
                        actor="system",
                        detail=json.dumps(
                            {
                                "file_id": meta.file_id,
                                "uploader": meta.uploader,
                                "uploader_id": meta.uploader_id,
                            }
                        ),
                    )

                upload_retention_runner = UploadRetentionRunner(
                    _upload_store, audit=_audit_upload_prune
                )
                upload_retention_runner.start()
            # Back the COMPLETE loosening list on GET /security/posture: [auth] carries posture switches
            # (ad_session_recheck_seconds) that security_loosenings() must see. Stashed here, OUTSIDE the
            # `enabled` guard below, deliberately — a settings object that exists but is disabled is still
            # the resolved settings, and stashing it only on the enabled path would make the route silently
            # fall back to AuthSettings() defaults and report a subset. Mirrors store_settings above.
            if auth_settings is not None:
                app.state.auth_settings = auth_settings
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
                        alerts_settings,
                        secret_provider=secret_provider,
                        trust_anchor_policy=tls_settings.policy() if tls_settings else None,
                    )
                    if security_notifier is not None:
                        security_notifier.start()
                auth = AuthService(
                    store,
                    auth_settings,
                    security_notifier=security_notifier,
                    secret_provider=secret_provider,
                    # #285 (ASVS 6.7.1): pass the enforcement dial so the OIDC anchor's construction-site
                    # preflight in build_idp_opener honors [security].enforcement — warn+audit (via the
                    # central run_anchor_preflight above) rather than refusing at enforce-only. Central
                    # preflight already ran before any listener bound; this keeps the seam consistent.
                    enforcing=trust_anchors_enforcing,
                    # #329: thread the derived instance posture to the LDAPS bind so its ad_tls_verify=false
                    # escape is clamped on an enforcing-PHI instance (LdapAuthenticator is built out of the
                    # connector-construction gate, so the clamp is inert unless the posture arrives here).
                    hop_posture=_hop_posture,
                )
                bootstrap = await auth.initialize()
                app.state.auth = auth
                if bootstrap is not None:
                    _emit_bootstrap_admin(bootstrap, resolved)
                await _assert_security_notice_is_deliverable(
                    store,
                    auth_settings=auth_settings,
                    alerts_settings=alerts_settings,
                    ai_settings=ai_settings,
                    security_settings=security_settings,
                )
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
                if auth.oidc_enabled:
                    # ADR 0142: a CONFIG-ONLY preflight. Deliberately NOT the Kerberos shape above —
                    # it performs no network I/O and cannot mark the IdP unavailable, because
                    # "must not make a reachable IdP a precondition for operating the engine" is an
                    # explicit ADR constraint and AC-8 wants recovery without a restart. The settings
                    # validators already refuse a misconfigured [auth].oidc_* at load (AC-9), so this
                    # only surfaces the posture an operator should see in the boot log.
                    _log.info(
                        "Federated sign-in (OIDC) is ENABLED for the browser console: issuer=%s "
                        "redirect=%s. The engine verifies what the IdP ASSERTS about MFA, "
                        "cryptographically — it cannot prove the IdP enforced it.",
                        auth_settings.oidc_issuer,
                        auth_settings.oidc_redirect_path,
                    )
                reaper = asyncio.create_task(_session_reaper(store))
                if auth.bootstrap_deadline_configured:
                    # ASVS 6.4.5 arm 2: nudge an operator BEFORE an unclaimed first-run bootstrap admin is
                    # auto-disabled. API-lifespan-owned (like the session reaper), NOT engine-owned — it
                    # reaches the AuthService directly. The warn method latches once-per-window; the sink logs
                    # (LoggingAlertSink fallback) or notifies. No task when NEITHER bound is configured.
                    #
                    # BACKLOG #1141: this open-coded `auth_settings.bootstrap_expiry_hours > 0`, a THIRD copy
                    # of a question `bootstrap_expiry_warning` answers over TWO bounds — WP-3 account
                    # retirement AND the ASVS 6.4.1 credential expiry. At bootstrap_expiry_hours=0 with
                    # initial_password_expiry_hours set, that method computed a correct deadline and this
                    # task — ITS ONLY CONSUMER — was never created, so the warning arm was SILENTLY DEAD.
                    # BACKLOG #1245 corrected the two computations in auth/service.py and never reached the
                    # gate deciding whether they run. Ask the AuthService, which owns the predicate now.
                    bootstrap_reminder = asyncio.create_task(
                        _bootstrap_expiry_reminder(auth, notifier or LoggingAlertSink())
                    )
                if auth.directory_reconcile_enabled:
                    # ADR 0079 mechanism 2: propagate an AD disable/delete to live engine sessions.
                    # Default OFF (ad_session_recheck_seconds = 0) — no task, no behaviour change.
                    _log.info(
                        "Directory session reconciliation is ENABLED: live AD sessions are "
                        "re-resolved every %ds; a principal absent from the directory for %d "
                        "consecutive passes has its sessions revoked. A directory outage revokes "
                        "NOTHING, and a pass that would revoke too many at once aborts and alerts.",
                        auth_settings.ad_session_recheck_seconds,
                        auth_settings.ad_session_recheck_strikes,
                    )
                    reconciler = asyncio.create_task(
                        _directory_reconciler(auth, auth_settings.ad_session_recheck_seconds)
                    )
            yield
        finally:
            if upload_retention_runner is not None:
                await upload_retention_runner.stop()
            if reconciler is not None:
                reconciler.cancel()
                await asyncio.gather(reconciler, return_exceptions=True)
            if reaper is not None:
                reaper.cancel()
                # gather(return_exceptions): absorbs both our cancellation AND any exception a
                # previously-died reaper stored, so it can't propagate here and skip engine.stop()
                # (review M-33).
                await asyncio.gather(reaper, return_exceptions=True)
            if bootstrap_reminder is not None:
                bootstrap_reminder.cancel()
                # gather(return_exceptions): absorb our cancellation + any stored exception so it can't
                # propagate here and skip engine.stop() (the reaper precedent).
                await asyncio.gather(bootstrap_reminder, return_exceptions=True)
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
        # Build the opt-in uploaded-logs store in the SERVE path too (previously only the direct/test
        # path passed store_settings, so `serve` never wired it): the ASVS 5.2.4 retention runner above
        # needs a live UploadStore to prune. None uploads_dir → create_app leaves upload_store None.
        store_settings=resolved,
        ai_settings=ai_settings,
        security_settings=security_settings,
        expose_docs=expose_docs,
        allow_no_auth=allow_no_auth,
        audit_all_authz=audit_all_authz,
        ws_allowed_origins=ws_allowed_origins,
        serve_ui=serve_ui,
        oidc_enabled=bool(auth_settings is not None and auth_settings.oidc_enabled),
        oidc_authorization_endpoint=(
            (auth_settings.oidc_authorization_endpoint or "") if auth_settings is not None else ""
        ),
        public_origin=public_origin,
        webauthn_rp_from_request=webauthn_rp_from_request,
        exposure_protected=exposure_protected,
        loopback=loopback,
        tls_terminated_upstream=tls_terminated_upstream,
        tls_client_cert_identities=tls_client_cert_identities,
        trusted_proxies=trusted_proxies,
        phi_read_hop_secure=phi_read_hop_secure,
        configured_log_level=configured_log_level,
    )
