# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Operational **service settings** — deployment config, distinct from the code-first message graph.

The message graph (Connections/Routers/Handlers) is authored in Python and loaded from ``--config``;
this module covers the *operational* knobs an admin sets to run the service: where the store lives,
the API bind address, logging. They load from a TOML file + environment + CLI, with precedence::

    CLI flag  >  environment variable  >  messagefoundry.toml  >  built-in default

Secrets (e.g. a future DB password) belong in **env** (``MEFOR_<SECTION>_<KEY>``), never in the file.
This is the first cut (build-order step 1 of docs/CONFIGURATION.md): ``[store]`` (backend/path/
synchronous), ``[api]`` (host/port), and ``[logging]`` (level + structured-JSON ``format`` + off-box
``forward_*`` syslog shipping — sec-offbox-log). ``[retention]`` is now enforced (the
``RetentionRunner``), except its ``audit_days`` key, which is reserved/keep-forever by design.
Remaining planned keys (some server-DB ``[store]`` keys) are accepted-but-ignored for now so a
forward-looking config file still loads.
"""

from __future__ import annotations

import logging
import os
import re
import tomllib
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from messagefoundry.config.ai_policy import AiDataScope, AiMode, DataClass
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
)
from messagefoundry.config.tls_policy import validate_tls_ciphers
from messagefoundry.logging_setup import LOG_LEVELS

__all__ = [
    "StoreBackend",
    "SqliteSync",
    "SqlAuth",
    "StoreSettings",
    "ApiSettings",
    "InboundSettings",
    "DeliverySettings",
    "PipelineSettings",
    "EnvironmentsSettings",
    "LoggingSettings",
    "LogFormat",
    "SyslogProtocol",
    "ReferenceSettings",
    "RetentionSettings",
    "AuthSettings",
    "AiSettings",
    "AiMode",
    "AiDataScope",
    "DataClass",
    "EgressSettings",
    "ShadowSettings",
    "AlertsSettings",
    "ClusterSettings",
    "ApprovalsSettings",
    "ServiceSettings",
    "load_settings",
]

#: Known config sections (used to parse ``MEFOR_<SECTION>_<KEY>`` env vars).
_SECTIONS = (
    "store",
    "api",
    "inbound",
    "delivery",
    "environments",
    "logging",
    "reference",
    "retention",
    "auth",
    "ai",
    "egress",
    "shadow",
    "alerts",
    "cluster",
    "approvals",
)
_ENV_PREFIX = "MEFOR_"
_DEFAULT_FILE = "messagefoundry.toml"

_log = logging.getLogger(__name__)

#: (section, key) secrets that belong in env, never the config file (see _warn_file_secrets).
_FILE_SECRET_KEYS = (
    ("store", "password"),
    ("store", "encryption_key"),
    ("store", "encryption_keys_retired"),
    ("auth", "ad_bind_password"),
    ("alerts", "email_password"),
    ("api", "tls_key_password"),
)


class StoreBackend(str, Enum):
    SQLITE = "sqlite"
    SQLSERVER = (
        "sqlserver"  # production server-DB backend; full staged pipeline (see store/sqlserver.py)
    )
    POSTGRES = (
        "postgres"  # production server-DB backend with single-node parity (see store/postgres.py)
    )


class SqliteSync(str, Enum):
    NORMAL = "normal"  # crash-safe under WAL, no per-commit fsync (default)
    FULL = "full"


class SqlAuth(str, Enum):
    SQL = "sql"  # SQL login (username + password)
    INTEGRATED = "integrated"  # Windows Integrated auth
    ENTRA = "entra"  # Microsoft Entra ID (Azure AD)


class _Section(BaseModel):
    # Ignore unknown keys so a forward-looking file (planned retention/delivery keys) still loads.
    model_config = ConfigDict(extra="ignore")


#: Env var that explicitly permits MITM-able TLS overrides for a trusted-network dev/test bind.
INSECURE_TLS_ESCAPE_ENV = "MEFOR_ALLOW_INSECURE_TLS"


def insecure_tls_allowed() -> bool:
    """Whether the explicit dev escape to permit insecure TLS overrides is set (ASVS 12.3.2).

    Certificate-validation overrides (``ad_tls_verify=false`` for LDAPS, ``trust_server_certificate
    =true`` for SQL Server) are MITM-able, so they now **refuse** at startup unless
    ``MEFOR_ALLOW_INSECURE_TLS`` is truthy. This means a production deployment can't silently disable
    server-cert validation; an operator must opt in loudly for a trusted-network dev/test bind."""
    return os.environ.get(INSECURE_TLS_ESCAPE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


class StoreSettings(_Section):
    backend: StoreBackend = StoreBackend.SQLITE

    # --- SQLite (default backend) -------------------------------------------
    path: str = "messagefoundry.db"
    synchronous: SqliteSync = SqliteSync.NORMAL

    # --- PHI-at-rest encryption (both backends; STORE-1 / WP-5) -------------
    # Base64 32-byte ACTIVE key; when set, PHI columns (raw bodies + error/last_error/detail) are
    # AES-256-GCM-encrypted at rest. Secret — supply via MEFOR_STORE_ENCRYPTION_KEY, never the file.
    # Empty = off (values stored as-is).
    encryption_key: str | None = None
    # Comma-separated base64 RETIRED keys, kept available for *decrypt only* during a key rotation
    # (ASVS 11.2.2) until `messagefoundry rotate-key` finishes re-encrypting under the active key.
    # Secret — env-only (MEFOR_STORE_ENCRYPTION_KEYS_RETIRED). Empty = none.
    encryption_keys_retired: str = ""
    # When true, `serve` refuses to start without an encryption key (any environment). Off by default;
    # with it off, a 'prod' environment still gets a loud startup warning. See docs/PHI.md §3.
    require_encryption: bool = False
    # Windows DPAPI-protected key file (WP-11d, ASVS 13.3.1): a path produced by
    # `messagefoundry protect-key`. When `encryption_key` is unset and this is set, the active key is
    # CryptUnprotectData'd from this file at open — so the plaintext key never sits in the service
    # environment. This is a *path*, not a secret, so it may live in the config file. Windows-only;
    # the env key takes precedence. Empty = use `encryption_key` (the cross-platform default).
    encryption_key_file: str | None = None
    # KeyProvider seam (ADR 0019, ASVS 13.3.3): selects HOW the active/retired DEK bytes are *sourced* —
    # never how they are used (the cipher, keyring, and `mfenc:v1` format are unchanged). `auto` (the
    # default) is the env-then-DPAPI ladder, BYTE-IDENTICAL to the pre-seam behavior; `env`/`dpapi` pin a
    # single built-in source; `aws_kms`|`azure_kv`|`gcp_kms`|`vault`|`pkcs11` are external HSM/KMS/Vault
    # envelope-decrypt providers (lazy, optional extras — not built yet, fail closed if selected). This
    # names a *provider*, not key material, so it is NOT a secret — it must never be added to
    # `_FILE_SECRET_KEYS`. Unknown/unresolvable values fail closed at `open_store` (store/keyprovider.py).
    key_provider: str = "auto"

    # --- Server-DB backends (backend = "sqlserver" | "postgres") ------------
    # These connection fields are shared by every server-database backend. SQL Server consumes them
    # via an ODBC DSN (store/sqlserver.py); Postgres maps them onto asyncpg connection params
    # (store/postgres.py). trust_server_certificate/encrypt drive the TLS posture identically.
    server: str | None = None
    # Default is SQL Server's port (1433); for the Postgres backend a left-at-default 1433 is treated
    # as "use Postgres's conventional 5432" by the model_validator below, so a Postgres deployment that
    # omits `port` still connects (set MEFOR_STORE_PORT explicitly to override either default).
    port: int = 1433
    database: str | None = None
    auth: SqlAuth = SqlAuth.SQL
    username: str | None = None
    password: str | None = None  # secret — supply via MEFOR_STORE_PASSWORD, never the file
    encrypt: bool = True
    trust_server_certificate: bool = False
    pool_size: int = 5
    connect_timeout: int = 15  # seconds
    command_timeout: int = 30  # seconds
    db_schema: str | None = (
        None  # 'db_schema' avoids shadowing BaseModel.schema; env: MEFOR_STORE_DB_SCHEMA
    )
    application_name: str = "messagefoundry"
    # Inflight-row lease TTL (seconds) for the multi-node server-DB backends (Track B Step 2). When a
    # worker claims a row it stamps owner + a lease_expires_at = now + this; a renew timer extends it
    # while processing, and a leader sweep reclaims only rows whose lease has expired (so a crashed
    # node's work is recovered without stealing a live sibling's in-flight rows). A shared server-DB
    # field — harmless to SQL Server / SQLite, which don't lease and ignore it. The lease is wall-clock
    # across nodes, so the no-theft guarantee assumes clocks are NTP-synced to well within this TTL;
    # set it comfortably larger than expected clock skew + the renew interval.
    lease_ttl_seconds: float = 60.0

    @field_validator("lease_ttl_seconds")
    @classmethod
    def _positive_lease_ttl(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("lease_ttl_seconds must be > 0")
        return value

    @field_validator("server", "database", "username", "application_name")
    @classmethod
    def _no_odbc_injection(cls, value: str | None) -> str | None:
        """Reject ODBC connection-string metacharacters in identity fields (STORE-5).

        These go into the DSN; a ``;``/``{``/``}``/``=`` or newline could smuggle extra keywords
        (e.g. downgrade TLS or redirect the server). Passwords legitimately contain these, so they
        are brace-escaped at build time instead (see ``sqlserver.connection_string``)."""
        if value is not None and any(ch in value for ch in ";{}=\r\n"):
            raise ValueError(
                "must not contain ';', '{', '}', '=', or newlines (ODBC injection risk)"
            )
        return value

    @model_validator(mode="after")
    def _require_server_db_fields(self) -> "StoreSettings":
        """When a server-database backend (SQL Server or Postgres) is selected, its connection
        essentials must be present. Both backends share the ``server``/``database`` (+ ``username``
        for SQL auth) connection fields; Postgres additionally only supports SQL (username/password)
        auth in this phase — INTEGRATED/ENTRA are SQL-Server-only until a Postgres equivalent
        (Kerberos/IAM) is built."""
        if self.backend in (StoreBackend.SQLSERVER, StoreBackend.POSTGRES):
            label = self.backend.value
            if self.backend is StoreBackend.POSTGRES:
                if self.auth is not SqlAuth.SQL:
                    raise ValueError(
                        "postgres backend supports only auth='sql' (username + MEFOR_STORE_PASSWORD) "
                        f"in this phase, not auth={self.auth.value!r}"
                    )
                if self.port == 1433:
                    # Left at the SQL-Server default → fall back to Postgres's conventional port so a
                    # Postgres deployment that omits `port` doesn't silently dial 1433 and fail.
                    self.port = 5432
            missing = [name for name in ("server", "database") if getattr(self, name) is None]
            if self.auth is SqlAuth.SQL and self.username is None:
                missing.append("username")  # SQL login needs a user (+ MEFOR_STORE_PASSWORD)
            if missing:
                raise ValueError(f"{label} backend requires: " + ", ".join(missing))
        return self


class ApiSettings(_Section):
    host: str = "127.0.0.1"  # Phase 1 = localhost only
    port: int = 8765
    expose_docs: bool = False  # serve /docs, /redoc, /openapi.json (off by default; widens surface)
    # Extra directories /config/reload may load from, besides the startup --config dir. The loader
    # EXECUTES Python from these, so list only admin-owned, trusted roots (e.g. an IDE staging dir).
    config_reload_roots: list[str] = []

    # Browser Origins allowed to open the /ws/stats WebSocket (ASVS 4.4.2). The only shipped client
    # is the PySide6 desktop console, which sends NO Origin header, so the secure default is empty:
    # a request that carries an Origin (i.e. a browser) is rejected unless its Origin is listed here.
    ws_allowed_origins: list[str] = []

    # --- In-process API/WebSocket TLS (WP-13a, ADR 0002) --------------------
    # When tls_cert_file is set the engine terminates TLS in uvicorn, so the API serves https/wss and
    # HSTS (already emitted on https) engages — the first-class way to bind off-loopback safely. PEM
    # paths (not secrets); the key may be in the cert PEM (tls_key_file optional).
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    # Passphrase for an encrypted private key. Secret — supply via MEFOR_API_TLS_KEY_PASSWORD, never
    # the file.
    tls_key_password: str | None = None
    # Minimum negotiated TLS version floor (NIST SP 800-52r2: 1.2+). "1.2" or "1.3".
    tls_min_version: str = "1.2"
    # Optional OpenSSL cipher string (default = the interpreter's secure defaults).
    tls_ciphers: str | None = None
    # Optional CA bundle to verify CLIENT certs (mTLS for the console; opt-in, future).
    tls_client_ca_file: str | None = None

    # --- Reverse-proxy / upstream TLS termination (WP-15, ADR 0002) --------
    # Proxy IPs whose X-Forwarded-For/-Proto headers are trusted (uvicorn forwarded_allow_ips). Empty =
    # trust nothing (the audit/rate-limit source IP is then the direct TCP peer). Set this ONLY to the
    # reverse proxy's address(es), or XFF spoofing returns.
    trusted_proxies: list[str] = []
    # Declare that a reverse proxy / load balancer terminates TLS in front of the engine. Lets a
    # non-loopback bind satisfy the exposed-gate WITHOUT in-process TLS — but only when trusted_proxies
    # is set (so the engine knows a terminator is really in front).
    tls_terminated_upstream: bool = False

    @property
    def tls_enabled(self) -> bool:
        """Whether in-process API TLS is configured (a server cert is present)."""
        return bool(self.tls_cert_file)

    @property
    def exposure_protected(self) -> bool:
        """Whether an off-loopback bind is safe: in-process TLS (WP-13a) OR a declared upstream TLS
        terminator behind trusted proxies (WP-15)."""
        return self.tls_enabled or (self.tls_terminated_upstream and bool(self.trusted_proxies))

    @property
    def is_loopback(self) -> bool:
        """Whether the API binds a loopback host — i.e. is **not** exposed off-box, so the exposed-bind
        TLS gate and the MFA-at-exposure advisory (``serve``) don't apply. Treats ``127.0.0.1``,
        ``localhost`` and ``::1`` as loopback (a dual-stack box never spuriously counts as exposed)."""
        return self.host in ("127.0.0.1", "localhost", "::1")

    @field_validator("config_reload_roots", "ws_allowed_origins", "trusted_proxies", mode="before")
    @classmethod
    def _split_roots(cls, v: object) -> object:
        # The env layer delivers list settings (MEFOR_API_CONFIG_RELOAD_ROOTS,
        # MEFOR_API_WS_ALLOWED_ORIGINS, MEFOR_API_TRUSTED_PROXIES) as one string; split it on the
        # platform path separator so these list-typed settings can be set via env (review low-12).
        if isinstance(v, str):
            return [p for p in v.split(os.pathsep) if p]
        return v

    @field_validator("tls_min_version")
    @classmethod
    def _check_tls_min_version(cls, v: str) -> str:
        if v not in ("1.2", "1.3"):
            raise ValueError(f"tls_min_version must be '1.2' or '1.3' (NIST 800-52r2), got {v!r}")
        return v

    @field_validator("tls_ciphers")
    @classmethod
    def _check_tls_ciphers(cls, v: str | None) -> str | None:
        # Reject a cipher string that would admit a non-forward-secret key exchange (ASVS 11.6.2), so a
        # misconfiguration can't widen the suite below the ECDHE policy. Fails loud at load, not bind.
        return v if v is None else validate_tls_ciphers(v)

    @model_validator(mode="after")
    def _check_tls_cert_dependency(self) -> "ApiSettings":
        # A key (or its passphrase / a client-CA) is meaningless without a server cert; require it so a
        # half-configured TLS block fails loud at load, not at bind.
        if (
            self.tls_key_file or self.tls_key_password or self.tls_client_ca_file
        ) and not self.tls_cert_file:
            raise ValueError(
                "tls_key_file / tls_key_password / tls_client_ca_file require [api].tls_cert_file"
            )
        # An upstream TLS terminator only satisfies the exposed-gate when the engine knows (and trusts)
        # the proxy in front — otherwise it's an unverifiable claim that XFF could spoof.
        if self.tls_terminated_upstream and not self.trusted_proxies:
            raise ValueError("[api].tls_terminated_upstream requires [api].trusted_proxies")
        return self


class InboundSettings(_Section):
    """Inbound-connection defaults that are an operational, per-environment decision rather than
    something authored in the message graph."""

    # The network interface EVERY inbound MLLP/TCP listener binds to. Loopback by default; binding
    # 0.0.0.0 exposes unauthenticated MLLP to the network, so it's a deliberate per-instance admin
    # choice (DEV typically loopback, PROD a specific NIC or 0.0.0.0) — not a developer default.
    # Connections never carry a host; they inherit this. See docs/CONNECTIONS.md.
    bind_host: str = "127.0.0.1"

    # Default ACK timing for every inbound (staged pipeline, ADR 0001): INGEST = ACK-on-receipt
    # (the message is ACKed once durably committed to the ingress stage). A connection's own
    # ack_after= overrides this. Step A supports only INGEST; 'delivered' (defer the ACK until
    # delivery) is not yet implemented and is rejected at engine start.
    ack_after: AckAfter = AckAfter.INGEST


class DeliverySettings(_Section):
    """Global outbound-delivery defaults. An outbound connection that declares no ``retry=``/
    ``ordering=`` of its own inherits these; an explicit per-connection value overrides them
    (resolution order: per-connection override > ``[delivery]`` global default > built-in). The
    retry fields mirror :class:`~messagefoundry.config.models.RetryPolicy`; a test guards the sync.
    """

    # Key names match docs/CONFIGURATION.md's [delivery] catalog (retry_-prefixed so the section can
    # also grow non-retry keys like outbox_workers/dead_letter later). max_attempts unset (None) =
    # retry forever (the conservative default — see RetryPolicy); set a finite value to dead-letter.
    retry_max_attempts: int | None = None
    retry_backoff_seconds: float = 5.0
    retry_backoff_multiplier: float = 2.0
    retry_max_backoff_seconds: float = 300.0
    # Default queue ordering for every outbound (FIFO = strict in-order per connection).
    ordering: OrderingMode = OrderingMode.FIFO
    # What a delivery worker does on an internal/code error: continue (dead-letter + advance, default)
    # or stop the connection and alert. Per-connection internal_error= overrides this.
    internal_error: InternalErrorPolicy = InternalErrorPolicy.CONTINUE
    # queue_buildup alert thresholds for every outbound. Mirror BuildupThreshold (a test guards the
    # sync); buildup_max_depth unset = depth dimension off; per-connection buildup= overrides.
    buildup_max_depth: int | None = None
    buildup_max_oldest_seconds: float | None = 300.0

    def retry_policy(self) -> RetryPolicy:
        """The global default :class:`RetryPolicy` an outbound inherits when it sets none."""
        return RetryPolicy(
            max_attempts=self.retry_max_attempts,
            backoff_seconds=self.retry_backoff_seconds,
            backoff_multiplier=self.retry_backoff_multiplier,
            max_backoff_seconds=self.retry_max_backoff_seconds,
        )

    def buildup_threshold(self) -> BuildupThreshold:
        """The global default :class:`BuildupThreshold` an outbound inherits when it sets none."""
        return BuildupThreshold(
            max_depth=self.buildup_max_depth,
            max_oldest_seconds=self.buildup_max_oldest_seconds,
        )


class PipelineSettings(_Section):
    """Staged-pipeline tunables (ADR 0013 Increment 2). ``max_correlation_depth`` bounds re-ingress
    loops: a re-ingressed message at this correlation depth still routes, but the next hop (depth+1)
    dead-letters its work-row and the origin is marked ``ERROR``. Coarse by design (it bounds total work,
    not topology) — a chain that legitimately bounces A→B→A a few times needs headroom; the default 8 is
    safe for typical request→response→route feeds. Floor of 1 (a value of 0 would dead-letter every
    re-ingress)."""

    max_correlation_depth: int = Field(default=8, ge=1)


class EnvironmentsSettings(_Section):
    """Where the per-environment **values** (``env()`` lookups in the message graph) live.

    The ACTIVE environment is the single cross-cutting selector ``[ai].environment`` (a free-form
    name, ADR 0017); this section only locates the value files. Each environment has a ``<env>.toml``
    flat table under ``dir`` for non-secret values (versioned), overlaid by ``MEFOR_VALUE_<KEY>`` env
    vars for secrets. See docs/CONFIGURATION.md."""

    dir: str = "environments"  # directory of <env>.toml value files, relative to base_dir (below)
    # Anchor that ``dir`` (and thus ``environments/<env>.toml``) resolves against. Empty (default) =
    # the process working directory — the original behavior, so an existing deployment is unchanged.
    # Set it to the config-repo root (a standalone config repo keeps environments/ at its root, a
    # sibling of the --config dir) so env-value resolution no longer depends on where serve was
    # launched — important under NSSM, whose working dir is rarely the repo. A relative value is taken
    # against the working dir; an absolute value is used as-is (on Windows it must be drive-qualified,
    # e.g. C:/repo — a leading-slash "/repo" is drive-relative and still inherits the launch drive).
    # Overridable per run via ``serve --project-root``. See resolve_values_base_dir + docs/CONFIGURATION.md.
    base_dir: str = ""


class LogFormat(str, Enum):
    TEXT = "text"  # human-readable (the default; stdout unchanged)
    JSON = "json"  # one JSON object per line — structured for a log shipper / SIEM


class SyslogProtocol(str, Enum):
    UDP = "udp"  # RFC 5426; fire-and-forget, never blocks the engine (the default)
    TCP = (
        "tcp"  # RFC 6587; connection-oriented (down-at-startup skipped; runtime stall bounded by a
    )
    #              socket timeout so a wedged collector can't block the event loop — synchronous send)


class LoggingSettings(_Section):
    """``[logging]`` — log level, stdout rendering, and optional off-box forwarding (sec-offbox-log).

    PHI redaction + control-char scrubbing are applied to **every** sink (stdout and the forwarder) by
    ``logging_setup.configure_logging``, so structured output and off-box shipping never weaken the
    "never log full PHI bodies" guarantee (docs/PHI.md §7)."""

    level: str = "INFO"
    # stdout rendering: "text" (default, unchanged) or "json" (one JSON object per line, friendlier to
    # a log shipper tailing NSSM's captured stdout).
    format: LogFormat = LogFormat.TEXT

    # --- Off-box forwarding to a syslog/SIEM collector (ASVS 16.x) ----------
    # Ship a copy of every log record to a remote syslog collector so log evidence survives a host
    # compromise (the local audit_log is tamper-evident, but lives on the same host). Off by default.
    # PHI redaction applies to the forwarded stream exactly as to stdout, but the syslog transport
    # itself is plaintext — terminate it at a local TLS-forwarding agent or keep it on a trusted
    # management network (see docs/SECURITY.md / docs/PHI.md). The forwarder never blocks the engine
    # indefinitely: UDP is fire-and-forget; a TCP collector unreachable at startup is skipped (warns),
    # and a runtime stall is bounded by a socket timeout (record dropped). Synchronous send — for a
    # high-volume feed prefer UDP or a local agent.
    forward_enabled: bool = False
    forward_host: str | None = None
    forward_port: int = 514
    forward_protocol: SyslogProtocol = SyslogProtocol.UDP
    # Wire format sent off-box, independent of the stdout `format`. JSON is the SIEM-friendly default and
    # guarantees one record per line; "text" framing is best-effort (a multi-line traceback spans lines).
    forward_format: LogFormat = LogFormat.JSON

    @field_validator("level")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        upper = value.upper()
        if upper not in LOG_LEVELS:
            raise ValueError(
                f"invalid log level {value!r}; expected one of {', '.join(LOG_LEVELS)}"
            )
        return upper

    @field_validator("forward_port")
    @classmethod
    def _check_forward_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("[logging].forward_port must be between 1 and 65535")
        return value

    @model_validator(mode="after")
    def _forward_needs_host(self) -> "LoggingSettings":
        if self.forward_enabled and not self.forward_host:
            raise ValueError(
                "[logging].forward_enabled requires [logging].forward_host (the syslog/SIEM collector)"
            )
        return self


class ReferenceSettings(_Section):
    """``[reference]`` — managed, versioned, read-only lookup snapshots (ADR 0006 Tier 1).

    Enforced by the engine's :class:`~messagefoundry.pipeline.reference_sync.ReferenceSyncRunner`.
    Reference sets are declared in wiring modules with ``Reference(name, source=…)`` and materialized
    OFF the message path; a transform reads them purely via ``reference("name").get(key)``. The runner
    is a no-op when no sets are declared, so these defaults are safe for an existing deployment."""

    # Base cadence (seconds) the sync loop ticks at; each set re-materializes when its own
    # refresh_seconds is due. Must be > 0.
    refresh_interval_seconds: float = 3600.0
    # Sync every declared set once at startup, before inbound listeners begin serving, so a transform's
    # reference(...) resolves on the very first message. Strongly recommended on.
    sync_on_startup: bool = True
    # Reserved freshness guard (seconds; 0 = off): alert/refuse when the active snapshot is older than
    # this. Not enforced in Tier 1 — accepted so a forward-looking file still loads.
    max_staleness_seconds: float = 0.0

    @field_validator("refresh_interval_seconds")
    @classmethod
    def _positive_interval(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("refresh_interval_seconds must be > 0")
        return value

    @field_validator("max_staleness_seconds")
    @classmethod
    def _non_negative_staleness(cls, value: float) -> float:
        if value < 0:
            raise ValueError("max_staleness_seconds must be >= 0 (0 = off)")
        return value


class RetentionSettings(_Section):
    """``[retention]`` — data-retention + SQLite maintenance (PHI.md §8, ASVS 14.2.x).

    Enforced by the engine's :class:`~messagefoundry.pipeline.retention.RetentionRunner`. Every window
    defaults to ``0``/``""`` = keep/off, so an existing deployment is unchanged until an operator opts
    in. A purge **NULLs the PHI *body*** of a message/dead-letter while **keeping its metadata row**
    (counts + disposition + audit stay intact — the Mirth Data-Pruner pattern); it never deletes a
    ``messages`` row, and never touches a body still in flight (at-least-once is preserved).
    """

    # Past N days, null inbound bodies (raw/summary/error) of fully-resolved messages, keeping the
    # metadata row. 0 = keep forever.
    messages_days: int = 0
    # Past N days, null the bodies of DEAD (dead-lettered) outbound rows — their own window because a
    # dead row stays replayable until its body is purged. 0 = keep forever.
    dead_letter_days: int = 0
    # Past N days, DELETE transform-state entries (ADR 0005) last written before the cutoff — keeps the
    # in-memory state cache + table bounded. A simple global age purge; per-namespace policy is a
    # follow-up. 0 = keep forever (the default — state correlation data is opt-in to purge).
    state_max_age_days: int = 0
    # Audit-log retention. RESERVED / not enforced: the audit_log is a tamper-evident hash chain and
    # HIPAA expects ~6-year retention, so audit is keep-forever by design here; archive-first pruning
    # is a tracked follow-up. Accepted (not rejected) so a forward-looking file still loads.
    audit_days: int = 0
    # Warn (WARNING log + AlertSink storage_threshold) when the DB file (+ -wal/-shm) exceeds this
    # many MB. 0 = off. Advisory only — never auto-deletes.
    max_db_mb: int = 0
    # How often the purge/maintenance loop runs a pass (seconds).
    purge_interval_seconds: float = 3600.0
    # PRAGMA wal_checkpoint(TRUNCATE) cadence in seconds (SQLite). 0 = off — rely on SQLite's
    # auto-checkpoint. Evaluated once per purge pass, so a value below purge_interval_seconds is
    # effectively rounded up to it.
    wal_checkpoint_seconds: float = 0.0
    # Daily local clock time "HH:MM" at which to run VACUUM (SQLite; reclaims space freed by purges).
    # "" = off. A daily off-peak time, not a cron expression, to avoid a new dependency — VACUUM holds
    # a write lock on the whole DB while it runs, so it is off by default and meant for a quiet window.
    vacuum_at: str = ""

    @field_validator(
        "messages_days", "dead_letter_days", "audit_days", "max_db_mb", "state_max_age_days"
    )
    @classmethod
    def _non_negative_days(cls, value: int) -> int:
        if value < 0:
            raise ValueError("retention windows/thresholds must be >= 0 (0 = keep/off)")
        return value

    @field_validator("purge_interval_seconds")
    @classmethod
    def _positive_interval(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("purge_interval_seconds must be > 0")
        return value

    @field_validator("wal_checkpoint_seconds")
    @classmethod
    def _non_negative_wal(cls, value: float) -> float:
        if value < 0:
            raise ValueError("wal_checkpoint_seconds must be >= 0 (0 = off)")
        return value

    @field_validator("vacuum_at")
    @classmethod
    def _valid_clock_time(cls, value: str) -> str:
        value = value.strip()
        if value and cls._parse_clock(value) is None:
            raise ValueError(f"vacuum_at must be empty or 'HH:MM' (24h), got {value!r}")
        return value

    @staticmethod
    def _parse_clock(value: str) -> tuple[int, int] | None:
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", value.strip())
        if not m:
            return None
        hour, minute = int(m.group(1)), int(m.group(2))
        if 0 <= hour <= 23 and 0 <= minute <= 59:
            return hour, minute
        return None

    def vacuum_time(self) -> tuple[int, int] | None:
        """The configured daily VACUUM time as ``(hour, minute)`` local, or ``None`` when disabled."""
        return self._parse_clock(self.vacuum_at) if self.vacuum_at else None


class AuthSettings(_Section):
    """Authentication + RBAC knobs. Secrets (the AD bind password) come from env, never the file."""

    # Authentication is required by default; this flag exists only for the embedding/test path.
    enabled: bool = True
    session_idle_timeout_minutes: int = 30
    session_absolute_hours: int = 12
    # Cap concurrent sessions per user (ASVS 7.1.2); a login beyond the cap revokes the user's oldest
    # active session. 0 = unlimited. Default 5 (WP-10): generous for a few devices/console instances.
    max_sessions_per_user: int = 5
    # Step-up re-verification (ASVS 7.5.3): a highly sensitive operation requires the session to have
    # re-verified its credential — at login or via POST /me/reauth — within this many seconds. The
    # initial login counts as the first verification (sudo-timestamp model). Default 5 minutes.
    step_up_max_age_seconds: int = 300

    # Multi-factor authentication (WP-14, ADR 0002 §3; ASVS 6.3.3) — a native RFC 6238 TOTP second
    # factor for LOCAL accounts. AD/Kerberos MFA is delegated to the directory (Entra Conditional
    # Access / an MFA proxy), so a directory login is never prompted for an engine TOTP. When
    # require_mfa is on, a user holding the Administrator role MUST enroll TOTP and satisfy it before
    # any step-up (sensitive) operation; non-admins may opt in voluntarily. Default OFF preserves
    # today's loopback behavior byte-for-byte (on the 127.0.0.1 bind 6.3.3 is deferred-by-design with
    # the single-trusted-host compensating control). An off-loopback bind that serves local accounts
    # SHOULD turn this on; ``serve`` now makes that posture explicit (sec-mfa-on) — on an exposed
    # (non-loopback) PHI bind with this off it **refuses to start** on a production instance and
    # **warns** on a non-production one, mirroring the keyless-store / open-egress startup gates (see
    # __main__._serve), so MFA can't be silently skipped at exposure. Scope: it gates **step-up
    # (sensitive) operations** for the Administrator role — it is NOT a gate on every authenticated PHI
    # read (those stay behind RBAC + the PHI-read throttle).
    require_mfa: bool = False
    # How many single-use recovery codes are minted at enrollment (the lost-authenticator escape
    # hatch). 0 disables recovery codes (an admin reset is then the only recovery path).
    mfa_recovery_code_count: int = 10
    # Admin-interface defense-in-depth contextual-risk signal (WP-L3-13, ADR 0002; ASVS 8.4.2). When
    # on, a step-up (sensitive admin) request arriving from a client IP that differs from the one the
    # session last verified from is treated as higher-risk: it emits an audit + out-of-band notice and
    # FORCES a fresh step-up (a successful re-verify re-anchors the session to the new IP). It is
    # advisory + step-up-forcing only — it NEVER changes an RBAC allow/deny and never blocks the
    # non-admin request path. Default OFF preserves today's behavior byte-for-byte; and even on, a
    # single-host loopback deployment never trips it (loopback addresses 127.0.0.1 and ::1 are treated
    # as the same host, so a dual-stack box doesn't spuriously fire).
    # An off-loopback bind serving admins SHOULD turn this on (operator/runbook responsibility).
    admin_new_ip_step_up: bool = False

    # Local-password policy — ASVS 5.0-aligned (WP-3): length-first, no mandatory composition.
    password_min_length: int = 15
    # Character-class requirements are OFF by default (ASVS forbids mandatory composition) but kept
    # as opt-in knobs for deployments with a legacy standard that still mandates them.
    password_require_uppercase: bool = False
    password_require_lowercase: bool = False
    password_require_digit: bool = False
    password_require_symbol: bool = False
    password_check_breached: bool = True  # reject known common/breached passwords (offline corpus)
    password_check_context: bool = True  # reject passwords containing app/vendor/HL7 terms
    password_check_username: bool = (
        True  # reject passwords containing the user's own username (6.2.11)
    )
    # Optional path to a larger offline breach corpus that augments the bundled top-10k list (6.2.12):
    # a plaintext list OR an HIBP-style SHA-1-hash export (HASH[:count] lines, auto-detected). Fully
    # offline — no live HIBP call. Use a curated subset, not the full ~40 GB HIBP set (loaded into memory).
    password_breach_corpus_file: str | None = None
    lockout_threshold: int = 5  # consecutive failed logins before the account locks
    lockout_minutes: int = 15
    # First-run bootstrap admin: auto-disabled once a second administrator exists, and (if still
    # unclaimed — never password-changed) disabled this many hours after creation. 0 = no time expiry.
    bootstrap_expiry_hours: int = 72

    # Active Directory / LDAP. The bind password is a secret: MEFOR_AUTH_AD_BIND_PASSWORD.
    ad_enabled: bool = False
    ad_server: str | None = None  # e.g. ldaps://dc1.example.com:636
    ad_domain: str | None = None  # e.g. example.com (UPN suffix)
    ad_user_search_base: str | None = None
    ad_group_search_base: str | None = None
    ad_bind_dn: str | None = None  # service-account DN used to look users up
    ad_bind_password: str | None = None  # secret — supply via env only
    ad_use_nested_groups: bool = True  # resolve nested groups via LDAP_MATCHING_RULE_IN_CHAIN
    ad_tls_verify: bool = True
    ad_tls_ca_cert_file: str | None = None  # trust an internal CA without disabling verification
    ad_allow_insecure_ldap: bool = False  # explicit opt-in to a non-ldaps:// bind (trusted-net dev)

    # Windows SSO (Kerberos/SPNEGO) — passwordless login from a domain-joined client.
    # Experimental; off by default. Not a supported v0.1 feature — hardening targeted for 0.2.
    kerberos_enabled: bool = False
    kerberos_spn: str | None = None  # e.g. HTTP/host.example.com

    # Login rate limiting (AUTH-RATE) — in-process sliding window in front of the per-account
    # lockout: bounds password-spray + argon2 CPU-burn. In-process only; an exposed/multi-host
    # deployment must also front the API with a proxy/WAF limiter. None/0 disables a limit.
    login_rate_limit_enabled: bool = True
    login_rate_limit_per_ip: int = 10  # max attempts per client IP per window
    login_rate_limit_global: int = 60  # max attempts across all clients per window
    login_rate_limit_window_seconds: float = 60.0

    # Anti-automation on the authenticated PHI-read endpoints (WP-8, ASVS 2.4.1): a per-actor sliding
    # window over /messages, /messages/{id}, /dead-letters — bounds scripted PHI harvesting on top of
    # pagination + access auditing. Generous by default (clears console/human use); in-process only,
    # so an exposed deployment must also front a proxy/WAF limiter. 0 disables that dimension.
    phi_read_rate_limit_enabled: bool = True
    phi_read_rate_limit_per_actor: int = 120  # max PHI reads per user per window
    phi_read_rate_limit_global: int = 0  # max PHI reads across all users per window (0 = off)
    phi_read_rate_limit_window_seconds: float = 60.0

    # Out-of-band user notification of security events (ASVS 6.3.5/6.3.7): email the affected user on
    # lockout / first-success-after-failures / password/email/role/disable changes. Email requires the
    # [alerts] SMTP transport to be configured (no SMTP → email is skipped); the audited
    # /me/security-events feed records these regardless of this toggle.
    notify_security_events: bool = True

    @field_validator("mfa_recovery_code_count")
    @classmethod
    def _check_recovery_count(cls, value: int) -> int:
        if not 0 <= value <= 50:
            raise ValueError("mfa_recovery_code_count must be between 0 and 50 (0 = disabled)")
        return value

    @model_validator(mode="after")
    def _require_ad_fields(self) -> "AuthSettings":
        """AD/SSO need their connection essentials present when enabled."""
        if self.ad_enabled and (self.ad_server is None or self.ad_user_search_base is None):
            raise ValueError("ad_enabled requires: ad_server, ad_user_search_base")
        if (
            self.ad_enabled
            and self.ad_server is not None
            and not self.ad_server.lower().startswith("ldaps://")
            and not self.ad_allow_insecure_ldap
        ):
            raise ValueError(
                "ad_enabled requires an ldaps:// ad_server (credentials go over a SIMPLE bind); "
                "set ad_allow_insecure_ldap=true only for a trusted-network dev override"
            )
        if self.ad_enabled and (self.ad_bind_dn is None or self.ad_bind_password is None):
            raise ValueError(
                "ad_enabled requires a service account: ad_bind_dn and ad_bind_password "
                "(supply the password via MEFOR_AUTH_AD_BIND_PASSWORD)"
            )
        if self.kerberos_enabled and not self.ad_enabled:
            raise ValueError("kerberos_enabled requires ad_enabled (SSO resolves roles via AD)")
        return self


#: Characters permitted in a free-form environment NAME (it selects ``environments/<name>.toml``, so
#: it must be a safe single path segment).
_ENV_NAME_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

#: Built-in environment names whose security posture (data_class, production) is derived when
#: ``[ai].data_class`` / ``[ai].production`` are left unset — back-compat with the original
#: dev/staging/prod tiers. A CUSTOM name must set posture explicitly (it is never inferred from a
#: free-form string), so a 'test'/'poc' instance can never default permissive (ADR 0017).
_KNOWN_ENV_POSTURE: dict[str, tuple[DataClass, bool]] = {
    "dev": (DataClass.SYNTHETIC, False),
    "staging": (DataClass.PHI, False),
    "prod": (DataClass.PHI, True),
}


class AiSettings(_Section):
    """Central AI-assistance policy plus the instance's active **environment name** and security
    **posture**. The two AI axes (mode + data scope) are bounded by the production-posture ceiling
    computed by :func:`~messagefoundry.config.ai_policy.resolve_effective_policy` (the API endpoint
    and the ``ai-policy`` CLI both clamp these before serving them). See docs/AI.md.

    ``environment`` is the **free-form** active-environment name (ADR 0017): it selects
    ``environments/<name>.toml`` and is what ``current_environment()`` returns. It has **no default** —
    ``serve`` requires it, so a missing env can never silently resolve another environment's
    values/secrets. ``data_class`` / ``production`` are the explicit security posture, **decoupled from
    the name**: for the built-in names dev/staging/prod they are derived when unset, but a custom name
    must set them (see :meth:`require_posture`)."""

    mode: AiMode = AiMode.BYO
    data_scope: AiDataScope = AiDataScope.CODE_ONLY
    # Free-form active-environment NAME (ADR 0017): selects environments/<name>.toml + what
    # current_environment() returns. No default — serve requires it (a missing env must never silently
    # resolve another env's values/secrets).
    environment: str | None = None
    # Explicit security POSTURE, decoupled from the name. Unset is derived from a built-in name
    # (dev->synthetic/non-prod, staging->phi/non-prod, prod->phi/prod); a custom name must set them.
    data_class: DataClass | None = None
    production: bool | None = None

    # --- forward-compat (accepted-but-UNUSED in this MVP; for the P1 engine broker) ----------
    # These describe a managed provider connection. They parse so a forward-looking config loads,
    # but nothing in this build reads them — managed modes are not yet implemented.
    provider: str = "claude"
    model: str = "claude-opus-4-8"
    baa_attested: bool = False
    endpoint: str | None = None

    @field_validator("environment")
    @classmethod
    def _valid_environment_name(cls, v: str | None) -> str | None:
        # The name becomes a filename segment (environments/<name>.toml), so keep it a simple token.
        if v is not None and (not v or not set(v) <= _ENV_NAME_ALLOWED):
            raise ValueError(
                "[ai].environment must be a non-empty name of letters, digits, '.', '_' or '-' "
                "(it selects environments/<name>.toml)"
            )
        return v

    def derived_posture(self) -> tuple[DataClass | None, bool | None]:
        """``(data_class, production)`` with built-in-name derivation applied where each is unset.

        Either element may still be ``None`` when a *custom* environment name leaves it unset — callers
        that need a definite posture use :meth:`require_posture` (fail-closed) or default the missing
        ``production`` to ``True`` (strictest ceiling) for an advisory read."""
        dc, prod = self.data_class, self.production
        known = _KNOWN_ENV_POSTURE.get(self.environment or "")
        if known is not None:
            if dc is None:
                dc = known[0]
            if prod is None:
                prod = known[1]
        return dc, prod

    def require_posture(self) -> tuple[DataClass, bool]:
        """The fail-closed ``(data_class, production)`` posture; raises ``ValueError`` when a custom or
        unset environment name has no explicit posture. Used at ``serve`` so a custom env never defaults
        permissive (ADR 0017)."""
        dc, prod = self.derived_posture()
        if dc is None or prod is None:
            raise ValueError(
                f"environment {self.environment!r} has no built-in security posture (not one of "
                "dev/staging/prod); set [ai].data_class (synthetic|phi) and [ai].production "
                "(true|false) explicitly"
            )
        return dc, prod


class EgressSettings(_Section):
    """``[egress]`` — fail-closed outbound destination allowlist (WP-11c; ASVS 13.2.4/13.2.5/14.2.3).

    Bounds where the engine may **send** PHI, so a fat-fingered or hostile outbound destination can't
    exfiltrate it. Each list is **opt-in**: empty = unrestricted (today's behavior); once a transport's
    list is set, a destination of that transport not on it is **refused at config load/reload**
    (fail-closed), checked against the resolved (``env()``-substituted) destination. The webhook/SMTP
    *alert* sinks carry no PHI bodies and keep their own ``[alerts]`` host allowlists.

    Set ``deny_by_default = true`` to flip the whole posture fail-closed: a transport with an **empty**
    allowlist then refuses *every* destination of that type (so each permitted destination must be
    listed). Default false keeps the per-list opt-in behavior.
    """

    # Allowed MLLP outbound destinations: each entry is "host" (any port) or "host:port".
    allowed_mllp: list[str] = []
    # Allowed raw-TCP outbound destinations: each entry is "host" (any port) or "host:port".
    allowed_tcp: list[str] = []
    # Allowed File outbound directories: a destination's directory must resolve at/under one of these.
    allowed_file_dirs: list[str] = []
    # Allowed REST/SOAP (HTTP) outbound hosts: each entry is "host" (any port) or "host:port".
    allowed_http: list[str] = []
    # Allowed DATABASE outbound servers: each entry is "host" (any port) or "host:port".
    allowed_db: list[str] = []
    # Allowed REMOTEFILE (SFTP/FTP/FTPS) hosts — gates the connector in BOTH directions (the source
    # dials out to poll, the destination dials out to upload). Each entry is "host" or "host:port".
    allowed_remote: list[str] = []

    # Opt-in deny-by-default (Q5b): when true, a transport with an EMPTY allowlist refuses every
    # destination of that type instead of allowing any. A global on-ramp to fail-closed egress without
    # having to enumerate one list just to flip the posture; pairs with the prod/staging open-egress
    # startup advisory. Default false = the per-list opt-in behavior above (empty = unrestricted).
    deny_by_default: bool = False

    @field_validator(
        "allowed_mllp",
        "allowed_tcp",
        "allowed_file_dirs",
        "allowed_http",
        "allowed_db",
        "allowed_remote",
        mode="before",
    )
    @classmethod
    def _split_list(cls, v: object) -> object:
        # Allow setting via env (MEFOR_EGRESS_ALLOWED_MLLP=...) as one comma-separated string.
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


class ShadowSettings(_Section):
    """``[shadow]`` — parallel-run / shadow-instance egress suppression (#15).

    A *shadow* MessageFoundry instance processes real (teed) traffic to validate it against a legacy
    engine, but must **not** deliver to live partners (the legacy engine is still the real sender).
    Set ``simulate_all_egress = true`` to force **every** outbound into ``simulate`` mode regardless of
    its per-connection ``simulate=`` flag — the deployment-wide safety switch so a shadow stand-up
    can't accidentally leave one outbound live. Default false = each outbound's own ``simulate=`` flag
    applies. (Per-outbound is the precise control; this is the blunt instance-wide override.)
    """

    simulate_all_egress: bool = False


class AlertSeverity(str, Enum):
    """Severity a matching rule tags a fired alert with (ADR 0014) — carried in the payload so a
    webhook target (PagerDuty/Slack/Teams) or the email subject can triage by it."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


#: The alert event types a rule may match (plus ``"any"``); mirror the AlertSink methods.
_ALERT_EVENT_TYPES = frozenset(
    {"connection_stopped", "queue_buildup", "storage_threshold", "cert_expiry"}
)
#: The transport names a rule may route to; mirror ``AlertTransport.name``.
_ALERT_TRANSPORTS = frozenset({"webhook", "email"})


class AlertRule(BaseModel):
    """One operator-authored alerting rule (ADR 0014). The **first** rule that matches an event decides
    its severity, which transports fire, and the re-alert cooldown; an event matching no rule keeps the
    default (notify every configured transport at ``warning`` with the global ``realert_seconds``).
    Rules are pure data — there is no embedded code/expression."""

    model_config = ConfigDict(extra="forbid")

    # --- match (all conditions must hold) ---
    event_type: str = (
        "any"  # "any" | connection_stopped | queue_buildup | storage_threshold | cert_expiry
    )
    connection: str = "*"  # fnmatch glob over the connection name; "*" = all
    min_depth: int | None = Field(None, ge=1)  # queue_buildup: match only at/over this lane depth
    min_oldest_seconds: float | None = Field(
        None, ge=0
    )  # queue_buildup: …or oldest-message age (s)
    # --- outcome ---
    severity: AlertSeverity = AlertSeverity.WARNING
    transports: list[str] | None = (
        None  # None = every configured transport; [] = suppress entirely (event dropped, never sent)
    )
    cooldown_seconds: float | None = Field(
        None, gt=0
    )  # override realert_seconds for matching events

    @field_validator("event_type")
    @classmethod
    def _check_event_type(cls, v: str) -> str:
        if v != "any" and v not in _ALERT_EVENT_TYPES:
            allowed = ", ".join(sorted({"any", *_ALERT_EVENT_TYPES}))
            raise ValueError(f"event_type must be one of {allowed}; got {v!r}")
        return v

    @field_validator("transports")
    @classmethod
    def _check_transports(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            bad = [t for t in v if t not in _ALERT_TRANSPORTS]
            if bad:
                allowed = ", ".join(sorted(_ALERT_TRANSPORTS))
                raise ValueError(f"transports must be a subset of [{allowed}]; unknown: {bad}")
        return v


class AlertsSettings(_Section):
    """Where operational alerts (``connection_stopped`` / ``queue_buildup`` from the delivery
    pipeline) are delivered. Both transports are **off by default** — with neither configured the
    engine falls back to logging the events at ``WARNING`` (``LoggingAlertSink``).

    A transport is *enabled* when its essentials are present: ``webhook_url`` for the webhook;
    ``email_smtp_host`` + ``email_from`` + at least one ``email_to`` for email. The SMTP password is a
    secret — supply it via ``MEFOR_ALERTS_EMAIL_PASSWORD``, never the file. Payloads carry only the
    connection name + queue shape (no PHI)."""

    # --- webhook (generic HTTP POST; fronts Slack/Teams/PagerDuty/custom) ----
    webhook_url: str | None = None
    webhook_timeout: float = 10.0  # seconds per POST
    # Optional egress allowlist for the webhook host (ASVS 1.3.6, SSRF defense-in-depth). Empty =
    # any host (the URL is operator-configured, not request-derived). When set, the webhook_url host
    # must be listed or the transport refuses to send. Comma- or os.pathsep-separated via env.
    webhook_allowed_hosts: list[str] = []

    # --- email / SMTP -------------------------------------------------------
    email_smtp_host: str | None = None
    email_smtp_port: int = 587
    email_from: str | None = None
    email_to: list[str] = []
    email_use_tls: bool = True  # STARTTLS
    email_username: str | None = None
    email_password: str | None = None  # secret — supply via MEFOR_ALERTS_EMAIL_PASSWORD
    email_timeout: float = 30.0  # seconds per send
    # Egress allowlist for the SMTP host (WP-11c, parity with webhook_allowed_hosts). Empty = any.
    smtp_allowed_hosts: list[str] = []

    # Re-alert throttle: the same (event, connection) won't re-notify more often than this, so a
    # flapping lane can't spam the channel.
    realert_seconds: float = 300.0

    # Operator alert rules (ADR 0014): refine severity / which transports fire / cooldown / suppression
    # per event + connection. Empty = today's behaviour (every event → every transport, global throttle).
    # Authored as ``[[alerts.rules]]`` tables in the config file. First match wins.
    rules: list[AlertRule] = []

    @field_validator("email_to", "webhook_allowed_hosts", "smtp_allowed_hosts", mode="before")
    @classmethod
    def _split_recipients(cls, v: object) -> object:
        # The env layer delivers list-typed alerts settings (MEFOR_ALERTS_EMAIL_TO,
        # MEFOR_ALERTS_WEBHOOK_ALLOWED_HOSTS) as one string; split on commas so they can be set via
        # env (mirrors api.config_reload_roots).
        if isinstance(v, str):
            return [addr.strip() for addr in v.split(",") if addr.strip()]
        return v


class ClusterSettings(_Section):
    """``[cluster]`` — active-passive HA coordination (Track B Steps 3-7).

    The multi-node coordination seam (a ``nodes`` table + per-node heartbeat + leader election) without
    changing single-node behavior: with ``enabled = false`` (the default) the engine uses the no-op
    :class:`~messagefoundry.pipeline.cluster.NullCoordinator` and runs byte-identically to before.
    With ``enabled = true`` on a shared server-DB store, the active-passive HA feature set is COMPLETE:
    leader election (Step 4 — exactly one node drains the graph; a standby takes over on failover),
    leader-gated poll-source intake (Step 4b), cross-node reference + config-reload + transform-state
    convergence (Steps 6/6b), and the read-only observability API (Step 7 — ``/cluster/status`` +
    ``/cluster/nodes``). Exactly one node runs the leader-only WRITE singletons (retention, the
    lease-reclaim sweep) and re-reads each reference source while followers read-through the shared
    snapshot; an operator config reload propagates cluster-wide via a version token; and operators can
    see membership + leadership over the API. Operators must keep node clocks synced (NTP — the
    failover-recovery leases are wall-clock), run identical config dirs on every node, and apply config
    changes via a coordinated (not rolling) restart — see ``docs/CLUSTERING.md``. Leadership itself is a
    **self-fencing lease** (Workstream A2): the leader renews a ``leader_lease`` row every
    ``heartbeat_seconds`` to ``DB_now + leader_lease_ttl_seconds``, a standby acquires only once that
    lease has expired, and a leader that cannot renew within ``leader_fence_timeout_seconds`` self-fences
    before the lease can expire (the split-brain guard). The cross-section validator below requires
    ``[store].backend = postgres`` and ``[store].pool_size >= 2`` when this is enabled (a clustered node
    drives concurrent background work against the pool)."""

    enabled: bool = False
    # Override the auto-generated node id (host:pid:hex). Pin it for a stable identity across restarts
    # or in tests; left unset, the factory reuses the store's lease owner-id so node-id == owner-id.
    node_id: str | None = None
    # How often a node refreshes its `last_seen` heartbeat. The same cadence drives leadership-lease
    # renewal (Track B Step 4 / Workstream A2) — no separate leader-check knob. Must be > 0.
    heartbeat_seconds: float = 10.0
    # A node is considered dead when its last_seen is older than this. Consulted by DbCoordinator's
    # cluster_members() (Step 7) as the freshness filter for the /cluster/nodes observability endpoint —
    # it discards a crashed ex-leader's stale is_leader flag and bounds the failover window in which a
    # just-beaten node still counts toward the derived leader. It is NOT what transfers leadership: the
    # self-fencing leadership lease is (a standby acquires only once the lease has expired). Must be > 0.
    node_timeout_seconds: float = 30.0
    # How often the LEADER runs the lease-reclaim sweep (reclaim_expired_leases) that recovers crashed
    # nodes' in-flight rows (Track B Step 4). Only the current leader acts; followers no-op. Must be > 0.
    reclaim_interval_seconds: float = 30.0
    # The leadership LEASE TTL (Workstream A2 active-passive self-fencing). The current leader renews the
    # lease every heartbeat_seconds, extending its expiry to DB_now + this; a standby may acquire leadership
    # ONLY once the lease has expired, so it always waits out the full TTL. Measured on the DB's own clock
    # (clock_timestamp()), so inter-node clock skew is irrelevant to leadership correctness. Must be > 0.
    leader_lease_ttl_seconds: float = 30.0
    # The SELF-FENCE timeout: a leader that has not renewed its lease within this many seconds (its own
    # monotonic clock, with NO DB I/O so a hung/partitioned DB can't block it) halts its leader work.
    # MUST be < leader_lease_ttl_seconds so the old leader stops BEFORE the lease can expire and a standby
    # acquire — the split-brain guard. MUST be > heartbeat_seconds so a single missed renew doesn't fence.
    leader_fence_timeout_seconds: float = 20.0

    @field_validator(
        "heartbeat_seconds",
        "node_timeout_seconds",
        "reclaim_interval_seconds",
        "leader_lease_ttl_seconds",
        "leader_fence_timeout_seconds",
    )
    @classmethod
    def _positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("must be > 0")
        return value

    @model_validator(mode="after")
    def _timeout_exceeds_heartbeat(self) -> "ClusterSettings":
        """A node must beat at least once within its dead-timeout, or Step-4 election would mark a
        live node dead between beats. node_timeout_seconds is reserved for that election, but lock the
        invariant in now so a misconfiguration is caught at config load, not at election bring-up."""
        if self.node_timeout_seconds <= self.heartbeat_seconds:
            raise ValueError(
                "node_timeout_seconds must be > heartbeat_seconds "
                f"(got node_timeout_seconds={self.node_timeout_seconds}, "
                f"heartbeat_seconds={self.heartbeat_seconds}) — a node must beat at least once before "
                "it is considered dead"
            )
        return self

    @model_validator(mode="after")
    def _fence_ordering(self) -> "ClusterSettings":
        """The split-brain guard's timing invariant (Workstream A2): heartbeat < fence < lease TTL. The
        leader must renew faster than it fences (so one missed beat doesn't demote it) and must fence
        before the lease can expire (so a partitioned old leader stops before a standby acquires).
        Caught at config load, not at failover."""
        if not (
            self.heartbeat_seconds
            < self.leader_fence_timeout_seconds
            < self.leader_lease_ttl_seconds
        ):
            raise ValueError(
                "cluster lease timing must satisfy heartbeat_seconds < leader_fence_timeout_seconds "
                "< leader_lease_ttl_seconds "
                f"(got heartbeat_seconds={self.heartbeat_seconds}, "
                f"leader_fence_timeout_seconds={self.leader_fence_timeout_seconds}, "
                f"leader_lease_ttl_seconds={self.leader_lease_ttl_seconds}) — the leader must renew "
                "faster than it fences, and fence before the lease can expire and a standby acquire it"
            )
        return self


class CertMonitorSettings(_Section):
    """Periodic TLS-certificate expiry monitor (``[cert_monitor]``). The engine scans the certificate
    PEM files it actually serves with — the ``[api]`` TLS cert and every connection's ``tls_cert_file``
    (MLLP server/client identity) — and raises a ``cert_expiry`` alert when one is expired or within
    ``warn_days`` of expiry. Now that native off-loopback TLS is the supported posture, this catches a
    silently expiring cert (a hard PHI-feed outage at renewal time) ahead of time. Only the public
    certificate is read, never any private key. Set ``warn_days`` to 0 to disable the monitor."""

    warn_days: int = 30  # alert this many days before expiry (0 = monitor off)
    check_interval_seconds: float = 43_200.0  # rescan cadence (default 12h)

    @field_validator("warn_days")
    @classmethod
    def _check_warn_days(cls, v: int) -> int:
        if v < 0:
            raise ValueError("cert_monitor.warn_days must be >= 0 (0 disables the monitor)")
        return v

    @field_validator("check_interval_seconds")
    @classmethod
    def _check_interval(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("cert_monitor.check_interval_seconds must be > 0")
        return v


#: The high-value operations dual-control can gate (registry keys). Confining ``[approvals].operations``
#: to this set catches a typo'd op name at startup rather than silently never gating it.
APPROVABLE_OPERATIONS: frozenset[str] = frozenset({"dead_letter_replay", "connection_purge"})


class ApprovalsSettings(_Section):
    """Optional dual-control (maker-checker) approval for high-value actions (``[approvals]``, ASVS
    2.3.5). **Off by default** so a single-operator deployment is never blocked. When ``enabled``, an
    action in ``operations`` is held as a pending request and must be released by a *distinct* second
    user holding ``approvals:approve`` — the requester can never approve their own. A request older than
    ``expiry_hours`` can no longer be approved."""

    enabled: bool = False
    operations: list[str] = Field(default_factory=lambda: sorted(APPROVABLE_OPERATIONS))
    expiry_hours: float = (
        72.0  # a pending request expires this many hours after it's made (0 = never)
    )

    @field_validator("operations")
    @classmethod
    def _known_operations(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - APPROVABLE_OPERATIONS)
        if unknown:
            raise ValueError(
                f"[approvals].operations has unknown operation(s) {unknown}; "
                f"valid: {sorted(APPROVABLE_OPERATIONS)}"
            )
        return v

    @field_validator("expiry_hours")
    @classmethod
    def _check_expiry(cls, v: float) -> float:
        if v < 0:
            raise ValueError("approvals.expiry_hours must be >= 0 (0 = never expires)")
        return v


class ServiceSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")  # tolerate forward-looking/unknown sections

    store: StoreSettings = Field(default_factory=StoreSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    inbound: InboundSettings = Field(default_factory=InboundSettings)
    delivery: DeliverySettings = Field(default_factory=DeliverySettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    environments: EnvironmentsSettings = Field(default_factory=EnvironmentsSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    reference: ReferenceSettings = Field(default_factory=ReferenceSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    ai: AiSettings = Field(default_factory=AiSettings)
    egress: EgressSettings = Field(default_factory=EgressSettings)
    shadow: ShadowSettings = Field(default_factory=ShadowSettings)
    alerts: AlertsSettings = Field(default_factory=AlertsSettings)
    cert_monitor: CertMonitorSettings = Field(default_factory=CertMonitorSettings)
    cluster: ClusterSettings = Field(default_factory=ClusterSettings)
    approvals: ApprovalsSettings = Field(default_factory=ApprovalsSettings)

    @model_validator(mode="after")
    def _cluster_requires_server_db(self) -> "ServiceSettings":
        """Cluster coordination needs a shared **server-DB** store to back the ``nodes`` + leadership-
        lease tables. SQLite is single-file/single-node, so it cannot. **Postgres** and **SQL Server**
        both can: each runs the active-passive leadership lease (one leader drains the graph; a standby
        takes over on failure). The leader-gate + self-fence keep a single active processor at a time on
        either backend. This spans two sections, so it lives here (not on :class:`ClusterSettings`,
        which can't see ``[store]``)."""
        if self.cluster.enabled:
            if self.store.backend not in (StoreBackend.POSTGRES, StoreBackend.SQLSERVER):
                raise ValueError(
                    "[cluster].enabled requires [store].backend in {'postgres', 'sqlserver'} "
                    f"(got {self.store.backend.value!r}); SQLite is single-node — cluster coordination "
                    "needs a shared server-DB store (Postgres active-passive, or SQL Server "
                    "active-passive)"
                )
            if self.store.pool_size < 2:
                # A clustered node runs concurrent background work against the pool — the maintenance
                # loop (heartbeat + leadership-lease renew + config-version refresh), the leader-gated
                # reclaim sweep, and the per-stage workers — alongside request traffic. A pool of 1 would
                # serialize all of it behind a single connection, so require headroom.
                raise ValueError(
                    "[cluster].enabled requires [store].pool_size >= 2 "
                    f"(got {self.store.pool_size}); a clustered node drives concurrent background work "
                    "(the membership/lease maintenance loop + the leader reclaim sweep + the per-stage "
                    "workers) against the pool, so a pool of 1 would serialize everything — prefer "
                    "pool_size >= 3 for clustered Postgres"
                )
        return self


def _merge(dst: dict[str, dict[str, Any]], src: Mapping[str, Any]) -> None:
    """Shallow-merge per-section dicts from ``src`` into ``dst`` (later layers win)."""
    for section, values in src.items():
        if isinstance(values, dict):
            dst.setdefault(section, {}).update(values)


def _env_overrides(environ: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """Parse ``MEFOR_<SECTION>_<KEY>`` vars into ``{section: {key: value}}`` (strings; pydantic coerces)."""
    out: dict[str, dict[str, Any]] = {}
    for name, value in environ.items():
        if not name.startswith(_ENV_PREFIX):
            continue
        section, _, key = name[len(_ENV_PREFIX) :].lower().partition("_")
        if section in _SECTIONS and key:
            out.setdefault(section, {})[key] = value
    return out


def _warn_file_secrets(file_data: Mapping[str, Any], path: Path) -> None:
    """Warn when a secret is supplied via the config file instead of the environment."""
    for section, key in _FILE_SECRET_KEYS:
        sect = file_data.get(section)
        if isinstance(sect, dict) and sect.get(key) is not None:
            _log.warning(
                "secret [%s].%s is set in %s; move it to env (MEFOR_%s_%s) — the config file is "
                "not a safe place for secrets",
                section,
                key,
                path,
                section.upper(),
                key.upper(),
            )


def load_settings(
    *,
    config_path: str | Path | None = None,
    cli: Mapping[str, Mapping[str, Any]] | None = None,
    environ: Mapping[str, str] | None = None,
) -> ServiceSettings:
    """Resolve settings with CLI > env > file > default precedence.

    ``config_path`` reads that TOML file (error if it's missing); when ``None``, ``./messagefoundry.toml``
    is used **only if it exists**. ``cli`` is a nested ``{section: {key: value}}`` of explicitly-provided
    CLI overrides (omit a key to fall through). ``environ`` defaults to ``os.environ``.
    """
    environ = os.environ if environ is None else environ
    data: dict[str, dict[str, Any]] = {}

    path = Path(config_path) if config_path is not None else Path(_DEFAULT_FILE)
    if config_path is not None and not path.exists():
        raise FileNotFoundError(f"service config not found: {path}")
    if path.exists():
        with path.open("rb") as fh:
            file_data = tomllib.load(fh)
        _warn_file_secrets(file_data, path)
        _merge(data, file_data)

    _merge(data, _env_overrides(environ))
    if cli:
        _merge(data, cli)

    return ServiceSettings.model_validate(data)
