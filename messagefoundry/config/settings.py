"""Operational **service settings** — deployment config, distinct from the code-first message graph.

The message graph (Connections/Routers/Handlers) is authored in Python and loaded from ``--config``;
this module covers the *operational* knobs an admin sets to run the service: where the store lives,
the API bind address, logging. They load from a TOML file + environment + CLI, with precedence::

    CLI flag  >  environment variable  >  messagefoundry.toml  >  built-in default

Secrets (e.g. a future DB password) belong in **env** (``MEFOR_<SECTION>_<KEY>``), never in the file.
This is the first cut (build-order step 1 of docs/CONFIGURATION.md): ``[store]`` (backend/path/
synchronous), ``[api]`` (host/port), and ``[logging]`` (level). ``[retention]`` is now enforced (the
``RetentionRunner``), except its ``audit_days`` key, which is reserved/keep-forever by design.
Remaining planned keys (some server-DB ``[store]`` keys, structured ``[logging]``) are
accepted-but-ignored for now so a forward-looking config file still loads.
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

from messagefoundry.config.ai_policy import AiDataScope, AiEnvironment, AiMode
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
)
from messagefoundry.logging_setup import LOG_LEVELS

__all__ = [
    "StoreBackend",
    "SqliteSync",
    "SqlAuth",
    "StoreSettings",
    "ApiSettings",
    "InboundSettings",
    "DeliverySettings",
    "EnvironmentsSettings",
    "LoggingSettings",
    "ReferenceSettings",
    "RetentionSettings",
    "AuthSettings",
    "AiSettings",
    "AiMode",
    "AiDataScope",
    "AiEnvironment",
    "EgressSettings",
    "AlertsSettings",
    "ClusterSettings",
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
    "alerts",
    "cluster",
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
)


class StoreBackend(str, Enum):
    SQLITE = "sqlite"
    SQLSERVER = (
        "sqlserver"  # implemented but EXPERIMENTAL / not production-ready (see store/sqlserver.py)
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

    @field_validator("config_reload_roots", "ws_allowed_origins", mode="before")
    @classmethod
    def _split_roots(cls, v: object) -> object:
        # The env layer delivers list settings (MEFOR_API_CONFIG_RELOAD_ROOTS,
        # MEFOR_API_WS_ALLOWED_ORIGINS) as one string; split it on the platform path separator so
        # these list-typed settings can be set via env (review low-12).
        if isinstance(v, str):
            return [p for p in v.split(os.pathsep) if p]
        return v


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


class EnvironmentsSettings(_Section):
    """Where the per-environment **values** (``env()`` lookups in the message graph) live.

    The ACTIVE environment is the single cross-cutting selector ``[ai].environment`` (dev/staging/
    prod); this section only locates the value files. Each environment has a ``<env>.toml`` flat
    table under ``dir`` for non-secret values (versioned), overlaid by ``MEFOR_VALUE_<KEY>`` env
    vars for secrets. See docs/CONFIGURATION.md."""

    dir: str = "environments"  # directory of <env>.toml value files, relative to the working dir


class LoggingSettings(_Section):
    level: str = "INFO"

    @field_validator("level")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        upper = value.upper()
        if upper not in LOG_LEVELS:
            raise ValueError(
                f"invalid log level {value!r}; expected one of {', '.join(LOG_LEVELS)}"
            )
        return upper


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


class AiSettings(_Section):
    """Central AI-assistance policy: the two axes (mode + data scope) bounded by an environment
    ceiling. The effective, enforced policy is computed by
    :func:`~messagefoundry.config.ai_policy.resolve_effective_policy` (the API endpoint and the
    ``ai-policy`` CLI both clamp these before serving them). See docs/AI.md."""

    mode: AiMode = AiMode.BYO
    data_scope: AiDataScope = AiDataScope.CODE_ONLY
    # Unset resolves to the safest ceiling: prod floors non-BAA modes at code_only.
    environment: AiEnvironment = AiEnvironment.PROD

    # --- forward-compat (accepted-but-UNUSED in this MVP; for the P1 engine broker) ----------
    # These describe a managed provider connection. They parse so a forward-looking config loads,
    # but nothing in this build reads them — managed modes are not yet implemented.
    provider: str = "claude"
    model: str = "claude-opus-4-8"
    baa_attested: bool = False
    endpoint: str | None = None


class EgressSettings(_Section):
    """``[egress]`` — fail-closed outbound destination allowlist (WP-11c; ASVS 13.2.4/13.2.5/14.2.3).

    Bounds where the engine may **send** PHI, so a fat-fingered or hostile outbound destination can't
    exfiltrate it. Each list is **opt-in**: empty = unrestricted (today's behavior); once a transport's
    list is set, a destination of that transport not on it is **refused at config load/reload**
    (fail-closed), checked against the resolved (``env()``-substituted) destination. The webhook/SMTP
    *alert* sinks carry no PHI bodies and keep their own ``[alerts]`` host allowlists.
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
    """``[cluster]`` — horizontal scale-out coordination (Track B Steps 3-7).

    The multi-node coordination seam (a ``nodes`` table + per-node heartbeat + leader election) without
    changing single-node behavior: with ``enabled = false`` (the default) the engine uses the no-op
    :class:`~messagefoundry.pipeline.cluster.NullCoordinator` and runs byte-identically to before.
    With ``enabled = true`` on Postgres, the scale-out feature set is COMPLETE: leader election (Step 4),
    leader-gated poll-source intake (Step 4b), per-lane FIFO ownership (Step 5), cross-node reference +
    config-reload + transform-state convergence (Steps 6/6b), and the read-only observability API
    (Step 7 — ``/cluster/status`` + ``/cluster/nodes``). Exactly one node runs the leader-only WRITE
    singletons (retention, the lease-reclaim sweep) and re-reads each reference source while followers
    read-through the shared snapshot; an operator config reload propagates cluster-wide via a version
    token; and operators can see membership + leadership over the API. Operators must keep node clocks
    synced (NTP — leases are wall-clock), run identical config dirs on every node, and apply config
    changes via a coordinated (not rolling) restart — see ``docs/CLUSTERING.md``. The cross-section
    validator below requires ``[store].backend = postgres`` and ``[store].pool_size >= 2`` when this is
    enabled (the leader holds one dedicated pooled connection for its leadership advisory lock)."""

    enabled: bool = False
    # Override the auto-generated node id (host:pid:hex). Pin it for a stable identity across restarts
    # or in tests; left unset, the factory reuses the store's lease owner-id so node-id == owner-id.
    node_id: str | None = None
    # How often a node refreshes its `last_seen` heartbeat. The same cadence drives leader-lock
    # maintenance (Track B Step 4) — no separate leader-check knob. Must be > 0.
    heartbeat_seconds: float = 10.0
    # A node is considered dead when its last_seen is older than this. Consulted by DbCoordinator's
    # cluster_members() (Step 7) as the freshness filter for the /cluster/nodes observability endpoint —
    # it discards a crashed ex-leader's stale is_leader flag and bounds the failover window in which a
    # just-beaten node still counts toward the derived leader. It is NOT what transfers leadership: the
    # session-level leader advisory lock is (a crashed leader's lock auto-releases server-side). Must be > 0.
    node_timeout_seconds: float = 30.0
    # How often the LEADER runs the lease-reclaim sweep (reclaim_expired_leases) that recovers crashed
    # nodes' in-flight rows (Track B Step 4). Only the current leader acts; followers no-op. Must be > 0.
    reclaim_interval_seconds: float = 30.0

    @field_validator("heartbeat_seconds", "node_timeout_seconds", "reclaim_interval_seconds")
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


class ServiceSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")  # tolerate forward-looking/unknown sections

    store: StoreSettings = Field(default_factory=StoreSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    inbound: InboundSettings = Field(default_factory=InboundSettings)
    delivery: DeliverySettings = Field(default_factory=DeliverySettings)
    environments: EnvironmentsSettings = Field(default_factory=EnvironmentsSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    reference: ReferenceSettings = Field(default_factory=ReferenceSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    ai: AiSettings = Field(default_factory=AiSettings)
    egress: EgressSettings = Field(default_factory=EgressSettings)
    alerts: AlertsSettings = Field(default_factory=AlertsSettings)
    cluster: ClusterSettings = Field(default_factory=ClusterSettings)

    @model_validator(mode="after")
    def _cluster_requires_postgres(self) -> "ServiceSettings":
        """Cluster coordination needs a shared multi-node store. SQLite is single-file/single-node and
        SQL Server is experimental (no leases), so only the Postgres backend can back the ``nodes``
        table + row leases the coordinator depends on. This spans two sections, so it lives here (not
        on :class:`ClusterSettings`, which can't see ``[store]``)."""
        if self.cluster.enabled:
            if self.store.backend is not StoreBackend.POSTGRES:
                raise ValueError(
                    "[cluster].enabled requires [store].backend = 'postgres' "
                    f"(got {self.store.backend.value!r}); SQLite is single-node and SQL Server is "
                    "experimental — cluster coordination is Postgres-only"
                )
            if self.store.pool_size < 2:
                # Leader election holds ONE pooled connection for the lifetime of its session-level
                # advisory lock (Track B Step 4). With pool_size=1 that lone connection would be the
                # store's only connection, starving every query, so require headroom.
                raise ValueError(
                    "[cluster].enabled requires [store].pool_size >= 2 "
                    f"(got {self.store.pool_size}); the leader holds one dedicated pooled connection "
                    "for its leadership advisory lock, so a pool of 1 would starve the store. Note the "
                    "floor of 2 leaves only ONE working connection while a node holds the leader "
                    "connection under contention — prefer pool_size >= 3 for clustered Postgres"
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
