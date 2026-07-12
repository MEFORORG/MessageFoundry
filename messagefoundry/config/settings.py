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
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from messagefoundry.config.ai_policy import AiDataScope, AiMode, DataClass
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    Priority,
    RetryPolicy,
    StallThreshold,
)
from messagefoundry.config.tls_policy import (
    HopPosture,
    TrustAnchorMode,
    TrustAnchorPolicy,
    current_hop_posture,
    validate_proxy_tls_posture,
    validate_tls_ciphers,
)
from messagefoundry.logging_setup import LOG_LEVELS
from messagefoundry.service_status import is_safe_service_name

__all__ = [
    "StoreBackend",
    "SqliteSync",
    "SqlAuth",
    "StoreSettings",
    "ApiSettings",
    "TlsSettings",
    "InboundSettings",
    "DeliverySettings",
    "PipelineSettings",
    "SandboxSettings",
    "DiagnosticsSettings",
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
    "IntegritySettings",
    "BackupSettings",
    "DrSettings",
    "DrActivationMode",
    "ServiceSettings",
    "load_settings",
]

#: Known config sections (used to parse ``MEFOR_<SECTION>_<KEY>`` env vars).
_SECTIONS = (
    "store",
    "api",
    "tls",
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
    "integrity",
    "diagnostics",
    "backup",
    "dr",
    "pipeline",  # enables MEFOR_PIPELINE_* env overrides (e.g. MEFOR_PIPELINE_PER_LANE_WAKE, ADR 0061)
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


def hop_insecure_escape_downgrades(*, production: bool) -> bool:
    """Whether ``MEFOR_ALLOW_INSECURE_TLS`` may downgrade an insecure-hop REFUSE→WARN here (#200).

    The **clamp** on the blunt global escape for the posture-keyed hop refusal (ADR 0092, decision 2):
    the escape may only relax a hop REFUSE to WARN on a **non-production** instance. On production it is
    **inert** for hop refusal — it can NEVER satisfy a production-PHI hop (a deliberate behaviour change
    from the pre-#200 global escape, which silenced the refusal in every environment). Cells pass the
    result as :func:`~messagefoundry.config.tls_policy.insecure_hop_disposition`'s ``audited_opt_out``
    argument, so on production that argument is always ``False`` and the ``production`` REFUSE arm wins.
    Attestation (per-connection ``tls_hop_attested``) is the only way to cross a prod-PHI hop."""
    return insecure_tls_allowed() and not production


def weakened_tls_escape_permitted(posture: HopPosture | None = None) -> bool:
    """Whether ``MEFOR_ALLOW_INSECURE_TLS`` may permit a weakened / verify-off TLS hop under ``posture``,
    CLAMPED so a production-PHI hop is NEVER relaxed (#200, ADR 0092 decision 2).

    The is_phi-blind **strict verify-off** cells — the engine<->store TLS gate
    (:func:`~messagefoundry.store.sqlserver.connection_string` / ``store.postgres._build_ssl``), the MLLP
    and FTPS ``tls_verify=false`` contexts, and the credentialed plain-``ftp`` guard — route their global-
    escape check through here so the blunt escape can no longer silence a **production-PHI** refusal
    (matching the ``--allow-insecure-bind`` API-bind clamp). Pass the construction-time
    :func:`~messagefoundry.config.tls_policy.current_hop_posture` (transport cells) or the store's threaded
    posture. Semantics: the escape must be set at all, AND the hop must not be production-PHI. ``None``
    (a backup utility / embedding / test outside the construction gate) falls back to the **unclamped**
    escape — byte-identical to pre-#200 — since the enforced serve/reload gate already vetted the real
    production posture, so this fallback never loosens the clamp."""
    if not insecure_tls_allowed():
        return False
    if posture is None:
        return True
    return not (posture.production and posture.is_phi)


def weakened_tls_escape_permitted_here() -> bool:
    """:func:`weakened_tls_escape_permitted` keyed on the ACTIVE construction posture (#200).

    Convenience for a transport cell built inside the ``active_hop_posture`` construction scope: reads
    :func:`~messagefoundry.config.tls_policy.current_hop_posture` itself so the call site stays a drop-in
    replacement for the old bare ``insecure_tls_allowed()`` check."""
    return weakened_tls_escape_permitted(current_hop_posture())


#: Env var that explicitly permits loading config from a source a low-privileged principal can write
#: (a user-writable dev/CI checkout). Off by default so a production service fails closed (SEC-003).
INSECURE_CONFIG_SOURCE_ESCAPE_ENV = "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE"


def insecure_config_source_allowed() -> bool:
    """Whether the explicit dev/test escape to load config from a writable-by-others source is set.

    The config loader executes config Python as the engine's service account (which holds PHI + DB
    credentials), so a directory a low-privileged user can write is a local code-execution vector and
    is **refused** at load time (SEC-003, CWE-732). A production deployment locks the config dir (the
    installer does — see docs/SERVICE.md), so it never trips. This escape downgrades the refusal to a
    loud warning for a dev/CI checkout that is intentionally user-writable (e.g. the default ACL on a
    Windows runner grants ``BUILTIN\\Users`` write); it must never be set in production, mirroring
    ``MEFOR_ALLOW_INSECURE_TLS``."""
    return os.environ.get(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


class StoreSettings(_Section):
    backend: StoreBackend = StoreBackend.SQLITE

    # --- SQLite (default backend) -------------------------------------------
    path: str = "messagefoundry.db"
    synchronous: SqliteSync = SqliteSync.NORMAL
    # App-side group-commit (ADR 0055, SQLite only). When > 0, the SQLite store runs a dedicated
    # committer coroutine that COALESCES the grouped stage-handoff mutations (enqueue_ingress,
    # route_handoff, transform_handoff, mark_done, complete_with_response, dead_letter_now, mark_failed)
    # into ONE durable commit, amortizing the per-commit fsync (a large win under synchronous=FULL,
    # muted under the default NORMAL). A member waits up to this window (milliseconds) for siblings to
    # join before the batch commits; the claim*/reference-snapshot/audit writes stay STANDALONE (never
    # grouped — Hazard A / hash-chain). The window is bounded above by `command_timeout`-class latency,
    # but in practice a few ms is plenty. DEFAULT 0 = DISABLED → byte-identical to the inline-commit
    # path (no committer coroutine, each method commits as it always has). Off-by-default is mandatory:
    # this is reliability-core code (ADR 0055). Ignored by the server-DB backends, which coalesce via
    # their connection pool + concurrent submission instead. "Native commit_delay" is PostgreSQL-ONLY
    # (a durability-neutral GUC, a planned gated/off-by-default increment); SQL Server has NO durability-
    # neutral group-commit knob (its DELAYED_DURABILITY relaxes durability and is rejected for the PHI
    # store), so its scale path is the concurrent pool + sharding (ADR 0037), not a native GUC.
    group_commit_window_ms: float = 0.0
    # Flush threshold for the group-commit committer: once this many members are enrolled in the open
    # batch, it commits immediately without waiting out the rest of `group_commit_window_ms` (bounds
    # batch size / latency under load). Ignored when group-commit is disabled (window == 0).
    group_commit_max_batch: int = 64
    # Batch-claim on the INGRESS/ROUTED FIFO claim path (ADR 0058; all three backends). The router /
    # transform workers normally claim ONE row per commit (claim_next_fifo, a standalone DB round-trip on
    # the critical path). When this is > 1 they instead claim the CONTIGUOUS DUE head-prefix — up to this
    # many of the lane's oldest due rows in ONE commit (claim_next_fifo_batch) — then process each in
    # strict FIFO order with its own per-row off-loop route/transform + separate handoff, amortizing the
    # standalone claim commit toward 1/N. The contiguous-due-prefix + block-on-locked-head rules keep
    # strict per-lane FIFO (#285); a not-due/locked head still blocks the lane (empty batch == single-claim
    # None). The OUTBOUND/delivery claim is NEVER batched (its skip-and-complete dedup must stay atomic).
    # DEFAULT 1 = OFF → byte-identical to the single TOP(1)/LIMIT 1 claim (the batch method is never
    # invoked). > 1 is opt-in throughput tuning (recommend 8-16; size against worst-case message size, not
    # the average — N decrypted bodies are resident per lane between the one claim and the N handoffs).
    fifo_claim_batch: int = Field(
        default=1,
        ge=1,
        le=64,
        description=(
            "Max rows the INGRESS/ROUTED FIFO claim takes per commit (ADR 0058). 1 = OFF "
            "(byte-identical to the single claim). > 1 claims the contiguous due head-prefix in one "
            "commit (opt-in throughput tuning; outbound is never batched)."
        ),
    )

    # --- PHI-at-rest encryption (both backends; STORE-1 / WP-5) -------------
    # Base64 32-byte ACTIVE key; when set, PHI columns (raw bodies + summary/metadata + error/
    # last_error/detail) are AES-256-GCM-encrypted at rest. (SQL Server encrypts raw + summary/metadata
    # + the response/payload bodies; its error/last_error/detail stay plaintext — see sqlserver.py.)
    # Secret — supply via MEFOR_STORE_ENCRYPTION_KEY, never the file.
    # Empty = off (values stored as-is).
    encryption_key: str | None = None
    # Comma-separated base64 RETIRED keys, kept available for *decrypt only* during a key rotation
    # (ASVS 11.2.2) until `messagefoundry rotate-key` finishes re-encrypting under the active key.
    # Secret — env-only (MEFOR_STORE_ENCRYPTION_KEYS_RETIRED). Empty = none.
    encryption_keys_retired: str = ""
    # When true, `serve` refuses to start without an encryption key (any environment, any data_class).
    # Off by default. See docs/PHI.md §3. (Independent of the data_class-gated keyless refusal below:
    # this forces the refusal even for a synthetic/non-PHI instance.)
    require_encryption: bool = False
    # Explicit, audited opt-out of the data_class-gated keyless refusal (H3, OWASP *Fail Securely* / SDS
    # §4.3 PW.9). By default a PHI-carrying instance (`[ai].data_class == phi`, ANY environment) REFUSES
    # to start with no encryption key — secure-by-default. Setting this true is the loud, deliberate
    # override that lets such an instance start keyless (it still emits the UNENCRYPTED-at-rest warning
    # and the override is audited at startup). It does NOT override `require_encryption=true` (that wins).
    # A synthetic/non-PHI instance never needs this — it stays key-free regardless (CI parity).
    allow_unencrypted_phi: bool = False
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
    # Delegated-identity precondition (#203, ASVS 13.2.1/13.3.2). Off by default. When true, `serve`
    # asserts the store authenticates via a MANAGED / DELEGATED identity (Windows Integrated or Entra),
    # NOT a static username+password: a production instance refuses to start and a non-production one
    # warns if the store uses a static credential. It makes the operator's least-privilege identity
    # posture a CHECKED precondition rather than a silent assumption. SQLite (a local file, no network
    # credential) is exempt; Postgres has no managed-identity auth mode, so it cannot satisfy it. Admin
    # device posture + AD/SMTP managed identity stay deployment-delegated (see docs/SECURITY.md).
    require_managed_identity: bool = False
    encrypt: bool = True
    trust_server_certificate: bool = False
    # Optional certificate file to verify the DB server certificate against a PRIVATE / self-signed CA (the
    # common hospital-estate posture) WITHOUT installing it box-globally into the OS trust store. Honored by
    # BOTH server-DB backends (#45), on the SECURE posture only (encrypt=true, trust_server_certificate=false)
    # — it NEVER disables verification:
    #   * POSTGRES — asyncpg takes an SSLContext, so this loads ssl.create_default_context(cafile=...), a
    #     CA-bundle pin (chain + hostname still verified).
    #   * SQL SERVER — the ODBC Driver 18.1+ `ServerCertificate` keyword pins the server's certificate by
    #     file (a leaf/exact-cert match, brace-quoted STORE-5-safe); requires ODBC Driver 18.1 or newer.
    # REJECTED for SQLite (no TLS at all). A path, not a secret — it may live in the config file /
    # connections.toml. Empty = use the system trust store (the secure default). Existence is checked at load
    # (a missing file fails loud here, not confusingly at connect).
    ssl_root_cert: str | None = None
    # SQL SERVER ONLY: emit the ODBC `MultiSubnetFailover=Yes` keyword so a client connecting to an
    # Always On Availability Group *listener* reaches the current PRIMARY promptly across subnets,
    # instead of serially waiting out each replica subnet's DNS/TCP timeout on failover. A no-op for
    # Postgres/SQLite (they never see the ODBC string). Default off — only multi-subnet AOAG needs it.
    multi_subnet_failover: bool = False
    pool_size: int = 40
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

    # --- Store connection-pool pre-warm (server-DB backends only; no-op on SQLite) ----------
    # On graph start/promotion the engine fires a best-effort BACKGROUND task that pre-opens pooled
    # connections so a connection burst (the post-promotion delivery workers in active-passive HA, or a
    # cold start) finds them warm instead of paying cold connects (TCP+TLS+login — the dogfood box
    # measured 340-958 ms ODBC acquires stretching failover recovery). UNLIKE group-commit this is
    # ON-by-default: it touches no message-handling/commit seam (it only pre-acquires then releases
    # connections, is bounded, self-releasing, never raises), so the reliability-core off-by-default rule
    # does not apply — but a connection-constrained/licensed site can set this false to opt out.
    warm_pool: bool = True
    # Upper bound (seconds) on the background warm-up; on expiry it logs and continues with a partially
    # warm pool. Default 15.0 = connect_timeout (a warm acquire IS a connect), comfortably below the
    # cluster's leader_fence_timeout_seconds (default 20.0) so a warm can't outlive the leadership term
    # that started it. A clustered server-DB node rejects an EXPLICIT value that violates that bound
    # (ServiceSettings._warm_pool_timeout_under_fence); the default never breaks a config.
    warm_pool_timeout: float = 15.0
    # How many connections to pre-open. None (default) = a safe fraction of the pool
    # (min(pool_size-1, pool_size//2)) so the warm never pins more than half the pool while the concurrent
    # startup work (on-promotion recovery, the coordinator heartbeat, the first delivery workers) keeps
    # slots; an explicit value is clamped to pool_size-1. A pool of 1 is never warmed. At the default
    # pool_size=40 this resolves to min(39, 20) = 20 pre-opened connections per server-DB engine at startup.
    warm_pool_target: int | None = None

    def managed_identity_precondition(self) -> str | None:
        """When ``require_managed_identity`` is set, the reason the store VIOLATES the delegated-
        identity precondition (#203, ASVS 13.2.1/13.3.2), or ``None`` when it is satisfied / the flag
        is off. SQLite (a local file) is exempt; SQL Server must use Integrated/Entra auth; Postgres
        has no managed-identity mode. The caller (``serve``) refuses on production, warns otherwise."""
        if not self.require_managed_identity:
            return None
        if self.backend is StoreBackend.SQLITE:
            return None  # a local file has no network credential to delegate
        if self.backend is StoreBackend.SQLSERVER:
            if self.auth in (SqlAuth.INTEGRATED, SqlAuth.ENTRA):
                return None
            return (
                "the SQL Server store uses a static SQL login ([store].auth='sql'); "
                "set [store].auth to 'integrated' (gMSA) or 'entra'"
            )
        return (
            "the Postgres store authenticates with a static username+password (no managed-identity "
            "mode); use a SQL Server store with [store].auth='integrated'/'entra', or clear "
            "[store].require_managed_identity"
        )

    @field_validator("lease_ttl_seconds")
    @classmethod
    def _positive_lease_ttl(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("lease_ttl_seconds must be > 0")
        return value

    @field_validator("group_commit_window_ms")
    @classmethod
    def _nonneg_group_commit_window(cls, value: float) -> float:
        # 0 = disabled (the default); a negative window is meaningless and would otherwise enable an
        # always-flush committer with no coalescing benefit.
        if value < 0:
            raise ValueError("group_commit_window_ms must be >= 0 (0 disables group-commit)")
        return value

    @field_validator("group_commit_max_batch")
    @classmethod
    def _positive_group_commit_max_batch(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("group_commit_max_batch must be > 0")
        return value

    @field_validator("warm_pool_timeout")
    @classmethod
    def _positive_warm_pool_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("warm_pool_timeout must be > 0")
        return value

    @field_validator("warm_pool_target")
    @classmethod
    def _positive_warm_pool_target(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("warm_pool_target must be > 0 (or unset for the pool-size default)")
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

    @field_validator("ssl_root_cert")
    @classmethod
    def _ssl_root_cert_exists(cls, value: str | None) -> str | None:
        """Fail loud at load if the pinned cert path is missing, rather than surfacing a confusing
        error only at connect (#45). A path, not a secret — cheap to stat here. Empty/unset = no-op."""
        if value and not Path(value).is_file():
            raise ValueError(
                f"[store].ssl_root_cert path does not exist or is not a file: {value!r}"
            )
        return value

    @model_validator(mode="after")
    def _ssl_root_cert_backend(self) -> "StoreSettings":
        """``ssl_root_cert`` pins the DB server certificate for verification (#45). Both server-DB
        backends honor it — Postgres as an asyncpg SSLContext CA-bundle, SQL Server via the ODBC Driver
        18.1+ ``ServerCertificate`` keyword — but SQLite uses no TLS, so setting it there is a silent
        no-op: fail loud instead of leaving the operator thinking a private CA is pinned."""
        if self.ssl_root_cert and self.backend is StoreBackend.SQLITE:
            raise ValueError(
                "[store].ssl_root_cert requires a server-DB backend (postgres or sqlserver); "
                "SQLite uses no TLS, so pinning a certificate has no effect."
            )
        return self


class ApiSettings(_Section):
    host: str = "127.0.0.1"  # Phase 1 = localhost only
    port: int = 8765
    expose_docs: bool = False  # serve /docs, /redoc, /openapi.json (off by default; widens surface)
    # Serve the same-origin, read-only browser ops dashboard under /ui (ADR 0065, BACKLOG #75). Off by
    # default so a JSON-only deployment is byte-identical; when on, the engine mounts /ui + /ui/static and
    # accepts an HttpOnly session cookie CONFINED to /ui (the JSON API stays Authorization-header-only).
    # Off a loopback host it requires exposure_protected (see serve gate) — the UI is a stricter surface.
    serve_ui: bool = False
    # The browser-facing external origin of the /ui dashboard when it is reached OFF-loopback through a
    # reverse proxy that does NOT preserve the Host header (ADR 0065). The same-origin CSRF + CSWSH checks
    # normally compare the browser's Origin to the request Host; behind such a proxy the Host is the
    # internal one, so set this to the exact public origin (e.g. "https://ops.example.com") and the checks
    # validate against it instead. Empty (default) = loopback / Host-preserving-proxy behavior, unchanged.
    public_origin: str | None = None
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
    # mTLS client-cert → MessageFoundry principal map (#200, ADR 0002). Meaningful only with in-process
    # mTLS (tls_client_ca_file set, so uvicorn CERT_REQUIRED-verifies the client). A VERIFIED peer cert's
    # subject CN / SAN is resolved to an existing username via this ALLOW-LIST, and that principal's RBAC
    # authorizes the request (a service-to-service identity that carries no bearer token). Keys are the
    # QUALIFIED cert name "CN:<commonName>" or "SAN:<type>:<value>" (e.g. "SAN:DNS:svc.internal"); values
    # are existing usernames. DENY-BY-DEFAULT: an unmapped verified cert — or any spoofed CN not present
    # here — resolves to no identity and is denied. Structured map → TOML-only (no env-string form). An
    # empty map (default) disables cert-identity, byte-identical to the pre-#200 mTLS-for-transport-only
    # behavior. NOTE (honest): stock uvicorn does NOT surface the peer cert to the ASGI scope, so this
    # resolver is inert until a TLS-extension-capable server/shim populates it — see api/security.py.
    tls_client_cert_identities: dict[str, str] = {}

    # --- Reverse-proxy / upstream TLS termination (WP-15, ADR 0002) --------
    # Proxy IPs whose X-Forwarded-For/-Proto headers are trusted (uvicorn forwarded_allow_ips). Empty =
    # trust nothing (the audit/rate-limit source IP is then the direct TCP peer). Set this ONLY to the
    # reverse proxy's address(es), or XFF spoofing returns.
    trusted_proxies: list[str] = []
    # Declare that a reverse proxy / load balancer terminates TLS in front of the engine. Lets a
    # non-loopback bind satisfy the exposed-gate WITHOUT in-process TLS — but only when trusted_proxies
    # is set (so the engine knows a terminator is really in front).
    tls_terminated_upstream: bool = False

    # --- Posture-B (upstream TLS termination) attestations (#200, ADR 0002) --------
    # In Posture-B the proxy terminates browser TLS and the proxy→engine hop is a plaintext segment on
    # the internal network. The ENGINE cannot observe the proxy's negotiated TLS/KEX or authenticate the
    # internal hop for itself, so a PHI-PRODUCTION Posture-B bind must not start on trust alone. These are
    # operator ATTESTATIONS made FAIL-CLOSED (mirroring MEFOR_TLS_REVOCATION_ATTESTED): the serve gate
    # REFUSES a production-PHI Posture-B bind unless both are affirmatively declared (warns on non-prod
    # PHI, quiet on synthetic — byte-identical). They are NOT runtime enforcement (see the honest docs).
    #
    # proxy_intra_service_auth — HOW the proxy→engine hop is authenticated so a rogue peer on the internal
    #   segment cannot impersonate the proxy. "none" (default) is undeclared → refuse on prod-PHI. Declare
    #   "mtls" (the proxy presents a client cert), "network" (an isolated proxy↔engine segment / host
    #   firewall allow-list), or "shared_secret" (a pre-shared header the proxy injects). Attestation only.
    proxy_intra_service_auth: Literal["none", "mtls", "network", "shared_secret"] = "none"
    # proxy_tls_min_version — the operator-DECLARED TLS version floor the reverse proxy negotiates with
    # browsers ("1.2"/"1.3"). None (default) = undeclared → refuse on prod-PHI Posture-B. The engine
    # terminates no browser TLS here, so it cannot inspect the proxy's version (11.6.2) — this is the
    # attested floor, validated only for coherence at load.
    proxy_tls_min_version: str | None = None
    # proxy_tls_ciphers — an OPTIONAL declared OpenSSL cipher list for that proxy floor. When set it must
    # resolve to forward-secret (EC)DHE suites (ASVS 11.6.2), reusing the in-process cipher validator, so
    # a declared floor can't itself name a non-forward-secret key exchange. None = no cipher declaration.
    proxy_tls_ciphers: str | None = None

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

    @property
    def proxy_intra_service_declared(self) -> bool:
        """Whether the Posture-B proxy→engine intra-service-auth posture is affirmatively declared
        (#200). ``"none"`` (the default) is undeclared → a prod-PHI Posture-B bind refuses."""
        return self.proxy_intra_service_auth != "none"

    @property
    def proxy_tls_floor_declared(self) -> bool:
        """Whether the Posture-B proxy TLS/KEX floor is declared (#200): a ``proxy_tls_min_version`` is
        set. Undeclared → a prod-PHI Posture-B bind refuses (the engine cannot observe the proxy's TLS)."""
        return self.proxy_tls_min_version is not None

    @field_validator("public_origin", mode="after")
    @classmethod
    def _normalize_public_origin(cls, v: str | None) -> str | None:
        """Require a bare origin (``scheme://host[:port]``, no path/query/fragment) and normalize it, so
        the same-origin comparison is an exact match against the browser's ``Origin`` header."""
        if not v:
            return None
        parts = urlsplit(v)
        if (
            parts.scheme not in ("http", "https")
            or not parts.netloc
            or parts.path.rstrip("/")
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "[api].public_origin must be a bare origin like 'https://ops.example.com' "
                "(scheme + host, no path/query/fragment)"
            )
        # Lowercase scheme + host (case-insensitive per RFC 3986 §3.2.2) so the same-origin comparison
        # is reliable regardless of how the admin cased it or how the browser sends the Origin.
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"

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
        # A cert-identity ALLOW-LIST only means anything when the engine actually verifies client certs
        # (in-process mTLS): without tls_client_ca_file no peer cert is validated, so a mapping would be
        # a false sense of a service identity. Fail loud at load, not silently ignore it (#200).
        if self.tls_client_cert_identities and not self.tls_client_ca_file:
            raise ValueError(
                "[api].tls_client_cert_identities requires [api].tls_client_ca_file (in-process mTLS "
                "verifies the client cert before its subject is resolved to a principal)"
            )
        # An upstream TLS terminator only satisfies the exposed-gate when the engine knows (and trusts)
        # the proxy in front — otherwise it's an unverifiable claim that XFF could spoof.
        if self.tls_terminated_upstream and not self.trusted_proxies:
            raise ValueError("[api].tls_terminated_upstream requires [api].trusted_proxies")
        # Validate the DECLARED Posture-B proxy TLS floor for internal coherence (#200, ASVS 11.6.2) —
        # an attestation, but a *coherent* one (a NIST version floor; forward-secret ciphers if named).
        validate_proxy_tls_posture(self.proxy_tls_min_version, self.proxy_tls_ciphers)
        return self


class TlsSettings(_Section):
    """``[tls]`` — the instance-wide client **trust-anchor** policy (#190, ADR 0093).

    A small, shared fallback for outbound connectors that verify a downstream *server* certificate
    (MLLP/DICOM/FTPS today). By default the OS trust store roots verify the peer; a hospital estate
    whose internal endpoints present a PRIVATE / internal-CA cert can pin that CA here once instead of
    installing it box-globally or repeating a per-connection ``tls_ca_file``. This is a CLIENT trust
    anchor — it selects WHICH roots verify the peer, it NEVER disables verification — so it composes
    with (never weakens) the connectors' fail-closed no-CA / ``tls_verify=false`` / cleartext-hop
    refusals. A connection that names its **own** ``tls_ca_file`` always wins verbatim; a loopback hop
    is exempt. Default (``internal_ca_file`` unset, ``trust_anchor_mode="system"``) = no-op, so a config
    with no ``[tls]`` block builds a byte-identical SSL context."""

    # PEM path to the org's internal CA (NOT a secret — a path, like tls_cert_file / forward_tls_ca_file).
    # Empty (default) = no internal anchor; every hop uses the OS trust store (byte-identical).
    internal_ca_file: str | None = None
    # How internal_ca_file composes with the OS default roots for a non-loopback internal hop:
    #   "system"  (default) — OS trust store only; internal_ca_file is ignored (byte-identical to today).
    #   "augment" — OS roots AND the internal CA (a mixed public + private estate).
    #   "pinned"  — ONLY the internal CA, not the public bundle (a fully-private estate; strictest,
    #               the forward_tls_ca_file template).
    trust_anchor_mode: TrustAnchorMode = "system"

    @model_validator(mode="after")
    def _check_pinned_requires_internal_ca(self) -> "TlsSettings":
        # "pinned" is the exclude-public-CAs posture — trust ONLY the internal CA. With no
        # internal_ca_file there is nothing to pin, so resolve_trust_anchor falls back to the full OS
        # trust store: the operator asked to EXCLUDE public roots but silently got all of them (a
        # fail-open misconfig). Refuse it at load (like [api]'s half-configured-TLS guards) so the
        # intent can't collapse to a wider trust store. ("augment" without a CA is harmless — it equals
        # "system" — and "system" ignores the field, so only "pinned" needs the anchor.)
        if self.trust_anchor_mode == "pinned" and not self.internal_ca_file:
            raise ValueError(
                "[tls].trust_anchor_mode = 'pinned' requires [tls].internal_ca_file (pinned trusts "
                "ONLY the internal CA; with no CA it would silently fall back to the full OS trust "
                "store, defeating the exclusion of public CAs)"
            )
        return self

    def policy(self) -> TrustAnchorPolicy:
        """The resolved :class:`~messagefoundry.config.tls_policy.TrustAnchorPolicy` threaded onto each
        outbound so a connector's client-verify context resolves the same anchor at build_check and
        live construction (the internal-outbound context builders call ``resolve_trust_anchor``)."""
        return TrustAnchorPolicy(
            internal_ca_file=self.internal_ca_file, mode=self.trust_anchor_mode
        )


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
    # message_stall alert threshold (Corepoint "Max Message Stall") for every outbound. Mirror
    # StallThreshold (a test guards the sync); None (the default) = the stall alert is OFF — deny-by-
    # default, opt-in because it overlaps queue_buildup's age dimension. Per-connection stall= overrides.
    stall_max_oldest_seconds: float | None = None
    # Global DR / priority tier default for every connection (#61, ADR 0048). A connection that declares
    # no priority= of its own inherits this (resolution order: per-connection override > [delivery]
    # global default > built-in NORMAL); the DR run-profile then starts only connections whose resolved
    # tier rank >= [dr].priority_threshold rank. NORMAL keeps every connection at the same tier by default
    # (so a deployment that never enables DR is byte-unchanged). An unknown value fails config load.
    priority: Priority = Priority.NORMAL

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

    def stall_threshold(self) -> StallThreshold:
        """The global default :class:`StallThreshold` an outbound inherits when it sets none (#50,
        Corepoint "Max Message Stall"). ``None`` keeps the stall alert off by default."""
        return StallThreshold(max_oldest_seconds=self.stall_max_oldest_seconds)


class PipelineSettings(_Section):
    """Staged-pipeline tunables (ADR 0013 Increment 2). ``max_correlation_depth`` bounds re-ingress
    loops: a re-ingressed message at this correlation depth still routes, but the next hop (depth+1)
    dead-letters its work-row and the origin is marked ``ERROR``. Coarse by design (it bounds total work,
    not topology) — a chain that legitimately bounces A→B→A a few times needs headroom; the default 8 is
    safe for typical request→response→route feeds. Floor of 1 (a value of 0 would dead-letter every
    re-ingress)."""

    max_correlation_depth: int = Field(default=8, ge=1)

    # Per-lane wake events (B12, ADR 0061). DEFAULT-OFF: when False the engine uses the historical
    # engine-wide singleton wake events (byte-identical). When True, a committed message wakes ONLY its
    # own (stage, lane) worker instead of every worker of that stage — killing the ~1,500-worker
    # thundering-herd empty-claim storm at connection scale. Reliability-core + read ONCE at engine
    # construction (a /config/reload does NOT toggle it — restart to change). Harness A/B via
    # MEFOR_PIPELINE_PER_LANE_WAKE. The 0.25s poll_interval lost-wakeup backstop is unchanged in both arms.
    per_lane_wake: bool = Field(default=False)

    # Pooled per-stage claimers (ADR 0066). DEFAULT: claim_mode="pooled" runs one StageDispatcher per
    # stage — K claimer tasks batch-claim head-prefixes across lanes, collapsing the ~1,500-worker
    # claim-session storm and holding zero-loss at high fan-out where per_lane drops messages. The
    # default was flipped from "per_lane" to "pooled" for issue #744 on the rate-walk resilience GO
    # (single-node), the reinterpreted §8.12b (target-vs-capacity, not a pooled fault), and the row-1b
    # fan-in soak PASS on live SS+PG. "per_lane" stays fully selectable as the opt-out — it is
    # byte-identical to the pre-ADR-0066 topology (one worker per inbound router/transform + per
    # outbound), enforced by a test sentinel. Reliability-core + read ONCE at engine construction (a
    # /config/reload does NOT toggle claim_mode or any pooled_* knob — restart to change, exactly like
    # per_lane_wake). Harness A/B via MEFOR_PIPELINE_CLAIM_MODE. Caveats (docs/CONNECTIONS.md): the
    # flip evidence is single-node (NullCoordinator) — failover duplicate/ordering paths are unmeasured
    # (ADR 0070 tracks the T17 infra-fault limitation); and exactly-once still degrades under load
    # (no inbound de-dup — the "receivers must be idempotent" contract contains it), not pooled-specific.
    claim_mode: Literal["per_lane", "pooled"] = Field(default="pooled")
    # K claimer tasks per stage (>1 hash-partitions lanes across claimers).
    pooled_claimers_per_stage: int = Field(default=1, ge=1)
    # The clock-driven sweep interval (the bounded at-least-once backstop). 0.25s = poll_interval parity.
    pooled_sweep_interval: float = Field(default=0.25, gt=0)
    # Max lanes batch-claimed per claim round-trip. Clamped DOWN at construction to the backend store
    # chunk (SQLite 200, SS/PG 500) so the dispatcher never over-sends lanes the store would drop.
    pooled_claim_lane_chunk: int = Field(default=256, ge=1, le=500)
    # Max concurrently-PROCESSING lanes per stage (the decrypted-body / crash-exposure bound).
    pooled_max_processing_lanes: int = Field(default=256, ge=1)
    # SQL Server pooled mode fails closed at startup if READ_COMMITTED_SNAPSHOT is OFF; False downgrades
    # to a loud warning + a /stats rcsi_off_degraded gauge (the §3.2 correctness proofs assume RCSI on).
    require_rcsi_for_pooled: bool = Field(default=True)

    # Pooled T17 (infra/machinery-fault) handling (ADR 0070). A store/handoff error, or any raise from
    # OUTSIDE the per-item body, is caught by the dispatcher's T17 handler; fix A always re-pends the
    # faulting head at an exponential-capped backoff (collapsing the ~4×/s sweep spin). This policy
    # bounds a PERSISTENT such fault. "stop" (default) STOPs the head-of-line-blocked lane after
    # infra_fault_stop_after consecutive zero-progress faults (~4 min under the backoff) — reusing the
    # InternalErrorPolicy.STOP muscle (STOPPED phase + connection_stopped alert + reload/notify_work
    # re-arm), never dead-lettering the good message. "retry_forever" never STOPs — it retries the head
    # at capped backoff forever and emits a throttled lane_stuck alert once the horizon is crossed (for
    # a deliberately-unattended flaky-infra site). Reliability-core + read ONCE at construction (a
    # /config/reload does NOT re-read it — restart to change, exactly like claim_mode).
    infra_fault_policy: Literal["stop", "retry_forever"] = Field(default="stop")
    # Consecutive zero-progress T17 faults before a "stop"-policy lane transitions to STOPPED. Also the
    # "retry_forever" stuck horizon at which the throttled lane_stuck alert first fires. Under the
    # exponential backoff (cap infra_fault_backoff_cap) 10 spans ~4 min of wall clock — a duration gate.
    infra_fault_stop_after: int = Field(default=10, ge=1)
    # Cap (seconds) on fix A's exponential head re-pend backoff (base = the dispatcher's 1s lane-error
    # backoff, doubling per consecutive zero-progress fault). ~60s keeps a recovered dependency picked
    # back up within ~1 min while still collapsing the spin.
    infra_fault_backoff_cap: float = Field(default=60.0, gt=0)

    # #109 (ADR 0095) partner-account-lockout protection. What an outbound File/FTP/SFTP sender does on
    # a PERMANENT credential/auth fault (bad password, key rejected). "stop" (default) halts the lane
    # IMMEDIATELY (not after a streak) and RETAINS the queued rows UN-ERRORED (they stay pending/
    # claimable, never dead-lettered), so a backlog cannot repeatedly re-authenticate and lock out the
    # partner account — reusing the STOP muscle (connection_stopped alert + reload/restart re-arm).
    # "dead_letter" keeps the historical fail-fast behaviour (dead-letter just the offending row and
    # advance). A content-permanent reject (AR/CR, no-such-dir) is UNAFFECTED — it still dead-letters.
    credential_fault_policy: Literal["stop", "dead_letter"] = Field(default="stop")

    # #147 (ADR 0095) per-connection active-window scheduler tick granularity (seconds). The runner
    # reconciles each SCHEDULED connection's up/down state against its window calendar every tick; a
    # window boundary is honoured within one tick. Only affects connections that declare a schedule
    # (byte-identical always-on otherwise). Small enough for prompt boundaries, large enough to not busy-
    # poll; injectable clock (tests) makes the boundary itself deterministic regardless of this value.
    schedule_tick_seconds: float = Field(default=30.0, gt=0)

    # ADR 0071 B5 thread-hop fusion. DEFAULT-OFF and SQL-Server-scoped: when True AND the store backend
    # is SQL Server AND claim_mode="pooled", each fused stage (INGRESS/ROUTED) runs its off-loop CPU
    # stage (route_only/transform_one) together with its store handoff on a SINGLE dedicated-executor
    # worker hop, collapsing a multi-statement aioodbc handoff into ONE executor->loop completion (the
    # profiled per-completion async-marshaling wall, ADR 0071 §2). Fail-closed + provably no-op on the
    # other backends: Postgres (asyncpg loop-native — nothing to fuse) and SQLite (loop-affine handoff
    # lock) keep the async path by construction; a non-SS backend logs "ignored" and runs async, and a
    # sync-handoff-pool open failure downgrades to the async path with a loud warning + a degraded gauge
    # (never a lane outage). Reliability-core + read ONCE at engine construction (a /config/reload does
    # NOT re-read it — restart to change, exactly like claim_mode). Harness A/B via
    # MEFOR_PIPELINE_FUSE_THREAD_HOPS.
    fuse_thread_hops: bool = Field(default=False)
    # Worker count for each per-stage fusing executor (ADR 0071 B5). Each fused stage (INGRESS/ROUTED)
    # gets its OWN ThreadPoolExecutor of this width plus a matching-width dedicated synchronous pyodbc
    # handoff pool (one connection per worker, so a fused hop never blocks acquiring). Small by default —
    # a fused hop holds a worker across DB latency, so this is the fused-stage concurrency; it also
    # clamps the fused stages' effective max_processing_lanes to ~2x this value (so the claimer does not
    # reserve 256 slots for a handful of workers, inflating in_pipeline + the crash-replay recovery set).
    pooled_fusing_workers: int = Field(default=8, ge=1)

    # ADR 0075 per-hop SQL statement batching. DEFAULT-ON (retained only as an emergency off-switch —
    # promoted 2026-07-08 as a distance-insurance lever; set false to disable) and SQL-Server-scoped: when True AND the store
    # backend is SQL Server, each per-hop staged handoff (route_handoff / transform_handoff) folds the
    # non-result-returning DML of its body into the fewest ``pyodbc.execute()`` T-SQL batches — same
    # ordered (sql, params) sequence, one round-trip per batch (the _SQL_APPLOCK precedent), still
    # committing exactly ONCE per hop (commits/msg stays 2.000). It cuts network round-trips, NOT
    # transactions: no commit boundary moves, the claim stays its own poison-guard txn, the ACK-on-receipt
    # fence is untouched. Each result-consuming statement whose value gates later control flow (the guard
    # DELETE, the finalize GROUP BY, and the finalize sp_getapplock rc-check) stays its own execute — the
    # rc-check is kept a client-side gate (the "strict" / applock_hard fold: the finalize UPDATE is only
    # SENT after the rc is validated >=0), so an ungranted lock never lets an unserialized write reach the
    # wire. Fail-closed + provably no-op on the other backends: Postgres (asyncpg loop-native, pipelines
    # internally) and SQLite (loop-affine single writer) have no batched path and run byte-identically; a
    # non-SS store ignores the flag (logged). Reliability-core + read ONCE at engine construction (a
    # /config/reload does NOT re-read it — restart to change, exactly like claim_mode / fuse_thread_hops).
    # Harness A/B via MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS.
    batch_handoff_statements: bool = Field(default=True)


class SandboxSettings(_Section):
    """``[sandbox]`` — opt-in subprocess isolation for Routers/Handlers (ADR 0087, BACKLOG #197).

    Routers/Handlers are admin-authored pure Python the engine runs in its own address space (the
    DEK, audit chain, and live sockets live there). ASVS 15.2.5 wants a hard isolation boundary; this
    section turns one on. ``mode="off"`` (the default) runs them in-process, **byte-identically and
    with zero overhead** — the isolation seam is invisible. ``mode="subprocess"`` runs each inbound's
    Router/Handler in a **persistent per-inbound worker child** (never a per-message fork), enforcing
    a forbidden-import guard (socket/store/crypto), the resource caps below, and a fail-closed refusal
    of the live ``db_lookup``/``fhir_lookup`` bridges (they re-enter the event loop — a subprocess
    boundary breaks that; a Handler needing live enrichment runs with ``mode=off``). An isolation
    denial routes the message to ``ERROR``/dead-letter **post-ACK** (no NAK), never dropping it.

    Reliability-core + read ONCE at engine construction (a ``/config/reload`` does NOT re-read it —
    restart to change, exactly like ``claim_mode``)."""

    # off (default, byte-identical, no subprocess) | subprocess (persistent per-inbound worker child).
    mode: Literal["off", "subprocess"] = Field(default="off")
    # Authoritative wall-clock cap (seconds) per Router/Handler call on EVERY platform: the parent
    # kills a worker that overruns it, so a pathological busy-loop can never wedge intake. Floor > 0.
    wall_seconds: float = Field(default=5.0, gt=0)
    # POSIX-only RLIMIT_CPU backstop (seconds) inside the child (a no-op on Windows, where wall_seconds
    # governs). Kept <= wall_seconds in spirit; the OS reaps a CPU-bound child sooner where supported.
    cpu_seconds: float = Field(default=2.0, gt=0)
    # POSIX-only RLIMIT_AS address-space cap (MiB) inside the child (no-op on Windows). None disables it.
    mem_mb: int | None = Field(default=512, ge=1)
    # Bound (seconds) on the one-time child bootstrap (config load + guard install) before start fails.
    startup_seconds: float = Field(default=30.0, gt=0)


class DiagnosticsSettings(_Section):
    """``[diagnostics]`` — the Corepoint-style event log (#46). Both switches are **on by default** and
    safe to be: ``connection_events`` writes only metadata (connection name, peer IP, a scrubbed
    reason — never a frame or body), and ``response_sent`` always stores the non-PHI ACK disposition
    metadata while storing the AA-ACK *body* only when the store is encrypted (else NULL). A
    per-connection ``capture_connection_errors`` / ``capture_ack`` flag overrides the matching master
    switch for one connection (``None`` = inherit)."""

    # Master switch for the connection/transport event log: inbound lifecycle (established/closed) +
    # pre-ingress failures (allowlist/capacity/oversize/peer-reset/framing) + outbound lane transitions
    # (connection_lost/restored). Metadata-only; written off the hot path by a drain task.
    connection_events: bool = True
    # Master switch for "Response Sent" — the ACK/NAK the engine returns to an inbound sender. Always
    # captures the disposition metadata (ack_code/phase/outcome); the AA body is stored only on an
    # encrypted store, and every NAK body is NULL (the offending field value is never persisted).
    response_sent: bool = True
    # Verbosity of the per-message `message_events` disposition log (#63). This governs how many rows
    # the store writes to the `message_events` table — it does NOT touch the messages/queue disposition
    # rows (count-and-log is separate) or the tamper-evident `audit_log` chain.
    #   "all"    — record every event (the default; unchanged behavior).
    #   "errors" — drop routine success events (received/delivered/replayed); keep the compliance floor.
    #   "off"    — keep ONLY the compliance floor.
    # COMPLIANCE FLOOR (retained at EVERY level, even "off"): `viewed` (a PHI-access record — the HIPAA
    # message-view trail must never be dropped) and the terminal failure events `dead`/`error`/`failed`.
    message_events: Literal["all", "errors", "off"] = "all"


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
    # RFC 5426; fire-and-forget, never blocks the engine (the default).
    UDP = "udp"
    # RFC 6587; connection-oriented (down-at-startup skipped; runtime stall bounded by a socket
    # timeout so a wedged collector can't block the event loop — synchronous send).
    TCP = "tcp"
    # RFC 5425; syslog over an ssl-wrapped TCP socket (native, no local agent needed — ADR 0080). Same
    # down-at-startup-skipped + bounded-timeout posture as tcp; the handshake is also bounded so a
    # collector that stalls TLS can't block the event loop. Requires a CA trust anchor unless
    # verification is explicitly disabled (see LoggingSettings.forward_tls_*).
    TLS = "tls"


class LoggingSettings(_Section):
    """``[logging]`` — log level, stdout rendering, and optional off-box forwarding (sec-offbox-log).

    PHI redaction + control-char scrubbing are applied to **every** sink (stdout and the forwarder) by
    ``logging_setup.configure_logging``, so structured output and off-box shipping never weaken the
    "never log full PHI bodies" guarantee (docs/PHI.md §7)."""

    level: str = "INFO"
    # stdout rendering: "text" (default, unchanged) or "json" (one JSON object per line, friendlier to
    # a log shipper tailing NSSM's captured stdout).
    format: LogFormat = LogFormat.TEXT
    # Optional directory NSSM (or another supervisor) rotates the engine's captured stdout/stderr into.
    # We never write log FILES ourselves (the engine logs to stdout — see logging_setup), but if an
    # operator tells us where the supervisor parks them, GET /status meters that directory's total bytes
    # + filesystem free space alongside the DB metrics (#50). None (the default) = stdout-only, no
    # metering. Metadata only — the contents are never read.
    log_dir: str | None = None

    # --- Off-box forwarding to a syslog/SIEM collector (ASVS 16.x; ADR 0080) ----------
    # Ship a copy of every log record to a remote syslog collector so log evidence survives a host
    # compromise (the local audit_log is tamper-evident, but lives on the same host). PHI redaction
    # applies to the forwarded stream exactly as to stdout. The forwarder never blocks the engine
    # indefinitely: UDP is fire-and-forget; a TCP/TLS collector unreachable at startup is skipped
    # (warns), and a runtime stall is bounded by a socket timeout (record dropped). Synchronous send —
    # for a high-volume feed prefer UDP or a local agent.
    #
    # Default-on-when-configured (ADR 0080): None (the default) is DERIVED by the model validator to
    # (forward_host is not None) — so pointing forward_host at a collector turns forwarding ON by
    # default, forward_enabled=false is the explicit opt-out, and NO collector leaves it OFF (byte-
    # identical to the pre-0080 stdout-only default). A literal True default is impossible: it would
    # trip the forward_enabled-requires-host rule on an unconfigured engine.
    forward_enabled: bool | None = None
    forward_host: str | None = None
    forward_port: int = 514
    forward_protocol: SyslogProtocol = SyslogProtocol.UDP
    # Wire format sent off-box, independent of the stdout `format`. JSON is the SIEM-friendly default and
    # guarantees one record per line; "text" framing is best-effort (a multi-line traceback spans lines).
    forward_format: LogFormat = LogFormat.JSON
    # --- Native TLS-syslog (forward_protocol="tls"; RFC 5425, ADR 0080) ----------
    # PEM trust anchor for the collector's certificate. With protocol="tls" and verification on this is
    # REQUIRED (the validator enforces it): only this CA is trusted (system roots are NOT loaded), so an
    # on-prem SIEM's private/self-signed cert is anchored explicitly instead of silently trusting the
    # public CA bundle (which any public-CA cert could exploit to impersonate the collector).
    forward_tls_ca_file: str | None = None
    # Verify + hostname-check the collector's certificate (secure default). forward_tls_verify=false is
    # the documented INSECURE opt-out (CERT_NONE, no CA file needed) — a lab / pinned-network only.
    forward_tls_verify: bool = True
    # Optional client cert (PEM cert+key chain) for mutual TLS to the collector. None = no client auth.
    forward_tls_client_cert: str | None = None
    # --- Startup clock-sync gate (ASVS 16.2.2; ADR 0080) ----------
    # Cross-host log/audit correlation assumes the engine host's clock tracks a reference. This gate is
    # OPT-IN because the engine cannot verify sync without an operator-chosen peer (default = a NO-OP,
    # byte-identical startup). With require_time_sync + ntp_peer set, serve() runs a bounded SNTP probe
    # before listeners start and WARNS loudly on skew (or an unreachable peer); with time_sync_fail_closed
    # it REFUSES to start instead. See __main__.serve + logging_setup.query_sntp_offset.
    require_time_sync: bool = False
    ntp_peer: str | None = (
        None  # NTP/SNTP host to compare the local clock against (required if the above)
    )
    time_sync_max_skew_seconds: float = 2.0  # |local - peer| above this is "skewed"
    time_sync_fail_closed: bool = (
        False  # refuse to start on skew / unreachable peer (further opt-in)
    )

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

    @field_validator("time_sync_max_skew_seconds")
    @classmethod
    def _check_skew_threshold(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("[logging].time_sync_max_skew_seconds must be > 0")
        return value

    @model_validator(mode="after")
    def _resolve_forwarding(self) -> "LoggingSettings":
        # Default-on-when-configured: an unset forward_enabled follows whether a collector is named.
        if self.forward_enabled is None:
            self.forward_enabled = self.forward_host is not None
        if self.forward_enabled and not self.forward_host:
            raise ValueError(
                "[logging].forward_enabled requires [logging].forward_host (the syslog/SIEM collector)"
            )
        # Native TLS-syslog: verifying the collector needs an explicit CA anchor (see forward_tls_ca_file
        # above). Only enforced when forwarding is actually on and verification is not opted out.
        if (
            self.forward_enabled
            and self.forward_protocol is SyslogProtocol.TLS
            and self.forward_tls_verify
            and not self.forward_tls_ca_file
        ):
            raise ValueError(
                "[logging].forward_protocol='tls' with certificate verification requires "
                "[logging].forward_tls_ca_file (a PEM trust anchor for the collector); set "
                "[logging].forward_tls_verify=false to accept an unverified server (insecure)"
            )
        # Clock-sync gate config coherence (the gate itself runs in serve()).
        if self.require_time_sync and not self.ntp_peer:
            raise ValueError(
                "[logging].require_time_sync needs [logging].ntp_peer (an NTP/SNTP host to compare "
                "the local clock against)"
            )
        if self.time_sync_fail_closed and not self.require_time_sync:
            raise ValueError("[logging].time_sync_fail_closed requires [logging].require_time_sync")
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
    # Past N HOURS, DELETE connection_event rows (#46) — the Corepoint-style transport/lifecycle log can
    # be high-volume (a connect-per-message sender, a probe storm), so it has its own short window in
    # HOURS (not days). 0 = inherit the message-body window (messages_days), the ADR 0021 §7.5 default.
    connection_event_retention_hours: int = 0
    # Past N days, DELETE application LOG FILES (``.log``/``.txt``, one level) from the configured
    # ``[logging].log_dir`` (#120). The supervisor (NSSM ``AppRotateBytes``) rotates the engine's daily
    # logs by SIZE but never deletes them by AGE, so the log directory grows unbounded; this bounds it.
    # 0 = keep forever (the default). Metadata only — file content is never read (no PHI). A no-op
    # unless ``[logging].log_dir`` is set.
    app_log_days: int = 0
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
    # Secure-by-default opt-out (#186a, ASVS 14.2.4): on a PHI instance `serve` refuses to start (prod)
    # / warns (non-prod) unless BOTH PHI-body retention windows are bounded — the inbound-body window
    # (`messages_days`) and the dead-letter-body window (`dead_letter_days`), each of which keeps FULL
    # raw PHI until purged — so PHI bodies do not accumulate without bound. Setting this true is the
    # explicit, audited override that lets a PHI instance run with unbounded (keep-forever) retention.
    # Off by default; ignored on a synthetic/non-PHI instance (exempt from the gate). See
    # messagefoundry/__main__.py.
    allow_unbounded_phi: bool = False

    @field_validator(
        "messages_days",
        "dead_letter_days",
        "audit_days",
        "max_db_mb",
        "state_max_age_days",
        "connection_event_retention_hours",
        "app_log_days",
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
    # Action-bound step-up (ADR 0077; ASVS 7.5.1/8.2.4). When on (default), the durable-takeover
    # JSON routes — TOTP enroll/confirm, disable-MFA — require a fresh proof BOUND to
    # that specific action (POST /me/reauth with a matching `purpose`), single-use, instead of riding
    # the session-wide step-up window. This closes the most-exploitable default: a session hijacked
    # inside the 300s login-seeded window could otherwise bind an attacker's authenticator with no
    # fresh proof. It changes ONLY those factor-binding routes; the broad admin/replay/config/purge
    # routes keep the session-window step-up (7.5.3). Default True is secure-by-default and does not
    # touch the loopback bind, TLS, or any collector path. Set False to revert to the legacy
    # session-window behaviour (0.2.x semantics) — the documented org opt-out.
    require_action_step_up: bool = True

    # Multi-factor authentication (WP-14, ADR 0002 §3; ASVS 6.3.3) — a native RFC 6238 TOTP second
    # factor for LOCAL accounts. AD/Kerberos MFA is delegated to the directory (Entra Conditional
    # Access / an MFA proxy), so a directory login is never prompted for an engine TOTP. When
    # require_mfa is on, a user holding the Administrator role MUST enroll TOTP and satisfy it before
    # any step-up (sensitive) operation; non-admins may opt in voluntarily.
    #
    # Default ON (BACKLOG #187, secure-by-default + org opt-out): best practice is that an
    # Administrator authenticates with a second factor, so the engine ships MFA required for the
    # Administrator role out of the box, INCLUDING the default 127.0.0.1 loopback bind. This is an
    # intentional break from the pre-#187 byte-identical-loopback posture — the owner chose the
    # secure default over back-compat. It cannot lock a fresh admin out: a required-but-unenrolled
    # Administrator can still reach the factor-enrollment routes (they are gated by a fresh PASSWORD
    # step-up bound to the enroll/confirm action, never by the MFA gate — see
    # api/security.py:require_reauth_only_action), so the bootstrap admin enrolls TOTP then satisfies
    # it. Set ``require_mfa = false`` (the documented opt-out) to revert to the single-factor default.
    # An off-loopback bind that serves local accounts MUST keep this on; ``serve`` makes that posture
    # explicit (sec-mfa-on) — on an exposed (non-loopback) PHI bind with this **explicitly opted out**
    # it **refuses to start** on a production instance and **warns** on a non-production one, mirroring
    # the keyless-store / open-egress startup gates (see __main__._serve), so MFA can't be silently
    # skipped at exposure. Scope: it gates **step-up (sensitive) operations** for the Administrator
    # role — it is NOT a gate on every authenticated PHI read (those stay behind RBAC + the PHI-read
    # throttle).
    require_mfa: bool = True
    # TOTP clock-skew tolerance, in 30-second time steps, applied when verifying a submitted code
    # (BACKLOG #187; ASVS 6.5.5). Default 0 = STRICT: only the current 30 s step is accepted, so a
    # captured code is replayable for at most the remainder of its own step (ASVS 6.5.5 prefers the
    # tightest window). Set 1 (or 2) to restore RFC-6238 network-delay/clock-drift tolerance — the
    # documented opt-out: 1 also accepts the immediately-prior and (fast-clock-clamped) next step, i.e.
    # the historical ±1 behaviour. The forward half of the window is still clamped to the current step
    # so tolerating a fast-clock code can't advance the single-use high-water mark (SEC-014); values
    # above 2 are rejected (an over-wide window weakens replay resistance).
    totp_skew_steps: int = 0
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

    # Anti-automation on the state-changing admin surface (BACKLOG #193, ASVS 2.4.2): a per-actor
    # sliding window folded into the step-up gate (require_step_up) for every NON-GET sensitive op —
    # purge, replay, config deploy/reload. It paces scripted admin-write abuse on top of RBAC + step-up
    # re-verification; the sole step-up GET (/messages/search) is exempt. The floor is set an order of
    # magnitude above human console interaction AND above the worst-case 403 → /me/reauth → retry burst
    # (that burst is only two writes), so an operator is never throttled while a machine-speed loop trips
    # immediately. In-process only (front a proxy/WAF when exposed). enabled=False disables it.
    admin_write_rate_limit_enabled: bool = True
    admin_write_rate_limit_per_actor: int = (
        12  # max state-changing admin writes per actor per window
    )
    admin_write_rate_limit_window_seconds: float = 1.0

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

    @field_validator("totp_skew_steps")
    @classmethod
    def _check_totp_skew(cls, value: int) -> int:
        # 0 = strict (current step only, ASVS 6.5.5); 1/2 = the documented network-delay opt-out. A
        # negative window is meaningless and a wider-than-2 window materially weakens replay resistance.
        if not 0 <= value <= 2:
            raise ValueError(
                "totp_skew_steps must be 0, 1, or 2 (0 = strict current-step only; "
                "1/2 = RFC-6238 clock-skew tolerance)"
            )
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


def hop_posture_from_ai(ai: AiSettings) -> HopPosture:
    """The instance's :class:`~messagefoundry.config.tls_policy.HopPosture` for the #200 hop-refusal gate.

    Maps the AI section's *derived* posture (built-in dev/staging/prod derivation applied) onto the
    ``(is_phi, production)`` the transport cells decide on. ``is_phi`` keys on ``data_class == phi`` being
    *explicitly* declared — an **undeclared** ``data_class`` is **not** PHI, exactly as the keyless-refusal
    (§3), ``[egress]`` and #906 Posture-B gates all key on ``data_class == phi`` being set: a bare/default
    on-prem config carries no PHI assertion, so its hops stay byte-identical (never newly refused). Only the
    ``production`` dimension fails closed (``None`` → ``True``) — which matters solely once the instance
    *has* declared PHI, splitting a declared-PHI hop between prod-REFUSE and staging-WARN. The construction
    gate stamps the result via ``tls_policy.active_hop_posture`` (ADR 0092)."""
    data_class, production = ai.derived_posture()
    if data_class is not None:
        # Resolved (a known env or an explicit data_class): PHI only if it is *phi*.
        is_phi: bool | None = data_class is DataClass.PHI
    elif ai.environment is None:
        # Bare/default config — no environment AND no data_class declared. This carries no PHI
        # assertion, so it is NOT PHI: its hops stay byte-identical (never newly refused), exactly
        # as the keyless-refusal / [egress] / #906 gates all key on data_class == phi being set.
        is_phi = False
    else:
        # A *custom* env is declared but leaves data_class unresolved — the operator asserted a
        # non-standard deployment without a posture; fail closed (serve refuses such a start anyway).
        is_phi = None
    return HopPosture.fail_closed(is_phi=is_phi, production=production)


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
    # Allowed EMAIL (SMTP) outbound hosts: each entry is "host" (any port) or "host:port" (ADR 0029).
    allowed_smtp: list[str] = []
    # Allowed DIRECT (S/MIME-over-SMTP HISP relay) outbound hosts: each entry is "host" (any port) or
    # "host:port" (ADR 0085). Kept SEPARATE from allowed_smtp so an operator can permit a Direct HISP
    # relay without opening generic email egress (a distinct trust relationship carrying encrypted PHI).
    allowed_direct: list[str] = []

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
        "allowed_smtp",
        "allowed_direct",
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
    {
        "connection_stopped",
        "queue_buildup",
        "storage_threshold",
        "cert_expiry",
        "secret_rotation",  # #195b (ADR 0019 §5): a tracked secret is overdue/near-due for rotation
        "connection_error",  # #46: an outbound lane went down (connection_lost), throttled per lane
        "message_stall",  # #50: an outbound lane's oldest undelivered message aged past the threshold
        "integrity_drift",  # #54: startup attestation found in-place-tampered engine module(s)
        "update_available",  # #30: a newer MessageFoundry version is pinned than is running (ADR 0026)
        "backup_failed",  # #60 (ADR 0049): a scheduled/on-demand DR backup failed (snapshot/encrypt/verify)
    }
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
    event_type: str = "any"  # "any" | connection_stopped | queue_buildup | storage_threshold | cert_expiry | secret_rotation | connection_error | message_stall | integrity_drift | update_available | backup_failed
    connection: str = "*"  # fnmatch glob over the connection name; "*" = all
    min_depth: int | None = Field(None, ge=1)  # queue_buildup: match only at/over this lane depth
    min_oldest_seconds: float | None = Field(
        None, ge=0
    )  # queue_buildup/message_stall: …or oldest-message age (s)
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

    # Secure-by-default (#188, ASVS 6.3.5/6.3.7): out-of-band security-event notifications are required
    # by default. On a PHI instance `serve` refuses to start (prod) / warns (non-prod) when no effective
    # security-notification channel exists — SMTP transport (the settings above) configured AND the
    # [auth].notify_security_events kill-switch on (both are what api/app.py needs to wire the notifier)
    # — so account-security events (lockout, password/roles change, new-IP admin action) always have a
    # push channel, not just the pull-only /me/security-events feed. Set false to accept the pull-only
    # feed in writing (the explicit, audited opt-out). Ignored on a synthetic/non-PHI instance. See
    # messagefoundry/__main__.py.
    security_notifications_required: bool = True

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
    ``[store].backend`` in ``{postgres, sqlserver}`` and ``[store].pool_size >= 2`` when this is enabled
    (a clustered node drives concurrent background work against the pool)."""

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
    # Leader-PREFERENCE handicap (ADR 0096). Seconds this node waits — MEASURED AGAINST THE LEASE-EXPIRY
    # TIME on the DB clock — before it may claim an EXPIRED leadership lease. 0.0 (default) = no handicap
    # (byte-identical to before this knob existed). A preferred site keeps its nodes at 0.0 and a warm
    # remote-DR node at a positive value, so on a ROUTINE leadership transition (leader restart / patch /
    # DB blip) the preferred node — which may claim the instant the lease expires — wins the take-over race
    # and the DR node only becomes leader if no preferred node claims within the delay. It NEVER delays a
    # RENEWAL by the current leader (only the take-over-of-expired path) and only ever makes a node WAIT
    # LONGER than the un-handicapped expiry, so it can never open a two-leader window (the split-brain
    # guarantee is preserved). It governs take-over of an EXPIRED lease (the routine-transition path); the
    # very first election on an empty lease table is a plain race — use ``promotable`` / operator ordering
    # to control cold bring-up. Must be >= 0.
    acquire_delay_seconds: float = 0.0
    # NON-PROMOTABLE standby flag (ADR 0096). True (default) = a normal HA node. False = this node may
    # NEVER become leader: it never inserts a fresh lease, never takes over an expired one, and does not
    # renew, so it can neither acquire nor retain leadership — a node that somehow already holds the lease
    # steps down cleanly on its next maintenance tick (the fence watchdog is the backstop). Use it for a
    # warm DR-site engine that must stay passive/read-only until an operator promotes it out-of-band. At
    # least ONE promotable node MUST exist in the cluster, or no node ever acquires the lease and the graph
    # never drains — an all-non-promotable cluster is a misconfiguration (documented, not guarded here).
    promotable: bool = True

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

    @field_validator("acquire_delay_seconds")
    @classmethod
    def _nonneg_acquire_delay(cls, value: float) -> float:
        # 0.0 (the default) = no handicap; a negative delay would let a node claim BEFORE the lease
        # expires (a two-leader window), so it is rejected at config load.
        if value < 0:
            raise ValueError(
                "acquire_delay_seconds must be >= 0 (0 disables the leader-preference handicap)"
            )
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


class SecretRotationSettings(_Section):
    """Periodic **secret-rotation reminder** (``[secret_rotation]``, ADR 0019 §5, BACKLOG #195b). Long-
    lived secrets (the store data-encryption key today; connector credentials in a future
    ``SecretProvider`` follow-on) have no natural expiry the way a TLS cert does, so nothing tells an
    operator when one is overdue for rotation. This is the secret-side twin of ``[cert_monitor]``: the
    engine periodically compares each tracked secret's **operator-configured last-rotated date** against
    its **max age** and raises a ``secret_rotation_due`` alert when it is overdue or within ``warn_days``
    of due. It reads **only** the rotation *dates* an operator supplied here — never any secret value
    (PHI-free). Set ``warn_days`` to 0 to disable the reminder.

    The store DEK is tracked **deny-by-default**: it is watched only once an operator sets
    ``store_key_last_rotated`` (an ISO ``YYYY-MM-DD`` date). The connector-credential
    ``SecretProvider`` generalization (AD/SQL/SMTP secrets off env) is a **design-only follow-on** (ADR
    0019 §5) and is intentionally NOT tracked here yet."""

    warn_days: int = (
        14  # alert this many days before a secret is due for rotation (0 = reminder off)
    )
    check_interval_seconds: float = (
        86_400.0  # rescan cadence (rotation is a slow signal; daily is ample)
    )
    # Store DEK tracking (deny-by-default): the operator records when the store encryption key was last
    # rotated (ISO YYYY-MM-DD) + how long it may live. Unset last-rotated → the DEK is not tracked. These
    # are DATES, not the key — never a secret value.
    store_key_last_rotated: str | None = None
    store_key_max_age_days: int = 365  # rotate the store DEK within this many days of last_rotated

    @field_validator("warn_days")
    @classmethod
    def _check_warn_days(cls, v: int) -> int:
        if v < 0:
            raise ValueError("secret_rotation.warn_days must be >= 0 (0 disables the reminder)")
        return v

    @field_validator("check_interval_seconds")
    @classmethod
    def _check_interval(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("secret_rotation.check_interval_seconds must be > 0")
        return v

    @field_validator("store_key_max_age_days")
    @classmethod
    def _check_max_age(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("secret_rotation.store_key_max_age_days must be > 0")
        return v

    @field_validator("store_key_last_rotated")
    @classmethod
    def _check_last_rotated(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            date.fromisoformat(v)
        except ValueError as exc:
            raise ValueError(
                "secret_rotation.store_key_last_rotated must be an ISO date (YYYY-MM-DD); "
                f"got {v!r}"
            ) from exc
        return v


class UpdateCheckSettings(_Section):
    """Engine-side version-update check (``[update_check]``, ADR 0026 §3). The MVP is a **no-network**
    "pinned-vs-current" diff: it compares the running :data:`messagefoundry.__version__` against the
    version recorded in the installed distribution metadata (``importlib.metadata``) / the bundled
    ``requirements.lock`` — **zero outbound traffic**. The result is surfaced as one additive
    ``/status`` field and (optionally) one ``update_available`` AlertSink event.

    The no-network local diff is cheap and PHI-safe, so it is **on by default**; set ``enabled=false``
    to suppress the ``/status`` field + the alert entirely. ``mode`` is clamped to ``"local"`` — the
    ``"live"`` egress path (ADR 0026 §2) is **defined but rejected at load** so a config can never
    silently turn the check into a phone-home. ``index_*`` are forward-compat, accepted-but-unused."""

    enabled: bool = True
    check_interval_seconds: float = 86_400.0  # diff cadence (the diff is trivial; daily is ample)
    mode: str = "local"  # "local" (no-network diff, the only MVP value); "live" rejected at load
    # Forward-compat (§2 live mode only); accepted-but-unused in the MVP — like AiSettings' broker keys.
    index_url: str | None = None
    index_allowed_hosts: list[str] = Field(default_factory=list)

    @field_validator("check_interval_seconds")
    @classmethod
    def _check_interval(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("update_check.check_interval_seconds must be > 0")
        return v

    @field_validator("mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        # ADR 0026 §3: "live" is DEFINED but rejected-at-load until the §2 constrained-egress envelope is
        # built, so the value can never silently become a phone-home out of a PHI system.
        if v == "live":
            raise ValueError(
                "update_check.mode='live' is not implemented — the live egress update-check (ADR 0026 "
                "§2) is deferred; use mode='local' (the no-network pinned-vs-current diff)"
            )
        if v != "local":
            raise ValueError(f"update_check.mode must be 'local'; got {v!r}")
        return v


#: The high-value operations dual-control can gate (registry keys). Confining ``[approvals].operations``
#: to this set catches a typo'd op name at startup rather than silently never gating it.
#: ``config_reload`` (ADR 0041 D2) is the broadest-blast-radius runtime action — one re-authenticated
#: person reloads the entire live graph (the loader EXECUTES config Python) — so it is gateable; it is
#: NOT in the default ``operations`` set below, so single-operator deployments stay byte-unchanged until
#: an operator opts it in (deny-by-default, pairs with the ADR 0041 D1 reload fingerprint).
APPROVABLE_OPERATIONS: frozenset[str] = frozenset(
    {"dead_letter_replay", "connection_purge", "config_reload"}
)

#: The subset enabled by DEFAULT when ``[approvals].enabled`` is true. ``config_reload`` is deliberately
#: excluded (opt-in) so turning dual-control on for replay/purge does not also start holding every
#: reload — an operator must add ``config_reload`` to ``[approvals].operations`` explicitly.
_DEFAULT_APPROVABLE_OPERATIONS: frozenset[str] = frozenset(
    {"dead_letter_replay", "connection_purge"}
)


class IntegritySettings(_Section):
    """``[integrity]`` — startup self-attestation of the installed engine wheel (ADR 0041 D3).

    At startup (and on demand) the engine hashes its loaded ``messagefoundry`` module files against the
    installed wheel's ``*.dist-info/RECORD`` baseline; on drift it writes a hash-chained
    ``startup_integrity`` audit row + fires the AlertSink. Both keys default safe: attestation is **on**
    but **alert-only** (it never blocks startup), so an existing deployment is unchanged. An EDITABLE
    install (``pip install -e .`` — no RECORD baseline) is a NO-OP regardless, so dev is never bricked
    (see messagefoundry/integrity.py)."""

    # Run startup attestation at all. On by default (alert-only is harmless); a no-op off an editable
    # install. Set false only to suppress the check entirely (e.g. an unusual packaging where RECORD is
    # known-stale) — you then lose the in-place-tamper tripwire.
    enabled: bool = True
    # When true, drift (a loaded engine module not matching its RECORD hash) makes serve REFUSE to start
    # (after recording the audit row + alerting). Default false = alert-only: a legitimate reviewed
    # in-place security hotfix (the documented vendored-parser patch contingency) would itself trip a
    # RECORD mismatch, so fail-closed-by-default would brick a legitimate patch. Opt in for hard
    # enforcement on a locked-down instance.
    fail_closed_on_drift: bool = False
    # When true, the engine re-walks the tamper-evident audit hash-chain once at startup (#190). This is
    # ALERT-ONLY: a broken chain logs a WARNING + fires the AlertSink but NEVER crashes startup (a
    # refuse-to-start on a tripped tamper alarm would be a self-inflicted DoS). Default false — opt in;
    # on a very large audit_log the full re-walk adds startup latency, so it is not on by default.
    audit_verify_on_start: bool = False


class ApprovalsSettings(_Section):
    """Optional dual-control (maker-checker) approval for high-value actions (``[approvals]``, ASVS
    2.3.5). **Off by default** so a single-operator deployment is never blocked. When ``enabled``, an
    action in ``operations`` is held as a pending request and must be released by a *distinct* second
    user holding ``approvals:approve`` — the requester can never approve their own. A request older than
    ``expiry_hours`` can no longer be approved."""

    enabled: bool = False
    operations: list[str] = Field(default_factory=lambda: sorted(_DEFAULT_APPROVABLE_OPERATIONS))
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


#: The two snapshot mechanisms for the SQLite store backup (ADR 0049). ``vacuum_into`` (default) writes
#: a fresh, fully-checkpointed, defragmented single-file copy under the store write lock — mandatory
#: off-peak. ``online_backup`` uses SQLite's page-batched Online Backup API (low-contention) for a
#: large/busy store.
_SNAPSHOT_METHODS = frozenset({"vacuum_into", "online_backup"})

#: Cloud-URL schemes the destination must NEVER be (ADR 0049 — local/UNC only, no new egress surface).
_CLOUD_DEST_SCHEMES = ("s3://", "gs://", "gcs://", "azure://", "http://", "https://", "ftp://")


class BackupSettings(_Section):
    """``[backup]`` — engine-managed scheduled + on-demand DR backup of the config bundle + the SQLite
    store, written as one AES-256-GCM ``.mfbak`` archive to a local/UNC destination (ADR 0049, #60).

    **Opt-in:** ``enabled = false`` (the default) is a complete no-op — a deployment with no ``[backup]``
    is unaffected. When enabled the :class:`~messagefoundry.pipeline.dr_backup.BackupRunner` (leader-gated,
    daily-clock like the RetentionRunner) takes a **consistent SQLite snapshot** (read-only against the
    live store — never claims/mutates a staged-queue row), bundles the loaded ``--config`` dir, encrypts
    to ``.mfbak`` under the existing store DEK (ADR 0019 KeyProvider), applies keep-N retention, runs a
    lightweight restore-verify (open + integrity_check + row-count), and records one PHI-free
    ``dr_backup`` audit row. **No cloud target** (local/UNC only — no new egress). For a server-DB store
    (postgres/sqlserver) the store backup is **DBA-delegated** (#52): config-only or skip per
    ``config_only_on_server_db``."""

    # Opt-in master switch; a deployment with no [backup] is unaffected (no-op default).
    enabled: bool = False
    # Operator-set LOCAL or UNC destination path, e.g. "D:/mefor-backups" or r"\\nas\mefor\backups".
    # REQUIRED (non-empty) when enabled. A cloud URL (s3://, https://, ...) is REJECTED — no cloud target.
    destination: str = ""
    # Daily local "HH:MM" at which the scheduled backup runs (reusing the RetentionSettings clock parser).
    # "" = on-demand only (the `messagefoundry backup` CLI), no scheduled pass.
    schedule_at: str = "02:00"
    # keep-N: after a successful, verified new archive, prune the oldest archives beyond the newest N at
    # the destination. 0 = keep all (never prune). A verify-FAILED archive is never counted as a good
    # backup when pruning (so a failing run can't evict the last good one).
    retention_keep: int = 7
    # "vacuum_into" (default; writer-lock under the off-peak schedule) | "online_backup" (low-contention,
    # page-batched). See ADR 0049 §"New store surface".
    snapshot_method: str = "vacuum_into"
    # Bundle the loaded --config dir into the archive (so the cold seed is self-sufficient — store + the
    # config that interprets it — without assuming the DR box can reach the org git repo, ADR 0048).
    include_config: bool = True
    # Run the lightweight restore-verify after every backup (open + integrity_check + row-count). On by
    # default — a backup nobody has opened is a backup that silently doesn't restore.
    verify_after_backup: bool = True
    # The heavier full restore-verify (restore the snapshot to a throwaway temp DB and open it through the
    # real open_store path). On-demand / opt-in extra; off by default (it is not the per-backup default).
    full_restore_verify: bool = False
    # On a server-DB store (postgres/sqlserver) the DB backup is DBA-delegated (#52); back up the config
    # bundle ONLY. False = skip the backup entirely on a server-DB store (no config-only archive either).
    config_only_on_server_db: bool = True
    # Audited escape: permit a CLEARTEXT archive ONLY for a no-key synthetic instance (parallel to
    # [store].allow_unencrypted_phi). A PHI instance with no key still REFUSES to write an unencrypted
    # archive (fail-closed) regardless of this flag — see the BackupRunner's key check.
    allow_unencrypted: bool = False

    @field_validator("schedule_at")
    @classmethod
    def _valid_schedule(cls, value: str) -> str:
        # Reuse the RetentionSettings clock parser so [backup].schedule_at and [retention].vacuum_at
        # accept exactly the same "HH:MM" grammar (empty = on-demand only).
        value = value.strip()
        if value and RetentionSettings._parse_clock(value) is None:
            raise ValueError(f"[backup].schedule_at must be empty or 'HH:MM' (24h), got {value!r}")
        return value

    @field_validator("retention_keep")
    @classmethod
    def _non_negative_keep(cls, value: int) -> int:
        if value < 0:
            raise ValueError("[backup].retention_keep must be >= 0 (0 = keep all)")
        return value

    @field_validator("snapshot_method")
    @classmethod
    def _known_snapshot_method(cls, value: str) -> str:
        if value not in _SNAPSHOT_METHODS:
            raise ValueError(
                f"[backup].snapshot_method must be one of {sorted(_SNAPSHOT_METHODS)}, got {value!r}"
            )
        return value

    @field_validator("destination")
    @classmethod
    def _no_cloud_destination(cls, value: str) -> str:
        # No cloud target / no new egress surface (ADR 0049, owner-locked). Reject a cloud-URL destination
        # at config load rather than silently treating it as a (bogus) local path at 02:00.
        low = value.strip().lower()
        if low and any(low.startswith(scheme) for scheme in _CLOUD_DEST_SCHEMES):
            raise ValueError(
                f"[backup].destination must be a LOCAL or UNC path, not a cloud URL ({value!r}); "
                "MessageFoundry DR backups have no cloud target (ADR 0049 — no new egress)"
            )
        return value

    @model_validator(mode="after")
    def _require_destination_when_enabled(self) -> "BackupSettings":
        # A backup with nowhere to write is a misconfiguration; fail loud at config load, not at 02:00.
        if self.enabled and not self.destination.strip():
            raise ValueError(
                "[backup].enabled=true requires a non-empty [backup].destination (a LOCAL or UNC path)"
            )
        return self

    def schedule_time(self) -> tuple[int, int] | None:
        """The configured daily backup time as ``(hour, minute)`` local, or ``None`` for on-demand only."""
        return RetentionSettings._parse_clock(self.schedule_at) if self.schedule_at else None


class DrActivationMode(str, Enum):
    """How a third-tier DR standby box takes over (ADR 0048, #61). ``MANUAL`` is the **only** mode built
    in this slice — the DR box promotes only on the explicit, RBAC-gated ``POST /dr/activate`` operator
    action; no health-probe ever activates it. ``AUTO`` (the DR box detects HA-pair loss and self-promotes)
    is a **deferred future mode**: it is named so a forward-looking config is explicit, but config load
    **rejects** it with a clear "not yet supported" error until that mode lands — never a silent no-op."""

    MANUAL = "manual"
    AUTO = "auto"


class DrSettings(_Section):
    """``[dr]`` — third-tier disaster-recovery standby (ADR 0048, #61).

    A **right-sized DR box** that activates only when the whole HA pair / site is gone and runs **only
    the high-priority feeds** in a deliberately degraded mode — the inverse of the dropped active-active
    scale-out (this runs *less*, not more). **Opt-in:** ``enabled = false`` (the default) is a complete
    no-op; a deployment with no ``[dr]`` is byte-unchanged.

    The engine owns two halves: the **per-connection priority tier** (``[delivery].priority`` +
    per-connection ``priority=``) and the **selective-startup DR run-profile** here. On activation it
    cold-seeds the store from a #60 ``.mfbak`` backup (fail-closed if the KeyProvider/DEK is unavailable
    at the DR site), starts only connections whose resolved tier rank >= ``priority_threshold`` (the rest
    report ``status:"filtered"``), and is fenced by **acquire-VIP-or-abort** (the passive ADR-0047 LB is
    the fence; ``takeover_hook`` is optional belt-and-braces for non-LB topologies). **Activation is
    MANUAL** (``POST /dr/activate``, gated by the ``dr:operate`` permission); ``auto`` is rejected at load.

    ``enabled``/``activate`` are read at engine start (the DR run-profile is a startup decision, ADR
    0048); a deployment is either a DR box (``enabled = true``) or it is not. ``activate = true`` (or
    the operator endpoint) declares this box should run under the DR profile this boot.
    """

    # Opt-in master switch: is this deployment a DR standby box at all? false = the engine runs the
    # NORMAL run-profile (every connection starts subject only to ADR 0031), byte-unchanged.
    enabled: bool = False
    # Whether this DR box should come up UNDER the DR run-profile on this boot (the startup activation
    # latch — distinct from the runtime POST /dr/activate endpoint, which re-evaluates the graph). When
    # enabled but activate=false the box is provisioned-but-passive: it does NOT bind the priority feeds
    # until an operator activates it. A no-op unless enabled.
    activate: bool = False
    activation_mode: DrActivationMode = DrActivationMode.MANUAL
    # The DR run-profile threshold: start ONLY connections whose resolved priority rank >= this tier's
    # rank. CRITICAL (the default, owner-locked) starts only the critical feeds; NORMAL would also start
    # normal-tier feeds. A below-threshold connection reports status:"filtered" (distinct from ADR 0031's
    # "failed"). An unknown value fails config load.
    priority_threshold: Priority = Priority.CRITICAL
    # acquire-VIP-or-abort (ADR 0048): an OPTIONAL operator command run before binding the priority
    # listeners — exit 0 / success = "VIP acquired", any non-zero / timeout = "not acquired" (activation
    # ABORTS). For an ADR-0047 LB topology the passive LB is the fence and this is belt-and-braces only;
    # "" (the default) = no hook (rely on the passive LB). Whitespace-only is rejected at load.
    takeover_hook: str = ""
    # The symmetric release command run on POST /dr/release (release the VIP back to the recovered
    # primary). "" = no hook. Whitespace-only is rejected at load.
    release_hook: str = ""
    # Bound (seconds) on the takeover/release hook AND on the KeyProvider-reachability check at the DR
    # site: a hook or key probe that does not succeed within this aborts activation closed (no hang, no
    # silent retry-forever — ADR 0048 AC-14). Must be > 0.
    takeover_timeout_seconds: float = 30.0
    # The #60 .mfbak backup archive to cold-seed the DR store from on activation. "" = the operator
    # supplies the archive path in the POST /dr/activate request body instead (the runbook path). A
    # cloud URL is rejected (the seed is local/UNC only, like the backup destination — no new egress).
    seed_archive: str = ""
    # OPT-IN server-DB DR restore-token (BACKLOG #223, ADR 0102 — option b). A LOCAL/UNC path to a small
    # JSON token the DBA/operator places on the DR box recording the EXPECTED source-backup anchor of a
    # native (postgres/sqlserver) restore: {"expected_backup_archive": "<the most-recent engine dr_backup
    # archive name the restored 'mefor' DB should carry, sourced OUT-of-band from the PRIMARY>"}. When set,
    # the #102 server-DB seed gate cross-checks it against the restored DB's OWN latest successful dr_backup
    # archive — a VINTAGE FLOOR a bare boolean attestation cannot give (a stale/wrong native restore's
    # latest anchor differs → activation refuses closed). "" (the default) = OFF: the #102 gate is
    # byte-unchanged and SQLite is a no-op. A cloud URL is rejected (local/UNC only, like seed_archive).
    restore_token: str = ""

    @field_validator("takeover_hook", "release_hook")
    @classmethod
    def _hook_not_blank(cls, value: str) -> str:
        # "" disables the hook; a present-but-whitespace-only command is a config footgun (it would run
        # an empty shell and "succeed") — fail loud at load, mirroring InboundConnection.bind_address.
        if value and not value.strip():
            raise ValueError(
                "[dr] takeover_hook/release_hook must be a non-blank command (or omit it)"
            )
        return value

    @field_validator("takeover_timeout_seconds")
    @classmethod
    def _positive_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("[dr].takeover_timeout_seconds must be > 0")
        return value

    @field_validator("seed_archive")
    @classmethod
    def _no_cloud_seed(cls, value: str) -> str:
        low = value.strip().lower()
        if low and any(low.startswith(scheme) for scheme in _CLOUD_DEST_SCHEMES):
            raise ValueError(
                f"[dr].seed_archive must be a LOCAL or UNC path, not a cloud URL ({value!r}); "
                "the DR cold seed has no cloud source (ADR 0048 — no new egress)"
            )
        return value

    @field_validator("restore_token")
    @classmethod
    def _no_cloud_restore_token(cls, value: str) -> str:
        # The restore-token is a DBA-placed local artifact on the DR box (BACKLOG #223, ADR 0102); like
        # seed_archive it is LOCAL/UNC only — a cloud URL would imply new egress, which DR forbids.
        low = value.strip().lower()
        if low and any(low.startswith(scheme) for scheme in _CLOUD_DEST_SCHEMES):
            raise ValueError(
                f"[dr].restore_token must be a LOCAL or UNC path, not a cloud URL ({value!r}); "
                "the DR restore-token is a local artifact on the DR box (ADR 0102 — no new egress)"
            )
        return value

    @model_validator(mode="after")
    def _reject_auto_mode(self) -> "DrSettings":
        # ADR 0048: auto-probe activation is a DEFERRED future mode — config rejects it with a clear
        # "not yet supported" error (never a silent no-op / fallback to manual), so a config can never
        # quietly believe it has automatic site failover that this slice does not build.
        if self.activation_mode is DrActivationMode.AUTO:
            raise ValueError(
                "[dr].activation_mode='auto' is not yet supported — automatic HA-pair-loss detection "
                "and self-promotion are deferred to a future ADR (ADR 0048); use activation_mode='manual' "
                "(the default) and the RBAC-gated POST /dr/activate operator action"
            )
        return self


class ServiceStatusSettings(_Section):
    """``[service]`` — optionally report the engine's own Windows-service (NSSM) run state to the ops
    console (L6a, ADR 0065). Read-only + unprivileged: ``sc query <service_name>`` off the event loop,
    gated by ``monitoring:read``. Default off. There is NO control here (start/stop/restart is cut — the
    engine can't restart its own host over the API), no path input, no shell, no elevation."""

    report_status: bool = False
    service_name: str = Field(default="", max_length=256)

    @field_validator("service_name")
    @classmethod
    def _validate_service_name(cls, value: str) -> str:
        # A plain Windows service name only — reject anything that could carry a shell metacharacter
        # even though the query uses an argv list (defense-in-depth; empty = disabled).
        if value and not is_safe_service_name(value):
            raise ValueError("service_name must be letters, digits, space, '.', '_' or '-' only")
        return value


class ServiceSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")  # tolerate forward-looking/unknown sections

    store: StoreSettings = Field(default_factory=StoreSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    tls: TlsSettings = Field(default_factory=TlsSettings)
    inbound: InboundSettings = Field(default_factory=InboundSettings)
    delivery: DeliverySettings = Field(default_factory=DeliverySettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    diagnostics: DiagnosticsSettings = Field(default_factory=DiagnosticsSettings)
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
    secret_rotation: SecretRotationSettings = Field(default_factory=SecretRotationSettings)
    update_check: UpdateCheckSettings = Field(default_factory=UpdateCheckSettings)
    cluster: ClusterSettings = Field(default_factory=ClusterSettings)
    approvals: ApprovalsSettings = Field(default_factory=ApprovalsSettings)
    integrity: IntegritySettings = Field(default_factory=IntegritySettings)
    backup: BackupSettings = Field(default_factory=BackupSettings)
    dr: DrSettings = Field(default_factory=DrSettings)
    service: ServiceStatusSettings = Field(default_factory=ServiceStatusSettings)

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
                    "pool_size >= 3 for a clustered node (Postgres or SQL Server)"
                )
        return self

    @model_validator(mode="after")
    def _dr_activate_not_clustered(self) -> "ServiceSettings":
        """A DR box coming up under the DR run-profile must not also be a ``[cluster]`` member (ADR 0096
        rider). The two govern DIFFERENT things — ``[dr].activate`` gates which *connections* start (the
        priority-threshold run-profile, ADR 0048), while ``[cluster].enabled`` makes the node contend for
        *leadership* of a shared store — and combining them is a topology error: a warm DR-site engine
        should be a NON-PROMOTABLE cluster member (``[cluster].promotable = false``) OR a cold/manually
        promoted DR box, never a lease-contending DR box that could drive the primary store cross-WAN the
        moment it activates. Refuse the combination at config load rather than let it silently co-elect.
        Spans two sections, so it lives here (not on either section, which can't see the other)."""
        if self.dr.activate and self.cluster.enabled:
            raise ValueError(
                "[dr].activate cannot be combined with [cluster].enabled: the DR run-profile gates which "
                "connections start, not leadership acquisition, so a DR box that also contends for the "
                "cluster lease could win leadership and drive the primary store cross-WAN. Run the DR "
                "engine cold (or manually promoted) with [cluster] disabled, or make the warm DR node a "
                "NON-PROMOTABLE cluster member ([cluster].enabled=true, [cluster].promotable=false) "
                "instead of a [dr] box."
            )
        return self

    @model_validator(mode="after")
    def _warm_pool_timeout_under_fence(self) -> "ServiceSettings":
        """A pool warm-up should finish within the leadership term that started it, so a clustered
        server-DB node rejects an **explicit** ``[store].warm_pool_timeout >= [cluster].
        leader_fence_timeout_seconds``. Only an explicitly-set value is rejected: a slow warm past the
        fence is benign by construction (it self-releases, a re-promotion cancels it, and a demoted node
        only ever holds its OWN pool's idle connections — never the incoming leader's separate pool), so
        the default must not break an otherwise-valid config that merely lowered the fence. Spans two
        sections, so it lives here; SQLite warms nothing and single-node has no fence, so both are
        exempt."""
        if (
            self.cluster.enabled
            and self.store.warm_pool
            and self.store.backend in (StoreBackend.POSTGRES, StoreBackend.SQLSERVER)
            and "warm_pool_timeout" in self.store.model_fields_set
            and self.store.warm_pool_timeout >= self.cluster.leader_fence_timeout_seconds
        ):
            raise ValueError(
                "[store].warm_pool_timeout must be < [cluster].leader_fence_timeout_seconds "
                f"(got warm_pool_timeout={self.store.warm_pool_timeout}, "
                f"leader_fence_timeout_seconds={self.cluster.leader_fence_timeout_seconds}); a pool "
                "warm-up must finish within the leadership term that started it. Lower warm_pool_timeout, "
                "or set [store].warm_pool=false to opt out."
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
