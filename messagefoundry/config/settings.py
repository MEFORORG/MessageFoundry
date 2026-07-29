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

import ipaddress
import logging
import os
import re
import string
import tomllib
from collections.abc import Mapping, Sequence
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from messagefoundry.config.ai_policy import (
    AiDataScope,
    AiMode,
    DataClass,
    SecurityEnforcement,
)
from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    Priority,
    RetryPolicy,
    SaturationThreshold,
    Schedule,
    SignatureAlgorithm,
    StallThreshold,
    _check_hop_attestation,
)
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    TrustAnchorMode,
    TrustAnchorPolicy,
    current_hop_posture,
    insecure_hop_disposition,
    is_loopback_hop_host,
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
    "SecurityEnforcement",
    "EgressSettings",
    "ShadowSettings",
    "AlertsSettings",
    "SecretsSettings",
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
    "secrets",  # enables MEFOR_SECRETS_* env overrides (connector SecretProvider selection, ADR 0019 §5)
    "cluster",
    "approvals",
    "integrity",
    "diagnostics",
    "backup",
    "dr",
    "pipeline",  # enables MEFOR_PIPELINE_* env overrides (e.g. MEFOR_PIPELINE_PER_LANE_WAKE, ADR 0061)
    "security",  # ADR 0118: the plain-language posture switches (MEFOR_SECURITY_* env overrides)
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
    ("auth", "oidc_client_secret"),  # ADR 0142: env only (MEFOR_AUTH_OIDC_CLIENT_SECRET)
    ("alerts", "email_password"),
    ("api", "tls_key_password"),
    ("ai", "api_key"),  # ADR 0135: engine-broker LLM credential — env only (MEFOR_AI_API_KEY)
)


class StoreBackend(str, Enum):  # noqa: UP042
    SQLITE = "sqlite"
    SQLSERVER = (
        "sqlserver"  # production server-DB backend; full staged pipeline (see store/sqlserver.py)
    )
    POSTGRES = (
        "postgres"  # production server-DB backend with single-node parity (see store/postgres.py)
    )


class SqliteSync(str, Enum):  # noqa: UP042
    NORMAL = "normal"  # crash-safe under WAL, no per-commit fsync (default)
    FULL = "full"


class SqlAuth(str, Enum):  # noqa: UP042
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


def hop_insecure_escape_downgrades(*, enforcing: bool) -> bool:
    """Whether ``MEFOR_ALLOW_INSECURE_TLS`` may downgrade an insecure-hop REFUSE→WARN here (#200).

    The **clamp** on the blunt global escape for the posture-keyed hop refusal (ADR 0092, decision 2):
    the escape may only relax a hop REFUSE to WARN when the security dial is **not enforcing**. Under
    ENFORCE it is **inert** — it can NEVER satisfy an enforcing hop (a deliberate behaviour change from
    the pre-#200 global escape, which silenced the refusal in every environment).

    **Scope after ADR 0153 (decision 5): the TRANSPORT cells no longer consult this at all.** The
    cleartext-hop authority lost its ``audited_opt_out`` parameter, so the variable cannot influence a
    connection's cleartext-hop decision; the per-connection ``cleartext_accepted`` declaration replaced
    it there. This clamp survives for the two **non-connection** cells that still key on the escape and
    have nowhere to carry a per-hop declaration — the ``[logging]`` forwarder
    (:func:`forward_hop_disposition`) and the API PHI-read serve hop
    (:func:`~messagefoundry.config.tls_policy.phi_read_hop_disposition`) — plus the verify-off cells via
    :func:`weakened_tls_escape_permitted`. On a connection, ``tls_hop_attested`` (ALLOW) or
    ``cleartext_accepted`` (WARN + audit) is now the only way across an enforcing hop."""
    return insecure_tls_allowed() and not enforcing


def weakened_tls_escape_permitted(posture: HopPosture | None = None) -> bool:
    """Whether ``MEFOR_ALLOW_INSECURE_TLS`` may permit a weakened / verify-off TLS hop under ``posture``,
    CLAMPED so an enforcing PHI hop is NEVER relaxed (#200, ADR 0092 decision 2).

    The is_phi-blind **strict verify-off** cells — the engine<->store TLS gate
    (:func:`~messagefoundry.store.sqlserver.connection_string` / ``store.postgres._build_ssl``), the MLLP
    and FTPS ``tls_verify=false`` contexts, and the credentialed plain-``ftp`` guard — route their global-
    escape check through here so the blunt escape can no longer silence an **enforcing PHI** refusal
    (matching the ``--allow-insecure-bind`` API-bind clamp). Pass the construction-time
    :func:`~messagefoundry.config.tls_policy.current_hop_posture` (transport cells) or the store's threaded
    posture. Semantics: the escape must be set at all, AND the hop must not be enforcing PHI. ``None``
    (a backup utility / embedding / test outside the construction gate) falls back to the **unclamped**
    escape — byte-identical to pre-#200 — since the enforced serve/reload gate already vetted the real
    production posture, so this fallback never loosens the clamp."""
    if not insecure_tls_allowed():
        return False
    if posture is None:
        return True
    return not (posture.enforcing and posture.is_phi)


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
    # ADR 0114 Phase-4 claim-path sub-levers. All three: DEFAULT OFF (reliability-core), read ONCE at
    # store open (restart to change, like claim_mode), and SQL-Server-only by construction: only
    # SqlServerStore reads them; MessageStore/PostgresStore never reference them, so on those backends
    # they are provable no-ops (the ADR 0075 scoping precedent, frozen by a sentinel test). Each may be
    # flipped ON only after ITS OWN ADR 0114 §8 bench gate; default flips are a separate, owner-gated
    # follow-up decision recorded against the passed gate (AC-14).
    fifo_claim_fold_reset: bool = Field(
        default=False,
        description=(
            "Fold the pooled claim's session LOCK_TIMEOUT reset into the claim batch on the CLEAN "
            "success path at INGRESS/ROUTED (commit#2 disappears; the shielded finally-guard remains "
            "for every non-clean exit). SQL Server only; OFF = byte-identical shipped batch + guard."
        ),
    )
    fifo_claim_proc: bool = Field(
        default=False,
        description=(
            "Execute the pooled claim via the two lane-family versioned procs "
            "(dbo.mefor_claim_fifo_heads_cid_v1/_dst_v1; fixed-arity CALL) instead of the ~3KB ad-hoc "
            "batch. Fails safe to the batch (loud) if the procs are missing/stale or compat < 130. "
            "SQL Server only; OFF = byte-identical."
        ),
    )
    fifo_claim_prepared: bool = Field(
        default=False,
        description=(
            "Stabilize the pooled claim's statement text (one JSON lanes parameter) and retain a "
            "prepared claim cursor on store-owned dedicated connections (INGRESS/ROUTED). Logs + "
            "no-ops unless fifo_claim_fold_reset is ON. Non-DDL fallback lane to fifo_claim_proc. "
            "SQL Server only; OFF = byte-identical."
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
    # Bind each at-rest AES-256-GCM value to its (table, column, row) cell via GCM Associated Data
    # (ASVS 11.3.3, ADR 0019). **On by default** (ADR 0148 GIVEN 1: the default configuration runs the
    # hardened path, so it is exercised everywhere and not first in production): NEW writes use the
    # mfenc:v2 writer with cell-bound AAD (it sets the cipher's `write_v2`), so a ciphertext cut-and-pasted
    # into another cell fails the auth tag (dead-lettered, not silently accepted). Legacy v1 rows still
    # decrypt (dual-read) and `messagefoundry rotate-key` upgrades them v1→v2, so the flip is safe on an
    # existing store and reversible. No effect without an encryption key (the identity cipher has nothing
    # to bind). Setting it false selects the frozen mfenc:v1 writer (byte-identical at rest, CRYPTO-1) and
    # is a LOOSENING — `security_loosenings()` names it, so the opt-out is never silent.
    aad_bind: bool = True
    # KeyProvider seam (ADR 0019, ASVS 13.3.3): selects HOW the active/retired DEK bytes are *sourced* —
    # never how they are used (the cipher, keyring, and `mfenc:v1` format are unchanged). `auto` (the
    # default) is the env-then-DPAPI ladder, BYTE-IDENTICAL to the pre-seam behavior; `env`/`dpapi` pin a
    # single built-in source; `aws_kms`|`azure_kv`|`gcp_kms`|`vault`|`pkcs11` are external HSM/KMS/Vault
    # envelope-decrypt providers (lazy, optional extras — not built yet, fail closed if selected). This
    # names a *provider*, not key material, so it is NOT a secret — it must never be added to
    # `_FILE_SECRET_KEYS`. Unknown/unresolvable values fail closed at `open_store` (store/keyprovider.py).
    key_provider: str = "auto"
    # Store CIPHER provider (ADR 0138, ASVS 13.3.3): selects the at-rest cipher ITSELF — distinct from
    # `key_provider` above, which only *sources* DEK bytes for the in-process AES-GCM cipher. `aesgcm` (the
    # default) is that in-process cipher, BYTE-IDENTICAL to today. `vault_transit` performs the bulk
    # encrypt/decrypt INSIDE Vault/OpenBao Transit (store/crypto_transit.py), so the plaintext DEK never
    # enters engine heap — the ASVS 13.3.3 "isolated security module" control (13.3.1's L3 hardware clause
    # still wants the vault HSM-sealed). In `vault_transit` mode the local `encryption_key`/`key_provider`
    # are unused (Transit holds the key), at-rest values carry the `mfenc:v3:` marker, and the audit chain
    # is keyed by an ISOLATED-MODULE MAC — Transit's `generate_hmac`, computed inside the vault so no HMAC
    # key ever enters heap (ADR 0138). Threaded into ALL THREE store backends (ASVS 13.3.3): before that,
    # a vault_transit + Postgres/SQL Server store ran its chain fully UNKEYED, because
    # `TransitCipher.audit_mac_key()` returns None by design. Vault address/token/data-key name
    # come from MEFOR_STORE_VAULT_* env. Names a *provider*, NOT key material → not a secret, never in
    # `_FILE_SECRET_KEYS`. Unknown values fail closed at `open_store`.
    cipher_provider: str = "aesgcm"

    # --- Offline uploaded-logs (BACKLOG #125/#126, ADR 0134) ----------------
    # Directory holding operator-uploaded diagnostic message files (browsed offline, decoupled from any
    # live connection). UNSET (the default) DISABLES the uploaded-logs subsystem entirely — every
    # upload/list/browse/resend/delete route 503s — so no new PHI-at-rest surface exists unless an
    # operator explicitly opts in. When set, uploaded files are stored here AES-256-GCM-encrypted under
    # the store DEK when a key is configured (identity/plaintext-on-disk otherwise — the File-connector
    # spill-dir at-rest tier, see docs/PHI.md §2). A configured-but-absent dir is created best-effort on
    # first use (owner-only, like the store DB). This is a storage PATH, not a secret.
    uploads_dir: str | None = None
    # Hard cap (bytes) on a single uploaded file. Bounds the in-memory whole-file split at browse time and
    # the multipart upload buffer (ADR 0134). Default 25 MiB. The global 1 MiB HTTP-body cap is raised to
    # this value ONLY on the upload route.
    max_upload_bytes: int = Field(
        default=25 * 1024 * 1024,
        ge=1,
        le=512 * 1024 * 1024,
        description=(
            "Max size (bytes) of a single operator-uploaded diagnostic file (ADR 0134). Bounds the "
            "upload buffer and the offline whole-file split. Default 25 MiB."
        ),
    )
    # Per-uploader quotas + retention on the uploaded-logs surface (ASVS 5.2.4). These are DEFAULTS-ON
    # with a `ge=1` floor, so the control cannot ship disabled — the *subsystem* is opt-in via
    # `uploads_dir`, but once it is enabled a user cannot exhaust disk or hoard files unbounded, and stale
    # PHI-at-rest is age-pruned. Enforced in `UploadStore.save` (a would-be over-quota upload is refused
    # HTTP 409 before any write, audited `upload.reject_quota`) and by an age-based prune sweep (blob+meta
    # pairs older than `uploads_retention_days` are deleted, opportunistically at save time plus a periodic
    # task, each prune audited `upload.prune`). Quotas are per-process per-`uploads_dir` (multiple engine
    # shards at one dir multiply the budget — a documented residual, same shape as the summary-rate cap).
    max_upload_files_per_user: int = Field(
        default=100,
        ge=1,
        description=(
            "Max number of uploaded diagnostic files one uploader may retain at once (ASVS 5.2.4). A "
            "would-be 101st upload is refused HTTP 409. Default 100."
        ),
    )
    max_upload_total_bytes_per_user: int = Field(
        default=250 * 1024 * 1024,
        ge=1,
        description=(
            "Max aggregate bytes of uploaded diagnostic files one uploader may retain (ASVS 5.2.4). An "
            "upload that would push the uploader's total over this cap is refused HTTP 409. Default 250 "
            "MiB."
        ),
    )
    uploads_retention_days: int = Field(
        default=30,
        ge=1,
        description=(
            "Age (days) after which an uploaded diagnostic file (blob+meta pair) is pruned (ASVS 5.2.4). "
            "Swept opportunistically at save time and by a periodic task; every prune is audited. "
            "Default 30."
        ),
    )

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
    def _require_server_db_fields(self) -> StoreSettings:
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
    def _ssl_root_cert_backend(self) -> StoreSettings:
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
    # Serve the same-origin browser ops console under /ui (ADR 0065, BACKLOG #75). On by default (ADR
    # 0143 — the console is the operator UI, effectively core); disable with [security].serve_web_console=
    # false (a surface-reducing opt-out). When on, the engine mounts /ui + /ui/static and accepts an
    # HttpOnly session cookie CONFINED to /ui (the JSON API stays Authorization-header-only). Off a
    # loopback host it requires exposure_protected (see serve gate) — the UI is a stricter surface.
    serve_ui: bool = True
    # ADR 0143 soft-degrade signal — INTERNAL plumbing, set by _desugar_security (NOT a user knob). True
    # only when [security].serve_web_console was EXPLICITLY provided, so the serve path can tell an
    # explicit serve_web_console=true (console package absent -> HARD refuse) from the default-on posture
    # (package absent -> JSON-only serve + WARNING, never a start failure). Absent-[security] leaves it
    # False = default-on.
    serve_ui_explicit: bool = False
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
    # WP #285 (ASVS 6.7.1): optional SHA-256 pin over the mTLS client-CA trust anchor above. Set to the
    # lowercase-hex SHA-256 of the PEM file's bytes; the loaded anchor's fingerprint is checked against
    # it at construction AND at reload and a mismatch REFUSES to start — always, independent of
    # [security].enforcement (a substituted client-CA would admit a forged peer cert). Block-scoped
    # (direct-read by api/tls.py + the trust-anchor preflight, NOT desugared through [security]). None
    # (default) = no pin, dormant.
    tls_client_ca_pin: str | None = None
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
    # ASVS 6.4.5: PEM paths of INBOUND service callers' client certs the operator holds a copy of. The
    # [cert_monitor] scan folds these in, so a caller's cert expiry is caught even when that caller stops
    # connecting (the handshake-time check can only see a cert while it is still being presented). These
    # are certs the engine VERIFIES, not ones it presents, so they are invisible to the served-cert
    # enumeration. Public certificates only — never a key (nothing here is a secret; they are paths).
    # Empty (default) = file-based client-cert monitoring off, byte-identical to before.
    tls_client_cert_files: list[str] = []

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

    @field_validator(
        "config_reload_roots",
        "ws_allowed_origins",
        "trusted_proxies",
        "tls_client_cert_files",
        mode="before",
    )
    @classmethod
    def _split_roots(cls, v: object) -> object:
        # The env layer delivers list settings (MEFOR_API_CONFIG_RELOAD_ROOTS,
        # MEFOR_API_WS_ALLOWED_ORIGINS, MEFOR_API_TRUSTED_PROXIES,
        # MEFOR_API_TLS_CLIENT_CERT_FILES) as one string; split it on the
        # platform path separator so these list-typed settings can be set via env (review low-12).
        if isinstance(v, str):
            return [p for p in v.split(os.pathsep) if p]
        return v

    @field_validator("trusted_proxies", mode="after")
    @classmethod
    def _check_trusted_proxies(cls, v: list[str]) -> list[str]:
        # Both spellings below are FAIL-OPENS that uvicorn accepts silently, so validate them here
        # rather than discover them from a poisoned audit trail:
        #   "*"  -> uvicorn's _TrustedHosts trusts EVERY peer and hands back the client-authored
        #           LEFTMOST X-Forwarded-For entry for every request, so any client can declare its own
        #           source address (uvicorn.middleware.proxy_headers).
        #   typo -> an unparseable entry degrades to a "trusted literal" that can never match, which
        #           still satisfies the tls_terminated_upstream pairing check below while trusting
        #           nothing — quietly collapsing every client to the proxy address and degrading the
        #           audit source IP, the per-IP login limiter, and the new-client-IP step-up signal.
        for entry in v:
            if entry == "*":
                raise ValueError(
                    "[api].trusted_proxies = '*' trusts the X-Forwarded-For header from EVERY peer, so "
                    "any client can declare its own source address (poisoning the audit trail, the "
                    "per-IP login limiter and the new-client-IP step-up signal). List the reverse "
                    "proxy's exact address(es) instead."
                )
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"[api].trusted_proxies entry {entry!r} is not a valid IP address or CIDR network: "
                    f"{exc} (uvicorn would silently treat it as a literal that never matches, "
                    "collapsing every client source IP to the proxy)"
                ) from exc
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
    def _check_tls_cert_dependency(self) -> ApiSettings:
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
    def _check_pinned_requires_internal_ca(self) -> TlsSettings:
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

    # Very-large-document streaming in-flight budget (#149, ADR 0105 Phase 1a) — the aggregate DoS guard
    # that replaces the frame-cap-as-only-OOM-guard for streaming inbounds. It caps the TOTAL bytes of
    # over-threshold message bodies concurrently mid-detach (buffered + being sealed into the attachment
    # substrate) across ALL inbounds; a detach that would push the running total over it is refused with
    # backpressure (the message is NAK'd/ERROR'd, never accepted-and-dropped) so a burst of huge uploads
    # can't exhaust memory. 0 (the default) = unlimited (the per-connection max_message_bytes still bounds
    # a SINGLE body); a positive value bounds concurrency. Only over-threshold streaming detaches count
    # against it — below-threshold and non-streaming ingress is byte-identical and never touches it.
    stream_inflight_budget_bytes: int = 0


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
    # saturation alert threshold (#93, ADR 0014 amendment): fire when a lane's backlog is RISING
    # SUSTAINED over this many samples (the DERIVATIVE signal, distinct from buildup/stall's absolute
    # ceilings). None (the default) = OFF — deny-by-default, opt-in because it overlaps queue_buildup's
    # age dimension. Mirror SaturationThreshold (a test guards the sync); floor of 2 (fewer can't tell a
    # burst from sustained growth). Global-only for now (per-connection saturation= override is a
    # documented follow-up); a per-connection AlertRule (connection glob + transports=[]) can still
    # suppress it for a known-bursty feed.
    saturation_sustain_samples: int | None = None
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

    def saturation_threshold(self) -> SaturationThreshold:
        """The global default :class:`SaturationThreshold` every lane inherits (#93, ADR 0014
        amendment). ``None`` keeps the saturation (rising-backlog derivative) alert off by default."""
        return SaturationThreshold(sustain_samples=self.saturation_sustain_samples)


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
    # ADR 0104: copy-on-Send snapshots each Send's payload at construction so a divergent fan-out
    # (mutate-between-Sends) delivers per-destination state instead of a last-write-collapse. Now
    # DEFAULT-ON (BACKLOG #230 default-flip): the gate is satisfied — the conservative estate AST scan
    # flagged 1/152 handlers on the "construct Send, then mutate before return" surface, and human triage
    # found that one mutates an independent clone (a false positive → genuine divergence is 0; ADR 0104
    # §8.1), so the flip changes delivered bytes for zero handlers; and Message.copy() is now genuine
    # copy-on-write, so the common
    # single-Send / no-post-mutation path is zero-copy (~0.1us) and a deepcopy fires only on an actual
    # divergence. Set False to restore the pre-ADR-0104 last-write behavior. Reliability-core + read ONCE at
    # engine construction (a /config/reload does NOT re-read it — restart to change, like claim_mode).
    # Backend-agnostic (rides the run-context seam). Env/harness override: MEFOR_PIPELINE_SNAPSHOT_ON_SEND.
    snapshot_on_send: bool = Field(default=True)


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
    # ASVS 16.3.2 (BACKLOG #244): audit EVERY authorization GRANT, not just the sensitive/state-changing
    # set. OFF by default — only the sensitive surface (state-change/config/user-mgmt) writes an
    # `auth.grant` row, because require()/authorize_ws fire on every protected request and auditing every
    # read grant would flood the hash-chained `audit_log` (console polling + the /ws/stats feed). Turn ON
    # for an off-loopback deployment that wants the full L3 authorization trail; PHI-view grants stay
    # excluded even under 'all' (the PHI-access audit path already records those). Threaded onto
    # app.state by create_app (api/security.py `_audit_all_authz`).
    audit_all_authz: bool = False


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


class LogFormat(str, Enum):  # noqa: UP042
    TEXT = "text"  # human-readable (the default; stdout unchanged)
    JSON = "json"  # one JSON object per line — structured for a log shipper / SIEM


class SyslogProtocol(str, Enum):  # noqa: UP042
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
    # Per-hop insecure-forwarding attestation (#200, ADR 0092 shape — the [logging] sibling of a
    # connection's `tls_hop_attested`). The off-box forwarder ships a PHI-REDACTED copy of every log +
    # audit row, but the default `forward_protocol = "udp"` puts that evidence stream (usernames,
    # message ids, connection names, IPs, the audit chain) on the wire in the clear, and it was the ONE
    # egress path with no posture gate at all. It is now decided by the same shared authority the
    # transports use (see `forward_hop_disposition`): a plaintext / unverified-TLS collector hop is
    # REFUSED on an enforcing production-PHI instance unless the operator ATTESTS it — the acknowledged
    # opt-out, replacing a silent default. Loopback is always allowed, so the ADR 0080 "point tcp/udp at
    # 127.0.0.1 and let a local rsyslog/Vector agent add TLS" deployment is untouched.
    forward_hop_attested: bool = False
    forward_hop_attested_reason: str | None = None
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
    def _resolve_forwarding(self) -> LoggingSettings:
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
        # The attestation pair is validated by the SAME shared rule connection-level tls_hop_attested
        # uses (a reason without the flag, or a blank reason, is a config mistake) — never re-forked.
        # Re-raised under the [logging] field names so the operator sees which setting is at fault
        # (the shared helper's message names the connection-level `tls_hop_attested*` pair).
        try:
            _check_hop_attestation(self.forward_hop_attested, self.forward_hop_attested_reason)
        except ValueError as exc:
            raise ValueError(
                f"[logging].forward_hop_attested/forward_hop_attested_reason rejected: {exc}"
            ) from exc
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
    in. A purge **NULLs the PHI *body*** of a message/dead-letter while **keeping the message ROW**
    (counts + disposition + audit stay intact — the Mirth Data-Pruner pattern); it never deletes a
    ``messages`` row, and never touches a body still in flight (at-least-once is preserved). The row
    survives; its PHI *columns* do not. Tiers that carry nothing but PHI and back no count (transform
    state, connection events) are DELETEd outright instead.
    """

    # Past N days, null inbound bodies (raw/summary/error/metadata) of fully-resolved messages,
    # keeping the message ROW. `metadata` rides this same window (ASVS 14.2.7) — it is operator-
    # attached PHI (#150 SetMeta), not disposition, so it can never outlive the body.
    # 0 = keep forever.
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
    # Past N days, GZIP application LOG FILES (``.log``/``.txt``, one level) in ``[logging].log_dir`` to
    # ``<name>.gz`` (#119). NSSM rotates by size but never compresses, so a long-running box carries its
    # whole uncompressed log history; this shrinks it in place instead of deleting it, keeping the tail
    # readable (`gzip -d`) for far longer at the same disk cost. Each file is FREE-SPACE PRECHECKED
    # (skipped, not attempted, when the volume lacks room) and the written archive is INTEGRITY-VALIDATED
    # (decompressed off disk and compared byte-for-byte) *before* the original is removed — a failed
    # validation always leaves the original in place. The archive inherits the source's mtime, so the
    # `app_log_days` delete window still ages it out (that sweep extends to `*.log.gz`/`*.txt.gz` only
    # while this window is on). Set this SHORTER than `app_log_days` — a longer window compresses nothing,
    # because the delete sweep runs first and has already removed the file.
    # 0 = never compress (the default). A no-op unless ``[logging].log_dir`` is set.
    app_log_compress_days: int = 0
    # Past N days, DELETE saved-search presets (ADR 0136) whose `updated_at` is before the cutoff. The
    # stored `criteria` is the operator's own content/field_value needle — PHI-SHAPED by construction
    # (PHI.md §2, PL-2) and encrypted at rest — and until now no purge touched it (ASVS 14.2.7). The
    # whole ROW is DELETEd, not blanked: a preset's entire payload IS its criteria, so nulling would
    # leave the console listing a recallable-but-broken preset; and unlike `messages` it backs no count
    # and carries no disposition, so count-and-log does not reach it (the same reasoning that already
    # lets state/connection_event rows be DELETEd).
    #
    # The window keys on LAST-USED (#306): the cutoff is compared against the LATER of `updated_at` (a
    # save) and `last_used_at` (a recall), so a preset an operator runs daily but never re-saves is
    # KEPT. A row that predates the `last_used_at` column ages out on `updated_at` alone. The default is
    # still keep-forever rather than an inherited window — turning this on is an explicit, informed
    # choice, and nothing is deleted on upgrade.
    # 0 = keep forever (the default — byte-identical on upgrade; nothing is deleted until an operator
    # sets a window).
    search_preset_days: int = 0
    # Audit-log retention. RESERVED / not enforced: the audit_log is a tamper-evident hash chain and
    # HIPAA expects ~6-year retention, so audit is keep-forever by design here; archive-first pruning
    # is a tracked follow-up. Accepted (not rejected) so a forward-looking file still loads.
    audit_days: int = 0
    # Warn (WARNING log + AlertSink storage_threshold) when the DB file (+ -wal/-shm) exceeds this
    # many MB. 0 = off. Advisory only — never auto-deletes.
    max_db_mb: int = 0
    # How often the purge/maintenance loop runs a pass (seconds).
    purge_interval_seconds: float = 3600.0
    # Maximum wall-clock seconds one maintenance pass may spend (#121, ADR 0137). A BETWEEN-PHASE soft
    # cap: `run_once` checks the elapsed monotonic time before each phase and, once this is reached, SKIPS
    # the remaining phases (marking the pass `capped`) so a long pass can't run unbounded into the next
    # maintenance window — the skipped tail re-runs next interval (a skipped WAL-checkpoint/VACUUM does NOT
    # advance its last-run marker). Checked only BETWEEN phases, never inside one, so a running VACUUM is
    # non-interruptible. 0 = off (the default — no cap, byte-identical to the pre-#121 pass); recommend
    # ~14400 (4h, the Corepoint default off-peak ceiling) when enabled.
    max_pass_seconds: float = 0.0
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
        "app_log_compress_days",
        "search_preset_days",
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

    @field_validator("max_pass_seconds")
    @classmethod
    def _non_negative_max_pass(cls, value: float) -> float:
        if value < 0:
            raise ValueError("max_pass_seconds must be >= 0 (0 = off, no cap)")
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
    # require_mfa is on, an in-scope local account (see require_mfa_scope) MUST enroll a factor and
    # satisfy it before its session may reach ANY authorized route — MFA is an ACCESS gate, not only
    # a step-up gate (ASVS 6.3.3). A user who has already enrolled a factor is always required to
    # satisfy it, whatever the scope.
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
    # skipped at exposure. Scope: since ASVS 6.3.3 it gates **every authorized route** for an in-scope
    # session, not merely step-up operations — an MFA-pending session is refused with 403 +
    # ``X-MFA-Required: 1`` (api/security.py:require) and, in the browser, confined to /ui/mfa.
    require_mfa: bool = True
    # WHICH local accounts an un-enrolled session's access gate covers when require_mfa is on (ASVS
    # 6.3.3). ``every_local_account`` (default) means any local account must carry a second factor;
    # ``administrators`` is the pre-6.3.3 posture where only the Administrator role must. An account
    # that has ALREADY enrolled a factor is required to satisfy it under either value — this dial only
    # decides who must enroll in the first place. Directory (AD/Kerberos) identities are out of scope
    # under either value: their MFA is delegated to the directory (owner-signed relaxation).
    #
    # OPERATOR NOTE: under ``every_local_account`` a non-interactive LOCAL bearer-token service account
    # becomes MFA-pending and cannot enroll unattended — move it to mTLS (api/security.py:
    # require_service_cert, which is exempt by design) or to AD, or set this to ``administrators``.
    require_mfa_scope: Literal["administrators", "every_local_account"] = "every_local_account"
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
    # ASVS 6.4.5 arm 2: how many hours BEFORE that auto-disable to start reminding an operator (via the
    # `bootstrap_admin_expiring` AlertSink event) that the unclaimed first-run credential is about to be
    # retired. The API-lifespan reminder fires once per process while now sits inside
    # [expires_at - bootstrap_warn_hours, expires_at). Only meaningful when bootstrap_expiry_hours > 0.
    bootstrap_warn_hours: int = 24
    # ASVS 6.4.1: an admin-issued initial/reset credential (a `must_change_password` temp password) that
    # is never claimed EXPIRES this many hours after it was set. Without it, an unused reset password
    # grants an authenticated session indefinitely — and the one action it permits is to SET the
    # password, i.e. account takeover. Keyed on `password_changed_at`; a user who set their own password
    # has `must_change_password=False` and is unaffected. The bootstrap admin has its own
    # `bootstrap_expiry_hours` path and is exempt. 0 = no expiry (not recommended on a PHI instance).
    initial_password_expiry_hours: int = 72

    # Active Directory / LDAP. The bind password is a secret: MEFOR_AUTH_AD_BIND_PASSWORD.
    ad_enabled: bool = False
    ad_server: str | None = None  # e.g. ldaps://dc1.example.com:636
    ad_domain: str | None = None  # e.g. example.com (UPN suffix)
    ad_user_search_base: str | None = None
    ad_group_search_base: str | None = None
    ad_bind_dn: str | None = None  # service-account DN used to look users up
    ad_bind_password: str | None = None  # secret — supply via env only
    # Connector SecretProvider reference (ADR 0019 §5, BACKLOG #196). When set AND [secrets].provider is
    # configured, the bind password is resolved from that provider (e.g. a Vault KV 'path#field') at
    # LdapAuthenticator construction INSTEAD of ad_bind_password — so it need not sit in an env var. Unset
    # (the default) → ad_bind_password is used exactly as before (byte-identical). Not a secret itself (a
    # reference/label, not the value), so it may live in the config file. Fail-closed: a reference with no
    # [secrets].provider, or an unresolvable one, raises at startup (never a blank bind).
    ad_bind_password_secret: str | None = None
    ad_use_nested_groups: bool = True  # resolve nested groups via LDAP_MATCHING_RULE_IN_CHAIN
    ad_tls_verify: bool = True
    ad_tls_ca_cert_file: str | None = None  # trust an internal CA without disabling verification
    # WP #285 (ASVS 6.7.1): optional SHA-256 pin over ad_tls_ca_cert_file (lowercase-hex of the PEM
    # bytes). Checked at the trust-anchor preflight (load AND reload); a mismatch REFUSES — always,
    # independent of [security].enforcement (a substituted AD anchor permits an LDAPS MITM). Dormant
    # when None. Block-scoped (direct-read by the preflight, not desugared).
    ad_tls_ca_cert_pin: str | None = None
    ad_allow_insecure_ldap: bool = False  # explicit opt-in to a non-ldaps:// bind (trusted-net dev)
    # Finite network timeouts for EVERY ldap3 Server/Connection the authenticator builds (ASVS 13.1.3).
    # ldap3's own defaults are None on both, and the engine never calls socket.setdefaulttimeout, so
    # without these an unresponsive domain controller made the TCP connect and every LDAP response read
    # a block-forever operation — AuthService dispatches each LDAP call through a bare asyncio.to_thread
    # with no wait_for, so one wedged DC pinned a thread-pool worker indefinitely instead of failing the
    # login. 10 s each is well above a healthy on-prem DC round trip and well below any human patience
    # for a login. Both must be > 0: a 0/negative value would restore the unbounded wait.
    ad_connect_timeout: float = 10.0  # seconds — bound the LDAP/LDAPS TCP connect
    ad_receive_timeout: float = 10.0  # seconds — bound each LDAP response read (bind + search)

    # --- directory session reconciliation (ADR 0079 mechanism 2) -------------------------------
    # Disabling an account in AD does NOT terminate its live engine session: once an opaque token is
    # minted the directory is never re-consulted, so the session keeps working (and refreshing) up to
    # the flat session_absolute_hours cap. This background reconciler re-resolves each directory-backed
    # principal that still holds a live session and revokes the sessions of accounts that have been
    # disabled or deleted. See docs/adr/0079-kerberos-idp-session-coordination.md.
    #
    # How often a reconciliation pass runs, in seconds. **300 (five minutes) by default** (ADR 0148
    # GIVEN 1 — the hardened path is the shipped path), floored at 60 s: the pass costs one LDAP bind per
    # signed-in directory user, and a fat-fingered `1` would be a DC denial-of-service. `0` disables the
    # loop entirely and is a LOOSENING once AD is enabled — `security_loosenings()` names it.
    #
    # The default is INERT without AD: `AuthService.should_reconcile()` also requires an LDAP client, so a
    # deployment that never enables `ad_enabled` creates no task and issues no bind. That is why the
    # cross-field check below refuses only an EXPLICIT non-zero value without `ad_enabled` — refusing the
    # shipped default would break every non-AD deployment at startup, while an operator who deliberately
    # typed a value still gets told their control would be dead.
    ad_session_recheck_seconds: int = 300
    # How many CONSECUTIVE passes must fail to find a principal before its sessions are revoked. A
    # single ambiguous result never revokes: `resolve_principal` collapses "disabled", "deleted" and
    # "the search returned nothing" into one `None`, so requiring two agreeing probes costs at most one
    # extra interval of exposure and buys immunity to a single flaky search. Strike state is
    # process-local (the rate-limiter precedent), so a restart resets it — biased toward NOT revoking.
    ad_session_recheck_strikes: int = 2
    # Per-pass bind budget. A pass probes at most this many distinct users; the remainder are picked up
    # by the following passes (least-recently-probed first), so a very large estate degrades to a longer
    # effective interval instead of a bind storm against the DC.
    ad_session_recheck_max_users: int = 200
    # --- mass-revoke circuit breaker ---
    # A misconfigured search base, a moved OU, or a service account that lost read rights returns "not
    # found" for EVERY user — indistinguishable from "everyone was disabled". Without a brake the
    # reconciler would sign out the entire estate during exactly the incident when operators need the
    # console. A pass that would revoke more than BOTH of these thresholds aborts, revokes nothing, and
    # raises a loud operator-visible alert (log ERROR + an `auth.ad_reconcile_aborted` audit row).
    #
    # BOTH must be exceeded to trip, deliberately: the absolute floor stops the breaker firing on a tiny
    # estate where any proportion is meaningless (3 of 3 genuine offboardings is 100 %), and the
    # proportion stops a large estate being signed out wholesale. Requiring both means it fires only on
    # a change that is simultaneously large in absolute terms AND broad relative to the signed-in
    # population — the signature of a misconfiguration, not of offboarding. Below the floor the breaker
    # cannot distinguish the two cases; signing out a handful of operators is recoverable, and if the
    # directory really is broken they cannot sign back in, which is the loudest possible signal.
    ad_session_revoke_max: int = 5  # absolute: never auto-revoke more than this in one pass
    ad_session_revoke_max_fraction: float = 0.34  # proportional: ...nor more than this share

    # Windows SSO (Kerberos/SPNEGO) — passwordless login from a domain-joined client.
    # Experimental; off by default. Not a supported v0.1 feature — hardening targeted for 0.2.
    kerberos_enabled: bool = False
    kerberos_spn: str | None = None  # e.g. HTTP/host.example.com

    # Federated SSO — OIDC authorization-code + PKCE relying party (ADR 0142, BACKLOG #274). A THIRD
    # login mechanism for an identity that ALREADY exists in on-prem AD: the id_token is verified, then
    # the username claim is resolved against AD (roles come from LDAP, never the token). Default OFF and
    # byte-identical when off. Hybrid-only: a principal with no on-prem AD object is refused. Endpoints
    # are operator-pinned (no .well-known discovery), so no attacker-influenced URL exists.
    oidc_enabled: bool = False
    oidc_issuer: str | None = None  # https; exact-matched against the id_token `iss`
    oidc_client_id: str | None = None  # also the required `aud`/`azp`
    # The confidential-client secret. ENV ONLY (MEFOR_AUTH_OIDC_CLIENT_SECRET) — never the config file
    # (_FILE_SECRET_KEYS warns) — or via a [secrets].provider reference in oidc_client_secret_ref. The
    # `_ref` suffix (not the house `_secret`) avoids the absurd `oidc_client_secret_secret`; ADR 0142.
    oidc_client_secret: str | None = None
    oidc_client_secret_ref: str | None = None
    oidc_authorization_endpoint: str | None = None  # https, pinned
    oidc_token_endpoint: str | None = None  # https, pinned
    oidc_jwks_uri: str | None = None  # https, pinned
    # Defence-in-depth allow-list: every OIDC endpoint host must appear here (the model-validator
    # checks it, and jwks/flow re-check before each outbound call). Refused empty when enabled.
    oidc_allowed_endpoints: list[str] = Field(default_factory=list)
    # The engine's OWN back-channel TLS trust for the IdP. transports/rest.py uses OpenSSL's default
    # trust, which does NOT consult the Windows machine store — a domain-issued / self-signed IdP cert
    # is untrusted to the engine regardless of browser trust. Mirror of ad_tls_ca_cert_file.
    oidc_tls_ca_cert_file: str | None = None
    # WP #285 (ASVS 6.7.1): optional SHA-256 pin over oidc_tls_ca_cert_file (lowercase-hex of the PEM
    # bytes). Checked at build_idp_opener AND the trust-anchor preflight (load + reload); a mismatch
    # REFUSES — always, independent of [security].enforcement (a substituted OIDC anchor permits JWKS
    # substitution + forged id_tokens). Dormant when None. Block-scoped (direct-read, not desugared).
    oidc_tls_ca_cert_pin: str | None = None
    oidc_redirect_path: str = "/ui/oidc/callback"  # full URI derived from [api].public_origin
    oidc_scopes: list[str] = Field(default_factory=lambda: ["openid", "profile"])
    oidc_signing_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    oidc_username_claim: str = "preferred_username"
    oidc_username_strip_domain: bool = True  # strip at '@' → sAMAccountName
    # THE control that stops a federated principal picking which on-prem account it resolves to.
    # `preferred_username` is neither unique nor stable (OIDC Core §5.7) and is operator- or even
    # self-editable on many IdPs, so without this a guest presenting "Administrator@attacker.example"
    # strips to "Administrator" and logs in as the on-prem Domain Admin. When strip_domain is on, the
    # claim's UPN suffix MUST match one of these. Empty = fall back to [auth].ad_domain; if neither is
    # set, oidc_enabled is refused at load rather than stripping unchecked. List the alternate UPN
    # suffixes of a multi-domain forest here.
    oidc_allowed_username_domains: list[str] = Field(default_factory=list)
    oidc_clock_skew_seconds: int = 60  # wall clock; validator-capped 0..300
    # The BACKLOG #99(g) control: refuse a login whose verified token carries no configured MFA claim.
    # Secure default ON. The engine verifies what the IdP ASSERTS, not what it enforced.
    oidc_require_mfa_claim: bool = True
    oidc_mfa_amr_values: list[str] = Field(default_factory=lambda: ["mfa"])
    oidc_required_acr_values: list[str] = Field(default_factory=list)
    oidc_acr_values: str | None = None  # requested `acr_values` authorize param
    oidc_prompt: str | None = None  # requested `prompt` authorize param
    oidc_jwks_ttl_seconds: int = 3600
    oidc_jwks_min_refetch_seconds: int = 300  # the amplification bound
    oidc_flow_ttl_seconds: int = 300
    oidc_flow_cache_max: int = 512  # reject-when-full (never evict — that is a login DoS)
    oidc_session_max_hours: int | None = None  # G2: cap below id_token.exp if tighter is wanted

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
    # re-verification; the step-up GETs are exempt from admin-write pacing and instead charge the
    # per-actor PHI-read budget explicitly at admission (see enforce_phi_read_pacing). The floor is set an order of
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

    @field_validator(
        "oidc_allowed_endpoints",
        "oidc_scopes",
        "oidc_signing_algorithms",
        "oidc_mfa_amr_values",
        "oidc_required_acr_values",
        "oidc_allowed_username_domains",
        mode="before",
    )
    @classmethod
    def _split_oidc_lists(cls, v: object) -> object:
        # Allow env-setting a list key as one comma-separated string (MEFOR_AUTH_OIDC_SCOPES=...);
        # without this the "zero env-plumbing" property holds only for scalars (precedent: egress).
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("oidc_clock_skew_seconds")
    @classmethod
    def _check_oidc_skew(cls, value: int) -> int:
        if not 0 <= value <= 300:
            raise ValueError("oidc_clock_skew_seconds must be between 0 and 300")
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

    @field_validator("ad_connect_timeout", "ad_receive_timeout")
    @classmethod
    def _check_ad_timeout(cls, value: float) -> float:
        # Must stay FINITE and positive (ASVS 13.1.3): ldap3 treats 0/None as "wait forever", which is
        # exactly the unbounded wait these settings exist to remove, and inf/NaN are the same hole by
        # another spelling. Rejected at config load, not discovered at bind time against a wedged DC.
        if not value > 0 or value == float("inf"):
            raise ValueError(
                "ad_connect_timeout / ad_receive_timeout must be a finite number of seconds > 0 "
                "(0, a negative value, inf or NaN would restore an unbounded LDAP wait)"
            )
        return value

    @field_validator("ad_session_recheck_seconds")
    @classmethod
    def _check_ad_recheck_seconds(cls, value: int) -> int:
        # 0 = off (the default). Anything else is floored at 60 s: a pass costs one LDAP bind per
        # signed-in directory user, so a mistyped `1` would hammer the domain controller.
        if value < 0:
            raise ValueError("ad_session_recheck_seconds must be >= 0 (0 = disabled)")
        if 0 < value < 60:
            raise ValueError(
                "ad_session_recheck_seconds must be 0 (disabled) or >= 60 — a shorter interval "
                "would bind against the domain controller once per signed-in user per few seconds"
            )
        return value

    @field_validator("ad_session_recheck_strikes")
    @classmethod
    def _check_ad_recheck_strikes(cls, value: int) -> int:
        # >=1: a zero would revoke on the first ambiguous probe, defeating the whole point.
        if not 1 <= value <= 10:
            raise ValueError("ad_session_recheck_strikes must be between 1 and 10")
        return value

    @field_validator("ad_session_recheck_max_users")
    @classmethod
    def _check_ad_recheck_max_users(cls, value: int) -> int:
        if value < 1:
            raise ValueError("ad_session_recheck_max_users must be >= 1")
        return value

    @field_validator("ad_session_revoke_max")
    @classmethod
    def _check_ad_revoke_max(cls, value: int) -> int:
        if value < 0:
            raise ValueError("ad_session_revoke_max must be >= 0")
        return value

    @field_validator("ad_session_revoke_max_fraction")
    @classmethod
    def _check_ad_revoke_fraction(cls, value: float) -> float:
        # A 0.0 fraction can never be exceeded by a non-negative count in the AND-form trip test, which
        # would silently disable the proportional half of the breaker; refuse it rather than pretend.
        if not 0.0 < value <= 1.0:
            raise ValueError(
                "ad_session_revoke_max_fraction must be > 0.0 and <= 1.0 (1.0 = the proportional "
                "half of the breaker never trips; the absolute ad_session_revoke_max still applies)"
            )
        return value

    @model_validator(mode="after")
    def _require_ad_fields(self) -> AuthSettings:
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
        if self.ad_enabled and self.ad_bind_dn is None:
            raise ValueError("ad_enabled requires a service account: ad_bind_dn")
        if (
            self.ad_enabled
            and self.ad_bind_password is None
            and self.ad_bind_password_secret is None
        ):
            # The service-account password may come from the env (ad_bind_password via
            # MEFOR_AUTH_AD_BIND_PASSWORD) OR a [secrets].provider reference (ad_bind_password_secret,
            # ADR 0019 §5) — but one of them must be present, or the SIMPLE bind has no credential.
            raise ValueError(
                "ad_enabled requires a service-account password: set ad_bind_password (via "
                "MEFOR_AUTH_AD_BIND_PASSWORD) or ad_bind_password_secret (a [secrets].provider reference)"
            )
        if self.kerberos_enabled and not self.ad_enabled:
            raise ValueError("kerberos_enabled requires ad_enabled (SSO resolves roles via AD)")
        if (
            self.ad_session_recheck_seconds
            and not self.ad_enabled
            and "ad_session_recheck_seconds" in self.model_fields_set
        ):
            # Refuse rather than no-op: an operator who set this believes directory revocation now
            # propagates. A silently-dead security control is worse than never having enabled it.
            #
            # Keyed on model_fields_set, not on the value, since the hardened SHIPPED default (300, ADR
            # 0148 GIVEN 1) is non-zero: refusing it unconditionally would fail startup on every
            # deployment that does not use AD, which is most of them. An untouched default carries no
            # operator belief to falsify, and it is inert anyway — should_reconcile() also requires an
            # LDAP client. An explicitly typed value still refuses, which is the case the rule is for.
            raise ValueError(
                "ad_session_recheck_seconds requires ad_enabled (the reconciler re-resolves "
                "principals through the same LDAP service-account bind)"
            )
        return self

    @model_validator(mode="after")
    def _require_oidc_fields(self) -> AuthSettings:
        """Federated OIDC needs its pinned endpoints + a fail-closed posture when enabled (ADR 0142).

        The redirect origin is cross-section (``[api].public_origin``), so that one check lives on
        :class:`ServiceSettings`; everything self-contained to ``[auth]`` is enforced here.
        """
        if not self.oidc_enabled:
            return self
        if not self.ad_enabled:
            # Hybrid-only: a federated login resolves roles against on-prem AD (same as Kerberos SSO).
            raise ValueError(
                "oidc_enabled requires ad_enabled (federated logins resolve roles via AD)"
            )

        missing = [
            name
            for name, value in (
                ("oidc_issuer", self.oidc_issuer),
                ("oidc_client_id", self.oidc_client_id),
                ("oidc_authorization_endpoint", self.oidc_authorization_endpoint),
                ("oidc_token_endpoint", self.oidc_token_endpoint),
                ("oidc_jwks_uri", self.oidc_jwks_uri),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"oidc_enabled requires: {', '.join(missing)}")

        if self.oidc_client_secret is None and self.oidc_client_secret_ref is None:
            raise ValueError(
                "oidc_enabled requires a client secret: set oidc_client_secret (via "
                "MEFOR_AUTH_OIDC_CLIENT_SECRET) or oidc_client_secret_ref (a [secrets].provider reference)"
            )

        # Every pinned URL must be https (no dev escape — this is an off-box trust boundary) and its
        # host must appear in the allow-list, which must itself be non-empty.
        if not self.oidc_allowed_endpoints:
            raise ValueError("oidc_enabled requires a non-empty oidc_allowed_endpoints allow-list")
        allowed = set(self.oidc_allowed_endpoints)
        for name, url in (
            ("oidc_issuer", self.oidc_issuer),
            ("oidc_authorization_endpoint", self.oidc_authorization_endpoint),
            ("oidc_token_endpoint", self.oidc_token_endpoint),
            ("oidc_jwks_uri", self.oidc_jwks_uri),
        ):
            parts = urlsplit(url or "")
            if parts.scheme != "https":
                raise ValueError(f"[auth].{name} must be an https URL (got {url!r})")
            if parts.hostname not in allowed:
                raise ValueError(
                    f"[auth].{name} host {parts.hostname!r} is not in oidc_allowed_endpoints "
                    f"{sorted(allowed)}"
                )

        # A gate that can never fire is worse than none: require at least one MFA family populated.
        if self.oidc_require_mfa_claim and not (
            self.oidc_mfa_amr_values or self.oidc_required_acr_values
        ):
            raise ValueError(
                "oidc_require_mfa_claim=true needs at least one of oidc_mfa_amr_values / "
                "oidc_required_acr_values (an MFA gate that can never match is refused)"
            )

        # The callback route is registered at the literal DEFAULT path, while the redirect_uri handed
        # to the IdP is built from this key — so a non-default value would only fail at the last hop
        # of a live login, as an IdP-side redirect_uri mismatch or a 404 the operator cannot place.
        # AC-9 says an unusable combination is refused at load, naming the exact key.
        default_redirect_path = type(self).model_fields["oidc_redirect_path"].default
        if self.oidc_redirect_path != default_redirect_path:
            raise ValueError(
                f"oidc_redirect_path is fixed at {default_redirect_path!r} in this release: the "
                f"browser callback route is registered at that literal path, so a different value "
                f"would be advertised to the identity provider but never served"
            )

        # Stripping a UPN suffix without checking it lets a federated principal CHOOSE which on-prem
        # account it resolves to (OIDC Core §5.7: preferred_username is neither unique nor stable).
        # Refuse rather than strip unchecked.
        if self.oidc_username_strip_domain and not self.effective_oidc_username_domains:
            raise ValueError(
                "oidc_username_strip_domain=true requires oidc_allowed_username_domains (or "
                "[auth].ad_domain to fall back to): the claim's UPN suffix must be checked, or a "
                "federated principal can pick which on-prem account it resolves to"
            )

        # Coerce the pinned algorithms through the closed enum (forecloses alg:none / HS* at config).
        try:
            [SignatureAlgorithm(a) for a in self.oidc_signing_algorithms]
        except ValueError as exc:
            raise ValueError(
                f"oidc_signing_algorithms must all be supported JWS algorithms: {exc}"
            ) from exc
        return self

    @property
    def effective_oidc_username_domains(self) -> tuple[str, ...]:
        """The UPN suffixes a federated ``username`` claim may carry, lower-cased.

        Explicit ``oidc_allowed_username_domains`` wins; otherwise fall back to the single
        ``ad_domain`` the LDAP layer already builds UPNs from (``auth/ldap.py``). Empty means no
        suffix source is configured at all, which the validator above refuses when stripping is on.
        """
        if self.oidc_allowed_username_domains:
            return tuple(d.strip().lower() for d in self.oidc_allowed_username_domains if d.strip())
        return (self.ad_domain.strip().lower(),) if self.ad_domain else ()


#: Characters permitted in a free-form environment NAME (it selects ``environments/<name>.toml``, so
#: it must be a safe single path segment).
_ENV_NAME_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

#: Built-in environment names whose security posture (data_class, production) is derived when
#: ``[ai].data_class`` / ``[ai].production`` are left unset — back-compat with the original
#: dev/staging/prod tiers. A CUSTOM name must set posture explicitly (it is never inferred from a
#: free-form string), so a 'test'/'poc' instance can never default permissive (ADR 0017).
#: GIVEN 1 (ADR 0148): the default env ``dev`` derives **PHI** too — the default/CI path runs the
#: PHI-carrying posture (secure-by-default, so encryption/egress/retention are exercised, not first met
#: in production). A genuinely-synthetic dev/CI box must declare ``[security].handles_real_patient_data
#: = false`` — a loud, audited opt-out. Only ``production`` still differs across the three (prod alone is
#: the production tier, which drives the AI data-scope ceiling + the DEBUG-log refusal, not the security
#: refuse/warn dial — that is ``[security].enforcement``, GIVEN 2).
_KNOWN_ENV_POSTURE: dict[str, tuple[DataClass, bool]] = {
    "dev": (DataClass.PHI, False),
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
    # (ADR 0148 GIVEN 1: dev->phi/non-prod, staging->phi/non-prod, prod->phi/prod); a custom name must
    # set them. The refuse/warn dial is [security].enforcement (GIVEN 2), not `production`.
    data_class: DataClass | None = None
    production: bool | None = None

    # --- engine broker (ADR 0135 / BACKLOG #95) ------------------------------------------------
    # These describe the customer-managed / self-hosted LLM the engine brokers to under
    # AiMode.MANAGED_ENDPOINT (POST /ai/chat). provider/model/endpoint select and address it;
    # baa_attested is an operator attestation carried for the P2 managed_claude_baa path (unused by
    # the code_only MVP broker, which never sends PHI regardless).
    provider: str = "claude"
    model: str = "claude-opus-4-8"
    baa_attested: bool = False
    endpoint: str | None = None
    # The broker credential (the LLM provider API key). SECRET — env only (MEFOR_AI_API_KEY), listed in
    # _FILE_SECRET_KEYS (warns if placed in the file) and _SECRET_SETTING_KEYS (redacted). Never logged.
    api_key: str | None = None
    # SSRF fail-closed allowlist (ADR 0135): each entry is "host" (any port) or "host:port". The broker
    # validates its configured `endpoint` against THIS list ITSELF — an un-listed host (or an empty list)
    # is REFUSED. Deliberately independent of [egress].allowed_http, which is permissive-when-empty and so
    # cannot be the gate for this new egress surface.
    allowed_endpoints: list[str] = []

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
                "dev/staging/prod); set [security].handles_real_patient_data (true|false) and "
                "[security].production_instance (true|false) explicitly"
            )
        return dc, prod


def hop_posture_from_ai(ai: AiSettings, *, enforcement: SecurityEnforcement) -> HopPosture:
    """The instance's :class:`~messagefoundry.config.tls_policy.HopPosture` for the #200 hop-refusal gate.

    Maps the AI section's *derived* ``is_phi`` (built-in dev/staging/prod derivation applied) plus the
    explicit ``[security].enforcement`` level onto the ``(is_phi, enforcing)`` the transport cells decide
    on. ``is_phi`` keys on ``data_class == phi`` being *explicitly* declared — an **undeclared**
    ``data_class`` is **not** PHI, exactly as the keyless-refusal (§3), ``[egress]`` and #906 Posture-B
    gates all key on ``data_class == phi`` being set: a bare/default on-prem config carries no PHI
    assertion, so its hops stay byte-identical (never newly refused). ``enforcing`` is
    ``enforcement is ENFORCE`` (the secure default), which re-keys the REFUSE/WARN dial off the old
    production-tier flag onto the explicit enforcement level: at the default it reproduces the historical
    ``production=True`` refuse — splitting a declared-PHI hop between ENFORCE-REFUSE and WARN-WARN. The
    construction gate stamps the result via ``tls_policy.active_hop_posture`` (ADR 0092)."""
    data_class, _production = ai.derived_posture()
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
    return HopPosture.fail_closed(
        is_phi=is_phi, enforcing=(enforcement is SecurityEnforcement.ENFORCE)
    )


def forward_hop_disposition(log: LoggingSettings, posture: HopPosture) -> HopDisposition:
    """Decide what to do with the off-box log/audit forwarding hop (#200 residual, ADR 0092 — PURE).

    The ``[logging].forward_*`` syslog/SIEM forwarder was the one PHI-adjacent egress path with **no**
    posture gate: ``forward_protocol`` defaults to plaintext ``udp`` (RFC 5426), so an operator who
    named a collector shipped a PHI-**redacted** but still sensitive evidence stream — usernames,
    connection names, message ids, client IPs, the tamper-evident audit chain — off-box in the clear,
    silently. Native TLS-syslog has existed since ADR 0080 (``forward_protocol = "tls"``, RFC 5425,
    CA-anchored), so a secure transport is available and this is a *default* problem, not a
    capability gap.

    The decision is delegated to :func:`~messagefoundry.config.tls_policy.insecure_hop_disposition` —
    the SAME authority the transports consume — so the forwarder decides identically to every other
    egress cell. A hop is treated as **secure** (and never gated) only when it is TLS *with
    verification on*; plaintext ``udp``/``tcp`` and the ``forward_tls_verify=false`` opt-out are both
    MITM-able and go to the gradient:

    #. loopback collector → ALLOW — the ADR 0080 "point ``tcp``/``udp`` at ``127.0.0.1`` and let a
       local rsyslog/Vector agent add TLS" deployment is explicitly preserved, byte-identical.
    #. synthetic instance (not ``is_phi``) → ALLOW — silent, nothing sensitive rides the hop. Applied
       HERE (not by the shared authority, which ADR 0153 stripped of the label) — see below.
    #. ``forward_hop_attested`` → ALLOW — the acknowledged, reasoned opt-out (a trusted management
       segment), the ``[logging]`` sibling of a connection's ``tls_hop_attested``.
    #. the CLAMPED global escape → WARN (never fires under ENFORCE — see
       :func:`hop_insecure_escape_downgrades`).
    #. enforcing PHI → REFUSE. #. else (non-enforcing PHI) → WARN.

    Callers that have not resolved a posture pass the fail-closed one; ``serve`` supplies
    :func:`hop_posture_from_ai`. Pure so the gate is unit-testable without standing up ``serve``.

    **ADR 0153 leaves this cell keyed on the data label, deliberately** (its *Explicitly out of scope*
    table: "Stays keyed on posture; a ``[logging]`` sibling of ``cleartext_accepted`` is a follow-up").
    The forwarder is not a connection, so it has nowhere to carry a per-hop declaration, and refusing
    it instead would create a deviation the loosening registry cannot express. The ``not is_phi`` ALLOW
    arm 0153 deleted from the shared authority is therefore restated HERE, explicitly, rather than
    inherited — the scope limit is a written decision at the one place it applies, not an emergent
    property of a signature change."""
    if log.forward_protocol is SyslogProtocol.TLS and log.forward_tls_verify:
        # Verified, CA-anchored TLS (ADR 0080) — an encrypted+authenticated hop, nothing to gate.
        return HopDisposition.ALLOW
    if not posture.is_phi:
        # ADR 0153 scope carve-out — see the docstring. Restated here, not inherited.
        return HopDisposition.ALLOW
    return insecure_hop_disposition(
        enforcing=posture.enforcing,
        # An unset forward_host cannot happen with forwarding on (the validator requires it), and the
        # empty string is treated as loopback by the shared predicate — so an unconfigured forwarder
        # can never be refused.
        is_loopback_hop=is_loopback_hop_host(log.forward_host or ""),
        hop_attested=log.forward_hop_attested,
        # The global escape keeps its arm HERE (same scope carve-out): it is the only expressible
        # relaxation this non-connection cell has. Clamped upstream to non-enforcing, so under ENFORCE
        # it is always False and can never cross an enforcing PHI hop (ADR 0092 decision 2). It rides
        # the new arm 3, which occupies exactly the pre-0153 arm-4 slot, so this is byte-identical.
        cleartext_accepted=hop_insecure_escape_downgrades(enforcing=posture.enforcing),
    )


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

    # ADR 0126 (#112/#128): a site-wide DEFAULT forward/egress web proxy for the HTTP family
    # (REST/SOAP/FHIR/fhir_lookup/DICOMweb + the OAuth2/SMART token endpoints). A connection that sets no
    # per-connection `proxy` inherits this; a per-connection value overrides it. None (default) = no
    # site-wide proxy (byte-identical — only per-connection proxies apply). "default" = the OS default web
    # proxy (getproxies()); an http(s):// address = an explicit proxy. Credentials stay per-connection
    # (secrets via env()), not a global TOML value. Env: MEFOR_EGRESS_PROXY_URL.
    proxy_url: str | None = None
    # The site-wide NO_PROXY-style bypass list inherited by a connection that sets no per-connection
    # `proxy_no_proxy` (#128). Each entry is a host / `.suffix` / `*.suffix` / `*`. Env (comma-separated):
    # MEFOR_EGRESS_PROXY_NO_PROXY.
    proxy_no_proxy: list[str] = []

    # Opt-in deny-by-default (Q5b): when true, a transport with an EMPTY allowlist refuses every
    # destination of that type instead of allowing any. A global on-ramp to fail-closed egress without
    # having to enumerate one list just to flip the posture; pairs with the prod/staging open-egress
    # startup advisory. Default false = the per-list opt-in behavior above (empty = unrestricted).
    deny_by_default: bool = False

    # 1.2.2 (ASPIRATIONAL, ASVS 1.2.2): require the per-value-encoded structured params= form for every
    # fhir_lookup search. When true, the author-encoded flat '?'-query escape hatch is REFUSED (raised in
    # FhirLookupExecutor._resolve_read_url before the defense-in-depth screen) so a search value can never
    # smuggle an extra FHIR search parameter. Default false keeps the flat form (byte-identical to today);
    # a read-by-id and the structured params= form are unaffected either way.
    # Env: MEFOR_EGRESS_FHIR_REQUIRE_STRUCTURED_PARAMS.
    fhir_require_structured_params: bool = False

    @field_validator(
        "allowed_mllp",
        "allowed_tcp",
        "allowed_file_dirs",
        "allowed_http",
        "allowed_db",
        "allowed_remote",
        "allowed_smtp",
        "allowed_direct",
        "proxy_no_proxy",
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


class AlertSeverity(str, Enum):  # noqa: UP042
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
        "saturation",  # #93 (ADR 0014 amendment): a lane's backlog is RISING SUSTAINED (ingest > drain)
        "integrity_drift",  # #54: startup attestation found in-place-tampered engine module(s)
        # ASVS 11.3.4: the active store DEK crossed 2**31 persisted AES-GCM invocations (half the
        # fail-closed 2**32 birthday ceiling) — rotate before encrypts start refusing.
        "gcm_invocations",
        "update_available",  # #30: a newer MessageFoundry version is pinned than is running (ADR 0026)
        "backup_failed",  # #60 (ADR 0049): a scheduled/on-demand DR backup failed (snapshot/encrypt/verify)
        "lane_stuck",  # ADR 0070: a pooled lane is retrying a persistent infra fault forever (retry_forever)
        "rcsi_off_degraded",  # ADR 0066: pooled claim running with READ_COMMITTED_SNAPSHOT OFF (correctness-degraded)
        "leadership_acquired",  # #145 (ADR 0014 amendment): a node went non-leader→leader (HA failover / election)
        "dr_activated",  # #145 (ADR 0014 amendment, ADR 0048): a third-tier DR standby was promoted
        "content_match",  # #81 (ADR 0133): a code-first Handler ("Action Point") matched message content (PHI-free)
        # ASVS 6.4.5 arm 2: an UNCLAIMED first-run bootstrap admin is nearing its auto-disable deadline
        # (payload is the ISO deadline + whole hours remaining — never the password; PHI-free)
        "bootstrap_admin_expiring",
        # NOTE: the INVERSE events (leadership_lost / dr_released) are auto-resolve-only (alert_sinks
        # _AUTO_RESOLVE), NOT rule-targetable alert types — a step-down / fail-back needs no page.
    }
)
#: The transport names a rule may route to; mirror ``AlertTransport.name``.
_ALERT_TRANSPORTS = frozenset({"webhook", "email"})

#: #144 (ADR 0128) — the whitelisted connection-control actions an alert rule may fire on match. Only
#: the two warm-restart primitives (never a bare stop, which would silently wedge a feed with no re-arm);
#: mirror ``RegistryRunner.restart_inbound`` / ``restart_outbound``.
_ALERT_CONTROL_ACTIONS = frozenset({"restart_inbound", "restart_outbound"})

#: #138 (ADR 0127) — the CLOSED, non-PHI variable allowlist an alert-email template may reference. Every
#: name here is *structurally* non-PHI (a severity enum / event-type token / connection name / timestamp
#: / integer count / cooldown / operator rule label), so a template can NEVER interpolate a message body
#: or an arbitrary HL7 field. Any other reference is rejected at config-load (fail-closed). The renderer
#: in ``pipeline/alert_sinks.py`` MUST provide exactly these keys (a test pins the two in sync).
_ALERT_TEMPLATE_VARS = frozenset(
    {
        "severity",  # info / warning / critical
        "type",  # the alert event type (connection_stopped, queue_buildup, …)
        "connection",  # the connection / label the event is about (operator config, not PHI)
        "timestamp",  # ISO-8601 UTC of the event
        "depth",  # queue_buildup pending depth (a count) — "" when the event has none
        "oldest_age_seconds",  # oldest-undelivered age (a count) — "" when the event has none
        "cooldown_seconds",  # the effective re-alert cooldown for this event
        "rule_id",  # the matching rule's operator label ({rule_id}); "" when unset / no rule
    }
)


def validate_alert_template(template: str, *, where: str) -> None:
    """Validate one alert-email template against the closed non-PHI allowlist (#138, ADR 0127) —
    **fail-closed at config-load**. Uses ``string.Formatter().parse`` (never ``str.format``), so every
    ``{...}`` placeholder must be a **bare allowlisted identifier**: attribute/index access
    (``{connection.__class__}`` / ``{0}``), a conversion (``{x!r}``), or a format-spec (``{x:>10}``) is
    rejected, closing the ``str.format`` injection surface. Any name outside
    :data:`_ALERT_TEMPLATE_VARS` (e.g. a message-body / HL7 field) raises :class:`ValueError`. ``where``
    labels the offending setting in the error. Escaped braces (``{{`` / ``}}``) are literal text and are
    fine."""
    allowed = ", ".join(sorted(_ALERT_TEMPLATE_VARS))
    for _literal, field, spec, conv in string.Formatter().parse(template):
        if field is None:
            continue
        if field == "":
            raise ValueError(
                f"{where}: an empty '{{}}' placeholder is not allowed — reference a named variable "
                f"(allowed, non-PHI only: {allowed})"
            )
        if field not in _ALERT_TEMPLATE_VARS:
            raise ValueError(
                f"{where}: unknown / PHI-unsafe template variable {{{field}}}; alert-email templates may "
                f"reference only these non-PHI variables: {allowed} (a message body / HL7 field is never "
                "permitted — ADR 0127 fail-closed)"
            )
        if conv is not None or spec:
            raise ValueError(
                f"{where}: a conversion / format-spec on {{{field}}} is not allowed — use a bare "
                "{name} placeholder (ADR 0127: no str.format attribute/spec surface)"
            )


class EscalationTier(BaseModel):
    """One **occurrence-driven escalation tier** of an :class:`AlertRule` (#81, ADR 0133). Once the
    matched alert instance has fired at least ``after_count`` times, the tier's overrides apply over the
    base rule — the highest satisfied tier wins, so a persistent condition climbs (warn → page →
    critical). Pure data; **NOT** the ADR 0014 §3-declined *timed* escalation (this keys on the
    occurrence count, never elapsed time). Any override left ``None`` inherits the base rule's value."""

    model_config = ConfigDict(extra="forbid")

    # Escalate once the open instance has fired at least this many times (ge=1; the base rule is tier 0).
    after_count: int = Field(ge=1)
    severity: AlertSeverity | None = None  # None = keep the base rule's severity
    transports: list[str] | None = None  # None = keep the base; [] = suppress at this tier
    recipients: list[str] | None = None  # None = keep the base recipients

    @field_validator("transports")
    @classmethod
    def _check_transports(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            bad = [t for t in v if t not in _ALERT_TRANSPORTS]
            if bad:
                allowed = ", ".join(sorted(_ALERT_TRANSPORTS))
                raise ValueError(f"transports must be a subset of [{allowed}]; unknown: {bad}")
        return v

    @field_validator("recipients")
    @classmethod
    def _check_recipients(cls, v: list[str] | None) -> list[str] | None:
        # A tier recipient OVERRIDE that resolves to nobody is a config error (parity with AlertRule).
        if v is not None:
            cleaned = [addr.strip() for addr in v if addr.strip()]
            if not cleaned:
                raise ValueError(
                    "escalate[].recipients must be a non-empty list of addresses (omit it)"
                )
            return cleaned
        return v


class AlertRule(BaseModel):
    """One operator-authored alerting rule (ADR 0014). The **first** rule that matches an event decides
    its severity, which transports fire, and the re-alert cooldown; an event matching no rule keeps the
    default (notify every configured transport at ``warning`` with the global ``realert_seconds``).
    Rules are pure data — there is no embedded code/expression."""

    model_config = ConfigDict(extra="forbid")

    # --- match (all conditions must hold) ---
    event_type: str = "any"  # "any" | connection_stopped | queue_buildup | storage_threshold | cert_expiry | secret_rotation | connection_error | message_stall | saturation | integrity_drift | update_available | backup_failed | lane_stuck | rcsi_off_degraded | bootstrap_admin_expiring
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
    # #146 (ADR 0014 amendment): per-rule EMAIL recipient override. None = the global [alerts].email_to
    # is used, byte-identical to before. A non-empty list re-targets the email transport for events this
    # rule matches (Corepoint-parity routing — page the on-call for OB_* stops, email the interface team
    # for a specific feed). Addresses are operator config, NOT PHI; but they are an INTERNAL routing key
    # popped before any webhook payload (the webhook never carries recipient addresses). Empty [] is
    # rejected (a recipient override that sends to nobody is a config error — use transports=[] to
    # suppress instead).
    recipients: list[str] | None = None
    # #138 (ADR 0127): optional operator label for this rule, surfaced as the {rule_id} alert-email
    # template variable and in the read-only /alerts/rules view. Non-PHI free text; NEVER interpolated as
    # code (it is a value substituted into an allowlisted template placeholder). None = "" in a template.
    id: str | None = None
    # #144 (ADR 0128): OPTIONAL auto-remediation control action fired when this rule matches — one of
    # "restart_inbound" / "restart_outbound" (whitelisted). None (default) = notify only, no control
    # (byte-identical). Dispatched OFF the delivery worker + never-raise; throttled WITH the notification
    # (≤ once per cooldown per event+connection); independent of transport suppression (transports=[] ⇒
    # quiet auto-remediation). Requires the notifier (≥1 transport). Pure data — no embedded code.
    control_action: str | None = None
    # The connection the control action targets. None = the event's own connection (natural for the
    # connection-scoped events connection_stopped / connection_error / queue_buildup); set it to act on a
    # DIFFERENT connection than the one that fired (e.g. restart an inbound when its paired outbound stalls).
    control_target: str | None = None
    # #143 (ADR 0044 amendment): a static per-rule NOTIFICATION mute. True suppresses the notification for
    # matching events (equivalent to transports=[], but reads as intent) while STILL recording the alert
    # instance (AC-3) and still permitting a quiet #144 control action. The config-static twin of the
    # operator's windowed POST /alerts/{id}/suspend. Default False = byte-identical. Pure data — no code.
    mute: bool = False
    # #81 (ADR 0133): OCCURRENCE-driven escalation tiers. Empty (default) = no escalation (byte-identical).
    # Once the matched instance has fired >= a tier's after_count, that tier's severity/transports/
    # recipients override the base rule (the highest satisfied tier wins). NOT the ADR 0014 §3-declined
    # timed chain — this keys on the occurrence count, never elapsed time. Pure data — no code/expression.
    escalate: list[EscalationTier] = []
    # #81 (ADR 0133): schedule-aware matching — the rule applies ONLY when its Schedule is active at the
    # event time (the #147/ADR 0095 Schedule: weekday + local time-of-day window + IANA tz + invert). None
    # (default) = always applies (byte-identical). Two rules with different schedules express time-varying
    # thresholds (e.g. page in business hours, email off-hours) — first match wins, per ADR 0014.
    schedule: Schedule | None = None
    # #81 (ADR 0133): route CONTENT-triggered alerts by their operator label — matches a `content_match`
    # event only when its `label` equals this (non-PHI operator config, NEVER a matched field value). None
    # (default) = no label filter. Meaningful with event_type='content_match' (or 'any').
    content_label: str | None = None

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

    @field_validator("recipients")
    @classmethod
    def _check_recipients(cls, v: list[str] | None) -> list[str] | None:
        # None = fall through to [alerts].email_to (the default). A recipient OVERRIDE that resolves to
        # nobody is a config error — an operator suppresses a notification with transports=[], not by
        # handing the email transport an empty recipient list. Reject empty / all-blank fail-closed.
        if v is not None:
            cleaned = [addr.strip() for addr in v if addr.strip()]
            if not cleaned:
                raise ValueError(
                    "recipients must be a non-empty list of addresses (omit it to use the global "
                    "[alerts].email_to, or set transports=[] to suppress)"
                )
            return cleaned
        return v

    @field_validator("control_action")
    @classmethod
    def _check_control_action(cls, v: str | None) -> str | None:
        # #144 (ADR 0128): whitelist the auto-remediation action — only the two warm-restart primitives.
        if v is not None and v not in _ALERT_CONTROL_ACTIONS:
            allowed = ", ".join(sorted(_ALERT_CONTROL_ACTIONS))
            raise ValueError(f"control_action must be one of [{allowed}]; got {v!r}")
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
    # Connector SecretProvider reference (ADR 0019 §5, BACKLOG #196). When set AND [secrets].provider is
    # configured, the SMTP password is resolved from that provider (e.g. a Vault KV 'path#field') at
    # notifier construction INSTEAD of email_password. Unset (the default) → email_password is used exactly
    # as before (byte-identical). A reference/label, not the value, so it may live in the config file.
    # Fail-closed: a reference with no [secrets].provider, or an unresolvable one, raises at startup.
    email_password_secret: str | None = None
    email_timeout: float = 30.0  # seconds per send
    # Egress allowlist for the SMTP host (WP-11c, parity with webhook_allowed_hosts). Empty = any.
    smtp_allowed_hosts: list[str] = []
    # #138 (ADR 0127): OPTIONAL operator-editable alert-email templates. All None (the default) = the
    # fixed subject + key/value body, byte-identical to before. When set, each is a {name} template over
    # the CLOSED non-PHI variable allowlist (_ALERT_TEMPLATE_VARS) — validated at config-load, fail-closed
    # (an unknown / message-derived reference raises). email_html_template adds an HTML alternative whose
    # substituted VALUES are HTML-escaped; the plain-text part is ALWAYS kept (never HTML-only).
    email_subject_template: str | None = None
    email_body_template: str | None = None
    email_html_template: str | None = None

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

    @model_validator(mode="after")
    def _check_email_templates(self) -> AlertsSettings:
        # #138 (ADR 0127): validate each configured alert-email template against the CLOSED non-PHI
        # allowlist at config-load — fail-closed, so a template referencing a message body / arbitrary
        # HL7 field (or any unknown name) refuses `serve`/reload rather than leaking PHI off-box at send.
        for value, where in (
            (self.email_subject_template, "[alerts].email_subject_template"),
            (self.email_body_template, "[alerts].email_body_template"),
            (self.email_html_template, "[alerts].email_html_template"),
        ):
            if value is not None:
                validate_alert_template(value, where=where)
        return self


class SecretsSettings(_Section):
    """``[secrets]`` — the connector **SecretProvider** selection (ADR 0019 §5, BACKLOG #196 residual).

    Selects HOW a named connector credential (an AD LDAP bind password, an SMTP password, a SQL Server
    auth password) is *sourced* — from an external secrets backend **instead of** a ``MEFOR_*`` env var.
    It is the connector-secret twin of ``[store].key_provider`` (which sources the store DEK).

    ``provider`` is one of ``none`` | ``env`` | ``vault``. **``none`` (the default) means no provider is
    consulted** — every credential point reads its env-sourced value exactly as before (BYTE-IDENTICAL). A
    provider is used only for a credential whose per-credential ``*_secret`` reference is set (e.g.
    ``[auth].ad_bind_password_secret``, ``[alerts].email_password_secret``); an unset reference always
    falls through to the env value. ``vault`` reads Vault KV v2 behind the lazy ``[vault]`` extra (the SAME
    ``hvac`` dependency the store's Vault KeyProvider uses — no new dependency). This names a *provider*,
    not credential material, so it is NOT a secret. Unknown/unresolvable values fail closed at the
    consuming credential point (config/secretprovider.py)."""

    provider: str = "none"


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
    def _timeout_exceeds_heartbeat(self) -> ClusterSettings:
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
    def _fence_ordering(self) -> ClusterSettings:
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

    The store DEK is tracked **live-by-default** (ASVS 13.3.4, BACKLOG #282): at first keyed start the
    engine persists a non-secret tracked-since stamp (the DEK key-id + first-seen date) in store meta and
    watches the DEK off it, so setting ``store_key_last_rotated`` (an ISO ``YYYY-MM-DD`` date) is an
    **override**, not a prerequisite. The connector/AD/SMTP/Vault/OIDC credentials the engine holds are
    tracked too — each is fingerprinted with a DEK-derived keyed MAC into store meta and its clock reset
    when the fingerprint changes (rotation auto-detected). The broader ``SecretProvider`` generalization
    (a pluggable secret backend) remains a design-only follow-on (ADR 0019 §5)."""

    warn_days: int = (
        14  # alert this many days before a secret is due for rotation (0 = reminder off)
    )
    check_interval_seconds: float = (
        86_400.0  # rescan cadence (rotation is a slow signal; daily is ample)
    )
    # Store DEK tracking: the operator MAY record when the store encryption key was last rotated (ISO
    # YYYY-MM-DD) + how long it may live. When unset, the DEK is tracked LIVE-BY-DEFAULT off a persisted
    # tracked-since stamp (ASVS 13.3.4, BACKLOG #282): the engine records the DEK key-id + first-seen date
    # in store meta at first keyed start, so the operator date is an OVERRIDE, not a prerequisite. These
    # are DATES, not the key — never a secret value.
    store_key_last_rotated: str | None = None
    store_key_max_age_days: int = 365  # rotate the store DEK within this many days of last_rotated
    # Cadence for the NON-DEK tracked secret classes (ASVS 13.3.4): connector/AD/SMTP/Vault/OIDC secrets
    # the engine holds are fingerprinted (keyed MAC) into store meta, their clock reset when the
    # fingerprint changes (rotation auto-detected), and alerted this many days after last-observed change.
    secret_max_age_days: int = 365
    # ENFORCE escalation grace (ASVS 13.3.4): under [security].enforcement=ENFORCE, a DEK older than
    # store_key_max_age_days + this grace escalates its rotation alert (higher severity) at restart.
    enforce_grace_days: int = 30

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

    @field_validator("store_key_max_age_days", "secret_max_age_days")
    @classmethod
    def _check_max_age(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("secret_rotation max-age days must be > 0")
        return v

    @field_validator("enforce_grace_days")
    @classmethod
    def _check_grace(cls, v: int) -> int:
        if v < 0:
            raise ValueError("secret_rotation.enforce_grace_days must be >= 0")
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
    def _require_destination_when_enabled(self) -> BackupSettings:
        # A backup with nowhere to write is a misconfiguration; fail loud at config load, not at 02:00.
        if self.enabled and not self.destination.strip():
            raise ValueError(
                "[backup].enabled=true requires a non-empty [backup].destination (a LOCAL or UNC path)"
            )
        return self

    def schedule_time(self) -> tuple[int, int] | None:
        """The configured daily backup time as ``(hour, minute)`` local, or ``None`` for on-demand only."""
        return RetentionSettings._parse_clock(self.schedule_at) if self.schedule_at else None


class DrActivationMode(str, Enum):  # noqa: UP042
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
    def _reject_auto_mode(self) -> DrSettings:
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


class SecuritySettings(_Section):
    """``[security]`` — the single, plain-language home for the high-value security **posture switches**
    (ADR 0118). Every switch **defaults to the secure position**, uses **positive framing** (the secure
    state is ``true``: ``require_*`` / ``*_only``), and loosening one is deliberate and **warned at
    serve** (see ``docs/SECURITY-LOOSENING.md``).

    This section is an **input layer**, not a new enforcement surface: the loader
    (:func:`load_settings`) **desugars** it into the internal section fields it replaces
    (``[api]``/``[auth]``/``[store]``/``[egress]``/``[retention]``/``[diagnostics]``/``[ai]``) and
    **rejects** those legacy keys as file/env input (see :data:`_RELOCATED_TO_SECURITY`), so every serve
    gate + the ``checks.py`` mirror keep reading the same internal fields — **no shipped refusal is
    loosened** (No-loosen rule, ADR 0092 §5). Low-level *plumbing* (TLS cert paths, ``[egress]``
    allow-list *contents*, ``[retention].dead_letter_days``, DB identity, password policy, rate limits)
    **stays in its functional section** (CISA "minimize settings"). Editing is **IDE-only**; the web
    console is **read-only** (``GET /security/posture``, no settings-write API).

    Desugaring is **presence-gated**: an *absent* switch leaves the internal field at its own default so
    the posture-aware serve-gate flips (retention auto-bound, egress deny-by-default, keyless-PHI refusal)
    still apply exactly as today — an absent ``[security]`` section is byte-identical to the pre-ADR-0118
    behaviour. An *explicitly set* switch is written through (and the serve gate still applies its
    posture logic on top)."""

    # ── Network access (operator API + web console) ──────────────────
    local_access_only: bool = True  # reachable only from this machine (loopback bind)
    listen_address: str = "127.0.0.1"  # bind address; used only when local_access_only = false
    require_encryption_for_remote: bool = True  # any off-machine access must be over TLS
    serve_web_console: bool = True  # mount the browser ops console at /ui — on by default (ADR 0143); disable with serve_web_console=false
    web_console_public_address: str = ""  # external origin when the console is exposed off-box
    # Source-address allow-list for the operator API + web console — the guard-rail for the deliberate
    # off-box opt-in. EMPTY (the default) = NO source restriction, byte-identical to today. Non-empty =
    # a request whose client address falls outside EVERY listed network is refused in ASGI middleware,
    # before routing and before auth. Each entry is a CIDR ("10.20.0.0/16", "2001:db8::/48") or a bare
    # host address ("10.20.4.7" -> /32); IPv4 and IPv6, mixed freely. Same syntax as an inbound
    # connection's source_ip_allowlist, and the same matcher (messagefoundry.netaddr).
    # SCOPE: the OPERATOR surface only. It does NOT restrict the MLLP/TCP/X12/DICOM/HTTP ingest
    # listeners — those have their own per-connection [inbound].source_ip_allowlist.
    # LOOPBACK IS ALWAYS ALLOWED, unconditionally and with no knob: the credential-less on-box clients
    # (the tray's tokenless /health poll (ADR 0113), a browser opening /ui on the engine host,
    # `messagefoundry check`, the harness/apiclient, a container HEALTHCHECK) cannot be allow-listed, so
    # naming a ward subnet must never lock the box out of its own console.
    # HONEST LIMIT: this matches the address uvicorn reports. Behind a DECLARED reverse proxy
    # ([api].trusted_proxies -> forwarded_allow_ips) that is the real client; behind an UNDECLARED one —
    # or NAT / a bridge-networked container — every request looks like the intermediary and the control
    # is INERT. It is defence-in-depth behind a host firewall, never the primary network control.
    # Setting this also TIGHTENS [api].trusted_proxies (single-host entries only) — see ServiceSettings.
    # Env: MEFOR_SECURITY_ALLOWED_CLIENT_NETWORKS (COMMA-separated).
    allowed_client_networks: list[str] = []

    # ── Security enforcement dial ────────────────────────────────────
    # The REFUSE/WARN dial for the posture GATES + the ADR 0092 escape-clamp, DECOUPLED from the
    # production-tier fact (this refactor). ENFORCE (secure default) reproduces the historical
    # production=True refuse posture byte-identically; warn reproduces the non-production warn+continue.
    # DIRECT-READ by the serve gate / hop_posture_from_ai — NOT desugared (no legacy section it replaces).
    enforcement: SecurityEnforcement = SecurityEnforcement.ENFORCE

    # ── Encryption of stored data ────────────────────────────────────
    encrypt_stored_data: bool = True  # PHI encrypted at rest (key from env)
    allow_unencrypted_phi: bool = False  # audited escape: start a PHI instance with no key
    allow_unencrypted_phi_under_strict_enforcement: bool = (
        False  # ADR 0140: SECOND ack also required to start keyless under strict enforcement
    )

    # ── In-use data protection (ASVS 11.7.1, ADR 0152 rung 2) ────────
    # The OPERATOR'S DECLARATION that this host provides hardware memory encryption (AMD SEV-SNP,
    # Intel TDX, or equivalent), so PHI is protected in RAM while it is being processed. The engine
    # CANNOT verify it — a local CPU flag is emitted by the OS whose integrity the requirement
    # protects against — so this records WHO TOOK RESPONSIBILITY; it does not establish the property
    # and it does not satisfy ASVS 11.7.1.
    # NAMED "operator_declared", NOT "attested", ON PURPOSE. In confidential computing — the exact
    # domain of 11.7.1 — "attestation" is the term of art for a CPU-signed quote verified against the
    # silicon vendor's root PKI, which is ADR 0152 rung 3 and is NOT BUILT. The codebase's other
    # unverifiable-property switches (MEFOR_TLS_REVOCATION_ATTESTED, the Posture-B proxy
    # declarations) use "attested" in the weaker in-house sense, but that convention does not travel
    # with a JSON body leaving the building, and this is the one field whose value is quotable as a
    # compliance claim. Same discipline, different word.
    # Default FALSE and BYTE-IDENTICAL when unset.
    # DIRECT-READ by the serve gate + GET /security/posture — deliberately NOT in
    # _SECURITY_PASSTHROUGH: there is no legacy internal field this replaces (it is net-new), and a
    # passthrough entry would imply a section that owns it. Setting it TRUE is not a loosening (it
    # asserts a protection); it is nonetheless cross-checked against the platform read-out, and a
    # contradiction is reported on GET /security/posture.
    memory_encryption_operator_declared: bool = False
    # OPT-IN ENFORCEMENT of the declaration above. Default FALSE, and that default is load-bearing:
    # an exposed PHI instance with no declaration WARNS, it never refuses, so nothing that boots
    # today stops booting on upgrade. The property is a HOST property no operator can satisfy on
    # Windows (the read-out is always null there), so a refusal keyed on it by default would
    # hard-stop working dev/staging/prod deployments over a platform fact they cannot change — the
    # outcome ADR 0151 avoided by scoping its companion refusal to its own opt-in, and the reason the
    # Posture-B widening warns on the recommended loopback-behind-proxy topology. Set TRUE to turn
    # that warning into a refusal for an estate that has standardized on confidential-computing
    # hosts; the refuse/warn dial ([security].enforcement, ADR 0148) still applies on top, so
    # enforcement=warn keeps it a warning even when this is set. Not a loosening (it tightens).
    require_memory_encryption_declaration: bool = False

    # ── Sign-in & identity ───────────────────────────────────────────
    require_sign_in: bool = True  # authenticate every request
    require_mfa: bool = True  # second factor, enforced as an ACCESS gate (ASVS 6.3.3)
    # Who must enroll one when require_mfa is on. Default widens the gate past the Administrator role
    # to every local account (ASVS 6.3.3); "administrators" restores the pre-6.3.3 posture.
    require_mfa_scope: Literal["administrators", "every_local_account"] = "every_local_account"
    allow_single_factor_admin_when_exposed: bool = (
        False  # ADR 0140: permit single-factor admin on an EXPOSED production-PHI bind
    )
    sign_out_after_idle_minutes: int = 30
    max_session_hours: int = 12

    # ── Data handling ────────────────────────────────────────────────
    block_unlisted_outbound: bool = (
        True  # deny-by-default egress; only allow-listed destinations send
    )
    delete_message_bodies_after_days: int = 30  # 0 = keep indefinitely (audited)
    allow_keeping_phi_indefinitely: bool = False
    # PHI access is ALWAYS audited (the tamper-evident chain + message-event floor are unconditional);
    # this only extends tracing to EVERY authz decision (defence-in-depth, not a HIPAA requirement).
    # Default false — forcing it on risks flooding the audit log (ADR 0118 §5, owner-confirmed).
    audit_all_authorization_decisions: bool = False

    # ── What this instance handles (the master posture lever) ────────
    # None (the default) = DERIVE from the [ai].environment name (dev→synthetic, staging/prod→phi; a
    # custom name must declare a posture or serve fails closed via require_posture — parity with today).
    # true/false are explicit overrides. The §1 "= true" in ADR 0118 is the RESOLVED secure position for a
    # production instance, not the raw default; a stock dev/staging/prod instance needs no value here.
    handles_real_patient_data: bool | None = None  # was [ai].data_class = "phi"
    production_instance: bool | None = None  # was [ai].production

    @field_validator("allowed_client_networks", mode="before")
    @classmethod
    def _split_client_networks(cls, v: object) -> object:
        # COMMA, never os.pathsep. os.pathsep is ':' on POSIX — which is also the IPv6 group separator —
        # so reusing the [api] list splitter (_split_roots) would shred every v6 entry on the Linux leg.
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("allowed_client_networks", mode="after")
    @classmethod
    def _check_client_networks(cls, v: list[str]) -> list[str]:
        # Parse at LOAD so a typo fails loud here rather than becoming a silently-dropped rule, which
        # would leave the surface WIDER than the operator believes. strict=False matches the inbound
        # source_ip_allowlist syntax (netaddr.peer_ip_allowed) so the two allow-lists never disagree
        # about what is legal; we store the NORMALIZED (masked) form so `security show` and
        # GET /security/posture display exactly what is enforced — an operator who wrote "10.1.2.3/24"
        # sees it become "10.1.2.0/24" instead of quietly matching a wider range than they typed.
        out: list[str] = []
        for entry in v:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"[security].allowed_client_networks entry {entry!r} is not a valid CIDR network "
                    f"or host address: {exc}"
                ) from exc
            if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped:
                # An IPv4-mapped literal like ::ffff:10.20.0.0/112 can never match: the matcher unmaps a
                # dual-stack peer to its IPv4 form before testing. Say so rather than fail silently.
                raise ValueError(
                    f"[security].allowed_client_networks entry {entry!r} is an IPv4-mapped IPv6 "
                    "network; write the plain IPv4 CIDR instead (dual-stack peers are unmapped before "
                    "matching, so a mapped literal can never match)"
                )
            out.append(str(network))
        return out

    @property
    def client_networks(self) -> tuple[str, ...]:
        """``allowed_client_networks`` as the normalized strings the matcher consumes. A plain
        property, NOT a pydantic field, so ``model_dump()`` (and therefore ``GET /security/posture``)
        is unchanged."""
        return tuple(self.allowed_client_networks)


class ServiceSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")  # tolerate forward-looking/unknown sections

    security: SecuritySettings = Field(default_factory=SecuritySettings)
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
    secrets: SecretsSettings = Field(default_factory=SecretsSettings)
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
    def _oidc_requires_public_origin(self) -> ServiceSettings:
        """A federated redirect URI is built from ``[api].public_origin`` — refuse ``oidc_enabled``
        without a resolvable one, rather than silently constructing a wrong URI the IdP rejects at
        runtime. This spans ``[auth]`` and ``[api]``, so it lives here (ADR 0142)."""
        if self.auth.oidc_enabled and not self.api.public_origin:
            raise ValueError(
                "[auth].oidc_enabled requires [api].public_origin (the federated redirect URI is "
                "derived from it); set it to the browser-reachable origin, e.g. "
                "'https://ops.example.com' or 'http://localhost:8765' for a loopback lab"
            )
        return self

    @model_validator(mode="after")
    def _client_allowlist_requires_pinned_proxies(self) -> ServiceSettings:
        """A host inside ``[api].trusted_proxies`` can set ``X-Forwarded-For`` to ANY value and uvicorn
        hands that value to us as ``scope["client"]`` — so every trusted host can forge itself into
        ``[security].allowed_client_networks``. A broad entry like ``10.0.0.0/8`` on a hospital LAN
        numbered out of 10/8 therefore makes every workstation a trusted spoofer and reduces the
        allow-list to decoration — it would silently nullify the very restriction the operator just
        asked for. When the allow-list is in use, REFUSE (not warn): a warning on an off-box PHI
        console is a warning nobody reads, and this can only trigger on the opt-in, so it cannot break
        an existing deployment. Spans ``[security]`` and ``[api]``, so it lives here."""
        if not self.security.allowed_client_networks:
            return self
        for entry in self.api.trusted_proxies:
            net = ipaddress.ip_network(entry, strict=False)  # already validated by ApiSettings
            if net.num_addresses != 1:
                raise ValueError(
                    f"[api].trusted_proxies entry {entry!r} covers {net.num_addresses} addresses. "
                    "With [security].allowed_client_networks set, every trusted proxy must be a "
                    "SINGLE HOST (a bare address, /32 or /128): any host inside a trusted range can "
                    "forge its own X-Forwarded-For and defeat the allow-list. List the proxy's exact "
                    "address(es) instead."
                )
        return self

    @model_validator(mode="after")
    def _cluster_requires_server_db(self) -> ServiceSettings:
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
    def _dr_activate_not_clustered(self) -> ServiceSettings:
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
    def _warm_pool_timeout_under_fence(self) -> ServiceSettings:
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


# --- ADR 0118: the [security] section desugars into the internal fields it replaces ----------------
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: Legacy ``(section, key)`` → the ``[security]`` key that replaces it (ADR 0118). Setting any of these
#: in its old section (file OR ``MEFOR_<SECTION>_<KEY>`` env) is REJECTED at load — the posture switches
#: have a single canonical home. Plumbing keys NOT relocated (``[store].require_encryption``,
#: ``[retention].dead_letter_days``, ``[egress].allowed_*``, TLS cert paths, …) stay accepted.
_RELOCATED_TO_SECURITY: dict[tuple[str, str], str] = {
    ("api", "host"): "local_access_only / listen_address",
    ("api", "serve_ui"): "serve_web_console",
    ("api", "public_origin"): "web_console_public_address",
    ("store", "allow_unencrypted_phi"): "allow_unencrypted_phi",
    ("auth", "enabled"): "require_sign_in",
    ("auth", "require_mfa"): "require_mfa",
    ("auth", "require_mfa_scope"): "require_mfa_scope",
    ("auth", "session_idle_timeout_minutes"): "sign_out_after_idle_minutes",
    ("auth", "session_absolute_hours"): "max_session_hours",
    ("egress", "deny_by_default"): "block_unlisted_outbound",
    ("retention", "messages_days"): "delete_message_bodies_after_days",
    ("retention", "allow_unbounded_phi"): "allow_keeping_phi_indefinitely",
    ("diagnostics", "audit_all_authz"): "audit_all_authorization_decisions",
    ("ai", "data_class"): "handles_real_patient_data",
    ("ai", "production"): "production_instance",
}

#: ``[security]`` key → ``(section, field)`` for the switches that map 1:1 onto a settable internal field.
#: The non-1:1 switches (network host, at-rest encryption, the posture lever, require_encryption_for_remote)
#: are handled explicitly in :func:`_desugar_security`.
_SECURITY_PASSTHROUGH: tuple[tuple[str, str, str], ...] = (
    ("serve_web_console", "api", "serve_ui"),
    ("require_sign_in", "auth", "enabled"),
    ("require_mfa", "auth", "require_mfa"),
    ("require_mfa_scope", "auth", "require_mfa_scope"),
    ("sign_out_after_idle_minutes", "auth", "session_idle_timeout_minutes"),
    ("max_session_hours", "auth", "session_absolute_hours"),
    ("block_unlisted_outbound", "egress", "deny_by_default"),
    ("delete_message_bodies_after_days", "retention", "messages_days"),
    ("allow_keeping_phi_indefinitely", "retention", "allow_unbounded_phi"),
    ("audit_all_authorization_decisions", "diagnostics", "audit_all_authz"),
    ("production_instance", "ai", "production"),
)


def _reject_relocated_keys(data: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` if a relocated posture key is set in its OLD section (ADR 0118 AC-1). The
    switch moved to ``[security]``; accepting it in two places would defeat the single-canonical-home
    goal and could silently disagree with ``[security]``. Checked against file+env (not CLI plumbing)."""
    for (section, key), replacement in _RELOCATED_TO_SECURITY.items():
        sect = data.get(section)
        if isinstance(sect, dict) and key in sect:
            raise ValueError(
                f"[{section}].{key} moved to [security].{replacement} (ADR 0118) and is no longer "
                f"accepted; set [security].{replacement} instead (see docs/CONFIGURATION.md)."
            )


def _desugar_security(data: dict[str, dict[str, Any]]) -> None:
    """Populate the internal section fields from ``[security]`` (ADR 0118). **Presence-gated**: only an
    EXPLICITLY-set switch is written through, so an absent switch leaves the internal default (and the
    posture-aware serve-gate flips: retention auto-bound, egress deny-by-default, keyless-PHI refusal)
    intact — an absent ``[security]`` is byte-identical to pre-ADR-0118. Runs AFTER
    :func:`_reject_relocated_keys` and BEFORE the CLI merge, so ``--host``/``--db`` still win. Note:
    ``require_encryption_for_remote`` maps to no field — the serve gate reads it directly."""
    raw = data.get("security")
    if not isinstance(raw, dict):
        return

    # Pydantic sections are extra="ignore", so an UNKNOWN [security] key loads clean, does nothing, and
    # says nothing. For posture switches that is a silent fail-open: mistype `block_unlisted_outbound`
    # or set a switch that does not exist yet (a key backported from newer docs), and the operator
    # believes a control is on while the engine applies its permissive default. Relocated keys are the
    # loud exception (_reject_relocated_keys), which is exactly the signal this restores for the rest.
    # WARN rather than reject: an unknown key may be a forward-compatible config shared across an estate
    # mid-upgrade, and refusing would turn a harmless typo into a failed start on every host at once.
    unknown = sorted(set(raw) - set(SecuritySettings.model_fields))
    if unknown:
        _log.warning(
            "[security] has unrecognized key(s): %s — IGNORED, so any posture they were meant to set "
            "is NOT in effect. Check the spelling against docs/CONFIGURATION.md; a switch that moved "
            "sections is rejected loudly instead.",
            ", ".join(unknown),
        )

    # Validate through the model so env-delivered STRINGS are coerced properly ("false" → False, not the
    # truthy non-empty string) and ``model_fields_set`` tells us which switches were EXPLICITLY provided
    # (presence-gating). A malformed [security] value fails loud here, exactly like any other section.
    sec = SecuritySettings.model_validate(raw)
    provided = sec.model_fields_set

    def _set(section: str, key: str, value: Any) -> None:
        data.setdefault(section, {})[key] = value

    for skey, section, field in _SECURITY_PASSTHROUGH:
        if skey in provided:
            _set(section, field, getattr(sec, skey))

    # ADR 0143: mark serve_ui EXPLICITLY requested (serve_web_console was provided, at either value) so
    # the serve path can tell an explicit serve_web_console=true (console package absent -> HARD refuse)
    # from the default-on posture (package absent -> JSON-only + WARNING soft-degrade). Irrelevant when
    # serve_web_console=false (serve_ui is then off — no console to degrade).
    if "serve_web_console" in provided:
        _set("api", "serve_ui_explicit", True)

    # Network host: local_access_only forces loopback; a contradictory non-loopback listen_address with
    # local_access_only=true REFUSES (AC-3) rather than silently overriding.
    if "local_access_only" in provided or "listen_address" in provided:
        if sec.local_access_only and sec.listen_address not in _LOOPBACK_HOSTS:
            raise ValueError(
                f"[security].local_access_only=true but [security].listen_address={sec.listen_address!r} "
                "is not a loopback address (127.0.0.1/localhost/::1). Set local_access_only=false to "
                "bind it off-box (TLS required), or use a loopback listen_address."
            )
        _set("api", "host", "127.0.0.1" if sec.local_access_only else sec.listen_address)

    # Web-console external origin (empty string = unset → None, matching [api].public_origin).
    if "web_console_public_address" in provided:
        origin = sec.web_console_public_address.strip()
        _set("api", "public_origin", origin or None)

    # At-rest encryption: encrypt_stored_data=false OR allow_unencrypted_phi=true both suppress the
    # keyless-PHI refusal (the audited opt-out). [store].require_encryption (force even synthetic) is
    # plumbing that stays put and still wins.
    if "encrypt_stored_data" in provided or "allow_unencrypted_phi" in provided:
        _set(
            "store",
            "allow_unencrypted_phi",
            sec.allow_unencrypted_phi or not sec.encrypt_stored_data,
        )

    # Master posture lever: bool → DataClass string. None (unset) is NOT written, so the posture derives
    # from the [ai].environment name exactly as today (parity; custom-unset still fails closed).
    if sec.handles_real_patient_data is not None:
        _set("ai", "data_class", "phi" if sec.handles_real_patient_data else "synthetic")


def security_loosenings(
    sec: SecuritySettings,
    store: StoreSettings,
    auth: AuthSettings,
    cleartext_hops: Sequence[str],
) -> list[tuple[str, str]]:
    """Every security-relevant switch currently at its INSECURE value, as ``(switch, plain-language risk)``.

    Every parameter is REQUIRED, not optional, and deliberately so. There is exactly ONE shipped posture
    and an operator may only loosen from it, so a deviation that this registry cannot see is a second
    posture by the back door. An optional parameter is a detector that silently fails to fire; a required
    one makes omission a type error at every call site.

    ``cleartext_hops`` is the list of OUTBOUND CONNECTION NAMES that declare ``cleartext_accepted``
    (ADR 0153) — the one connection-scoped deviation in this otherwise settings-scoped registry. It
    arrives as plain names rather than a ``Registry`` so ``config.settings`` never has to know the graph
    type; the caller resolves them (``checks.accepted_cleartext_hops`` is the shared reader). A caller
    that genuinely has no graph — ``messagefoundry security show``, which reads a settings file and
    never loads the connection config — passes an empty sequence and SAYS SO in its output, rather than
    reporting a subset as if it were everything.

    Shared by the serve-time loosening warning (``__main__``, ADR 0118 AC-4) and the read-only posture
    view (``GET /security/posture``, AC-5), so the two never drift. This is advisory only — it names what
    a deliberate opt-out gives up; the posture GATES (which still refuse a production-PHI weakening) are
    unchanged. ``audit_all_authorization_decisions=false`` is the owner-confirmed SECURE default, so it is
    NOT a loosening. See ``docs/SECURITY-LOOSENING.md``."""
    out: list[tuple[str, str]] = []
    if sec.enforcement is SecurityEnforcement.WARN:
        out.append(
            (
                "enforcement",
                "the security REFUSE/WARN dial is at 'warn' — posture weakenings (cleartext/verify-off "
                "hops, keyless PHI, open egress, single-factor admin at exposure) are WARNED + audited "
                "and permitted to continue rather than refused, and MEFOR_ALLOW_INSECURE_TLS / "
                "--allow-insecure-bind escapes are honored",
            )
        )
    if not sec.local_access_only:
        out.append(("local_access_only", "the operator API/console is reachable off this machine"))
    # Deliberately CONDITIONAL, unlike every other entry here: the function's contract is "every switch
    # currently at its INSECURE value", and an EMPTY allow-list on the default loopback bind is the
    # SECURE position (no restriction is needed when nothing off-box can reach the socket). It becomes a
    # loosening only once the surface is actually exposed. Gated on EXPOSURE, not on the bind: the
    # RECOMMENDED off-box topology keeps local_access_only=true (loopback bind) behind a reverse proxy
    # that faces the network, so a `not local_access_only` test alone would never fire in the
    # most-exposed supported posture. Residual (documented, not fixed): a JSON-only off-box deployment
    # behind a proxy declares no web_console_public_address, and [security] carries no other signal of an
    # upstream proxy, so it still won't trip this.
    if (
        not sec.local_access_only or bool(sec.web_console_public_address)
    ) and not sec.allowed_client_networks:
        out.append(
            (
                "allowed_client_networks",
                "the operator API/console is exposed off this machine with NO source-network "
                "allow-list — every host that can route to the bind (or to the proxy in front of it) "
                "may reach the sign-in page",
            )
        )
    if not sec.require_encryption_for_remote:
        out.append(
            (
                "require_encryption_for_remote",
                "off-machine access is permitted WITHOUT TLS — bearer tokens and PHI would cross the network "
                "in cleartext (still refused on a production-PHI bind)",
            )
        )
    if not sec.require_sign_in:
        out.append(
            (
                "require_sign_in",
                "authentication is DISABLED — requests run as a full-privilege system identity "
                "(loopback-only; a non-loopback bind refuses)",
            )
        )
    if not sec.require_mfa:
        out.append(
            (
                "require_mfa",
                "every local account is single-factor — no native TOTP second factor is required",
            )
        )
    elif sec.require_mfa_scope != "every_local_account":
        # Not a refusal: "administrators" is the pre-ASVS-6.3.3 posture, and refusing to boot on it
        # would be the fleet-wide breaking upgrade the owner declined. Advisory read-out only.
        out.append(
            (
                "require_mfa_scope",
                "only Administrators must enroll a second factor — every other local account is "
                "single-factor until it opts in by enrolling",
            )
        )
    if sec.allow_single_factor_admin_when_exposed:
        out.append(
            (
                "allow_single_factor_admin_when_exposed",
                "single-factor admin is permitted on an EXPOSED production-PHI bind — no second factor over the network",
            )
        )
    if not sec.encrypt_stored_data:
        out.append(
            (
                "encrypt_stored_data",
                "at-rest encryption is OFF — PHI would be stored unencrypted (a PHI instance still refuses "
                "unless allow_unencrypted_phi is also set)",
            )
        )
    if sec.allow_unencrypted_phi:
        out.append(
            (
                "allow_unencrypted_phi",
                "a PHI instance may start keyless — PHI stored UNENCRYPTED at rest",
            )
        )
    if sec.allow_unencrypted_phi_under_strict_enforcement:
        out.append(
            (
                "allow_unencrypted_phi_under_strict_enforcement",
                "a PHI instance may start keyless under strict enforcement — PHI stored UNENCRYPTED at rest",
            )
        )
    if not sec.block_unlisted_outbound:
        out.append(
            (
                "block_unlisted_outbound",
                "outbound egress is allow-any — a transform may send PHI to any destination",
            )
        )
    if sec.delete_message_bodies_after_days == 0:
        out.append(
            (
                "delete_message_bodies_after_days",
                "message bodies are kept indefinitely (a PHI instance still auto-bounds/refuses per posture)",
            )
        )
    if sec.allow_keeping_phi_indefinitely:
        out.append(("allow_keeping_phi_indefinitely", "unbounded PHI retention is permitted"))
    # --- switches outside [security] that are still posture deviations (ADR 0148: one posture, loosen
    # only). They live in [store]/[auth] for cohesion, but an operator turning either off is loosening the
    # shipped posture, so they belong in the same registry rather than a parallel one that could drift.
    if not store.aad_bind:
        out.append(
            (
                "aad_bind",
                "at-rest values are NOT bound to their (table, column, row) cell — a ciphertext moved "
                "between cells decrypts instead of failing its auth tag (no effect without a store key)",
            )
        )
    # Conditional on ad_enabled, like allowed_client_networks above: with no directory there is nothing to
    # reconcile against, so 0 is not a weaker choice, it is the only meaningful one.
    if auth.ad_enabled and not auth.ad_session_recheck_seconds:
        out.append(
            (
                "ad_session_recheck_seconds",
                "directory revocation does NOT propagate — an AD account disabled or deleted keeps its "
                "live engine sessions until they expire on their own",
            )
        )
    # --- the one CONNECTION-scoped deviation (ADR 0153 decision 2). It is not a [security] switch, but
    # it is a declared departure from the one shipped posture, so it belongs in the one registry an
    # operator reads — a deviation the registry cannot see is a second posture by the back door.
    if cleartext_hops:
        named = ", ".join(sorted(cleartext_hops))
        out.append(
            (
                "cleartext_accepted",
                f"{len(cleartext_hops)} outbound connection(s) cross a CLEARTEXT hop by declaration "
                f"({named}) — the payload, and any credential the connection carries, ride those hops "
                "unencrypted and readable by anything on the path",
            )
        )
    return out


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

    # ADR 0118: the [security] section is the canonical home for the posture switches. Reject the legacy
    # keys in their old sections (file+env), then desugar [security] into the internal fields it replaces
    # — BEFORE the CLI merge, so a --host/--db override still wins over a [security] value.
    _reject_relocated_keys(data)
    _desugar_security(data)

    if cli:
        _merge(data, cli)

    return ServiceSettings.model_validate(data)
