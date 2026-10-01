# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

An unrecognized **key in the TOML file** is **refused** at load (:func:`_reject_unknown_file_keys`) — a
silently-dropped key leaves the setting it was meant to apply un-applied, with nothing anywhere
reporting a problem. An unknown top-level **section** is still tolerated.

The refusal is scoped to the **file** on purpose, and the scope is load-bearing rather than an
oversight: the **env** layer and the ``cli`` mapping still drop an unrecognized key silently. Env
cannot be checked the same way because roughly a dozen documented ``MEFOR_*`` variables are read
straight from ``os.environ`` by their consuming module and are not fields on any section
(``MEFOR_STORE_VAULT_ADDR``, ``MEFOR_TLS_REVOCATION_ATTESTED`` and siblings), so a field-membership
test would refuse a correctly-configured deployment. ``cli`` keys are engine-written from parsed
arguments, never operator-spelled; an operator's unknown flag never reaches them, because argparse
refuses it first with exit 2. The one
exception is ``[security]``, refused from env as well (the arm inside :func:`_desugar_security`).
Anything stated to an operator about this refusal must carry that scope — see
``docs/CONFIGURATION.md``.
"""

from __future__ import annotations

import difflib
import ipaddress
import logging
import os
import re
import string
import tomllib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from messagefoundry.api_tls_source import api_tls_source
from messagefoundry.childenv import outside_engine_namespace
from messagefoundry.config.ai_policy import (
    AiDataScope,
    AiMode,
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
from messagefoundry.config.retention_classification import PHI_RETENTION_WINDOWS
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
from messagefoundry.connection_names import is_connection_name
from messagefoundry.logging_setup import LOG_LEVELS
from messagefoundry.redaction import json_loads_or_refusal
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
    "LogWriteFailurePolicy",
    "LogFormat",
    "SyslogProtocol",
    "ReferenceSettings",
    "RetentionSettings",
    "AuthSettings",
    "AiSettings",
    "AiMode",
    "AiDataScope",
    "SecurityEnforcement",
    "EgressSettings",
    "ShadowSettings",
    "AlertsSettings",
    "SecretsSettings",
    "ClusterSettings",
    "ClusterVipSettings",
    "ApprovalsSettings",
    "IntegritySettings",
    "BackupSettings",
    "DrSettings",
    "DrActivationMode",
    "ServiceSettings",
    "load_settings",
    "settings_error_detail",
    "keyless_opt_out_refusal",
    "KEYLESS_REFUSED_BY_REQUIRE_ENCRYPTION",
    "KEYLESS_REFUSED_BY_NO_OPT_OUT",
    "KEYLESS_REFUSED_BY_NO_STRICT_ACK",
    "KEYLESS_REFUSED_BY_UNREAD_KEY",
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
    # ADR 0087 subprocess isolation. ABSENT UNTIL BACKLOG #1365, which made MEFOR_SANDBOX_MODE parse
    # to a section that did not exist and be DROPPED -- so an operator who set it by environment got
    # in-process execution and no warning, while the identical key in the config FILE worked. A
    # missing entry here does not fail; it disappears, which is why nothing caught it.
    "sandbox",
)
_ENV_PREFIX = "MEFOR_"
_DEFAULT_FILE = "messagefoundry.toml"

#: How many failing fields :func:`settings_error_detail` names before it counts the rest. A bad
#: section can fail every key in it, and an unbounded list is unreadable in a one-line CLI error.
_ERROR_DETAIL_ROWS = 5

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


class StorePrivilegeStatus(str, Enum):  # noqa: UP042
    """Whether the store principal's effective privileges were actually READ (#1008, ASVS 13.2.2).

    Three values, and the third is the point. ``OBSERVED`` with an empty excess list is a clean bill
    of health; ``UNOBSERVABLE`` is the ABSENCE of one. A two-valued version of this enum would let a
    probe that never ran report as a pass, which is the fail-open shape the preflight exists to close.
    """

    OBSERVED = "observed"  # the probe ran and read the principal's effective privileges
    NOT_APPLICABLE = "not_applicable"  # SQLite: a local file, no server principal exists to probe
    UNOBSERVABLE = "unobservable"  # the probe could NOT run — permission denied, no probe, an error


@dataclass(frozen=True, slots=True)
class StorePrivilegePosture:
    """The store-privilege preflight's finding in the plain data shape :func:`security_loosenings`
    consumes.

    A plain dataclass rather than the store package's richer report for the same reason the
    connection-scoped deviations arrive there as plain NAMES: ``config.settings`` must never import
    the store package (``store/*`` imports THIS module, so the reverse direction is a cycle)."""

    status: StorePrivilegeStatus
    #: What the principal holds beyond the documented least-privilege grant; empty when it holds
    #: nothing extra, and always empty when ``status`` is not ``OBSERVED``.
    excess: tuple[str, ...] = ()
    #: Why the probe could not observe (``UNOBSERVABLE``), or what it observed against (otherwise).
    detail: str = ""


class SchemaManagement(str, Enum):  # noqa: UP042
    """Who runs the store's schema DDL (BACKLOG #305, ASVS 13.2.2).

    ``AUTO``: the engine runs its own DDL batch at open, so its runtime principal needs standing DDL
    rights. ``EXTERNAL``: a separate provisioning step (``messagefoundry store provision-schema``, run
    by a DDL-capable principal) owns the DDL, and open only READS the ``schema_meta`` marker and
    refuses on a mismatch. The runtime principal then needs row access only."""

    AUTO = "auto"
    EXTERNAL = "external"


class SqliteSync(str, Enum):  # noqa: UP042
    NORMAL = "normal"  # crash-safe under WAL, no per-commit fsync (default)
    FULL = "full"


class SqlAuth(str, Enum):  # noqa: UP042
    SQL = "sql"  # SQL login (username + password)
    INTEGRATED = "integrated"  # Windows Integrated auth
    ENTRA = "entra"  # Microsoft Entra ID (Azure AD)


def refuse_a_blank_anchor_pin(value: str | None, setting: str) -> str | None:
    """Refuse a trust-anchor SHA-256 pin that is set but blank (BACKLOG #1142).

    ``None`` is the only spelling of "no pin". An empty or whitespace value, such as an environment
    variable set to nothing, used to reach the anchor code as a pin and refuse there or, on a
    connection, read as no pin at all. A blank pin is a mistake, so it refuses at load, naming the
    setting. Shared with the per-connection ``tls_ca_pin`` check in ``auth/trust_anchors.py``."""
    if value is not None and not value.strip():
        raise ValueError(
            f"{setting} is set but empty, so it pins nothing. Remove it for no pin, or set it to "
            "the SHA-256 of the CA file (64 hex characters)"
        )
    return value


def _refuse_a_missing_crl_file(value: str | None, setting: str) -> str | None:
    """Refuse a CRL path that names no file, at load, naming ``setting`` (BACKLOG #1997).

    ``harden_crl_check`` would catch it when the hop's context is built, but its refusals hard-code
    the prefix ``[tls] crl file`` for every call site, so a bad path on any other CRL knob would be
    reported against the wrong config section. A path, not a secret.

    A blank value is refused too, as ``refuse_a_blank_anchor_pin`` refuses a blank pin. ``None`` is
    the only spelling of "no CRL": some consumers test ``is not None`` and would hand ``""`` to
    ``harden_crl_check``, while others test truthiness and would silently read it as unset."""
    if value is not None and not value.strip():
        raise ValueError(f"{setting} is set but empty. Remove it for no CRL, or name a CRL file")
    if value is not None and not Path(value).is_file():
        raise ValueError(f"{setting} path does not exist or is not a file: {value!r}")
    return value


class _Section(BaseModel):
    # extra="ignore" stays on the MODEL; unknown keys are refused by the LOADER instead
    # (_reject_unknown_file_keys). A model-level extra="forbid" would refuse the engine's OWN writes:
    # _env_overrides scrapes every MEFOR_<section>_<key> into its section dict, and a dozen documented
    # variables are read straight from os.environ by their consuming module rather than being fields here
    # (the Vault KMS/Transit and secret-provider credentials, MEFOR_TLS_REVOCATION_ATTESTED, the two
    # phase-timing levers) — a Vault-backed store configured exactly as the shipped docs instruct would
    # fail to start. Two further reasons the model is the wrong surface: pydantic's extra_forbidden error
    # echoes the offending VALUE and the CLI prints the exception verbatim to a log file, so a mistyped
    # SECRET key would disclose the secret; and `security show` validates SecuritySettings directly, so a
    # forbidding model would deny an operator the very view they use to repair the typo.
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


def weakened_tls_escape_permitted(posture: HopPosture | None) -> bool:
    """Whether ``MEFOR_ALLOW_INSECURE_TLS`` may permit a weakened / verify-off TLS hop under ``posture``,
    CLAMPED so an enforcing PHI hop is NEVER relaxed (#200, ADR 0092 decision 2).

    The **weakened-TLS / cleartext-escape** cells route their global-escape check through
    here so the blunt escape can no longer silence an **enforcing** refusal (matching the
    ``--allow-insecure-bind`` API-bind clamp). That is **at least** the engine<->store TLS gate
    (:func:`~messagefoundry.store.sqlserver.connection_string` / ``store.postgres._build_ssl``), the MLLP
    and FTPS ``tls_verify=false`` contexts and the credentialed plain-``ftp`` guard, **and — since #329 —**
    the LDAPS ``ad_tls_verify=false`` bind (:mod:`messagefoundry.auth.ldap`), the SFTP unknown-host-key
    acceptance (:mod:`messagefoundry.transports.remotefile`), and the webhook-alert-sink and AI-broker
    cleartext-``http`` hops. Pass the construction-time
    :func:`~messagefoundry.config.tls_policy.current_hop_posture` (in-gate transport cells, via
    :func:`weakened_tls_escape_permitted_here`) or an explicitly-threaded posture (the store hop and the
    out-of-gate #329 cells, whose construction never stamps the contextvar). Semantics: the escape must
    be set, AND a posture must be known, AND it must not be enforcing.

    **``None`` FAILS CLOSED (vault BACKLOG #2354).** No posture means the escape is NOT permitted.
    CORRECTED: this read *"``None`` (a backup utility / embedding / test outside the construction gate)
    falls back to the **unclamped** escape -- byte-identical to pre-#200 -- since the enforced
    serve/reload gate already vetted the real production posture"*. That premise was false for every
    caller the gate never reaches: a reference sync, and every CLI command that opens the store. Each
    let the escape cross a weakened hop under ``enforce``. A caller that needs the escape on a
    ``warn`` instance passes that posture explicitly; there is no other way to say "not enforcing".

    The clamp used to require an enforcing **PHI** hop. Every instance carries patient data now
    (BACKLOG #1279), so the second conjunct could not vary and is gone: under ``enforce`` the blunt
    escape is inert, full stop."""
    return insecure_tls_allowed() and posture is not None and not posture.enforcing


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
    installer does — see docs/SERVICE.md), so the permission arms do not trip. A Windows read that
    cannot finish still refuses (ADR 0036 Amendment B); fix the read rather than set this. This escape
    downgrades the refusal to a
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
            "(dbo.mefor_claim_fifo_heads_cid_v2/_dst_v2; fixed-arity CALL) instead of the ~3KB ad-hoc "
            "batch. Fails safe to the batch (loud) whenever the startup gate cannot verify both "
            "deployed bodies against this build — at least: a missing proc, a body matching no form "
            "this build deploys, a definition this principal cannot read (no VIEW DEFINITION, or "
            "WITH ENCRYPTION), or compat < 130. SQL Server only; OFF = byte-identical."
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
    # When true, `serve` refuses to start without an encryption key even when the audited opt-out
    # below is set. Off by default. See docs/PHI.md §3.
    require_encryption: bool = False
    # Explicit, audited opt-out of the keyless-start refusal (H3, OWASP *Fail Securely* / SDS §4.3
    # PW.9). Every instance carries patient data (BACKLOG #1279), so by default EVERY instance, in
    # ANY environment, REFUSES to start with no encryption key — secure-by-default. Setting this true
    # is the loud, deliberate override that lets one start keyless (it still emits the
    # UNENCRYPTED-at-rest warning and the override is audited at startup). It does NOT override
    # `require_encryption=true` (that wins). Under [security].enforcement = enforce it needs a SECOND
    # acknowledgment, `allow_unencrypted_phi_under_strict_enforcement` (ADR 0140).
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
    # mfenc:v4 writer (v2 before ADR 0196) with cell-bound AAD (it sets the cipher's `write_v2`), so a
    # ciphertext cut-and-pasted
    # into another cell fails the auth tag (dead-lettered, not silently accepted). Legacy v1 rows still
    # decrypt (dual-read) and `messagefoundry rotate-key` upgrades them v1 to v4, so the flip is safe on an
    # existing store and reversible. No effect without an encryption key (the identity cipher has nothing
    # to bind). Setting it false selects the frozen mfenc:v1 writer (byte-identical at rest, CRYPTO-1) and
    # is a LOOSENING — `security_loosenings()` names it, so the opt-out is never silent.
    aad_bind: bool = True
    # Accept an UNMARKED value in a cipher-covered column of a KEYED store (BACKLOG #1169, ASVS 11.3.3).
    # **Off by default**: a keyed store writes only `mfenc:` ciphertext there, and the at-open sweep
    # seals legacy plaintext only on a (table, column) surface that holds no ciphertext yet, so a
    # non-blank unmarked value beside sealed ones is a stripped marker or a planted row -- the cipher
    # REFUSES it (`CipherError`, an `integrity_drift` alert with subject `store-cipher`) instead of
    # returning it as plaintext. A purged '' is never refused. Setting it true restores the old
    # behaviour: unmarked values read back as plaintext and the sweep seals every unmarked value. It is
    # a LOOSENING -- `security_loosenings()` names it. No effect without an encryption key. It also
    # restores the passthrough for a plaintext UPLOADED FILE, which a keyed store otherwise refuses
    # until `rotate-key` seals it, alerting under `upload-cipher` (owner ruling 2026-09-23).
    allow_unmarked_ciphertext: bool = False
    # KeyProvider seam (ADR 0019, ASVS 13.3.3): selects HOW the active/retired DEK bytes are *sourced* —
    # never how they are used (the cipher, keyring, and `mfenc:v1` format are unchanged). `auto` (the
    # default) is the env-then-DPAPI ladder, BYTE-IDENTICAL to the pre-seam behavior; `env`/`dpapi` pin a
    # single built-in source; `aws_kms`|`azure_kv`|`gcp_kms`|`vault`|`pkcs11` are external HSM/KMS/Vault
    # envelope-decrypt providers (lazy, optional extras; `vault` ships in store/keyprovider_vault.py, the
    # rest are not built yet and fail closed if selected). Every external provider counts as a
    # configured key for the keyless at-rest gate, before it resolves (BACKLOG #1998). This
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
    # task, each prune audited `upload.prune`). Quotas are enforced per-`uploads_dir`, NOT per-process:
    # the check reads the sidecars off disk with no cache, so engine shards sharing one dir see each
    # other's files and the budget does NOT multiply (measured 2026-08-10 — two UploadStores over one
    # dir, the second refused the same uploader at quota, against a live positive control). The
    # check-then-write race that used to survive across them — an overshoot of one file per shard
    # caught between its scan and its write — is closed by an atomic reservation on the unified store
    # every shard shares (ASVS 2.3.4, BACKLOG #1112); the surviving residuals are stated once in
    # `uploads.UploadQuotaError`. Shards given SEPARATE dirs get separate budgets, by construction.
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
    # Least-PRIVILEGE precondition on the store principal (#1008, ASVS 13.2.2) — the privilege sibling
    # of require_managed_identity above, which constrains the credential's KIND and never what it may
    # do (a `sysadmin` gMSA satisfies that one clean). The serve-time probe
    # (store/privilege.py) reads the principal's EFFECTIVE fixed-server-role / database-role membership
    # on SQL Server and its role attributes / grants on Postgres, and compares them against the grant
    # docs/DEPLOY-SERVER-DB.md §1.1/§1.2 prescribes.
    #
    # The probe always runs, logs, audits and feeds security_loosenings(). Since ADR 0199 (owner ruling
    # 2026-09-27) an OBSERVED over-grant REFUSES under [security].enforcement = enforce with this left
    # FALSE; the audited escape is [security].allow_over_granted_store_principal. An UNOBSERVABLE probe
    # only warns by default. Setting this TRUE is the stricter declaration: it also refuses on a probe
    # that could NOT RUN, because a declared refusal that passes an unobservable principal is exactly
    # the fail-open shape the operator turned it on to prevent, and it outranks the opt-out. The split
    # reads [security].enforcement, NOT the deployment tier, so enforcement='warn' downgrades every
    # refusal here to a warning. SQLite is exempt (a local file has no server principal to probe).
    require_least_privilege: bool = False
    # Who runs the schema DDL (#305, ASVS 13.2.2); see SchemaManagement. None resolves per backend in
    # resolved_schema_management(): EXTERNAL on SQL Server and Postgres, AUTO on SQLite. External is
    # the server-DB default because it is the only mode in which the runtime principal can run without
    # DDL rights; `auto` keeps the engine building and upgrading its own schema at open. Under
    # external, a fresh database or a build whose schema moved REFUSES to open until a DBA runs
    # `messagefoundry store provision-schema`. SQLite has no principal to split, so it is always auto
    # and an explicit `external` there is refused at load (see _schema_management_backend).
    schema_management: SchemaManagement | None = None
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
    # BACKLOG #299: optional PEM file of CRLs checked against the DB SERVER's certificate.
    # The store hop builds its own context and resolves no trust anchor, so [tls].crl_file never reaches
    # it -- this is its own knob rather than a silent inheritance, the per-hop scoping error that item
    # warns about. POSTGRES ONLY, on a verifying posture: the engine builds the SSLContext asyncpg uses
    # on both verifying branches, the pinned CA (`ssl_root_cert`) and, since BACKLOG #300, the system
    # trust store, so a CRL loads on either. It used to require `ssl_root_cert`, because the default
    # path returned `True` and asyncpg built the context. SQL Server never sees this (it rides an ODBC
    # keyword string, not a context). Same fail-closed refusals as every other CRL: absent, unloadable
    # or past nextUpdate refuses at store open rather than at the first DB handshake.
    ssl_crl_file: str | None = None
    # SQL SERVER ONLY: emit the ODBC `MultiSubnetFailover=Yes` keyword so a client connecting to an
    # Always On Availability Group *listener* reaches the current PRIMARY promptly across subnets,
    # instead of serially waiting out each replica subnet's DNS/TCP timeout on failover. A no-op for
    # Postgres/SQLite (they never see the ODBC string). Default off — only multi-subnet AOAG needs it.
    multi_subnet_failover: bool = False
    pool_size: int = 40
    connect_timeout: int = 15  # seconds
    command_timeout: int = 30  # seconds
    # Upper bound (seconds) on ONE pooled-connection borrow from the server-DB store pool, and on the
    # throwaway pool a DatabaseRef reference sync opens (BACKLOG #1052, ASVS 13.2.6). Server-DB only —
    # SQLite has no pool. `connect_timeout` bounds the LOGIN and `command_timeout` the STATEMENT;
    # neither bounds the WAIT for a free pooled connection, which was unbounded, so a pool-exhausted or
    # unresponsive database could block an acquiring task forever with the queue backing up behind it.
    # At the limit the borrow raises `StoreAcquireTimeout`, which every store caller already handles as
    # a transient stage failure (retry / dead-letter) — see docs/CONNECTIONS.md "Behaviour at the
    # store-pool acquire limit". 30 s matches the connector tier's per-connection `acquire_timeout` and
    # sits far above a healthy wait; watch p95/p99 in the pool_status acquire-wait histogram before
    # lowering it. Must be > 0: the point of the knob is that the wait is always bounded.
    acquire_timeout: float = 30.0
    # POSTGRES ONLY, refused on the other backends (see _db_schema_backend). 'db_schema' avoids
    # shadowing BaseModel.schema; env: MEFOR_STORE_DB_SCHEMA.
    db_schema: str | None = None
    application_name: str = "messagefoundry"
    # Inflight-row lease TTL (seconds) for the multi-node server-DB backends (Track B Step 2). When a
    # worker claims a row it stamps owner + a lease_expires_at = now + this, and a leader sweep reclaims
    # only rows whose lease has expired (so a crashed node's work is recovered without stealing a live
    # sibling's in-flight rows). A shared server-DB field — harmless to SQL Server / SQLite, which don't
    # lease and ignore it. The lease is wall-clock across nodes, so the no-theft guarantee assumes clocks
    # are NTP-synced to well within this TTL.
    #
    # THE ROW LEASE IS STAMPED ONCE AT CLAIM AND IS NEVER RENEWED — there is no renew timer anywhere in
    # the store (earlier text here and in the sweep's own docstrings claimed one; it did not exist).
    # So size this against the longest a single row can legitimately stay claimed, not against a renew
    # interval: it must comfortably exceed the connector's timeout_seconds + any pacing + batch-gather,
    # plus expected clock skew. Set it too low and the leader's own sweep re-pends rows it is still
    # processing — the sweep is owner-blind, so "a crashed node's rows" includes this node's own.

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

    @field_validator("acquire_timeout")
    @classmethod
    def _positive_acquire_timeout(cls, value: float) -> float:
        # No "0 disables" escape hatch, unlike command_timeout: an unbounded pool wait is the defect
        # this setting exists to remove, so there is deliberately no way to configure it back.
        if value <= 0:
            raise ValueError("acquire_timeout must be > 0 (the pool wait is always bounded)")
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

    @field_validator("ssl_crl_file")
    @classmethod
    def _ssl_crl_file_exists(cls, value: str | None) -> str | None:
        """Fail loud at load if the CRL path is missing or blank (#299); why is on the helper."""
        return _refuse_a_missing_crl_file(value, "[store].ssl_crl_file")

    @model_validator(mode="after")
    def _ssl_crl_file_reachable(self) -> StoreSettings:
        """``ssl_crl_file`` only reaches a handshake on a VERIFYING POSTGRES hop, so refuse the
        configurations where it would be a silent no-op (#299).

        Refuse rather than ignore, exactly as ``_ssl_root_cert_backend`` does — and the stakes are
        higher here, because this is the setting that crosses the #201 revocation refusal. An
        operator who sets it and gets nothing believes revocation checking is on when it is not, and
        a security control that silently does nothing is worse than an absent one.

        * On SQL SERVER or SQLITE: neither ever sees an ``SSLContext`` — SQL Server pins via an ODBC
          keyword string and SQLite uses no TLS — so no CRL can be loaded on either.
        * With ``encrypt=false`` or ``trust_server_certificate=true``: ``_build_ssl`` returns no
          context or a verify-off one, and a CRL means nothing on a hop that verifies no certificate.

        Before BACKLOG #300 this also refused ``ssl_crl_file`` without ``ssl_root_cert``, because the
        default path returned ``True`` and asyncpg built the context. The engine builds that context
        now, so the CRL loads on the system-trust path too."""
        if not self.ssl_crl_file:
            return self
        if self.backend is not StoreBackend.POSTGRES:
            raise ValueError(
                "[store].ssl_crl_file requires the postgres backend; SQL Server pins its certificate "
                "through an ODBC keyword and SQLite uses no TLS, so neither can load a CRL."
            )
        if not self.encrypt or self.trust_server_certificate:
            raise ValueError(
                "[store].ssl_crl_file requires a verifying store hop (encrypt=true and "
                "trust_server_certificate=false); with verification off the hop checks no "
                "certificate, so revocation would NOT be checked."
            )
        return self

    @model_validator(mode="after")
    def _db_schema_backend(self) -> StoreSettings:
        """``db_schema`` is honoured only by Postgres, which points the pool's ``search_path`` at it.

        The SQL Server store never reads it: it creates and queries every table unqualified, so the
        names resolve against the login's default schema. Two installs on one database would share
        the queue and the cluster election while believing they were isolated. The SQL Server
        coordinator used to namespace its lease key by this setting, which would have elected one
        leader per install over that one shared queue; its keys are now constant. SQLite has no
        schemas. Refuse rather than ignore, as ``_ssl_root_cert_backend`` does. An empty string stays
        accepted, because both Postgres readers treat it as unset."""
        if self.db_schema and self.backend is not StoreBackend.POSTGRES:
            raise ValueError(
                "[store].db_schema is honoured only by the postgres backend, not "
                f"{self.backend.value!r}, whose store never reads it. "
                "Give each install its own database."
            )
        return self

    @model_validator(mode="after")
    def _schema_management_backend(self) -> StoreSettings:
        """An explicit ``external`` on SQLite is refused rather than ignored. The file store has no
        server principal to split, so it always builds its own schema; accepting the setting would let
        an operator believe the runtime cannot run DDL when it can."""
        if (
            self.schema_management is SchemaManagement.EXTERNAL
            and self.backend is StoreBackend.SQLITE
        ):
            raise ValueError(
                "[store].schema_management = 'external' applies to the sqlserver and postgres "
                "backends only; the sqlite store always builds its own schema at open"
            )
        return self

    def resolved_schema_management(self) -> SchemaManagement:
        """The mode this store actually runs in (#305): the explicit setting on a server backend,
        else EXTERNAL there, and always AUTO on SQLite."""
        if self.backend is StoreBackend.SQLITE:
            return SchemaManagement.AUTO
        return self.schema_management or SchemaManagement.EXTERNAL


#: The hosts that count as a loopback bind for the OPERATOR API, i.e. not exposed off-box. Both IPv4 and
#: IPv6 loopback are listed so a dual-stack box never spuriously counts as exposed.
#:
#: Defined here rather than beside its ADR 0118 use because at least two security decisions in this
#: module key on it and must not disagree: :attr:`ApiSettings.is_loopback`, which used to inline the
#: same three hosts as a tuple, and ``_desugar_security``'s refusal of a non-loopback ``listen_address``
#: under ``local_access_only = true``. This unifies THIS module only. Other packages carry same-named
#: frozensets for their own transports, with different contents (``::ffff:127.0.0.1`` in
#: ``pipeline.wiring_runner`` and ``transports.dicom``, ``[::1]`` in the harness poller); reconciling
#: those is a separate question, recorded in ADR 0154.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: A cert-map name ``credential.cert_name_candidates`` can actually yield: ``CN:<value>`` or
#: ``SAN:<type>:<value>``, each part non-empty. Anything else loads and then never matches (#2237).
_QUALIFIED_CERT_NAME = re.compile(r"CN:.+|SAN:[^:]+:.+", re.DOTALL)
#: A users-row id as ``AuthService`` mints it (``uuid4().hex``). The cert map targets this, never a
#: username, because a rename can hand a username to another row (#2238).
_USER_ID = re.compile(r"[0-9a-f]{32}")


def request_host_is_browser_origin(
    *, loopback: bool, trusted_proxies: Sequence[str], tls_terminated_upstream: bool
) -> bool:
    """Whether config says the request ``Host`` is the origin the browser itself used: a loopback
    bind with no proxy declared or trusted. Only then may the web console fall back to that Host
    when no external origin is set, for the WebAuthn rp_id (ADR 0068 section 7) and for the /ui
    same-origin checks (BACKLOG #2217). Behind a proxy the forwarded Host is client-controllable.

    Both proxy fields are read. For a loaded ``ApiSettings`` the terminator term is redundant, because
    the validator makes a declared terminator imply ``trusted_proxies``. An app factory's caller is
    not validated, so there it keeps the answer closed (BACKLOG #2219). A proxy named nowhere in
    config cannot be detected here."""
    return loopback and not trusted_proxies and not tls_terminated_upstream


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
    # The browser-facing external origin of the /ui dashboard when it is reached OFF-loopback through a
    # reverse proxy that does NOT preserve the Host header (ADR 0065). The same-origin CSRF + CSWSH checks
    # normally compare the browser's Origin to the request Host; behind such a proxy the Host is the
    # internal one, so set this to the exact public origin (e.g. "https://ops.example.com") and the checks
    # validate against it instead. Empty (default) = loopback / Host-preserving-proxy behavior, unchanged.
    public_origin: str | None = None
    # Extra directories /config/reload may load from, besides the startup --config dir. The loader
    # EXECUTES Python from these, so list only admin-owned, trusted roots (e.g. an IDE staging dir).
    config_reload_roots: list[str] = []

    # Browser Origins allowed on the native (Authorization-header) path of the /ws/stats WebSocket
    # (ASVS 4.4.2). The shipped client is the browser web console. When the console is mounted, its
    # same-origin handshake is tried first with the session cookie through the console's own hook,
    # which checks the Origin itself and does not read this list; a handshake that hook declines
    # comes to the header path. A native client sends NO Origin header, so the secure default
    # is empty: a request on the header path that carries an Origin (i.e. a browser) is rejected
    # unless its Origin is listed here.
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
    # Optional OpenSSL cipher string (default = the approved AEAD suites, BACKLOG #300).
    tls_ciphers: str | None = None
    # Optional CA bundle to verify CLIENT certs (in-process mTLS; opt-in, requires tls_cert_file).
    # Set, the API requires every client to present a certificate this CA verifies. It is a trust
    # anchor. api/tls.py checks it when it builds the listener at start and loads the bytes that
    # check read. auth/trust_anchors.py re-checks the file, audited, at start and at every real (not
    # dry-run) reload, but the listener keeps the CA it loaded at start.
    tls_client_ca_file: str | None = None
    #: Opt-in CRL for the mTLS client certificates `tls_client_ca_file` verifies (BACKLOG #1005).
    #: A PEM file holding the client CA's CRL. Put the CA itself in `tls_client_ca_file`, where the
    #: #285 pin covers it: a certificate in this file the store lacks refuses start (BACKLOG #1890).
    #: Absent, client certificates are verified for chain and RFC 5280 conformance but NOT for
    #: revocation -- measured, a revoked-but-chain-valid client is ACCEPTED. Set it and a revoked
    #: partner certificate is refused at the handshake.
    #:
    #: **An expired CRL refuses EVERY client, not only revoked ones**, so this is read at startup
    #: and refused loudly there rather than at the first partner handshake. See
    #: :func:`~messagefoundry.config.tls_policy.harden_crl_check`.
    tls_client_crl_file: str | None = None
    # WP #285 (ASVS 6.7.1): optional SHA-256 pin over the mTLS client-CA trust anchor above. Set to the
    # lowercase-hex SHA-256 of the PEM file's bytes; the loaded anchor's fingerprint is checked against
    # it at construction AND at reload and a mismatch REFUSES to start — always, independent of
    # [security].enforcement (a substituted client-CA would admit a forged peer cert). Block-scoped
    # (direct-read by api/tls.py + the trust-anchor preflight, NOT desugared through [security]). None
    # (default) = no pin, dormant.
    tls_client_ca_pin: str | None = None
    # mTLS client-cert → MessageFoundry principal map (#200, ADR 0002, ADR 0083). Meaningful only with
    # in-process mTLS (tls_client_ca_file set, so the server verifies the client). A VERIFIED peer cert is
    # resolved through this ALLOW-LIST to an existing account, whose RBAC authorizes the request (a
    # service-to-service identity that carries no bearer token).
    #
    # NESTED BY ISSUER (BACKLOG #2237): the outer key is the RFC 4514 subject DN of the LOADED client CA
    # that directly issued the leaf, found by signature (pki.IssuerIndex, read by the
    # api/tls_client_cert shim), never from the leaf's own issuer field alone. The inner keys are the
    # QUALIFIED cert names "CN:<commonName>" or "SAN:<type>:<value>". A subject maps only under the CA
    # named for it, so a second CA in tls_client_ca_file issuing the same subject reaches nothing. In
    # TOML:
    #     [api.tls_client_cert_identities.'CN=Acme Service CA,O=Acme,C=US']
    #     "CN:svc.internal" = "<the account's 32-hex id>"
    # VALUES ARE ACCOUNT IDS (BACKLOG #2238): the users-row id (the "id" field of GET /users), never a
    # username. A rename can hand a username to another row; the id never moves.
    # The loader refuses a flat (issuer-less) entry, an empty or non-canonical issuer, an issuer with no
    # names, a name no certificate can carry, and a value that is not a 32-hex account id.
    #
    # DENY-BY-DEFAULT: an unmapped verified cert, a spoofed CN, a listed subject from an unlisted,
    # unloaded or ambiguous CA, or an unknown or disabled account resolves to no identity and is
    # denied. Structured map → TOML-only (no env-string form). An empty map (default) disables
    # cert-identity.
    tls_client_cert_identities: dict[str, dict[str, str]] = {}
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
    # The operator's acknowledgement that, with tls_terminated_upstream and no tls_cert_file, the
    # proxy-to-engine hop is PLAINTEXT by design (ADR 0172 decision 3): the engine mints no
    # certificate there, so encrypting or isolating that hop is the DEPLOYING SITE's job. `serve`
    # refuses to start that topology without it, in every mode -- enforcing or warn, loopback or
    # not -- because only the operator can take on a hop the engine does not protect. With an
    # operator tls_cert_file the engine serves that hop over TLS, so it is not required there (and
    # harmless if set). It records who took the hop on; it secures nothing. Meaningful only with
    # tls_terminated_upstream, so setting it without that is refused at load (a stray
    # acknowledgement would read as a decision about a hop that does not exist). Default False.
    plaintext_upstream_hop_acknowledged: bool = False

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
        TLS gate and the MFA-at-exposure advisory (``serve``) don't apply. The host set is
        :data:`_LOOPBACK_HOSTS`, shared with the ``[security]`` desugar so one definition serves every
        off-box decision."""
        return self.host in _LOOPBACK_HOSTS

    @property
    def host_is_browser_origin(self) -> bool:
        """:func:`request_host_is_browser_origin` for this config. False means the browser reaches the
        engine off-box or through a proxy, which is also what ``serve``'s console exposure checks
        test (BACKLOG #2218)."""
        return request_host_is_browser_origin(
            loopback=self.is_loopback,
            trusted_proxies=self.trusted_proxies,
            tls_terminated_upstream=self.tls_terminated_upstream,
        )

    @property
    def webauthn_rp_from_request(self) -> bool:
        """Whether a WebAuthn ceremony may take its rp_id from the request URL when no external origin
        is set (ADR 0068 section 7). The app factories derive the same answer from the same rule
        (BACKLOG #2219)."""
        return self.host_is_browser_origin

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

    @property
    def serves_plaintext_upstream_hop(self) -> bool:
        """Whether the engine serves the proxy-to-engine hop in PLAINTEXT (BACKLOG #1179): a declared
        upstream terminator and no operator certificate, in :func:`api_tls_source`'s order. The one
        definition the serve refusal, its AUDIT line, the ``upstream-hop-ack`` check leg and
        ``security_loosenings()`` share, so none of them can decide the question differently."""
        return (
            api_tls_source(
                cert_file=self.tls_cert_file, tls_terminated_upstream=self.tls_terminated_upstream
            )
            == "upstream"
        )

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
                "[security].web_console_public_address must be a bare origin like "
                "'https://ops.example.com' (scheme + host, no path/query/fragment)"
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

    @field_validator("tls_client_cert_identities", mode="before")
    @classmethod
    def _cert_identities_name_an_issuer(cls, v: Any) -> Any:
        """Refuse the flat, issuer-less shape with its own message (#2237). Runs BEFORE coercion, so
        the operator reads this rather than pydantic's generic "should be a valid dictionary"."""
        if isinstance(v, Mapping):
            for issuer, names in v.items():
                if not isinstance(names, Mapping):
                    raise ValueError(
                        f"[api].tls_client_cert_identities entry {issuer!r} names no issuer: every "
                        "entry must sit under the DN of the CA that issues it, e.g. "
                        "[api.tls_client_cert_identities.'CN=svc-ca,O=acme,C=US'] then "
                        '"CN:svc.internal" = ... (BACKLOG #2237)'
                    )
        return v

    @field_validator("tls_client_cert_identities")
    @classmethod
    def _cert_identities_can_match(cls, v: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
        """Refuse an entry that would silently match nothing (#2237)."""
        # Lazy: pki pulls in cryptography, which a config with no cert map never needs.
        from messagefoundry.pki import canonical_dn

        field = "[api].tls_client_cert_identities"
        for issuer, names in v.items():
            canonical = canonical_dn(issuer)
            if canonical is None:
                raise ValueError(
                    f"{field} issuer {issuer!r} is not an RFC 4514 distinguished name "
                    "(attr=value,...); name the issuing CA's DN"
                )
            if canonical != issuer:
                # Shown as a TOML literal (single-quoted) key, which keeps its backslashes as written.
                raise ValueError(
                    f"{field} issuer {issuer!r} is not in the canonical form the engine compares, "
                    f"so it would never match; write it as the key '{canonical}'"
                )
            if not names:
                raise ValueError(f"{field} issuer {issuer!r} maps no certificate names")
            for name, target in names.items():
                if not _QUALIFIED_CERT_NAME.fullmatch(name):
                    raise ValueError(
                        f"{field} name {name!r} under {issuer!r} is not qualified: write "
                        '"CN:<commonName>" or "SAN:<type>:<value>" (e.g. "SAN:DNS:svc.internal")'
                    )
                if not _USER_ID.fullmatch(target):
                    raise ValueError(
                        f"{field} name {name!r} under {issuer!r} maps to {target!r}, which is not "
                        "an account id: the value is the account's id (32 lowercase hex characters, "
                        "the 'id' field of GET /users), not its username, which a rename can hand to "
                        "another account (BACKLOG #2238)"
                    )
        return v

    @field_validator("tls_client_ca_pin")
    @classmethod
    def _refuse_a_blank_client_ca_pin(cls, v: str | None) -> str | None:
        return refuse_a_blank_anchor_pin(v, "[api].tls_client_ca_pin")

    @field_validator("tls_client_crl_file")
    @classmethod
    def _tls_client_crl_file_exists(cls, v: str | None) -> str | None:
        return _refuse_a_missing_crl_file(v, "[api].tls_client_crl_file")

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
        # The reverse direction (BACKLOG #2055, ASVS 3.3.1 and 3.3.3). uvicorn rewrites the request
        # scheme from a trusted peer's X-Forwarded-Proto, so a proxy that says "http" would turn the
        # session cookie's Secure flag off on the minted-placeholder bind. So a trusted forwarded
        # scheme requires exposure_protected, which forces Secure whatever that scheme says. An
        # operator certificate earns it, so a proxy re-encrypting to one is not refused. Not keyed
        # on the minted pair: header_floor.served_chain_is_self_signed reads a false
        # exposure_protected over https as "the placeholder" and keeps HSTS off it.
        if self.trusted_proxies and not self.exposure_protected:
            raise ValueError(
                "[api].trusted_proxies requires [api].tls_terminated_upstream = true, or an "
                "operator [api].tls_cert_file if the proxy re-encrypts to the engine. Without "
                "either, a proxy forwarding X-Forwarded-Proto 'http' makes the web console issue "
                "its session cookie without Secure (BACKLOG #2055). A declared terminator is an "
                "exposed posture: see docs/CONFIGURATION.md for what serve then requires."
            )
        # Refuse rather than ignore a stray acknowledgement, as ad_session_recheck_seconds without
        # ad_enabled is refused: an operator who set it believes a proxy-to-engine hop exists and
        # was considered, and without tls_terminated_upstream there is no such hop.
        if self.plaintext_upstream_hop_acknowledged and not self.tls_terminated_upstream:
            raise ValueError(
                "[api].plaintext_upstream_hop_acknowledged requires [api].tls_terminated_upstream "
                "(it acknowledges the plaintext proxy-to-engine hop that only that topology has)"
            )
        # Validate the DECLARED Posture-B proxy TLS floor for internal coherence (#200, ASVS 11.6.2) —
        # an attestation, but a *coherent* one (a NIST version floor; forward-secret ciphers if named).
        validate_proxy_tls_posture(self.proxy_tls_min_version, self.proxy_tls_ciphers)
        # ASVS 3.4.1 — an IP-literal public_origin under a declared TLS posture makes HSTS INERT.
        # RFC 6797 §8.1.1: a UA "MUST NOT note" an IP-literal host as a Known HSTS Host, so the
        # Strict-Transport-Security header the engine emits for such an origin is required to be
        # DISCARDED by every conforming browser. The control would report success while doing nothing —
        # the exact shape this codebase keeps finding and refusing to ship.
        #
        # Checked HERE rather than in the public_origin field validator because the field alone cannot
        # see the posture: a bare http:// loopback origin with no TLS declared is a legitimate dev
        # flow, and only the model knows whether a TLS posture is in play.
        if self.public_origin and (self.tls_terminated_upstream or self.tls_enabled):
            host = urlsplit(self.public_origin).hostname or ""
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass  # a DNS name — HSTS is notable, nothing to refuse
            else:
                raise ValueError(
                    f"[security].web_console_public_address {self.public_origin!r} is an IP literal "
                    "while a TLS posture is declared. RFC 6797 §8.1.1 forbids a browser from noting "
                    "an IP-literal host as "
                    "an HSTS host, so the Strict-Transport-Security header would be silently "
                    "discarded and the console would have no HTTPS-downgrade protection (ASVS 3.4.1). "
                    "Use a DNS hostname for the console — a dedicated subdomain, since "
                    "includeSubDomains on a hospital apex forces https on every sibling host."
                )
        return self


class TlsSettings(_Section):
    """``[tls]`` — the instance-wide client **trust-anchor and revocation** policy (#190, ADR 0093).

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
    # PEM path to a file of CRLs for OUTBOUND hops (BACKLOG #299). NOT a secret — a path,
    # the same status as internal_ca_file. Empty (default) = no outbound revocation checking, which is
    # exactly the gap the #201 RevocationHopGuard refuses on an enforcing hop. Set it and every hop that
    # resolves a trust anchor loads the CRL onto its OWN context and sets VERIFY_CRL_CHECK_LEAF.
    #
    # WARNING, and it is the operational half of this setting: VERIFY_CRL_CHECK_LEAF refuses a peer whose
    # issuer has NO CRL in the store, not only a revoked one. So the file must cover every issuer the
    # covered hops present, and it must be refreshed before its nextUpdate. Both failures are
    # fail-CLOSED (the handshake is refused, nothing crosses unverified), and harden_crl_check refuses an
    # already-expired or unloadable CRL at construction rather than at the first partner handshake.
    # LOOPBACK HOPS ARE EXEMPT for that reason -- an on-box peer is usually issued by a different,
    # local PKI the org CRL does not cover, and the revocation guard already ALLOWs a loopback hop, so
    # applying a CRL there would break on-box traffic to close a gap the gate does not consider open.
    crl_file: str | None = None

    @field_validator("crl_file")
    @classmethod
    def _crl_file_exists(cls, v: str | None) -> str | None:
        # Only the first hop to resolve a trust anchor would otherwise stat this path, so a typo
        # would surface at that hop's construction rather than at load.
        return _refuse_a_missing_crl_file(v, "[tls].crl_file")

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
            internal_ca_file=self.internal_ca_file,
            mode=self.trust_anchor_mode,
            crl_file=self.crl_file,
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

    # Very-large-document streaming in-flight budget (#149, ADR 0105 Phase 1a) — the OPT-IN aggregate DoS
    # guard for streaming inbounds. It caps the TOTAL bytes of over-threshold message bodies concurrently
    # mid-detach (buffered + being sealed into the attachment substrate) across ALL inbounds; a detach
    # that would push the running total over it is refused with backpressure (the message is
    # NAK'd/ERROR'd, never accepted-and-dropped) so a burst of huge uploads can't exhaust memory. Only
    # over-threshold streaming detaches count against it — below-threshold and non-streaming ingress is
    # byte-identical and never touches it.
    #
    # THE TWO CEILINGS BOUND DIFFERENT THINGS, and this one does NOT replace the other. A SINGLE body on a
    # streaming inbound is bounded by that inbound's per-connection max_message_bytes, which applies
    # whether or not this is set. What THIS bounds is the AGGREGATE. 0 (the default) = unlimited IN THE
    # AGGREGATE: no single body escapes max_message_bytes, but the NUMBER of such bodies in flight at once
    # is uncapped until an operator sets a positive value. docs/CONNECTIONS.md ("Two ceilings bound it")
    # is the operator-facing statement of the same split; docs/CONFIGURATION.md carries the catalog row.
    #
    # BACKLOG #1729: this block used to open by calling the setting "the aggregate DoS guard that replaces
    # the frame-cap-as-only-OOM-guard", four lines above its own "0 (the default) = unlimited" — one
    # comment contradicting itself, and the SDS-3.7 shape (a compensating control resting on a false
    # premise) for anyone who read only the first sentence. The DEFAULT is deliberately unchanged: it is a
    # coupled pin (tests/test_threat_model_doc_drift.py, "streaming-detach budget default 0 = unlimited",
    # against a vault THREAT-MODEL.md row), and "a multiple of the largest max_message_bytes" is not
    # expressible here at all — max_message_bytes is PER-CONNECTION and no registry exists at settings
    # load. What closes the visibility half is a start-time WARNING, keyed on the registry where the
    # streaming inbounds are actually in hand: pipeline/wiring_runner.warn_unbudgeted_streaming_inbound.
    stream_inflight_budget_bytes: int = 0

    # Staged-backlog depth bound (BACKLOG #290 slice 2, ASVS 15.2.2). OPT-IN per owner ruling R1 of
    # 2026-09-27: 0 (the default) = off. When positive, the engine PAUSES INTAKE while the not-done
    # rows at the ingress + routed stages of the ONE unified store exceed it, and resumes once they
    # drain to 90% of it, so the pause does not flap. Store-global, so N engine shards sharing a store
    # share one budget. The pause is backpressure only: a source stops taking in new input before
    # it reads it (docs/CONFIGURATION.md says how each one pauses, and what an open DICOM
    # association still takes in). Nothing already read is NAKed, dropped or left uncommitted. The
    # outbound stage is not counted, so one partner's down destination does not stop intake for
    # every feed. A stalled router or transform on ONE feed does
    # count, and can hold every feed paused: that is the cost of a shared budget. It lives
    # in [inbound] because it governs intake; the low-disk floor that also pauses intake is
    # [retention].min_free_disk_mb, because that one number also gates `serve`.
    max_staged_depth: int = 0

    @field_validator("max_staged_depth")
    @classmethod
    def _non_negative_depth(cls, value: int) -> int:
        if value < 0:
            raise ValueError("max_staged_depth must be >= 0 (0 = off)")
        return value


class DeliverySettings(_Section):
    """Global outbound-delivery defaults. An outbound connection that declares no ``retry=``/
    ``ordering=`` of its own inherits these; an explicit per-connection value overrides them
    (resolution order: per-connection override > ``[delivery]`` global default > built-in). The
    retry fields mirror :class:`~messagefoundry.config.models.RetryPolicy`; a test guards the sync.
    """

    # Key names match docs/CONFIGURATION.md's [delivery] catalog (retry_-prefixed so the section can
    # also grow non-retry keys like outbox_workers/dead_letter later). Mirrors RetryPolicy's finite
    # 100 default (#1051) — a test guards the sync, and the two MUST move together: leaving this at
    # None would restore retry-forever for every outbound that declares no retry= of its own, which
    # is the overwhelmingly common shape.
    # `ge=1` because a configured 0 loaded clean and dead-lettered on the FIRST failure: the delivery
    # check is `item.attempts >= max_attempts` against a POST-increment count, so 0 means give up
    # immediately while READING like "no limit". `None` is the documented retry-forever posture and
    # stays legal. The floor is on the OPERATOR-FACING setting only -- `RetryPolicy(max_attempts=0)`
    # remains a deliberate internal idiom for a permanent, no-retry failure (store `mark_failed`), and
    # constraining that instead would delete a used mechanism while claiming to add a guard.
    retry_max_attempts: int | None = Field(default=100, ge=1)
    retry_backoff_seconds: float = 5.0
    retry_backoff_multiplier: float = 2.0
    retry_max_backoff_seconds: float = 300.0

    # BACKLOG #1217 half 2. TOML has no null literal and an env var is always a string, so `None`
    # (retry-forever) was reachable from code-first Python only. The string spelling "forever"
    # (case-insensitive; MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS=forever works the same way) is coerced to
    # None here, `mode="before"` so it runs ahead of int|None coercion (precedent: _split_oidc_lists
    # above). Every other value — a real int, or a garbage string like "" or "none" — falls through
    # unchanged to that normal coercion/the `ge=1` floor, so it fails exactly as it did before.
    @field_validator("retry_max_attempts", mode="before")
    @classmethod
    def _retry_forever_spelling(cls, value: object) -> object:
        if isinstance(value, str) and value.strip().lower() == "forever":
            return None
        return value

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
    # `require_rcsi_for_pooled` USED TO SIT HERE; it is refused at load (see `_REMOVED_KEYS`).

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
    # Also, under EITHER policy, the consecutive claimer deaths a lane's own dispatch may cause before
    # the dispatcher STOPs that lane (BACKLOG #2074): each death stalls the lane's siblings too.
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
    # It also governs a permanent CONFIGURATION fault (BACKLOG #2083: an FTP server refusing AUTH TLS,
    # PROT P or the greeting, or demanding TLS of a plain session), which every row would meet alike.
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
    # ONE OTHER SETTING CAN CANCEL THIS ONE, and you must be told here rather than in that knob's
    # docs: the runner HARD-DISABLES fusion whenever [sandbox].mode is subprocess (it ships off, so
    # this bites only a site that turned the sandbox on). Fusion runs Router/Handler/accepts= code
    # in-process on an executor hop, so honouring both would silently run unsandboxed the code a
    # config asked to isolate; the runner fails CLOSED to the async sandboxed path and logs it. To
    # get fusion you must also set [sandbox].mode=off, and that trade is yours to make on purpose.
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


def _pass_environment_refusal(name: str) -> str | None:
    """Why ``name`` may not be handed to a sandbox worker, or ``None`` if it may.

    The worker runs the code ``[sandbox]`` exists to keep the engine's secrets from, so nothing of
    the engine's own may be named: no ``MEFOR_*`` variable at all, and no secret a library reads on
    the engine's behalf. That is the rule the DR hook's environment follows
    (:func:`messagefoundry.childenv.outside_engine_namespace`), reused so the two cannot drift.
    Refusing the whole namespace, not a list of secret names, cannot go stale when a secret is
    added. The text never echoes a value, only the name the operator typed."""
    if not (name.isascii() and name.isidentifier()):
        return f"{name!r} is not an environment variable name"
    if not outside_engine_namespace(name):
        return f"{name} is one of the engine's own variables; it may not be passed to a worker"
    return None


class SandboxSettings(_Section):
    """``[sandbox]`` — opt-in subprocess isolation for Routers/Handlers (ADR 0087, BACKLOG #197).

    **THIS DOES NOT STOP CONFIG PYTHON EXECUTING IN THE ENGINE PROCESS, and that is the first thing
    to know about it.** The loader executes every ``*.py`` in the config directory in-process, as the
    service account, at every ``serve`` and every reload, ungated by ``mode``
    (:func:`messagefoundry.config.wiring.load_config`). What ``mode`` governs is where a Router's or
    Handler's *body* runs once the graph is built — module top level is out of its reach either way,
    and the safe-source DACL gate is still what covers that.

    Routers/Handlers are admin-authored pure Python. In the engine's own address space sit the DEK,
    the audit chain, and every live socket. ASVS 15.2.5 wants a hard isolation boundary; this section
    turns one on. ``mode="off"`` (**the default**) runs them in-process, **byte-identically and with
    zero overhead** — the isolation seam is invisible. ``mode="subprocess"`` runs each inbound's
    Router/Handler in a **persistent per-inbound worker child** (never a per-message fork), enforcing
    a forbidden-import guard (socket/store/crypto), the resource caps below, and a fail-closed refusal
    of the live ``db_lookup``/``fhir_lookup`` bridges. An isolation denial routes the message to
    ``ERROR``/dead-letter **post-ACK** (no NAK), never dropping it.

    **What turning it on costs, all of it measured in ADR 0087 (do not re-derive):**

    * **Live enrichment is refused.** ``db_lookup``/``fhir_lookup`` re-enter the event loop, which a
      process boundary breaks, so they fail closed inside the child. **A Handler needing either must
      run ``mode="off"``** — that escape is supported and is not going away. ``[sandbox]`` is a
      single **engine-wide** section: :meth:`messagefoundry.pipeline.engine.Engine.add_registry`
      renders ONE ``SandboxPolicy`` for the whole graph and a connection carries no per-connection
      sandbox field, so ``mode="off"`` set for one Handler runs **every** Router and Handler in the
      process in-process, not just that one.
    * **``wall_seconds`` starts being enforced.** At ``mode="off"`` there is no timeout at all; at
      ``mode="subprocess"`` the parent kills a worker that overruns and dead-letters that message
      post-ACK. A busy-loop can no longer wedge intake, **and** a legitimately slow Handler that used
      to finish now dead-letters. ``startup_seconds`` and the POSIX ``cpu_seconds``/``mem_mb`` arm
      with it.
    * **Throughput** ~0.19 ms per dispatch with no reference view; a 20k-entry crosswalk ~4.5 ms
      marshalling and ~6.2 ms end-to-end, ~1.4x a pickle round-trip — inside the pipeline's existing
      per-interface bound. **One message is not one dispatch:** a message routed to one handler with
      an ``accepts=`` predicate costs three (router, predicate, transform), and fan-out to K handlers
      costs 1 + 2K, each re-marshalling the reference view.
    * **Per inbound with traffic:** one child process, two parent daemon threads (frame reader +
      stderr relay), three parent pipe fds, and on Windows a job-object handle.
    * **The pre-deploy gate does not learn this setting.** ``messagefoundry check`` and ``dryrun``
      always run in-process (:func:`messagefoundry.pipeline.dryrun.dry_run` takes no ``sandbox``
      argument), so a Handler calling ``db_lookup``/``fhir_lookup`` passes the gate green and then
      fails closed at ``serve``.

    Reliability-core + read ONCE at engine construction (a ``/config/reload`` does NOT re-read it —
    **restart to change**, exactly like ``claim_mode``)."""

    # off (default, byte-identical, no subprocess — and the supported escape for a Handler needing
    # live enrichment) | subprocess (persistent per-inbound worker child). ENGINE-WIDE, not per
    # connection: one policy is rendered for the whole graph.
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
    # Extra environment variable NAMES the worker is given, beyond its allowlist
    # (messagefoundry/childenv.py). The worker loads the config again under that allowlist, so a
    # config that reads another variable needs it named here, or its worker is refused when the
    # graph it builds differs from the engine's. Names only, and never a MEFOR_* name or another
    # of the engine's own: see _pass_environment_refusal.
    pass_environment: tuple[str, ...] = ()

    @field_validator("pass_environment", mode="before")
    @classmethod
    def _split_pass_environment(cls, v: object) -> object:
        # The env layer delivers MEFOR_SANDBOX_PASS_ENVIRONMENT as one string; split on commas.
        if isinstance(v, str):
            return [name.strip() for name in v.split(",") if name.strip()]
        return v

    @field_validator("pass_environment")
    @classmethod
    def _pass_environment_names(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for name in v:
            refusal = _pass_environment_refusal(name)
            if refusal is not None:
                raise ValueError(f"sandbox.pass_environment: {refusal}")
        return v


class DiagnosticsSettings(_Section):
    """``[diagnostics]`` — the Corepoint-style event log (#46). The two event-log master switches are
    **on by default** and safe to be: ``connection_events`` writes only metadata (connection name,
    peer IP, a scrubbed reason — never a frame or body), and ``response_sent`` always stores the
    non-PHI ACK disposition metadata while storing the AA-ACK *body* only when the store is encrypted
    (else NULL). A per-connection ``capture_connection_errors`` / ``capture_ack`` flag overrides the
    matching master switch for one connection (``None`` = inherit).

    ``audit_all_authz`` is a third default-on switch and is NOT one of those two: it governs the
    tamper-evident ``audit_log`` rather than the event log, and no per-connection flag overrides it."""

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
    # ASVS 16.3.2 (BACKLOG #244; default flipped ON by BACKLOG #1277). Audit EVERY authorization GRANT,
    # not just the sensitive/state-changing set. Setting it false narrows the trail back to that set
    # (state-change/config/user-mgmt), which cannot answer the question an audit trail exists to answer
    # — what did this account actually reach — because the read rows were never written and cannot be
    # reconstructed after the fact. PHI-view grants stay excluded at EITHER value: the PHI-access audit
    # path already records those, and a grant row there would be a double. Threaded onto app.state by
    # create_app (api/security.py `_audit_all_authz`).
    #
    # THE OFF DEFAULT NAMED THE WRONG SURFACE, AND THIS IS THE ONE PLACE THAT RECORD LIVES (SDS-3.5).
    # This comment used to read "console polling + the /ws/stats feed". The browser console is
    # server-rendered in-process, calls engine functions directly, and gates on its own cookie-world
    # `require_ui`, which records DENIALS only — it never traverses require(), so no console page view
    # can write a grant row. authorize_ws runs once per CONNECTION rather than per message, so the
    # stats feed writes one row per connect.
    #
    # VOLUME MOVES; IT DOES NOT VANISH. The JSON API is the surface that changes. Measured at
    # 3585fe555: 33 GET routes in api/app.py traverse require() (22 directly, 11 via
    # require_phi_read/require_step_up, which wrap it), of which 30 newly write a row per authenticated
    # request — the other 3 ask only for a PHI-view permission and stay silent — and auth_routes.py
    # adds 9 more. The ceiling is ONE row per request per require() dependency, because
    # _grant_audit_permission returns a single permission. So the growth is bounded by JSON-API client
    # polling cadence (the harness polls /stats), not by console page views. Nothing prunes the chain:
    # `[retention].audit_days` is reserved and unenforced by design, so `[retention].max_db_mb` (an
    # advisory warning, never a delete) is the only size signal.
    #
    # THE COST IS A COMMIT, NOT JUST A ROW, and that is the half a storage estimate misses. `require()`
    # AWAITS `record_audit` before the route body runs, and `record_audit` takes the store's write lock,
    # reads the chain head, INSERTs, and commits STANDALONE — audit is explicitly excluded from the ADR
    # 0055 group committer (store.py, `_GroupCommitter`: "claim*/reference-snapshot/audit stay
    # STANDALONE"), so there is no batching lever to soften it. That puts one extra commit on the same
    # lock the staged-pipeline handoffs use, per authenticated request. If it proves too high the answer
    # is a rate or sampling bound on read grants, or enrolling audit in group-commit — not an off switch
    # on the whole trail.
    audit_all_authz: bool = True


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


class LogWriteFailurePolicy(str, Enum):  # noqa: UP042
    """What the engine does when an application-log sink is unwritable AND its replacement is too."""

    # Fail-closed (the default): stop every connection this process owns. Never fires on a first
    # failure — only when the rolled replacement is unwritable as well (#122 stage 2, ADR 0162).
    STOP = "stop"
    # Alert + roll, but keep running. The documented opt-out; an operator choosing it accepts that
    # messages can be processed with no application-log record of the processing.
    CONTINUE = "continue"


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
    # The engine writes no log FILE of its own unless `file` below is set (opt-in, #122), but if an
    # operator tells us where the supervisor parks them, GET /status meters that directory's total bytes
    # + filesystem free space alongside the DB metrics (#50). None (the default) = stdout-only, no
    # metering. Metadata only — the contents are never read.
    log_dir: str | None = None

    # --- Engine-managed application log file + fail-closed write guard (#122, ADR 0162) ----------
    # OPT-IN second sink the ENGINE owns end to end: it opens it, it size-rotates it (file_max_bytes /
    # file_backup_count) and it rolls it aside on a write failure. None (the default) = stdout-only,
    # byte-identical to before, and NSSM stays the sole rotation owner of the captured stdout files.
    # ONE FILE, ONE OWNER: the validator below refuses a `file` inside `log_dir` (the supervisor's
    # rotation territory) — two rotation owners renaming one file is how a log gets shredded. See
    # docs/SERVICE.md "Who owns which log file".
    file: str | None = None
    file_max_bytes: int = 50_000_000  # size-rotate at ~50 MB (0 = never rotate on size)
    file_backup_count: int = 5  # keep app.log.1 .. app.log.N alongside the live file
    # THE FAIL-CLOSED CONTROL (#122). "stop" (default): when a log sink cannot be written AND the
    # replacement rolled into its place cannot be written either, every connection this PROCESS owns
    # stops — an engine that cannot log must not keep processing (CLAUDE.md §1 count-and-log). A first
    # failure alone NEVER stops anything; the roll absorbs the transient. "continue" is the documented
    # opt-out for an operator who would rather run blind than stop a feed; it still alerts and still
    # rolls, it just does not stop.
    on_write_failure: LogWriteFailurePolicy = LogWriteFailurePolicy.STOP

    # --- Off-box forwarding to a syslog/SIEM collector (ASVS 16.x; ADR 0080) ----------
    # Ship a copy of every log record to a remote syslog collector so log evidence survives a host
    # compromise (the local audit_log is tamper-evident, but lives on the same host). PHI redaction
    # applies to the forwarded stream exactly as to stdout. The forwarder never blocks the engine
    # indefinitely: UDP is fire-and-forget; the send runs on the forwarder's own thread, bounded by a
    # socket timeout. With the on-disk spool below (the default), a TCP/TLS collector unreachable at
    # startup is retried and a refused record is kept on disk; with the spool off, the collector is
    # skipped at startup (warns) and a refused record is dropped (BACKLOG #1966).
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
    # Optional PEM file of CRLs checked against the COLLECTOR's certificate (BACKLOG
    # #299). The syslog forwarder builds its own context and resolves no trust anchor, so
    # [tls].crl_file never reaches it -- this is its own knob rather than a silent inheritance, which
    # would be the per-hop scoping error that item warns about. Applies only with
    # forward_tls_verify=true: the opt-out arm is CERT_NONE, where there is no chain to check against.
    # Same fail-closed refusals as every other CRL: absent, unloadable or past nextUpdate refuses at
    # startup rather than at the first collector handshake.
    forward_tls_crl_file: str | None = None
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
    # --- On-disk spool behind the forwarder (BACKLOG #1966, ADR 0200) ----------
    # Records the collector does not take (down, backing off, or still queued at shutdown) are kept
    # here, in order, and sent when it answers again. None (the default) puts it at
    # `<dir of [store].path>/log-spool/<engine or shard id>`, so each engine shard gets its own. It
    # holds PHI-REDACTED text only (the filters run before the hand-off queue), PL-1 like the app log.
    forward_spool_dir: str | None = None
    # Cap on the spool's size on disk, in bytes. When full, the NEWEST record is dropped and the drop
    # reported, which keeps the oldest evidence. 0 turns the spool off (the pre-#1966 behaviour).
    forward_spool_max_bytes: int = Field(default=100_000_000, ge=0)
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

    @model_validator(mode="before")
    @classmethod
    def _refuse_renamed_file_keys(cls, data: Any) -> Any:
        """Refuse the legacy planned spellings instead of silently ignoring them.

        ``[logging]`` is pydantic ``extra="ignore"`` and CONFIGURATION.md carried ``max_bytes`` /
        ``backups`` as accepted-but-ignored *planned* keys while the engine-managed file was unbuilt.
        Now that the sink is real, ignoring them would hand an operator the 50 MB / 5-backup defaults
        while their config said otherwise — a control that reports success while doing something
        else. ``mode="before"`` because ``extra="ignore"`` drops them before any field validator
        could see them.

        **WHICH LAYER ACTUALLY REFUSES DEPENDS ON WHERE THE KEY CAME FROM, and this validator is not
        the one an operator meets first.** :func:`_reject_unknown_file_keys` refuses an unrecognized
        key in the TOML **file** before any model is built, so a file carrying either spelling never
        reaches here. Measured: ``[logging].max_bytes`` in a file is refused by the loader *and*
        suggested onward as ``file_max_bytes``, while ``[logging].backups`` is refused naming no
        replacement — the loader's nearest-name heuristic does not reach ``file_backup_count``.

        **The layer this one covers is ENV, which the file refusal deliberately does not.**
        ``_env_overrides`` scrapes ``MEFOR_LOGGING_*`` straight into the section dict, and a
        misspelled env var is otherwise dropped in silence (docs/CONFIGURATION.md, "The refusal covers
        the FILE"). Measured: ``MEFOR_LOGGING_MAX_BYTES`` and ``MEFOR_LOGGING_BACKUPS`` each reach
        this validator and are refused naming their replacement. So the two spellings are the rare
        env keys that fail loudly, and that is worth keeping rather than folding into the loader."""
        if isinstance(data, dict):
            for legacy, actual in (
                ("max_bytes", "file_max_bytes"),
                ("backups", "file_backup_count"),
            ):
                if legacy in data:
                    raise ValueError(
                        f"[logging].{legacy} is not a setting — the engine-managed application-log "
                        f"file uses [logging].{actual} (BACKLOG #122, ADR 0162)"
                    )
        return data

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

    @field_validator("forward_tls_crl_file")
    @classmethod
    def _forward_tls_crl_file_exists(cls, value: str | None) -> str | None:
        return _refuse_a_missing_crl_file(value, "[logging].forward_tls_crl_file")

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
        # ONE FILE, ONE ROTATION OWNER (#122, ADR 0162 §6). `log_dir` is where the SUPERVISOR (NSSM)
        # parks and rotates the captured stdout; `file` is a log the ENGINE opens, rotates and rolls.
        # Putting the engine's file inside the supervisor's directory points two rotators at one
        # directory, and the loser of that race is the log an operator reads after an incident.
        if self.file is not None and self.log_dir is not None:
            engine_file = Path(self.file).expanduser().resolve(strict=False)
            supervisor_dir = Path(self.log_dir).expanduser().resolve(strict=False)
            if engine_file == supervisor_dir or supervisor_dir in engine_file.parents:
                raise ValueError(
                    f"[logging].file ({self.file}) is inside [logging].log_dir ({self.log_dir}), "
                    "which the supervisor (NSSM) rotates. Two rotation owners on one directory "
                    "corrupt the log they are meant to preserve — put the engine-managed file "
                    "somewhere the supervisor does not rotate (docs/SERVICE.md)"
                )
        if self.file_max_bytes < 0:
            raise ValueError("[logging].file_max_bytes must be >= 0 (0 = never rotate on size)")
        if self.file_backup_count < 0:
            raise ValueError("[logging].file_backup_count must be >= 0")
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

    One knob here is default-ON rather than off: ``min_free_disk_mb``, the low-disk storage floor
    (BACKLOG #290). It refuses a ``serve`` start and warns at runtime; it never purges anything.
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
    # Past N days, DELETE ORPHANED reference snapshots (ADR 0006) — the rows of a set that config no
    # longer declares, whose active version was synced before the cutoff. `reference.value` is PL-2
    # (PHI.md §2) and a snapshot row can be patient-keyed, but until ASVS 14.2.7 it had NO purge path at
    # all: the only thing that ever replaced a snapshot was the next sync's build-new-then-flip, which
    # never comes for a set nobody declares any more. 0 = keep forever.
    #
    # ORPHAN-SCOPED, and the limit is the honest part: a set that IS still declared is never touched
    # however old its `synced_at`, because its snapshot is live data the engine serves. So the normal
    # case — a wired set holding live PHI — remains purged by nothing. That is a stated residual, not a
    # closed cell; do not let a classification table describe this window as covering `reference.value`
    # generally, which would machine-bless a false claim.
    reference_snapshot_days: int = 0
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
    # Audit-log retention. RESERVED / not enforced. The rationale is the AUDIT-RETENTION REQUIREMENT
    # (45 CFR 164.316(b)(2)(i), ~6 years) -- not chain-breakage, which this comment used to give as
    # the reason. Whether a delete breaks the chain depends on WHICH rows go. Measured 2026-09-03,
    # BACKLOG #1421. The reasoning is stated in ONE place -- the `audit_days` row in
    # docs/CONFIGURATION.md, which also carries the contract an archive-first purge has to meet --
    # so read it there rather than restating it here; four copies of it are how the records drifted
    # apart. Archive-first pruning is a tracked follow-up. Accepted (not rejected) so a
    # forward-looking file still loads.
    audit_days: int = 0
    # Warn (WARNING log + AlertSink storage_threshold) when the DB file (+ -wal/-shm) exceeds this
    # many MB. 0 = off. Advisory only — never auto-deletes.
    max_db_mb: int = 0
    # Low-disk storage floor (BACKLOG #290, ASVS 15.2.2), in MiB of FREE space on the volume that holds
    # the SQLite store file. DEFAULT-ON at 1024 MiB (1 GiB, the DR-backup preflight's low-space line),
    # per owner ruling 2026-09-27. `serve` REFUSES TO START (exit 2) when free space is below it, and
    # the periodic retention pass logs a WARNING while free space stays below it. At runtime the engine
    # also PAUSES INTAKE below it (slice 2, pipeline/intake_bound.py) and resumes at the floor plus a
    # tenth: the same pause as [inbound].max_staged_depth, which says how sources honour it. It never
    # drops, NAKs or deletes anything: a full disk is what would. One number drives both, so the runtime WARNING
    # starts at the same line a restart would be refused at; it is not an earlier notice.
    # SQLite only: on SQL Server and Postgres the store's disk is not this process's to stat, so serve
    # logs one INFO line and skips it. 0 = off. Unlike `max_db_mb` this measures the VOLUME, not the
    # store's own size, so the two do not overlap.
    min_free_disk_mb: int = 1024
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
        "min_free_disk_mb",
        "state_max_age_days",
        "connection_event_retention_hours",
        "app_log_days",
        "app_log_compress_days",
        "search_preset_days",
        "reference_snapshot_days",
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


def is_ldaps_address(server: str) -> bool:
    """Whether an ``[auth].ad_server`` value names an LDAPS endpoint (vault BACKLOG #2354).

    The scheme ``ldaps://`` and nothing looser. A bare host such as ``ldapsrv01.corp.example`` starts
    with ``ldaps`` too, but ldap3 dials it on 389 with no TLS, so a prefix test without ``://`` would
    take a cleartext bind for an encrypted one. ``AuthSettings`` and ``LdapAuthenticator`` both read
    this, so the settings refusal and the TLS the authenticator builds agree on what is plain.
    Surrounding whitespace is ignored, because ldap3 strips it before it reads the scheme."""
    return server.strip().lower().startswith("ldaps://")


def split_kerberos_spn(spn: str) -> tuple[str, str]:
    """Split ``[auth].kerberos_spn`` into ``(service, hostname)`` for pyspnego (BACKLOG #275).

    pyspnego builds the acceptor SPN itself as ``"<service>/<hostname>"``, and its ``hostname``
    defaults to ``"unspecified"``. So passing the whole ``HTTP/host`` value as ``service=`` yields
    ``HTTP/host/unspecified``, which names no account. The value must be split once, here.

    Accepts exactly ``SERVICE/host`` with both halves non-empty. A realm suffix (``HTTP/host@REALM``)
    is refused rather than passed through: no lab has confirmed that form works on either provider,
    and the host's own domain supplies the realm. The ``ValueError`` text never repeats the value.
    """
    if any(ch.isspace() or not ch.isprintable() for ch in spn):
        raise ValueError(
            "kerberos_spn must not contain whitespace or control characters; use the form "
            "SERVICE/host"
        )
    if "@" in spn:
        raise ValueError(
            "kerberos_spn must not carry a realm suffix (@REALM); use the form SERVICE/host, "
            "e.g. HTTP/host.example.com -- the host's own domain supplies the realm"
        )
    service, sep, hostname = spn.partition("/")
    if not sep or not service or not hostname or "/" in hostname:
        raise ValueError(
            "kerberos_spn must be exactly SERVICE/host with one '/' and both parts non-empty, "
            "e.g. HTTP/host.example.com"
        )
    return service, hostname


#: The shortest site context term ``[auth].password_extra_context_words`` accepts. The context screen
#: is a case-insensitive SUBSTRING test, so a one- or two-letter term would refuse a large share of
#: ordinary passphrases. Three is the length of the shortest shipped term (``hl7``) and admits the
#: three-letter organization acronyms ASVS 6.1.2 has in mind. A COPY of
#: ``auth.policy.EXTRA_CONTEXT_WORD_MIN_LENGTH``, which derives it; this module does not import auth,
#: and ``tests/test_site_context_words.py`` holds the two equal.
EXTRA_CONTEXT_WORD_MIN_LENGTH = 3

#: Upper bound for ``[auth].ad_connect_timeout`` and ``ad_receive_timeout``. An hour is far past any
#: real directory round trip and far below the point where a socket timeout overflows.
_AD_TIMEOUT_MAX_SECONDS = 3600.0


class AuthSettings(_Section):
    """Authentication + RBAC knobs. Secrets (the AD bind password) come from env, never the file."""

    # Authentication is required by default; this flag exists only for the embedding/test path.
    enabled: bool = True
    session_idle_timeout_minutes: int = 30
    session_absolute_hours: int = 12
    # Cap concurrent sessions per user (ASVS 7.1.2); a login beyond the cap revokes the user's oldest
    # live session; lapsed sessions neither count nor survive it (BACKLOG #1900). Sign-ins still
    # owing a second factor are capped apart, so they never evict a full session (BACKLOG #2076).
    # 0 = unlimited.
    # Default 5 (WP-10): generous for a few devices/console instances.
    max_sessions_per_user: int = 5
    # Step-up re-verification (ASVS 7.5.3): a highly sensitive operation requires the session to have
    # re-verified its credential -- at login, via POST /me/reauth, or with a code at
    # POST /auth/mfa-verify (or their console twins) -- within this many seconds. A LOCAL login
    # that owes no second factor counts as the first verification (sudo-timestamp model) unless the
    # account has signed in before and this address is not among its recent completed sign-ins (at
    # most 200 rows of each kind and 90 days back; BACKLOG #288, _classify_login_address). That
    # check fails open on no address or a failed read. A combined password-plus-TOTP sign-in counts
    # from any address (ADR 0197). A directory login (Kerberos, OIDC) never does (BACKLOG #1144).
    # Default 5 minutes.
    step_up_max_age_seconds: int = 300
    # Action-bound step-up (ADR 0077; ASVS 7.5.1/8.2.4). When on (default), a fixed set of routes
    # requires a fresh proof BOUND to that specific action (POST /me/reauth with a matching
    # `purpose`), single-use, instead of riding the session-wide step-up window: the self-service
    # factor and session-terminate routes, and the admin user-update, reset-password, reset-mfa and
    # federated-identity routes (the STEP_UP_ACTION_* constants in auth/service.py; the route list is
    # in docs/CONFIGURATION.md). This closes the most-exploitable default: a session hijacked inside
    # the 300s login-seeded window could otherwise bind an attacker's authenticator with no fresh
    # proof. Every other step-up route keeps the session-window step-up (7.5.3). Default True is
    # secure-by-default and does not touch the loopback bind, TLS, or any collector path. Set False to revert to the legacy
    # session-window behaviour (0.2.x semantics) — the documented org opt-out.
    require_action_step_up: bool = True

    # Multi-factor authentication (WP-14, ADR 0002 §3; ASVS 6.3.3) — a native RFC 6238 TOTP second
    # factor. It covers EVERY account, directory ones included (BACKLOG #1144, ASVS 6.8.4): a ticket
    # or a bind asserts nothing about what the directory enforced, so the engine grants nothing on it
    # and asks for its own factor instead of exempting the leg. When require_mfa is on, an in-scope
    # account (see require_mfa_scope) MUST enroll a factor and
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
    # api/security.py:require_reauth_only_action), so a newly provisioned admin enrolls TOTP then satisfies
    # it. Set ``require_mfa = false`` (the documented opt-out) to revert to the single-factor default.
    # An off-loopback bind that serves local accounts MUST keep this on; ``serve`` makes that posture
    # explicit (sec-mfa-on) — on an exposed (non-loopback) PHI bind with this **explicitly opted out**
    # it **refuses to start** on a production instance and **warns** on a non-production one, mirroring
    # the keyless-store / open-egress startup gates (see __main__._serve), so MFA can't be silently
    # skipped at exposure. Scope: since ASVS 6.3.3 it gates **every authorized route** for an in-scope
    # session, not merely step-up operations — an MFA-pending session is refused with 403 +
    # ``X-MFA-Required: 1`` (api/security.py:require) and, in the browser, confined to /ui/mfa.
    require_mfa: bool = True
    # WHICH accounts an un-enrolled session's access gate covers when require_mfa is on (ASVS 6.3.3).
    # ``every_local_account`` (default) means any account must carry a second factor;
    # ``administrators`` is the pre-6.3.3 posture where only the Administrator role must. An account
    # that has ALREADY enrolled a factor is required to satisfy it under either value — this dial only
    # decides who must enroll in the first place.
    #
    # THE ``every_local_account`` SPELLING IS NOW WIDER THAN ITS NAME (BACKLOG #1144). Directory
    # identities used to be exempt under either value; they are not, because the directory legs assert
    # no strength and the engine grants nothing on that. Renaming the Literal reaches this model, the
    # CONFIGURATION.md table and the tests that pin both -- its own coherent change, not a rider on a
    # security fix. THIS IS THE SINGLE PLACE that mismatch is explained; do not restate it (SDS-3.5).
    #
    # OPERATOR NOTE: under ``every_local_account`` a non-interactive bearer-token service account
    # becomes MFA-pending and cannot enroll unattended. ``administrators`` frees only a LOCAL account
    # without the Administrator role (AuthService._mfa_required_for keeps that role in scope under
    # either value); ``require_mfa = false`` frees any un-enrolled account, at the exposure gate's
    # cost. Moving it to AD is NO LONGER an escape: while require_mfa is on, a directory session that
    # proved no factor owes one under either require_mfa_scope value (BACKLOG #1144); setting the
    # scope to administrators takes only a local account without the Administrator role out of scope.
    # Nor is mTLS: require_service_cert (api/security.py) admits a cert identity on
    # GET /service/identity alone, so it cannot carry a working service account.
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
    # THE LEAST TIME BETWEEN SIGN-IN AND THE SECOND FACTOR, AND IT IS PROVISIONAL (BACKLOG #2301, ASVS
    # 2.4.2; owner ruling R7 of 2026-09-23 chose published human-timing research over a timed
    # session). A code or passkey that completes an MFA-pending session sooner than this after the
    # session was minted is refused with the leg's ordinary failure, so the refusal says nothing about
    # timing. It is audited with reason "too_early", charges no lockout and spends no code. Only the
    # PENDING session is floored; a step-up code on a session whose factor is already satisfied is not.
    # Sized from the keystroke-level model (Card, Moran and Newell, "The keystroke-level model for user
    # performance time with interactive systems", Communications of the ACM 23(7), 1980, pp. 396-410):
    #   M   take in a prompt the person has not seen, and decide    1.35 s
    #   K   one keystroke by the fastest typist the model lists     0.08 s
    # The second step is a new prompt and at least one submit, M + K = 1.43 s, even with the code
    # filled in by a password manager. The default sits about 30% below, at 1.0 s, because M is an
    # average and some people are faster; the dual-control dwell takes a margin for the same reason.
    # It is a judgment, not a measurement, and nobody has timed a person on THIS console.
    # [auth].oidc_callback_min_elapsed_seconds reuses this derivation. 0 turns the floor off.
    mfa_verify_min_elapsed_seconds: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    # Admin-interface defense-in-depth contextual-risk signal (WP-L3-13, ADR 0002; ASVS 8.4.2). When
    # on, a step-up (sensitive admin) request arriving from a client IP that differs from the one the
    # session last verified from is treated as higher-risk: it emits an audit + out-of-band notice and
    # FORCES a fresh step-up (a successful re-verify re-anchors the session to the new IP). It is
    # advisory + step-up-forcing only — it NEVER changes an RBAC allow/deny and never blocks the
    # non-admin request path. A single-host loopback deployment never trips it (loopback addresses
    # 127.0.0.1 and ::1 are treated as the same host, so a dual-stack box doesn't spuriously fire).
    #
    # DEFAULT ON since BACKLOG #288 (owner ruling 2026-09-26, ASVS 8.2.4). It used to default off,
    # with an exposure-time advisory asking an off-loopback operator to turn it on; the hardened path
    # is now the shipped path. Setting it false is a LOOSENING -- `security_loosenings()` names it
    # whenever auth is on -- because it removes the only mid-session address signal.
    admin_new_ip_step_up: bool = True

    # Local-password policy — ASVS 5.0-aligned (WP-3): length-first, no mandatory composition.
    password_min_length: int = 15
    # Character-class requirements are OFF by default (ASVS forbids mandatory composition) but kept
    # as opt-in knobs for deployments with a legacy standard that still mandates them.
    password_require_uppercase: bool = False
    password_require_lowercase: bool = False
    password_require_digit: bool = False
    password_require_symbol: bool = False
    password_check_breached: bool = True  # reject known common/breached passwords (offline corpus)
    # Reject passwords containing a context word: a shipped CONTEXT_WORDS term or a site term from
    # password_extra_context_words below. One switch for both lists.
    password_check_context: bool = True
    # A site's OWN context words (ASVS 6.1.2 / 6.2.11): organization, product, project, department or
    # role names that a shipped constant cannot know. ADDITIVE ONLY -- they join CONTEXT_WORDS in the
    # same screen and can never remove a shipped term. Validated at load by
    # `_check_extra_context_words`: lower-cased the way the screen compares, each at least
    # EXTRA_CONTEXT_WORD_MIN_LENGTH characters, and a blank entry refuses rather than being dropped.
    # Env: MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS="acme,globex" (comma-separated). An empty piece,
    # a trailing comma included, refuses the load, unlike the OIDC and egress lists.
    password_extra_context_words: list[str] = Field(default_factory=list)
    # Reject passwords containing the user's own username. No ASVS 5.0 requirement names this screen:
    # 6.2.11 grades the documented context-word list, and a username is not on it.
    password_check_username: bool = True
    # Optional path to a larger offline breach corpus that augments the bundled one (6.2.12): a
    # plaintext list OR an HIBP-style SHA-1-hash export (HASH[:count] lines, auto-detected). Fully
    # offline — no live HIBP call. Use a curated subset, not the full ~40 GB HIBP set (loaded into
    # memory). Only entries at or above password_min_length add coverage — see docs/CONFIGURATION.md.
    password_breach_corpus_file: str | None = None
    lockout_threshold: int = 5  # consecutive failed logins before the account locks
    # 0 or less expires every lock the moment it is set. Minutes below the default, a threshold above
    # it and a lockout_max_minutes below its own are each a LOOSENING `security_loosenings()` names
    # (BACKLOG #1131). A threshold of 0 or less locks on the first failure, which is stricter.
    lockout_minutes: int = 15
    # ADR 0197 (BACKLOG #1131, ASVS 6.1.1): the CEILING an escalating lock doubles up to. A lock
    # doubles per cycle only where the owner has a way past it (the second-step lock on a local
    # account, and the sign-in lock on a local account with TOTP enrolled); every other lock keeps
    # `lockout_minutes`. 1440 (24 hours) is the owner's ruling of 2026-09-27. Must be at least
    # `lockout_minutes`.
    lockout_max_minutes: int = 1440
    # ASVS 6.4.1: an admin-issued initial/reset credential (a `must_change_password` temp password) that
    # is never claimed EXPIRES this many hours after it was set. Without it, an unused reset password
    # grants an authenticated session indefinitely — and the one action it permits is to SET the
    # password, i.e. account takeover. Keyed on `password_changed_at`; a user who set their own password
    # has `must_change_password=False` and is unaffected. Every local account holding such a temporary
    # password is in scope: the engine creates no default account (ADR 0183 Amendment A), so there is
    # no carve-out to reason about. 0 = no expiry (not recommended on a PHI instance).
    initial_password_expiry_hours: int = 72

    # Active Directory / LDAP. The bind password is a secret: MEFOR_AUTH_AD_BIND_PASSWORD.
    #
    # `ad_enabled` means DIRECTORY BIND CAPABILITY -- this engine can reach AD and resolve principals.
    # It is what Kerberos SSO, federated OIDC and the session reconciler each depend on, and it is why
    # they all validate against it rather than against the login pathway below (BACKLOG #1137).
    # There is no switch for a directory-PASSWORD sign-in: that pathway is retired (BACKLOG #1137),
    # and AuthService._dispatch_login refuses `provider=ad`. A bind as the user survives only as the
    # step-up re-bind (`_reauth_ad`).
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
    # Explicit opt-in to a non-ldaps:// bind (trusted-net dev). Honoured only under
    # [security].enforcement = warn, and named as a loosening there (vault BACKLOG #2354). Under enforce it
    # is inert: ServiceSettings refuses the plain bind at load, as the MEFOR_ALLOW_INSECURE_TLS escape is
    # inert there.
    ad_allow_insecure_ldap: bool = False
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
    # single ambiguous result never revokes: "the search returned nothing" cannot tell deleted from
    # moved out of the search base, and a set disabled bit or an unreadable userAccountControl strikes
    # the same way, so requiring two agreeing probes costs at most one extra interval of exposure and
    # buys immunity to a single flaky search. Strike state is process-local (the rate-limiter
    # precedent), so a restart resets it — biased toward NOT revoking.
    ad_session_recheck_strikes: int = 2
    # Per-pass bind budget. A pass probes at most this many distinct users; the remainder are picked up
    # by the following passes (least-recently-probed first), so a very large estate degrades to a longer
    # effective interval instead of a bind storm against the DC.
    ad_session_recheck_max_users: int = 200
    # --- mass-revoke circuit breaker ---
    # A misconfigured search base, a moved OU, or a service account that lost read rights on the
    # entries returns "not found" for EVERY user — indistinguishable from "everyone was deleted".
    # Without a brake the reconciler would sign out the entire estate during exactly the incident when
    # operators need the console. A pass that would revoke more than BOTH of these thresholds aborts,
    # revokes nothing, and raises a loud operator-visible alert (log ERROR + an
    # `auth.ad_reconcile_aborted` audit row).
    #
    # BOTH must be exceeded to trip, deliberately: the absolute floor stops the breaker firing on a tiny
    # estate where any proportion is meaningless (3 of 3 genuine offboardings is 100 %), and the
    # proportion stops a large estate being signed out wholesale. Requiring both means it fires only on
    # a change that is simultaneously large in absolute terms AND broad relative to the signed-in
    # population — the signature of a misconfiguration, not of offboarding. Below the floor the breaker
    # cannot distinguish the two cases and revokes.
    #
    # A service account that loses read on `userAccountControl` ALONE is NOT this breaker's case any
    # more (ADR 0195, BACKLOG #2039). Those accounts read UNDETERMINED, not "not found", and the
    # reconciler holds them without revoking under the rule ADR 0195 states (`hold_engaged` in
    # auth/reconcile.py). That hold has no floor and no setting: the count of one is fixed. The
    # old reasoning here, that signing out a handful below the floor is recoverable, did not hold for
    # that case: nobody can sign back in while the attribute is unreadable, and on a larger estate the
    # breaker only delayed the wave until attrition brought it under the floor.
    ad_session_revoke_max: int = 5  # absolute: never auto-revoke more than this in one pass
    ad_session_revoke_max_fraction: float = 0.34  # proportional: ...nor more than this share

    # Windows SSO (Kerberos/SPNEGO) — passwordless login from a domain-joined client.
    # Experimental; off by default. Needs ad_enabled.
    kerberos_enabled: bool = False
    # Exactly SERVICE/host, e.g. HTTP/host.example.com; no realm suffix. Refused at load otherwise.
    # Unset or empty calls spnego.server() bare: GSSAPI then uses the default keytab, but SSPI
    # (Windows) asks for the literal principal host/unspecified, so set it there. See
    # split_kerberos_spn.
    kerberos_spn: str | None = None

    # Federated SSO — OIDC authorization-code + PKCE relying party (ADR 0142, BACKLOG #274). A THIRD
    # login mechanism for an identity that ALREADY exists in on-prem AD: the id_token is verified, then
    # the account is selected by the verified (issuer, sub) pair an administrator bound to it, and its
    # principal is re-resolved in AD from that row (ADR 0184). The username claim selects nothing, and
    # roles come from LDAP, never the token. Default OFF and byte-identical when off. Hybrid-only: a
    # principal with no on-prem AD object is refused. Endpoints are operator-pinned (no .well-known
    # discovery), so no attacker-influenced URL exists.
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
    # BACKLOG #299: optional PEM file of CRLs checked against the IdP's certificate. The
    # IdP opener resolves no trust anchor, so [tls].crl_file cannot reach it -- this is its own knob
    # rather than a silent inheritance. A revoked IdP cert matters more than on a data hop: this is the
    # leg carrying the client secret, the authorization code and the identity assertion. Same
    # fail-closed refusals as every other CRL (absent / unloadable / past nextUpdate refuses at start).
    oidc_tls_crl_file: str | None = None
    oidc_redirect_path: str = "/ui/oidc/callback"  # full URI derived from [api].public_origin
    oidc_scopes: list[str] = Field(default_factory=lambda: ["openid", "profile"])
    oidc_signing_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    oidc_username_claim: str = "preferred_username"
    oidc_username_strip_domain: bool = True  # strip at the first '@'; a hint, not the account key
    # When strip_domain is on, the claim's UPN suffix MUST match one of these, or the id_token is
    # refused. This no longer decides which on-prem account a login reaches: since ADR 0184 the bound
    # (issuer, sub) pair selects it, and the claim is only a hint in the not-bound refusal. It was that
    # control before, because `preferred_username` is neither unique nor stable (OIDC Core §5.7) and is
    # self-editable on many IdPs. Empty = fall back to [auth].ad_domain; if neither is set while
    # strip_domain is on, oidc_enabled is refused at load rather than stripping unchecked. List the alternate UPN suffixes
    # of a multi-domain forest here.
    oidc_allowed_username_domains: list[str] = Field(default_factory=list)
    oidc_clock_skew_seconds: int = 60  # wall clock; validator-capped 0..300
    # The BACKLOG #99(g) control: refuse a login whose verified token carries no configured MFA claim.
    # Secure default ON. The engine verifies what the IdP ASSERTS, not what it enforced.
    oidc_require_mfa_claim: bool = True
    oidc_mfa_amr_values: list[str] = Field(default_factory=lambda: ["mfa"])
    oidc_required_acr_values: list[str] = Field(default_factory=list)
    # Requested `acr_values` authorize param. A request only: the claim gate checks the returned
    # acr against oidc_required_acr_values (while oidc_require_mfa_claim is on), so setting this
    # with no non-blank required value is refused at load (BACKLOG #2032).
    oidc_acr_values: str | None = None
    oidc_prompt: str | None = None  # requested `prompt` authorize param
    oidc_jwks_ttl_seconds: int = 3600
    oidc_jwks_min_refetch_seconds: int = 300  # the amplification bound
    oidc_flow_ttl_seconds: int = 300  # single-use flow window; validator-capped 30..1800
    # The FLOOR beside that ceiling (BACKLOG #2301, ASVS 2.4.2), PROVISIONAL: a callback that returns
    # sooner than this after its flow started is refused as "federated sign-in failed". A step-up
    # flow asks the IdP to authenticate afresh (max_age=0, prompt=login), so the floor always
    # applies there. A sign-in flow is floored only when the id_token's auth_time shows the person
    # signed in at the IdP during THIS flow: an IdP holding a live single sign-on session answers with
    # no human step at all, and flooring that would refuse every such sign-in, retry after retry. The
    # default reuses mfa_verify_min_elapsed_seconds' derivation (a new prompt and one submit, 1.43 s
    # by the keystroke-level model, less a margin). 0 turns it off; it must be shorter than the TTL.
    oidc_callback_min_elapsed_seconds: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    oidc_flow_cache_max: int = 512  # reject-when-full (never evict — that is a login DoS)
    oidc_session_max_hours: int | None = None  # G2: cap below id_token.exp if tighter is wanted
    # ASVS 6.8.4 / 7.6.1, BACKLOG #296 / #1150: the most time, in seconds, that may pass between the
    # user's authentication AT THE IdP and the end of the engine session it mints. Sent as `max_age` on
    # every authorization request, so a conforming IdP re-authenticates only when its own SSO session
    # is older than this (single sign-on survives for everyone inside the window) and MUST return
    # `auth_time`. The ladder refuses a token with no `auth_time` or a stale one, and the session is
    # capped at `auth_time + max_age`. There is deliberately NO off switch: None and 0 are refused
    # (0 is `prompt=login` under another name, which throws away single sign-on). The default matches
    # the shipped 12-hour absolute session cap, so a fresh IdP login changes nothing and an old one
    # cannot buy a session reaching past 12 hours from the moment the human actually authenticated.
    oidc_max_age_seconds: int = 43200

    # Login rate limiting (AUTH-RATE) — in-process sliding window in front of the per-account
    # lockout: bounds password-spray + argon2 CPU-burn. In-process only; an exposed/multi-host
    # deployment must also front the API with a proxy/WAF limiter. 0 disables a limit, and a window
    # of 0 or less disables both. A count above its default, a window below it, and each off value is
    # a LOOSENING that `security_loosenings()` names while auth is on (BACKLOG #1131); so are the
    # PHI-read, admin-write, session-cap and OIDC flow-cache limits below.
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
    # per-actor PHI-read budget explicitly at admission (see enforce_phi_read_pacing). In-process only
    # (front a proxy/WAF when exposed). enabled=False disables it.
    #
    # THE DEFAULT IS A HUMAN-TIMING FLOOR, AND IT IS PROVISIONAL (BACKLOG #287; owner ruling R7 of
    # 2026-09-23 chose published human-timing research over a timed session on this console). It is
    # derived from the keystroke-level model (KLM): Card, Moran and Newell, "The keystroke-level model
    # for user performance time with interactive systems", Communications of the ACM 23(7), 1980,
    # pp. 396-410, the source [approvals].min_dwell_seconds cites. Its pointing time is a Fitts' law
    # average. The click time is Kieras's KLM guidance ("Using the Keystroke-Level Model to Estimate
    # Execution Times", University of Michigan, 1993), where a click is a press plus a release:
    #   M   mentally prepare                 1.35 s
    #   P   point the mouse at a target      1.1 s
    #   BB  press and release the button     0.2 s (0.1 s each)
    # A console write is a click, so the model prices it at M + P + BB = 2.65 s, and twelve take about
    # 32 s. The floor must not refuse a person who has decided a run up front, so drop M: P + BB =
    # 1.3 s is the fastest write the model allows. Twelve writes per 15 s is one per 1.25 s, just
    # under that, so a person at the model's pace does not trip it. The margin is thin, and P is an
    # average: a person clicking a button that is already under the pointer skips P and can trip it.
    # That is a judgment, not a measurement. (min_dwell_seconds prices its
    # submit at the fastest KEYSTROKE, 0.08 s. Priced that way a write would take 1.18 s and the window
    # would have to be 14 s; every console write is a click, so the click time is used here. The
    # difference is one reason the number is provisional.) The 403 -> reauth -> retry burst is two
    # writes and sits well inside the budget; a script loops far faster and trips at the thirteenth
    # write inside the window. Nobody has timed a person on THIS console, so an assessor who insists
    # on local timing will not accept the number. That is why it is labelled provisional and why the
    # window is a setting.
    admin_write_rate_limit_enabled: bool = True
    admin_write_rate_limit_per_actor: int = (
        12  # max state-changing admin writes per actor per window
    )
    # gt=0 and no nan/inf: a zero window turns the floor off silently, and a nan one never prunes, so
    # every write after the twelfth would be refused for the life of the process.
    admin_write_rate_limit_window_seconds: float = Field(default=15.0, gt=0, allow_inf_nan=False)
    # THE MINIMUM GAP BETWEEN TWO WRITES BY ONE ACTOR, AND IT IS PROVISIONAL TOO (BACKLOG #2301, ASVS
    # 2.4.2; owner ruling R7 of 2026-09-23). The count above admits its twelve writes back to back;
    # this refuses a write that lands sooner than this after the same actor's last admitted one. It
    # charges nothing: a refused write is not recorded, as with the count. Same sources as above. The
    # fastest console write the model allows, with the decision made and the hand already in place,
    # is one click, BB = 0.2 s (Kieras 1993), or Tab then Enter at the fastest typist the model lists,
    # 2 K = 2 x 0.08 s = 0.16 s (Card, Moran and Newell 1980). The default sits just under the faster,
    # at 0.15 s. A real second write also waits for the page to come back, which only adds to the
    # gap. It is a judgment, not a measurement, and nobody has timed a person on THIS console. 0 turns
    # the gap off. It must be shorter than the window, or the last write ages out of the window before
    # the gap is measured (checked below).
    admin_write_min_interval_seconds: float = Field(default=0.15, ge=0, allow_inf_nan=False)

    # Out-of-band user notification of security events (ASVS 6.3.5/6.3.7): email the affected user on
    # lockout / first-success-after-failures / password/email/role/disable changes. Email requires the
    # [alerts] SMTP transport to be configured (no SMTP means email is skipped). This toggle does not
    # touch the audit log; which events the /me/security-events feed shows is stated once, in
    # auth/notifications.py.
    notify_security_events: bool = True

    @model_validator(mode="after")
    def _check_floors_inside_their_windows(self) -> AuthSettings:
        # A gap as long as the window measures nothing: the limiter prunes the last write before it
        # compares, so the gap would silently fall back to the count. Refused at load instead.
        if (
            self.admin_write_rate_limit_enabled
            and self.admin_write_min_interval_seconds >= self.admin_write_rate_limit_window_seconds
        ):
            raise ValueError(
                "admin_write_min_interval_seconds must be shorter than "
                "admin_write_rate_limit_window_seconds"
            )
        # The same shape for the federated floor: at or past the flow TTL, every flow would expire
        # before it could complete. Checked whether or not federation is on, as the TTL itself is.
        if self.oidc_callback_min_elapsed_seconds >= self.oidc_flow_ttl_seconds:
            raise ValueError(
                "oidc_callback_min_elapsed_seconds must be shorter than oidc_flow_ttl_seconds"
            )
        # And for the MFA floor: at or past the idle timeout, every pending session would idle out
        # before its code could be accepted, so no account with a factor could finish signing in.
        idle_seconds = self.session_idle_timeout_minutes * 60
        if idle_seconds > 0 and self.mfa_verify_min_elapsed_seconds >= idle_seconds:
            raise ValueError(
                "mfa_verify_min_elapsed_seconds must be shorter than session_idle_timeout_minutes"
            )
        return self

    @model_validator(mode="after")
    def _check_lockout_ceiling(self) -> AuthSettings:
        # ADR 0197: a ceiling below the base would make the first lock the longest one, which reads
        # as a working escalation and is not one. Refused rather than silently raised to the base.
        if self.lockout_max_minutes < self.lockout_minutes:
            raise ValueError(
                f"lockout_max_minutes ({self.lockout_max_minutes}) must be at least lockout_minutes "
                f"({self.lockout_minutes}): it is the ceiling an escalating lock doubles up to"
            )
        return self

    @field_validator("password_extra_context_words", mode="before")
    @classmethod
    def _split_extra_context_words(cls, v: object) -> object:
        # The environment carries a list as one comma-separated string, as the OIDC lists do. Unlike
        # them, an empty piece is KEPT so the check below can refuse it: "acme,,globex" is a typo,
        # and silently dropping the gap would hide it. A wholly blank value means "no site terms".
        # A JSON array is read as one, because split on commas it would load terms that still carry
        # the brackets and quotes, and those match nothing.
        if isinstance(v, str):
            text = v.strip()
            if not text:
                return []
            if text.startswith("["):
                # The helper returns rather than raises, so this refusal has no decode error on its
                # chain (BACKLOG #2085). It also turns json's RecursionError on a deeply nested value
                # into a refusal. It hides nothing else: pydantic's error still quotes the raw value
                # as input_value.
                parsed, refusal = json_loads_or_refusal(text)
                if refusal is not None:
                    raise ValueError(
                        "[auth].password_extra_context_words looks like a JSON array but does not "
                        f"parse ({refusal}); check its brackets, quotes and commas"
                    )
                return parsed
            return v.split(",")
        return v

    @field_validator("password_extra_context_words")
    @classmethod
    def _check_extra_context_words(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            stripped = raw.strip()
            if not stripped:
                raise ValueError(
                    "[auth].password_extra_context_words holds an empty or whitespace-only entry; "
                    "remove it (an empty term would match every password)"
                )
            if any(c.isspace() for c in stripped):
                # "acme health" would never refuse "AcmeHealth2026". Make the operator choose the
                # spellings rather than guess one for them.
                raise ValueError(
                    f"[auth].password_extra_context_words entry {stripped!r} contains whitespace; "
                    "list each spelling as its own term, for example 'acmehealth' and 'acme'"
                )
            term = stripped.lower()
            # Measured before lower-casing: lower() can lengthen a non-ASCII letter.
            if len(stripped) < EXTRA_CONTEXT_WORD_MIN_LENGTH:
                raise ValueError(
                    f"[auth].password_extra_context_words entry {term!r} is shorter than "
                    f"{EXTRA_CONTEXT_WORD_MIN_LENGTH} characters; the screen is a substring test, "
                    "so a term that short would refuse a large share of ordinary passphrases"
                )
            if term not in out:
                out.append(term)
        return out

    @model_validator(mode="after")
    def _check_extra_context_words_are_screened(self) -> AuthSettings:
        # Site terms only act through the context screen. With it off they would load and do
        # nothing, which reads as a working control. Refused rather than silently ignored.
        if self.password_extra_context_words and not self.password_check_context:
            raise ValueError(
                "[auth].password_extra_context_words is set but password_check_context is false, "
                "so no site term would be screened; turn the check on or remove the terms"
            )
        return self

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

    @field_validator("ad_tls_ca_cert_pin", "oidc_tls_ca_cert_pin")
    @classmethod
    def _refuse_a_blank_ca_cert_pin(cls, v: str | None, info: ValidationInfo) -> str | None:
        return refuse_a_blank_anchor_pin(v, f"[auth].{info.field_name}")

    @field_validator("oidc_tls_crl_file")
    @classmethod
    def _oidc_tls_crl_file_exists(cls, v: str | None) -> str | None:
        return _refuse_a_missing_crl_file(v, "[auth].oidc_tls_crl_file")

    @field_validator("kerberos_spn")
    @classmethod
    def _check_kerberos_spn(cls, value: str | None) -> str | None:
        # Refuse a malformed SPN at load, not at the first browser login (BACKLOG #275).
        if value:
            split_kerberos_spn(value)
        return value

    @field_validator("oidc_clock_skew_seconds")
    @classmethod
    def _check_oidc_skew(cls, value: int) -> int:
        if not 0 <= value <= 300:
            raise ValueError("oidc_clock_skew_seconds must be between 0 and 300")
        return value

    @field_validator("oidc_flow_ttl_seconds")
    @classmethod
    def _check_oidc_flow_ttl(cls, value: int) -> int:
        # Bounded at BOTH ends (BACKLOG #1156, ASVS 10.1.2), because each end fails differently.
        # FLOOR: the value becomes the flow cookie's `Max-Age`, so at or below zero the browser
        # discards the cookie on receipt and every federated login then fails `flow_binding_missing`
        # with nothing naming the cause. CEILING: this is both the single-use replay window for the
        # staged `(state, nonce, code_verifier)` and how long one abandoned flow holds an
        # `oidc_flow_cache_max` slot -- see that field for why the cache rejects rather than evicts.
        #
        # The endpoints are a JUDGMENT with no measured anchor, and no neighbouring field supplies
        # one: every other lifetime and size in this OIDC block is itself unbounded (verified by
        # execution -- `oidc_jwks_ttl_seconds` accepts 10_000_000). What is NOT a judgment is that
        # an unbounded value is wrong in both directions.
        if not 30 <= value <= 1800:
            raise ValueError("oidc_flow_ttl_seconds must be between 30 and 1800")
        return value

    @field_validator("oidc_max_age_seconds")
    @classmethod
    def _check_oidc_max_age(cls, value: int) -> int:
        # Bounded at both ends, and the floor is what makes "no off switch" true. At 0 the IdP must
        # re-authenticate on every sign-in, which is `prompt=login` and destroys single sign-on; a
        # few seconds is that in practice. The 5-minute floor and the 24-hour ceiling are a JUDGMENT
        # with no measured anchor, like the flow-TTL bounds above. The ceiling keeps the knob from
        # quietly becoming "unbounded"; the 12-hour absolute session cap sits below it anyway.
        if not 300 <= value <= 86400:
            raise ValueError(
                "oidc_max_age_seconds must be between 300 and 86400 (there is no off switch: the "
                "IdP authentication recency bound is always enforced when oidc_enabled is set)"
            )
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
        # Must stay FINITE and positive (ASVS 13.1.3): ldap3 treats a None, or a 0 connect_timeout, as
        # "wait forever", which is exactly the unbounded wait these settings exist to remove, and
        # inf/NaN are the same hole by another spelling. (A 0 receive_timeout instead makes the socket
        # non-blocking, so every read fails at once.) Rejected at config load, not at bind time.
        if not value > 0 or value == float("inf"):
            raise ValueError(
                "ad_connect_timeout / ad_receive_timeout must be a finite number of seconds > 0 "
                "(inf, NaN or a None connect timeout would mean an unbounded LDAP wait; 0 or a "
                "negative value would fail every LDAP read or connect)"
            )
        # A huge finite value overflows socket.settimeout / setsockopt (measured from about 3e6 s on
        # Windows) with OverflowError or TypeError. Those are not ldap3 errors, so they would skip
        # the LdapError mapping and the auth.login_error audit. The cap sits far below that point.
        if value > _AD_TIMEOUT_MAX_SECONDS:
            raise ValueError(
                f"ad_connect_timeout / ad_receive_timeout must be at most {_AD_TIMEOUT_MAX_SECONDS:g} "
                f"seconds (got {value:g}); the cap keeps the value far below where a socket "
                "timeout overflows"
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

    @property
    def plain_ldap_bind(self) -> bool:
        """Whether AD is on and its ``ad_server`` is not an LDAPS address (vault BACKLOG #2354).

        Read by at least the opt-in check below, the ``enforce`` refusal in :class:`ServiceSettings`
        and :func:`security_loosenings`. The scheme test is :func:`is_ldaps_address`, which
        ``LdapAuthenticator`` shares."""
        return (
            self.ad_enabled and self.ad_server is not None and not is_ldaps_address(self.ad_server)
        )

    @model_validator(mode="after")
    def _require_ad_fields(self) -> AuthSettings:
        """AD/SSO need their connection essentials present when enabled."""
        if self.ad_enabled and (self.ad_server is None or self.ad_user_search_base is None):
            raise ValueError("ad_enabled requires: ad_server, ad_user_search_base")
        if self.plain_ldap_bind and not self.ad_allow_insecure_ldap:
            raise ValueError(
                "ad_enabled requires an ldaps:// ad_server (credentials go over a SIMPLE bind); "
                "ad_allow_insecure_ldap=true overrides this only under [security].enforcement = warn, "
                "for a trusted-network dev box"
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

        # BLANK, not merely empty — the same test the client-secret guard below already applies, and
        # for the same reason. `if not value` catches "" and lets "   " through, so a stray space in
        # a config file or an NSSM environment entry produced a whitespace-only value that loaded
        # clean. This validator disagreed with itself about what "missing" means: measured before the
        # fix, `oidc_client_id=""` was refused while "   " and "\t" both loaded.
        #
        # It is not cosmetic for `oidc_client_id`, which is the expected `aud` — the ID Token
        # audience check would have compared an incoming claim against whitespace. For the four
        # pinned URLs it deferred the failure to the https check below, which then reports a SCHEME
        # problem for what is really a missing value. Whitespace is stripped for the TEST only; the
        # value itself is never rewritten (BACKLOG #1161, ASVS 10.5.4).
        missing = [
            name
            for name, value in (
                ("oidc_issuer", self.oidc_issuer),
                ("oidc_client_id", self.oidc_client_id),
                ("oidc_authorization_endpoint", self.oidc_authorization_endpoint),
                ("oidc_token_endpoint", self.oidc_token_endpoint),
                ("oidc_jwks_uri", self.oidc_jwks_uri),
            )
            if not (value or "").strip()
        ]
        if missing:
            raise ValueError(f"oidc_enabled requires: {', '.join(missing)}")

        # EMPTY, not just absent. `is None` was the test here, and it let the most common shape of a
        # missing secret straight through: an env var exported with no value. `MEFOR_AUTH_OIDC_CLIENT_SECRET=`
        # in a service wrapper or an NSSM environment entry produces `""`, which is not None, so the guard
        # that exists to make a missing client secret fail at CONFIG LOAD did not fire — the failure moved
        # to the first token exchange, as an IdP rejection an operator has to go read a proxy log to
        # understand. `if not value` is already the emptiness test used by the `missing` list ten lines
        # above; this line was the only one in the validator that disagreed. Whitespace is stripped for the
        # test only — the value itself is never rewritten.
        if (
            not (self.oidc_client_secret or "").strip()
            and not (self.oidc_client_secret_ref or "").strip()
        ):
            raise ValueError(
                "oidc_enabled requires a NON-EMPTY client secret: set oidc_client_secret (via "
                "MEFOR_AUTH_OIDC_CLIENT_SECRET) or oidc_client_secret_ref (a [secrets].provider "
                "reference). An env var exported with no value counts as missing."
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

        # BACKLOG #2032: `oidc_acr_values` is only a REQUEST. It rides the authorization URL, and
        # the claim gate checks the returned `acr` against `oidc_required_acr_values` alone (and
        # only while `oidc_require_mfa_claim` is on), which defaults to empty. So setting just the
        # request would ask the IdP for an assurance class and check nothing that came back.
        # Refused rather than inferred: acr values are not ordered, so treating the requested set
        # as the accepted set would silently turn a request into a requirement. An explicit
        # required list makes the operator state what they accept.
        requested_acr = (self.oidc_acr_values or "").split()
        if requested_acr and not any(v.strip() for v in self.oidc_required_acr_values):
            raise ValueError(
                f"oidc_acr_values requests {requested_acr} from the identity provider, but "
                "oidc_required_acr_values names no acr value, so nothing checks the acr the "
                "identity provider returns. Set oidc_required_acr_values to the acr values this "
                "engine accepts, or remove oidc_acr_values. The gate reads "
                "oidc_required_acr_values only while oidc_require_mfa_claim is true"
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

        # Refuse rather than strip a UPN suffix unchecked (OIDC Core §5.7: preferred_username is
        # neither unique nor stable). Before ADR 0184 an unchecked suffix let a federated principal
        # choose which on-prem account it resolved to; the bound (issuer, sub) pair now selects the
        # account, so this check is defence in depth on the claim.
        if self.oidc_username_strip_domain and not self.effective_oidc_username_domains:
            raise ValueError(
                "oidc_username_strip_domain=true requires oidc_allowed_username_domains (or "
                "[auth].ad_domain to fall back to): the claim's UPN suffix must be checked before "
                "it is stripped. The bound (issuer, sub) pair selects the account, so this check "
                "is defence in depth on the claim"
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

#: Built-in environment names whose **production tier** is derived when ``[security]
#: .production_instance`` is left unset — back-compat with the original dev/staging/prod tiers. A
#: CUSTOM name must set it explicitly (it is never inferred from a free-form string), so a
#: 'test'/'poc' instance can never default permissive (ADR 0017).
#:
#: **This used to carry a data class as well, and no longer does (BACKLOG #1279).** ADR 0148 GIVEN 1
#: had already made all three names derive PHI; what remained was a per-instance opt-out
#: (``[security].handles_real_patient_data = false``) that silenced the whole PHI gate family at
#: once. That combined override is retired: every instance carries patient data, and an operator who
#: needs a specific gate relaxed uses that gate's own switch. The tier below still differs across the
#: three — prod alone is the production tier, which drives the AI data-scope ceiling and the
#: DEBUG-log refusal, not the security refuse/warn dial (that is ``[security].enforcement``).
_KNOWN_ENV_POSTURE: dict[str, bool] = {
    "dev": False,
    "staging": False,
    "prod": True,
}

#: BACKLOG #95 -- the ``[ai].provider`` values the engine can actually SERVICE.
#:
#: **Its source of truth is ``AiBroker.chat``**
#: (:mod:`messagefoundry.transports.ai_broker`), which builds ONE wire shape unconditionally: an
#: Anthropic Messages body with ``x-api-key`` and ``anthropic-version`` headers, and an
#: ``_extract_text`` that assumes Anthropic's content-block list. There is no provider registry, no
#: dispatch, and ``AiBroker.provider`` has zero readers -- so the serviceable set is exactly one entry
#: and NOTHING can derive it. That makes this list hand-maintained, which is a real cost: it decays
#: the moment a second wire shape is added and nobody widens it.
#:
#: **The failure to avoid is the inverse one, and it is the tempting one:** listing aspirational names
#: (``azure_openai``, ``bedrock``, ``ollama``) would ACCEPT configurations the broker still cannot
#: service, turning a clean config-time refusal back into the opaque runtime 502 this validator exists
#: to eliminate. The list must describe what ``chat()`` can send, never what the roadmap intends.
_SERVICEABLE_AI_PROVIDERS = frozenset({"claude"})


class AiSettings(_Section):
    """Central AI-assistance policy plus the instance's active **environment name** and security
    **posture**. The two AI axes (mode + data scope) are bounded by the production-posture ceiling
    computed by :func:`~messagefoundry.config.ai_policy.resolve_effective_policy` (the API endpoint
    and the ``ai-policy`` CLI both clamp these before serving them). See docs/AI.md.

    ``environment`` is the **free-form** active-environment name (ADR 0017): it selects
    ``environments/<name>.toml`` and is what ``current_environment()`` returns. It has **no default** —
    ``serve`` requires it, so a missing env can never silently resolve another environment's
    values/secrets. ``production`` is the explicit production **tier**, **decoupled from the name**:
    for the built-in names dev/staging/prod it is derived when unset, but a custom name must set it
    (see :meth:`require_posture`). There is no data-class axis — every instance carries patient data
    (BACKLOG #1279)."""

    mode: AiMode = AiMode.BYO
    data_scope: AiDataScope = AiDataScope.CODE_ONLY
    # Free-form active-environment NAME (ADR 0017): selects environments/<name>.toml + what
    # current_environment() returns. No default — serve requires it (a missing env must never silently
    # resolve another env's values/secrets).
    environment: str | None = None
    # Explicit production TIER, decoupled from the name. Unset is derived from a built-in name
    # (dev/staging -> non-prod, prod -> prod); a custom name must set it. The refuse/warn dial is
    # [security].enforcement (ADR 0148 GIVEN 2), not `production`.
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

    @field_validator("provider")
    @classmethod
    def _serviceable_provider(cls, v: str) -> str:
        # BACKLOG #95: refuse an unserviced provider at CONFIG time. Previously any string was
        # accepted and the mistake surfaced later as an opaque provider-side failure, or as nothing
        # at all -- the value is recorded in the per-use audit either way, so a config naming a
        # provider the engine cannot service made the audit trail assert something untrue.
        #
        # FIELD-level, so it refuses in EVERY mode rather than only under managed_endpoint. A
        # mode-gated model_validator would be narrower and is the defensible alternative, but the
        # value is audit-visible regardless of mode, and "the engine cannot service this name" is
        # true independently of whether this instance happens to call the broker today.
        if v not in _SERVICEABLE_AI_PROVIDERS:
            allowed = ", ".join(sorted(_SERVICEABLE_AI_PROVIDERS))
            raise ValueError(
                f"[ai].provider must be one of [{allowed}]; got {v!r}. The engine brokers exactly "
                "one wire shape (the Messages API body from Anthropic, in transports/ai_broker.py); a "
                "provider it cannot service is refused here rather than failing at request time."
            )
        return v

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

    def derived_posture(self) -> bool | None:
        """The production **tier** with built-in-name derivation applied when it is unset.

        Still ``None`` when a *custom* environment name leaves it unset — callers that need a definite
        answer use :meth:`require_posture` (fail-closed) or default it to ``True`` (strictest ceiling)
        for an advisory read.

        It no longer returns a data class. Every instance carries patient data (BACKLOG #1279), so
        there is nothing left to derive on that axis and no caller has to ask."""
        if self.production is not None:
            return self.production
        return _KNOWN_ENV_POSTURE.get(self.environment or "")

    def require_posture(self) -> bool:
        """The fail-closed production tier; raises ``ValueError`` when a custom or unset environment
        name has no explicit tier. Used at ``serve`` so a custom env never defaults permissive
        (ADR 0017)."""
        prod = self.derived_posture()
        if prod is None:
            raise ValueError(
                f"environment {self.environment!r} has no built-in security posture (not one of "
                "dev/staging/prod); set [security].production_instance (true|false) explicitly"
            )
        return prod


def hop_posture_from_ai(ai: AiSettings, *, enforcement: SecurityEnforcement) -> HopPosture:
    """The instance's :class:`~messagefoundry.config.tls_policy.HopPosture` for the #200 hop-refusal gate.

    Maps the explicit ``[security].enforcement`` level onto the ``enforcing`` the transport cells
    decide on. ``enforcing`` is ``enforcement is ENFORCE`` (the secure default), which keys the
    REFUSE/WARN dial off the explicit enforcement level rather than the production tier (ADR 0148
    GIVEN 2). The construction gate stamps the result via ``tls_policy.active_hop_posture``
    (ADR 0092).

    **The ``is_phi`` axis is gone (BACKLOG #1279).** It used to key on ``data_class == phi`` being
    explicitly declared, which made a bare/default config's hops non-PHI and left the whole family
    relaxable by one switch. Every instance now carries patient data, so the only question a hop asks
    is whether the instance is enforcing. ``ai`` stays in the signature because the tier it derives is
    still read by the callers that report posture."""
    return HopPosture(enforcing=(enforcement is SecurityEnforcement.ENFORCE))


def _names_this_host(host: str) -> bool:
    """Whether ``host`` is loopback or the unspecified address, for the #1966 gate. Stricter than
    :func:`is_loopback_hop_host`, which fails toward "remote" because it guards a CLEARTEXT hop,
    where "remote" is the cautious answer. Here "remote" is the permissive one, so ``0.0.0.0``,
    ``::``, ``localhost.`` and the IPv4 shorthand ``127.1`` must all count as this host. No DNS."""
    import ipaddress
    import socket as _socket

    h = host.strip().rstrip(".").lower()
    if is_loopback_hop_host(h) or h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        try:
            addr = ipaddress.IPv4Address(_socket.inet_aton(h))  # 127.1, 0 and friends; no DNS
        except OSError:
            return False
    return addr.is_loopback or addr.is_unspecified


def forwarding_gate_refusal(log: LoggingSettings) -> str | None:
    """Why ``log`` fails the R4 (a) forwarding start gate, or ``None`` when it passes (BACKLOG #1966).

    Owner ruling R4 (a) of 2026-09-24 (ASVS 16.4.3, ADR 0200): once the on-disk spool exists, a PHI
    instance under ``[security].enforcement = "enforce"`` refuses to start unless log forwarding is
    configured with verified TLS to a collector that is not on loopback. This is the predicate; the
    caller owns the refuse/warn split.

    **It reads configuration only.** It opens no socket and resolves no name, so a collector that is
    down, or a DNS server that is slow, can never stop a start through it: the ruling keys the gate
    on configuration precisely so a network fault cannot hold a clinical message path down.

    Two things do NOT pass it, on purpose. **Loopback**, because 16.4.3 asks for a logically separate
    system, and a local agent on 127.0.0.1 is the same host; :func:`is_loopback_hop_host` never
    resolves DNS, so a NAME that resolves to loopback does pass, and the collector-separation probe
    that would catch it is #1199's remainder. **``forward_hop_attested``**, because it attests that an
    unprotected hop is secure by other means, and this gate asks whether verified TLS is configured
    at all; letting one flag answer the other's question is how a flag silently widens."""
    if not log.forward_enabled or not log.forward_host:
        return "no off-box collector is configured ([logging].forward_host is unset or forwarding is off)"
    if log.forward_protocol is not SyslogProtocol.TLS:
        return f"[logging].forward_protocol is {log.forward_protocol.value!r}, not 'tls'"
    if not log.forward_tls_verify:
        return "[logging].forward_tls_verify is false, so the collector is not authenticated"
    if _names_this_host(log.forward_host):
        return (
            f"[logging].forward_host {log.forward_host!r} is loopback or unspecified, which is this "
            "host and not a logically separate collector"
        )
    return None


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
    #. ``forward_hop_attested`` → ALLOW — the acknowledged, reasoned opt-out (a trusted management
       segment), the ``[logging]`` sibling of a connection's ``tls_hop_attested``.
    #. the CLAMPED global escape → WARN (never fires under ENFORCE — see
       :func:`hop_insecure_escape_downgrades`).
    #. enforcing → REFUSE. #. else (non-enforcing) → WARN.

    Callers that have not resolved a posture pass the fail-closed one; ``serve`` supplies
    :func:`hop_posture_from_ai`. Pure so the gate is unit-testable without standing up ``serve``.

    **ADR 0153 left this cell keyed on the data label; BACKLOG #1279 removed the label.** 0153's
    scope reasoning stands and is kept: the forwarder is not a connection, so it has nowhere to carry
    a per-hop declaration, and refusing outright would create a deviation the loosening registry
    cannot express. What that reasoning bought was a restated ``not is_phi`` ALLOW arm, and with every
    instance carrying patient data there is no instance left for it to fire on, so it is gone. A
    ``[logging]`` sibling of ``cleartext_accepted`` remains the recorded follow-up and is now the only
    way this cell could express an acceptance."""
    if log.forward_protocol is SyslogProtocol.TLS and log.forward_tls_verify:
        # Verified, CA-anchored TLS (ADR 0080) — an encrypted+authenticated hop, nothing to gate.
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
    exfiltrate it. With ``deny_by_default`` off, each destination list is **opt-in**: empty =
    unrestricted; once a transport's list is set, a destination of that transport not on it is
    **refused at config load/reload** (fail-closed), checked against the resolved
    (``env()``-substituted) destination. The webhook/SMTP *alert* sinks carry no PHI bodies and keep
    their own ``[alerts]`` host allowlists.

    ``deny_by_default`` flips the destination lists fail-closed, so an empty one refuses everything.
    The comment on the field says what else it covers, how operators set it, and when ``serve`` turns
    it on.
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
    # The forward-PROXY host allowlist (BACKLOG #1659). Each entry is "host" (any port) or "host:port".
    # NOT a destination list: it gates the operator-chosen transport INTERMEDIARY an http-family
    # connection dials through, which under `proxy_auth_type = basic` receives a pre-emptive
    # `Proxy-Authorization` header on both destination schemes (ADR 0126) and so is a second
    # credential-bearing egress host. It is deliberately its OWN list rather than an arm of
    # `allowed_http`: ADR 0126 rules the proxy out of that gate's scope, because one corporate proxy
    # fronts many destinations and would have to be co-listed with every one of them.
    #
    # DENY-BY-DEFAULT, matching `[ai].allowed_endpoints` (ADR 0135) rather than the permissive-when-
    # empty `allowed_*` destination lists: an explicit `proxy_url` with an EMPTY `allowed_proxy` is
    # refused at config load. That costs an operator who configures no proxy nothing (the gate only
    # bites once a proxy is set), and it is the whole point of the key -- permissive-when-empty would
    # leave the credential-bearing host ungated on exactly the default posture. The `"default"`
    # sentinel is exempt: it names no address at config time, and `proxy_config_from_settings` refuses
    # to combine it with proxy credentials, so that path mints no `Proxy-Authorization`.
    # Env (comma-separated): MEFOR_EGRESS_ALLOWED_PROXY.
    allowed_proxy: list[str] = []

    # Deny-by-default (Q5b): when true, a transport with an EMPTY allowlist refuses every destination
    # of that type instead of allowing any, and so do at least the DATABASE/REMOTEFILE sources and the
    # db_lookup/fhir_lookup reads that dial through the same lists. Operators set it as
    # [security].block_unlisted_outbound (ADR 0118), which reaches this field only when written.
    #
    # This field's model default is false (the per-list opt-in above), and a caller that loads settings
    # without `serve` sees false. `serve` sets it True whenever it is left unset, with no further
    # condition in the code: since BACKLOG #1279 every instance counts as a PHI instance, so this is
    # any PHI instance. On stock defaults the open-egress gate just before the flip refuses to start
    # first. The code at the flip, in `_serve` in messagefoundry/__main__.py, is the authority.
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
        "proxy_no_proxy",
        "allowed_proxy",
        mode="before",
    )
    @classmethod
    def _split_list(cls, v: object) -> object:
        # Allow setting via env (MEFOR_EGRESS_ALLOWED_MLLP=...) as one comma-separated string.
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


#: How an operator-facing refusal says ``EgressSettings.deny_by_default`` is on (BACKLOG #1361).
#:
#: BOTH ARMS ARE REACHABLE, AND SAYING ONLY "is set" ASSERTS SOMETHING FALSE ON THE COMMON PATH. The
#: operator can write ``[security].block_unlisted_outbound`` -- but ``__main__`` also FLIPS the field on
#: for any PHI instance that left it unset, announcing that as "defaulted ON". An instance that
#: configured nothing is the usual way this refusal fires, so a message reading "is set" tells that
#: operator they set something they did not.
#:
#: Defined once, beside the field, because the six refusal sites live in two other modules
#: (``pipeline/reference_sync.py``, ``pipeline/wiring_runner.py``) and a second copy of this sentence
#: is how five of them stay right while the sixth goes stale.
#:
#: Names the ``[security]`` spelling, not ``[egress].deny_by_default``: ADR 0118 relocated the key and
#: the loader REFUSES the old one as file or env input, so naming it hands out a remediation that dies
#: at load. tests/test_relocated_key_messages.py holds that line.
BLOCK_UNLISTED_OUTBOUND_IN_FORCE = (
    "[security].block_unlisted_outbound is in force (set, or defaulted ON for a PHI instance)"
)


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
        # BACKLOG #305 (ASVS 13.2.2): the store privilege preflight found the store principal
        # over-granted, or could not read it, at start.
        "store_privilege_warning",
        "leadership_acquired",  # #145 (ADR 0014 amendment): a node went non-leader→leader (HA failover / election)
        "dr_activated",  # #145 (ADR 0014 amendment, ADR 0048): a third-tier DR standby was promoted
        # ASVS 6.4.5 (BACKLOG #1141): an admin-issued temporary password is UNCLAIMED and near the
        # instant the login gate stops accepting it (keyed on the holder's username; PHI-free)
        "initial_credential_expiring",
        # #122 (ADR 0162): an application-log sink was rolled after a write failure (stage 1) or is
        # UNWRITABLE and this process's connections were stopped (stage 2). Routable on its own so an
        # operator can page on "the engine went deaf" apart from the per-connection connection_stopped
        # events the stop also emits.
        "log_write_failed",
        # ASVS 8.3.2: a dual-control release was refused because the requester no longer holds the
        # authority the operation needs (deleted, disabled, permission or channel scope withdrawn).
        "approval_stale_requester",
        # BACKLOG #287 (ASVS 2.4.2): a dual-control release refused for arriving before the
        # [approvals].min_dwell_seconds floor. Keyed `approval:<id>`, which no connection can be named.
        "approval_too_early",
        # BACKLOG #315: a release by an approver account changed after the request, and an
        # Administrator grant through the console API.
        "approval_approver_provenance",
        "administrator_granted",
        # ADR 0079 mechanism 2: the directory reconciler's two audited outcomes, each routable apart:
        # the mass-revoke breaker tripped (nothing revoked), and one principal's sessions were revoked.
        "ad_reconcile_aborted",
        "ad_session_revoked",
        # ADR 0195: the reconciler held accounts whose userAccountControl it could not read.
        "ad_reconcile_held",
        # BACKLOG #290 (ASVS 15.2.2): the engine paused intake, because the staged backlog went over
        # [inbound].max_staged_depth or the SQLite volume fell below [retention].min_free_disk_mb.
        # Keyed `intake:<reason>`, which no connection can be named.
        "intake_paused",
        # NOTE: the INVERSE events (leadership_lost / dr_released / intake_resumed) are
        # auto-resolve-only (alert_sinks _AUTO_RESOLVE), NOT rule-targetable alert types -- a
        # step-down, a fail-back or a resumed intake needs no page.
    }
)
#: The transport names a rule may route to; mirror ``AlertTransport.name``.
_ALERT_TRANSPORTS = frozenset({"webhook", "email"})

#: #144 (ADR 0128) — the whitelisted connection-control actions an alert rule may fire on match. Only
#: the two warm-restart primitives (never a bare stop, which would silently wedge a feed with no re-arm);
#: mirror ``RegistryRunner.restart_inbound`` / ``restart_outbound``.
_ALERT_CONTROL_ACTIONS = frozenset({"restart_inbound", "restart_outbound"})

#: BACKLOG #1898: the event types a rule may attach a ``control_action`` to. These are the types
#: whose emitters normally put a connection (or lane) name in the event's ``connection`` key. Every
#: other type puts a stand-in there (a username, an approval id, a DB path, a cert label, a node id).
#: Some stand-ins fit the connection-name grammar, so a restart aimed at one could hit an unrelated
#: real connection. The notifier checks the same set at dispatch (``NotifierAlertSink._emit``).
#:
#: KNOWN GAPS this set does not close, at least these two. First, two emitters raise
#: ``connection_stopped`` with a stand-in: ``reference:<name>`` (pipeline/reference_sync.py) and
#: ``transform-state`` (pipeline/state_convergence.py); the second fits the connection-name grammar.
#: Second, an allowed event can carry an inbound name or an outbound name, and the two are separate
#: namespaces. With no control_target, restart_outbound on an inbound's event, or restart_inbound on
#: an outbound's, aims at whatever connection on the other side shares the bare name.
_ALERT_CONTROL_EVENT_TYPES = frozenset(
    {
        "connection_stopped",
        "connection_error",
        "queue_buildup",
        "message_stall",
        "saturation",
        "lane_stuck",
    }
)

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
    event_type: str = "any"  # "any" | a member of _ALERT_EVENT_TYPES (validated below)
    connection: str = "*"  # fnmatch glob over the connection name; "*" = all
    # `default=` is spelled as a KEYWORD on every Field here, and must stay one: mypy's
    # dataclass_transform support reads only the keyword, so a positional `Field(None, ...)` types
    # the field as REQUIRED and every `AlertRule(...)` call that omits it reads as a missing
    # argument. Runtime is identical either way (BACKLOG #1799 measured 207 such false errors).
    min_depth: int | None = Field(default=None, ge=1)  # queue_buildup: match at/over this depth
    min_oldest_seconds: float | None = Field(
        default=None, ge=0
    )  # queue_buildup/message_stall: …or oldest-message age (s)
    # --- outcome ---
    severity: AlertSeverity = AlertSeverity.WARNING
    transports: list[str] | None = (
        None  # None = every configured transport; [] = suppress entirely (event dropped, never sent)
    )
    cooldown_seconds: float | None = Field(
        default=None, gt=0
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
    # BACKLOG #1898: allowed only with an event_type in _ALERT_CONTROL_EVENT_TYPES; "any" and every
    # other type are refused at load (_check_control_scope below).
    control_action: str | None = None
    # The connection the control action targets. None = the event's own `connection` key (see the
    # KNOWN GAP on _ALERT_CONTROL_EVENT_TYPES); set it to act on a DIFFERENT connection than the one
    # that fired (e.g. restart an inbound when its paired outbound stalls). BACKLOG #1898: when set it
    # must be a connection name and needs a control_action.
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

    @model_validator(mode="after")
    def _check_control_scope(self) -> AlertRule:
        # BACKLOG #1898: the two field validators above each check one field, and nothing related
        # them, so a catch-all rule (event_type "any") or one keyed on a non-connection event could
        # carry a control_action. Its default target is then the event's stand-in key, and a stand-in
        # that fits the connection-name grammar restarts whatever real connection shares that name.
        # Refuse the pair at load. The message names the rule's own label and event type, never a
        # target or any other value.
        rule = f"rule {self.id!r}" if self.id is not None else "a rule"
        if self.control_target is not None:
            # An empty target would fall back to the event's own key at dispatch (`or`), and a
            # target outside the grammar can only fail there, logged and swallowed. A target with
            # no action is dead config. Each is refused here so the rule does what it reads as.
            if self.control_action is None:
                raise ValueError(f"{rule} sets control_target without a control_action")
            if not is_connection_name(self.control_target):
                raise ValueError(f"{rule} sets a control_target that is not a connection name")
        if self.control_action is None or self.event_type in _ALERT_CONTROL_EVENT_TYPES:
            return self
        allowed = ", ".join(sorted(_ALERT_CONTROL_EVENT_TYPES))
        raise ValueError(
            f"{rule} sets control_action with event_type {self.event_type!r}; control_action is "
            f"allowed only with a connection-scoped event_type, one of [{allowed}]"
        )


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
    # #323 layer 3: whether that STARTTLS hop VERIFIES the relay's certificate. True (the default) builds
    # an explicit verifying context via tls_policy.build_smtp_tls_context; before #323 there was no
    # context at all and smtplib's fallback verified NOTHING (CERT_NONE, check_hostname=False), so the
    # hop was encrypted but unauthenticated. FALSE is an audited loosening: it is named by
    # security_loosenings() and REFUSED at the serve gate on an enforcing PHI instance unless
    # [security].allow_unverified_alert_smtp_tls is also set. Only meaningful when email_use_tls=true.
    email_tls_verify: bool = True
    # PEM bundle of trust anchors for that hop. None (the default) = the [tls] internal-CA policy if one
    # is configured, else the OS trust store. A path, not a secret — same status as [tls].internal_ca_file.
    email_tls_ca_file: str | None = None
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
    # push channel, not just the pull-only /me/security-events feed. That feed carries the user's own
    # events, not an administrator's change to their account (auth/notifications.py states the rule).
    # Set false to accept the pull-only feed in writing (the explicit, audited opt-out). Ignored on a synthetic/non-PHI instance. See
    # messagefoundry/__main__.py. BACKLOG #2008 (ASVS 6.4.5): the same gate also requires a credential-
    # reminder RECIPIENT (webhook_url, or email_to beside host + sender), and false waives that too.
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


def _vip_address_problems(address: str | None, mask: str | None) -> list[str]:
    if address is None:
        return ["address is required"]
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return [f"address must be an IPv4 address (IPv6 is deferred), got {address!r}"]
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return [
            f"address {address!r} cannot float between nodes: it is unspecified, loopback, "
            "link-local, multicast or reserved"
        ]
    if mask is not None:
        net = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
        # A /31 or /32 has no network or broadcast address; every address in it is a host.
        if net.prefixlen <= 30 and ip in (net.network_address, net.broadcast_address):
            return [f"address {address!r} is the network or broadcast address of {net}"]
    return []


def _vip_interface_problems(interface: str | None) -> list[str]:
    if interface is None or not interface.strip():
        return ["interface is required (this node's Windows connection name, e.g. 'Ethernet0')"]
    if interface != interface.strip():
        # Refused rather than trimmed: the address is scoped to one exact interface name, and a
        # silently trimmed name is a second spelling of it.
        return [f"interface {interface!r} has leading or trailing whitespace"]
    if '"' in interface or not interface.isprintable():
        # The name ends up as a command-line argument on the elevated side (ADR 0056 "Platform
        # mechanics"). Refusing a quote or a control character here is cheaper than trusting every
        # quoting layer between the file and that argument.
        return [f"interface {interface!r} contains a double quote or a non-printable character"]
    return []


class ClusterVipSettings(_Section):
    """``[cluster.vip]`` — the engine-managed virtual IP (ADR 0056), a sub-table of ``[cluster]``.

    **Configuration and load-time checks only.** Nothing in this build binds, releases or announces the
    address; the controller is a later change, so :func:`load_settings` logs a WARNING when this is on.
    **Windows-only** at v1, and IPv4 only.

    ``enabled = false`` (the default) is a complete no-op: every check is gated on it, so a switched-off
    block is never refused for what it holds (AC-6). The checks that need ``[cluster]`` live on
    :meth:`ClusterSettings._vip_fits_the_cluster`. File-only: the env layer is one level deep, so there
    is no ``MEFOR_CLUSTER_VIP_*`` override (docs/CONFIGURATION.md)."""

    enabled: bool = False
    # The floating address. IPv4 only (IPv6 is deferred on every platform, ADR 0056).
    address: str | None = None
    # This node's adapter, by its Windows connection name (e.g. "Ethernet0").
    interface: str | None = None
    # Exactly one of these two when enabled; both resolve to `mask` below.
    prefix: int | None = None
    netmask: str | None = None
    # Announce the address with an IPv4 gratuitous ARP once it is bound.
    gratuitous_arp: bool = True
    # How long a newly promoted leader waits before it binds and announces the address. Must be >= 0 and
    # < [cluster].leader_fence_timeout_seconds; ADR 0056 D2 says why 2.0, and why that bound.
    release_grace_seconds: float = 2.0

    @property
    def mask(self) -> str | None:
        """The dotted-decimal IPv4 netmask the helper's ``bind`` request carries (ADR 0056 D2), e.g.
        ``"255.255.255.0"`` from either ``prefix = 24`` or ``netmask = "255.255.255.0"``. ``None``
        unless exactly one form is set and valid, which a loaded, enabled block always satisfies."""
        if (self.prefix is None) == (self.netmask is None):
            return None
        spelled = self.netmask if self.netmask is not None else str(self.prefix)
        try:
            net = ipaddress.IPv4Network(f"0.0.0.0/{spelled}")
        except ValueError:
            return None
        # A netmask must round-trip unchanged: ipaddress also reads "0.0.0.255" as a HOSTMASK and "24" as
        # a prefix, and either would otherwise load as a mask nobody wrote.
        if net.prefixlen < 1 or (self.netmask is not None and str(net.netmask) != self.netmask):
            return None
        return str(net.netmask)

    @model_validator(mode="after")
    def _enabled_block_is_usable(self) -> ClusterVipSettings:
        """Refuse, at load rather than at the first bind, a switched-on block the helper could not act
        on. Every problem is reported in one pass, not one restart per typo."""
        if not self.enabled:
            return self
        mask = self.mask
        problems = [
            *_vip_address_problems(self.address, mask),
            *_vip_interface_problems(self.interface),
        ]
        if self.prefix is not None and self.netmask is not None:
            problems.append("set prefix or netmask, not both")
        elif self.prefix is None and self.netmask is None:
            problems.append("set one of prefix or netmask")
        elif mask is None and self.prefix is not None:
            problems.append(f"prefix must be 1-32, got {self.prefix}")
        elif mask is None:
            problems.append(
                "netmask must be a contiguous dotted-decimal IPv4 netmask such as '255.255.255.0', "
                f"got {self.netmask!r}"
            )
        # Written as a positive test so a NaN fails it too.
        if not self.release_grace_seconds >= 0:
            problems.append(f"release_grace_seconds must be >= 0, got {self.release_grace_seconds}")
        if problems:
            raise ValueError("[cluster.vip] is enabled but cannot be used: " + "; ".join(problems))
        return self


def _fence_tick_seconds(fence_timeout_seconds: float) -> float:
    """The self-fence watchdog's poll interval, as a function of the fence timeout.

    A SECOND copy of ``messagefoundry.pipeline.cluster.fence_tick_seconds``, which is the definition.
    It is copied rather than imported because ``config/`` is the leaf layer and ``pipeline/`` imports
    it, so importing back would invert the dependency — and :class:`DbCoordinator` deliberately
    duck-types its settings for the same reason. A copied safety constant is a drift hazard, so
    ``tests/test_adr0157_inc0_margin.py`` pins the two equal across a range of inputs. Do not "fix"
    this by importing; fix it by keeping the test green."""
    return max(0.05, min(1.0, fence_timeout_seconds / 5.0))


def _detection_margin_seconds(fence_timeout_seconds: float, lease_ttl_seconds: float) -> float:
    """The demotion DETECTION MARGIN: what is left of the lease after the fence timeout elapses.

    ``ttl - fence - fence_tick``. The watchdog polls once per tick, so detection lands up to one tick
    after the fence timeout, and the tick is why this is not simply ``ttl - fence``. Everything the
    ex-leader still has to do -- tear the graph down, and stop a renew it issued before it fenced --
    has to fit inside this remainder. Written once here because three callers below need it."""
    return lease_ttl_seconds - fence_timeout_seconds - _fence_tick_seconds(fence_timeout_seconds)


#: Absolute cap on the DERIVED renew clamp. A renew is one small UPDATE; waiting longer than this for
#: it is pathological whatever the lease timings are. It binds only when the margin exceeds 10.0 s, so
#: it does not bind at the shipped 10/20/30 (margin 9.0, derived 4.5).
_RENEW_CLAMP_CEILING_SECONDS = 5.0

#: Share of the detection margin the derived renew clamp may take. Deliberately the same 0.5 as
#: ``pipeline.cluster._DEMOTE_BUDGET_FRACTION``, off the same margin, because the two things that must
#: fit inside it are CONCURRENT, not sequential: at the fence moment the ex-leader starts tearing the
#: graph down while a renew it issued beforehand may still be in flight. Each gets half, each is
#: strictly inside the margin, and neither has to know the other's number.
_RENEW_CLAMP_MARGIN_FRACTION = 0.5

#: FLOOR on the derived clamp, and the reason it exists is a LIVENESS bound the margin does not see.
#: The clamp is asyncpg's per-statement timeout on the lease renew, so a renew slower than it RAISES
#: and ``_last_renew_ok`` is not advanced; enough consecutive failures and the watchdog self-fences a
#: leader whose database was merely slow. The margin bounds the clamp from ABOVE (correctness: a stray
#: renew must not outlive the fence). Nothing in the margin bounds it from BELOW, and at a tight
#: fence/TTL pair ``0.5 * margin`` lands at 0.6-0.7 s -- a plausible latency for one small UPDATE on a
#: loaded server, which would turn a slow DB into a spurious failover. 1.0 s is a sane floor for a
#: single-row UPSERT. A pair whose margin cannot fit even this is refused by the check below rather
#: than run with a clamp that would fence it; see :meth:`ClusterSettings._renew_fits_the_margin`.
_RENEW_CLAMP_FLOOR_SECONDS = 1.0


def _derived_renew_timeout_seconds(margin_seconds: float) -> float:
    """The renew clamp for an operator who did not set one, from the two bounds it sits between.

    A FIXED default cannot do this job. The clamp's correctness requirement is ``clamp < margin``,
    and the margin is a function of the fence/TTL pair, so any constant is wrong for some legitimate
    pair -- a fixed 5.0 refused this repository's own failover profiles
    (``harness/load/profiles/failover.toml``, margin 1.2 s) at config load. Deriving it means a tight
    fence/TTL pair gets a proportionally tight clamp rather than a refusal.

    **But the margin is only the UPPER bound, and deriving from it alone is how this went wrong
    once.** The first cut returned ``min(ceiling, 0.5 * margin)`` with no floor, which at those same
    failover profiles is 0.6-0.7 s. That is a per-statement timeout on the lease renew, so it trades
    a config-load refusal for a RUNTIME one: a renew slower than the clamp raises, the fence baseline
    is not advanced, and a merely-slow database self-fences the leader. The floor is the lower bound
    that the margin cannot express.

    **So the result is CHECKED, not correct by construction.** With a floor in it this can exceed a
    small margin -- deliberately, because that pair cannot carry a safe clamp and should be refused
    rather than quietly run at a fencing one. :meth:`ClusterSettings._renew_fits_the_margin` applies
    the same comparison to this value as to an operator's own.

    An EXPLICIT value is never silently clamped to this -- it is checked and refused, because quietly
    overriding an operator's number would make the check unfalsifiable."""
    return max(
        _RENEW_CLAMP_FLOOR_SECONDS,
        min(_RENEW_CLAMP_CEILING_SECONDS, _RENEW_CLAMP_MARGIN_FRACTION * margin_seconds),
    )


#: The largest ``[cluster].acquire_delay_seconds`` the config accepts (BACKLOG #2539). Picked, not
#: derived; ``ClusterSettings._nonneg_acquire_delay`` says why. The stepdown pause also clamps a
#: sibling delay to it (``pipeline.cluster.stepdown_pause_seconds``), because that delay is read
#: back from a ``nodes`` row, which something other than this validator may have written.
MAX_ACQUIRE_DELAY_SECONDS = 3600.0


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
    # monotonic clock, with NO DB I/O so a hung/partitioned DB can't block it) stops reporting itself
    # leader. MUST be < leader_lease_ttl_seconds so it does so BEFORE the lease can expire and a standby
    # acquire. MUST be > heartbeat_seconds so a single missed renew doesn't fence. _fence_ordering below
    # enforces exactly that ordering — and ONLY the ordering.
    #
    # What the ordering does NOT establish, for anyone sizing these down from the defaults: detection
    # lands up to one fence tick late, so the usable margin is (ttl - fence - fence_tick) and NOT
    # (ttl - fence). _renew_fits_the_margin below checks that remainder against the renew clamp. The
    # renew round trip is no longer a term in it — ADR 0157 Inc 0 stamps the fence baseline BEFORE the
    # renew is issued, so the baseline is never later than the DB clock's own lease stamp — and the
    # prose that used to subtract it here was left over from the pre-Inc-0 ordering. Fencing still does
    # not stop the graph: it flips a boolean, and the listeners and in-flight sends wind down on the
    # DEMOTE teardown budget (ADR 0157 Inc 4/5), which is derived from that same remainder. The shipped
    # 10/20/30 leave real slack; tightened values consume it silently.
    leader_fence_timeout_seconds: float = 20.0
    # ADR 0157 Inc 0 — the CLAMP on the leadership-lease acquire/renew round trip. Before this the renew
    # inherited `[store].command_timeout` (30 s), which EQUALS the stock lease TTL, so a self-fenced node
    # could keep a renew in flight long enough to extend its own lease well past the moment it stopped
    # calling itself leader. That is a liveness cost, not a split-brain one (the fence baseline is
    # stamped before the renew is issued, so the detection margin holds either way) — a standby cannot
    # take over until the lease it just re-extended expires again.
    #
    # SCOPE, stated because a control that claims more than it covers is worse than none: this clamps
    # the POSTGRES coordinator, where it is asyncpg's own per-statement `timeout=`. The SQL Server
    # coordinator's renew still inherits `[store].command_timeout` from the ODBC connection, because a
    # per-statement override there lives in `store/sqlserver.py`. That is a NAMED, open residual of
    # ADR 0157 Inc 0 — not something this setting silently covers.
    #
    # UNSET (the default) means DERIVED from the detection margin, not a fixed number: half the margin,
    # capped at 5.0 s and floored at 1.0 s. The floor is a LIVENESS bound the margin cannot express --
    # this value is the renew's per-statement timeout, so a clamp below a realistic latency for one
    # small UPDATE self-fences a leader whose DB was merely slow. A fixed default cannot be right
    # either. The clamp's correctness requirement is
    # `clamp < (ttl - fence - fence_tick)`, which is a function of the fence/TTL pair, so a constant is
    # wrong for some legitimate pair -- a fixed 5.0 refused this repository's own failover profiles
    # (fence 4.0 / ttl 6.0, margin 1.2 s) at config load. Deriving it gives a tight pair a
    # proportionally tight clamp instead of a refusal, and the default can never contradict the margin
    # by construction. At the shipped 10/20/30 the margin is 9.0 s and this resolves to 4.5.
    #
    # Set it EXPLICITLY and it is checked, not clamped: a value that does not fit the margin is
    # REFUSED at config load (_renew_fits_the_margin below). Silently shrinking an operator's number to
    # fit would make the check unfalsifiable -- it would accept everything. Must be > 0.
    lease_renew_timeout_seconds: float | None = None
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
    # to control cold bring-up. Must be between 0 and 3600 (BACKLOG #2539).
    acquire_delay_seconds: float = 0.0
    # NON-PROMOTABLE standby flag (ADR 0096). True (default) = a normal HA node. False = this node may
    # NEVER become leader: it never inserts a fresh lease, never takes over an expired one, and does not
    # renew, so it can neither acquire nor retain leadership — a node that somehow already holds the lease
    # steps down cleanly on its next maintenance tick (the fence watchdog is the backstop). Use it for a
    # warm DR-site engine that must stay passive/read-only until an operator promotes it out-of-band. At
    # least ONE promotable node MUST exist in the cluster, or no node ever acquires the lease and the graph
    # never drains — an all-non-promotable cluster is a misconfiguration (documented, not guarded here).
    promotable: bool = True
    # Engine-managed virtual IP (ADR 0056): the [cluster.vip] sub-table. Off by default, and a no-op
    # while off. See ClusterVipSettings.
    vip: ClusterVipSettings = Field(default_factory=ClusterVipSettings)

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

    @field_validator("lease_renew_timeout_seconds")
    @classmethod
    def _positive_renew_clamp(cls, value: float | None) -> float | None:
        # Split out of _positive above because None is this field's "derive it" sentinel, and the
        # shared validator would compare None to 0. There is deliberately no "0 disables" escape
        # hatch: an unbounded renew is the defect the knob removes.
        if value is not None and value <= 0:
            raise ValueError("must be > 0 (leave it unset to derive it from the detection margin)")
        return value

    @field_validator("acquire_delay_seconds")
    @classmethod
    def _nonneg_acquire_delay(cls, value: float) -> float:
        # 0.0 (the default) = no handicap; a negative delay would let a node claim BEFORE the lease
        # expires (a two-leader window), so it is rejected at config load.
        #
        # BACKLOG #2539: bounded above too. A planned stepdown pauses the drained node for the
        # longest promotable sibling's delay, so a typo of a few extra digits on any one sibling
        # left that node unable to reclaim for hours, and an infinite or NaN delay could never be
        # met at all. 3600 s is picked, not derived: the docs only ever describe delays of seconds
        # to minutes, and an hour leaves ample room above that.
        if not 0 <= value <= MAX_ACQUIRE_DELAY_SECONDS:
            raise ValueError(
                "acquire_delay_seconds must be between 0 and "
                f"{MAX_ACQUIRE_DELAY_SECONDS:g} (0 disables the leader-preference handicap)"
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

    @model_validator(mode="after")
    def _renew_fits_the_margin(self) -> ClusterSettings:
        """Resolve the renew clamp against the detection margin, and refuse a pair that has none.

        The MARGIN check ``_fence_ordering`` does not make (ADR 0157 Inc 0). ``_fence_ordering``
        establishes ``fence < ttl`` and stops there, so it accepts a pair whose remaining margin --
        ``ttl - fence - fence_tick``, see :func:`_detection_margin_seconds` -- is a fraction of a
        second, or negative.

        Three outcomes, in order:

        1. **No margin at all** (``<= 0``, or NaN): refused, naming the fence/TTL pair. ``_fence_ordering``
           accepts such a pair -- fence 4.0 / TTL 4.5 orders fine and leaves -0.3 s. **This branch changes
           the MESSAGE, not the verdict:** step 3 refuses the same pair anyway, because a derived clamp
           off a negative margin is itself negative and fails the comparison. It is here so the operator
           is told their fence/TTL pair has no margin, instead of being told to lower a clamp they never
           set; do not describe it as catching something step 3 misses.
        2. **Clamp unset**: DERIVED (:func:`_derived_renew_timeout_seconds`) and filled in here, so every
           consumer downstream reads a concrete float. The derivation carries a FLOOR, so it is **not**
           correct by construction and is not trusted -- it falls through to step 3 like any other value.
           A margin too small to fit the floor is a pair that cannot carry a safe clamp, and is refused
           rather than run at one that would self-fence a merely-slow leader.
        3. **The comparison, applied to whichever value step 2 left**: it must be strictly below the
           margin, or refused. An explicit value is never silently clamped to fit: a check that rewrites
           its subject to pass accepts everything, which is the same as not checking. An operator who
           tightens the fence/TTL pair under a pinned clamp gets told.

        **It is not a proof that the teardown fits** -- the DEMOTE budget (ADR 0157 Inc 4/5) is derived
        from the same margin and bounds the source phase only.

        **Backend scope.** ``lease_renew_timeout_seconds`` clamps the Postgres coordinator's renew.
        The SQL Server coordinator's renew still inherits ``[store].command_timeout``, an open ADR 0157
        Inc 0 residual, so on that backend this checks a value the renew does not yet use. Said here
        rather than left to be inferred from a green config load."""
        tick = _fence_tick_seconds(self.leader_fence_timeout_seconds)
        margin = _detection_margin_seconds(
            self.leader_fence_timeout_seconds, self.leader_lease_ttl_seconds
        )
        # Written as positive tests so a NaN fails them too, as _vip_fits_the_cluster is.
        if not margin > 0:
            raise ValueError(
                "cluster lease timing leaves NO demotion detection margin: "
                "(leader_lease_ttl_seconds - leader_fence_timeout_seconds - the fence tick) must "
                "be > 0 "
                f"(got leader_lease_ttl_seconds={self.leader_lease_ttl_seconds}, "
                f"leader_fence_timeout_seconds={self.leader_fence_timeout_seconds}, "
                f"fence tick={tick}, so the margin is {margin}) -- the self-fence watchdog polls once "
                "per tick, so detection can land at or after the moment the lease expires and a "
                "standby acquires it. Widen the gap between leader_fence_timeout_seconds and "
                "leader_lease_ttl_seconds; no lease_renew_timeout_seconds fits this pair"
            )
        if self.lease_renew_timeout_seconds is None:
            self.lease_renew_timeout_seconds = _derived_renew_timeout_seconds(margin)
        # The derived value FALLS THROUGH the same check rather than returning early, and since the
        # derivation gained a floor it can genuinely fail here: any margin at or below the floor. That
        # is the intended refusal -- such a pair cannot carry a clamp that is both inside the margin
        # and long enough for one small UPDATE, so running it would self-fence a merely-slow leader.
        # Checked beats asserted in any case: mutating the derivation back to a fixed 5.0 makes this
        # refuse the repository's own failover profiles instead of silently handing them an oversized
        # clamp.
        if not self.lease_renew_timeout_seconds < margin:
            raise ValueError(
                "cluster lease timing leaves no room for the renew clamp: "
                "lease_renew_timeout_seconds must be < (leader_lease_ttl_seconds - "
                "leader_fence_timeout_seconds - the fence tick) "
                f"(got lease_renew_timeout_seconds={self.lease_renew_timeout_seconds}, "
                f"leader_lease_ttl_seconds={self.leader_lease_ttl_seconds}, "
                f"leader_fence_timeout_seconds={self.leader_fence_timeout_seconds}, "
                f"fence tick={tick}, so the margin is {margin}) -- a renew still in flight when this "
                "node self-fences can re-extend the lease it is standing down from, and a standby "
                "cannot take over until that extension expires. Lower lease_renew_timeout_seconds, "
                "unset it to derive it from the margin, or widen the gap between the fence timeout "
                "and the TTL"
            )
        return self

    @model_validator(mode="after")
    def _vip_fits_the_cluster(self) -> ClusterSettings:
        """``[cluster.vip]`` needs clustering on, and its grace must end inside the leadership term that
        started it, the rule :meth:`ServiceSettings._warm_pool_timeout_under_fence` applies to a pool
        warm-up. Unlike that rule this one binds the default too; ADR 0056 D2 says why. The server-DB
        half of AC-8 needs no check here: :meth:`ServiceSettings._cluster_requires_server_db` already
        refuses any clustered node without one."""
        if not self.vip.enabled:
            return self
        if not self.enabled:
            raise ValueError(
                "[cluster.vip].enabled requires [cluster].enabled = true: the address follows the "
                "leadership lease, and only a clustered node holds one"
            )
        grace = self.vip.release_grace_seconds
        # Written as a positive test so a NaN fails it too.
        if not grace < self.leader_fence_timeout_seconds:
            raise ValueError(
                "[cluster.vip].release_grace_seconds must be < [cluster].leader_fence_timeout_seconds "
                f"(got release_grace_seconds={grace}, "
                f"leader_fence_timeout_seconds={self.leader_fence_timeout_seconds}); a newly promoted "
                "leader's bind must come due before its own fence could fire. Set a smaller "
                "release_grace_seconds explicitly when you shorten the fence timeout."
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


#: The store DEK's secret-class id. It is NOT a valid ``enforce_secret_expiry_classes`` entry: the DEK
#: has its own refusal, ``enforce_store_key_expiry``, which defaults ON.
STORE_DEK_SECRET_CLASS = "MEFOR_STORE_ENCRYPTION_KEY"  # nosec B105 - an env-var NAME, not a value

#: The ``enforce_secret_expiry_classes`` token for every per-Connection ``env()`` connector credential.
#: Those are keyed by operator-chosen env names that are unknown at settings load, so they opt in as
#: one class rather than by name.
CONNECTOR_SECRET_EXPIRY_CLASS = "connector"  # nosec B105 - a class TOKEN, not a secret value

#: Every name ``[secret_rotation].enforce_secret_expiry_classes`` accepts (ASVS 13.3.4, BACKLOG #1932):
#: the fixed ``MEFOR_*`` classes the rotation watcher fingerprints, plus the connector token. Kept equal
#: to ``pipeline.secret_rotation._ENV_SECRET_CLASSES`` by ``tests/test_secret_expiry_opt_in.py``; it
#: lives here because config must not import the pipeline.
ENFORCEABLE_SECRET_EXPIRY_CLASSES: frozenset[str] = frozenset(
    {
        "MEFOR_STORE_PASSWORD",
        "MEFOR_AUTH_AD_BIND_PASSWORD",
        "MEFOR_ALERTS_EMAIL_PASSWORD",
        "MEFOR_AUTH_OIDC_CLIENT_SECRET",
        "MEFOR_API_TLS_KEY_PASSWORD",
        "MEFOR_STORE_VAULT_TOKEN",
        "MEFOR_SECRETS_VAULT_TOKEN",
        "MEFOR_AI_API_KEY",
        CONNECTOR_SECRET_EXPIRY_CLASS,
    }
)


class SecretRotationSettings(_Section):
    """Periodic **secret-rotation reminder** (``[secret_rotation]``, ADR 0019 §5, BACKLOG #195b). Long-
    lived secrets (the store data-encryption key today; connector credentials in a future
    ``SecretProvider`` follow-on) have no natural expiry the way a TLS cert does, so nothing tells an
    operator when one is overdue for rotation. This is the secret-side twin of ``[cert_monitor]``: the
    engine periodically compares each tracked secret's **operator-configured last-rotated date** against
    its **max age** and raises a ``secret_rotation_due`` alert when it is overdue or within ``warn_days``
    of due. It reads **only** the rotation *dates* an operator supplied here — never any secret value
    (PHI-free). Set ``warn_days`` to 0 to disable the reminder.

    **The store DEK's calendar expiry is ENFORCED, not merely announced** (ASVS 13.3.4, BACKLOG #1004).
    Under ``[security].enforcement=ENFORCE`` with a keyed store, a DEK past ``store_key_max_age_days +
    enforce_grace_days`` — or one whose age cannot be determined at all — **aborts engine start**
    (``StoreKeyRotationOverdueError``), alongside the escalated alert rather than instead of it. That
    matches the same key's **usage** axis, which has always refused unconditionally at ``2**32``
    encrypts. ``enforce_store_key_expiry = false`` keeps the alert and drops the refusal; it is a
    reported security loosening, not a quiet switch.

    **The other classes refuse only when the operator opts them in** (BACKLOG #1932).
    ``enforce_secret_expiry_classes`` names the non-DEK classes whose calendar expiry refuses the same
    way, on ``secret_max_age_days + enforce_grace_days``. It ships empty, so a class not named there
    keeps its alert-only behaviour. Opting in tightens the posture; leaving it empty is not reported
    as a loosening.

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
    # The opt-in non-DEK refusal (enforce_secret_expiry_classes) uses the same grace.
    enforce_grace_days: int = 30
    # ASVS 13.3.4 / BACKLOG #1004 — the calendar axis REFUSES, not just alerts. Under
    # [security].enforcement=ENFORCE with a keyed store, a DEK past store_key_max_age_days +
    # enforce_grace_days (or one whose age cannot be determined) aborts engine start. Default TRUE:
    # the DEK's USAGE axis already refuses unconditionally at 2**32 encrypts, so a calendar axis
    # shipping OFF would be strictly weaker than its own sibling on the same key, and a default-off
    # build would buy the setting without the posture. Setting it false is a LOOSENING and
    # security_loosenings() names it, so the opt-out is never silent.
    enforce_store_key_expiry: bool = True
    # ASVS 13.3.4 / BACKLOG #1932 — the calendar refusal for the NON-DEK classes, OPT-IN per class.
    # Each entry names one class from ENFORCEABLE_SECRET_EXPIRY_CLASSES. Under
    # [security].enforcement=ENFORCE, a named class the engine holds that is past
    # secret_max_age_days + enforce_grace_days (or whose age cannot be determined) aborts engine start,
    # alongside an enforced alert. Default EMPTY, so every class not named here keeps the alert-only
    # behaviour it has always had; an unknown name is refused at load rather than silently ignored.
    enforce_secret_expiry_classes: list[str] = []

    @field_validator("enforce_secret_expiry_classes", mode="before")
    @classmethod
    def _split_expiry_classes(cls, v: object) -> object:
        # Accept one comma-separated string as well as a TOML array. There is no MEFOR_* env route to
        # this field: _env_overrides splits the section name at the first '_', so "secret_rotation"
        # is never reached from the environment.
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("enforce_secret_expiry_classes", mode="after")
    @classmethod
    def _check_expiry_classes(cls, v: list[str]) -> list[str]:
        # Refuse an unknown name at LOAD. A typo that was silently ignored would leave the operator
        # believing a class refuses when it only alerts, which is the exact gap this setting closes.
        out: list[str] = []
        for entry in v:
            if entry == STORE_DEK_SECRET_CLASS:
                raise ValueError(
                    f"[secret_rotation].enforce_secret_expiry_classes entry {entry!r} is the store "
                    "data-encryption key, which has its own refusal: use "
                    "[secret_rotation].enforce_store_key_expiry"
                )
            if entry not in ENFORCEABLE_SECRET_EXPIRY_CLASSES:
                raise ValueError(
                    f"[secret_rotation].enforce_secret_expiry_classes entry {entry!r} is not a "
                    "tracked secret class; valid entries: "
                    + ", ".join(sorted(ENFORCEABLE_SECRET_EXPIRY_CLASSES))
                )
            if entry not in out:
                out.append(entry)
        return out

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
    but **alert-only** (it never blocks startup). An install that **declares** itself editable
    (``pip install -e .``) is a NO-OP regardless, so dev is never bricked. An install that merely *has no
    usable baseline* is not that no-op (BACKLOG #1679): it verified nothing, so it warns, audits and
    alerts, and under ``fail_closed_on_drift`` it refuses to start (see messagefoundry/integrity.py)."""

    # Run startup attestation at all. On by default (alert-only is harmless); a no-op off an editable
    # install. Set false only to suppress the check entirely (e.g. an unusual packaging where RECORD is
    # known-stale) — you then lose the in-place-tamper tripwire.
    enabled: bool = True
    # When true, drift (a loaded engine module not matching its RECORD hash) makes serve REFUSE to start
    # (after recording the audit row + alerting). Default false = alert-only: a legitimate reviewed
    # in-place security hotfix (the documented vendored-parser patch contingency) would itself trip a
    # RECORD mismatch, so fail-closed-by-default would brick a legitimate patch. Opt in for hard
    # enforcement on a locked-down instance.
    # It ALSO refuses when attestation verified NOTHING — no baseline, a RECORD stripped of its package
    # rows, or the package loaded from outside the install root (BACKLOG #1679). A pass that compared
    # zero files cannot say the bytes are clean, and stripping the baseline is easier for the stated
    # adversary than editing a module. An install that declares itself editable is still exempt.
    fail_closed_on_drift: bool = False
    # When true, the engine re-walks the tamper-evident audit hash-chain once at startup (#190). This is
    # ALERT-ONLY: a broken chain logs a WARNING + fires the AlertSink but NEVER crashes startup (a
    # refuse-to-start on a tripped tamper alarm would be a self-inflicted DoS). Default false — opt in;
    # on a very large audit_log the full re-walk adds startup latency, so it is not on by default.
    audit_verify_on_start: bool = False
    # Path to a file holding one COUNT:HEAD anchor as printed by `messagefoundry audit-anchor` (BACKLOG
    # #328). Empty (the default) = the startup walk stays the bare walk it is today, byte-identical.
    #
    # WHAT IT BUYS: the walk alone cannot see a TRUNCATED TAIL — deleting the newest rows leaves a prefix
    # that still chains cleanly — so audit_verify_on_start on its own is blind to exactly what an
    # attacker hiding their tracks would do. An anchor is the external witness that catches it.
    #
    # THE ENGINE CONSUMES IT AS A PREFIX, NOT AS THE CLI'S EXACT SEAL, and that difference is why this
    # key can exist at all. `audit-verify --expected-anchor` compares the CURRENT head, so it diverges
    # the moment one more row is appended; a running engine writes audit rows, so a startup check built
    # on the exact seal would alarm on essentially every restart. This feeds `expected_prefix`
    # (`audit_prefix_verdict`) instead, which asks the weaker, survivable question: was the recorded
    # state ever true, and has the chain only GROWN since? It still catches a truncated tail and a
    # mid-chain rewrite. So a stale anchor stays VALID here — it just witnesses less.
    #
    # ALERT-ONLY, like its partner: a missing, unreadable or malformed anchor logs a WARNING and lets the
    # bare walk run. It never crashes startup, and it never fires the tamper alert — a config fault must
    # not manufacture a tamper alarm, or a real one stops meaning anything. `0:`, the anchor of an empty
    # log, is refused the same way: it can witness nothing, so it is reported rather than compared.
    #
    # It does nothing on its own: without audit_verify_on_start the engine warns at startup that the
    # anchor is never read.
    audit_anchor_file: str = ""


class ApprovalsSettings(_Section):
    """Optional dual-control (maker-checker) approval for high-value actions (``[approvals]``, ASVS
    2.3.5). **Off by default** so a single-operator deployment is never blocked. When ``enabled``, an
    action in ``operations`` is held as a pending request and must be released by a *distinct* second
    user holding ``approvals:approve`` — the requester can never approve their own. A request older than
    ``expiry_hours`` can no longer be approved, and one younger than ``min_dwell_seconds`` cannot be
    approved YET.

    ``min_dwell_seconds`` is the FLOOR beside ``expiry_hours``' CEILING (ASVS 2.4.2, BACKLOG #287). An
    approve that arrives sooner gets a 409 and an ``approval.too_early`` audit row.

    **The default (2.0 s) is PROVISIONAL.** It comes from published human-timing research, not from a
    timed session (owner ruling 2026-09-23). Source: Card, Moran and Newell, "The keystroke-level model
    for user performance time with interactive systems", Communications of the ACM 23(7), 1980,
    pp. 396-410. How the default follows from it, and what the floor does not do, is stated once in
    docs/SECURITY.md under "Dual-control approval for high-value actions". Change the two together."""

    enabled: bool = False
    operations: list[str] = Field(default_factory=lambda: sorted(_DEFAULT_APPROVABLE_OPERATIONS))
    # A pending request expires this many hours after it's made (0 = never). allow_inf_nan=False because
    # a non-finite expiry means something different on each store backend, and none of them is what an
    # operator asked for. `nan > 0` is also False, so a nan expiry would skip the dwell cross-check below.
    expiry_hours: float = Field(default=72.0, allow_inf_nan=False)
    # Seconds a pending request must have existed before it may be approved (0 = no floor), measured
    # from its own ``requested_at``. allow_inf_nan=False matters: nan compares False against everything,
    # so `age < nan` would switch the floor OFF silently.
    min_dwell_seconds: float = Field(default=2.0, ge=0, allow_inf_nan=False)

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
        # A huge FINITE value still overflows to inf once guard() turns it into seconds, which is the
        # non-finite expiry allow_inf_nan exists to refuse.
        if v * 3600.0 == float("inf"):
            raise ValueError("approvals.expiry_hours is too large to express in seconds")
        return v

    @model_validator(mode="after")
    def _dwell_inside_expiry(self) -> ApprovalsSettings:
        # A floor at or past the ceiling leaves no moment when a request can be approved: each one is
        # refused as too early and then as expired. Refuse that at startup, not at the first release.
        # Only while dual control is ON: a disabled feature must not refuse startup over its defaults.
        if (
            self.enabled
            and self.expiry_hours > 0
            and self.min_dwell_seconds >= self.expiry_hours * 3600.0
        ):
            raise ValueError(
                "approvals.min_dwell_seconds must be shorter than approvals.expiry_hours, or no "
                "request could ever be approved"
            )
        return self


#: The two snapshot mechanisms for the SQLite store backup (ADR 0049). ``vacuum_into`` (default) writes
#: a fresh, fully-checkpointed, defragmented single-file copy. ``online_backup`` uses SQLite's Online
#: Backup API for a page-for-page copy. Neither holds the store write lock for the copy (BACKLOG #1937);
#: what the copy still costs is stated once, on ``MessageStore.snapshot_to``.
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
    # "vacuum_into" (default; defragmented copy) | "online_backup" (page-for-page copy). Neither holds
    # the store write lock for the copy (BACKLOG #1937). See ADR 0049 §"New store surface".
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
    # supplies the archive path in the POST /dr/activate request body instead (the runbook path),
    # which needs seed_dir below. A cloud URL is rejected (the seed is local/UNC only, like the
    # backup destination — no new egress).
    seed_archive: str = ""
    # The one directory a POST /dr/activate request body may name an archive under (vault BACKLOG
    # #2581). "" (the default) = a request may name NO archive, and activation uses seed_archive,
    # which is operator configuration and is not confined. Must be absolute. A cloud URL is
    # rejected, like seed_archive.
    seed_dir: str = ""
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

    @field_validator("seed_archive", "seed_dir")
    @classmethod
    def _no_cloud_seed(cls, value: str, info: ValidationInfo) -> str:
        low = value.strip().lower()
        if low and any(low.startswith(scheme) for scheme in _CLOUD_DEST_SCHEMES):
            raise ValueError(
                f"[dr].{info.field_name} must be a LOCAL or UNC path, not a cloud URL ({value!r}); "
                "the DR cold seed has no cloud source (ADR 0048 — no new egress)"
            )
        return value

    @field_validator("seed_dir")
    @classmethod
    def _seed_dir_absolute(cls, value: str) -> str:
        # "" switches request-named archives off. A blank-but-present or relative value would
        # instead resolve against the service's working directory and quietly open that. So blank
        # reads as "" and relative fails at load. "Absolute" is judged for THIS platform, the one
        # that will resolve it: a rooted path with no drive is relative on Windows.
        value = value.strip()
        if value and not os.path.isabs(value):
            raise ValueError(f"[dr].seed_dir must be an absolute path, or omitted ({value!r})")
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
    # listeners — those have their own per-connection source_ip_allowlist (an inbound(...) keyword,
    # NOT an [inbound] service key: that spelling is accepted and silently discarded).
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

    # ── Outbound alert email (data in transit) ───────────────────────
    # #323 layer 3: the SECOND acknowledgment required to run the alerts / security-event SMTP hop with
    # certificate verification OFF ([alerts].email_tls_verify=false) on an ENFORCING PHI instance.
    # AN ACKNOWLEDGMENT SWITCH, NOT THE CLAMP — and the difference is the whole reason this cell shipped
    # separately from the EMAIL/DIRECT connectors. Those are built inside build_check_registry's
    # `active_hop_posture` scope, so they read the CLAMPED weakened_tls_escape_permitted_here() and an
    # enforcing PHI hop can never be relaxed. The alerts notifier is constructed in the API lifespan,
    # OUTSIDE that scope (measured: the contextvar is stamped only in pipeline/wiring_runner.py), where
    # current_hop_posture() is None and the clamp degraded to the UNCLAMPED escape — i.e. the connectors'
    # mechanism would silently have provided no refusal at all here. (Since vault BACKLOG #2354 a None
    # posture fails closed instead; this switch is unchanged by that.) So the refusal is keyed on this explicit
    # switch at the serve gate instead, in the shape of allow_unencrypted_phi_under_strict_enforcement.
    # Default FALSE and byte-identical when unset. Setting it TRUE is a LOOSENING: security_loosenings()
    # names it, so the opt-out is never silent.
    allow_unverified_alert_smtp_tls: bool = False

    # ── Store principal privileges (ASVS 13.2.2, ADR 0199) ───────────
    # The audited opt-out from the refusal an OBSERVED over-grant earns under enforcement = enforce: the
    # startup preflight (store/privilege.py) found the store login holding more than the grant
    # docs/DEPLOY-SERVER-DB.md prescribes, and the operator accepts that in writing. It lifts that one
    # refusal and nothing else: an unobservable probe needs no opt-out (it only warns), and
    # [store].require_least_privilege outranks it. Default FALSE. Setting it TRUE is a LOOSENING: an
    # AUDIT: line at every start that uses it, over_grant_accepted=true on the store_privilege_preflight
    # audit row, and a security_loosenings() entry. DIRECT-READ by the serve lifespan, not desugared.
    allow_over_granted_store_principal: bool = False

    # ── Backend credentials (ASVS 13.2.1, BACKLOG #1182) ─────────────
    # OPT-IN REFUSAL of every backend hop that presents an unchanging credential or none. Default
    # FALSE by owner decision (2026-09-23): "Opt-in, off". When TRUE, `serve` refuses to start while
    # any hop that config/static_credentials.py's static_credential_hops() names lacks an entry in
    # static_credential_accepted below; the refuse/warn split is [security].enforcement, exactly like
    # [store].require_managed_identity. The settings half (six sections: [store], [secrets],
    # [alerts], [ai], [auth] and [logging]) is checked before anything starts; the graph half at every
    # graph load and /config/reload, where a refusal is a WiringError. Several hops have NO compliant
    # credential kind in the product today, so with this on they can only run under an opt-out. The
    # one list of them is the table in docs/CONNECTIONS.md, "Static credentials on every backend hop";
    # each hop's compliant_kind field is the source of record. Not a loosening (it tightens).
    # DIRECT-READ by the serve gate, not desugared: there is no legacy field it replaces.
    require_nonstatic_credentials: bool = False
    # The audited per-hop opt-outs: hop name -> the operator's reason, e.g.
    # {"OB_ACME_REST" = "partner offers HTTP Basic only", "settings:alerts.webhook" = "..."}. Hop names
    # are the ones `messagefoundry check`'s static-credentials line and GET /security/posture print.
    # Read only when require_nonstatic_credentials is TRUE; each honoured entry is logged at startup
    # (hop name and reason, never a secret) and named by security_loosenings(). A blank reason is
    # refused at load: an opt-out must say why.
    static_credential_accepted: dict[str, str] = Field(default_factory=dict)

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
    # Per-tier acknowledgements for the retention windows the engine never auto-bounds (owner ruling
    # R4 (b), 2026-09-24; ASVS 14.2.7; BACKLOG #1967). On an enforcing instance `serve` refuses to start
    # while one of these tiers has no window, unless ITS switch here is set; each honoured switch is
    # written as a WARNING-level `AUDIT:` line naming the tier, in the shape of the keyless-PHI second
    # ack. One switch per tier, never one for all: acknowledging app logs must not also keep transform
    # state. `allow_keeping_phi_indefinitely` above does NOT satisfy them -- it covers the auto-bounded
    # body tiers only. The tier each one answers is `acknowledged_by` in
    # config/retention_classification.py. Default FALSE. Setting one TRUE is a LOOSENING and
    # security_loosenings() names it. DIRECT-READ by the serve gate; no legacy field to desugar into.
    allow_keeping_transform_state_indefinitely: bool = False  # [retention].state_max_age_days
    allow_keeping_search_presets_indefinitely: bool = False  # [retention].search_preset_days
    allow_keeping_app_logs_indefinitely: bool = False  # [retention].app_log_days
    allow_keeping_backup_archives_indefinitely: bool = False  # [backup].retention_keep
    # PHI access is ALWAYS audited (the tamper-evident chain + message-event floor are unconditional);
    # this extends tracing to EVERY authz decision, so a site can reconstruct what an account reached.
    # DEFAULT TRUE since BACKLOG #1277, which reversed the `false` ADR 0118 §5 recorded on 2026-07-17.
    # The owner delegated that call to the Console on 2026-09-02; the Console decided. The measurement
    # the reversal rests on is written once, at `[diagnostics].audit_all_authz` above — the internal
    # field this desugars to. Setting it false is now a LOOSENING and security_loosenings() names it.
    audit_all_authorization_decisions: bool = True

    # ── What this instance handles ───────────────────────────────────
    # `handles_real_patient_data` USED TO SIT HERE and is retired (BACKLOG #1279). Every instance
    # carries patient data, so there is no declaration to make: the PHI gates apply unconditionally.
    # An operator who needs a specific one relaxed uses that gate's own switch — allow_unencrypted_phi,
    # block_unlisted_outbound, allow_keeping_phi_indefinitely, allow_single_factor_admin_when_exposed,
    # allow_unverified_alert_smtp_tls, [alerts].security_notifications_required, a per-connection
    # cleartext_accepted, tls_hop_attested or tls_revocation_attested (each with its mandatory reason),
    # the process-wide MEFOR_TLS_REVOCATION_ATTESTED, or the [security].enforcement dial. Each of those
    # is separately named and separately audited; the retired lever was neither, and it silenced nineteen gates at
    # once. Setting it is now REFUSED at load with a message naming this decision (see `_REMOVED_KEYS`).
    #
    # The production TIER stays: it is a true property of the instance and it drives the AI
    # data-scope ceiling and the DEBUG-log refusal, neither of which is a PHI gate.
    # None (the default) = DERIVE from the [ai].environment name (dev/staging -> false, prod -> true);
    # a custom name must declare it or serve fails closed via require_posture.
    production_instance: bool | None = None  # was [ai].production

    # ── Leaving the organization: the ASVS 3.7.3 interstitial ────────
    # Domains that count as INSIDE the organization. ASVS 3.7.3 asks for a notification when the user
    # is sent somewhere "outside the application's CONTROL", and control is organisational rather than
    # topological — an operator's own AD FS is a different host, a different origin, and squarely
    # theirs. Matched on a LABEL boundary, so "hospital.example" covers "adfs.hospital.example" and
    # NOT "evilhospital.example"; a bare endswith would admit the lookalike.
    #
    # EMPTY (the default) is deliberately the strict position, not the lax one: with nothing declared,
    # every absolute http(s) destination is treated as external and gets the interstitial. An operator
    # who configures nothing is warned too often, never too little.
    organization_domains: list[str] = Field(default_factory=list)
    # The interstitial itself. On by default (ADR-less: this IS the 3.7.3 control). Turning it off is
    # a posture decision, not a convenience one, and the serve gate says so.
    external_link_interstitial: bool = True
    # WARNING: THE AUDITED ESCAPE, and it LOWERS SECURITY. Destinations here are navigated to with no
    # notification and no cancel — precisely what 3.7.3 asks for. It exists because operators have
    # legitimate high-volume external destinations they do not want to declare as their own domain.
    # Same label-boundary matching. Non-empty produces a startup warning naming every entry; the
    # method's rule is that a signed relaxation is never a Pass, so this is the delta, not the default.
    external_link_allowlist: list[str] = Field(default_factory=list)

    @field_validator("organization_domains", "external_link_allowlist", mode="before")
    @classmethod
    def _split_domain_list(cls, value: object) -> object:
        """Accept a comma/whitespace-separated string as well as a list — parity with the other
        list-valued settings here, so an env-var override does not need TOML array syntax."""
        if isinstance(value, str):
            return [part for part in value.replace(",", " ").split() if part]
        return value

    @field_validator("organization_domains", "external_link_allowlist", mode="after")
    @classmethod
    def _check_domains_are_bare_hosts(cls, value: list[str]) -> list[str]:
        """Reject a URL or a wildcard where a domain belongs.

        ``https://hospital.example/`` and ``*.hospital.example`` both look right and both silently
        match NOTHING under label-boundary comparison — the operator would believe they had declared
        an internal domain and get an interstitial on every internal link, or worse, believe they had
        allowlisted something that is still being warned about. Failing at config load is the only
        place this is cheap to notice.
        """
        cleaned: list[str] = []
        for raw in value:
            item = raw.strip().lower().lstrip(".")
            if not item:
                continue
            if "/" in item or ":" in item or "*" in item:
                raise ValueError(
                    f"{item!r} must be a bare domain such as 'hospital.example', not a URL, scheme "
                    "or wildcard — subdomains are matched automatically on a label boundary"
                )
            cleaned.append(item)
        return cleaned

    @field_validator("static_credential_accepted", mode="after")
    @classmethod
    def _opt_outs_say_why(cls, value: dict[str, str]) -> dict[str, str]:
        blank = sorted(name for name, reason in value.items() if not str(reason).strip())
        if blank:
            raise ValueError(
                "[security].static_credential_accepted: every opt-out needs a reason; blank for "
                + ", ".join(repr(name) for name in blank)
            )
        return value

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

    @property
    def serve_web_console_explicit(self) -> bool:
        """Whether ``serve_web_console`` was PROVIDED, at either value (BACKLOG #2000).

        ``serve`` reads it to tell an explicit console request from the default-on posture; ADR 0143
        says what each one does. Read from ``model_fields_set`` rather than stored, so only the
        switch itself can set it. It replaced ``[api].serve_ui_explicit``, a field an operator could
        write too. A plain property, so ``model_dump()`` is unchanged.

        It holds for the model the loader validated. A copy rebuilt from ``model_dump()`` marks
        every field set, so it reads True there."""
        return "serve_web_console" in self.model_fields_set


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
        runtime. This spans ``[auth]`` and ``[api]``, so it lives here (ADR 0142).

        ``[api].public_origin`` is the INTERNAL field. The operator-facing key is
        ``[security].web_console_public_address``, which desugars into it; the old spelling is REFUSED
        as file/env input (ADR 0118), so the refusal below must name the [security] one or it hands out
        a remediation that dies at load (BACKLOG #1361)."""
        if self.auth.oidc_enabled and not self.api.public_origin:
            raise ValueError(
                "[auth].oidc_enabled requires an external origin (the federated redirect URI is "
                "derived from it); set [security].web_console_public_address to the browser-reachable "
                "origin, e.g. 'https://ops.example.com' or 'http://localhost:8765' for a loopback lab"
            )
        return self

    @model_validator(mode="after")
    def _plain_ldap_refused_under_enforce(self) -> ServiceSettings:
        """Under ``[security].enforcement = enforce``, ``[auth].ad_allow_insecure_ldap`` is inert, so a
        plain ``ldap://`` AD bind is refused (vault BACKLOG #2354).

        The ``MEFOR_ALLOW_INSECURE_TLS`` escape is clamped this way (ADR 0092 decision 2, and
        ``weakened_tls_escape_permitted``). This one was honoured at any dial, so on a first deployment
        at the shipped ``enforce`` it would have sent the service-account and user passwords over a
        cleartext SIMPLE bind. The dial and the bind live in different sections, so the check lives
        here, where the existing ``ldap://`` check already runs at load. ``LdapAuthenticator`` repeats
        it at build for a caller that hands it an ``AuthSettings`` alone. Under ``warn`` the opt-in is
        honoured, warned at build and named by :func:`security_loosenings`.

        Not keyed on ``[auth].enabled``: with sign-in off nothing dials the directory, but turning
        sign-in on would make the bind live with no second check, so the config is refused either way.
        A loopback ``ldap://`` (an on-box LDAPS proxy) is refused too; the cleartext-hop gradient's
        loopback ALLOW was not extended to this hop."""
        if self.auth.plain_ldap_bind and self.security.enforcement is SecurityEnforcement.ENFORCE:
            raise ValueError(
                "[auth].ad_server is not an ldaps:// address, and [auth].ad_allow_insecure_ldap is "
                "inert under [security].enforcement = enforce: the service-account and user passwords "
                "would cross the network in cleartext. Use an ldaps:// ad_server, and anchor an "
                "internal CA with ad_tls_ca_cert_file if the directory needs one. The opt-in is "
                "honoured only under enforcement = warn, and that relaxes every serve gate, not only "
                "this one"
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
                    "single host (a bare address, /32 or /128): any host inside a trusted range can "
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


def _section_models() -> dict[str, type[BaseModel]]:
    """``{section name: its settings model}``, derived from :class:`ServiceSettings` itself so it cannot
    drift out of step with the sections that exist (a hand-kept list would silently stop checking a
    section someone added)."""
    out: dict[str, type[BaseModel]] = {}
    for name, field in ServiceSettings.model_fields.items():
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            out[name] = annotation
    return out


def _near_field(model: type[BaseModel], key: str) -> str | None:
    """The closest real field name to ``key``, or ``None`` when nothing is close enough. A refusal that
    names the typo's likely intent is the difference between a fix and a search."""
    near = difflib.get_close_matches(key, sorted(model.model_fields), n=1)
    return near[0] if near else None


def _unknown_key_report(items: Sequence[tuple[str, str, str | None]]) -> str:
    """Render ``(section, key, suggestion)`` triples as ``[section].key (did you mean 'x'?)``.

    Names the section and key only — **never the value**. The offending value is frequently a secret
    (``_FILE_SECRET_KEYS`` exists because secrets land in this file), and the CLI prints a load failure
    verbatim to stderr, which the service captures to a log file."""
    return ", ".join(
        f"[{section}].{key}" + (f" (did you mean '{suggestion}'?)" if suggestion else "")
        for section, key, suggestion in items
    )


def _unknown_keys(
    table: str, model: type[BaseModel], values: Mapping[str, Any]
) -> Iterator[tuple[str, str, str | None]]:
    """Each key in ``values`` that ``model`` does not define, as ``(table, key, suggestion)``, descending
    into a sub-table whose field is itself a :class:`_Section` and naming it by its dotted path
    (``[cluster.vip]``). Only ``_Section`` sub-models: their ``extra="ignore"`` leaves unknown-key
    refusal to this loader, so a typo one level down would otherwise drop silently."""
    fields = model.model_fields
    for key, value in values.items():
        field = fields.get(key)
        if field is None:
            yield table, key, _near_field(model, key)
            continue
        sub = field.annotation
        if isinstance(value, dict) and isinstance(sub, type) and issubclass(sub, _Section):
            yield from _unknown_keys(f"{table}.{key}", sub, value)


def _reject_unknown_file_keys(file_data: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` if the config FILE sets a key its section does not define.

    Owner ruling, 2026-08-16: refuse unknown keys. A key the engine does not recognize used to load
    clean, do nothing, and say nothing — so a mistyped ``[egress].deny_by_defalt`` left the operator
    believing a control was configured while the engine applied its permissive default. Refusing at load
    is the only way that failure surfaces at all: nothing downstream can distinguish "not set" from
    "set, misspelt, dropped".

    Scoped to the FILE deliberately. The env layer (:func:`_env_overrides`) scrapes any
    ``MEFOR_<section>_<key>`` into its section dict, including a dozen documented variables that their
    consuming module reads straight from ``os.environ`` and that are not fields here — refusing there
    would refuse a variable the shipped docs tell operators to set. The CLI layer and the ``[security]``
    desugar write only real fields, and the file is the surface the ruling names. Unknown top-level
    **sections** stay tolerated (``ServiceSettings`` is ``extra="ignore"``) — a separate question."""
    models = _section_models()
    offenders: list[tuple[str, str, str | None]] = []
    for section, values in file_data.items():
        model = models.get(section)
        if model is None or not isinstance(values, dict):
            continue  # unknown SECTION (tolerated) or a non-table value (pydantic reports the type)
        offenders.extend(_unknown_keys(section, model, values))
    if offenders:
        raise ValueError(
            f"unrecognized config key(s): {_unknown_key_report(offenders)}. An unrecognized key is "
            "REFUSED, not ignored — a dropped key leaves the setting it was meant to apply silently "
            "un-applied. Check the spelling against docs/CONFIGURATION.md; a key that MOVED to another "
            "section is reported by name instead."
        )


# --- ADR 0118: the [security] section desugars into the internal fields it replaces ----------------
# The loopback host set this section keys on is _LOOPBACK_HOSTS, defined beside `ApiSettings` above so
# `is_loopback` and the desugar refusal cannot disagree about what "off-box" means.

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
    ("ai", "production"): "production_instance",
}

#: ``(section, key)`` → why it is REFUSED, for a key that was **removed** rather than relocated. A
#: relocated key has somewhere to go and :data:`_RELOCATED_TO_SECURITY` says where; these have
#: nowhere, so the message has to carry the decision instead of a forwarding address.
#:
#: Both spellings of the retired data-class lever are here (BACKLOG #1279). Refusing rather than
#: ignoring matters more for a REMOVED posture switch than for a misspelled one: an operator whose
#: config says ``handles_real_patient_data = false`` believes nineteen gates are off. Ignoring the key
#: would start the engine with all nineteen ON, which is the safe direction but a silent contradiction
#: of what their config says — and the next person to read that file would draw the wrong conclusion
#: about what the running instance is doing.
_REMOVED_KEYS: dict[tuple[str, str], str] = {
    ("security", "handles_real_patient_data"): (
        "every instance now carries patient data, so there is no data-class declaration to make "
        "(BACKLOG #1279). The PHI gates this used to relax as a group each have their own switch — "
        "[security].allow_unencrypted_phi, block_unlisted_outbound, allow_keeping_phi_indefinitely, "
        "allow_single_factor_admin_when_exposed, allow_unverified_alert_smtp_tls, "
        "[alerts].security_notifications_required, a per-connection cleartext_accepted, "
        "tls_hop_attested or tls_revocation_attested (each with its reason), the process-wide "
        "MEFOR_TLS_REVOCATION_ATTESTED, or the [security].enforcement dial. Relax the one you mean, "
        "or delete this line"
    ),
    ("ai", "data_class"): (
        "the data class was removed, not relocated: every instance now carries patient data "
        "(BACKLOG #1279). [ai].data_class had already moved to "
        "[security].handles_real_patient_data under ADR 0118, and that key is retired too — delete "
        "this line"
    ),
    # BACKLOG #2000. It was loader plumbing that an operator could also set, and setting it changed
    # startup while [security] reported no choice. `serve` now reads the same fact from what
    # [security] was given (SecuritySettings.serve_web_console_explicit), so nothing writes this key.
    ("api", "serve_ui_explicit"): (
        "it was an internal marker the loader set, never an operator setting (BACKLOG #2000). "
        "Remove it from the config file, or unset MEFOR_API_SERVE_UI_EXPLICIT if the environment "
        "sets it. To request the web console explicitly, set [security].serve_web_console"
    ),
    # BACKLOG #2090 (ADR 0066 §12): `false` could only start the mode that deadlocks.
    ("pipeline", "require_rcsi_for_pooled"): (
        "a SQL Server store no longer opens with READ_COMMITTED_SNAPSHOT off. The pooled start "
        "check also always fails closed, so this key has nothing left to relax (BACKLOG #2090, "
        "ADR 0066 section 12). Remove it from the config file, or unset "
        "MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED if the environment sets it. To run pooled on SQL "
        "Server, turn READ_COMMITTED_SNAPSHOT on for the database"
    ),
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
    goal and could silently disagree with ``[security]``. Checked against file+env (not CLI plumbing).

    Also refuses the keys in :data:`_REMOVED_KEYS`, which went away entirely rather than moving. That
    arm runs FIRST: ``[security].handles_real_patient_data`` is no longer a model field, so without it
    the generic unknown-key refusal in :func:`_desugar_security` would fire and offer a spelling
    suggestion for a key that is not misspelled."""
    for (section, key), reason in _REMOVED_KEYS.items():
        sect = data.get(section)
        if isinstance(sect, dict) and key in sect:
            raise ValueError(
                f"[{section}].{key} was REMOVED and is no longer accepted: {reason} "
                "(see docs/CONFIGURATION.md)."
            )
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

    # Pydantic sections are extra="ignore", so an UNKNOWN [security] key would load clean, do nothing,
    # and say nothing. For posture switches that is a silent fail-open: mistype `block_unlisted_outbound`
    # or set a switch that does not exist yet (a key backported from newer docs), and the operator
    # believes a control is on while the engine applies its permissive default.
    #
    # This arm REFUSES where it used to warn (owner ruling, 2026-08-16: "refuse unknown keys"). The
    # reasoning it replaces is recorded here rather than deleted, so a future reader can see the decision
    # instead of re-deriving the old one: warning was chosen because an unknown key might be a
    # forward-compatible config shared across an estate mid-upgrade, where refusing would turn a harmless
    # typo into a failed start on every host at once. That argument assumed an INSTALLED ESTATE. There is
    # none — zero deployments, zero adopters (CLAUDE.md §0) — so the cost it guarded against is zero
    # today, while the fail-open it accepted in exchange is real on the first deployment. If an estate
    # ever exists, the answer is a documented upgrade path, not a return to silence: zero deployments
    # removes the migration cost, it does not make the refusal optional.
    #
    # _reject_unknown_file_keys covers the FILE for every section including this one; this arm stays
    # because it also sees ENV-delivered [security] keys, which the file check cannot. Safe here
    # specifically: every MEFOR_SECURITY_* variable in the tree maps to a real field, so unlike
    # [store]/[secrets]/[tls] there is no out-of-band env variable for it to collide with.
    unknown = sorted(set(raw) - set(SecuritySettings.model_fields))
    if unknown:
        raise ValueError(
            f"unrecognized config key(s): "
            f"{_unknown_key_report([('security', k, _near_field(SecuritySettings, k)) for k in unknown])}. An "
            "unrecognized posture switch is REFUSED, not ignored — ignoring it would leave the operator "
            "believing a control is in effect while the engine applies its permissive default. Check the "
            "spelling against docs/CONFIGURATION.md; a switch that MOVED sections is reported by name "
            "instead."
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

    # The master posture lever USED TO BE DESUGARED HERE, into [ai].data_class. Both keys are retired
    # (BACKLOG #1279) and `_reject_relocated_keys` refuses either spelling before this runs, so there
    # is nothing left to translate. The production tier still passes through `_SECURITY_PASSTHROUGH`.


def _reconcile_effective_bind(settings: ServiceSettings) -> None:
    """Fold the EFFECTIVE API bind back into the ``[security]`` view, in the loosening direction only
    (BACKLOG #1852).

    :func:`_desugar_security` writes ``[security]`` down into ``[api].host`` and runs BEFORE the CLI
    merge so ``serve --host`` still wins. That ordering is deliberate and stays, but it leaves the two
    views disagreeing: ``--host 0.0.0.0`` moves the socket off-box while ``[security]`` still reads
    ``local_access_only = true``. Nothing reported that. :func:`security_loosenings` reads the raw
    ``[security]`` model, so BOTH the ``local_access_only`` entry and the exposure-gated
    ``allowed_client_networks`` entry stayed silent. The serve-time loosening warning,
    ``GET /security/posture`` and the web console's "Local access only" row all said the engine was
    loopback-only while it was listening on every interface. The exposed-bind TLS gate in ``__main__``
    was never fooled (it reads :attr:`ApiSettings.is_loopback`); only the REPORTING was.

    Reconciling here, on the validated object, reuses that same ``is_loopback`` predicate, so the gate
    and the posture view share one definition of "off-box" and cannot drift apart again. It also fixes
    every consumer at once without adding a parameter to the loosening registry. That parameter would
    be wrong for ``messagefoundry security show`` anyway, where the declared reading IS the effective
    one because there is no CLI bind to reconcile against. This is the same move ``serve`` already
    makes for the egress and retention flips (ADR 0118), one layer earlier.

    A FREE FUNCTION AND NOT A ``ServiceSettings`` AFTER-VALIDATOR, deliberately. The two cross-section
    validators on that model REFUSE a contradiction; they do not rewrite a field, and a mutating one
    beside them would read as the same kind of rule. More to the point, this fold is a LOADER concern:
    what it reconciles against is the CLI-over-file precedence :func:`load_settings` owns, and a
    ``ServiceSettings`` a caller builds by hand has no CLI layer for it to be about. A validator would
    not even be the stronger guarantee it looks like, since ``model_copy(update=...)`` re-runs none.

    ``is_loopback`` is a three-host string match, so a bind on ``127.0.0.2`` (loopback on every
    supported platform) reconciles as EXPOSED. That over-reports, which is the safe direction, and it
    is byte-identical to what the serve TLS gate already does with the same host. Do not "fix" it into
    an :mod:`ipaddress` ``is_loopback`` call here: that would relax the TLS gate in the same move.

    **ONE-WAY, and that is the load-bearing part.** Reconcile only where the effective bind ADDS a
    loosening:

    * effective bind is NON-loopback: force ``local_access_only`` false and point ``listen_address``
      at the host actually bound (leaving it at ``127.0.0.1`` would make the model lie, since that
      field is documented as the address used once ``local_access_only`` is false);
    * effective bind IS loopback: change nothing. Never flip ``local_access_only`` back to true. An
      operator may declare ``local_access_only = false`` and leave ``listen_address`` at its loopback
      default; the declaration is still a deviation from the one shipped posture and the registry must
      keep reporting it. Suppressing a loosening the operator declared is the wrong direction, whatever
      the socket ended up bound to.
    """
    if settings.api.is_loopback:
        return
    settings.security.local_access_only = False
    settings.security.listen_address = settings.api.host


#: The most consecutive failed attempts NIST SP 800-63B lets a verifier allow on one account before
#: it acts (SP 800-63B-4 section 3.2.2, "Rate Limiting (Throttling)"; section 5.2.2 in the superseded
#: rev. 3 set the same number). Any ``[auth].lockout_threshold`` above the shipped default is named
#: by :func:`security_loosenings` (BACKLOG #1131); one above this ceiling also says it exceeds NIST,
#: because a large enough threshold never arms, which is the lockout turned off in all but name.
LOCKOUT_THRESHOLD_CEILING = 100


def _trust_every_peer_entries(entries: Sequence[str]) -> list[str]:
    """The ``[api].trusted_proxies`` ranges that, together, trust every peer of an address family,
    read the way uvicorn reads them: a strict network parse, where a host-bits-set entry is not a
    network. Collapsed per family, so the two ``/1`` halves of ``0.0.0.0/0`` count as the whole.
    Returns the multi-address entries of each such family (a single-host entry adds nothing)."""
    v4: list[tuple[str, ipaddress.IPv4Network]] = []
    v6: list[tuple[str, ipaddress.IPv6Network]] = []
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            v4.append((entry, net))
        else:
            v6.append((entry, net))
    named: list[str] = []
    if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(net for _, net in v4)):
        named += [entry for entry, net in v4 if net.num_addresses > 1]
    if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(net for _, net in v6)):
        named += [entry for entry, net in v6 if net.num_addresses > 1]
    return list(dict.fromkeys(named))  # a repeated entry is named once, in order


def _auth_default(field: str) -> Any:
    """The SHIPPED default of an ``[auth]`` field, read off the model rather than restated, so the
    loosening test below and the default it judges against cannot drift apart."""
    return AuthSettings.model_fields[field].default


def _auth_limit_loosenings(auth: AuthSettings) -> list[tuple[str, str]]:
    """The ``[auth]`` anti-automation limits set LOOSER THAN THEIR SHIPPED DEFAULT, as
    ``(switch, risk)`` entries for :func:`security_loosenings`, which calls this only while sign-in is
    on (BACKLOG #1131; ASVS 6.1.1, 6.3.1, 2.3.2, and the 2.4.1, 2.4.2 and 7.1.2 each field cites).

    **Why the default is the cutoff.** The first pass named only the values the code reads as OFF,
    and a vault re-read then measured near-off values that were just as off in effect and silent: a
    sign-in window of ``1e-6`` s admitted 10000 of 10000 attempts, and a count of ``1e9`` removed the
    ceiling. There is ONE shipped posture and an operator may only loosen from it, so the shipped
    default is the one cutoff that needs no invented number (Manager decision 2026-09-30). A value
    STRICTER than the default is never named, and the defaults name nothing.

    **The direction is read from each consumer, not from the name.**

    * ``SlidingWindowRateLimiter`` (the sign-in, ceremony, PHI-read and admin-write limiters) treats a
      falsy count as "no limit on that dimension" and admits more as a count rises. It prunes every hit
      older than the window, so a SHORTER window admits more, and one of 0 or less (``-inf`` included)
      prunes each hit before it is counted. A negative count refuses more, and a NaN or ``+inf``
      window never prunes, so none of those is named. A ``min_interval_seconds`` of 0 turns the gap
      off, and a shorter gap admits a faster burst.
    * ``next_lockout_state`` ends a lock at now + ``lockout_minutes`` (shorter is looser; 0 or less
      ends it at once) and arms it at ``lockout_threshold`` failures (higher is looser; 0 or less locks
      on the first failure). An escalating lock doubles up to ``lockout_max_minutes`` (ADR 0197), so a
      lower ceiling is looser, and one equal to ``lockout_minutes`` turns the doubling off. A ceiling
      at the default or above is not named even when it equals ``lockout_minutes``: every lock then
      lasts at least as long as the default's longest.
    * ``_enforce_session_cap`` skips a ``max_sessions_per_user`` of 0 or less, and a higher cap keeps
      more sessions live.
    * ``FlowCache`` refuses a new federated flow once it holds ``oidc_flow_cache_max`` pending ones, so
      a higher cap holds more and 0 or less refuses every flow, which is stricter, not looser.

    A part of a limiter is named only while that limiter is built, as ``email_tls_verify`` sits under
    ``email_use_tls``: with the limiter off, a weak count or window changes nothing and would only
    repeat the off entry. A window of 0 or less likewise stands in for its counts.

    * The BACKLOG #2301 time floors (``admin_write_min_interval_seconds``,
      ``mfa_verify_min_elapsed_seconds``, ``oidc_callback_min_elapsed_seconds``) refuse an action that
      comes sooner than the floor and skip the check at 0 or less, so a floor below its default is
      looser and 0 is off. A higher floor is stricter, and is not named.

    **Not covered, and stated so the gap is visible:** ``[approvals].min_dwell_seconds``, the
    dual-control approval floor, is another time floor of the same kind. It lives in a section this
    registry does not receive, and reporting it needs a new required parameter at every call site."""
    out: list[tuple[str, str]] = []

    def _count(field: str, value: int, *, what: str, so: str, off: str | None) -> None:
        """A count limit: named at 0 where ``off`` says what 0 turns off, and above its default."""
        default = _auth_default(field)
        if off is not None and value == 0:
            out.append((field, off))
        elif value > default:
            out.append((field, f"{what} is {value}, above the default of {default}, so {so}"))

    def _floor_verdict(field: str, value: float) -> Literal["off", "looser"] | None:
        """A time floor refuses an action sooner than ``value`` seconds, so 0 or less is off and a
        value below the default is looser. A floor above the default refuses more: None.

        Returns a LITERAL, never the value, so a caller can pick its text without the configured
        number ever reaching that text (see the second-factor floor below)."""
        if value <= 0:
            return "off"
        if value < _auth_default(field):
            return "looser"
        return None

    def _floor(field: str, value: float, *, what: str, so: str, off: str) -> None:
        """A time floor whose configured value the entry quotes."""
        verdict = _floor_verdict(field, value)
        if verdict == "off":
            out.append((field, off))
        elif verdict == "looser":
            default = _auth_default(field)
            out.append(
                (
                    field,
                    f"{what} is {value:g} s, shorter than the default of {default:g} s, so {so}",
                )
            )

    def _window(
        field: str, value: float, *, what: str, off: str | None, counts: tuple[int, ...]
    ) -> bool:
        """A window: named at 0 or less where ``off`` says what that turns off, and below its
        default. Returns whether the window still counts anything, which gates its counts.

        ``counts`` are the counts the window paces. When every one is 0 (off), a short window
        changes nothing, so it is not named as looser; each off count is named on its own."""
        default = _auth_default(field)
        if off is not None and value <= 0:
            out.append((field, off))
            return False
        if value < default and any(counts):
            out.append(
                (
                    field,
                    f"{what} is {value:g} s, shorter than the default of {default:g} s, so each "
                    f"limit it paces admits its count once per {value:g} s instead of once per "
                    f"{default:g} s; a short enough window admits nearly every attempt, while the "
                    "limiter still reads as on",
                )
            )
        return True

    # --- the sign-in limiter. The same keys build the per-user CEREMONY limiter (_reauth_limiter),
    # which paces re-auth, password change and MFA enrolment, and the console's second-factor step
    # at sign-in (POST /ui/mfa).
    ceremonies = (
        "the per-user limit on credential ceremonies (re-auth, password change, MFA enrolment "
        "and the console's second-factor step at sign-in)"
    )
    if not auth.login_rate_limit_enabled:
        out.append(
            (
                "login_rate_limit_enabled",
                "sign-in has NO rate limit -- neither the per-address nor the all-clients "
                f"sign-in limiter is built, and nor is {ceremonies}, so the engine applies no "
                "attempt-rate limit to a password spray across many usernames",
            )
        )
    elif _window(
        "login_rate_limit_window_seconds",
        auth.login_rate_limit_window_seconds,
        what=(
            f"the window of the per-address and all-clients sign-in limits, and of {ceremonies},"
        ),
        off=(
            "the sign-in rate-limit window is zero or negative, which ages every attempt out "
            "before it is counted -- neither the per-address nor the all-clients sign-in "
            f"limit holds, and nor does {ceremonies}, although login_rate_limit_enabled "
            "still reads as on"
        ),
        counts=(auth.login_rate_limit_per_ip, auth.login_rate_limit_global),
    ):
        _count(
            "login_rate_limit_per_ip",
            auth.login_rate_limit_per_ip,
            what="the per-address sign-in limit",
            so=(
                "one client address may make that many attempts per window before it is "
                f"refused; the same number sets {ceremonies}, so that is looser too"
            ),
            off=(
                "there is no per-address sign-in limit, so one client address may make as "
                "many attempts as the all-clients limit allows; the same number sets "
                f"{ceremonies}, so that is off too"
            ),
        )
        _count(
            "login_rate_limit_global",
            auth.login_rate_limit_global,
            what="the all-clients sign-in limit",
            so=(
                "a password spray spread across many client addresses may make that many "
                "attempts per window before any is refused"
            ),
            off=(
                "there is no all-clients sign-in limit, so the total rate of a password "
                "spray spread across many client addresses grows with the number of "
                "addresses the attacker controls"
            ),
        )

    # --- the account lockout, on the sign-in and the second-step counter alike.
    minutes = auth.lockout_minutes
    if minutes <= 0:
        out.append(
            (
                "lockout_minutes",
                "no account lock ever holds -- a lock set at lockout_threshold failures expires "
                "the moment it is set, on the sign-in and the second-step counter alike, so no "
                "run of wrong guesses at one account's password or second factor is ever "
                "refused by a lock",
            )
        )
    elif minutes < _auth_default("lockout_minutes"):
        out.append(
            (
                "lockout_minutes",
                f"an account lock lasts {minutes} minute(s), shorter than the default of "
                f"{_auth_default('lockout_minutes')}, on the sign-in and the second-step counter "
                "alike -- a run of wrong guesses at one account's password or second factor "
                "resumes sooner after each lock",
            )
        )
    threshold = auth.lockout_threshold
    if threshold > _auth_default("lockout_threshold"):
        nist = (
            f", and above the {LOCKOUT_THRESHOLD_CEILING} that NIST SP 800-63B allows"
            if threshold > LOCKOUT_THRESHOLD_CEILING
            else ""
        )
        out.append(
            (
                "lockout_threshold",
                f"no account lock is set before {threshold} consecutive failures, above the "
                f"default of {_auth_default('lockout_threshold')}{nist} -- that many wrong guesses "
                "at one account's password or second factor are checked before any lock is set, "
                "and a session may fail that many re-proofs before it is revoked",
            )
        )
    # With no lock holding, a ceiling on how long it grows changes nothing.
    ceiling = auth.lockout_max_minutes
    if minutes > 0 and ceiling < _auth_default("lockout_max_minutes"):
        if ceiling <= minutes:
            risk = (
                f"lock escalation is OFF: the ceiling equals lockout_minutes ({minutes}), so a "
                "repeated lock on one account never grows (ADR 0197), and every run of wrong "
                f"guesses waits the same {minutes}-minute lock"
            )
        else:
            risk = (
                f"an escalating lock stops doubling at {ceiling} minutes, below the default of "
                f"{_auth_default('lockout_max_minutes')} (ADR 0197), so the longest lock a run of "
                "repeated lock cycles on one account can reach is shorter than the default's"
            )
        out.append(("lockout_max_minutes", risk))

    # --- the PHI-read limiter (WP-8, ASVS 2.4.1): per account, over the PHI-read routes and views.
    # The all-users count ships OFF (0), so no value of it is looser than the default.
    if not auth.phi_read_rate_limit_enabled:
        out.append(
            (
                "phi_read_rate_limit_enabled",
                "PHI reads have NO rate limit -- a signed-in account may read message bodies and "
                "dead letters through the API and the console as fast as the engine answers, so "
                "a stolen session can harvest PHI at machine speed",
            )
        )
    elif _window(
        "phi_read_rate_limit_window_seconds",
        auth.phi_read_rate_limit_window_seconds,
        what="the PHI-read rate-limit window",
        off=(
            "the PHI-read rate-limit window is zero or negative, which ages every read out before "
            "it is counted -- no PHI-read limit holds, although phi_read_rate_limit_enabled still "
            "reads as on"
        ),
        counts=(auth.phi_read_rate_limit_per_actor, auth.phi_read_rate_limit_global),
    ):
        _count(
            "phi_read_rate_limit_per_actor",
            auth.phi_read_rate_limit_per_actor,
            what="the per-account PHI-read limit",
            so=(
                "one signed-in account may make that many PHI reads per window before it is "
                "refused, and a stolen session harvests more PHI"
            ),
            off=(
                "there is no per-account PHI-read limit, so one signed-in account may read PHI "
                "as fast as the engine answers (only an all-users limit, if one is set, holds)"
            ),
        )

    # --- the admin-write limiter (BACKLOG #193 / #2301, ASVS 2.4.2): per actor, on every non-GET
    # sensitive action. Its window cannot be 0 or less (gt=0 at load), so it has no off value.
    if not auth.admin_write_rate_limit_enabled:
        out.append(
            (
                "admin_write_rate_limit_enabled",
                "state-changing admin actions (purge, replay, config deploy and reload, and every "
                "other non-GET sensitive action) have NO pacing -- neither the per-actor count nor "
                "the minimum gap holds, so a script holding a session may fire them as fast as the "
                "engine answers",
            )
        )
    else:
        _window(
            "admin_write_rate_limit_window_seconds",
            auth.admin_write_rate_limit_window_seconds,
            what="the admin-write rate-limit window",
            off=None,
            # Only the count reads the window: the gap is shorter than it (checked at load), so
            # the last write is never pruned before the gap is measured.
            counts=(auth.admin_write_rate_limit_per_actor,),
        )
        _count(
            "admin_write_rate_limit_per_actor",
            auth.admin_write_rate_limit_per_actor,
            what="the per-actor admin-write limit",
            so=(
                "one actor may make that many state-changing admin writes per window before it "
                "is refused"
            ),
            off=(
                "there is no per-actor admin-write count, so only the minimum gap paces a "
                "scripted run of purges, replays or config deploys"
            ),
        )
        _floor(
            "admin_write_min_interval_seconds",
            auth.admin_write_min_interval_seconds,
            what="the minimum gap between one actor's admin writes",
            so=(
                "a script may spend the per-actor count even faster than the default allows, and "
                "the default already sits just under the fastest keystroke-level write (0.16 s)"
            ),
            off=(
                "there is no minimum gap between one actor's admin writes, so the whole "
                "per-actor count may be spent back to back at machine speed"
            ),
        )

    # --- the second-factor time floor (BACKLOG #2301, ASVS 2.4.2): _second_factor_too_early refuses
    # a code or passkey that completes an MFA-pending session sooner than this after sign-in, and
    # skips the check at 0 or less. It applies to any account with a factor, whether or not
    # [security].require_mfa is on, so it is gated on sign-in only.
    #
    # Its entry does NOT quote the configured value, unlike every other floor here. CodeQL's
    # py/clear-text-logging-sensitive-data reads an attribute named mfa_* as a password source, and
    # these entries reach the serve WARNING and `security show` stdout, so quoting the number raised
    # two alerts on PR 1842. The value only picks a literal verdict (_floor_verdict), which carries
    # no data from it. The operator loses nothing they did not set themselves.
    step_field = "mfa_verify_min_elapsed_seconds"
    step_verdict = _floor_verdict(step_field, auth.mfa_verify_min_elapsed_seconds)
    if step_verdict == "off":
        out.append(
            (
                step_field,
                "there is no least time between sign-in and the second factor, so a script "
                "holding a password may complete the second step with a relayed or scripted code "
                "at once",
            )
        )
    elif step_verdict == "looser":
        out.append(
            (
                step_field,
                "the least time between sign-in and the second factor is shorter than the "
                f"default of {_auth_default(step_field):g} s, so a script holding a password may "
                "complete the second step with a relayed or scripted code sooner after sign-in "
                "than a person could take in the prompt and answer it",
            )
        )

    # --- the federated callback floor (BACKLOG #2301, ASVS 2.4.2): _oidc_callback_too_early refuses
    # a callback sooner than this after its flow started, and skips the check at 0 or less. The
    # flows exist only with OIDC on.
    if auth.oidc_enabled:
        _floor(
            "oidc_callback_min_elapsed_seconds",
            auth.oidc_callback_min_elapsed_seconds,
            what="the least time between a federated sign-in's start and its callback",
            so=(
                "a scripted flow may complete sooner after it starts than a person could answer "
                "the identity provider's prompt"
            ),
            off=(
                "there is no least time between a federated sign-in's start and its callback, "
                "so a scripted flow may complete at machine speed"
            ),
        )

    # --- concurrent sessions (ASVS 7.1.2). 0 or less means unlimited, so a negative cap is off too.
    sessions = auth.max_sessions_per_user
    _count(
        "max_sessions_per_user",
        max(sessions, 0),
        what="the per-user cap on live sessions",
        so=(
            "a user may hold that many sessions at once before the oldest is revoked, and more "
            "stolen or forgotten sessions stay live beside the owner's"
        ),
        off=(
            f"a user may hold any number of live sessions at once ({sessions} means unlimited) "
            "-- signing in again never revokes an old one, so a stolen or forgotten session "
            "stays live beside the owner's"
        ),
    )

    # --- the federated sign-in flow cache. Built only with OIDC on. It refuses at the cap, so 0 or
    # less refuses every flow, which is stricter; only a cap above the default is looser.
    if auth.oidc_enabled:
        _count(
            "oidc_flow_cache_max",
            auth.oidc_flow_cache_max,
            what="the engine-wide cap on pending federated sign-in flows",
            so=(
                "a flood of abandoned login starts holds that many flows in memory before a new "
                "one is refused, and only the per-address cap bounds it below that"
            ),
            off=None,
        )
    return out


def security_loosenings(
    sec: SecuritySettings,
    store: StoreSettings,
    auth: AuthSettings,
    alerts: AlertsSettings,
    secret_rotation: SecretRotationSettings,
    *,
    cleartext_hops: Sequence[str],
    expiry_relaxed_hops: Sequence[str],
    unverified_db_hops: Sequence[str],
    attested_hops: Sequence[str],
    revocation_attested_hops: Sequence[str],
    api: ApiSettings,
    store_privilege: StorePrivilegePosture | None,
    audit_chain_unkeyed: bool | None,
) -> list[tuple[str, str]]:
    """The ``[security]`` switches at their INSECURE value, plus the enumerated deviations outside that
    section, as ``(switch, plain-language risk)``.

    **Scope, stated precisely so the gap is visible rather than implied.** This registry covers *every*
    ``[security]`` switch — pinned by a completeness floor in ``tests/test_security_posture_defaults.py``
    that iterates ``SecuritySettings.model_fields`` and fails on an unreported, unexempted one — plus an
    ENUMERATED set of deviations that live elsewhere: ``[store].aad_bind``,
    ``[store].allow_unmarked_ciphertext`` (#1169),
    ``[auth].ad_session_recheck_seconds``, ``[auth].ad_allow_insecure_ldap`` with a live ``ldap://``
    bind (vault BACKLOG #2354), ``[auth].admin_new_ip_step_up`` (#288), the ``[auth]``
    sign-in rate-limit, lockout, PHI-read, admin-write, time-floor, session-cap and OIDC flow-cache
    settings :func:`_auth_limit_loosenings` lists, each set looser than its shipped default (#1131), an
    ``[api].trusted_proxies`` set of ranges covering every peer of a family (#1131),
    ``[api].plaintext_upstream_hop_acknowledged`` (#1179),
    ``[alerts].email_use_tls``/``email_tls_verify`` (#323
    layer 3), ``[secret_rotation].enforce_store_key_expiry`` (#1004), the per-connection
    deviations — ``cleartext_accepted``, ``tls_allow_expired``, a generic-ODBC ``DATABASE`` hop
    with TLS unenforced (#333), ``tls_hop_attested`` (owner ruling 2026-09-24) and
    ``tls_revocation_attested`` (ADR 0173) -- the store principal's OBSERVED privilege posture
    (#1008), the OBSERVED keying of the audit chain (#1905), and
    ``[store].schema_management = auto`` on a server backend (#305). It is NOT yet
    an exhaustive registry of every security-relevant switch in every section; ``[store]``/``[auth]``
    carry others (``encrypt``, ``trust_server_certificate``, ``enabled``, ``require_mfa``,
    ``ad_tls_verify``, ``oidc_require_mfa_claim``,
    ``password_check_breached``) that are gated elsewhere and are not reported here. That list is
    enumerated in the floor test's exemption set so the gap is a written decision that a new switch
    cannot silently join. That set also holds at least one switch this registry DOES report,
    ``ad_allow_insecure_ldap``, because its entry needs a live ``ldap://`` bind that the floor's lone
    flip never builds; its own tests pin it.

    **``[auth].initial_password_expiry_hours`` is also unreported, and BACKLOG #1245 made it
    load-bearing — recorded here as the written decision this paragraph demands, not left implied.**
    It is not a ``[security]`` field, so the completeness floor (which iterates
    ``SecuritySettings.model_fields``) never covered it and its absence is not a floor-test gap. What
    matters is the consequence: it is the ONLY bound on an admin-issued temporary password, so
    setting it to 0 unbounds every such credential, and nothing in this registry says so. Reporting it
    needs a new REQUIRED parameter (every one here is required by design, so an optional detector
    cannot be added quietly), which is a larger change than the item that exposed it — filed as
    content rather than folded in.

    ``api`` is a settings section like the five before it, but it sits in the keyword-only group, so
    every call site names it. It carries the BACKLOG #1179 acknowledgement.

    Every parameter is REQUIRED, not optional, and deliberately so. There is exactly ONE shipped posture
    and an operator may only loosen from it, so a deviation that this registry cannot see is a second
    posture by the back door. An optional parameter is a detector that silently fails to fire; a required
    one makes omission a type error at every call site. Everything after ``secret_rotation`` is
    keyword-only: the connection-scoped sequences all share the type ``Sequence[str]``, so a
    positional call could pass one set in another's slot and still type-check.

    ``store_privilege`` is the store-principal privilege OBSERVATION (#1008, ASVS 13.2.2), for the same
    reason and in the same plain shape: it is what the principal actually holds, produced by the
    serve-time probe in ``store/privilege.py`` and passed in as a
    :class:`StorePrivilegePosture` so this module never imports the store package. ``None`` means THIS
    CALL SITE has no probe result (no store is open — ``messagefoundry security show``, or a posture
    read on an engine that never ran the preflight), and the caller SAYS SO in its own output. It is not
    a clean result and this registry never renders it as one. Note the switch that acts on the finding
    — ``[store].require_least_privilege`` — is a HARDENING, so it is not itself reported here; the
    DEVIATION is what the observation found, exactly as with the connection-scoped entries.

    ``audit_chain_unkeyed`` is the second store OBSERVATION (BACKLOG #1905), from the open store's
    ``audit_chain_unkeyed()``: the store holds a key, yet its audit chain is keyless SHA-256 because
    rows were written before any key was in hand, and a keyed open never re-keys existing rows.
    ``None`` has the same meaning as for ``store_privilege`` -- no store is open at this call site, so
    nothing was observed -- and is never read as a clean result.

    The sequence parameters are the CONNECTION-scoped deviations, each a list of connection NAMES:
    ``cleartext_hops`` declares ``cleartext_accepted`` (ADR 0153), ``expiry_relaxed_hops`` declares
    ``tls_allow_expired`` (#129 / ADR 0094), ``unverified_db_hops`` is a generic-ODBC ``DATABASE``
    connection whose ``odbc_params`` leave TLS unenforced (#66 / ADR 0092's amendment), and
    ``attested_hops`` declares ``tls_hop_attested`` (ADR 0092, owner ruling 2026-09-24), and
    ``revocation_attested_hops`` declares ``tls_revocation_attested`` (ADR 0173). They arrive as
    plain names rather than a ``Registry`` so ``config.settings`` never has to know the graph type; the
    caller resolves them through the shared readers in ``config.wiring``
    (``accepted_cleartext_hops``, which walks both outbound connections and ``FhirLookup`` read
    connections; ``expiry_relaxed_hops``; ``unverified_generic_db_hops``, which walks inbound as well as
    outbound; ``attested_secure_hops``, which walks every carrier a hop gate reads;
    ``revocation_attested_hops``, which walks inbound, outbound and ``FhirLookup``). A caller that
    genuinely has no graph — ``messagefoundry security show``, which reads a
    settings file and never loads the connection config — passes empty sequences and SAYS SO in its
    output, rather than reporting a subset as if it were everything.

    Shared by the serve-time loosening warning (``__main__``, ADR 0118 AC-4) and the read-only posture
    view (``GET /security/posture``, AC-5), so the two never drift. This is advisory only — it names what
    a deliberate opt-out gives up; the posture GATES (which still refuse a production-PHI weakening) are
    unchanged.

    ``audit_all_authorization_decisions`` CHANGED SIDES, and the old sentence is quoted here rather than
    deleted so nobody re-derives it. It read: *"``audit_all_authorization_decisions=false`` is the
    owner-confirmed SECURE default, so it is NOT a loosening."* That was true while ``false`` shipped.
    BACKLOG #1277 flipped the default to ``true`` (delegated by the owner to the Console on 2026-09-02;
    decided by the Console), so ``false`` is now the switch at its insecure value and this registry
    reports it. See ``docs/SECURITY-LOOSENING.md``."""
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
                "off-machine access is permitted with no operator certificate — the API serves "
                "on its self-signed placeholder, which no trust store vouches for, and inbound "
                "listeners without tls bind in cleartext (still refused under enforcement=enforce)",
            )
        )
    if not sec.external_link_interstitial:
        out.append(
            (
                "external_link_interstitial",
                "the console navigates OFF-SITE with no notification and no cancel — an operator can be "
                "sent to a third-party site (including an identity provider) with no chance to stop it "
                "(ASVS 3.7.3)",
            )
        )
    if sec.external_link_allowlist:
        # Reported even though the switch is a LIST rather than a bool, because the completeness floor
        # only pins bools and an exempted list would be an unreported loosening by omission. Entries
        # are named individually: a count would say "3 destinations are exempt" without saying which,
        # which is the shape that lets an entry nobody intended survive a posture review.
        out.append(
            (
                "external_link_allowlist",
                "these destinations are exempt from the off-site interstitial and are navigated to "
                "with no notification and no cancel: "
                + ", ".join(sec.external_link_allowlist)
                + " (ASVS 3.7.3)",
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
                "every account is single-factor — no engine second factor is required, and a "
                "directory session is admitted on a ticket that asserts no strength",
            )
        )
    elif sec.require_mfa_scope != "every_local_account":
        # Not a refusal: "administrators" is the pre-ASVS-6.3.3 posture, and refusing to boot on it
        # would be the fleet-wide breaking upgrade the owner declined. Advisory read-out only.
        out.append(
            (
                "require_mfa_scope",
                "only Administrators must enroll a second factor — every other account, local or "
                "directory, is single-factor until it opts in by enrolling",
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
                # BACKLOG #1906: this read "a PHI instance still refuses unless allow_unencrypted_phi
                # is also set". The desugar sets [store].allow_unencrypted_phi from EITHER key, so the
                # two keys are one opt-out and the text must say so.
                "a PHI instance may start keyless — PHI stored UNENCRYPTED at rest (the same opt-out "
                "as allow_unencrypted_phi; a configured key still encrypts)",
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
    # BACKLOG #1967: the per-tier retention acknowledgements, read off the classification so a tier
    # given a switch there is reported here without a second list to keep in step.
    for window in PHI_RETENTION_WINDOWS:
        if window.acknowledged_by is not None and window.is_acknowledged(sec):
            out.append(
                (
                    window.acknowledged_by,
                    f"the {window.level} tier {window.setting} may start with no retention window "
                    "and accumulate without bound",
                )
            )
    if not sec.audit_all_authorization_decisions:
        # BACKLOG #1277. Stated as what the SITE loses rather than as "a setting is off", because the
        # loss is silent and unrecoverable: no row is written, so nothing later reports the gap and no
        # read history can be reconstructed. PHI access is audited either way — say so, or this reads
        # as a bigger deviation than it is.
        out.append(
            (
                "audit_all_authorization_decisions",
                "only the sensitive/state-changing surface leaves an authorization-grant row — every "
                "authenticated READ is authorized and NOT recorded, so what an account reached cannot "
                "be reconstructed afterwards (PHI access itself is still always audited)",
            )
        )
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
    # BACKLOG #1169 (ASVS 11.3.3). The substitution limb has a tag to fail; a downgrade to plaintext has
    # none, and only the refusal this switch turns off protects it.
    if store.allow_unmarked_ciphertext:
        out.append(
            (
                "allow_unmarked_ciphertext",
                "an UNMARKED value in an encrypted column reads back as plaintext instead of being "
                "refused — anyone who can write the store can strip a ciphertext's marker or plant a "
                "plaintext row and have the engine accept it as that row's content, and the next "
                "rotate-key seals it as genuine ciphertext. It also serves a plaintext uploaded file: "
                "anyone who can write [store].uploads_dir, with no store access at all, can drop a "
                "sidecar with a chosen uploader and have it listed, browsed and resent "
                "(no effect without a store key)",
            )
        )
    # BACKLOG #1004 (ASVS 13.3.4). Stated as what the SITE gives up rather than "a setting is off": the
    # engine keeps starting on a key past its documented cadence, and the only remaining signal is an
    # alert nobody has to answer. Named here because a silent opt-out from a refusal is indistinguishable
    # from the refusal never having been built — which is the defect the refusal replaced.
    if not secret_rotation.enforce_store_key_expiry:
        out.append(
            (
                "enforce_store_key_expiry",
                "the store data-encryption key's CALENDAR expiry does not stop anything — a DEK past "
                "its max age plus grace, or one whose age cannot be determined, still starts the "
                "engine and keeps encrypting PHI at rest, with an alert as the only signal (the same "
                "key's 2**32-encrypt usage ceiling still refuses unconditionally)",
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
    # Vault BACKLOG #2354: a plain ldap:// AD bind. ServiceSettings refuses it at load under enforce, so a
    # loaded config reaches this only at warn. Conditional on the bind being live: the flag beside an
    # ldaps:// address, with AD off, or with sign-in off (nothing builds the authenticator) changes
    # nothing and is not named. Sign-in is read off [security], as for the limiter entries below, so
    # `security set` turning it on shows this at once.
    if sec.require_sign_in and auth.plain_ldap_bind:
        out.append(
            (
                "ad_allow_insecure_ldap",
                "AD binds over plain ldap:// -- the service-account password and every signing-in "
                "user's password cross the network in cleartext, and nothing authenticates the "
                "domain controller",
            )
        )
    # BACKLOG #288: the new-client-IP step-up defaults ON. Conditional on auth, like the entry above is
    # on the directory: with sign-in off there is no session for the signal to guard.
    if auth.enabled and not auth.admin_new_ip_step_up:
        out.append(
            (
                "admin_new_ip_step_up",
                "a session token used from a NEW client address can perform a sensitive admin action "
                "without a fresh step-up -- nothing audits, notifies or challenges the address change "
                "mid-session",
            )
        )
    # BACKLOG #1131, owner ruling 2026-09-27 (#2006): a silent weakening of an anti-automation control
    # keeps its ASVS cell at partial. Every such limit LOOSER THAN ITS SHIPPED DEFAULT is named, not
    # only an off value; _auth_limit_loosenings says why and how each direction was read.
    # Gated on [security].require_sign_in rather than [auth].enabled (the desugar makes them equal on
    # every loaded path): `security set` passes the NEW [security] beside the [auth] it read before
    # the edit, so turning sign-in on there must show these at once.
    if sec.require_sign_in:
        out.extend(_auth_limit_loosenings(auth))
    # BACKLOG #1131: trusted_proxies ranges covering every peer of a family (0.0.0.0/0, ::/0, or
    # ranges whose union is that) make uvicorn trust X-Forwarded-For from all of them, which is what
    # the refused "*" does. The load still accepts them; naming them is the fix. Parsed STRICTLY, as
    # uvicorn's _TrustedHosts parses them (__main__ hands it the list verbatim): "10.1.2.3/0" loads
    # here (the validator is not strict) but fails uvicorn's strict parse and becomes a literal that
    # matches nothing, so it trusts no peer and is not this loosening. Not gated on sign-in: a forged
    # source address poisons the audit trail either way.
    # CodeQL's name heuristic reads `trusted_proxies` as a secret (main's alert 209 is that source on
    # an INFO line). The entries reach the serve WARNING and stdout below; no flow is reported today,
    # but a refactor of the helper may raise one. Fix it at the source, as the MFA floor above does.
    trust_all = _trust_every_peer_entries(api.trusted_proxies)
    if trust_all:
        out.append(
            (
                "trusted_proxies",
                f"[api].trusted_proxies includes {', '.join(trust_all)}, which together cover every "
                "address of their family, so X-Forwarded-For is trusted from EVERY such peer, as the "
                "refused '*' would be -- any client can declare its own source address, poisoning "
                "the audit trail, the per-address sign-in limit and the new-client-IP step-up signal",
            )
        )
    # BACKLOG #1179, owner ruling 2026-09-27 (#2006 question (a)): a silent weakening keeps ASVS
    # 12.3.3 at partial, so the acknowledgement is named here as well as warned at serve. Conditional
    # on the hop actually being plaintext, by the predicate serve uses: with an operator tls_cert_file
    # the engine serves that hop over TLS and the acknowledgement is inert.
    if api.plaintext_upstream_hop_acknowledged and api.serves_plaintext_upstream_hop:
        out.append(
            (
                "plaintext_upstream_hop_acknowledged",
                "the proxy-to-engine hop behind [api].tls_terminated_upstream is PLAINTEXT and the "
                "engine does nothing to protect it -- the operator has acknowledged that securing "
                "it is the deploying site's job. At least sign-in credentials, session tokens and "
                "PHI reads cross that hop unencrypted; isolating the hop limits who can read them "
                "but encrypts nothing (set [api].tls_cert_file to serve it over TLS instead)",
            )
        )
    # --- the [alerts] SMTP hop (#323 layer 3). Two SEPARATE entries, deliberately: the deviation and the
    # acknowledgment of it are different facts and an operator can hold either without the other. A hop
    # with verification off under enforcement=warn needs no acknowledgment to run, so keying the report
    # on the switch alone would leave the actual weakening invisible — which is the failure mode this
    # registry exists to prevent. Reported at every call site (unlike cleartext_accepted, this is
    # settings-scoped, so `security show` and a graphless GET /security/posture see it completely).
    if alerts.email_smtp_host and alerts.email_from:
        if not alerts.email_use_tls:
            out.append(
                (
                    "email_use_tls",
                    "the [alerts] SMTP hop is CLEARTEXT — operator alert bodies, every per-user "
                    "security-event email (lockout, password/roles change) and the SMTP login "
                    "credential cross it unencrypted and readable by anything on the path",
                )
            )
        elif not alerts.email_tls_verify:
            out.append(
                (
                    "email_tls_verify",
                    "the [alerts] SMTP hop is encrypted but UNAUTHENTICATED — it accepts any "
                    "certificate, so an on-path attacker presenting one reads the alert bodies, the "
                    "per-user security-event email and the SMTP login credential",
                )
            )
    if sec.allow_unverified_alert_smtp_tls:
        out.append(
            (
                "allow_unverified_alert_smtp_tls",
                "an unauthenticated [alerts] SMTP hop is permitted to start an enforcing PHI instance "
                "— the serve gate that would otherwise refuse it is acknowledged away",
            )
        )
    if sec.allow_over_granted_store_principal:
        out.append(
            (
                "allow_over_granted_store_principal",
                "a store login holding more than the documented least-privilege grant is permitted "
                "to start an enforcing instance (ADR 0199) — the refusal the startup privilege "
                "preflight would otherwise raise is acknowledged away",
            )
        )
    # BACKLOG #1182: while the opt-in static-credential refusal is ON, each per-hop opt-out is a
    # deliberate departure from it, so the opt-outs are the loosening. With the refusal OFF (the shipped
    # default, owner decision 2026-09-23) nothing is refused and an opt-out is inert, so it is not
    # reported; the static-credential inventory itself is GET /security/posture's
    # `static_credential_hops` and `messagefoundry check`'s static-credentials line.
    if sec.require_nonstatic_credentials and sec.static_credential_accepted:
        named = ", ".join(sorted(sec.static_credential_accepted))
        out.append(
            (
                "static_credential_accepted",
                f"{len(sec.static_credential_accepted)} opt-out(s) from the static-credential refusal "
                f"are declared ({named}) — each named hop that exists runs on an unchanging "
                "credential or none, which ASVS 13.2.1 asks backend hops not to do (the serve log "
                "names any opt-out that matches no hop)",
            )
        )
    # --- the CONNECTION-scoped deviations (ADR 0153 decision 2; #333). None is a [security] switch, but
    # each is a declared departure from the one shipped posture, so they belong in the one registry an
    # operator reads — a deviation the registry cannot see is a second posture by the back door.
    if cleartext_hops:
        named = ", ".join(sorted(cleartext_hops))
        out.append(
            (
                "cleartext_accepted",
                f"{len(cleartext_hops)} connection(s) cross a CLEARTEXT hop by declaration "
                f"({named}) — the payload, and any credential the connection carries, ride those hops "
                "unencrypted and readable by anything on the path",
            )
        )
    if expiry_relaxed_hops:
        named = ", ".join(sorted(expiry_relaxed_hops))
        # BOTH halves, deliberately. Stating only the risk would overstate it (this is not verify-off:
        # ADR 0094 ORs one flag, X509_V_FLAG_NO_CHECK_TIME) and stating only the mitigation would be the
        # compensating-control-on-a-false-premise shape. An operator deciding whether to keep a bridge
        # open needs to know exactly which check is off and that nothing expires it.
        out.append(
            (
                "tls_allow_expired",
                f"{len(expiry_relaxed_hops)} outbound connection(s) accept an EXPIRED server "
                f"certificate ({named}) — indefinitely, with nothing that expires the relaxation or "
                "re-checks it; the chain signature, hostname match and key usage are still fully "
                "verified, so this is narrower than verify-off",
            )
        )
    if unverified_db_hops:
        named = ", ".join(sorted(unverified_db_hops))
        out.append(
            (
                "generic_odbc_tls_unenforced",
                f"{len(unverified_db_hops)} generic-ODBC database connection(s) leave TLS to the "
                f"driver with no verifying keyword set ({named}) — MessageFoundry cannot introspect an "
                "arbitrary driver's TLS posture, so the weakened-TLS refusal does not apply and the "
                "rows, and the DSN credential, may cross in plaintext",
            )
        )
    # Owner ruling 2026-09-24: the one per-hop declaration that ALLOWs rather than WARNs, so it is the
    # one an audit most needs to see. The engine takes the operator's word that the hop is secure.
    if attested_hops:
        named = ", ".join(sorted(attested_hops))
        out.append(
            (
                "tls_hop_attested",
                f"{len(attested_hops)} connection(s) are ATTESTED secure by means the engine cannot "
                f"see ({named}) — the engine stops protecting those hops and ALLOWs a cleartext or "
                "verify-off crossing it would otherwise refuse; if an attestation is false, the payload "
                "and any credential cross in the clear",
            )
        )
    if revocation_attested_hops:
        named = ", ".join(sorted(revocation_attested_hops))
        # BOTH halves, for the reason tls_allow_expired gives above, and each stated only as far as
        # it is true. The attestation relaxes ONE refusal (revocation) wherever it would apply; it
        # does not claim the hop verifies a chain, because authoring checks only the flag/reason
        # pair and cannot know the hop's TLS shape. What it cannot do is reach a cleartext or
        # verify-off hop, whose own refusals it never lifts -- that is the true mitigation.
        out.append(
            (
                "tls_revocation_attested",
                f"{len(revocation_attested_hops)} connection(s) attest that certificate revocation "
                f"is checked outside the engine ({named}) — wherever the posture-keyed revocation "
                "refusal would apply to those hops it is lifted, so a revoked certificate is caught "
                "only if that external PKI control works; the attestation never lifts a cleartext "
                "or verify-off refusal",
            )
        )
    # --- the STORE PRINCIPAL's observed privilege posture (#1008, ASVS 13.2.2). An OBSERVATION, like
    # the connection-scoped entries above and unlike every switch: the deviation is what the
    # engine's own database credential turns out to hold, which no [store] flag declares. Both arms are
    # reported and they read DIFFERENTLY on purpose — "could not observe" is the ABSENCE of a clean
    # result, and collapsing it into silence would make this registry assert a posture nobody checked.
    if store_privilege is not None:
        if store_privilege.status is StorePrivilegeStatus.UNOBSERVABLE:
            out.append(
                (
                    "store_principal_privileges_unobserved",
                    "the store principal's EFFECTIVE privileges could not be read "
                    f"({store_privilege.detail}) — the least-privilege grant both server-DB runbooks "
                    "prescribe is UNVERIFIED on this instance, so an over-granted database credential "
                    "would not be detected here; this is the absence of a clean result, not one",
                )
            )
        elif store_privilege.excess:
            named = ", ".join(store_privilege.excess)
            out.append(
                (
                    "store_principal_over_granted",
                    f"the store principal holds {len(store_privilege.excess)} privilege(s) BEYOND the "
                    f"least-privilege grant docs/DEPLOY-SERVER-DB.md prescribes ({named}) — the "
                    "engine's own database credential can reach data and administrative operations "
                    "its runbook says it must not",
                )
            )
    # --- the AUDIT CHAIN's observed keying (BACKLOG #1905). An observation, like the entry above: no
    # switch declares it. A store that holds a key but opened onto a keyless chain with rows carries
    # tamper-evidence an attacker with write access can forge, and nothing else in this registry
    # would say so -- the at-rest entries report a MISSING key, and here the key is present.
    if audit_chain_unkeyed:
        out.append(
            (
                "audit_chain_unkeyed",
                "the audit chain is keyless SHA-256 although a store key is configured -- its rows "
                "were written before the key was in hand, and opening with a key does not re-key "
                "existing rows, so anyone who can write audit_log can forge a row that verifies "
                "clean; stop the engine and run `messagefoundry rekey-audit` to verify the chain and "
                "key every row after it",
            )
        )
    # --- [store].schema_management = auto on a server backend (#305, ASVS 13.2.2). External is the
    # server-DB default; auto hands the schema DDL back to the runtime principal, which then needs
    # standing DDL rights. SQLite resolves to auto by construction and is never reported.
    if (
        store.backend is not StoreBackend.SQLITE
        and store.resolved_schema_management() is SchemaManagement.AUTO
    ):
        out.append(
            (
                "schema_management",
                "the engine runs its own schema DDL at open ([store].schema_management = 'auto'), so "
                "its runtime database principal must hold standing DDL rights (db_ddladmin on SQL "
                "Server, CREATE on the schema on Postgres) that steady-state operation never uses",
            )
        )
    return out


def settings_error_detail(exc: Exception) -> str:
    """Render a :func:`load_settings` failure WITHOUT echoing any configured value.

    WHY ``str(exc)`` IS NOT SAFE HERE. ``str(ValidationError)`` carries ``input_value=`` for every
    failing field, and for an ``after``-mode model validator that value is the whole section's input
    mapping. The secrets in ``_FILE_SECRET_KEYS`` come from the environment
    (``MEFOR_STORE_PASSWORD`` and siblings) and are in that mapping, so one missing ``[store].server``
    renders the store password into whatever the caller does with the string -- stdout, a pasted
    ticket, a PowerShell ``throw`` in a transcript. Field path plus message, never ``input`` and never
    ``ctx``, is enough for an operator to find the key and carries no configured value at all.

    A LONG VALUE IS NOT SAFER: pydantic abbreviates a long ``input_value`` repr from the middle, so a
    32-character password loses its head and discloses its tail.

    THIS IS THE RENDERER TO REACH FOR, AND AT LEAST FIFTEEN CALLERS STILL DO NOT REACH FOR IT.
    "At least", and never an enumeration, for two reasons this paragraph has already been wrong about
    once each.

    FIRST, THE NUMBER IS A MEASUREMENT AND NOT AN INVARIANT. Nothing gates a new ``except`` arm, so
    the next one lands without touching this paragraph; PR 1141 was open with one in it while this
    was being written. Re-measure before you quote it.

    SECOND, AND THIS IS THE ONE THAT BIT: THE INSTRUMENT DECIDES THE ANSWER, so read what it asked.
    This paragraph used to say SEVEN arms, then SIX, then FIVE, each from an AST walk for a literal
    ``str(<bound>)`` in the handler. That walk is BLIND TO AN F-STRING, and most of these sites use
    one. Re-run over ``messagefoundry/__main__.py`` at ``19c98e023`` asking instead whether the bound
    exception reaches ANY string rendering -- ``str()``, an f-string, ``%`` or ``.format`` -- of the
    20 ``except`` arms naming ``ValidationError``, **16** render it, not five. The narrow instrument
    was not measuring a smaller problem; it was measuring a smaller part of the same one. The earlier
    counts are kept above as what they were: readings, from a tool that answered an adjacent question.

    SO NO LIST HERE IS THE POPULATION. #1523 fixed ``_cluster_vip``; this change fixed ``_ai_policy``
    (and this paragraph said those five were what remained, under the narrow walk, until the broad
    one was run). ``ai-policy`` is also the only one RUN and confirmed to disclose a planted
    ``MEFOR_STORE_PASSWORD``, first here and now pinned by ``tests/test_cli_ai_policy.py``; every
    other site was read, not run, so what follows counts ARMS, not confirmed disclosures.

    WHERE TO START, IF YOU ARE THE ONE DOING THE SWEEP, because the arms are not equally bad and a
    count flattens them. ``_serve`` (``__main__.py`` around line 1495) and ``_supervise`` are the
    two that matter most: both render a boot-time ``load_settings`` failure with
    ``print(f"error: {exc}", file=sys.stderr)``, and the engine runs as a Windows service under NSSM,
    which captures that stream to a file (docs/SERVICE.md). On first deployment a ``[store]`` that
    fails validation would therefore write ``MEFOR_STORE_PASSWORD`` into a persisted service log, on
    every start attempt, with no operator present to see it -- and support-bundle assembly collects
    logs. ``ai-policy`` reached one IDE bridge read; that one reaches a file that keeps it. A third
    group -- ``_security`` and ``_alert`` -- validates JSON the operator just typed at a named path,
    where echoing the input back is arguably the point; do not sweep those without deciding that
    question separately.

    ``_emit_error`` IS NOT THE CHOKEPOINT, and the shape of the sweep depends on knowing that. It
    takes an already-rendered ``str``, not an exception, so it cannot call this function without a
    signature change; many of its 56 call sites pass hand-authored or deliberately value-carrying
    text that must NOT be re-rendered (the JSON-echo group above is the clearest kind); and half the
    arms above never touch it, printing straight to stderr through their own emitter. The shape that
    DOES work is already written, in ``messagefoundry/verify/runner.py``'s ``_load_settings``: a
    wrapper returning ``(settings, detail)`` so each caller keeps its own emitter, stream and exit
    code. That one renders safely and is still missing ``OSError``, so it is a third site holding
    half the fix. The sweep is NOT part of #1523 or of this change, and is stated rather than done,
    so nobody reads this docstring as covering it.
    """
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        errors = exc.errors(include_url=False)
        rows = [
            f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}"
            for err in errors[:_ERROR_DETAIL_ROWS]
        ]
        extra = (
            ""
            if len(errors) <= _ERROR_DETAIL_ROWS
            else f" (+{len(errors) - _ERROR_DETAIL_ROWS} more)"
        )
        return "; ".join(rows) + extra
    # Our own model validators raise plain ValueError with hand-authored text naming the key, and
    # FileNotFoundError/OSError carry a path. Neither reflects a configured value back.
    return str(exc)


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
    file_data: Mapping[str, Any] = {}

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
    # After _reject_relocated_keys so a MOVED key keeps its specific "moved to [security].X" message, and
    # over `file_data` rather than `data` so it never sees a key the env overlay or the desugar wrote.
    _reject_unknown_file_keys(file_data)
    _desugar_security(data)

    if cli:
        _merge(data, cli)

    settings = ServiceSettings.model_validate(data)
    # AFTER the CLI merge, so a `--host` that moved the socket off-box is reported as the posture
    # loosening it is. One-way: it only ever ADDS a loosening. See the helper for why.
    _reconcile_effective_bind(settings)
    if settings.cluster.vip.enabled:
        # Configuration only in this build (ADR 0056). Say so, or an operator who switched it on finds
        # out at the first failover that the address never moved.
        _log.warning(
            "[cluster.vip].enabled is true, but this build has no engine-managed VIP controller: nothing "
            "binds, releases or announces %s. Keep the external floating VIP or load balancer in front "
            "of the cluster (ADR 0056).",
            settings.cluster.vip.address,
        )
    return settings


#: The settings that refuse running a store with NO key (BACKLOG #1905, #1916). Each value names the
#: setting an operator changes, so a caller can say which one refused without restating the rule.
KEYLESS_REFUSED_BY_REQUIRE_ENCRYPTION = "[store].require_encryption"
KEYLESS_REFUSED_BY_NO_OPT_OUT = "[security].allow_unencrypted_phi"
KEYLESS_REFUSED_BY_NO_STRICT_ACK = "[security].allow_unencrypted_phi_under_strict_enforcement"
#: A key IS set, but the pinned built-in ``[store].key_provider`` does not read it (BACKLOG #2077).
#: Not an opt-out question, so no opt-out waives it: the settings name a key and the store would not
#: use it. ``keyless_opt_out_refusal`` never returns this; ``__main__._keyless_store_gate`` does, and
#: ``store.base._checked_active_key`` refuses the same case at open for every other command.
KEYLESS_REFUSED_BY_UNREAD_KEY = "[store].key_provider"


def keyless_opt_out_refusal(store: StoreSettings, security: SecuritySettings) -> str | None:
    """Which setting refuses running this store with no key, or ``None`` when the audited opt-out applies.

    The at-rest opt-out rule, stated once. ``serve`` and ``provision-admin`` apply it before they open
    anything; ``open_store`` applies it to every command at the one moment it matters -- a fresh store
    with no keying secret, whose first audit row would start a chain that stays keyless.

    It does not ask whether a key is CONFIGURED, on purpose. A key named in the settings that the key
    provider does not resolve still opens the store keyless, and that must be refused exactly as an
    absent key is. (A pinned built-in provider that ignores the key that is set is refused earlier,
    when the key resolves, since BACKLOG #2077; this rule stays the backstop for anything else.)
    ``[store].require_encryption`` wins over the opt-out; under ``[security].enforcement = enforce``
    the opt-out needs its second acknowledgment (ADR 0140)."""
    if store.require_encryption:
        return KEYLESS_REFUSED_BY_REQUIRE_ENCRYPTION
    if not store.allow_unencrypted_phi:
        return KEYLESS_REFUSED_BY_NO_OPT_OUT
    if (
        security.enforcement is SecurityEnforcement.ENFORCE
        and not security.allow_unencrypted_phi_under_strict_enforcement
    ):
        return KEYLESS_REFUSED_BY_NO_STRICT_ACK
    return None
