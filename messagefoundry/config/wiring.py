# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Code-first wiring: declare **Connections** and decorate **Router**/**Handler** functions.

A config module (loaded from a directory via :func:`load_config`) declares named inbound/outbound
**Connections** and registers Router/Handler scripts — wired by name, with no enclosing "channel"
object::

    from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File

    inbound("IB_Test_ADT", MLLP(port=2575), router="adt_router")
    outbound("FILE-OUT_Test_ADT", File(directory="./out/adt"))

    @router("adt_router")
    def route(msg):
        return ["archive"] if msg["MSH-9.1"] == "ADT" else []   # [] -> logged UNROUTED

    @handler("archive")
    def handle(msg):
        if msg["MSH-9.2"] not in ("A01", "A04", "A08"):
            return None                                          # None -> logged FILTERED
        msg["MSH-3"] = "FOUNDRY"
        return Send("FILE-OUT_Test_ADT", msg)

This module only **declares** the graph (the registry); running it (inbound → router → handlers →
outbox → ACK) is the engine's job. Routers/Handlers are pure: they return where a message goes,
they never do network I/O (the outbox worker delivers, preserving at-least-once).
"""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import os
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from messagefoundry.config.code_sets import (
    CODESETS_DIR_NAME,
    CodeSet,
    CodeSetError,
    activated as _code_sets_activated,
    code_set as _resolve_code_set,
    load_code_sets,
)
from messagefoundry.config.models import (
    AckAfter,
    AckMode,
    BuildupThreshold,
    ConnectorType,
    ContentType,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
    Validation,
)
from messagefoundry.parsing.message import Message, RawMessage

__all__ = [
    "ConnectionSpec",
    "MLLP",
    "Tcp",
    "X12",
    "File",
    "Timer",
    "Loopback",
    "Rest",
    "FHIR",
    "DICOM",
    "DICOMweb",
    "Database",
    "DatabasePoll",
    "Soap",
    "Sftp",
    "Ftp",
    "Send",
    "SetState",
    "EnvRef",
    "env",
    "CodeSet",
    "code_set",
    "Reference",
    "FileRef",
    "DatabaseRef",
    "ReferenceSpec",
    "ReferenceSourceSpec",
    "resolve_env_settings",
    "referenced_env_keys",
    "display_settings",
    "redacted_settings",
    "InboundConnection",
    "OutboundConnection",
    "Registry",
    "WiringError",
    "PortConflictError",
    "API_LISTENER_LABEL",
    "inbound_binding_conflicts",
    "resolve_listener_binding",
    "bindings_overlap",
    "Diagnostic",
    "inbound",
    "outbound",
    "build_inbound_connection",
    "build_outbound_connection",
    "parse_env_setting",
    "router",
    "handler",
    "load_config",
    "validate_config",
]


class WiringError(ValueError):
    """A connection/router/handler was declared wrong, or references something missing."""


class PortConflictError(WiringError):
    """Two inbound listeners — or a listener and a reserved service binding (the API listener) — want
    the same ``(host, port)``.

    A subclass of :class:`WiringError`, so every existing handler keeps working: the API still maps it
    to 422, ``messagefoundry check`` still reports it, and the runner's ADR 0031 per-connection
    isolation still records the offending inbound as failed (the engine comes up DEGRADED rather than
    aborting). Callers that care can still catch the conflict specifically."""


@dataclass(frozen=True)
class Diagnostic:
    """One config problem, for tools (e.g. the IDE Problems panel) that want all errors at once."""

    message: str
    file: str | None = None
    severity: str = "error"


@dataclass(frozen=True)
class ConnectionSpec:
    """The transport bits of a Connection (type + settings); the logic lives in Router/Handler."""

    type: ConnectorType
    settings: dict[str, Any]


# --- environment-specific values (DEV/PROD) ----------------------------------

#: Sentinel for "no default" so ``env("k", default=None)`` (a deliberate None) is distinguishable
#: from "unset" (which makes a missing value a hard load error).
_UNSET: Any = object()


@dataclass(frozen=True)
class EnvRef:
    """A reference to an environment-specific value (e.g. a downstream host that differs DEV vs PROD).

    The graph carries the *reference*; the engine resolves it against the running instance's
    environment values when it builds the connector. One graph therefore runs in every environment,
    and a referenced-but-undefined value fails **loud** at load/promote rather than silently
    becoming a blank host (the classic Mirth ``${key}`` footgun). Authored via :func:`env`."""

    key: str
    default: Any = _UNSET
    cast: Callable[[Any], Any] | None = None


def env(key: str, *, default: Any = _UNSET, cast: Callable[[Any], Any] | None = None) -> EnvRef:
    """Reference an environment-specific value, resolved per running instance (DEV/PROD).

    Use it inside a connection spec for anything that differs by environment — a downstream peer,
    a path, a credential::

        outbound("OB_EPIC_ADT", MLLP(host=env("epic_host"), port=env("epic_port", cast=int)))

    Values come from the instance's environment: ``environments/<env>.toml`` (non-secrets, versioned)
    overlaid with ``MEFOR_VALUE_<KEY>`` env vars (secrets). A referenced key with no value and no
    ``default`` makes the engine refuse to load/promote that graph — never a silent blank.

    The key is matched case-insensitively (lower-cased here, as it is on the value side), so
    ``env("EPIC_HOST")``, the file key ``epic_host``, and ``MEFOR_VALUE_EPIC_HOST`` all line up."""
    return EnvRef(key=key.lower(), default=default, cast=cast)


#: Named casts a ``connections.toml`` env-ref may request (ADR 0007). A data file/GUI can't author an
#: arbitrary Python callable the way :func:`env` can, so the file form is restricted to these — and
#: ``int`` is the only cast used across the migration estate today.
_NAMED_CASTS: dict[str, Callable[[Any], Any]] = {
    "int": int,
    "float": float,
    "bool": bool,
    "str": str,
}

#: The only keys an env-ref inline table may carry (the inverse of :func:`display_settings`).
_ENVREF_KEYS = frozenset({"env", "default", "cast"})


def parse_env_setting(value: Any) -> Any:
    """Decode one ``connections.toml`` settings value into a literal or an :class:`EnvRef` (ADR 0007).

    An inline table carrying the reserved key ``env`` (and only ``env``/``default``/``cast``) becomes an
    :class:`EnvRef` — the inverse of :func:`display_settings`'s ``{"env": key[, "default"]}`` encoding;
    ``cast`` is a **named** cast (``"int"``/``"float"``/``"bool"``/``"str"``) since a file can't carry a
    Python callable. Any other value (a scalar, list, or a plain dict like a REST ``headers`` map) is
    returned verbatim. Raises :class:`WiringError` on a malformed env marker or an unknown cast name."""
    if not (isinstance(value, dict) and "env" in value and set(value) <= _ENVREF_KEYS):
        return value
    key = value["env"]
    if not isinstance(key, str) or not key:
        raise WiringError(f"env reference must name a non-empty string key, got {key!r}")
    cast_name = value.get("cast")
    if cast_name is not None and cast_name not in _NAMED_CASTS:
        raise WiringError(
            f"env reference {key!r}: unknown cast {cast_name!r} "
            f"(use one of {', '.join(sorted(_NAMED_CASTS))})"
        )
    cast = _NAMED_CASTS[cast_name] if cast_name is not None else None
    default = value["default"] if "default" in value else _UNSET
    return EnvRef(key=key.lower(), default=default, cast=cast)


# --- code sets (reference lookup tables) -------------------------------------


def code_set(name: str) -> CodeSet:
    """Reference a managed reference table from ``codesets/<name>.{csv,toml}`` (next to ``--config``).

    The code-first alternative to a hand-maintained dict: capture it once at a module's top level
    (``DIET = code_set("epic_diets")``) or look it up at call time inside a handler
    (``code_set("epic_diets").get(x)``) — both resolve against the active set the loader/runner has
    published. Returns a frozen, read-only :class:`CodeSet` (a mapping: ``cs[k]`` / ``cs.get(k, d)`` /
    ``k in cs`` / ``len(cs)`` / iteration); it is shared across transforms, so it must not be mutated.

    A missing or malformed code set fails **loud** as a :class:`WiringError`, surfaced by ``validate`` /
    ``check`` / reload exactly like a missing ``env()`` value — never a silent empty table. The
    reference data is read-only, so the lookup stays pure (re-run-safe); see
    :mod:`messagefoundry.config.code_sets` for the one reload-vs-re-run caveat."""
    try:
        return _resolve_code_set(name)
    except CodeSetError as exc:
        raise WiringError(str(exc)) from exc


# --- reference sets (external-data enrichment, ADR 0006 Tier 1) ---------------
# A reference set is declared in a wiring module with Reference(name, source=…); the engine's
# ReferenceSyncRunner materializes the source OFF the message path into a versioned, encrypted store
# snapshot, and a Handler reads it PURELY at run time via reference("name").get(key) (the read accessor
# lives in messagefoundry.config.reference). The DECLARATION here is the source + cadence only.


@dataclass(frozen=True)
class ReferenceSourceSpec:
    """Where a reference set's data is materialized from (the analog of :class:`ConnectionSpec`).

    ``kind`` selects the source connector (``"file"`` today; ``"database"`` is ADR-0006 increment 2);
    ``settings`` carries its options (may hold :class:`EnvRef` values, resolved per environment)."""

    kind: str
    settings: dict[str, Any]


def FileRef(
    *,
    path: str | EnvRef,
    encoding: str = "utf-8",
) -> ReferenceSourceSpec:
    """A reference **source** backed by a local CSV/TOML file (ADR 0006 Tier 1).

    The file has the same shape as a code set (``code_set`` format: header row, first column the key;
    one value column → scalar, several → ``{header: cell}``; or a flat/nested TOML). It is the path for
    an externally-produced export (e.g. a nightly job dumps a provider directory to a share): the engine
    re-reads it on the set's refresh cadence and materializes it into a versioned, encrypted snapshot,
    so an updated export is picked up without a config reload. ``path`` may be an :func:`env` ref."""
    return ReferenceSourceSpec("file", {"path": path, "encoding": encoding})


def DatabaseRef(
    *,
    server: str | EnvRef,
    database: str | EnvRef,
    statement: str,
    key_column: str,
    value_column: str | None = None,
    auth: str = "sql",
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,
    port: int | EnvRef = 1433,
    encrypt: bool = True,
    trust_server_certificate: bool = False,
    connect_timeout: int = 15,
    app_name: str = "messagefoundry",
    odbc_driver: str = "ODBC Driver 18 for SQL Server",
    pool_max: int = 5,
) -> ReferenceSourceSpec:
    """A reference **source** backed by a SQL query (ADR 0006 increment 2; SQL Server via the
    ``[sqlserver]`` extra + ODBC Driver 18 — **production / supported**, like the DATABASE connector).

    The engine runs ``statement`` (a read-only ``SELECT``/proc) on the set's refresh cadence and builds
    the snapshot from the rows: ``key_column`` is the lookup key; ``value_column`` (if given) is that
    column's value, else the value is a dict of the remaining columns (the multi-column ``code_set``
    shape). Put secrets (``password``) in :func:`env`. TLS is on by default; weakening it needs
    ``MEFOR_ALLOW_INSECURE_TLS``. The dial-out is gated by the **fail-closed** ``[egress].allowed_db``
    allowlist, exactly like a DATABASE poll source — point the engine only at allowed hosts."""
    return ReferenceSourceSpec(
        "database",
        {
            "server": server,
            "database": database,
            "statement": statement,
            "key_column": key_column,
            "value_column": value_column,
            "auth": auth,
            "username": username,
            "password": password,
            "port": port,
            "encrypt": encrypt,
            "trust_server_certificate": trust_server_certificate,
            "connect_timeout": connect_timeout,
            "app_name": app_name,
            "odbc_driver": odbc_driver,
            "pool_max": pool_max,
        },
    )


@dataclass(frozen=True)
class ReferenceSpec:
    """A declared reference set: ``name`` + its :class:`ReferenceSourceSpec` + sync cadence.

    Held in :class:`Registry` and consumed by the engine's ``ReferenceSyncRunner``; the data lives in
    the store, read via ``reference(name)``. ``refresh_seconds`` is the materialization cadence (the
    runner also syncs once on startup); ``max_staleness_seconds`` (0 = off) is a reserved freshness
    knob for a follow-up."""

    name: str
    source: ReferenceSourceSpec
    refresh_seconds: float = 3600.0
    max_staleness_seconds: float = 0.0


def Reference(
    name: str,
    *,
    source: ReferenceSourceSpec,
    refresh_seconds: float = 3600.0,
    max_staleness_seconds: float = 0.0,
) -> None:
    """Declare a reference set into the graph being loaded (side-effecting, like :func:`inbound`).

    The engine materializes ``source`` into a versioned snapshot every ``refresh_seconds`` (and once at
    startup); a Handler reads it purely with ``reference(name).get(key)``. Example::

        Reference("provider_npi", source=FileRef(path=env("provider_npi_csv")), refresh_seconds=3600)
    """
    if refresh_seconds < 0:
        raise WiringError(f"Reference({name!r}): refresh_seconds must be >= 0")
    _active_registry().add_reference(
        ReferenceSpec(
            name=name,
            source=source,
            refresh_seconds=refresh_seconds,
            max_staleness_seconds=max_staleness_seconds,
        )
    )


# --- live lookup connections (handler-callable db_lookup, ADR 0010) -----------
# A DatabaseLookup declares a NAMED, read-only database connection a Handler queries LIVE at run time via
# db_lookup(name, statement, params) (the read accessor lives in messagefoundry.config.db_lookup). Unlike
# a reference set (a synced snapshot read purely), there is no statement or cadence here — only the
# connection; each call supplies its own statement. The engine builds one pooled executor from these.


@dataclass(frozen=True)
class DatabaseLookupSpec:
    """A declared live-lookup database connection: ``name`` + connection ``settings`` (no statement — the
    statement is supplied per :func:`~messagefoundry.config.db_lookup.db_lookup` call). ``settings`` may
    hold :class:`EnvRef` values (put secrets like ``password`` in :func:`env`)."""

    name: str
    settings: dict[str, Any]


def DatabaseLookup(
    name: str,
    *,
    server: str | EnvRef,
    database: str | EnvRef,
    auth: str = "sql",
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,
    port: int | EnvRef = 1433,
    encrypt: bool = True,
    trust_server_certificate: bool = False,
    connect_timeout: int = 15,
    app_name: str = "messagefoundry",
    odbc_driver: str = "ODBC Driver 18 for SQL Server",
    pool_max: int = 5,
    acquire_timeout: float = 30.0,  # cap a pooled-connection borrow (s) — fail transiently, not forever
) -> None:
    """Declare a named live-lookup database connection (SQL Server via the ``[sqlserver]`` extra + ODBC
    Driver 18 — **production / supported**, like the DATABASE connector). A Handler queries it at run time with
    ``db_lookup(name, statement, params)`` (a read-only ``SELECT``/proc); the rows come back as
    ``{column: value}`` dicts. Side-effecting, like :func:`Reference`/:func:`inbound`.

    Put secrets (``password``) in :func:`env`. TLS is on by default; weakening it needs
    ``MEFOR_ALLOW_INSECURE_TLS``. The dial-out is gated by the **fail-closed** ``[egress].allowed_db``
    allowlist, like a DATABASE source — point the engine only at allowed hosts. Example::

        DatabaseLookup("clarity", server=env("clarity_host"), database="Clarity",
                       username=env("clarity_user"), password=env("clarity_pw"))
    """
    _active_registry().add_lookup(
        DatabaseLookupSpec(
            name,
            {
                "server": server,
                "database": database,
                "auth": auth,
                "username": username,
                "password": password,
                "port": port,
                "encrypt": encrypt,
                "trust_server_certificate": trust_server_certificate,
                "connect_timeout": connect_timeout,
                "app_name": app_name,
                "odbc_driver": odbc_driver,
                "pool_max": pool_max,
                "acquire_timeout": acquire_timeout,
            },
        )
    )


def resolve_env_settings(settings: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``settings`` with every :class:`EnvRef` resolved against ``values``.

    Resolution order per ref: the environment value (cast if a ``cast`` was given), else its
    ``default``, else it's *missing*. Raises a single :class:`WiringError` listing **all** problems
    at once — both missing keys and values that fail their ``cast`` (naming setting/key/value) — so
    the failure is loud and actionable, not a raw ``ValueError`` traceback that names nothing and
    aborts on the first bad value (fail loud, never blank; review M-22)."""
    resolved: dict[str, Any] = {}
    missing: list[str] = []
    bad: list[str] = []
    for name, value in settings.items():
        if isinstance(value, EnvRef):
            if value.key in values:
                raw = values[value.key]
                if value.cast is None:
                    resolved[name] = raw
                else:
                    try:
                        resolved[name] = value.cast(raw)
                    except (ValueError, TypeError) as exc:
                        bad.append(f"setting {name!r} (env {value.key!r}={raw!r}): {exc}")
            elif value.default is not _UNSET:
                resolved[name] = value.default
            else:
                missing.append(value.key)
        else:
            resolved[name] = value
    problems: list[str] = []
    if missing:
        problems.append("missing: " + ", ".join(sorted(set(missing))))
    if bad:
        problems.append("uncastable: " + "; ".join(bad))
    if problems:
        raise WiringError(
            "environment value(s) unusable — "
            + "; ".join(problems)
            + " — set/fix them in this environment's values (environments/<env>.toml or MEFOR_VALUE_*)"
        )
    return resolved


def referenced_env_keys(settings: Mapping[str, Any]) -> list[str]:
    """The environment keys a settings dict references (sorted, de-duplicated) — for tooling."""
    return sorted({v.key for v in settings.values() if isinstance(v, EnvRef)})


def display_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    """A JSON-safe view of settings for introspection: each EnvRef becomes ``{"env": key[, default]}``."""
    out: dict[str, Any] = {}
    for name, value in settings.items():
        if isinstance(value, EnvRef):
            ref: dict[str, Any] = {"env": value.key}
            if value.default is not _UNSET:
                ref["default"] = value.default
            out[name] = ref
        else:
            out[name] = value
    return out


#: Settings keys whose values are credentials — redacted in the API metadata view. Secrets are
#: required to be ``env()`` refs (so they already render as ``{"env": ...}``); this is defence in
#: depth against an inline value, and it suppresses an ``env()`` *default* for a secret field. Covers
#: every credential-bearing connector setting (HTTP auth, DB user/password, SFTP key + passphrase).
_SECRET_SETTING_KEYS = frozenset(
    {
        "password",
        "username",
        "bearer_token",
        "basic_password",
        "basic_user",
        "key_password",
        "tls_key_password",  # MLLP-over-TLS encrypted-key passphrase (WP-13b)
        "private_key",
        "api_key",
        "token",
        # ADR 0024 — SMART Backend Services signing-key material (the minted access token / assertion
        # are runtime-only and never persisted, so only the key inputs need redacting in /metadata).
        "smart_private_key",
        "smart_private_key_password",
    }
)

#: Header names whose value is a credential — redacted inside a REST/SOAP ``headers`` table (the
#: project requires secrets via ``env()`` bearer/basic settings, not inline headers; this is defence
#: in depth for an operator who hard-codes one anyway). Compared case-insensitively.
_SECRET_HEADER_NAMES = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key", "cookie"}
)


def redacted_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    """A JSON-safe, secret-scrubbed view of a connection's settings for the API ``/metadata`` endpoint:
    each EnvRef becomes ``{"env": key}`` (the value is never resolved — only the key is shown), a
    credential field rendered inline is replaced with ``"***"`` (an ``env()`` *default* is dropped for
    a credential field so a fallback secret can't leak), and a credential header inside a ``headers``
    table is redacted too."""
    out: dict[str, Any] = {}
    for name, value in settings.items():
        is_secret = name in _SECRET_SETTING_KEYS
        if isinstance(value, EnvRef):
            ref: dict[str, Any] = {"env": value.key}
            if value.default is not _UNSET and not is_secret:
                ref["default"] = value.default
            out[name] = ref
        elif is_secret:
            out[name] = "***"
        elif name == "headers" and isinstance(value, dict):
            out[name] = {
                k: ("***" if str(k).lower() in _SECRET_HEADER_NAMES else v)
                for k, v in value.items()
            }
        else:
            out[name] = value
    return out


def MLLP(
    *,
    host: str | EnvRef | None = None,  # OUTBOUND: the downstream peer (required; may be env()).
    # INBOUND: omit — the bind interface is a service setting ([inbound].bind_host), not authored.
    port: int | EnvRef,
    encoding: str = "utf-8",
    # Inbound DoS guards (defaults mirror transports.mllp.DEFAULT_*; pass None/0 to disable):
    max_connections: int | None = 256,  # cap concurrent clients (connection-flood guard)
    receive_timeout: float | None = 60.0,  # close a client idle this many seconds (slowloris)
    max_frame_bytes: int | None = 16 * 1024 * 1024,  # cap one frame's bytes (OOM guard); both dirs
    connect_timeout: float = 10.0,  # outbound: TCP connect timeout (seconds)
    timeout_seconds: float = 30.0,  # outbound: wait this long for the ACK
    encoding_characters: str | None = None,  # OUTBOUND: re-encode MSH-1/MSH-2 delimiters per dest
    capture_response: bool = False,  # outbound: capture the application ACK (MSA/ERR) as a reply (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    # --- TLS (WP-13b, ADR 0002) — per-connection MLLP-over-TLS ---
    tls: bool = False,  # turn TLS on (inbound: present a server cert; outbound: verify the peer)
    tls_cert_file: str
    | None = None,  # inbound: SERVER cert (required when tls); outbound: CLIENT cert (mTLS)
    tls_key_file: str | None = None,  # private key for tls_cert_file
    tls_key_password: str
    | EnvRef
    | None = None,  # passphrase for an ENCRYPTED tls_key_file (put the secret in env())
    tls_ca_file: str
    | None = None,  # trust anchor — inbound: verify client certs (mTLS); outbound: verify server
    tls_verify: bool = True,  # OUTBOUND: verify the server cert (false is MITM-able → needs MEFOR_ALLOW_INSECURE_TLS)
    tls_check_hostname: bool = True,  # OUTBOUND: require the server cert to match `host`
) -> ConnectionSpec:
    """An MLLP endpoint. Inbound uses port/max_connections/receive_timeout/max_frame_bytes (the
    bind interface comes from the service's ``[inbound].bind_host``, so ``host`` is rejected on an
    inbound); outbound uses host/port/connect_timeout/timeout_seconds/max_frame_bytes. ``encoding``
    applies to framing in both directions. ``capture_response`` (outbound, ADR 0013) records the
    application ACK as a captured reply (a negative ACK still dead-letters/retries unchanged).

    ``encoding_characters`` (**outbound only**, Corepoint ``MsgSend -override component`` parity) makes
    this destination re-encode each outgoing message with a different set of HL7 delimiters before
    framing. Give the **5 MSH delimiter characters in MSH order** — MSH-1 (field separator) followed by
    the four MSH-2 characters (component, repetition, escape, subcomponent) — e.g. the HL7 default is
    ``"|^~\\\\&"``. The connector parses the payload with its *current* (MSH-derived) delimiters,
    rewrites MSH-1/MSH-2, and re-serializes the whole body with the new ones, so a downstream re-parse
    yields the same logical fields under the new delimiters. ``None`` (the default) leaves the payload
    **byte-identical** — fully backward compatible. The string is validated at connector build (exactly
    five characters, all distinct); a non-HL7 payload that can't be parsed fails the delivery loud
    (``DeliveryError``) rather than being silently corrupted.

    **TLS (WP-13b).** ``tls=True`` wraps the connection: inbound presents ``tls_cert_file``/``tls_key_file``
    (a server identity; ``tls_ca_file`` adds opt-in mTLS — require + verify a client cert); outbound
    verifies the server cert against ``tls_ca_file`` (or the system trust store) with hostname checking,
    and may present ``tls_cert_file`` for mTLS. ``tls_key_password`` decrypts a passphrase-encrypted
    ``tls_key_file`` (supply it via ``env()`` so the secret stays out of config — mirrors the API
    listener's ``MEFOR_API_TLS_KEY_PASSWORD``); omit it for an unencrypted key. ``tls_verify=False``
    (outbound) is MITM-able and refused unless ``MEFOR_ALLOW_INSECURE_TLS`` is set (loud warning) —
    exactly like LDAPS / SQL Server. TLS is TLS 1.2+ and composes with the ``[egress].allowed_mllp``
    allowlist (both enforced)."""
    return ConnectionSpec(
        ConnectorType.MLLP,
        {
            "host": host,
            "port": port,
            "encoding": encoding,
            "max_connections": max_connections,
            "receive_timeout": receive_timeout,
            "max_frame_bytes": max_frame_bytes,
            "connect_timeout": connect_timeout,
            "timeout_seconds": timeout_seconds,
            "encoding_characters": encoding_characters,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "tls": tls,
            "tls_cert_file": tls_cert_file,
            "tls_key_file": tls_key_file,
            "tls_key_password": tls_key_password,
            "tls_ca_file": tls_ca_file,
            "tls_verify": tls_verify,
            "tls_check_hostname": tls_check_hostname,
        },
    )


def Tcp(
    *,
    host: str | EnvRef | None = None,  # OUTBOUND: the downstream peer (required; may be env()).
    # INBOUND: omit — the bind interface is a service setting ([inbound].bind_host), not authored.
    port: int | EnvRef,
    # Framing: a preset name ("stx_etx" | "vt_fs" | "mllp") OR explicit start/end[/trailer] byte ints.
    framing: str | None = "stx_etx",
    start: int | None = None,  # explicit start delimiter byte (use instead of `framing`)
    end: int | None = None,  # explicit end delimiter byte
    trailer: int | None = None,  # explicit optional trailer byte
    encoding: str = "utf-8",
    # Inbound DoS guards (defaults mirror MLLP; pass None/0 to disable):
    max_connections: int | None = 256,  # cap concurrent clients (connection-flood guard)
    receive_timeout: float | None = 60.0,  # close a client idle this many seconds (slowloris)
    max_frame_bytes: int | None = 16 * 1024 * 1024,  # cap one frame's bytes (OOM guard); both dirs
    connect_timeout: float = 10.0,  # outbound: TCP connect timeout (seconds)
    timeout_seconds: float = 30.0,  # outbound: send/await-reply timeout
    expect_reply: bool = False,  # outbound: read one framed reply and treat it as confirmation
    capture_response: bool = False,  # outbound: capture the framed reply (requires expect_reply, ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
) -> ConnectionSpec:
    """A raw-TCP endpoint with **configurable delimiter framing**, relaying the payload **opaquely**
    (no structured parse) — built for X12-over-TCP feeds. Set ``framing`` to a preset
    (``"stx_etx"`` = ``0x02``/``0x03``, the default; ``"vt_fs"``/``"mllp"`` = ``0x0B``/``0x1C``/``0x0D``)
    **or** give explicit ``start``/``end`` (with optional ``trailer``) delimiter byte ints — not both.

    Inbound takes no ``host`` (the bind interface is ``[inbound].bind_host``); pair it with
    ``content_type="x12"`` on ``inbound(...)`` so the body routes as a ``RawMessage`` (ADR 0004).
    There is **no HL7 ACK** — a Handler may still return a payload, which is framed back to the
    sender. Outbound dials ``host``/``port``, frames + sends; with ``expect_reply`` it waits for one
    framed reply and treats receiving it as confirmation (the reply is **not** parsed — X12 997/TA1
    acks are a deferred follow-up). Delivery is at-least-once → the receiver **must be idempotent**."""
    return ConnectionSpec(
        ConnectorType.TCP,
        {
            "host": host,
            "port": port,
            "framing": framing,
            "start": start,
            "end": end,
            "trailer": trailer,
            "encoding": encoding,
            "max_connections": max_connections,
            "receive_timeout": receive_timeout,
            "max_frame_bytes": max_frame_bytes,
            "connect_timeout": connect_timeout,
            "timeout_seconds": timeout_seconds,
            "expect_reply": expect_reply,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
        },
    )


def X12(
    *,
    host: str | EnvRef | None = None,  # OUTBOUND: the downstream peer (required; may be env()).
    # INBOUND: omit — the bind interface is a service setting ([inbound].bind_host), not authored.
    port: int | EnvRef,
    encoding: str = "utf-8",
    # Inbound DoS guards (defaults mirror MLLP/TCP; pass None/0 to disable):
    max_connections: int | None = 256,  # cap concurrent clients (connection-flood guard)
    receive_timeout: float | None = 60.0,  # close a client idle this many seconds (slowloris)
    max_interchange_bytes: int | None = 16
    * 1024
    * 1024,  # cap one interchange's bytes (OOM); both dirs
    connect_timeout: float = 10.0,  # outbound: TCP connect timeout (seconds)
    timeout_seconds: float = 30.0,  # outbound: send/await-reply timeout
    expect_reply: bool = False,  # outbound: read one returned interchange and treat it as confirmation
    # --- ADR 0016: synchronous request/response (real-time eligibility 270/271, 278N, 277) ---
    capture_response: bool = False,  # capture the returned interchange (271/TA1) as a reply (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    ta1_required: bool = False,  # outbound: a delivery that reads no TA1/business reply is a retry
) -> ConnectionSpec:
    """A raw-TCP **ASC X12 EDI** endpoint (ADR 0012), framed by the interchange itself (``ISA…IEA``) —
    there are **no delimiter-framing knobs**: the segment terminator is discovered from each ISA header.
    Use this when the interchange is the frame; for partners who wrap each interchange in a fixed
    sentinel (STX/ETX, VT/FS) use ``Tcp(framing=...)`` instead.

    Inbound takes no ``host`` (the bind interface is ``[inbound].bind_host``); pair it with
    ``content_type="x12"`` on ``inbound(...)`` so the body routes as a ``RawMessage`` (ADR 0004) that a
    Router/Handler parses on demand via ``messagefoundry.parsing.x12``. The inbound is an opaque relay
    (no TA1/997/999). Outbound dials ``host``/``port`` and writes the interchange verbatim; with
    ``expect_reply`` it waits for one returned interchange as confirmation (not parsed). **Synchronous
    request/response** (ADR 0016): set ``capture_response`` (or ``reingress_to=`` a ``Loopback()``
    inbound) to capture the returned **271/TA1** as a reply — a **TA1** interchange acknowledgement is
    classified (TA1*A → accepted; TA1*R → permanent reject/dead-letter; TA1*E → accepted-with-warning,
    *not* retried), a business 271/277/278 returned instead is itself the confirmation; ``ta1_required``
    makes a no-reply a retry. Egress is gated by ``[egress].allowed_tcp`` (X12 shares the raw-TCP
    allowlist). Delivery is at-least-once → the receiver **must be idempotent** (a crash-re-send of a
    non-idempotent 270 yields a fresh 271 captured at the next ``response_seq``)."""
    return ConnectionSpec(
        ConnectorType.X12,
        {
            "host": host,
            "port": port,
            "encoding": encoding,
            "max_connections": max_connections,
            "receive_timeout": receive_timeout,
            "max_interchange_bytes": max_interchange_bytes,
            "connect_timeout": connect_timeout,
            "timeout_seconds": timeout_seconds,
            "expect_reply": expect_reply,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "ta1_required": ta1_required,
        },
    )


def File(
    *,
    directory: str | EnvRef,
    filename: str | EnvRef = "{MSH-10}.hl7",
    pattern: str = "*.hl7",
    poll_seconds: float = 1.0,
    encoding: str = "utf-8",
    min_age_seconds: float = 0.0,  # inbound: skip files modified within this window (partial writes)
    after_read: str = "move",  # inbound: "move" (to processed_subdir) | "delete"
    sort: str = "name",  # inbound: process order — "name" | "mtime"
    recursive: bool = False,  # inbound: also scan subdirectories
    max_file_bytes: int | None = 16 * 1024 * 1024,  # inbound: skip files over this (OOM guard)
    overwrite: bool = False,  # outbound: overwrite vs. uniquify a name collision
    processed_subdir: str = ".processed",
    error_subdir: str = ".error",
) -> ConnectionSpec:
    """A File endpoint. Inbound polls ``directory`` for ``pattern``; outbound writes ``filename``
    (atomically). ``encoding`` is the file charset (outbound). ``max_file_bytes`` mirrors
    transports.file.DEFAULT_MAX_FILE_BYTES (pass None/0 to disable)."""
    return ConnectionSpec(
        ConnectorType.FILE,
        {
            "directory": directory,
            "filename": filename,
            "pattern": pattern,
            "poll_seconds": poll_seconds,
            "encoding": encoding,
            "min_age_seconds": min_age_seconds,
            "after_read": after_read,
            "sort": sort,
            "recursive": recursive,
            "max_file_bytes": max_file_bytes,
            "overwrite": overwrite,
            "processed_subdir": processed_subdir,
            "error_subdir": error_subdir,
        },
    )


def Timer(
    *,
    body: str,
    interval_seconds: float | None = None,
    run_once: bool = False,
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """A Timer **source** (inbound): emit ``body`` on a schedule (ADR 0011).

    Set ``interval_seconds`` to fire every N seconds (heartbeat starts at t=0), or ``run_once=True`` to
    fire a single time. ``body`` is emitted verbatim — declare its format with
    ``inbound(..., content_type=...)``: the default ``hl7v2`` runs the HL7 peek/validate/ACK path, while
    ``text``/``json`` route a :class:`RawMessage` (ADR 0004). In a cluster the schedule is leader-gated,
    so exactly one node fires it (single-node fires as normal). ``cron`` scheduling is a follow-up."""
    return ConnectionSpec(
        ConnectorType.TIMER,
        {
            "body": body,
            "interval_seconds": interval_seconds,
            "run_once": run_once,
            "encoding": encoding,
        },
    )


def Loopback() -> ConnectionSpec:
    """A Loopback **inbound** (ADR 0013 Increment 2): an inert inbound with **no source**. Messages
    arrive *only* via the engine-internal ``ingress_handoff`` — a captured reply re-ingressed as a new
    inbound message (a capturing outbound names this inbound with ``reingress_to=...``).

    It is an ordinary ``inbound(...)`` otherwise: declare its ``router`` (which routes the answer) and
    ``content_type`` (``hl7v2`` → :class:`Message`; ``x12``/``text``/``json`` → :class:`RawMessage`). It
    takes **no** ``ack_mode`` (no external peer to ACK — forced to ``NONE``), no ``bind_address``/
    ``source_ip_allowlist`` (no socket), and no ``strict`` validation (no untrusted intake)."""
    return ConnectionSpec(ConnectorType.LOOPBACK, {})


def Rest(
    *,
    url: str | EnvRef,  # the endpoint; may be env() for DEV/PROD-specific hosts
    method: str = "POST",
    content_type: str = "application/json",
    headers: dict[str, str] | None = None,  # static extra headers (no secrets — not env()-resolved)
    bearer_token: str | EnvRef | None = None,  # Authorization: Bearer … (use env() for the secret)
    basic_user: str
    | EnvRef
    | None = None,  # HTTP Basic (with basic_password); use env() for secrets
    basic_password: str | EnvRef | None = None,
    timeout_seconds: float = 30.0,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the HTTP response body as a reply (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
) -> ConnectionSpec:
    """An HTTP(S) endpoint (**outbound only** today — there is no REST source yet, ADR 0003). The
    Handler produces the request body; this delivers it to ``url`` via ``method`` with ``content_type``
    + ``headers`` and optional bearer/basic auth. A 2xx is delivered; 5xx/408/429/connection errors
    retry; other 4xx dead-letter (a permanent rejection). Redirects are refused and the egress host is
    gated by ``[egress].allowed_http``. Put secrets in ``env()`` (``bearer_token``/``basic_*``), never
    in ``headers``. The receiving endpoint **must be idempotent** (delivery is at-least-once)."""
    return ConnectionSpec(
        ConnectorType.REST,
        {
            "url": url,
            "method": method,
            "content_type": content_type,
            "headers": headers or {},
            "bearer_token": bearer_token,
            "basic_user": basic_user,
            "basic_password": basic_password,
            "timeout_seconds": timeout_seconds,
            "verify_tls": verify_tls,
            "encoding": encoding,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
        },
    )


def FHIR(
    *,
    url: str | EnvRef,  # the FHIR service BASE url, e.g. https://host/fhir (may be env())
    fhir_version: str = "R4B",  # "R4B" (default) | "R5" | "STU3" — explicit, no autodetect
    format: str = "json",  # "json" (MVP); "xml" is deferred (ADR 0022 Options #5)
    interaction: str = "create",  # "create" (POST) | "update" (PUT) | "transaction" | "batch" (Bundle POST)
    conditional: str | None = None,  # None | "if-none-exist" | "conditional-update" | "if-match"
    conditional_query: str
    | None = None,  # search params for if-none-exist / conditional-update (e.g. "identifier=sys|val")
    headers: dict[str, str] | None = None,  # static extra headers (no secrets — not env()-resolved)
    bearer_token: str | EnvRef | None = None,  # Authorization: Bearer … (SMART/OAuth; use env())
    basic_user: str
    | EnvRef
    | None = None,  # HTTP Basic (with basic_password); use env() for secrets
    basic_password: str | EnvRef | None = None,
    timeout_seconds: float = 30.0,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the server reply / OperationOutcome (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
) -> ConnectionSpec:
    """A FHIR REST endpoint (**outbound destination only** — the inbound FHIR server facade is ADR 0023).
    The Handler produces a FHIR-JSON resource (or transaction/batch ``Bundle``) body; this delivers it to
    the FHIR service ``url`` (the **base**, e.g. ``https://host/fhir``) using the FHIR HTTP interaction:
    ``create`` → ``POST {base}/{ResourceType}``, ``update`` → ``PUT {base}/{ResourceType}/{id}``,
    ``transaction``/``batch`` → ``POST {base}`` with the Bundle. ``application/fhir+json`` media type
    (JSON-only MVP). The three opt-in conditional knobs are the idempotency/concurrency levers:
    ``if-none-exist`` (conditional create, ``If-None-Exist`` header), ``conditional-update`` (search-based
    ``PUT`` with ``conditional_query`` in the URL), ``if-match`` (version-aware ``PUT`` whose ``If-Match``
    ETag is derived from the resource's ``meta.versionId``). A 2xx is delivered; 5xx / a transient
    OperationOutcome / 408 / 429 / connection errors retry; other 4xx dead-letter. Redirects are refused
    and the egress host is gated by ``[egress].allowed_http``. Put secrets in ``env()``
    (``bearer_token``/``basic_*``), never in ``headers``. The FHIR server operation **must be idempotent**
    (delivery is at-least-once) — the conditional knobs are the native lever. ADR 0022."""
    return ConnectionSpec(
        ConnectorType.FHIR,
        {
            "url": url,  # stored under "url" (NOT base_url) so the §3.4 egress gate reads the same key
            "fhir_version": fhir_version,
            "format": format,
            "interaction": interaction,
            "conditional": conditional,
            "conditional_query": conditional_query,
            "headers": headers or {},
            "bearer_token": bearer_token,
            "basic_user": basic_user,
            "basic_password": basic_password,
            "timeout_seconds": timeout_seconds,
            "verify_tls": verify_tls,
            "encoding": encoding,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
        },
    )


def DICOM(
    *,
    ae_title: str
    | EnvRef,  # this engine's AE Title (the SCP's, or the SCU's calling AE in Phase 2)
    host: str | EnvRef | None = None,  # OUTBOUND SCU peer (Phase 2). INBOUND SCP: omit (bind is
    # [inbound].bind_host, like MLLP/X12 — not authored here).
    port: int | EnvRef = 104,  # standard DICOM port
    called_ae_title: str | EnvRef | None = None,  # the peer's AE Title (Phase-2 SCU destination)
    presentation_contexts: list[str] | None = None,  # SOP class UIDs to negotiate (None → SR + the
    # common image storage classes + Verification); transfer syntaxes default to the standard set
    calling_ae_allowlist: list[str]
    | None = None,  # SCP: only these calling AE Titles may associate
    # (None → any AE the peer-IP allowlist admits — the [inbound].source_ip_allowlist is the IP gate)
    require_called_ae_title: bool = True,  # SCP: a peer must address THIS engine's ae_title as called AE
    tls: bool = False,  # DICOM-over-TLS off-loopback (§9); a non-loopback cleartext SCP is refused
    # fail-closed unless `serve --allow-insecure-bind` (the generalized bind-guard)
    tls_cert_file: str | EnvRef | None = None,  # SCP server identity (required when tls=True)
    tls_key_file: str | EnvRef | None = None,  # the cert's private key (PEM)
    tls_ca_file: str
    | EnvRef
    | None = None,  # opt-in mTLS: require + verify a calling peer's client cert
    max_object_bytes: int | None = 128 * 1024 * 1024,  # per-C-STORE-object cap; over-cap → DIMSE
    # failure BEFORE the durable commit (the X12 max_interchange_bytes analog; OOM/DoS guard, §9)
    max_associations: int = 10,  # cap concurrent associations (connection-flood guard)
    max_pdu_size: int = 16384,  # cap one PDU's bytes (0 = unbounded); DoS guard
    timeout_seconds: float = 30.0,  # ACSE/DIMSE/network timeout
    connect_timeout: float = 10.0,  # outbound SCU: association-request timeout (Phase 2)
) -> ConnectionSpec:
    """A **DICOM DIMSE** endpoint (ADR 0025). **Phase 1 (built): the inbound C-STORE SCP** — pair it
    with ``content_type="dicom"`` on ``inbound(...)`` so a received object is base64-carried (ADR 0028)
    and routed as a ``RawMessage`` a Router/Handler parses on demand via ``messagefoundry.parsing.dicom``.
    Like ``X12``, the inbound takes **no** ``host`` (the bind interface is ``[inbound].bind_host``); it
    runs a ``pynetdicom`` AE C-STORE SCP **off the event loop**, commits each object durably to the
    ingress stage **before** returning C-STORE Success (commit-before-SUCCESS), accepts only the
    ``calling_ae_allowlist`` AE Titles (when set) from the ``[inbound].source_ip_allowlist`` peers, and
    rejects an object over ``max_object_bytes`` with a DIMSE failure before the commit. A non-loopback
    cleartext SCP (no ``tls``) is refused at startup unless ``serve --allow-insecure-bind`` (PHI on the
    wire, §9).

    **Phase 2 (built): the outbound C-STORE SCU + C-ECHO destination.** Pair the same ``DICOM(...)`` with
    ``outbound(...)`` to **forward** a DICOM object to a downstream PACS over a C-STORE association —
    ``host``/``called_ae_title``/``connect_timeout`` configure dialing the peer; egress is gated by
    ``[egress].allowed_tcp`` (a raw socket, like X12). The destination recovers the outgoing object's
    bytes from the base64 carriage (ADR 0028), runs the blocking association **off the event loop**, and
    classifies the C-STORE status onto the retry model (out-of-resources → retry; a hard refusal →
    dead-letter). ``test_connection`` issues a **C-ECHO** (the DIMSE reachability ping). The modern HTTP
    imaging lane is the sibling :func:`DICOMweb` STOW-RS destination."""
    return ConnectionSpec(
        ConnectorType.DIMSE,
        {
            "ae_title": ae_title,
            "host": host,
            "port": port,
            "called_ae_title": called_ae_title,
            "presentation_contexts": presentation_contexts,
            "calling_ae_allowlist": calling_ae_allowlist,
            "require_called_ae_title": require_called_ae_title,
            "tls": tls,
            "tls_cert_file": tls_cert_file,
            "tls_key_file": tls_key_file,
            "tls_ca_file": tls_ca_file,
            "max_object_bytes": max_object_bytes,
            "max_associations": max_associations,
            "max_pdu_size": max_pdu_size,
            "timeout_seconds": timeout_seconds,
            "connect_timeout": connect_timeout,
        },
    )


def DICOMweb(
    *,
    url: str | EnvRef,  # the DICOMweb STOW-RS BASE url, e.g. https://host/dicom-web (may be env())
    study_uid: str | EnvRef | None = None,  # POST to {base}/studies (server assigns) or, when set,
    # {base}/studies/{study_uid} (store into a known study)
    headers: dict[str, str] | None = None,  # static extra headers (no secrets — not env()-resolved)
    bearer_token: str
    | EnvRef
    | None = None,  # Authorization: Bearer … (OAuth; use env() for the secret)
    basic_user: str
    | EnvRef
    | None = None,  # HTTP Basic (with basic_password); use env() for secrets
    basic_password: str | EnvRef | None = None,
    timeout_seconds: float = 30.0,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the STOW-RS dicom+json response as a reply (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
) -> ConnectionSpec:
    """A **DICOMweb STOW-RS** endpoint (ADR 0025 Phase 2 — **outbound destination only**; an inbound
    STOW-RS receiver awaits the HTTP listener, ADR 0023). The Handler produces (or forwards) a DICOM
    Part-10 object — carried base64 over the str/store substrate (ADR 0028) — and this **stores** it to
    the DICOMweb service ``url`` (the **base**, e.g. ``https://host/dicom-web``) via a STOW-RS
    ``POST {base}/studies`` (or ``{base}/studies/{study_uid}`` when ``study_uid`` is set), framing the
    object as ``multipart/related; type="application/dicom"``. It is a **sibling of the REST destination**
    — it reuses the hardened HTTP plumbing (no-redirect TLS-verifying opener, cleartext-credential
    refusal, the retry/dead-letter classification, the ``[egress].allowed_http`` gate) and adds only the
    STOW-RS multipart framing + the ``application/dicom+json`` response classification (a per-instance
    ``FailedSOPSequence`` → permanent dead-letter; 5xx/408/429/connection errors → retry). This is the
    modern HTTP imaging lane that **exceeds** both Mirth's and Corepoint's DICOM options. Put secrets in
    ``env()`` (``bearer_token``/``basic_*``), never in ``headers``. The DICOMweb server **must be
    idempotent** (delivery is at-least-once; a re-store of the same SOPInstanceUID is the native lever)."""
    return ConnectionSpec(
        ConnectorType.DICOMWEB,
        {
            "url": url,  # stored under "url" (NOT base_url) so the §6.4 HTTP egress gate reads the same key
            "study_uid": study_uid,
            "headers": headers or {},
            "bearer_token": bearer_token,
            "basic_user": basic_user,
            "basic_password": basic_password,
            "timeout_seconds": timeout_seconds,
            "verify_tls": verify_tls,
            "encoding": encoding,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
        },
    )


def Database(
    *,
    server: str | EnvRef,  # SQL Server host (may be env())
    database: str | EnvRef,
    statement: str,  # parameterized SQL / proc call with :name placeholders
    auth: str = "sql",  # sql | integrated | entra
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,  # secret — use env()
    port: int | EnvRef = 1433,
    encrypt: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    trust_server_certificate: bool = False,
    connect_timeout: int = 15,
    app_name: str = "messagefoundry",
    odbc_driver: str = "ODBC Driver 18 for SQL Server",
    pool_max: int = 5,
    acquire_timeout: float = 30.0,  # cap a pooled-connection borrow (s) — fail transiently, not forever
    capture_response: bool = False,  # capture the statement's RETURNING/OUTPUT result-set (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    capture_max_rows: int = 100,  # cap captured rows (over-cap → outcome='unparseable', empty body)
) -> ConnectionSpec:
    """A SQL database endpoint (**outbound only** today; SQL Server via the ``[sqlserver]`` extra + ODBC
    Driver 18 — **production / supported**). The Handler produces a JSON-object body; the connector binds its keys
    to the ``:name`` parameters in ``statement`` (translated to positional ``?`` — always parameterized,
    never string-built) and runs it. A transient DB error retries; a constraint/data error (or a payload
    that doesn't match) dead-letters. Put secrets (``password``) in ``env()``. TLS is on by default;
    weakening it needs ``MEFOR_ALLOW_INSECURE_TLS``. The write **must be idempotent** (at-least-once)."""
    return ConnectionSpec(
        ConnectorType.DATABASE,
        {
            "server": server,
            "database": database,
            "statement": statement,
            "auth": auth,
            "username": username,
            "password": password,
            "port": port,
            "encrypt": encrypt,
            "trust_server_certificate": trust_server_certificate,
            "connect_timeout": connect_timeout,
            "app_name": app_name,
            "odbc_driver": odbc_driver,
            "pool_max": pool_max,
            "acquire_timeout": acquire_timeout,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "capture_max_rows": capture_max_rows,
        },
    )


def DatabasePoll(
    *,
    server: str | EnvRef,  # SQL Server host (may be env())
    database: str | EnvRef,
    poll_statement: str,  # SELECT of the next batch (e.g. WHERE status='NEW' ORDER BY id)
    mark_statement: str
    | None = None,  # UPDATE/DELETE run per row after the handler succeeds (:name)
    body_column: str | None = None,  # None → whole row as JSON; set → that column's value verbatim
    poll_seconds: float = 5.0,
    auth: str = "sql",  # sql | integrated | entra
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,  # secret — use env()
    port: int | EnvRef = 1433,
    encrypt: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    trust_server_certificate: bool = False,
    connect_timeout: int = 15,
    app_name: str = "messagefoundry",
    odbc_driver: str = "ODBC Driver 18 for SQL Server",
    pool_max: int = 5,
    acquire_timeout: float = 30.0,  # cap a pooled-connection borrow (s) — fail transiently, not forever
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """A SQL database polling **source** (inbound, ADR 0003 §3; SQL Server via the ``[sqlserver]`` extra +
    ODBC Driver 18 — **production / supported**). Every ``poll_seconds`` it runs ``poll_statement`` (a ``SELECT``),
    hands each row to the bound router as a body, then runs ``mark_statement`` (bound from the row's
    columns) so the row isn't re-read — the File source's *process-then-mark-done* shape. At-least-once:
    a crash before the mark re-emits the row, so the downstream pipeline **must tolerate duplicates**.

    Lead pattern is a status column: ``poll_statement='SELECT id, payload FROM mf_inbox WHERE status=\\'NEW\\''``
    + ``mark_statement='UPDATE mf_inbox SET status=\\'DONE\\' WHERE id=:id'`` (a ``DELETE`` or a
    high-water-mark ``UPDATE`` work through the same ``mark_statement``). ``body_column`` unset → the
    whole row as a JSON object (pair with ``content_type=json``); set → that one column's value verbatim
    (e.g. a column holding an HL7 message → ``content_type=hl7v2``). Put secrets (``password``) in
    ``env()``; TLS is on by default (weakening needs ``MEFOR_ALLOW_INSECURE_TLS``); the polled ``server``
    is gated by ``[egress].allowed_db``."""
    return ConnectionSpec(
        ConnectorType.DATABASE,
        {
            "server": server,
            "database": database,
            "poll_statement": poll_statement,
            "mark_statement": mark_statement,
            "body_column": body_column,
            "poll_seconds": poll_seconds,
            "auth": auth,
            "username": username,
            "password": password,
            "port": port,
            "encrypt": encrypt,
            "trust_server_certificate": trust_server_certificate,
            "connect_timeout": connect_timeout,
            "app_name": app_name,
            "odbc_driver": odbc_driver,
            "pool_max": pool_max,
            "acquire_timeout": acquire_timeout,
            "encoding": encoding,
        },
    )


def Soap(
    *,
    url: str | EnvRef,  # the SOAP endpoint (may be env())
    soap_action: str | EnvRef | None = None,  # SOAPAction (1.1 header / 1.2 content-type param)
    soap_version: str = "1.1",  # "1.1" | "1.2"
    headers: dict[str, str] | None = None,  # static extra headers (no secrets — not env()-resolved)
    bearer_token: str | EnvRef | None = None,  # Authorization: Bearer … (use env() for the secret)
    basic_user: str | EnvRef | None = None,
    basic_password: str | EnvRef | None = None,
    timeout_seconds: float = 30.0,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the SOAP response envelope as a reply (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    # --- ADR 0015: mutual TLS + WS-* (Timestamp / UsernameToken / WS-Addressing) ---
    client_cert_file: str
    | EnvRef
    | None = None,  # PEM client cert (mTLS); requires client_key_file
    client_key_file: str | EnvRef | None = None,  # PEM private key (path or env() text)
    client_key_password: str | EnvRef | None = None,  # key passphrase — secret, use env()
    ws_security: bool = False,  # stamp <wsse:Security> (Timestamp + optional UsernameToken) in send()
    ws_username: str | EnvRef | None = None,  # UsernameToken username (defaults to basic_user)
    ws_password: str | EnvRef | None = None,  # UsernameToken password (defaults to basic_password)
    ws_password_type: str = "text",  # "text" (PasswordText; recommended over mTLS) | "digest"
    ws_addressing: bool = False,  # stamp <wsa:Action/To/MessageID> in send(); requires soap_version 1.2
    ws_timestamp_ttl_seconds: int = 300,  # Created→Expires window (must be >= max retry backoff)
) -> ConnectionSpec:
    """A SOAP web-service endpoint (**outbound only**, ADR 0003 + 0015).

    *Plain mode* (default): the Handler produces the **full SOAP envelope** and this POSTs it to ``url``
    with the SOAP ``Content-Type`` (+ a ``SOAPAction`` header for 1.1). *WS-\\* mode* (``ws_addressing``
    / ``ws_security``, ADR 0015): the Handler produces only the operation **``<Body>`` fragment** and
    the transport wraps it + stamps the non-deterministic ``<wsa:MessageID>`` / ``<wsu:Timestamp>`` /
    optional ``<wsse:UsernameToken>`` headers in ``send()`` (so a pure transform never mints them);
    WS-\\* requires ``soap_version="1.2"``. ``client_cert_file``/``client_key_file`` enable **mutual
    TLS** (incompatible with ``verify_tls=False``).

    A WS-Security auth/expiry fault, a **Sender/Client** fault, or an unrecognized fault dead-letters;
    a **Receiver/Server** fault retries; otherwise the HTTP status decides. Put secrets in ``env()``
    (``bearer_token``/``basic_*``/``client_key_password``/``ws_password``); the host is gated by
    ``[egress].allowed_http`` (shared with REST — **populate it for a PHI mTLS destination**). The
    operation **must be idempotent**: an at-least-once re-send mints a fresh ``<wsa:MessageID>`` (correct
    WS-\\* retry semantics), so the partner's dedup must treat a re-send as a retry, not a duplicate."""
    return ConnectionSpec(
        ConnectorType.SOAP,
        {
            "url": url,
            "soap_action": soap_action,
            "soap_version": soap_version,
            "headers": headers or {},
            "bearer_token": bearer_token,
            "basic_user": basic_user,
            "basic_password": basic_password,
            "timeout_seconds": timeout_seconds,
            "verify_tls": verify_tls,
            "encoding": encoding,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "client_cert_file": client_cert_file,
            "client_key_file": client_key_file,
            "client_key_password": client_key_password,
            "ws_security": ws_security,
            "ws_username": ws_username,
            "ws_password": ws_password,
            "ws_password_type": ws_password_type,
            "ws_addressing": ws_addressing,
            "ws_timestamp_ttl_seconds": ws_timestamp_ttl_seconds,
        },
    )


def Sftp(
    *,
    host: str | EnvRef,  # the SFTP/SSH server (may be env())
    port: int | EnvRef = 22,
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,  # secret — use env()
    private_key: str | EnvRef | None = None,  # PEM private key text/path — secret, use env()
    key_password: str | EnvRef | None = None,  # passphrase for an encrypted key — secret, use env()
    known_hosts: str | EnvRef | None = None,  # extra known_hosts file (system hosts always loaded)
    remote_dir: str | EnvRef,
    filename: str | EnvRef = "{MSH-10}.hl7",  # outbound: upload name (may template HL7 fields)
    pattern: str = "*.hl7",  # inbound: glob of files to poll
    poll_seconds: float = 5.0,  # inbound: poll interval
    after_read: str = "move",  # inbound: "move" (to processed_subdir) | "delete"
    min_age_seconds: float = 0.0,  # inbound: skip files modified within this window (partial writes)
    max_file_bytes: int | None = 16 * 1024 * 1024,  # inbound: skip files over this (OOM guard)
    overwrite: bool = False,  # outbound: overwrite vs. uniquify a name collision
    processed_subdir: str = ".processed",
    error_subdir: str = ".error",
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """An **SFTP** (SSH file transfer) endpoint — source **and** destination (ADR 0003 follow-on).

    Inbound polls ``remote_dir`` for ``pattern`` (process-then-move/delete, at-least-once); outbound
    uploads to ``remote_dir``/``filename`` (write to a temp name then rename, so a poller never sees a
    partial). Needs the ``[sftp]`` extra (``pip install 'messagefoundry[sftp]'``; paramiko is lazily
    imported). **Host-key verification is ON by default** (system + ``known_hosts``; an unknown key is
    refused) — accepting an unknown key needs ``MEFOR_ALLOW_INSECURE_TLS``. Put secrets (``password``/
    ``private_key``/``key_password``) in ``env()``. The host is gated by ``[egress].allowed_remote``
    (both directions). At-least-once: an upload may re-send and a poll may re-emit, so downstreams
    **must be idempotent**."""
    return ConnectionSpec(
        ConnectorType.REMOTEFILE,
        {
            "protocol": "sftp",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "private_key": private_key,
            "key_password": key_password,
            "known_hosts": known_hosts,
            "remote_dir": remote_dir,
            "filename": filename,
            "pattern": pattern,
            "poll_seconds": poll_seconds,
            "after_read": after_read,
            "min_age_seconds": min_age_seconds,
            "max_file_bytes": max_file_bytes,
            "overwrite": overwrite,
            "processed_subdir": processed_subdir,
            "error_subdir": error_subdir,
            "encoding": encoding,
        },
    )


def Ftp(
    *,
    host: str | EnvRef,  # the FTP server (may be env())
    port: int | EnvRef = 21,
    tls: bool = False,  # True → FTPS (explicit TLS, PROT P); False → plain ftp
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,  # secret — use env()
    remote_dir: str | EnvRef,
    filename: str | EnvRef = "{MSH-10}.hl7",  # outbound: upload name (may template HL7 fields)
    pattern: str = "*.hl7",  # inbound: glob of files to poll
    poll_seconds: float = 5.0,  # inbound: poll interval
    after_read: str = "move",  # inbound: "move" (to processed_subdir) | "delete"
    min_age_seconds: float = 0.0,  # inbound: skip files modified within this window (partial writes)
    max_file_bytes: int | None = 16 * 1024 * 1024,  # inbound: skip files over this (OOM guard)
    overwrite: bool = False,  # outbound: overwrite vs. uniquify a name collision
    processed_subdir: str = ".processed",
    error_subdir: str = ".error",
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """An **FTP** (``tls=False``) or **FTPS** (``tls=True`` — explicit TLS) endpoint, source **and**
    destination (stdlib ``ftplib`` — no extra). Same poll/upload shape as :func:`Sftp`.

    Plain ``ftp`` transmits credentials in **cleartext**: supplying a ``username``/``password`` over
    plain ``ftp`` is **refused** unless ``MEFOR_ALLOW_INSECURE_TLS`` is set (use ``tls=True`` for FTPS,
    or :func:`Sftp`). FTPS encrypts the control + data channels, so credentials are fine there. Put
    secrets (``password``) in ``env()``. The host is gated by ``[egress].allowed_remote`` (both
    directions). At-least-once → downstreams **must be idempotent**."""
    return ConnectionSpec(
        ConnectorType.REMOTEFILE,
        {
            "protocol": "ftps" if tls else "ftp",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "remote_dir": remote_dir,
            "filename": filename,
            "pattern": pattern,
            "poll_seconds": poll_seconds,
            "after_read": after_read,
            "min_age_seconds": min_age_seconds,
            "max_file_bytes": max_file_bytes,
            "overwrite": overwrite,
            "processed_subdir": processed_subdir,
            "error_subdir": error_subdir,
            "encoding": encoding,
        },
    )


@dataclass(frozen=True)
class Send:
    """A Handler's instruction to deliver ``message`` to a named outbound connection."""

    to: str
    message: Message | RawMessage | str


#: JSON-serializable scalar/container types a :class:`SetState` value may carry. Validated at
#: construction (fail loud in the author's code, not deep in a store INSERT), and what
#: :func:`messagefoundry.config.state.state_get` returns on a hit.
StateValue = str | int | float | bool | None | list[Any] | dict[str, Any]


@dataclass(frozen=True)
class SetState:
    """A Handler's instruction to **declare** a state write (cross-message correlation, ADR 0005).

    A Handler does not mutate state imperatively; it returns ``SetState(namespace, key, value)``
    alongside its :class:`Send`\\ s, and the engine applies the upsert **inside the routed→outbound
    handoff transaction** — so a crash before commit leaves no state and a re-run applies it exactly
    once (preserving the staged pipeline's pure-re-run invariant). ``value`` must be JSON-serializable
    (validated here); read it back synchronously with
    :func:`messagefoundry.config.state.state_get`."""

    namespace: str
    key: str
    value: StateValue

    def __post_init__(self) -> None:
        # Validate at construction so a non-serializable value fails in the author's handler (with a
        # clear message) rather than deep inside the store's INSERT during a handoff. namespace/key
        # are the composite PK and must be non-empty strings.
        if not isinstance(self.namespace, str) or not self.namespace:
            raise WiringError("SetState namespace must be a non-empty string")
        if not isinstance(self.key, str) or not self.key:
            raise WiringError("SetState key must be a non-empty string")
        try:
            import json

            json.dumps(self.value)
        except (TypeError, ValueError) as exc:
            raise WiringError(
                f"SetState({self.namespace!r}, {self.key!r}, ...): value must be JSON-serializable "
                f"(str/int/float/bool/None/list/dict) — {exc}"
            ) from exc


#: What a Router/Handler receives: a mutable HL7 :class:`Message`, or a :class:`RawMessage` for a
#: non-HL7 inbound (ADR 0004). The author knows which — a Router/Handler is bound to one inbound.
Payload = Message | RawMessage
RouterFn = Callable[[Payload], "list[str] | str | None"]
#: A Handler returns deliveries and/or state writes (ADR 0005): a single :class:`Send`/:class:`SetState`,
#: a mixed list, or ``None`` (filtered). ``Send``-only returns are unchanged — backward compatible.
HandlerFn = Callable[[Payload], "Send | SetState | list[Send | SetState] | None"]


@dataclass(frozen=True)
class InboundConnection:
    name: str
    spec: ConnectionSpec
    router: str
    ack_mode: AckMode = AckMode.ORIGINAL
    # None = inherit the global [inbound] ack_after default; an explicit value overrides it. Resolved
    # in the RegistryRunner, which rejects 'delivered' until that path is implemented (ADR 0001).
    ack_after: AckAfter | None = None
    validation: Validation = field(default_factory=Validation)
    content_type: ContentType = ContentType.HL7V2  # payload format (ADR 0004); HL7V2 = the HL7 path
    # Operability (Tier 4): free-form operator metadata (owner/runbook/env labels — surfaced by the
    # API, never used for routing); a per-connection inbound bind interface that overrides the service
    # [inbound].bind_host; and an inbound peer-IP allowlist (MLLP/TCP listen sources only). All
    # default to None/absent = unchanged behaviour.
    metadata: Mapping[str, Any] | None = None
    bind_address: str | None = None
    source_ip_allowlist: tuple[str, ...] | None = None
    # Corepoint-style event log overrides (#46): None = inherit the matching [diagnostics] master switch
    # for this connection; True/False = explicit override. capture_ack → "Response Sent" (ADR 0021);
    # capture_connection_errors → the inbound connection_event log (lifecycle + pre-ingress failures).
    capture_ack: bool | None = None
    capture_connection_errors: bool | None = None
    source_file: str | None = None  # where it was declared (for IDE go-to-definition)
    source_line: int | None = None


@dataclass(frozen=True)
class OutboundConnection:
    name: str
    spec: ConnectionSpec
    # None = inherit the global [delivery] default; an explicit value overrides it. Resolution
    # (per-connection override > [delivery] global default > built-in) happens in the RegistryRunner.
    retry: RetryPolicy | None = None
    ordering: OrderingMode | None = None
    internal_error: InternalErrorPolicy | None = None
    buildup: BuildupThreshold | None = None
    # Shadow / parallel-run egress suppression (#15). False = deliver normally; True = the delivery
    # worker suppresses the real egress + finalizes PROCESSED. [shadow].simulate_all_egress forces it on.
    simulate: bool = False
    metadata: Mapping[str, Any] | None = (
        None  # operability labels (Tier 4); API-surfaced, not routing
    )
    source_file: str | None = None
    source_line: int | None = None


# --- inbound listener port-conflict detection (review low-13) -----------------
# A listening source (MLLP/TCP/X12/DICOM C-STORE SCP) binds a local (host, port); two that bind the
# SAME port on OVERLAPPING interfaces collide at OS bind time with an EADDRINUSE that would otherwise
# abort the engine (or a single listener) with a bare, unattributed OSError. These primitives catch it
# statically — Registry.port_collisions at validate/check/load (literal ports), inbound_binding_conflicts
# (env-resolved + reserved-port aware) at the runner's start/reload — and the RegistryRunner also
# classifies the runtime bind failure, so a conflict always names the connection(s) + the contended port.

#: Connector types that bind a local listening port (so a port conflict is possible). File/Timer/
#: Loopback/RemoteFile sources never bind a listening port. A DATABASE poll source carries a ``port``
#: (the SQL server's), but it DIALS OUT — it must not be mistaken for a bind (a latent false positive
#: the literal-port-only check used to have, now excluded by this filter).
_LISTEN_TYPES: frozenset[ConnectorType] = frozenset(
    {ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.X12, ConnectorType.DIMSE}
)

#: Host spellings that mean "every interface": a wildcard bind contends with ANY host on the same port.
# B104 false positive: these are wildcard spellings we DETECT for port-conflict analysis, not a bind.
_WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::", "*", "::0"})  # nosec B104

#: Label for the reserved engine API-listener binding in a port-conflict message — the single source of
#: truth shared by the engine (which reserves it at runtime) and the ``connection`` CLI (which reserves
#: it when validating an edit). E.g. "inbound 'X' binds port 8765, reserved for the engine API listener
#: ([api].port)".
API_LISTENER_LABEL = "the engine API listener ([api].port)"


@dataclass(frozen=True)
class _Binding:
    """One resolved listener binding for conflict comparison: a display ``label`` + normalized
    ``host`` + ``port``. ``host`` is ``None`` when it inherits the (here-unknown) service
    ``[inbound].bind_host`` — two such inheritors resolve to the same interface, so they overlap."""

    label: str
    host: str | None
    port: int


def _normalize_bind_host(host: str | None) -> str | None:
    """Canonicalize a bind host for overlap comparison. ``None`` (inherit ``[inbound].bind_host``) is
    kept as ``None``; a wildcard spelling (``0.0.0.0``/``::``/``*``) folds to ``"*"`` (binds every
    interface); ``localhost`` folds to ``127.0.0.1``. IPv6 ``::1`` is left distinct from ``127.0.0.1``
    (whether v4/v6 loopback contend is OS-dependent — the runtime bind catch backstops that edge)."""
    if host is None:
        return None
    h = host.strip().lower()
    if h in _WILDCARD_HOSTS:
        return "*"
    if h == "localhost":
        return "127.0.0.1"
    return h


def _hosts_overlap(a: str | None, b: str | None) -> bool:
    """Whether two normalized bind hosts contend for the same port. A wildcard (``"*"``) overlaps every
    host; the inherit sentinel (``None``) overlaps another inheritor (same resolved bind_host) but NOT
    an explicit distinct interface — that may be a different NIC, so don't false-positive (the runner's
    env-resolved pass, which knows the real bind_host, decides those exactly)."""
    if a == "*" or b == "*":
        return True
    if a is None or b is None:
        return a is None and b is None
    return a == b


def _binding_conflicts(bindings: list[_Binding]) -> list[tuple[_Binding, _Binding]]:
    """Every pair of bindings sharing a port on overlapping interfaces, in declaration order."""
    out: list[tuple[_Binding, _Binding]] = []
    for i, a in enumerate(bindings):
        for b in bindings[i + 1 :]:
            if a.port == b.port and _hosts_overlap(a.host, b.host):
                out.append((a, b))
    return out


def _resolve_port(raw: Any, env_values: Mapping[str, Any]) -> int | None:
    """Resolve a connector ``port`` setting to an ``int`` when possible, else ``None`` (uncheckable).

    Handles a literal ``int``, a string literal (``"2575"`` from ``connections.toml``), and an
    :func:`env` ref (resolved against ``env_values``, applying its cast). A ``bool`` (an ``int``
    subclass) or an unresolved/unparseable value yields ``None`` so the caller simply skips it — a
    missing ``env()`` value is reported loud elsewhere (when the connector is built), not doubled here."""
    if isinstance(raw, EnvRef):
        if raw.key not in env_values:
            return None
        value: Any = env_values[raw.key]
        if raw.cast is not None:
            try:
                value = raw.cast(value)
            except (ValueError, TypeError):
                return None
        raw = value
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw.strip())
        except ValueError:
            return None
    return None


def resolve_listener_binding(
    ic: "InboundConnection", *, bind_host: str, env_values: Mapping[str, Any]
) -> tuple[str | None, int] | None:
    """The ``(normalized_host, port)`` a listener inbound will bind, or ``None`` when it binds no
    checkable listening port (not a listening source, or an ``env()`` port with no value yet). The host
    is the per-connection ``bind_address`` else the service ``bind_host`` (matching ``_source_config``),
    normalized for overlap comparison."""
    if ic.spec.type not in _LISTEN_TYPES:
        return None
    port = _resolve_port(ic.spec.settings.get("port"), env_values)
    if port is None:
        return None
    return _normalize_bind_host(ic.bind_address or bind_host), port


def bindings_overlap(host_a: str | None, port_a: int, host_b: str | None, port_b: int) -> bool:
    """Whether two resolved ``(host, port)`` listener bindings contend for the same socket. Hosts are
    (re-)normalized defensively, so a caller may pass a raw reserved host (e.g. ``"0.0.0.0"``)."""
    return port_a == port_b and _hosts_overlap(
        _normalize_bind_host(host_a), _normalize_bind_host(host_b)
    )


def inbound_binding_conflicts(
    registry: "Registry",
    *,
    bind_host: str,
    env_values: Mapping[str, Any],
    reserved: Sequence[tuple[str, str, int]] = (),
) -> list[str]:
    """Human-readable port-conflict messages for the inbound listeners in ``registry``, resolved
    against this instance's settings — the authoritative pass the runner runs at start/reload.

    Unlike :meth:`Registry.port_collisions` (registry-only, literal ports), this resolves ``env()``
    ports and the EFFECTIVE bind host (a connection's ``bind_address`` else the service ``bind_host``),
    and checks each listener against the ``reserved`` service bindings — each a ``(label, host, port)``,
    e.g. the engine's API listener — so an inbound that would steal the API's port is caught here rather
    than as a bare bind failure. Returns ``[]`` when there is no conflict."""
    listeners: list[_Binding] = []
    for conn in registry.inbound.values():
        binding = resolve_listener_binding(conn, bind_host=bind_host, env_values=env_values)
        if binding is None:
            continue  # not a listener, or an env() port with no value yet (reported loud at build)
        listeners.append(_Binding(conn.name, binding[0], binding[1]))
    messages = [
        f"inbound connections {a.label!r} and {b.label!r} both bind port {a.port}"
        for a, b in _binding_conflicts(listeners)
    ]
    for label, rhost, rport in reserved:
        for listener in listeners:
            if bindings_overlap(listener.host, listener.port, rhost, rport):
                messages.append(
                    f"inbound connection {listener.label!r} binds port {listener.port}, "
                    f"reserved for {label}"
                )
    return messages


@dataclass
class Registry:
    """The wired graph produced by loading config modules."""

    inbound: dict[str, InboundConnection] = field(default_factory=dict)
    outbound: dict[str, OutboundConnection] = field(default_factory=dict)
    routers: dict[str, RouterFn] = field(default_factory=dict)
    handlers: dict[str, HandlerFn] = field(default_factory=dict)
    # Reference lookup tables loaded from <config_dir>/codesets/ — attached so a runner can re-publish
    # this graph's code sets as the active set while its routers/handlers run (call-time resolution).
    code_sets: dict[str, CodeSet] = field(default_factory=dict)
    # Reference-set declarations (ADR 0006): name -> source + cadence. The engine's ReferenceSyncRunner
    # materializes each into a store snapshot; reference(name) reads the snapshot (data lives in the
    # store, not here). Carried with the graph so a reload re-arms the sync set atomically.
    references: dict[str, ReferenceSpec] = field(default_factory=dict)
    # Live-lookup connection declarations (ADR 0010): name -> connection settings. The RegistryRunner
    # builds one pooled executor from these; db_lookup(name, ...) queries it at handler run time. Carried
    # with the graph so a reload re-arms the executor atomically.
    lookups: dict[str, DatabaseLookupSpec] = field(default_factory=dict)

    def add_inbound(self, conn: InboundConnection) -> None:
        self._add(self.inbound, conn.name, conn, "inbound connection")

    def add_outbound(self, conn: OutboundConnection) -> None:
        self._add(self.outbound, conn.name, conn, "outbound connection")

    def add_router(self, name: str, fn: RouterFn) -> None:
        self._add(self.routers, name, fn, "router")

    def add_handler(self, name: str, fn: HandlerFn) -> None:
        self._add(self.handlers, name, fn, "handler")

    def add_reference(self, spec: ReferenceSpec) -> None:
        self._add(self.references, spec.name, spec, "reference set")

    def add_lookup(self, spec: DatabaseLookupSpec) -> None:
        self._add(self.lookups, spec.name, spec, "database lookup")

    @staticmethod
    def _add(table: dict[str, Any], name: str, value: Any, kind: str) -> None:
        if name in table:
            raise WiringError(f"duplicate {kind} name: {name!r}")
        table[name] = value

    def validate(self) -> None:
        """Statically check references (inbound → router) and literal inbound port collisions."""
        for conn in self.inbound.values():
            if conn.router not in self.routers:
                raise WiringError(
                    f"inbound connection {conn.name!r} references unknown router {conn.router!r}"
                )
        collisions = self.port_collisions()
        if collisions:
            port, first, second = collisions[0]
            raise WiringError(f"inbound connections {first!r} and {second!r} both bind port {port}")

    def port_collisions(self) -> list[tuple[int, str, str]]:
        """Inbound listeners that bind a shared literal port on overlapping interfaces, as
        ``(port, first, colliding)`` tuples.

        Caught statically so a duplicate port surfaces at validate/``check`` time naming both
        connections, instead of aborting the whole engine with a bare bind ``OSError`` (review low-13).
        Registry-only (no service settings here): the interface is the per-connection ``bind_address``
        — two listeners that override it to *different* explicit interfaces don't collide, while the
        common case (both inheriting ``[inbound].bind_host``) still does. Only listener types bind a
        port, and only an ``int`` literal is checkable (an ``EnvRef`` port resolves per environment —
        the runner's :func:`inbound_binding_conflicts` covers those, plus the reserved API port, at
        start/reload)."""
        bindings = [
            _Binding(conn.name, _normalize_bind_host(conn.bind_address), port)
            for conn in self.inbound.values()
            if conn.spec.type in _LISTEN_TYPES
            and isinstance((port := conn.spec.settings.get("port")), int)
            and not isinstance(port, bool)
        ]
        return [(a.port, a.label, b.label) for a, b in _binding_conflicts(bindings)]


# --- declaration API (writes to the registry being loaded) -------------------

_active: Registry | None = None


def _active_registry() -> Registry:
    if _active is None:
        raise WiringError(
            "inbound/outbound/router/handler must be declared in a config module loaded "
            "via load_config()"
        )
    return _active


def _call_site() -> tuple[str | None, int | None]:
    """File + line of the config module that called the declaration (for IDE go-to-definition)."""
    caller = sys._getframe(2)  # _call_site -> inbound/outbound -> config module
    return caller.f_code.co_filename, caller.f_lineno


def _check_metadata(name: str, metadata: Mapping[str, Any] | None) -> None:
    """Operability metadata must be a key/value table (or absent) — operator labels, not config."""
    if metadata is not None and not isinstance(metadata, Mapping):
        raise WiringError(f"connection {name!r}: metadata must be a table (key/value mapping)")


def _check_source_ip_allowlist(
    name: str, listens: bool, allowlist: list[str] | None
) -> tuple[str, ...] | None:
    """Validate an inbound peer-IP allowlist and freeze it to a tuple. Each entry must parse as an IP
    address or a CIDR network; the allowlist is only meaningful for an MLLP/TCP **listen** source.
    ``None``/empty = no restriction (the ``[egress]`` allowlist convention)."""
    if not allowlist:
        return None
    if not listens:
        raise WiringError(
            f"inbound connection {name!r}: source_ip_allowlist is only valid for an MLLP/TCP "
            "listen source"
        )
    for entry in allowlist:
        if not isinstance(entry, str) or not entry.strip():
            raise WiringError(
                f"inbound connection {name!r}: source_ip_allowlist entries must be non-empty strings"
            )
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
            else:
                ipaddress.ip_address(entry)
        except ValueError as exc:
            raise WiringError(
                f"inbound connection {name!r}: source_ip_allowlist entry {entry!r} is not a valid "
                f"IP address or CIDR network ({exc})"
            ) from exc
    return tuple(allowlist)


def _coerce_content_type(name: str, content_type: ContentType | str) -> ContentType:
    """Coerce a ``content_type`` argument to the :class:`ContentType` enum (or fail loud).

    A code-first author may pass the bare string (``content_type="x12"``) rather than the enum member;
    coerce it here, at the one shared inbound boundary, so a raw string can't flow into the pipeline and
    blow up later as ``'str' object has no attribute 'value'`` deep in dry-run. An unrecognized value
    fails loud as a :class:`WiringError` naming the connection and the allowed values — the same loud
    failure the ``connections.toml`` loader already gives. A member passed in is returned unchanged."""
    if isinstance(content_type, ContentType):
        return content_type
    try:
        return ContentType(content_type)
    except ValueError as exc:
        allowed = ", ".join(repr(member.value) for member in ContentType)
        raise WiringError(
            f"inbound connection {name!r}: invalid content_type {content_type!r} (allowed: {allowed})"
        ) from exc


def build_inbound_connection(
    name: str,
    spec: ConnectionSpec,
    *,
    router: str,
    ack_mode: AckMode = AckMode.ORIGINAL,
    ack_after: AckAfter | None = None,
    strict: bool = False,
    hl7_version: str | None = None,
    content_type: ContentType | str = ContentType.HL7V2,
    metadata: Mapping[str, Any] | None = None,
    bind_address: str | None = None,
    source_ip_allowlist: list[str] | None = None,
    capture_ack: bool | None = None,
    capture_connection_errors: bool | None = None,
    source_file: str | None = None,
    source_line: int | None = None,
) -> InboundConnection:
    """Validate the inbound-connection invariants and build an :class:`InboundConnection`.

    The shared core of code-first :func:`inbound` **and** the ``connections.toml`` loader (ADR 0007),
    so both authoring surfaces enforce identical guards. Pure — it does not touch the active registry;
    the caller is responsible for ``add_inbound``. ``content_type`` accepts a :class:`ContentType`
    member **or** its bare string value (``"x12"``, ``"json"``, …); it is coerced to the enum here so a
    raw string can't reach the pipeline and crash later."""
    content_type = _coerce_content_type(name, content_type)
    if (
        spec.type in (ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.X12, ConnectorType.DIMSE)
        and spec.settings.get("host") is not None
    ):
        # The bind interface is an environment/service decision (which NIC this instance exposes),
        # not a per-connection one — and exposing an unauthenticated raw listener on 0.0.0.0 must be
        # an admin choice, not a developer default. Set it service-side via [inbound].bind_host.
        kind = spec.type.value.upper()
        factory = "DICOM" if spec.type is ConnectorType.DIMSE else kind.title()
        raise WiringError(
            f"inbound connection {name!r}: {kind} inbound takes no host; the bind interface is a "
            f"service setting ([inbound].bind_host). Declare it as {factory}(port=...)."
        )
    if ack_after == AckAfter.DELIVERED:
        # Deferred-until-delivered ACK needs the listener to hold/replay the ACK from the delivery
        # worker (sender socket details, held connection) — not built in Step A. Fail loud at wiring
        # so a config asking for it is caught in dry-run / `messagefoundry check`, not silently
        # downgraded. (This also rules out the incoherent DELIVERED + ack_mode=NONE combination.)
        # Compared by VALUE not identity: AckAfter is a str-Enum, so a raw-string ack_after='delivered'
        # (== the member but not `is` it) must still be caught rather than slipping through as INGEST.
        raise WiringError(
            f"inbound connection {name!r}: ack_after='delivered' is not yet implemented "
            "(Step A ships ACK-on-receipt only — use ack_after='ingest', the default)"
        )
    if content_type is not ContentType.HL7V2 and strict:
        # Strict validation is hl7apy structure/cardinality validation — meaningless for a JSON/XML/text
        # body. Fail loud at wiring (caught in dry-run / `messagefoundry check`) rather than silently
        # ignoring it; non-HL7 payloads are validated in the Handler instead (ADR 0004).
        raise WiringError(
            f"inbound connection {name!r}: validation.strict is HL7-specific and can't apply to a "
            f"{content_type.value!r} content_type — validate non-HL7 payloads in the Handler instead"
        )
    if spec.type is ConnectorType.LOOPBACK:
        # A loopback inbound (ADR 0013) has no socket and no untrusted intake: strict HL7 validation is
        # meaningless, and there is no external peer to ACK. Messages arrive only via ingress_handoff.
        if strict:
            raise WiringError(
                f"inbound connection {name!r}: validation.strict is meaningless for a Loopback() "
                "inbound (no socket / no untrusted intake)"
            )
        if ack_mode in (AckMode.NONE, AckMode.ORIGINAL):
            ack_mode = AckMode.NONE  # unset/default → NONE (no external peer to ACK)
        else:
            raise WiringError(
                f"inbound connection {name!r}: Loopback() takes no ACK (no external peer) — "
                "ack_mode must be NONE"
            )
    _check_metadata(name, metadata)
    # Listen sources bind an interface and can carry a per-connection bind_address + peer-IP allowlist.
    # DIMSE (the C-STORE SCP) is a listener like MLLP/TCP (X12 binds but omits these per-conn knobs).
    listens = spec.type in (ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.DIMSE)
    if bind_address is not None:
        if not listens:
            # Only a listen source (MLLP/TCP/DIMSE) binds an interface; File/DB/etc. have nothing to bind.
            raise WiringError(
                f"inbound connection {name!r}: bind_address is only valid for an MLLP/TCP/DIMSE "
                "listen source"
            )
        if not bind_address.strip():
            # A present-but-blank bind_address would crash asyncio.start_server at boot (getaddrinfo
            # fails on whitespace) — fail loud at wiring so it's caught in dry-run / `messagefoundry
            # check`, like the allowlist. (Omit bind_address to inherit [inbound].bind_host.)
            raise WiringError(
                f"inbound connection {name!r}: bind_address must be a non-empty host/IP, not blank"
            )
    allowlist = _check_source_ip_allowlist(name, listens, source_ip_allowlist)
    # Corepoint-style event-log overrides (#46). capture_ack="Response Sent" only makes sense when the
    # inbound actually returns an HL7 ACK, so True requires an HL7v2 content_type with ACKs enabled
    # (ADR 0021 §4). capture_connection_errors logs pre-ingress framing/refuse failures, which only a
    # LISTEN source has (ADR 0021 §7.4) — content-agnostic, so no HL7/ack constraint. None = inherit.
    if capture_ack and (ack_mode is AckMode.NONE or content_type is not ContentType.HL7V2):
        raise WiringError(
            f"inbound connection {name!r}: capture_ack=True requires an HL7v2 content_type with ACKs "
            "enabled (ack_mode != NONE) — there is no ACK to record otherwise"
        )
    if capture_connection_errors and not listens:
        raise WiringError(
            f"inbound connection {name!r}: capture_connection_errors=True is only valid for an "
            "MLLP/TCP listen source (a poll/file source has no per-connection framing/refuse failures)"
        )
    return InboundConnection(
        name=name,
        spec=spec,
        router=router,
        ack_mode=ack_mode,
        ack_after=ack_after,
        validation=Validation(strict=strict, hl7_version=hl7_version),
        content_type=content_type,
        metadata=metadata,
        bind_address=bind_address,
        source_ip_allowlist=allowlist,
        capture_ack=capture_ack,
        capture_connection_errors=capture_connection_errors,
        source_file=source_file,
        source_line=source_line,
    )


def inbound(
    name: str,
    spec: ConnectionSpec,
    *,
    router: str,
    ack_mode: AckMode = AckMode.ORIGINAL,
    ack_after: AckAfter | None = None,
    strict: bool = False,
    hl7_version: str | None = None,
    content_type: ContentType | str = ContentType.HL7V2,
    metadata: Mapping[str, Any] | None = None,
    bind_address: str | None = None,
    source_ip_allowlist: list[str] | None = None,
    capture_ack: bool | None = None,
    capture_connection_errors: bool | None = None,
) -> None:
    """Declare an inbound connection that feeds every received message to ``router``.

    ``ack_after`` selects ACK *timing* (staged pipeline, ADR 0001): the default ``INGEST``
    (ACK-on-receipt) is the only value supported in Step A — ``DELIVERED`` (defer the ACK until
    delivery) is not yet implemented and raises ``WiringError``. ``ack_after`` is distinct from
    ``ack_mode`` (the ACK code family).

    ``content_type`` (ADR 0004) selects the payload format: the default ``HL7V2`` runs the HL7
    peek/validate/ACK path and the Router/Handler receive a :class:`Message`; any other value skips HL7
    parsing and they receive a :class:`RawMessage` (``.raw``/``.text``/``.json()``). It may be a
    :class:`ContentType` member **or** its bare string value (``content_type="x12"``), coerced at load —
    an unrecognized string fails loud as a :class:`WiringError`. ``strict`` validation is HL7-only, so it
    cannot combine with a non-HL7 ``content_type``.

    Operability (Tier 4, all optional): ``metadata`` attaches free-form operator labels
    (owner/runbook/environment) surfaced by the API and never used for routing; ``bind_address``
    overrides the service ``[inbound].bind_host`` for this MLLP/TCP listener only; ``source_ip_allowlist``
    restricts an MLLP/TCP listener to the given peer IPs / CIDR networks (absent/empty = no restriction)."""
    file, line = _call_site()
    _active_registry().add_inbound(
        build_inbound_connection(
            name,
            spec,
            router=router,
            ack_mode=ack_mode,
            ack_after=ack_after,
            strict=strict,
            hl7_version=hl7_version,
            content_type=content_type,
            metadata=metadata,
            bind_address=bind_address,
            source_ip_allowlist=source_ip_allowlist,
            capture_ack=capture_ack,
            capture_connection_errors=capture_connection_errors,
            source_file=file,
            source_line=line,
        )
    )


def build_outbound_connection(
    name: str,
    spec: ConnectionSpec,
    *,
    retry: RetryPolicy | None = None,
    ordering: OrderingMode | None = None,
    internal_error: InternalErrorPolicy | None = None,
    buildup: BuildupThreshold | None = None,
    simulate: bool = False,
    metadata: Mapping[str, Any] | None = None,
    source_file: str | None = None,
    source_line: int | None = None,
) -> OutboundConnection:
    """Validate the outbound-connection invariants and build an :class:`OutboundConnection`.

    The shared core of code-first :func:`outbound` **and** the ``connections.toml`` loader (ADR 0007).
    Pure — it does not touch the active registry; the caller is responsible for ``add_outbound``."""
    if (
        spec.type in (ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.X12)
        and spec.settings.get("host") is None
    ):
        # Outbound MLLP/TCP/X12 dials a downstream peer, so a host is mandatory. (It's the value that
        # legitimately differs per environment — see env() for DEV/PROD-specific peers.)
        kind = spec.type.value.upper()
        raise WiringError(
            f"outbound connection {name!r}: {kind} outbound requires a host (the downstream peer), "
            f"e.g. {kind.title()}(host=..., port=...)."
        )
    _check_metadata(name, metadata)
    # ADR 0013 Increment 2: reingress_to (route this outbound's reply back as a new inbound message)
    # IMPLIES capture (the reply must be captured to re-ingress it). Force capture_response here so the
    # capture-validity guards below also gate a re-ingress declaration; the cross-registry check that
    # reingress_to names an existing Loopback() inbound runs in build_check_registry (it sees the whole
    # registry). A re-ingress on FILE/REMOTEFILE therefore fails with the "no synchronous response" error.
    reingress_to = spec.settings.get("reingress_to")
    if reingress_to is not None:
        if not isinstance(reingress_to, str) or not reingress_to.strip():
            raise WiringError(
                f"outbound connection {name!r}: reingress_to must be a non-empty inbound name (ADR 0013)"
            )
        spec.settings["capture_response"] = True
    # ADR 0013: response capture must be wiring-valid at `check`/dry-run time (no store needed), and
    # this is the choke point for BOTH the code-first factories and the connections.toml desugar.
    if spec.settings.get("capture_response"):
        if spec.type in (ConnectorType.FILE, ConnectorType.REMOTEFILE):
            raise WiringError(
                f"outbound connection {name!r}: {spec.type.value.upper()} has no synchronous response, "
                "so capture_response=True is invalid (ADR 0013)."
            )
        if spec.type is ConnectorType.TCP and not spec.settings.get("expect_reply"):
            raise WiringError(
                f"outbound connection {name!r}: TCP capture_response=True requires expect_reply=True "
                "(there is no reply to capture otherwise) (ADR 0013)."
            )
        if spec.type is ConnectorType.X12 and not spec.settings.get("expect_reply"):
            raise WiringError(
                f"outbound connection {name!r}: X12 capture_response=True requires expect_reply=True "
                "(there is no returned interchange to capture otherwise) (ADR 0016)."
            )
        if spec.type is ConnectorType.DATABASE:
            stmt = str(spec.settings.get("statement") or "").lower()
            if "returning" not in stmt and "output" not in stmt:
                raise WiringError(
                    f"outbound connection {name!r}: DATABASE capture_response=True requires a "
                    "RETURNING/OUTPUT clause in the statement (it is fetched from the same cursor "
                    "before commit), not a separate SELECT (ADR 0013)."
                )
    # ADR 0015: WS-* / mutual-TLS validity for SOAP, at `check`/dry-run time (no store). The url-scheme
    # checks (https required for a client cert, cleartext-credential refusal) need the resolved url and
    # run in SoapDestination.__init__; the structural ones below work on the unresolved spec (an EnvRef
    # is truthy, so presence/pairing checks hold even before env() resolution).
    if spec.type is ConnectorType.SOAP:
        cert = spec.settings.get("client_cert_file")
        key = spec.settings.get("client_key_file")
        if bool(cert) != bool(key):
            raise WiringError(
                f"outbound connection {name!r}: SOAP client_cert_file and client_key_file must be set "
                "together (a client cert needs its key) (ADR 0015)."
            )
        if cert and spec.settings.get("verify_tls") is False:
            raise WiringError(
                f"outbound connection {name!r}: SOAP client cert is incompatible with verify_tls=false "
                "(presenting an identity to an unverified peer is incoherent) (ADR 0015)."
            )
        pw_type = spec.settings.get("ws_password_type", "text")
        if pw_type not in ("text", "digest"):
            raise WiringError(
                f"outbound connection {name!r}: SOAP ws_password_type must be 'text' or 'digest', "
                f"got {pw_type!r} (ADR 0015)."
            )
        if (spec.settings.get("ws_security") or spec.settings.get("ws_addressing")) and str(
            spec.settings.get("soap_version", "1.1")
        ) != "1.2":
            raise WiringError(
                f"outbound connection {name!r}: SOAP ws_security/ws_addressing require "
                "soap_version='1.2' (WS-Addressing/WS-Security are coherent only on SOAP 1.2) (ADR 0015)."
            )
    return OutboundConnection(
        name=name,
        spec=spec,
        retry=retry,
        ordering=ordering,
        internal_error=internal_error,
        buildup=buildup,
        simulate=simulate,
        metadata=metadata,
        source_file=source_file,
        source_line=source_line,
    )


def outbound(
    name: str,
    spec: ConnectionSpec,
    *,
    retry: RetryPolicy | None = None,
    ordering: OrderingMode | None = None,
    internal_error: InternalErrorPolicy | None = None,
    buildup: BuildupThreshold | None = None,
    simulate: bool = False,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    """Declare an outbound connection that Handlers can ``Send`` to.

    ``retry``/``ordering``/``internal_error``/``buildup`` override the global ``[delivery]`` defaults
    for this connection only (omit to inherit). ``ordering`` defaults to FIFO — strict in-order
    delivery per connection; ``internal_error`` defaults to continue (dead-letter a code-error row and
    advance); ``buildup`` sets the ``queue_buildup`` alert thresholds for this lane. ``simulate=True``
    runs the full pipeline but **suppresses the real egress** (shadow / parallel-run mode, #15) — no
    bytes leave the box and the message still finalizes PROCESSED. ``metadata`` attaches free-form
    operator labels (Tier 4) surfaced by the API, never used for delivery."""
    file, line = _call_site()
    _active_registry().add_outbound(
        build_outbound_connection(
            name,
            spec,
            retry=retry,
            ordering=ordering,
            internal_error=internal_error,
            buildup=buildup,
            simulate=simulate,
            metadata=metadata,
            source_file=file,
            source_line=line,
        )
    )


def router(name: str) -> Callable[[RouterFn], RouterFn]:
    """Register a Router: ``def route(msg) -> list[str] | str | None`` (handler names; [] => unrouted)."""

    def decorate(fn: RouterFn) -> RouterFn:
        _active_registry().add_router(name, fn)
        return fn

    return decorate


def handler(name: str) -> Callable[[HandlerFn], HandlerFn]:
    """Register a Handler: ``def handle(msg) -> Send | SetState | list[Send | SetState] | None``
    (``None`` => filtered; :class:`SetState` declares a state write applied exactly-once in the
    handoff, ADR 0005)."""

    def decorate(fn: HandlerFn) -> HandlerFn:
        _active_registry().add_handler(name, fn)
        return fn

    return decorate


# --- loader ------------------------------------------------------------------


class _SiblingHelperFinder:
    """Resolve a config module's top-level ``import _helpers`` to a sibling ``.py`` in the config dir.

    The loader runs non-``_`` modules under mangled names and skips ``_``-prefixed files as top-level
    modules, but CLAUDE.md §4 documents importing shared ``_``-prefixed helpers from siblings. Those
    files aren't on ``sys.path``, so without a finder Python can't locate them and the import fails
    (review low-10). Installed on ``sys.meta_path`` only while a config dir loads, and resolves a name
    only when ``<name>.py`` exists in that dir. :func:`_assert_safe_config_source` already vets every
    ``*.py`` (including ``_*``), so a helper sits inside the same trust boundary as its importers."""

    def __init__(self, directory: Path, created: set[str]) -> None:
        self._dir = directory
        self._created = created

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
        if path is not None or "." in fullname:
            return None  # only top-level absolute imports, resolved against the config dir
        candidate = self._dir / f"{fullname}.py"
        if not candidate.is_file():
            return None
        self._created.add(fullname)
        return importlib.util.spec_from_file_location(fullname, candidate)


# Serializes the shared module-global load state (_active, sys.meta_path/sys.modules mutations) so a
# reload offloaded to a worker thread can't race a concurrent validate/load (review low-3).
_load_lock = threading.Lock()


@contextmanager
def _loading(directory: Path, registry: Registry) -> Iterator[None]:
    """Hold the load lock, publish ``registry`` as the active declaration target **and its code sets
    as the active set** (so a module-top-level ``code_set(...)`` resolves), and install the
    sibling-helper import finder for ``directory`` — tearing all of it down (including any helper
    modules registered under their plain name) on exit."""
    global _active
    helpers: set[str] = set()
    finder = _SiblingHelperFinder(directory, helpers)
    with _load_lock:
        _active = registry
        sys.meta_path.insert(0, finder)
        # Code sets are published BEFORE the modules run so a top-level capture resolves; the registry
        # already holds them (loaded in load_config/validate_config), and activated() restores cleanly.
        try:
            with _code_sets_activated(registry.code_sets):
                yield
        finally:
            _active = None
            with suppress(ValueError):
                sys.meta_path.remove(finder)
            for name in helpers:
                sys.modules.pop(name, None)


def load_config(directory: str | Path) -> Registry:
    """Load every ``*.py`` config module in ``directory`` (sorted; ``_*`` skipped) into a Registry.

    Config modules are **executed** in-process with the engine's full privilege, so the source
    location is part of the trust boundary: :func:`_assert_safe_config_source` refuses a
    group/world-writable directory before any code runs. Blocking: an async caller (engine reload)
    should run this via ``asyncio.to_thread`` so heavy user-config imports don't stall listeners."""
    directory = Path(directory)
    # Fail loudly on a missing/typo'd dir: Path.glob() on a nonexistent dir yields nothing, so the
    # engine would otherwise start with an empty graph — a silently dead interface (review M-24).
    if not directory.is_dir():
        raise FileNotFoundError(f"config directory not found: {directory}")
    _assert_safe_config_source(directory)
    registry = Registry()
    # Load the bundle's reference tables (codesets/ relative to the config dir) BEFORE importing the
    # config modules, so a module-top-level code_set(...) capture resolves. A bad/duplicate table is a
    # WiringError here (fail loud), like a bad env value; a missing codesets/ dir is fine (no tables).
    try:
        registry.code_sets = load_code_sets(directory / CODESETS_DIR_NAME)
    except CodeSetError as exc:
        raise WiringError(str(exc)) from exc
    with _loading(directory, registry):
        for path in sorted(p for p in directory.glob("*.py") if not p.name.startswith("_")):
            _exec_module(path)
    # Connections may also be authored as data (ADR 0007): merge connections.toml into the SAME
    # registry the code-first inbound()/outbound() calls populated, before validating the whole graph.
    # Imported lazily to avoid a wiring<->connections_file import cycle. A name in both surfaces is a
    # duplicate WiringError via add_inbound/add_outbound (no silent precedence).
    from messagefoundry.config.connections_file import (
        CONNECTIONS_FILE_NAME,
        load_connections_file,
    )

    conn_file = directory / CONNECTIONS_FILE_NAME
    if conn_file.is_file():
        load_connections_file(conn_file, registry)
    registry.validate()
    return registry


# Group-write (0o020) | world-write (0o002): a writable bit for anyone but the owner.
_GROUP_WORLD_WRITABLE = 0o022


def _assert_safe_config_source(directory: Path) -> None:
    """Refuse to execute config Python from a group/world-writable location (POSIX).

    Because :func:`_exec_module` runs arbitrary Python as the engine's service account, a
    lower-privileged user who can write into the config dir (or a module file) could execute
    code as that account on the next reload. On POSIX we hard-fail on a group/world-writable
    directory or module. On Windows, NTFS DACL enforcement is delegated to the documented
    install-time ACL (see docs/SERVICE.md) — reading DACLs reliably needs platform APIs out of
    scope here — and to running under a least-privilege account (docs/SERVICE.md, DEPLOY-1)."""
    if os.name != "posix" or not directory.is_dir():
        return
    # getattr keeps mypy happy on win32 (os.getuid is POSIX-only); we already returned on non-posix.
    _getuid = getattr(os, "getuid", None)
    self_uid: int | None = _getuid() if _getuid is not None else None
    # Include _*.py: the loader skips them as top-level modules, but a sibling can import them, so a
    # writable/foreign-owned helper is just as much an injection vector (review M-21).
    candidates = [directory, *directory.glob("*.py")]
    for path in candidates:
        try:
            st = path.stat()
        except OSError:
            continue
        if st.st_mode & _GROUP_WORLD_WRITABLE:
            raise WiringError(
                f"refusing to load config from group/world-writable path {path} "
                f"(mode {oct(st.st_mode & 0o777)}); see docs/SERVICE.md for required permissions"
            )
        # Code here runs as the engine's account, so a file owned by a *different* unprivileged user
        # is an escalation vector even at 0644 — that user can rewrite it (CONFIG-2 / review M-21).
        if self_uid is not None and self_uid != 0 and st.st_uid != self_uid:
            raise WiringError(
                f"refusing to load config from {path} owned by uid {st.st_uid} — the engine runs as "
                f"uid {self_uid}; that owner could rewrite the executed code (see docs/SERVICE.md)"
            )


def _exec_module(path: Path) -> None:
    # Derive a collision-free module name from the resolved absolute path (not just the stem):
    # two same-stem files in different dirs must not share __module__ (breaks pickling, dataclass
    # __module__, get_type_hints). Register it in sys.modules so intra-config imports and anything
    # relying on sys.modules[__name__] resolve correctly; remove it again on failure.
    digest = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:12]
    mod_name = f"mefor_config_{path.stem}_{digest}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise WiringError(f"cannot load config module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except WiringError:
        sys.modules.pop(mod_name, None)
        raise
    except Exception as exc:
        sys.modules.pop(mod_name, None)
        raise WiringError(f"error loading config module {path.name}: {exc}") from exc


def validate_config(directory: str | Path) -> list[Diagnostic]:
    """Load ``directory`` best-effort and return **all** problems (not just the first).

    Unlike :func:`load_config`, a bad module is recorded and loading continues, and every
    unresolved ``inbound → router`` reference is reported — so an editor can show the full set
    at once. Returns ``[]`` when the config is valid.
    """
    directory = Path(directory)
    if not directory.is_dir():  # fail loudly, not silently empty (review M-24)
        return [Diagnostic(message=f"config directory not found: {directory}", file=str(directory))]
    try:
        # Same trust boundary as load_config: never execute Python from an unsafe source (review low-11).
        _assert_safe_config_source(directory)
    except WiringError as exc:
        return [Diagnostic(message=str(exc), file=str(directory))]
    registry = Registry()
    diagnostics: list[Diagnostic] = []
    # Load reference tables first (so a module-top-level code_set(...) resolves during import). A
    # bad/duplicate table is recorded as a diagnostic, not raised, so the editor sees every problem.
    codesets_dir = directory / CODESETS_DIR_NAME
    try:
        registry.code_sets = load_code_sets(codesets_dir)
    except CodeSetError as exc:
        diagnostics.append(Diagnostic(message=str(exc), file=str(codesets_dir)))
    with _loading(directory, registry):
        for path in sorted(p for p in directory.glob("*.py") if not p.name.startswith("_")):
            try:
                _exec_module(path)
            except WiringError as exc:
                diagnostics.append(Diagnostic(message=str(exc), file=str(path)))
    # Merge connections.toml best-effort too (ADR 0007), so the editor sees TOML problems alongside the
    # *.py ones and the router/port checks below cover TOML-authored connections. Lazy import (cycle).
    from messagefoundry.config.connections_file import (
        CONNECTIONS_FILE_NAME,
        load_connections_file,
    )

    conn_file = directory / CONNECTIONS_FILE_NAME
    if conn_file.is_file():
        try:
            load_connections_file(conn_file, registry)
        except WiringError as exc:
            diagnostics.append(Diagnostic(message=str(exc), file=str(conn_file)))
    for conn in registry.inbound.values():
        if conn.router not in registry.routers:
            diagnostics.append(
                Diagnostic(
                    message=f"inbound connection {conn.name!r} references unknown router "
                    f"{conn.router!r}"
                )
            )
    for port, first, second in registry.port_collisions():  # low-13
        diagnostics.append(
            Diagnostic(
                message=f"inbound connections {first!r} and {second!r} both bind port {port}"
            )
        )
    return diagnostics
