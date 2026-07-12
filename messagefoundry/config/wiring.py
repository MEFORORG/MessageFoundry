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
import inspect
import ipaddress
import logging
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
    BatchConfig,
    BuildupThreshold,
    ConnectorType,
    ContentType,
    InternalErrorPolicy,
    OrderingMode,
    Priority,
    RetryPolicy,
    Schedule,
    StallThreshold,
    Validation,
)
from messagefoundry.parsing.message import Message, RawMessage

__all__ = [
    "ConnectionSpec",
    "MLLP",
    "Tcp",
    "X12",
    "Http",
    "File",
    "Timer",
    "Loopback",
    "PassThrough",
    "Rest",
    "Direct",
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
    "SetMeta",
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
    "HandlerAccepts",
    "load_config",
    "validate_config",
]

_logger = logging.getLogger(__name__)


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


# A FhirLookup declares a NAMED, read-only FHIR connection a Handler reads LIVE at run time via
# fhir_lookup(name, query) (the read accessor lives in messagefoundry.config.fhir_lookup, ADR 0043). It
# is the FHIR mirror of DatabaseLookup: only the connection (the FHIR service base URL + the SMART auth
# seam the FHIR outbound uses); each call supplies its own read-by-id / search query. Unlike DatabaseLookup
# it returns the spec so with_smart_backend(FhirLookup(...)) can compose SMART auth onto it (the registry
# holds the same object), AND it self-registers — so the flat FhirLookup("epic", ...) form also lands in
# the graph. The engine builds one read executor from these.


@dataclass(frozen=True)
class FhirLookupSpec:
    """A declared live FHIR-lookup connection: ``name`` + connection ``settings`` (no query — the query is
    supplied per :func:`~messagefoundry.config.fhir_lookup.fhir_lookup` call). ``settings`` may hold
    :class:`EnvRef` values (put secrets like ``bearer_token`` / ``smart_private_key`` in :func:`env`).

    Mutable ``settings`` dict so :func:`~messagefoundry.transports.smart.with_smart_backend` can compose
    SMART auth onto it (the dataclass stays frozen — only the dict is mutated)."""

    name: str
    settings: dict[str, Any]


def FhirLookup(
    name: str,
    *,
    url: str | EnvRef,  # the FHIR service BASE url, e.g. https://host/fhir (may be env())
    fhir_version: str = "R4B",  # "R4B" (default) | "R5" | "STU3" — explicit, no autodetect
    headers: dict[str, str] | None = None,  # static extra headers (no secrets — not env()-resolved)
    bearer_token: str
    | EnvRef
    | None = None,  # Authorization: Bearer … (static; or compose with_smart_backend)
    basic_user: str
    | EnvRef
    | None = None,  # HTTP Basic (with basic_password); use env() for secrets
    basic_password: str | EnvRef | None = None,
    timeout_seconds: float = 30.0,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    encoding: str = "utf-8",
) -> FhirLookupSpec:
    """Declare a named live-lookup FHIR connection (ADR 0043). A Handler reads it at run time with
    ``fhir_lookup(name, query)`` — a **read-only** read-by-id (``"Patient/123"``) or search
    (``"Patient?identifier=MRN|123"``); the parsed resource / searchset ``Bundle`` comes back as a dict.
    Side-effecting (it self-registers), like :func:`Reference` / :func:`inbound`, **and** returns the spec
    so SMART auth can be composed onto it::

        FhirLookup("epic", url=env("epic_fhir_base"))                  # static / no auth
        with_smart_backend(                                           # SMART Backend Services bearer
            FhirLookup("epic", url=env("epic_fhir_base")),
            token_url=env("epic_token_url"), client_id=env("epic_client_id"),
            private_key=env("epic_smart_key"), scope="system/*.rs",
        )

    The read is **GET-only** (structurally read-only — a Handler cannot mutate the FHIR server through it;
    FHIR writes stay on the :func:`FHIR` outbound). The dial-out is gated by the **fail-closed**
    ``[egress].allowed_http`` allowlist (the same arm the FHIR outbound + SMART token endpoint use) — point
    the engine only at allowed hosts. Put secrets (``bearer_token`` / ``basic_*`` / SMART keys) in
    :func:`env`. TLS is on by default; weakening it needs ``MEFOR_ALLOW_INSECURE_TLS``. The pure
    ``parsing/fhir/`` codec parses the reply, so a ``FhirLookup``-declaring graph needs the optional
    ``messagefoundry[fhir]`` extra."""
    spec = FhirLookupSpec(
        name,
        {
            "url": url,  # stored under "url" (NOT base_url) so the egress gate reads the same key as FHIR()
            "fhir_version": fhir_version,
            "headers": headers or {},
            "bearer_token": bearer_token,
            "basic_user": basic_user,
            "basic_password": basic_password,
            "timeout_seconds": timeout_seconds,
            "verify_tls": verify_tls,
            "encoding": encoding,
        },
    )
    _active_registry().add_fhir_lookup(spec)
    return spec


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
    # Persistent outbound connection (ADR 0067) — outbound-only (inbound ignores them, like
    # timeout_seconds); pass None/0 on the two freshness knobs to disable that check:
    persistent: bool = False,  # outbound default (this release): connect-per-send; True = reuse ONE connection (opt-in, ADR 0067)
    idle_timeout_seconds: float
    | None = 60.0,  # outbound: don't reuse a connection idle longer than this
    max_connection_age_seconds: float
    | None = None,  # outbound: recycle by age (LB/firewall hygiene)
    encoding_characters: str | None = None,  # OUTBOUND: re-encode MSH-1/MSH-2 delimiters per dest
    hl7_raw_separators: bool = False,  # OUTBOUND: emit reserved separators as RAW bytes, not \F\..\T\ escapes (BACKLOG #107)
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
    tls_allow_expired: bool = False,  # OUTBOUND: honour an EXPIRED server cert (chain+hostname still verified; #129)
) -> ConnectionSpec:
    """An MLLP endpoint. Inbound uses port/max_connections/receive_timeout/max_frame_bytes (the
    bind interface comes from the service's ``[inbound].bind_host``, so ``host`` is rejected on an
    inbound); outbound uses host/port/connect_timeout/timeout_seconds/max_frame_bytes. ``encoding``
    applies to framing in both directions. ``capture_response`` (outbound, ADR 0013) records the
    application ACK as a captured reply (a negative ACK still dead-letters/retries unchanged).

    **Persistent outbound connection (ADR 0067).** Ships **opt-in** this release: ``persistent=False``
    is the default (connect-per-message — today's proven posture, dial a fresh connection per delivery).
    ``persistent=True`` (the opt-in — the MLLP-standard posture) makes the outbound reuse **one**
    lazily-established connection across deliveries instead of dialing per message, eliminating the
    per-message TCP/TLS handshake and its ``TIME_WAIT`` port pressure. A stale cached connection is
    detected **before any payload byte is written** and transparently redialed once (uncharged); any
    failure after the payload was written discards the connection, is charged, and retries per policy —
    the documented at-least-once duplicate window, unchanged in kind (receivers must stay idempotent).
    ``idle_timeout_seconds`` (default 60) refuses to reuse a connection idle longer than that;
    ``max_connection_age_seconds`` (off by default) recycles by age. The default flips to
    ``persistent=True`` in a subsequent release once the ADR 0067 §8 trigger is met; enable it now on
    sustained high-rate lanes. ``persistent=False`` also stays the compat mode for partners that
    require connection-per-message.

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

    ``hl7_raw_separators`` (**outbound only**, BACKLOG #107) is a deliberate escape-hatch for a partner
    that **cannot decode HL7 escape sequences**: when ``True`` the connector emits the four reserved
    **structural** separators as RAW bytes (``\\F\\ \\S\\ \\R\\ \\T\\`` → the message's own
    field/component/repetition/subcomponent character) instead of their escape sequences, reading the
    reserved chars from the payload's own MSH and re-serializing via the parsed model (never string
    slicing). ``False`` (the default) leaves the payload **byte-identical** — fully backward compatible.
    Enabling it can produce **non-conformant** output (a formerly-escaped ``^`` now reads as a component
    separator) — that is the point; use it only for such a broken partner. A non-HL7 payload that can't be
    parsed fails the delivery loud (``DeliveryError``). It composes with ``encoding_characters`` (the
    delimiter rewrite runs first, then the raw-separator emit).

    **TLS (WP-13b).** ``tls=True`` wraps the connection: inbound presents ``tls_cert_file``/``tls_key_file``
    (a server identity; ``tls_ca_file`` adds opt-in mTLS — require + verify a client cert); outbound
    verifies the server cert against ``tls_ca_file`` (or the system trust store) with hostname checking,
    and may present ``tls_cert_file`` for mTLS. ``tls_key_password`` decrypts a passphrase-encrypted
    ``tls_key_file`` (supply it via ``env()`` so the secret stays out of config — mirrors the API
    listener's ``MEFOR_API_TLS_KEY_PASSWORD``); omit it for an unencrypted key. ``tls_verify=False``
    (outbound) is MITM-able and refused unless ``MEFOR_ALLOW_INSECURE_TLS`` is set (loud warning) —
    exactly like LDAPS / SQL Server. TLS is TLS 1.2+ and composes with the ``[egress].allowed_mllp``
    allowlist (both enforced). ``tls_allow_expired=True`` (outbound, #129 / ADR 0094) is the **granular**
    alternative to ``tls_verify=False`` for the narrow real-world case of a partner whose server
    certificate has lapsed: it honours an **expired** cert while STILL verifying the chain and hostname
    (a wrong-host / untrusted-chain cert is still rejected), logs a WARN, and — because verification stays
    ON — is NOT an insecure hop the #200 posture gate refuses. Default ``False`` = byte-identical."""
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
            "persistent": persistent,
            "idle_timeout_seconds": idle_timeout_seconds,
            "max_connection_age_seconds": max_connection_age_seconds,
            "encoding_characters": encoding_characters,
            "hl7_raw_separators": hl7_raw_separators,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "tls": tls,
            "tls_cert_file": tls_cert_file,
            "tls_key_file": tls_key_file,
            "tls_key_password": tls_key_password,
            "tls_ca_file": tls_ca_file,
            "tls_verify": tls_verify,
            "tls_check_hostname": tls_check_hostname,
            "tls_allow_expired": tls_allow_expired,
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


def Http(
    *,
    port: int | EnvRef,
    # INBOUND only — the bind interface is a service setting ([inbound].bind_host), so there is no host.
    encoding: str = "utf-8",  # charset the POSTed body is decoded with (non-binary content types)
    # DoS guards (HTTP analogs of the MLLP frame/connection/idle caps; pass None/0 to disable):
    max_connections: int | None = 256,  # cap concurrent clients (connection-flood guard)
    receive_timeout: float
    | None = 60.0,  # bound the whole-request read (slow-loris guard), seconds
    max_body_bytes: int | None = 16 * 1024 * 1024,  # cap one request body's bytes (OOM guard)
    max_header_bytes: int | None = 64 * 1024,  # cap the request line + headers (header-flood guard)
    # --- TLS (WP-13b, ADR 0002 §0 / ADR 0023 D4) — per-connection HTTPS ---
    tls: bool = False,  # turn TLS on (present a server cert; off-loopback without it is refused at start)
    tls_cert_file: str | None = None,  # SERVER cert (required when tls)
    tls_key_file: str | None = None,  # private key for tls_cert_file
    tls_key_password: str
    | EnvRef
    | None = None,  # passphrase for an ENCRYPTED tls_key_file (put the secret in env())
    tls_ca_file: str | None = None,  # trust anchor — opt-in mTLS (require + verify a client cert)
) -> ConnectionSpec:
    """An **inbound HTTP/1.1 web-service listener** (ADR 0023) — a connector-owned bound socket that a
    partner ``POST``s a body to (REST / SOAP-body / FHIR / webhook). Source-only: it never delivers. The
    bind interface is the service's ``[inbound].bind_host`` (so it takes **no** ``host``, like MLLP/X12);
    declare it ``Http(port=...)``. Pair it with ``inbound(..., content_type=...)`` (ADR 0004): ``hl7v2``
    (the default) runs the HL7 peek/validate path and routes a :class:`Message`; ``json``/``xml``/``text``/
    ``fhir`` route a :class:`~messagefoundry.parsing.message.RawMessage` parsed on demand in the Handler.

    **Respond-with-receipt (first slice).** A ``POST`` is committed to the ingress stage and answered with
    a ``202 Accepted`` carrying the engine ``message_id`` the instant it is durably committed — mirroring
    MLLP's AA-on-receipt (ACK-on-receipt, ADR 0001). A post-ingress routing/transform/delivery failure
    happens *after* the ``202`` and is **not** reflected in the HTTP status (it surfaces as the message's
    ``ERROR``/dead-letter + the AlertSink). A pre-ingress refusal (oversize/malformed/allowlist) returns a
    synchronous ``4xx`` + an ADR 0021 ``connection_event``. ``GET``/``HEAD`` are static health probes (no
    ingress row). The synchronous downstream-reply (SOAP-envelope) path is a defined ADR 0013 follow-on,
    not built here.

    **DoS guards** are HTTP twins of MLLP's: ``max_connections`` (flood), ``receive_timeout`` (slow-loris
    — bounds the whole-request read), ``max_body_bytes`` (the frame-cap twin — refused on the declared
    ``Content-Length`` before a byte is buffered), and ``max_header_bytes`` (header flood).

    **TLS (WP-13b).** ``tls=True`` presents ``tls_cert_file``/``tls_key_file`` as the HTTPS server
    identity (``tls_ca_file`` adds opt-in mTLS); ``tls_key_password`` decrypts an encrypted key (supply via
    ``env()``). The runner's exposed-gate refuses a **non-loopback** HTTP listener **without** TLS at start
    (cleartext PHI can't cross an off-loopback socket by accident) — set ``tls=True`` or pass
    ``serve --allow-insecure-bind`` on a trusted, firewalled segment."""
    return ConnectionSpec(
        ConnectorType.HTTP,
        {
            "port": port,
            "encoding": encoding,
            "max_connections": max_connections,
            "receive_timeout": receive_timeout,
            "max_body_bytes": max_body_bytes,
            "max_header_bytes": max_header_bytes,
            "tls": tls,
            "tls_cert_file": tls_cert_file,
            "tls_key_file": tls_key_file,
            "tls_key_password": tls_key_password,
            "tls_ca_file": tls_ca_file,
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


def PassThrough() -> ConnectionSpec:
    """A pass-through (PT) **inbound** (ADR 0013, generalized): an inert *internal* inbound with **no
    source**. Messages arrive *only* via the engine-internal pass-through handoff — a Handler ``Send``\\ s
    its transformed message into this inbound (naming it like an outbound), and the engine re-ingresses
    that body as a **new, independent inbound message** on this channel, routed by this inbound's own
    Router. This is the Corepoint ``PT_*`` pattern: one logical feed fans out across internal connectors
    and re-routes deeper (e.g. ``PT_000000_ADT_2``) without an external hop.

    It is an ordinary ``inbound(...)`` otherwise: declare its ``router`` (which re-routes the message)
    and ``content_type`` (``hl7v2`` → :class:`~messagefoundry.parsing.message.Message`; ``x12``/``text``/
    ``json`` → :class:`~messagefoundry.parsing.message.RawMessage`). It takes **no** ``ack_mode`` (no
    external peer to ACK — forced to ``NONE``), no ``bind_address``/``source_ip_allowlist`` (no socket),
    and no ``strict`` validation (no untrusted intake — the body is engine-internal, already-stored
    state). Unlike :func:`Loopback`, which captures a 1:1 partner *reply*, a PT inbound is the 1:N
    internal *routing* sibling: any Handler may target it, and the body is the transformed message."""
    return ConnectionSpec(ConnectorType.PT, {})


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
    tls_allow_expired: bool = False,  # honour an EXPIRED server cert (chain+hostname still verified; #129)
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the HTTP response body as a reply (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    dynamic_headers: bool = False,  # #68: apply a Handler's per-message http.header.* SetMeta as headers
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
            "tls_allow_expired": tls_allow_expired,
            "encoding": encoding,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "dynamic_headers": dynamic_headers,
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
    tls_allow_expired: bool = False,  # honour an EXPIRED server cert (chain+hostname still verified; #129)
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the server reply / OperationOutcome (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    dynamic_headers: bool = False,  # #68: apply a Handler's per-message http.header.* SetMeta as headers
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
            "tls_allow_expired": tls_allow_expired,
            "encoding": encoding,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "dynamic_headers": dynamic_headers,
        },
    )


def Email(
    *,
    host: str | EnvRef,  # the SMTP server host (required; may be env())
    sender: str | EnvRef,  # the From: address (required; may be env())
    recipients: list[str] | str | EnvRef,  # To: address(es) — a list or a single string (required)
    port: int | EnvRef = 587,  # 587 STARTTLS submission (default); 465 → implicit TLS (SMTP_SSL)
    subject: str | EnvRef = "",  # static Subject (a per-message subject is a Phase-2 follow-up)
    username: str | EnvRef | None = None,  # optional SMTP AUTH user (use env() for the secret)
    password: str | EnvRef | None = None,  # optional SMTP AUTH password (use env() for the secret)
    use_tls: bool = True,  # STARTTLS by default; False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    timeout_seconds: float = 30.0,
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """An SMTP email endpoint (**outbound destination only** — IMAP/POP read is Phase 2, ADR 0029).
    The Handler produces the email **body** (content-agnostic — an HL7 string, a JSON/XML report, plain
    text); this delivers it as a plain-text SMTP message to ``host:port`` from ``sender`` to
    ``recipients`` with a static ``subject``. STARTTLS by default (``use_tls=True``) on the ``587``
    submission port; port ``465`` is implicit TLS (``SMTP_SSL``). Optional ``username``/``password`` do
    SMTP ``AUTH`` (over TLS only — a cleartext-credential config is refused). Disabling TLS
    (``use_tls=False``) is MITM-able and refused unless ``MEFOR_ALLOW_INSECURE_TLS`` is set (loud
    warning), like LDAPS / SQL Server / MLLP. The egress host is gated by ``[egress].allowed_smtp``. Put
    secrets in ``env()`` (``username``/``password``), never inline. Delivery is at-least-once, so a retry
    re-sends the email — a mailbox has no idempotency key, so a rare duplicate is possible and accepted
    (a duplicate beats a drop). ADR 0029."""
    return ConnectionSpec(
        ConnectorType.EMAIL,
        {
            "host": host,
            "sender": sender,
            "recipients": recipients,
            "port": port,
            "subject": subject,
            "username": username,
            "password": password,
            "use_tls": use_tls,
            "timeout_seconds": timeout_seconds,
            "encoding": encoding,
        },
    )


#: Alias — ``SMTP`` reads naturally for the protocol-minded; ``Email`` for the use-case-minded.
SMTP = Email


def Direct(
    *,
    host: str | EnvRef,  # the SMTP/HISP relay host (required; may be env())
    sender: str | EnvRef,  # the Direct From: address (required; may be env())
    recipients: list[str] | str | EnvRef,  # Direct To: address(es) — a list or a single string
    signing_cert: str | EnvRef,  # path to the sender's PEM/DER signing certificate (required)
    signing_key: str | EnvRef,  # path to the sender's PEM/DER signing private key (required)
    recipient_cert: str | EnvRef,  # path to the partner's PEM/DER encryption certificate (required)
    trust_anchor: str
    | EnvRef,  # path to the PEM/DER CA the recipient_cert must chain to (required)
    signing_key_password: str | EnvRef | None = None,  # passphrase for signing_key (use env())
    port: int | EnvRef = 587,  # 587 STARTTLS submission (default); 465 → implicit TLS (SMTP_SSL)
    subject: str | EnvRef = "",  # static Subject
    username: str | EnvRef | None = None,  # optional SMTP AUTH user (use env() for the secret)
    password: str | EnvRef | None = None,  # optional SMTP AUTH password (use env() for the secret)
    use_tls: bool = True,  # STARTTLS by default; False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    timeout_seconds: float = 30.0,
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """A Direct-Project **S/MIME-over-SMTP** endpoint (**outbound destination only** — inbound Direct
    mail, MDN, and DNS-CERT discovery are deferred, ADR 0085 PR1). The Handler produces the clinical
    **body** (content-agnostic — an HL7 string, a CDA/XML document, plain text); this **signs** it with
    ``signing_key``/``signing_cert``, **encrypts** the signed blob to the partner's ``recipient_cert``
    (which must chain to ``trust_anchor``), and submits the S/MIME message to ``host:port`` over
    STARTTLS. All cert/key material is loaded + validated at construction (fail loud). The egress host
    is gated by ``[egress].allowed_direct``. Put secrets in ``env()`` (``signing_key_password``,
    ``username``/``password``), never inline. Delivery is at-least-once, so a retry re-sends — a Direct
    mailbox has no idempotency key, so a rare duplicate is possible and accepted (a duplicate beats a
    drop). Crypto is core ``cryptography`` (``serialization.pkcs7``) — no new dependency. ADR 0085."""
    return ConnectionSpec(
        ConnectorType.DIRECT,
        {
            "host": host,
            "sender": sender,
            "recipients": recipients,
            "signing_cert": signing_cert,
            "signing_key": signing_key,
            "signing_key_password": signing_key_password,
            "recipient_cert": recipient_cert,
            "trust_anchor": trust_anchor,
            "port": port,
            "subject": subject,
            "username": username,
            "password": password,
            "use_tls": use_tls,
            "timeout_seconds": timeout_seconds,
            "encoding": encoding,
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
    tls_key_password: str | EnvRef | None = None,  # passphrase for a PKCS#8-encrypted tls_key_file
    # (env()-sourced, mirroring MLLP); None → unencrypted key. A no/wrong passphrase fails fast at
    # construction rather than hanging on an interactive TTY prompt (no TTY under a service/container).
    tls_ca_file: str
    | EnvRef
    | None = None,  # opt-in mTLS: require + verify a calling peer's client cert
    tls_allow_expired: bool = False,  # OUTBOUND SCU: honour an EXPIRED PACS cert (chain+hostname still verified; #129)
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
            "tls_key_password": tls_key_password,
            "tls_ca_file": tls_ca_file,
            "tls_allow_expired": tls_allow_expired,
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


def _reject_envref_odbc_params(odbc_params: Mapping[str, Any] | None) -> None:
    """Refuse an ``env()`` ref inside ``odbc_params`` (#66). Nested settings are NOT env-resolved (only
    top-level ones are — see :func:`resolve_env_settings`), so an ``EnvRef`` here would stringify to a
    broken literal at connect. Fail loud at authoring, pointing to the top-level ``username``/``password``
    fields (which ARE env-resolved + secret-redacted) for a per-environment/secret value."""
    if not odbc_params:
        return
    offenders = sorted(k for k, v in odbc_params.items() if isinstance(v, EnvRef))
    if offenders:
        raise WiringError(
            f"Database odbc_params may not use env() ({', '.join(offenders)}) — nested settings are "
            "not env-resolved. Put a credential/password in the top-level username/password fields "
            "(env-resolved + redacted); odbc_params carries only static driver keywords."
        )


def Database(
    *,
    server: str | EnvRef,  # DB host (may be env())
    statement: str,  # parameterized SQL / proc call with :name placeholders
    database: str
    | EnvRef
    | None = None,  # required for dialect='sqlserver'; optional for 'generic'
    dialect: str = "sqlserver",  # 'sqlserver' preset (default) | 'generic' ODBC (#66)
    auth: str = "sql",  # sql | integrated | entra (SQL Server preset only)
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,  # secret — use env()
    port: int | EnvRef = 1433,
    encrypt: bool = True,  # SQL Server preset: False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    trust_server_certificate: bool = False,  # SQL Server preset only
    connect_timeout: int = 15,
    app_name: str = "messagefoundry",
    odbc_driver: str = "ODBC Driver 18 for SQL Server",  # name the OS-installed driver for 'generic'
    odbc_params: dict[str, str | EnvRef]
    | None = None,  # generic dialect: driver-specific ODBC keywords (PORT, SSLmode, …)
    odbc_user_key: str = "UID",  # generic dialect: ODBC keyword the username is emitted under
    odbc_password_key: str = "PWD",  # generic dialect: ODBC keyword the password is emitted under
    pool_max: int = 5,
    acquire_timeout: float = 30.0,  # cap a pooled-connection borrow (s) — fail transiently, not forever
    capture_response: bool = False,  # capture the statement's RETURNING/OUTPUT result-set (ADR 0013)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    capture_max_rows: int = 100,  # cap captured rows (over-cap → outcome='unparseable', empty body)
) -> ConnectionSpec:
    """A SQL database endpoint (**outbound only** today; via the ``[sqlserver]`` extra's ``aioodbc``).

    ``dialect='sqlserver'`` (default) is the **production / supported** SQL Server preset over ODBC Driver
    18. ``dialect='generic'`` (#66) targets any OS-installed ODBC driver (PostgreSQL / Oracle / MySQL): name
    it in ``odbc_driver`` and pass driver-specific keywords (``PORT``, ``SSLmode``, …) via ``odbc_params``;
    credentials stay in ``username``/``password`` (emitted under ``odbc_user_key``/``odbc_password_key`` —
    default ``UID``/``PWD``). **On the generic path configure TLS via the driver's own keyword** (e.g.
    ``odbc_params={"SSLmode": "verify-full"}``) — the SQL-Server weakened-TLS refusal does not apply there.

    The Handler produces a JSON-object body; the connector binds its keys to the ``:name`` parameters in
    ``statement`` (translated to positional ``?`` — always parameterized, never string-built) and runs it. A
    transient DB error retries; a constraint/data error (or a payload that doesn't match) dead-letters. Put
    secrets (``password``) in ``env()``; ``odbc_params`` values are literals (put per-env/secret values in
    the top-level fields). The write **must be idempotent** (at-least-once)."""
    _reject_envref_odbc_params(odbc_params)
    return ConnectionSpec(
        ConnectorType.DATABASE,
        {
            "server": server,
            "database": database,
            "statement": statement,
            "dialect": dialect,
            "auth": auth,
            "username": username,
            "password": password,
            "port": port,
            "encrypt": encrypt,
            "trust_server_certificate": trust_server_certificate,
            "connect_timeout": connect_timeout,
            "app_name": app_name,
            "odbc_driver": odbc_driver,
            "odbc_params": odbc_params,
            "odbc_user_key": odbc_user_key,
            "odbc_password_key": odbc_password_key,
            "pool_max": pool_max,
            "acquire_timeout": acquire_timeout,
            "capture_response": capture_response,
            "reingress_to": reingress_to,
            "capture_max_rows": capture_max_rows,
        },
    )


def DatabasePoll(
    *,
    server: str | EnvRef,  # DB host (may be env())
    poll_statement: str,  # SELECT of the next batch (e.g. WHERE status='NEW' ORDER BY id)
    database: str
    | EnvRef
    | None = None,  # required for dialect='sqlserver'; optional for 'generic'
    dialect: str = "sqlserver",  # 'sqlserver' preset (default) | 'generic' ODBC (#66)
    mark_statement: str
    | None = None,  # UPDATE/DELETE run per row after the handler succeeds (:name)
    body_column: str | None = None,  # None → whole row as JSON; set → that column's value verbatim
    poll_seconds: float = 5.0,
    auth: str = "sql",  # sql | integrated | entra (SQL Server preset only)
    username: str | EnvRef | None = None,
    password: str | EnvRef | None = None,  # secret — use env()
    port: int | EnvRef = 1433,
    encrypt: bool = True,  # SQL Server preset: False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    trust_server_certificate: bool = False,  # SQL Server preset only
    connect_timeout: int = 15,
    app_name: str = "messagefoundry",
    odbc_driver: str = "ODBC Driver 18 for SQL Server",  # name the OS-installed driver for 'generic'
    odbc_params: dict[str, str | EnvRef]
    | None = None,  # generic dialect: driver-specific ODBC keywords (PORT, SSLmode, …)
    odbc_user_key: str = "UID",  # generic dialect: ODBC keyword the username is emitted under
    odbc_password_key: str = "PWD",  # generic dialect: ODBC keyword the password is emitted under
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
    is gated by ``[egress].allowed_db``.

    ``dialect='generic'`` (#66) polls any OS-installed ODBC driver (PostgreSQL / Oracle / MySQL) — name it
    in ``odbc_driver``, pass driver keywords via ``odbc_params``, and configure TLS through the driver's own
    keyword (the SQL-Server weakened-TLS refusal does not apply on that path). Credentials stay in
    ``username``/``password`` (under ``odbc_user_key``/``odbc_password_key``, default ``UID``/``PWD``)."""
    _reject_envref_odbc_params(odbc_params)
    return ConnectionSpec(
        ConnectorType.DATABASE,
        {
            "server": server,
            "database": database,
            "poll_statement": poll_statement,
            "dialect": dialect,
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
            "odbc_params": odbc_params,
            "odbc_user_key": odbc_user_key,
            "odbc_password_key": odbc_password_key,
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
    tls_allow_expired: bool = False,  # honour an EXPIRED server cert (chain+hostname still verified; #129)
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
            "tls_allow_expired": tls_allow_expired,
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
    tls_allow_expired: bool = False,  # FTPS: honour an EXPIRED server cert (chain+hostname still verified; #129)
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
            "tls_allow_expired": tls_allow_expired,
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


#: Per-message metadata cap (BACKLOG #150, ADR 0081): a handler's `SetMeta` contribution is bounded so
#: the encrypted `messages.metadata` column stays small. Over-cap raises at transform time → dead-letter.
META_MAX_KEYS = 32
META_MAX_BYTES = 4096


@dataclass(frozen=True)
class SetMeta:
    """A Handler's instruction to attach a small key/value to *this* message (channelMap / userdata
    parity, BACKLOG #150, ADR 0081).

    Like :class:`SetState`, a Handler does not mutate imperatively — it returns ``SetMeta(key, value)``
    alongside its :class:`Send`\\ s, and the engine merges it under the message's ``metadata.user``
    sub-key **inside the routed→outbound handoff transaction**, so a crash before commit leaves nothing
    and a re-run applies it exactly once (the staged-pipeline pure-re-run invariant). The bag is surfaced
    **read-only** (PHI-redacted) on the message API; there is no pipeline read-back. ``value`` is a
    ``str`` (Corepoint-faithful); last-writer-wins on a repeated key within a message."""

    key: str
    value: str

    def __post_init__(self) -> None:
        # Validate in the author's handler (clear message), not deep in a store UPDATE. Both are the
        # public metadata surface, so both must be plain strings.
        if not isinstance(self.key, str) or not self.key:
            raise WiringError("SetMeta key must be a non-empty string")
        if not isinstance(self.value, str):
            raise WiringError(
                f"SetMeta({self.key!r}, ...): value must be a str (got {type(self.value).__name__})"
            )


#: What a Router/Handler receives: a mutable HL7 :class:`Message`, or a :class:`RawMessage` for a
#: non-HL7 inbound (ADR 0004). The author knows which — a Router/Handler is bound to one inbound.
Payload = Message | RawMessage
RouterFn = Callable[[Payload], "list[str] | str | None"]
#: A Handler returns deliveries and/or writes (ADR 0005 state, ADR 0081 metadata): a single
#: :class:`Send`/:class:`SetState`/:class:`SetMeta`, a mixed list, or ``None`` (filtered). ``Send``-only
#: returns are unchanged — backward compatible.
HandlerFn = Callable[
    [Payload], "Send | SetState | SetMeta | list[Send | SetState | SetMeta] | None"
]
#: An optional **router-stage** applicability predicate a Handler may declare (``@handler(name,
#: accepts=...)``; ADR 0084). It is evaluated while the Router's selection is still being computed —
#: *before* any routed row is materialized — so a handler that declines costs **0** transactions
#: instead of the 2 an in-handler filter pays (ADR 0051's ``2H`` term becomes ``2·H_accepted``).
#:
#: It MUST be a **pure peek** over the message (message in → bool out): at-least-once replay re-runs
#: the router handoff, so which handlers were declined has to re-derive identically. It runs in the
#: router phase, where ``db_lookup``/``fhir_lookup`` already **raise** (ADR 0010/0043). The two OTHER
#: run-scoped inputs, ``state_get``/``response_get`` (ADR 0005/0013), are registered TRANSFORM-only and
#: **fail OPEN** in the router phase (they return their ``default``, not raise) — so a predicate that
#: read them would silently see an EMPTY view and could INVERT a suppression/dedup filter migrated from
#: a Handler. That would deliver PHI a rule excluded, with no ERROR/dead-letter/disposition anomaly, so
#: :meth:`Registry.validate` REJECTS an ``accepts=`` predicate that names ``state_get``/``response_get``
#: (fail-closed at load/``check`` time — a Handler that needs run-scoped state keeps its filter). It
#: must also **not mutate** the payload: the predicates of one message share the Router's payload object.
HandlerAccepts = Callable[[Payload], bool]

#: Run-scoped accessors that FAIL OPEN (return ``default``, never raise) when their view is inactive —
#: the router phase, where an ``accepts=`` predicate runs, activates neither. A predicate that named one
#: would silently read an empty view and could invert a filter, so it is refused at load time. (Unlike
#: ``db_lookup``/``fhir_lookup``, which RAISE in the router phase and so need no static check.)
_ACCEPTS_FORBIDDEN_ACCESSORS = frozenset({"state_get", "response_get"})


def _check_accepts_predicate(hname: str, pred: object) -> None:
    """Fail closed on an ``accepts=`` predicate that can't hold its contract (ADR 0084).

    Two static checks, both at load/``check`` time so a broken predicate is a :class:`WiringError`
    rather than a per-message routing-stage dead-letter storm:

    * **Non-callable** — ``accepts=True`` (passing the intended default instead of a predicate, a
      plausible typo) would pass the orphan check yet ``pred(msg)`` raises ``TypeError: 'bool' object is
      not callable`` on the FIRST message, dead-lettering every message on that inbound.
    * **Fail-open run-scoped read** — a predicate whose code names ``state_get``/``response_get`` (ADR
      0005/0013) would see an EMPTY view in the router phase and silently invert (deliver what a
      suppression rule excluded). Those accessors return ``default`` instead of raising, so nothing
      catches it at runtime; refuse it here (a filter that needs run-scoped state stays in the Handler).
    """
    if not callable(pred):
        raise WiringError(
            f"accepts= predicate for handler {hname!r} is not callable ({pred!r}); it must be a "
            "function (msg) -> bool"
        )
    code = getattr(inspect.unwrap(pred), "__code__", None)
    if code is None:
        return  # a callable with no analyzable code object (e.g. a callable instance) — can't inspect
    named = _ACCEPTS_FORBIDDEN_ACCESSORS.intersection(code.co_names)
    if named:
        raise WiringError(
            f"accepts= predicate for handler {hname!r} reads run-scoped state "
            f"({', '.join(sorted(named))}), which is unavailable in the router phase where the predicate "
            "runs — it would silently return its default and could invert the filter. Keep that guard in "
            "the Handler body (it runs in the transform phase, where the state view is active)."
        )


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
    # ADR 0057: opt into the inline Step-A fast-path. For an ELIGIBLE message (no-lookup graph,
    # single-handler, all-deliver) the router worker fuses route+transform+handoff into ONE committed
    # transaction (7 -> 5 commits/msg). Default False = the split pipeline, byte-identical. Eligibility is
    # re-checked per message at runtime (RegistryRunner); anything not eligible falls back to the split path.
    inline: bool = False
    # Per-connection auto-start (#115): True = the RegistryRunner binds this inbound's listener at engine
    # start (the default — unchanged behaviour); False = it is NOT bound at boot and reports
    # status:"stopped", but an operator can still start it at runtime (POST /connections/{name}/start).
    # A persisted "declare this feed start-disabled across restarts" flag (e.g. a test endpoint) — the
    # missing durable counterpart to the transient runtime start/stop. Code-first AND connections.toml.
    auto_start: bool = True
    # Per-connection active-window scheduler (#147, ADR 0095): None = always-on (no scheduler task,
    # byte-identical). Set = the RegistryRunner runs a per-connection scheduler task that AUTO-STARTs
    # this inbound's listener on entering an active window and cleanly STOPs it on leaving — distinct
    # from auto_start (a one-time boot gate) and from a TIMER source (which emits a body but never gates
    # a connection up/down). Code-first AND connections.toml.
    schedule: Schedule | None = None
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
    # Per-connection retention override (#34, ADR 0027): None = inherit the global [retention].messages_days
    # window; 0 = keep this connection's bodies forever; >0 = days. Keyed on the receiving inbound
    # (purge_message_bodies keys by messages.channel_id = this inbound name). Same override idiom as
    # capture_ack/RetryPolicy/BuildupThreshold — authored code-first AND via connections.toml (ADR 0007).
    messages_days: int | None = None
    # Per-connection embedded-document pruning (#47, ADR 0042): None = never strip embedded documents for
    # this inbound (the back-compat default); >0 = after that many days, retention strips each base64
    # embedded document (mfb64:v1: carriage value / HL7 OBX-5 ED embed) IN PLACE to a small tombstone,
    # keeping the surrounding message. `prune_documents_min_bytes` (None = inherit the built-in 0 = strip
    # any size) skips an embed smaller than that decoded-byte threshold. Distinct from `messages_days`
    # (whole-body purge): this evicts only the bulky attachment while keeping the readable message. Same
    # override idiom as messages_days — code-first AND via connections.toml (ADR 0007).
    prune_documents_after: int | None = None
    prune_documents_min_bytes: int | None = None
    # Per-connection DR / priority tier (#61, ADR 0048): None = inherit the global [delivery].priority
    # default; an explicit value overrides it (resolution in the RegistryRunner: per-connection override
    # > [delivery] global default > built-in NORMAL). The DR run-profile starts only inbound listeners
    # whose resolved tier rank >= [dr].priority_threshold rank — a below-threshold listener is NOT bound
    # and reports status:"filtered" (distinct from ADR 0031's "failed"). Inbound + outbound tiers are
    # INDEPENDENT. Same override idiom as messages_days/RetryPolicy — code-first AND via connections.toml.
    priority: Priority | None = None
    # Multi-process sharding (L3): the shard this inbound belongs to. None = the implicit default
    # shard. The supervisor runs one engine subprocess per distinct shard, each owning a disjoint
    # subset of inbounds (so intake parallelizes across CPU cores); outbound/routers/handlers are
    # shared across shards. Purely an intake-partition tag — never used for routing. See
    # messagefoundry/pipeline/sharding.py.
    shard: str | None = None
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
    stall: StallThreshold | None = None
    # Opt-in HL7 batch aggregation (#134, ADR 0082): None = deliver one message per send (unchanged);
    # set = coalesce up to batch.max_count lane rows into one BHS…BTS envelope per send (count-or-head-
    # age trigger). MLLP-only, and rejected on a capturing/reingressing outbound (validated at build).
    # Same override idiom as retry/buildup — code-first AND via connections.toml (ADR 0007).
    batch: BatchConfig | None = None
    # Shadow / parallel-run egress suppression (#15). False = deliver normally; True = the delivery
    # worker suppresses the real egress + finalizes PROCESSED. [shadow].simulate_all_egress forces it on.
    simulate: bool = False
    # Per-connection auto-start (#115): True = built at engine start (default, unchanged); False = NOT
    # built at boot (reports status:"stopped"), but startable at runtime (POST /connections/{name}/start).
    # Its delivery worker still spawns so any routed backlog self-heals, exactly like a DR-parked outbound.
    auto_start: bool = True
    # Per-connection active-window scheduler (#147, ADR 0095): None = always-on (byte-identical). Set =
    # the RegistryRunner AUTO-RESUMEs delivery on entering an active window and cleanly PAUSEs it (queued
    # rows RETAINED pending, never dropped) on leaving — reusing start_outbound/stop_outbound, the same
    # path the API uses. Code-first AND connections.toml.
    schedule: Schedule | None = None
    # Per-connection dead-letter retention override (#34, ADR 0027): None = inherit the global
    # [retention].dead_letter_days window; 0 = keep this outbound's dead-letter bodies forever; >0 = days.
    # Keyed on the outbound that dead-lettered the row (purge_dead_letters keys by queue.destination_name =
    # this outbound name). Same override idiom as retry/ordering/buildup — code-first AND connections.toml.
    dead_letter_days: int | None = None
    # Per-connection DR / priority tier (#61, ADR 0048): None = inherit the global [delivery].priority
    # default; an explicit value overrides it. The DR run-profile builds only outbound connectors whose
    # resolved tier rank >= [dr].priority_threshold rank — a below-threshold outbound is NOT built and
    # reports status:"filtered" (its delivery worker still spawns, so rows routed to it sit in the
    # outbound stage and self-heal on the next full startup, exactly as an ADR-0031 degraded outbound).
    # Inbound + outbound tiers are INDEPENDENT. Same override idiom as retry/ordering/stall.
    priority: Priority | None = None
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
    {
        ConnectorType.MLLP,
        ConnectorType.TCP,
        ConnectorType.X12,
        ConnectorType.DIMSE,
        ConnectorType.HTTP,
    }
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
    # Router-stage `accepts=` predicates (ADR 0084), keyed by handler name — a SPARSE table holding an
    # entry only for a handler that declared one. Deliberately parallel to `handlers` rather than folded
    # into it: `handlers` maps name -> the bare fn, and eight call sites introspect that fn directly
    # (`fn.__code__`, `__module__`) — reachability/impact analysis, the CLI, the sandbox worker, the
    # support bundle. A record type there would break every one of them; a parallel dict touches none.
    # Empty on a graph with no predicates, which route_only early-outs on (zero hot-path cost).
    handler_accepts: dict[str, HandlerAccepts] = field(default_factory=dict)
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
    # Live FHIR-lookup connection declarations (ADR 0043): name -> connection settings. Beside `lookups`
    # (the SQL kind): the RegistryRunner builds one read executor from these; fhir_lookup(name, query)
    # reads it at handler run time. Carried with the graph so a reload re-arms the executor atomically.
    fhir_lookups: dict[str, FhirLookupSpec] = field(default_factory=dict)
    # Engine-shard identity (ADR 0073), attached by pipeline.sharding.filter_registry_for_shard and
    # None on an unfiltered graph OR a single-shard config (which stays byte-identical to plain
    # `serve`). shard_id names THIS process's shard; all_shard_ids pins the full shard universe of
    # the config the filter ran against (sorted). Sharded-mode behaviors — the ownership-scoped
    # startup recovery, the single-delivery-consumer-per-outbound-lane gates, and the shard-set
    # reload refusal — all key off these.
    shard_id: str | None = None
    all_shard_ids: tuple[str, ...] | None = None

    def add_inbound(self, conn: InboundConnection) -> None:
        self._add(self.inbound, conn.name, conn, "inbound connection")

    def add_outbound(self, conn: OutboundConnection) -> None:
        self._add(self.outbound, conn.name, conn, "outbound connection")

    def add_router(self, name: str, fn: RouterFn) -> None:
        self._add(self.routers, name, fn, "router")

    def add_handler(self, name: str, fn: HandlerFn, accepts: HandlerAccepts | None = None) -> None:
        self._add(self.handlers, name, fn, "handler")
        if accepts is not None:
            # _add on `handlers` already rejected a duplicate name, so this can't collide.
            self.handler_accepts[name] = accepts

    def add_reference(self, spec: ReferenceSpec) -> None:
        self._add(self.references, spec.name, spec, "reference set")

    def add_lookup(self, spec: DatabaseLookupSpec) -> None:
        self._add(self.lookups, spec.name, spec, "database lookup")

    def add_fhir_lookup(self, spec: FhirLookupSpec) -> None:
        self._add(self.fhir_lookups, spec.name, spec, "fhir lookup")

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
        # An `accepts=` predicate keyed to no handler would silently never run (ADR 0084): the router
        # filter looks the predicate up BY handler name, so an orphan is dead code that reads as an
        # armed filter. Fail closed at load/`check` time. (add_handler cannot produce one; a registry
        # assembled by hand — a rebuild that drops a handler, a test — can.)
        for hname, pred in self.handler_accepts.items():
            if hname not in self.handlers:
                raise WiringError(f"accepts= predicate declared for unknown handler {hname!r}")
            _check_accepts_predicate(hname, pred)
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
    address or a CIDR network; the allowlist is only meaningful for an MLLP/TCP/X12/DIMSE **listen**
    source. ``None``/empty = no restriction (the ``[egress]`` allowlist convention)."""
    if not allowlist:
        return None
    if not listens:
        raise WiringError(
            f"inbound connection {name!r}: source_ip_allowlist is only valid for an "
            "MLLP/TCP/X12/DIMSE listen source"
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
    strict_timeout_s: float | None = None,
    content_type: ContentType | str = ContentType.HL7V2,
    inline: bool = False,
    auto_start: bool = True,
    schedule: Schedule | None = None,
    metadata: Mapping[str, Any] | None = None,
    bind_address: str | None = None,
    source_ip_allowlist: list[str] | None = None,
    capture_ack: bool | None = None,
    capture_connection_errors: bool | None = None,
    messages_days: int | None = None,
    prune_documents_after: int | None = None,
    prune_documents_min_bytes: int | None = None,
    priority: Priority | None = None,
    shard: str | None = None,
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
        spec.type
        in (
            ConnectorType.MLLP,
            ConnectorType.TCP,
            ConnectorType.X12,
            ConnectorType.DIMSE,
            ConnectorType.HTTP,
        )
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
    if spec.type in (ConnectorType.LOOPBACK, ConnectorType.PT):
        # An internal inbound (loopback re-ingress / pass-through, ADR 0013) has no socket and no
        # untrusted intake: strict HL7 validation is meaningless, and there is no external peer to ACK.
        # Messages arrive only via the engine-internal handoff (ingress_handoff / the PT branch of
        # transform_handoff). A PT inbound is a normal inbound for ROUTING (it carries a required
        # router — enforced by the inbound() signature — and gets router/transform workers), but it has
        # no LISTENER, so it shares these guards with Loopback().
        factory = "Loopback()" if spec.type is ConnectorType.LOOPBACK else "PassThrough()"
        if strict:
            raise WiringError(
                f"inbound connection {name!r}: validation.strict is meaningless for a {factory} "
                "inbound (no socket / no untrusted intake)"
            )
        if ack_mode in (AckMode.NONE, AckMode.ORIGINAL):
            ack_mode = AckMode.NONE  # unset/default → NONE (no external peer to ACK)
        else:
            raise WiringError(
                f"inbound connection {name!r}: {factory} takes no ACK (no external peer) — "
                "ack_mode must be NONE"
            )
    _check_metadata(name, metadata)
    # Listen sources bind an interface and can carry a per-connection bind_address + peer-IP allowlist.
    # DIMSE (the C-STORE SCP) and X12 are listeners like MLLP/TCP — all bind an interface.
    listens = spec.type in (
        ConnectorType.MLLP,
        ConnectorType.TCP,
        ConnectorType.DIMSE,
        ConnectorType.X12,
        ConnectorType.HTTP,
    )
    if bind_address is not None:
        if not listens:
            # Only a listen source (MLLP/TCP/DIMSE/X12/HTTP) binds an interface; File/DB/etc. have none.
            raise WiringError(
                f"inbound connection {name!r}: bind_address is only valid for an "
                "MLLP/TCP/DIMSE/X12/HTTP listen source"
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
    if messages_days is not None and messages_days < 0:
        # Per-connection retention override (#34, ADR 0027). None = inherit [retention].messages_days;
        # 0 = keep forever; >0 = days. A negative window is meaningless — fail loud at wiring (caught in
        # dry-run / `messagefoundry check`), mirroring RetentionSettings(messages_days=-1) rejection.
        raise WiringError(
            f"inbound connection {name!r}: messages_days must be >= 0 "
            "(0 = keep forever, omit to inherit the global [retention] window)"
        )
    if prune_documents_after is not None and prune_documents_after <= 0:
        # Per-connection embedded-document pruning (#47, ADR 0042). None = never strip; a window must be a
        # POSITIVE day count (0/negative is meaningless — "never" is None, not 0). Fail loud at wiring so
        # it's caught in dry-run / `messagefoundry check`.
        raise WiringError(
            f"inbound connection {name!r}: prune_documents_after must be > 0 days "
            "(omit it to never strip embedded documents)"
        )
    if prune_documents_min_bytes is not None and prune_documents_min_bytes < 0:
        raise WiringError(
            f"inbound connection {name!r}: prune_documents_min_bytes must be >= 0 "
            "(0 = strip any size, omit to inherit the default)"
        )
    if prune_documents_min_bytes is not None and prune_documents_after is None:
        # A size threshold with no window does nothing — catch the likely-mistaken config loud.
        raise WiringError(
            f"inbound connection {name!r}: prune_documents_min_bytes is set but prune_documents_after "
            "is not — the threshold has no effect without a pruning window"
        )
    if shard is not None and not shard.strip():
        # A present-but-blank shard tag would silently collapse into its own nameless shard (the
        # supervisor would spawn a subprocess named ""), a config footgun — fail loud at wiring so
        # it's caught in dry-run / `messagefoundry check`. Omit shard to use the default shard.
        raise WiringError(
            f"inbound connection {name!r}: shard must be a non-empty name, not blank "
            "(omit it to use the default shard)"
        )
    return InboundConnection(
        name=name,
        spec=spec,
        router=router,
        ack_mode=ack_mode,
        ack_after=ack_after,
        validation=Validation(
            strict=strict, hl7_version=hl7_version, strict_timeout_s=strict_timeout_s
        ),
        content_type=content_type,
        inline=inline,
        auto_start=auto_start,
        schedule=schedule,
        metadata=metadata,
        bind_address=bind_address,
        source_ip_allowlist=allowlist,
        capture_ack=capture_ack,
        capture_connection_errors=capture_connection_errors,
        messages_days=messages_days,
        prune_documents_after=prune_documents_after,
        prune_documents_min_bytes=prune_documents_min_bytes,
        priority=priority,
        shard=shard,
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
    strict_timeout_s: float | None = None,
    content_type: ContentType | str = ContentType.HL7V2,
    inline: bool = False,
    auto_start: bool = True,
    schedule: Schedule | None = None,
    metadata: Mapping[str, Any] | None = None,
    bind_address: str | None = None,
    source_ip_allowlist: list[str] | None = None,
    capture_ack: bool | None = None,
    capture_connection_errors: bool | None = None,
    messages_days: int | None = None,
    prune_documents_after: int | None = None,
    prune_documents_min_bytes: int | None = None,
    priority: Priority | None = None,
    shard: str | None = None,
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
    cannot combine with a non-HL7 ``content_type``. ``strict_timeout_s`` (#89) bounds the wall-clock a
    single strict hl7apy validate may run before the message dead-letters (a DoS backstop against a
    pathological body): ``None`` (default) inherits the engine default, ``<= 0`` disables it. Also a
    ``connections.toml`` key (ADR 0007), so it stays hand-/GUI-editable.

    Operability (Tier 4, all optional): ``metadata`` attaches free-form operator labels
    (owner/runbook/environment) surfaced by the API and never used for routing; ``bind_address``
    overrides the service ``[inbound].bind_host`` for this MLLP/TCP listener only; ``source_ip_allowlist``
    restricts an MLLP/TCP listener to the given peer IPs / CIDR networks (absent/empty = no restriction).

    ``messages_days`` (#34, ADR 0027) overrides the global ``[retention].messages_days`` window for this
    inbound only: ``None`` (default) inherits the global window, ``0`` keeps this connection's message
    bodies forever, ``>0`` prunes them after that many days — the Mirth per-channel storage lever. It is
    also a ``connections.toml`` key (ADR 0007), so it stays hand-/GUI-editable.

    ``prune_documents_after`` (#47, ADR 0042) strips bulky base64 **embedded documents** in place after
    that many days: ``None`` (default) never strips; ``>0`` replaces each ``mfb64:v1:`` carriage value /
    HL7 OBX-5 ED embed with a small size/content-type tombstone while keeping the surrounding message
    parseable (distinct from ``messages_days``, which nulls the whole body). ``prune_documents_min_bytes``
    (``None`` = strip any size) skips an embed below that decoded-byte threshold. Both are
    ``connections.toml`` keys.

    ``shard`` (L3 multi-process sharding) tags this inbound for a named engine subprocess: ``messagefoundry
    supervise`` runs one subprocess per distinct shard, each owning a disjoint set of inbounds (intake
    parallelizes across CPU cores; outbound/routers/handlers stay shared). ``None`` = the implicit default
    shard. It never affects routing — see :mod:`messagefoundry.pipeline.sharding`.

    ``priority`` (#61, ADR 0048) tags this inbound with a DR / priority tier (``critical``/``normal``/
    ``low``): ``None`` inherits the global ``[delivery].priority`` default, an explicit value overrides
    it. Under a DR run-profile the engine binds only inbound listeners whose resolved tier rank meets
    ``[dr].priority_threshold`` — a below-threshold listener is **not bound** and reports
    ``status:"filtered"`` (distinct from ADR 0031's ``"failed"``). It governs only **when** the
    connection runs, never routing; also a ``connections.toml`` key (ADR 0007)."""
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
            strict_timeout_s=strict_timeout_s,
            content_type=content_type,
            inline=inline,
            auto_start=auto_start,
            schedule=schedule,
            metadata=metadata,
            bind_address=bind_address,
            source_ip_allowlist=source_ip_allowlist,
            capture_ack=capture_ack,
            capture_connection_errors=capture_connection_errors,
            messages_days=messages_days,
            prune_documents_after=prune_documents_after,
            prune_documents_min_bytes=prune_documents_min_bytes,
            priority=priority,
            shard=shard,
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
    stall: StallThreshold | None = None,
    batch: BatchConfig | None = None,
    simulate: bool = False,
    auto_start: bool = True,
    schedule: Schedule | None = None,
    dead_letter_days: int | None = None,
    priority: Priority | None = None,
    metadata: Mapping[str, Any] | None = None,
    source_file: str | None = None,
    source_line: int | None = None,
) -> OutboundConnection:
    """Validate the outbound-connection invariants and build an :class:`OutboundConnection`.

    The shared core of code-first :func:`outbound` **and** the ``connections.toml`` loader (ADR 0007).
    Pure — it does not touch the active registry; the caller is responsible for ``add_outbound``."""
    if dead_letter_days is not None and dead_letter_days < 0:
        # Per-connection dead-letter retention override (#34, ADR 0027). None = inherit
        # [retention].dead_letter_days; 0 = keep forever; >0 = days. A negative window is meaningless —
        # fail loud at wiring (caught in dry-run / `messagefoundry check`).
        raise WiringError(
            f"outbound connection {name!r}: dead_letter_days must be >= 0 "
            "(0 = keep forever, omit to inherit the global [retention] window)"
        )
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
    # ADR 0082 (#134): opt-in HL7 batch aggregation. Gate at the wiring choke point so `check`/dry-run
    # rejects an unsupportable config before any store is opened.
    if batch is not None:
        if spec.type is not ConnectorType.MLLP:
            # BHS/BTS framing is HL7v2-specific; other transports have no batch-envelope analogue. The
            # outbound has no content_type (inbound-only), so gate on the MLLP connector type itself.
            raise WiringError(
                f"outbound connection {name!r}: batch aggregation is MLLP (HL7v2) only, "
                f"not {spec.type.value.upper()} (ADR 0082)."
            )
        if spec.settings.get("capture_response"):
            # One batch-level ACK covers the whole envelope; there is no per-row reply to capture or
            # re-ingress (ADR 0013). Reject the combination rather than silently drop N-1 captures.
            reason = "reingress_to" if spec.settings.get("reingress_to") else "capture_response"
            raise WiringError(
                f"outbound connection {name!r}: batch aggregation is incompatible with {reason} "
                "— one batch ACK cannot fan out to N per-message captured replies (ADR 0082/0013)."
            )
    return OutboundConnection(
        name=name,
        spec=spec,
        retry=retry,
        ordering=ordering,
        internal_error=internal_error,
        buildup=buildup,
        stall=stall,
        batch=batch,
        simulate=simulate,
        auto_start=auto_start,
        schedule=schedule,
        dead_letter_days=dead_letter_days,
        priority=priority,
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
    stall: StallThreshold | None = None,
    batch: BatchConfig | None = None,
    simulate: bool = False,
    auto_start: bool = True,
    schedule: Schedule | None = None,
    dead_letter_days: int | None = None,
    priority: Priority | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    """Declare an outbound connection that Handlers can ``Send`` to.

    ``retry``/``ordering``/``internal_error``/``buildup``/``stall`` override the global ``[delivery]``
    defaults for this connection only (omit to inherit). ``ordering`` defaults to FIFO — strict in-order
    delivery per connection; ``internal_error`` defaults to continue (dead-letter a code-error row and
    advance); ``buildup`` sets the ``queue_buildup`` alert thresholds for this lane; ``stall`` sets the
    ``message_stall`` oldest-undelivered-age threshold (Corepoint "Max Message Stall", off by default).
    ``simulate=True``
    runs the full pipeline but **suppresses the real egress** (shadow / parallel-run mode, #15) — no
    bytes leave the box and the message still finalizes PROCESSED. ``dead_letter_days`` (#34, ADR 0027)
    overrides the global ``[retention].dead_letter_days`` window for this outbound's dead-lettered bodies:
    ``None`` inherits the global window, ``0`` keeps them forever, ``>0`` prunes after that many days (also
    a ``connections.toml`` key). ``priority`` (#61, ADR 0048) tags this outbound with a DR / priority
    tier (``critical``/``normal``/``low``): ``None`` inherits the global ``[delivery].priority`` default,
    an explicit value overrides it; under a DR run-profile the engine builds only outbound connectors
    whose resolved tier rank meets ``[dr].priority_threshold`` — a below-threshold outbound reports
    ``status:"filtered"`` and queues its routed rows for later delivery (also a ``connections.toml`` key).
    ``metadata`` attaches free-form operator labels (Tier 4) surfaced by the API, never used for
    delivery."""
    file, line = _call_site()
    _active_registry().add_outbound(
        build_outbound_connection(
            name,
            spec,
            retry=retry,
            ordering=ordering,
            internal_error=internal_error,
            buildup=buildup,
            stall=stall,
            batch=batch,
            simulate=simulate,
            auto_start=auto_start,
            schedule=schedule,
            dead_letter_days=dead_letter_days,
            priority=priority,
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


def handler(
    name: str, *, accepts: HandlerAccepts | None = None
) -> Callable[[HandlerFn], HandlerFn]:
    """Register a Handler: ``def handle(msg) -> Send | SetState | SetMeta | list[...] | None``
    (``None`` => filtered; :class:`SetState` declares a cross-message state write, ADR 0005;
    :class:`SetMeta` attaches a per-message metadata key/value, ADR 0081 — both applied exactly-once in
    the handoff).

    ``accepts`` (ADR 0084) is an optional **pure** router-stage predicate — ``(msg) -> bool`` — that
    lets this handler decline a message at *routing* time, before a routed row is materialized: a
    decline then costs 0 transactions instead of the 2 an in-handler ``return []`` pays. Omitted (the
    default) the handler behaves exactly as today. See :data:`HandlerAccepts` for the purity contract
    (no live lookups — they raise in the router phase anyway; no ``state_get``/``response_get`` — they
    fail OPEN there and are rejected at load time; no mutation of the payload).

    **Disposition shift when migrating a filter.** Moving an in-handler ``return []`` to ``accepts=``
    changes a message that EVERY handler declines from ``FILTERED`` ("handlers ran, delivered nothing")
    to ``UNROUTED`` ("no handler took it") — the ratified ADR 0084 §4 semantic, since a declined handler
    never ran. Re-key any dashboard/alert that distinguishes the two buckets before migrating."""

    def decorate(fn: HandlerFn) -> HandlerFn:
        _active_registry().add_handler(name, fn, accepts)
        return fn

    return decorate


# --- loader ------------------------------------------------------------------


class _SiblingHelperFinder:
    """Resolve a config module's top-level ``import _helpers`` to a sibling ``.py`` in the config dir.

    The loader runs non-``_`` modules under mangled names and skips ``_``-prefixed files as top-level
    modules, but CLAUDE.md §4 documents importing shared ``_``-prefixed helpers from siblings. Those
    files aren't on ``sys.path``, so without a finder Python can't locate them and the import fails
    (review low-10). Installed on ``sys.meta_path`` only while a config dir loads, and resolves **only**
    ``_``-prefixed top-level names (matching the loader's ``_*``-skip rule) against ``<name>.py`` in
    that dir. Scoping to ``_``-prefixed names means a config-dir file named after a real module
    (``os.py``, ``json.py``, ``ssl.py``, ``requests.py`` — none start with ``_``) can no longer
    shadow the stdlib/installed module for the duration of the load (SEC-019, CWE-427); only the
    documented ``_``-helper convention is served. :func:`_assert_safe_config_source` already vets every
    ``*.py`` (including ``_*``), so a helper sits inside the same trust boundary as its importers."""

    def __init__(self, directory: Path, created: set[str]) -> None:
        self._dir = directory
        self._created = created

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
        if path is not None or "." in fullname:
            return None  # only top-level absolute imports, resolved against the config dir
        # SEC-019 (CWE-427): only serve the documented ``_``-prefixed helper convention so a config-dir
        # file named after a real stdlib/installed module (os/json/ssl/requests — none start with ``_``)
        # cannot pre-empt normal finder resolution and silently shadow it. No stdlib/installed top-level
        # module name starts with ``_``, and every legitimate sibling helper does, so this is sufficient.
        if not fullname.startswith("_"):
            return None
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

# --- Windows config-source trust (SEC-003, CWE-732) --------------------------
#
# On Windows the config dir + each *.py DACL/owner is parsed in-process (mirroring the POSIX
# group/world-writable + foreign-owner check) and a source whose DACL grants a broad/low-privilege
# principal a write-class right is refused. The check used to be an unconditional no-op, delegating
# entirely to install-time ACLs — but Windows is the documented primary deployment target and the
# installer does not lock the config dir, so an inherited write ACE could let a low-privileged local
# user rewrite a module that then executes as the engine service account (local privilege escalation).

# Any ALLOWED ACE granting one of these access rights is "write-class" — enough to rewrite/replace the
# executed code or hijack its ACL. FILE_WRITE_DATA/APPEND/WRITE_EA/WRITE_ATTRIBUTES + DELETE + the two
# ACL-control bits (WRITE_DAC/WRITE_OWNER) + GENERIC_WRITE/GENERIC_ALL.
_WIN_WRITE_MASK = (
    0x00000002  # FILE_WRITE_DATA
    | 0x00000004  # FILE_APPEND_DATA
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)

# Broad/low-privilege well-known SIDs that must never hold a write-class right on executed config.
_WIN_REJECTED_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # NT AUTHORITY\Authenticated Users
        "S-1-5-32-545",  # BUILTIN\Users
        "S-1-5-4",  # NT AUTHORITY\INTERACTIVE
        "S-1-5-7",  # NT AUTHORITY\Anonymous Logon
    }
)

# SIDs trusted to hold write on executed config (the owner is also always trusted, plus the current
# process user, both passed in at evaluation time): SYSTEM and the local Administrators group. The two
# placeholder/alias SIDs CREATOR OWNER (S-1-3-0) and OWNER RIGHTS (S-1-3-4) resolve to whoever OWNS the
# object (not a foreign principal), so an ACE granting them write is equivalent to an owner grant and
# is trusted — they appear on inherited ACLs (e.g. the user-profile temp dir) and must not be refused.
_WIN_TRUSTED_SIDS = frozenset(
    {
        "S-1-5-18",  # NT AUTHORITY\SYSTEM
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-3-0",  # CREATOR OWNER (placeholder: rights granted to the object's owner)
        "S-1-3-4",  # OWNER RIGHTS (the current owner's effective rights)
    }
)

# ACE type byte (ACE_HEADER.AceType) for an ACCESS_ALLOWED_ACE — the only type that grants rights.
_WIN_ACCESS_ALLOWED_ACE_TYPE = 0x00


def _evaluate_config_dacl(
    owner_sid: str,
    aces: Sequence[tuple[int, int, str]],
    self_sid: str | None,
) -> str | None:
    """Pure DACL policy: return a refusal reason, or ``None`` if the source is trusted.

    ``aces`` is ``(ace_type, access_mask, trustee_sid)`` tuples as strings (``ConvertSidToStringSidW``
    form). A source is refused when any **ALLOWED** ACE grants a **write-class** right to a principal
    that is neither the file owner, nor the current process user, nor a trusted admin/SYSTEM SID —
    and unconditionally when a broad/low-privilege SID (Everyone/Authenticated Users/Users/…) holds
    such a right. Kept free of ctypes so the policy is unit-testable on every platform."""
    trusted = set(_WIN_TRUSTED_SIDS)
    trusted.add(owner_sid)
    if self_sid is not None:
        trusted.add(self_sid)
    for ace_type, access_mask, trustee_sid in aces:
        if ace_type != _WIN_ACCESS_ALLOWED_ACE_TYPE:
            continue  # DENY/audit/etc. ACEs never grant a right
        if not access_mask & _WIN_WRITE_MASK:
            continue  # read/execute-only ACE (e.g. Users:RX on a repo checkout) is fine
        if trustee_sid in _WIN_REJECTED_SIDS:
            return f"a broad/low-privilege principal ({trustee_sid}) has write access"
        if trustee_sid not in trusted:
            return f"a non-owner, non-admin principal ({trustee_sid}) has write access"
    return None


def _assert_safe_config_source_windows(directory: Path) -> None:
    """Windows NTFS-DACL/owner check mirroring the POSIX guard (SEC-003).

    Parses the owner + DACL of the directory and each ``*.py`` (incl. ``_*.py`` helpers, the same
    candidate set as POSIX) via ctypes/advapi32 and refuses to load when :func:`_evaluate_config_dacl`
    rejects it. **Fail-open with a loud WARNING on a Win32 API error**: a ``GetNamedSecurityInfoW``
    failure must not brick a previously-working service — it logs and proceeds (no worse than the old
    no-op). A NULL/absent DACL, however, means "everyone allowed" and is treated as a REFUSAL. All
    ctypes work lives behind the ``sys.platform == 'win32'`` guard in the caller so mypy/lint pass on
    the Linux CI leg (mirrors :mod:`messagefoundry.secrets_dpapi`)."""
    if sys.platform != "win32":  # pragma: no cover - guard for type-checker / non-Windows
        return
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Declare prototypes so 64-bit pointers aren't truncated to a default c_int arg (which raises an
    # OverflowError on a high address). PVOID = c_void_p; PSID/PACL/PSECURITY_DESCRIPTOR are pointers.
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,  # pObjectName
        ctypes.c_int,  # SE_OBJECT_TYPE
        wintypes.DWORD,  # SECURITY_INFORMATION
        ctypes.POINTER(ctypes.c_void_p),  # ppsidOwner
        ctypes.POINTER(ctypes.c_void_p),  # ppsidGroup
        ctypes.POINTER(ctypes.c_void_p),  # ppDacl
        ctypes.POINTER(ctypes.c_void_p),  # ppSacl
        ctypes.POINTER(ctypes.c_void_p),  # ppSecurityDescriptor
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,  # TOKEN_INFORMATION_CLASS
        ctypes.c_void_p,  # TokenInformation (buffer)
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    # GetNamedSecurityInfoW(pObjectName, SE_FILE_OBJECT=1, SecurityInfo, ppOwner, ppGroup, ppDacl,
    # ppSacl, ppSecurityDescriptor). We request OWNER (0x1) | DACL (0x4). The SD is allocated by the
    # API and must be LocalFree'd; the owner/DACL pointers point INTO that buffer (do not free them).
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004

    class _ACL(ctypes.Structure):
        _fields_ = (
            ("AclRevision", wintypes.BYTE),
            ("Sbz1", wintypes.BYTE),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        )

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = (
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        )

    # ACCESS_ALLOWED_ACE: header + AccessMask (DWORD) + the first DWORD of the trustee SID (SidStart).
    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = (
            ("Header", _ACE_HEADER),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        )

    def _sid_to_str(sid_ptr: int) -> str | None:
        out = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
            return None
        try:
            return out.value
        finally:
            # ConvertSidToStringSidW allocates the string with LocalAlloc; free its address.
            if out:
                kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))

    def _self_sid() -> str | None:
        # Current process user SID, so a config dir the service account itself owns/controls passes.
        token = wintypes.HANDLE()
        _TOKEN_QUERY = 0x0008
        _TokenUser = 1
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            return None
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, _TokenUser, None, 0, ctypes.byref(size))
            if size.value == 0:
                return None
            buf = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(
                token, _TokenUser, buf, size.value, ctypes.byref(size)
            ):
                return None
            # TOKEN_USER = SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }; Sid is the first pointer.
            sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            return _sid_to_str(sid_ptr) if sid_ptr else None
        finally:
            kernel32.CloseHandle(token)

    self_sid = _self_sid()
    candidates = [directory, *directory.glob("*.py")]
    for path in candidates:
        owner_sid_ptr = ctypes.c_void_p()
        dacl_ptr = ctypes.c_void_p()
        sd_ptr = ctypes.c_void_p()
        rc = advapi32.GetNamedSecurityInfoW(
            ctypes.c_wchar_p(str(path)),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner_sid_ptr),
            None,
            ctypes.byref(dacl_ptr),
            None,
            ctypes.byref(sd_ptr),
        )
        if rc != 0:
            # API error (not a policy decision): fail OPEN with a loud warning — never brick a service
            # that started fine before this change (the worst case is "no worse than the old no-op").
            _logger.warning(
                "config-source trust guard could not evaluate the DACL of %s (Win32 error %d); "
                "proceeding WITHOUT the Windows ACL check — verify the config dir is not writable by "
                "a low-privileged principal (see docs/SERVICE.md)",
                path,
                rc,
            )
            continue
        try:
            # A NULL DACL means "no DACL present" => everyone is implicitly allowed full control. That
            # is the most-permissive possible state, so REFUSE (unlike an API error, this is a real,
            # observed insecure ACL — not an inability to read it).
            if not dacl_ptr:
                _refuse_unsafe_config_source(
                    f"refusing to load config from {path}: it has a NULL DACL (everyone implicitly "
                    f"has full control); see docs/SERVICE.md for required permissions"
                )
                continue
            owner_addr = owner_sid_ptr.value
            owner_sid = _sid_to_str(owner_addr) if owner_addr else None
            if owner_sid is None:
                _logger.warning(
                    "config-source trust guard could not resolve the owner SID of %s; proceeding "
                    "WITHOUT the Windows ACL check for this path (see docs/SERVICE.md)",
                    path,
                )
                continue
            acl = ctypes.cast(dacl_ptr, ctypes.POINTER(_ACL)).contents
            aces: list[tuple[int, int, str]] = []
            unreadable = False
            for i in range(acl.AceCount):
                ace_ptr = ctypes.c_void_p()
                if not advapi32.GetAce(dacl_ptr, i, ctypes.byref(ace_ptr)):
                    unreadable = True
                    break
                header = ctypes.cast(ace_ptr, ctypes.POINTER(_ACE_HEADER)).contents
                if header.AceType != _WIN_ACCESS_ALLOWED_ACE_TYPE:
                    aces.append((header.AceType, 0, ""))  # non-allow ACE: policy ignores it
                    continue
                allowed = ctypes.cast(ace_ptr, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
                # The trustee SID begins at the SidStart field offset within the ACE structure.
                sid_offset = _ACCESS_ALLOWED_ACE.SidStart.offset
                sid_ptr = ace_ptr.value + sid_offset if ace_ptr.value is not None else 0
                trustee = _sid_to_str(sid_ptr) if sid_ptr else None
                if trustee is None:
                    unreadable = True
                    break
                aces.append((header.AceType, int(allowed.Mask), trustee))
            if unreadable:
                _logger.warning(
                    "config-source trust guard could not enumerate the DACL of %s; proceeding WITHOUT "
                    "the Windows ACL check for this path (see docs/SERVICE.md)",
                    path,
                )
                continue
            reason = _evaluate_config_dacl(owner_sid, aces, self_sid)
            if reason is not None:
                _refuse_unsafe_config_source(
                    f"refusing to load config from writable-by-others path {path}: {reason}; "
                    f"see docs/SERVICE.md for required permissions"
                )
        finally:
            if sd_ptr:
                kernel32.LocalFree(sd_ptr)


def _refuse_unsafe_config_source(message: str) -> None:
    """Raise ``WiringError(message)`` unless the explicit dev/test escape is set, then warn instead.

    Fail-closed by default: a PHI service must not execute config Python a low-privileged user can
    rewrite. ``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE`` (off by default; never set in production — the
    installer locks the config dir so production never trips this) downgrades the refusal to a loud
    warning for a user-writable dev/CI checkout. Symmetric across the POSIX and Windows guards."""
    # Local import keeps the settings <-> wiring module load order independent (no circular import).
    from messagefoundry.config.settings import (
        INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
        insecure_config_source_allowed,
    )

    if insecure_config_source_allowed():
        _logger.warning(
            "%s — proceeding because %s is set (dev/test override; NEVER set this in production)",
            message,
            INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
        )
        return
    raise WiringError(message)


def _assert_safe_config_source(directory: Path) -> None:
    """Refuse to execute config Python from a writable-by-others location.

    Because :func:`_exec_module` runs arbitrary Python as the engine's service account, a
    lower-privileged user who can write into the config dir (or a module file) could execute
    code as that account on the next reload. On POSIX we hard-fail on a group/world-writable
    directory or module. On Windows the equivalent NTFS-DACL check now runs in-process
    (:func:`_assert_safe_config_source_windows`, SEC-003): the directory and each ``*.py``
    owner/DACL is parsed via ctypes and a source whose DACL grants a broad/low-privilege
    principal a write-class right is refused — no longer a silent no-op delegated entirely to
    install-time ACLs (docs/SERVICE.md, DEPLOY-1)."""
    if not directory.is_dir():
        return
    if sys.platform == "win32":
        _assert_safe_config_source_windows(directory)
        return
    if os.name != "posix":
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
            _refuse_unsafe_config_source(
                f"refusing to load config from group/world-writable path {path} "
                f"(mode {oct(st.st_mode & 0o777)}); see docs/SERVICE.md for required permissions"
            )
            continue
        # Code here runs as the engine's account, so a file owned by a *different* unprivileged user
        # is an escalation vector even at 0644 — that user can rewrite it (CONFIG-2 / review M-21).
        if self_uid is not None and self_uid != 0 and st.st_uid != self_uid:
            _refuse_unsafe_config_source(
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
    # Mirror Registry.validate's `accepts=` checks as editor diagnostics (ADR 0084) — an orphan /
    # non-callable / fail-open-state-reading predicate should surface in the IDE, not first at `serve`.
    for hname, pred in registry.handler_accepts.items():
        if hname not in registry.handlers:
            diagnostics.append(
                Diagnostic(message=f"accepts= predicate declared for unknown handler {hname!r}")
            )
            continue
        try:
            _check_accepts_predicate(hname, pred)
        except WiringError as exc:
            diagnostics.append(Diagnostic(message=str(exc)))
    for port, first, second in registry.port_collisions():  # low-13
        diagnostics.append(
            Diagnostic(
                message=f"inbound connections {first!r} and {second!r} both bind port {port}"
            )
        )
    return diagnostics
