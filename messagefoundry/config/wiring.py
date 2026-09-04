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
import re
import sys
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from messagefoundry.config.code_sets import (
    CODESETS_DIR_NAME,
    CodeSet,
    CodeSetError,
    load_code_sets,
)
from messagefoundry.config.code_sets import (
    activated as _code_sets_activated,
)
from messagefoundry.config.code_sets import (
    code_set as _resolve_code_set,
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
    _check_cleartext_acceptance,
)
from messagefoundry.config.send_snapshot import snapshot_on_send_active
from messagefoundry.parsing.message import Message, RawMessage, snapshot_payload

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
    "connector_secret_env_values",
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
    "message_type_of",
    "MessageTypeError",
    "load_config",
    "validate_config",
    "accepted_cleartext_hops",
    "expiry_relaxed_hops",
    "unverified_generic_db_hops",
    "overbroad_smart_scopes",
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
    default = value["default"] if "default" in value else _UNSET  # noqa: SIM401
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
    acquire_timeout: float = 30.0,  # cap this source's pooled-connection borrow (s) — BACKLOG #1052
) -> ReferenceSourceSpec:
    """A reference **source** backed by a SQL query (ADR 0006 increment 2; SQL Server via the
    ``[sqlserver]`` extra + ODBC Driver 18 — **production / supported**, like the DATABASE connector).

    The engine runs ``statement`` (a read-only ``SELECT``/proc) on the set's refresh cadence and builds
    the snapshot from the rows: ``key_column`` is the lookup key; ``value_column`` (if given) is that
    column's value, else the value is a dict of the remaining columns (the multi-column ``code_set``
    shape). Put secrets (``password``) in :func:`env`. TLS is on by default; weakening it needs
    ``MEFOR_ALLOW_INSECURE_TLS``. The dial-out is gated by the **fail-closed** ``[egress].allowed_db``
    allowlist, exactly like a DATABASE poll source — point the engine only at allowed hosts.

    ``acquire_timeout`` bounds the borrow from this source's throwaway pool (default 30 s, matching
    the DATABASE connector and ``[store].acquire_timeout``). On expiry the set's sync fails, the
    last-good snapshot stays active and the AlertSink fires — the runner syncs sets sequentially, so
    the bound is what stops one unresponsive server from stalling every other set's refresh."""
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
            "acquire_timeout": acquire_timeout,
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
    # ADR 0153 decision 2 — the same per-connection cleartext declaration an outbound carries. It must
    # be authorable HERE: the read executor honours the pair, so leaving it to a hand-mutated
    # `spec.settings` would be an escape with no load validation and nothing for the loosening registry
    # to name — a deviation the registry cannot see is a second posture by the back door.
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> FhirLookupSpec:
    """Declare a named live-lookup FHIR connection (ADR 0043). A Handler reads it at run time with
    ``fhir_lookup(name, query, params)`` — a **read-only** read-by-id (``fhir_lookup(name,
    "Patient/123")``) or a search whose path is ``query`` and whose fields are the structured ``params``
    mapping (``fhir_lookup(name, "Patient", {"identifier": FhirToken("MRN", mrn)})``). ``params`` is the
    **only** search form — each value is percent-encoded by the engine, so a value cannot inject an extra
    search parameter, and a ``?``-query inside ``query`` is refused (BACKLOG #1243). Percent-encoding is
    a URL-layer control only, so each value also states its **kind** at the FHIR value layer: a plain
    ``str`` is data and is refused if it carries ``,`` ``|`` or ``$``, a ``FhirToken`` is a
    ``system|code`` pair, and a ``FhirRaw`` is author-written search syntax — see
    :mod:`messagefoundry.fhirsearch`. The parsed resource / searchset ``Bundle`` comes back as a dict.
    Side-effecting (it self-registers), like :func:`Reference` / :func:`inbound`, **and** returns the spec
    so SMART auth can be composed onto it::

        FhirLookup("epic", url=env("epic_fhir_base"))                  # static / no auth
        with_smart_backend(                                           # SMART Backend Services bearer
            FhirLookup("epic", url=env("epic_fhir_base")),
            token_url=env("epic_token_url"), client_id=env("epic_client_id"),
            private_key=env("epic_smart_key"), scope="system/Patient.rs",  # read+search only
        )

    The read is **GET-only** (structurally read-only — a Handler cannot mutate the FHIR server through it;
    FHIR writes stay on the :func:`FHIR` outbound). The dial-out is gated by the **fail-closed**
    ``[egress].allowed_http`` allowlist (the same arm the FHIR outbound + SMART token endpoint use) — point
    the engine only at allowed hosts. Put secrets (``bearer_token`` / ``basic_*`` / SMART keys) in
    :func:`env`. TLS is on by default; weakening it needs ``MEFOR_ALLOW_INSECURE_TLS``. The pure
    ``parsing/fhir/`` codec parses the reply, so a ``FhirLookup``-declaring graph needs the optional
    ``messagefoundry[fhir]`` extra.

    ``cleartext_accepted`` / ``cleartext_reason`` (ADR 0153) declare that this lookup's read hop is
    cleartext, is not secure, and the operator accepts that — a mandatory written reason, a loud WARN
    plus an audit record at every construction, and an entry in ``security_loosenings()`` /
    ``GET /security/posture`` naming this connection. Same flag/reason coherence rules as an
    ``outbound()``: the flag without a reason, a blank reason, or a reason without the flag all fail
    loud at load."""
    # ADR 0153: coherence-checked at the ONE authoring surface, exactly as build_outbound_connection
    # does for an outbound, so the declaration cannot reach the read executor unvalidated.
    try:
        _check_cleartext_acceptance(cleartext_accepted, cleartext_reason)
    except ValueError as exc:
        raise WiringError(f"fhir lookup {name!r}: {exc}") from exc
    settings: dict[str, Any] = {
        "url": url,  # stored under "url" (NOT base_url) so the egress gate reads the same key as FHIR()
        "fhir_version": fhir_version,
        "headers": headers or {},
        "bearer_token": bearer_token,
        "basic_user": basic_user,
        "basic_password": basic_password,
        "timeout_seconds": timeout_seconds,
        "verify_tls": verify_tls,
        "encoding": encoding,
    }
    if cleartext_accepted:
        # Written only when declared, so an undeclared lookup's settings are byte-identical (and the
        # redacted settings view, which several surfaces render, gains no empty governance keys).
        settings["cleartext_accepted"] = True
        settings["cleartext_reason"] = cleartext_reason
        settings["cleartext_connection"] = name
    spec = FhirLookupSpec(name, settings)
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
                        # NEVER the raw value: a MEFOR_VALUE_* env() setting carries store passwords
                        # and connector keys, and this string is raised at startup into the operator
                        # log, the support bundle and GET /logs/tail (BACKLOG #1183). The value used to
                        # appear TWICE here -- once from this f-string and once inside the cast's own
                        # ValueError text ("invalid literal for int() with base 10: '<value>'") -- so
                        # dropping only the f-string half would still have leaked it. Name the setting,
                        # the key and the expected TYPE, which is the whole diagnostic an operator
                        # needs to go fix the value they already hold.
                        want = getattr(value.cast, "__name__", None) or type(value.cast).__name__
                        bad.append(
                            f"setting {name!r} (env {value.key!r}): value is not a valid {want} "
                            f"({type(exc).__name__}; value withheld)"
                        )
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
        # BACKLOG #65 — generic outbound HTTP auth secrets (OAuth2 client-credentials symmetric secret;
        # HTTP Digest / NTLM password). The minted bearer / digest response are runtime-only.
        "oauth2_client_secret",
        "http_auth_password",
        # BACKLOG #1106 follow-up — the HTTP Digest USERNAME, redacted defence-in-depth alongside
        # `basic_user`/`proxy_user`/`ws_username`/`credential_username`/`username` on the ground stated
        # there: a username names a principal and can leak directory structure. It was the sixth member
        # of a five-member class and the only one unclassified, because `with_http_digest` renames
        # parameter `user` into setting `http_auth_user` — the SAME parameter-to-setting boundary
        # `with_signing` crosses (`private_key` -> `sign_private_key`), which is the whole of #1106.
        # Measured before the fix: served verbatim by /metadata and printed by `graph --json`, with its
        # env() FALLBACK DEFAULT intact, beside a `proxy_user` that masked on the same object.
        "http_auth_user",
        # ADR 0126 (#127) — the forward/egress web-proxy credential. The Basic Proxy-Authorization header /
        # Digest response are runtime-only; the password + username inputs are redacted in /metadata (the
        # username alongside `basic_user`/`ws_username`, defence-in-depth).
        "proxy_password",
        "proxy_user",
        # ADR 0015 — WS-* SOAP outbound: the WS-Security UsernameToken credentials and the mTLS
        # client-key passphrase. ``ws_password`` back-fills from ``basic_password`` in the connector,
        # so omitting these disclosed under one name the very credential the other name masks.
        "ws_username",
        "ws_password",
        "client_key_password",
        # ADR 0085 — Direct S/MIME-over-SMTP: the signing-key passphrase. (``signing_key`` itself is a
        # *path* to the key file, like ``tls_key_file``/``client_key_file``, so it is not listed here.)
        "signing_key_password",
        # ADR 0132 (#111) — File-endpoint alternate Windows/UNC-share credential. The password is the
        # secret (env() only, enforced by the File() factory); the username is redacted defence-in-depth
        # alongside ``basic_user``/``ws_username``. ``credential_domain`` is non-secret (an AD domain
        # name), so it is intentionally not listed.
        "credential_username",
        "credential_password",
        # ADR 0154 (D6) — the inbound HTTP listener's intake-auth peer credential and its rotation
        # partner. Both are env()-only (enforced by the Http() factory) and rotatable, so they are
        # deliberately NOT in _NON_ROTATABLE_SECRET_SETTING_KEYS: that enrols them in the ASVS 13.3.4
        # fingerprinter and the 13.1.4 registration gate, which is the point. ``intake_api_key_header``
        # is a header NAME, not a credential, and is classified non-secret in tests/test_connection_api.
        "intake_api_key",
        "intake_api_key_next",
    }
)

#: Header names whose value is a credential — redacted inside a REST/SOAP ``headers`` table (the
#: project requires secrets via ``env()`` bearer/basic settings, not inline headers; this is defence
#: in depth for an operator who hard-codes one anyway). Compared case-insensitively.
_SECRET_HEADER_NAMES = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key", "cookie"}
)

#: Substrings that make a header name credential-bearing. BACKLOG #1201.
#:
#: The five names above were the WHOLE test, by exact membership. That is the same defect as #1106 and
#: strictly worse, because header names are OPERATOR-AUTHORED FREE TEXT -- there is no factory, no
#: signature and no registry to enumerate, so an exhaustive list cannot exist even in principle.
#: Measured 2026-08-09 against the shipped list: ``X-Auth-Token``, ``X-Amz-Security-Token`` (an AWS
#: SigV4 session credential) and ``Private-Token`` (GitLab's standard auth header) were all returned
#: VERBATIM by ``/metadata`` and printed by ``graph --json``.
#:
#: So the test is by SHAPE, with the explicit set kept as a floor rather than deleted -- ``cookie``
#: matches no substring rule and must stay named.
_SECRET_HEADER_SUBSTRINGS = (
    "auth",
    "token",
    "secret",
    "credential",
    "password",
    "passphrase",
    "key",
)

#: Header names that CONTAIN a secret-ish substring and are not credentials. Each is here because
#: redacting it would destroy operator-visible routing or tracing information that is public by nature.
#: Suffix-matched, because the convention is consistent: an ``-id`` names something, it is not the thing.
_NOT_SECRET_HEADER_SUFFIXES = (
    "-id",
    "-url",
    "-uri",
    "-name",
    "-type",
    "-version",
    "-agent",
    "-for",
)

#: Exact non-credential headers whose name defeats the suffix rule. ``Idempotency-Key`` is the live one:
#: it carries "key" and is a client-generated REQUEST identifier, published in the API docs of every
#: service that uses it.
_NOT_SECRET_HEADERS = frozenset({"idempotency-key", "x-idempotency-key"})


#: Value shapes that are credentials whatever the header is called. The NAME rule below is a heuristic
#: over free text and therefore has a permanent blind spot -- a vendor picks ``X-Shared-Signature`` or an
#: opaque internal name and no substring matches. This is the second arm, and it closes that blind spot
#: from the other side: it does not matter what the header is called if the VALUE is recognisably a
#: credential. Deliberately narrow, because a false positive here masks a value an operator may need:
#:   - an RFC 7235 auth scheme prefix (``Bearer``/``Basic``/``Digest``/``Negotiate``/``AWS4-HMAC-...``)
#:   - a JWT, which is unmistakable and is what most opaque bearer headers actually carry
_CREDENTIAL_VALUE_PREFIXES = ("bearer ", "basic ", "digest ", "negotiate ", "aws4-hmac")
_JWT_SHAPE = re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+$")


def _looks_like_a_credential_value(value: object) -> bool:
    """Is this VALUE a credential regardless of what the header is called?"""
    if not isinstance(value, str):
        return False
    v = value.strip()
    return v.lower().startswith(_CREDENTIAL_VALUE_PREFIXES) or bool(_JWT_SHAPE.match(v))


#: Credential-bearing ODBC/libpq driver keywords, by SHAPE and case-insensitively (BACKLOG #1206).
#:
#: A THIRD predicate rather than reuse, and the first attempt at this fix proves why. I reached for
#: :func:`_is_secret_setting` -- and it returned False for every one of ``PWD``, ``Password`` and
#: ``sslpassword``, because it matches a fixed frozenset of MessageFoundry SETTINGS names and these are
#: ODBC DRIVER keywords with different spellings and different case. A fix that shipped on that
#: predicate would have masked nothing while reading as a fix, in the change closing a defect whose
#: whole shape is a control whose domain is narrower than its surface.
#:
#: ``pwd`` is listed explicitly because it is an ABBREVIATION and matches no substring rule -- it is
#: also the single most common spelling in a SQL Server DSN.
_SECRET_ODBC_SUBSTRINGS = (
    "pwd",
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "passphrase",
)

#: ODBC keywords that carry a credential-ish substring and are PATHS, not material. Masking a path
#: hides configuration an operator needs to see and protects nothing: the file's contents never enter
#: settings. ``sslkey`` and ``sslcert`` are libpq file paths.
_NOT_SECRET_ODBC_KEYS = frozenset({"sslkey", "sslcert", "sslrootcert", "sslcrl"})


def _is_secret_odbc_key(name: str) -> bool:
    """Would printing this ODBC keyword's VALUE disclose a credential?"""
    low = str(name).strip().lower()
    if low in _NOT_SECRET_ODBC_KEYS or low.endswith(("_file", "_path")):
        return False
    return any(tok in low for tok in _SECRET_ODBC_SUBSTRINGS)


def _is_secret_header(name: str, value: object = None) -> bool:
    """Would printing this header's VALUE disclose a credential?

    TWO ARMS, because either alone has a gap. The NAME arm (see :data:`_SECRET_HEADER_SUBSTRINGS`) is a
    heuristic over operator-authored free text, so an opaque vendor header name defeats it. The VALUE
    arm catches those, and cannot be defeated by naming, but only recognises shapes it knows. Together
    they cover a name that looks like a credential OR a value that is one; neither is a proof.

    A false positive costs an operator one redacted value in a diagnostic view and one line in
    :data:`_NOT_SECRET_HEADERS`; a false negative serves a bearer credential to anyone holding
    ``MONITORING_READ``. The asymmetry is not close, so this errs toward redacting -- but the VALUE arm
    is kept narrow (auth-scheme prefixes and JWTs only) rather than "long and high-entropy", because
    masking every long header value would quietly destroy the view rather than protect it.
    """
    if _looks_like_a_credential_value(value):
        return True
    low = str(name).strip().lower()
    if low in _SECRET_HEADER_NAMES:
        return True
    if low in _NOT_SECRET_HEADERS or low.endswith(_NOT_SECRET_HEADER_SUFFIXES):
        return False
    return any(tok in low for tok in _SECRET_HEADER_SUBSTRINGS)


def _is_secret_setting(name: str) -> bool:
    """Is ``name`` a credential-bearing settings key?

    The single source of truth for **both** settings serializers — ``redacted_settings`` (the API
    ``/metadata`` view) and ``display_settings`` (``graph --json`` → stdout, CI logs, the IDE graph
    view). They must never disagree: a key masked on one surface and printed on the other is a
    disclosure wearing a false sense of cover, which is exactly how ``ws_password`` was served in
    plaintext while ``basic_password`` — the same credential — was masked.

    The ``body_secret_value_*`` prefix covers the SOAP body-secret values (ADR 0015 amendment /
    BACKLOG #236): the factory already forbids an inline literal and an ``env()`` default on them, so
    each renders as a bare ``{"env": key}`` regardless — but the prefix is belt-and-suspenders in case
    a value ever reaches a serializer resolved. The paired ``body_secret_tokens`` are **not** secret:
    a placeholder is public by nature (it sits in the committed Handler source).

    ``sign_private_key`` / ``sign_private_key_password`` are named EXPLICITLY (BACKLOG #1106), and the
    reason they were missing is the point. ``with_signing`` takes parameters ``private_key`` and
    ``private_key_password`` — both of which this function already classified — and RENAMES them on the
    way into the settings map (``transports/signing.py``). The parameter was covered and the setting it
    became was not, so both were served verbatim by ``/metadata`` behind ``MONITORING_READ`` alone and
    printed by ``graph --json``. Measured 2026-08-09; the leak predated the cell that scored it, so no
    change-detector was ever in play.

    NOT a ``sign_`` prefix rule: ``sign_key_id`` is an identifier, ``sign_algorithm`` and ``sign_header``
    are configuration, and a prefix would redact all three while reading as more thorough. The domain is
    guarded instead by ``tests/test_connection_factory_redaction_domain.py``, which calls every
    spec-returning factory and asserts nothing credential-shaped survives this function — at the level
    of EMITTED settings rather than parameters, which is the boundary the rename crosses."""
    return (
        name in _SECRET_SETTING_KEYS
        or name.startswith("body_secret_value_")
        or name in ("sign_private_key", "sign_private_key_password")
    )


#: Connector secret-setting keys that are IDENTIFIERS (usernames), not rotatable credentials — a
#: username names a principal, it is not itself cycled on a cadence (you rotate its paired *password*).
#: They live in :data:`_SECRET_SETTING_KEYS` only so ``/metadata`` redacts them defence-in-depth (a
#: username can leak directory structure). The **single source of truth** for "which secret settings are
#: rotatable": imported by ``tests/test_secret_rotation_inventory.py`` (the ASVS-13.1.4 registration gate)
#: and read by :func:`connector_secret_env_values` (the ASVS-13.3.4 rotation fingerprinter). That the
#: redaction list, the doc registration gate, and the runtime fingerprint set agree about which members
#: are credentials you rotate is **enforced by two gates, not assumed**: the forward gate
#: (``test_secret_setting_keys_are_registered``) proves every rotatable key is registered, and the
#: reverse gate (``test_registered_connector_secrets_are_reachable_by_the_fingerprinter``, BACKLOG #1009)
#: proves every registered connector secret is reachable by the fingerprinter — the direction a
#: hand-added registry entry (the SOAP ``body_secret_value`` class) had slipped through.
_NON_ROTATABLE_SECRET_SETTING_KEYS: frozenset[str] = frozenset(
    {
        "username",
        "basic_user",
        "proxy_user",
        "ws_username",
        "credential_username",
        "http_auth_user",  # BACKLOG #1106 follow-up — the HTTP Digest principal; you rotate its password
    }
)


def connector_secret_env_values(
    registry: Registry, env_values: Mapping[str, Any]
) -> dict[str, str]:
    """The per-Connection ``env()``-sourced credential VALUES the wired graph references right now, keyed
    by their environment-value key (a NON-SECRET identifier) — the input to the ASVS-13.3.4 rotation
    watcher's ``extra_values`` (``pipeline/secret_rotation.reconcile_rotation_meta``), which fingerprints
    each with the DEK-derived keyed MAC so a per-Connection connector credential is monitored for rotation
    exactly like the fixed ``MEFOR_*`` classes.

    A setting is included when its key is a **rotatable** credential — recognised by
    :func:`_is_secret_setting` (so the SOAP ``body_secret_value_<i>`` prefix class is covered, not only
    the fixed :data:`_SECRET_SETTING_KEYS` names) and not a non-rotatable identifier in
    :data:`_NON_ROTATABLE_SECRET_SETTING_KEYS` — AND it is an ``env()``
    ref whose key resolves to a **non-empty string** in ``env_values``. Values are returned **transiently**
    to be MAC'd — never persisted or logged; the map key is the operator-chosen env name, never the value.
    Connections sharing an env key collapse to one entry (one secret → one rotation clock). Inline (non-
    ``env()``) credentials are skipped: they carry no stable per-environment identity to fingerprint, and
    the factories already forbid an inline value for a secret setting."""
    out: dict[str, str] = {}
    # Both connection kinds carry a ``.spec`` (ConnectionSpec); collect specs so the loop is typed to
    # ConnectionSpec rather than the join of the two connection types.
    specs: list[ConnectionSpec] = [c.spec for c in registry.inbound.values()]
    specs += [c.spec for c in registry.outbound.values()]
    for spec in specs:
        for name, value in spec.settings.items():
            if name in _NON_ROTATABLE_SECRET_SETTING_KEYS or not _is_secret_setting(name):
                continue
            if isinstance(value, EnvRef):
                resolved = env_values.get(value.key)
                if isinstance(resolved, str) and resolved:
                    out[value.key] = resolved
    return out


#: Settings whose value is a URL that may carry `user:password@` userinfo. `proxy` has no `_url`
#: suffix, which is why this is a NAME set plus a suffix rule rather than a suffix rule alone.
_URL_SETTING_SUFFIXES = ("url", "_url", "_uri", "endpoint", "_endpoint")


def _mask_url_userinfo(value: object) -> object:
    """Replace the PASSWORD half of a URL's userinfo with ``***``, keeping everything else readable.

    BACKLOG #1207. ``url="https://user:SECRET@host/path"`` was returned verbatim by both serializers
    while ``proxy_password`` on the SAME object masked -- the credential was safe in the typed field
    and disclosed in the URL beside it.

    The user half and the host and path are PRESERVED deliberately: an operator diagnosing a
    connection needs to see which account and which host, and masking the whole URL would destroy the
    view rather than protect it. Only the secret is removed.
    """
    if not isinstance(value, str) or "@" not in value or "//" not in value:
        return value
    scheme, _, rest = value.partition("//")
    userinfo, at, hostpart = rest.rpartition("@")
    if not at or ":" not in userinfo:
        return value  # no userinfo, or a user with no password -- nothing secret to remove
    user, _, _pw = userinfo.partition(":")
    return f"{scheme}//{user}:***@{hostpart}"


def _redact_header_value(name: str, value: object) -> object:
    """One header's value, scrubbed. Handles the ``EnvRef`` case the headers branch used to miss.

    BACKLOG #1207. The headers branch had no ``EnvRef`` arm, so an ``env()`` ref inside a headers
    table came back as the RAW OBJECT -- not JSON-safe, and carrying its ``default`` intact. The same
    ``env()`` on a top-level credential correctly emits ``{"env": key}`` with the default dropped, so
    the hole was INSIDE the one container this control claims to handle.

    THE DEFAULT IS DROPPED FOR EVERY HEADER, not only credential-shaped ones. A header value sourced
    from ``env()`` is a credential by intent -- nobody env-refs a ``Content-Type`` -- so the name
    heuristic is the wrong gate here, and it is exactly the gate that failed: the measured instance
    used ``X-Vendor-Thing``, which matches no substring rule.
    """
    if isinstance(value, EnvRef):
        return {"env": value.key}
    return "***" if _is_secret_header(name, value) else value


def redacted_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    """A JSON-safe, secret-scrubbed view of a connection's settings for the API ``/metadata`` endpoint:
    each EnvRef becomes ``{"env": key}`` (the value is never resolved — only the key is shown), a
    credential field rendered inline is replaced with ``"***"`` (an ``env()`` *default* is dropped for
    a credential field so a fallback secret can't leak), and a credential header inside a ``headers``
    table is redacted too."""
    out: dict[str, Any] = {}
    for name, value in settings.items():
        is_secret = _is_secret_setting(name)
        if isinstance(value, EnvRef):
            ref: dict[str, Any] = {"env": value.key}
            if value.default is not _UNSET and not is_secret:
                ref["default"] = value.default
            out[name] = ref
        elif is_secret:
            out[name] = "***"
        elif isinstance(value, str) and name.lower().endswith(_URL_SETTING_SUFFIXES):
            # BACKLOG #1207 -- a credential in URL userinfo, masked without destroying the view.
            out[name] = _mask_url_userinfo(value)
        elif name == "headers" and isinstance(value, dict):
            out[name] = {k: _redact_header_value(k, v) for k, v in value.items()}
        elif name == "odbc_params" and isinstance(value, dict):
            # BACKLOG #1206. This bag is documented as carrying "only static driver keywords", and the
            # redactor honoured that by not descending -- so a credential inside it was served verbatim
            # by /metadata behind MONITORING_READ and printed by graph --json, on the SAME object whose
            # top-level `password` masked correctly.
            #
            # It is not merely operator misuse, which is why this masks rather than warns. The typed
            # fields carry exactly ONE credential (`username`/`password`, key names configurable via
            # `odbc_user_key`/`odbc_password_key`), and `_reject_envref_odbc_params` refuses `env()`
            # here. So a connection needing a SECOND driver credential -- libpq `sslpassword` beside
            # `PWD` -- has no typed home and no env() form, and the inline literal is the only
            # expressible shape. A refusal that removes the SAFE expression while leaving the UNSAFE
            # one is not a mitigation.
            #
            # Keys only, by the same predicate the rest of this function uses: real static driver
            # keywords (`Encrypt`, `TrustServerCertificate`, `ApplicationIntent`) are not
            # credential-shaped, and the ones that are -- `PWD`, `Password`, `sslpassword` -- are
            # credentials. Values are NOT shape-tested here: a driver keyword's value is opaque and
            # masking on its content would hide ordinary configuration with nothing to say so.
            #
            # THIS IS A DISPLAY FIX, NOT A STORAGE FIX. The credential remains an inline literal in
            # the config file. Keeping it out of the file needs `env()` to work here, which needs
            # nested settings to be env-resolved -- filed as #1206's route-onward, deliberately not
            # folded in, because it changes the resolution path and what the refusal above means.
            out[name] = {k: ("***" if _is_secret_odbc_key(k) else v) for k, v in value.items()}
        else:
            out[name] = value
    return out


def display_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    """A JSON-safe view of settings for introspection (``messagefoundry graph --json`` and the IDE
    graph view): each EnvRef becomes ``{"env": key[, default]}``.

    Credentials are scrubbed exactly as the API ``/metadata`` view scrubs them. This output reaches a
    terminal, a CI log and the IDE, so it earns the *same* treatment, not a weaker one — it used to
    apply none at all, printing an inline credential verbatim and an ``env()`` *default* (a fallback
    secret) for every connection in the graph."""
    return redacted_settings(settings)


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
    # INBOUND message-RATE pacing (BACKLOG #1249). Unlike the caps above these default to OFF, and
    # that is ruled rather than accidental: a rate on a clinical interface is only safe at a number
    # taken from a real feed profile. The connector has read both keys since the pacer was built --
    # until now no factory parameter and no connections.toml key could populate them, so the setting
    # existed and could not be reached. Over budget the listener PAUSES READING so TCP back-pressures
    # the sender: nothing is dropped, refused, NAK'd or reordered, which the count-and-log invariant
    # requires (a discarding limiter was never an option here).
    max_messages_per_second: float | None = None,  # None/0 = no rate bound (the shipped default)
    message_burst: float
    | None = None,  # allowance over the sustained rate; None = one second's worth
    connect_timeout: float = 10.0,  # outbound: TCP connect timeout (seconds)
    timeout_seconds: float = 30.0,  # outbound: wait this long for the ACK
    no_ack: bool = False,  # OUTBOUND (MLLP-only): fire-and-forward — skip the ACK read, deliver on the TCP write (at-most-once-confirmation; ADR 0124). Incompatible with capture_response/reingress_to.
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
    verify_ack_control_id: bool = False,  # outbound: require the ACK's MSA-2 to echo the sent MSH-10 (BACKLOG #82)
    send_min_interval_seconds: float
    | None = None,  # outbound: min seconds between sends on this lane (rate pacing; BACKLOG #82)
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
    tls_crl_file: str
    | None = None,  # INBOUND: opt-in CRL for mTLS client certs (#1005) — CA bundle + CRL, PEM
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

    ``no_ack`` (**outbound only**, BACKLOG #117 / ADR 0124) is fire-and-forward: when ``True`` the
    connector writes + drains and confirms delivery **on the TCP write** — it reads **no** ACK and
    validates **no** MSA-1, so there is **no NAK-driven and no ACK-timeout-driven retry**
    (*at-most-once-confirmation*; a connect/drain failure is still charged + retried, so receivers must
    stay idempotent). ``False`` (the default) is **byte-identical** (read + validate one ACK). It
    composes with ``persistent=True`` (no handshake *and* no ACK wait) and is **incompatible** with
    ``capture_response``/``reingress_to`` (there is no ACK to capture) — both rejected at ``check``.

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
    and may present ``tls_cert_file`` for mTLS.

    ``verify_ack_control_id`` (**outbound only**, BACKLOG #82) tightens the *accept* decision: when
    ``True``, a **positive** ACK (MSA-1 AA/CA) is accepted only if its MSA-2 (message control id)
    equals the sent message's MSH-10 — a reply carrying a different control id is treated as a
    correlation failure (retryable ``DeliveryError`` → the pipeline retries per the at-least-once
    path). Both control ids are read separator-aware from the message (never hardcoded ``|^~\\&``).
    ``False`` (the default) leaves delivery **byte-identical** — no correlation is performed. If the
    outgoing message's own MSH-10 is absent/unreadable there is nothing to correlate, so the check is
    skipped and the message delivers as before. It does not alter a negative ACK's handling.

    ``send_min_interval_seconds`` (**outbound only**, BACKLOG #82) paces this lane's egress: the engine
    holds each ``send`` until at least this many seconds have elapsed since the previous send on the
    **same** outbound started, so a partner that cannot absorb bursts sees a bounded send rate. Pacing is
    **per-envelope** — one interval per ``send()`` call — so a batching outbound (ADR 0082) counts a whole
    ``BHS``…``BTS`` batch as ONE interval (it throttles the send RATE, not a per-message rate; a strict
    per-message cap is a future refinement). The delay is a pure **wait**, enforced at the pipeline's
    delivery seam: it never reorders (strict per-lane FIFO holds — the row is already claimed) and is
    cancellable by the connection's stop signal. Independent outbounds pace independently (a per-lane
    clock, not a shared bucket). ``None``/``0`` (the default) = **no pacing**, delivery byte-identical.
    A negative value is rejected at wiring. ``tls_key_password`` decrypts a passphrase-encrypted
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
            "max_messages_per_second": max_messages_per_second,
            "message_burst": message_burst,
            "connect_timeout": connect_timeout,
            "timeout_seconds": timeout_seconds,
            "no_ack": no_ack,
            "persistent": persistent,
            "idle_timeout_seconds": idle_timeout_seconds,
            "max_connection_age_seconds": max_connection_age_seconds,
            "encoding_characters": encoding_characters,
            "hl7_raw_separators": hl7_raw_separators,
            "capture_response": capture_response,
            "verify_ack_control_id": verify_ack_control_id,
            "send_min_interval_seconds": send_min_interval_seconds,
            "reingress_to": reingress_to,
            "tls": tls,
            "tls_cert_file": tls_cert_file,
            "tls_key_file": tls_key_file,
            "tls_key_password": tls_key_password,
            "tls_ca_file": tls_ca_file,
            "tls_crl_file": tls_crl_file,
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
    framing: Literal["stx_etx", "vt_fs", "mllp"] | None = "stx_etx",
    start: int | None = None,  # explicit start delimiter byte (use instead of `framing`)
    end: int | None = None,  # explicit end delimiter byte
    trailer: int | None = None,  # explicit optional trailer byte
    encoding: str = "utf-8",
    # Inbound DoS guards (defaults mirror MLLP; pass None/0 to disable):
    max_connections: int | None = 256,  # cap concurrent clients (connection-flood guard)
    receive_timeout: float | None = 60.0,  # close a client idle this many seconds (slowloris)
    max_frame_bytes: int | None = 16 * 1024 * 1024,  # cap one frame's bytes (OOM guard); both dirs
    # INBOUND message-RATE pacing (BACKLOG #1114) — the MLLP pacer, ported. Unlike the caps above
    # these default to OFF, and that is ruled rather than accidental: a rate on a clinical interface
    # is only safe at a number taken from a real feed profile. Over budget the listener PAUSES
    # READING so TCP back-pressures the sender: nothing is dropped, refused or reordered, which the
    # count-and-log invariant requires. One bucket per connection, as on MLLP.
    max_messages_per_second: float | None = None,  # None/0 = no rate bound (the shipped default)
    message_burst: float
    | None = None,  # allowance over the sustained rate; None = one second's worth
    connect_timeout: float = 10.0,  # outbound: TCP connect timeout (seconds)
    timeout_seconds: float = 30.0,  # outbound: send/await-reply timeout
    # Persistent outbound connection (ADR 0067 §9 / BACKLOG #97) — outbound-only; None/0 on a freshness knob disables it:
    persistent: bool = False,  # outbound: reuse ONE connection across deliveries (opt-in; default connect-per-send)
    idle_timeout_seconds: float
    | None = 60.0,  # outbound: don't reuse a connection idle longer than this
    max_connection_age_seconds: float
    | None = None,  # outbound: recycle by age (LB/firewall hygiene)
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
    acks are a deferred follow-up). Delivery is at-least-once → the receiver **must be idempotent**.

    **Inbound message-rate pacing (BACKLOG #1114).** ``max_messages_per_second`` bounds how fast one
    accepted connection may feed messages in; ``message_burst`` is how large a burst passes before the
    sustained rate applies (default: one second's worth). Over budget the listener **pauses reading**
    before its next read, so TCP back-pressures the sender — **no message is dropped, refused or
    reordered**. Both ship **off**, which is a deliberate exception to this connector's usual
    secure-default rule: a guessed rate on a clinical interface throttles real traffic, so the number
    has to come from your own feed profile.

    ``persistent=true`` (ADR 0067 §9 / BACKLOG #97) reuses one lazily-established connection across
    deliveries (default ``false`` = connect-per-send, byte-identical); a stale socket is redialed once
    **before any byte is written** (uncharged), and any post-write failure is charged + retried.
    ``idle_timeout_seconds``/``max_connection_age_seconds`` bound reuse (``None``/``0`` = off)."""
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
            "max_messages_per_second": max_messages_per_second,
            "message_burst": message_burst,
            "connect_timeout": connect_timeout,
            "timeout_seconds": timeout_seconds,
            "persistent": persistent,
            "idle_timeout_seconds": idle_timeout_seconds,
            "max_connection_age_seconds": max_connection_age_seconds,
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
    # INBOUND interchange-RATE pacing (BACKLOG #1114) — the MLLP pacer, ported; one token per ISA/IEA
    # interchange, which is this connector's frame. Defaults to OFF for the ruled reason in MLLP().
    max_messages_per_second: float | None = None,  # None/0 = no rate bound (the shipped default)
    message_burst: float
    | None = None,  # allowance over the sustained rate; None = one second's worth
    connect_timeout: float = 10.0,  # outbound: TCP connect timeout (seconds)
    timeout_seconds: float = 30.0,  # outbound: send/await-reply timeout
    # Persistent outbound connection (ADR 0067 §9 / BACKLOG #97) — outbound-only; None/0 on a freshness knob disables it:
    persistent: bool = False,  # outbound: reuse ONE connection across deliveries (opt-in; default connect-per-send)
    idle_timeout_seconds: float
    | None = 60.0,  # outbound: don't reuse a connection idle longer than this
    max_connection_age_seconds: float
    | None = None,  # outbound: recycle by age (LB/firewall hygiene)
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
    non-idempotent 270 yields a fresh 271 captured at the next ``response_seq``).

    **Inbound interchange-rate pacing (BACKLOG #1114).** ``max_messages_per_second`` bounds how fast
    one accepted connection may feed **interchanges** in (one token per ``ISA…IEA``);
    ``message_burst`` is how large a burst passes before the sustained rate applies (default: one
    second's worth). Over budget the listener **pauses reading** before its next read, so TCP
    back-pressures the sender — **no interchange is dropped, refused or reordered**. Both ship
    **off**: a guessed rate throttles real traffic, so the number has to come from your feed profile.

    ``persistent=true`` (ADR 0067 §9 / BACKLOG #97) reuses one lazily-established connection across
    deliveries (default ``false`` = connect-per-send, byte-identical); a stale socket is redialed once
    **before any byte is written** (uncharged). A returned TA1/business interchange is a complete
    transaction on a healthy transport, so the connection **stays cached** across a captured reply (and a
    TA1*R reject); ``idle_timeout_seconds``/``max_connection_age_seconds`` bound reuse (``None``/``0`` = off)."""
    return ConnectionSpec(
        ConnectorType.X12,
        {
            "host": host,
            "port": port,
            "encoding": encoding,
            "max_connections": max_connections,
            "receive_timeout": receive_timeout,
            "max_interchange_bytes": max_interchange_bytes,
            "max_messages_per_second": max_messages_per_second,
            "message_burst": message_burst,
            "connect_timeout": connect_timeout,
            "timeout_seconds": timeout_seconds,
            "persistent": persistent,
            "idle_timeout_seconds": idle_timeout_seconds,
            "max_connection_age_seconds": max_connection_age_seconds,
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
    # Message-RATE pacing (BACKLOG #1114) — the MLLP pacer, ported. Defaults to OFF for the ruled
    # reason in MLLP(). Scoped to the LISTENER, not the connection: this connector answers one
    # request per connection, so a per-connection bucket would pace nothing at all.
    max_messages_per_second: float | None = None,  # None/0 = no rate bound (the shipped default)
    message_burst: float
    | None = None,  # allowance over the sustained rate; None = one second's worth
    # --- TLS (WP-13b, ADR 0002 §0 / ADR 0023 D4) — per-connection HTTPS ---
    tls: bool = False,  # turn TLS on (present a server cert; off-loopback without it is refused at start)
    tls_cert_file: str | None = None,  # SERVER cert (required when tls)
    tls_key_file: str | None = None,  # private key for tls_cert_file
    tls_key_password: str
    | EnvRef
    | None = None,  # passphrase for an ENCRYPTED tls_key_file (put the secret in env())
    tls_ca_file: str | None = None,  # trust anchor — opt-in mTLS (require + verify a client cert)
    tls_crl_file: str
    | None = None,  # opt-in CRL for mTLS client certs (#1005) — CA bundle + CRL, PEM
    # --- Intake authentication (ADR 0154 D6) — a PEER control on this connector, not admin RBAC ---
    intake_auth: Literal[
        "none", "api_key", "bearer", "mtls_subject"
    ] = "none",  # credential a peer must present to POST
    intake_api_key: EnvRef
    | None = None,  # the api_key/bearer credential (env() only — never inline)
    intake_api_key_next: EnvRef
    | None = None,  # rotation: accepted alongside intake_api_key, so a partner key rotates without an outage
    intake_api_key_header: str = "x-api-key",  # header carrying the api_key credential (a header NAME, not a secret)
    intake_client_subjects: Sequence[str]
    | None = None,  # mtls_subject allow-list, QUALIFIED: "CN:<v>" / "SAN:DNS:<v>"
    intake_auth_health: Literal[
        "require", "allow"
    ] = "require",  # whether GET/HEAD probes need the credential too
    intake_auth_rate_limit: int
    | None = 10,  # FAILED intake-auth attempts per minute per peer (0/None disables)
    intake_auth_rate_limit_global: int
    | None = 60,  # FAILED intake-auth attempts per minute across all peers
    # --- Synchronous captured-downstream reply (ADR 0154 D4) — reply_from's presence is the switch ---
    reply_from: str
    | None = None,  # names the outbound whose CAPTURED reply becomes this request's HTTP body
    reply_timeout: float = 30.0,  # seconds the HTTP turn may block waiting for that reply
    reply_on_timeout: Literal["504", "202"] = "504",  # what to answer when the wait expires
    reply_content_type: str = "passthrough",  # "passthrough" (echo the captured one) or a literal MIME
    reply_on_empty: Literal[
        "204", "200"
    ] = "204",  # answer for a captured but deliberately empty reply
    reply_write_timeout: float = 30.0,  # seconds to drain the (partner-sized) response to the caller
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
    ingress row). This is the behaviour of an inbound **without** ``reply_from``; naming it switches
    to the synchronous captured-downstream reply described below.

    **DoS guards** are HTTP twins of MLLP's: ``max_connections`` (flood), ``receive_timeout`` (slow-loris
    — bounds the whole-request read), ``max_body_bytes`` (the frame-cap twin — refused on the declared
    ``Content-Length`` before a byte is buffered), and ``max_header_bytes`` (header flood).

    **Message-rate pacing (BACKLOG #1114).** ``max_messages_per_second`` bounds how fast this listener
    takes messages in; ``message_burst`` is how large a burst passes before the sustained rate applies
    (default: one second's worth). Over budget the connector **waits before reading the request**, so
    the partner is back-pressured and its request is then served in full — nothing is dropped, refused
    or answered differently, and the wait sits outside ``receive_timeout`` so a paced partner is never
    handed a ``408`` for a delay the engine imposed. The bucket is **listener-wide, not
    per-connection**: this connector answers one request per connection, so a per-connection bucket
    would pace nothing. A ``GET``/``HEAD`` health probe waits behind an outstanding debt but charges
    nothing, and neither does a refused request — only a committed message spends the budget. Both
    keys ship **off**, for the same reason as MLLP's: the number has to come from your feed profile.

    **TLS (WP-13b).** ``tls=True`` presents ``tls_cert_file``/``tls_key_file`` as the HTTPS server
    identity (``tls_ca_file`` adds opt-in mTLS); ``tls_key_password`` decrypts an encrypted key (supply via
    ``env()``). The runner's exposed-gate refuses a **non-loopback** HTTP listener **without** TLS at start
    (cleartext PHI can't cross an off-loopback socket by accident) — set ``tls=True`` or pass
    ``serve --allow-insecure-bind`` on a trusted, firewalled segment.

    **Intake authentication (ADR 0154 D6).** ``intake_auth`` requires a peer to prove who it is before it
    may submit a message. It is a sibling of ``source_ip_allowlist`` — a **peer control on this
    connector** — not admin RBAC: it mints no identity, opens no session, and authorises *submitting*,
    never *reading*. ``api_key`` reads the credential from ``intake_api_key_header``, ``bearer`` from
    ``Authorization: Bearer``, and ``mtls_subject`` maps the verified client certificate's subject/SAN
    against ``intake_client_subjects``. Set ``intake_api_key_next`` to rotate a partner key without an
    outage: both are accepted while the partner cuts over.

    **TLS is confidentiality; intake auth is authentication.** Enabling one is never an argument for
    relaxing the other. In particular a bare ``tls`` + ``tls_ca_file`` means "any certificate this CA ever
    signed", with no subject binding at all — which is why ``mtls_subject`` additionally requires
    ``intake_client_subjects``.

    Health probes are **inside** the gate by default; ``intake_auth_health="allow"`` exempts ``GET``/
    ``HEAD`` for a load-balancer check, at the cost of an unauthenticated "is MessageFoundry up, and
    where" oracle on a PHI intake socket.

    **Synchronous captured-downstream reply (ADR 0154 D4).** Naming ``reply_from`` turns this inbound
    from fire-and-forget into a **proxy**: the HTTP turn blocks until the named outbound's reply has
    been captured and **committed**, then returns that reply as the response body. One knob, not two —
    a separate ``sync_reply: bool`` would admit a half-configured state (mode on, no target) that
    could only fail at runtime.

    The returned bytes always come from a **committed** ``response`` row, never from an in-flight
    delivery, so a reply is returned only once it is durable and replayable. ``reply_timeout`` bounds
    the block and ``reply_write_timeout`` bounds the drain of the (partner-sized) response back to the
    caller, so a sync-reply turn has three independent clocks with ``receive_timeout`` still bounding
    the read. A timeout answers ``reply_on_timeout`` and **leaves the message flowing** — the HTTP
    status is never a second disposition channel, and the finalizer remains the only authority on
    that.

    ``reply_content_type="passthrough"`` echoes the partner's own captured ``content-type``; a literal
    MIME type pins it instead. ``reply_on_empty`` chooses how a deliberately empty partner reply is
    answered — ``204`` is correct, ``200`` is the escape hatch for toolchains that mishandle a
    bodyless response.

    **The reply body is PHI**: the partner's response, decrypted out of the store. It is returned to
    the caller and *nowhere else* — never logged, and never placed in an exception, a
    ``connection_event.reason`` or a ``message_events.detail``.

    An inbound **without** ``reply_from`` keeps the shipped ``202``-on-receipt behaviour byte for
    byte; every knob above is inert without it, and setting one alone is refused rather than silently
    ignored."""
    settings: dict[str, Any] = {
        "port": port,
        "encoding": encoding,
        "max_connections": max_connections,
        "receive_timeout": receive_timeout,
        "max_body_bytes": max_body_bytes,
        "max_header_bytes": max_header_bytes,
        "max_messages_per_second": max_messages_per_second,
        "message_burst": message_burst,
        "tls": tls,
        "tls_cert_file": tls_cert_file,
        "tls_key_file": tls_key_file,
        "tls_key_password": tls_key_password,
        "tls_ca_file": tls_ca_file,
        "tls_crl_file": tls_crl_file,
        "intake_auth": intake_auth,
        "intake_api_key": intake_api_key,
        "intake_api_key_next": intake_api_key_next,
        "intake_api_key_header": intake_api_key_header,
        "intake_client_subjects": list(intake_client_subjects) if intake_client_subjects else None,
        "intake_auth_health": intake_auth_health,
        "intake_auth_rate_limit": intake_auth_rate_limit,
        "intake_auth_rate_limit_global": intake_auth_rate_limit_global,
        "reply_from": reply_from,
        "reply_timeout": reply_timeout,
        "reply_on_timeout": reply_on_timeout,
        "reply_content_type": reply_content_type,
        "reply_on_empty": reply_on_empty,
        "reply_write_timeout": reply_write_timeout,
    }
    _validate_intake_auth(settings)
    _validate_sync_reply(settings)
    return ConnectionSpec(ConnectorType.HTTP, settings)


#: The synchronous-reply knobs. Every one is inert without ``reply_from``, so setting any of them
#: alone is a configuration that silently does nothing — refused, for the same reason a credential
#: configured with ``intake_auth="none"`` is.
_SYNC_REPLY_KNOBS = (
    "reply_timeout",
    "reply_on_timeout",
    "reply_content_type",
    "reply_on_empty",
    "reply_write_timeout",
)


def _sync_reply_defaults() -> dict[str, Any]:
    """The knobs' default values, read off :func:`Http`'s own signature.

    Derived rather than duplicated on purpose: a hand-copied table would go stale the first time a
    default changed, and the failure would be silent — the "configured but never read" refusal below
    would simply stop firing for that knob, which is the opposite of what a guard should do when it
    drifts. Cheap: this runs once per ``Http()`` call, and only on the path that is already about to
    raise or return."""
    params = inspect.signature(Http).parameters
    return {name: params[name].default for name in _SYNC_REPLY_KNOBS}


def apply_sync_reply_capture_implication(registry: Registry) -> None:
    """Make ``reply_from`` imply capturing the partner's ``content-type`` (ADR 0154 D4, owner ruling).

    **Resolves a contradiction in the ADR itself.** ``reply_content_type`` defaults to
    ``"passthrough"``, and D4 then requires ``"content-type"`` to be in the named outbound's
    ``capture_response_headers`` — which defaults to ``None`` on all three capable factories, and
    ``normalize_header_allowlist(None)`` is the empty set. So the ADR's own headline shape,
    ``Http(reply_from="X")`` + ``Rest(capture_response=True)``, would raise at ``check`` until the
    operator *also* wrote ``capture_response_headers=["content-type"]``. Asking for a reply to be
    echoed back verbatim **is** asking for its content type; requiring both is a papercut with no
    decision behind it.

    Applied as an explicit, **idempotent** normalisation of the resolved graph rather than a hidden
    runtime fallback, so the implied header appears in ``/metadata`` and ``graph --json`` like any
    other captured header. An operator reading the outbound's configuration sees what is actually
    captured — which is the point: an implication nobody can observe is indistinguishable from a bug.

    Only touches outbounds that are the ``reply_from`` target of an inbound using ``passthrough``,
    and only those whose factory has the setting at all (it exists on 3 of the 8 outbound factories).
    A capturing outbound with no allow-list is left alone and refused explicitly by
    :func:`~messagefoundry.pipeline.wiring_runner.check_http_sync_reply`.
    """
    targets: set[str] = set()
    for ic in registry.inbound.values():
        if ic.spec.type is not ConnectorType.HTTP:
            continue
        reply_from = ic.spec.settings.get("reply_from")
        if reply_from and ic.spec.settings.get("reply_content_type") == "passthrough":
            targets.add(str(reply_from))

    for name in sorted(targets):
        oc = registry.outbound.get(name)
        if oc is None or "capture_response_headers" not in oc.spec.settings:
            continue  # unknown target, or a factory with no allow-list — both refused elsewhere
        current = oc.spec.settings.get("capture_response_headers") or []
        if any(str(h).strip().lower() == "content-type" for h in current):
            continue  # already asked for — idempotent
        oc.spec.settings["capture_response_headers"] = [*current, "content-type"]


def _validate_sync_reply(settings: Mapping[str, Any]) -> None:
    """Refuse a synchronous-reply configuration that cannot work, at **factory** time (ADR 0154 D4).

    Factory-local checks only — everything decidable from this one ``Http()`` call, with no store, no
    posture and no registry, so it fires identically in ``messagefoundry check``, in dry-run, and
    through the ``connections.toml`` desugar.

    The **cross-registry** half lives in ``build_check_registry``: that ``reply_from`` names a
    deployed outbound, that the outbound captures responses, the ``passthrough`` content-type
    requirement, and the effective ``ordering``/``max_attempts`` refusals. None of those are knowable
    from here, and pretending otherwise would mean validating against a registry this function
    cannot see.
    """
    reply_from = settings["reply_from"]
    if reply_from is not None and not str(reply_from).strip():
        raise WiringError("Http reply_from must name an outbound connection, not an empty string")

    if reply_from is None:
        defaults = _sync_reply_defaults()
        configured = [name for name in _SYNC_REPLY_KNOBS if settings[name] != defaults[name]]
        if configured:
            raise WiringError(
                f"Http sets {', '.join(configured)} but no reply_from, so the synchronous-reply path "
                "is off and none of them is ever read — name the outbound whose captured reply should "
                "become the HTTP body, or remove the setting"
            )
        return

    for name in ("reply_timeout", "reply_write_timeout"):
        value = settings[name]
        if not isinstance(value, int | float) or value <= 0:
            raise WiringError(
                f"Http {name} must be a positive number of seconds — got {value!r}. It bounds a "
                "blocked HTTP turn; an unbounded or zero budget is not a timeout"
            )

    if settings["reply_on_timeout"] not in ("504", "202"):
        raise WiringError(
            f"Http reply_on_timeout must be '504' or '202' — got {settings['reply_on_timeout']!r}"
        )
    if settings["reply_on_empty"] not in ("204", "200"):
        raise WiringError(
            f"Http reply_on_empty must be '204' or '200' — got {settings['reply_on_empty']!r}"
        )

    content_type = settings["reply_content_type"]
    if not content_type or not str(content_type).strip():
        raise WiringError(
            "Http reply_content_type must be 'passthrough' or a literal MIME type, not empty"
        )
    if content_type != "passthrough" and "/" not in str(content_type):
        raise WiringError(
            f"Http reply_content_type must be 'passthrough' or a MIME type — got {content_type!r}, "
            "which is neither (a MIME type contains a '/', e.g. 'application/json')"
        )


#: The intake-auth modes that carry a shared-secret credential (as opposed to a client certificate).
_INTAKE_KEY_MODES = ("api_key", "bearer")
#: Qualified-namespace prefixes an ``intake_client_subjects`` entry may take, mirroring what
#: :func:`~messagefoundry.credential.cert_name_candidates` actually yields.
_INTAKE_SUBJECT_PREFIXES = ("CN:", "SAN:")


def _validate_intake_auth(settings: Mapping[str, Any]) -> None:
    """Refuse an intake-auth configuration that cannot work, at **factory** time (ADR 0154 D4).

    Runs with no store and no posture, so it fires identically in ``messagefoundry check``, in dry-run,
    and through the ``connections.toml`` desugar (which calls this same factory). Every rule here
    catches a configuration whose failure mode is otherwise silent or total:

    * a mode that needs a credential, with none configured — the listener would refuse 100 % of traffic;
    * ``mtls_subject`` without ``tls`` + ``tls_ca_file`` — the ``SSLContext`` never requests a client
      certificate, so ``getpeercert()`` comes back empty and deny-by-default ``403``s everything, with
      no start-time error to explain it;
    * ``mtls_subject`` with no subjects — "any certificate this CA ever signed" is not a peer control;
    * an unqualified subject entry — ``cert_name_candidates`` yields ``"CN:<v>"`` / ``"SAN:DNS:<v>"``, so
      a bare ``partner.example`` matches nothing and 403s every request from the very partner it names;
    * a credential configured while ``intake_auth="none"`` — nothing would ever check it, and an
      operator reading that config would reasonably believe the listener was protected.

    The secret itself must be an ``env()`` reference with no default and no cast, mirroring
    ``File(credential_password=...)`` (ADR 0132): a fallback credential is a silent credential.
    """
    mode = settings["intake_auth"]
    if mode not in ("none", *_INTAKE_KEY_MODES, "mtls_subject"):
        raise WiringError(
            f"Http intake_auth must be one of none/api_key/bearer/mtls_subject — got {mode!r}"
        )
    if settings["intake_auth_health"] not in ("require", "allow"):
        raise WiringError(
            "Http intake_auth_health must be 'require' or 'allow' — got "
            f"{settings['intake_auth_health']!r}"
        )

    for name in ("intake_api_key", "intake_api_key_next"):
        value = settings[name]
        if value is None:
            continue
        if not isinstance(value, EnvRef):
            raise WiringError(
                f"Http {name} must be an env() reference — an intake credential is a secret and is "
                f"never inline (CLAUDE.md §5); e.g. {name}=env('acme_intake_key')"
            )
        if value.default is not _UNSET:
            raise WiringError(
                f"Http {name} env() must not carry a default= — a fallback intake credential would "
                "be a silent credential"
            )
        if value.cast is not None:
            raise WiringError(f"Http {name} env() must not carry a cast= (a credential is text)")

    if mode == "none":
        configured = [
            n
            for n in ("intake_api_key", "intake_api_key_next", "intake_client_subjects")
            if settings[n]
        ]
        if configured:
            raise WiringError(
                f"Http sets {', '.join(configured)} but intake_auth='none', so no credential is ever "
                "checked — set intake_auth, or remove the setting; a control that is configured but "
                "never consulted reads as protection that does not exist"
            )
        return

    if mode in _INTAKE_KEY_MODES:
        if settings["intake_api_key"] is None:
            raise WiringError(
                f"Http intake_auth={mode!r} needs intake_api_key — supply it via env() "
                "(intake_api_key=env('acme_intake_key')); an unset value is not an env-resolution "
                "failure, so nothing else would catch it"
            )
        if not settings["intake_api_key_header"]:
            raise WiringError("Http intake_api_key_header must be a non-empty header name")
        return

    # mtls_subject
    if not settings["tls"] or not settings["tls_ca_file"]:
        raise WiringError(
            "Http intake_auth='mtls_subject' needs tls=True and tls_ca_file — without a CA the "
            "SSLContext never requests a client certificate, so getpeercert() is empty and every "
            "request is refused 403 with no start-time error to explain it"
        )
    subjects = settings["intake_client_subjects"]
    if not subjects:
        raise WiringError(
            "Http intake_auth='mtls_subject' needs a non-empty intake_client_subjects — tls_ca_file "
            "alone means 'any certificate this CA ever signed', which binds no subject and "
            "authenticates no one in particular"
        )
    unqualified = [s for s in subjects if not str(s).startswith(_INTAKE_SUBJECT_PREFIXES)]
    if unqualified:
        raise WiringError(
            f"Http intake_client_subjects entries must be qualified — {unqualified} lack a "
            "'CN:' / 'SAN:<type>:' prefix. A certificate's names are matched as 'CN:<value>' and "
            "'SAN:DNS:<value>' so a spoofed commonName cannot collide with a pinned SAN; a bare name "
            "matches nothing and would 403 every request from the partner it names"
        )


def File(
    *,
    directory: str | EnvRef,
    filename: str | EnvRef = "{MSH-10}.hl7",
    pattern: str = "*.hl7",
    poll_seconds: float = 1.0,
    encoding: str = "utf-8",
    min_age_seconds: float = 0.0,  # inbound: skip files modified within this window (partial writes)
    after_read: Literal[
        "move", "delete", "leave"
    ] = "move",  # inbound: "move" (to processed_subdir) | "delete" | "leave" (process in place, #142)
    sort: str = "name",  # inbound: process order — "name" | "mtime"
    recursive: bool = False,  # inbound: also scan subdirectories
    max_file_bytes: int | None = 16 * 1024 * 1024,  # inbound: skip files over this (OOM guard)
    validate_directory: bool = False,  # both directions (#114): fail-fast at start on a missing/unusable dir, and never create it; default defers to run time
    overwrite: bool = False,  # outbound: overwrite vs. uniquify a name collision
    processed_subdir: str = ".processed",
    error_subdir: str = ".error",
    # Per-endpoint alternate Windows/network-share credential (UNC/SMB — ADR 0132, #111). Unset (the
    # default) => the engine uses its own service-account identity, byte-identical. When set, the
    # File connector authenticates to the share under this identity (win32-only; a non-Windows host
    # raises a clear error at build). The password is a SECRET — env() ONLY (enforced below).
    credential_username: str | EnvRef | None = None,
    credential_domain: str | EnvRef | None = None,  # optional; omit for DOMAIN\\user or user@domain
    credential_password: EnvRef | None = None,  # secret — env() only, never inline
    compress: Literal["gzip"]
    | None = None,  # outbound: "gzip" gzips the drop and appends `.gz` (ADR 0123)
    decompress: Literal["gzip"]
    | None = None,  # inbound: "gzip" gunzips each drop before the sniff/scan/split
    max_decompressed_bytes: int | None = 64 * 1024 * 1024,  # inbound: decompression-bomb ceiling
) -> ConnectionSpec:
    """A File endpoint. Inbound polls ``directory`` for ``pattern``; outbound writes ``filename``
    (atomically). ``encoding`` is the file charset (outbound). ``max_file_bytes`` mirrors
    transports.file.DEFAULT_MAX_FILE_BYTES (pass None/0 to disable).

    ``after_read`` (inbound) chooses the source-file disposition: ``move`` (→ ``processed_subdir``,
    the default), ``delete``, or ``leave`` — **process in place** for a read-only share / a directory
    another system owns (#142; a HASHED per-file ledger dedups so a left file is ingested once).
    ``validate_directory`` (#114, **both directions**) makes a missing/unusable directory **fail
    startup** (the connection is reported ``failed``) instead of the default deferral to run time. On an
    **inbound** a ``leave`` source validates read-only (a read-only share passes) while ``move``/
    ``delete`` also need write. On an **outbound** the target must already exist and accept a write, and
    the directory is then **never created** — not at start, not on write, and not by the on-demand
    ``POST /connections/{name}/test`` probe. Leaving it off keeps the default: the outbound target is
    created on first write (now logged as a WARNING when it actually had to be created).

    ``credential_username`` / ``credential_domain`` / ``credential_password`` (ADR 0132, #111) give the
    endpoint an **alternate Windows identity** for a UNC/SMB share, distinct from the engine service
    account (both inbound poll and outbound write). ``credential_username`` may be ``user`` (+ separate
    ``credential_domain``), ``DOMAIN\\user``, or a ``user@domain`` UPN. ``credential_password`` is a
    secret and **must be an** :func:`env` **reference** — an inline literal is refused. Win32-only: on a
    non-Windows host the connector refuses to build (a clear error, never a silent no-op).

    **Compression** (ADR 0123, single-stream gzip only). Outbound ``compress="gzip"`` gzips the encoded
    body and appends ``.gz`` to the rendered name. Inbound ``decompress="gzip"`` gunzips each dropped
    file **before** the HL7 sniff, the pre-ingest AV scan, and the batch split; ``max_decompressed_bytes``
    (default 64 MiB, None/0 disables) caps the *decompressed* size — a decompression-bomb guard the
    compressed-only ``max_file_bytes`` cannot provide. A corrupt/oversized archive is moved to
    ``.error`` (never accept-and-dropped). Multi-entry zip / raw deflate stay Handler-composed via
    ``messagefoundry.parsing.compression``."""
    settings: dict[str, Any] = {
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
        "validate_directory": validate_directory,
        "overwrite": overwrite,
        "processed_subdir": processed_subdir,
        "error_subdir": error_subdir,
        "compress": compress,
        "decompress": decompress,
        "max_decompressed_bytes": max_decompressed_bytes,
    }
    if credential_username is not None or credential_password is not None:
        # A share credential is being configured — the password is a secret and must never be inline
        # (CLAUDE.md §5). Mirror the SOAP body_secrets rule (_hoist_body_secrets): reject a literal /
        # a defaulted / cast env(), so a fallback secret can't slip in and the value renders as a bare
        # {"env": key} in every settings view (belt-and-suspenders atop _SECRET_SETTING_KEYS).
        if credential_username is None:
            raise WiringError(
                "File credential_password is set without credential_username — supply the share "
                "identity (credential_username) too"
            )
        if credential_password is None:
            raise WiringError(
                "File credential_username is set without credential_password — a Windows/UNC share "
                "credential needs a password; supply it via env() (credential_password=env('...'))"
            )
        if not isinstance(credential_password, EnvRef):
            raise WiringError(
                "File credential_password must be an env() reference — a share password is a secret "
                "and is never inline (CLAUDE.md §5); e.g. credential_password=env('acme_share_pw')"
            )
        if credential_password.default is not _UNSET:
            raise WiringError(
                "File credential_password env() must not carry a default= — a fallback share password "
                "would be a silent secret"
            )
        if credential_password.cast is not None:
            raise WiringError(
                "File credential_password env() must not carry a cast= (a password is text)"
            )
        settings["credential_username"] = credential_username
        settings["credential_password"] = credential_password
        if credential_domain is not None:
            settings["credential_domain"] = credential_domain
    return ConnectionSpec(ConnectorType.FILE, settings)


def Timer(
    *,
    body: str,
    interval_seconds: float | None = None,
    run_once: bool = False,
    encoding: str = "utf-8",
    cron_expression: str | None = None,
    timezone: str | None = None,
) -> ConnectionSpec:
    """A Timer **source** (inbound): emit ``body`` on a schedule (ADR 0011).

    Set ``interval_seconds`` to fire every N seconds (heartbeat starts at t=0), ``run_once=True`` to fire
    a single time, or ``cron_expression`` for a calendar schedule (ADR 0011 amendment, BACKLOG #160) — the
    three are mutually exclusive. ``body`` is emitted verbatim — declare its format with
    ``inbound(..., content_type=...)``: the default ``hl7v2`` runs the HL7 peek/validate/ACK path, while
    ``text``/``json`` route a :class:`RawMessage` (ADR 0004). In a cluster the schedule is leader-gated,
    so exactly one node fires it (single-node fires as normal).

    **Cron** is a standard 5-field expression (``minute hour day-of-month month day-of-week``) with
    ``*``, lists, ranges, and steps; day-of-week is ``0-6`` (Sunday = 0, or 7). Unlike the interval
    heartbeat, cron does **not** fire at ``t=0`` — the first fire is the next scheduled minute. Optional
    ``timezone`` is an IANA name (e.g. ``"America/New_York"``) the schedule matches against (DST-aware);
    omitted, it matches the **system-local** wall clock. E.g. ``cron_expression="0 8 * * 1-5"`` fires at
    08:00 on weekdays."""
    return ConnectionSpec(
        ConnectorType.TIMER,
        {
            "body": body,
            "interval_seconds": interval_seconds,
            "run_once": run_once,
            "encoding": encoding,
            "cron_expression": cron_expression,
            "timezone": timezone,
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
    and re-routes deeper (e.g. ``PT_<site>_ADT_2``, where ``<site>`` is the estate's site code) without
    an external hop.

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
    capture_response_headers: list[str]
    | None = None,  # #154: allow-list of response header names to capture (e.g. ["Location", "ETag"])
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    dynamic_headers: bool = False,  # #68: apply a Handler's per-message http.header.* SetMeta as headers
    # --- ADR 0126: outbound forward/egress web proxy (#112/#127/#128) ---
    proxy: str
    | None = None,  # #112: None = inherit [egress].proxy_url / off; "default" = system default web proxy; or an http(s):// address
    proxy_user: str | EnvRef | None = None,  # #127: forward-proxy auth username (use env())
    proxy_password: str
    | EnvRef
    | None = None,  # #127: forward-proxy auth password — secret, use env()
    proxy_auth_type: Literal["basic", "digest", "ntlm", "windows"]
    | None = None,  # #127: "basic" (default) | "digest" (http dest only); ntlm/windows deferred
    proxy_no_proxy: list[str]
    | None = None,  # #128: NO_PROXY-style bypass host list (intranet direct)
) -> ConnectionSpec:
    """An HTTP(S) endpoint (**outbound only** today — there is no REST source yet, ADR 0003). The
    Handler produces the request body; this delivers it to ``url`` via ``method`` with ``content_type``
    + ``headers`` and optional bearer/basic auth. A 2xx is delivered; 5xx/408/429/connection errors
    retry; other 4xx dead-letter (a permanent rejection). Redirects are refused and the egress host is
    gated by ``[egress].allowed_http``. Put secrets in ``env()`` (``bearer_token``/``basic_*``), never
    in ``headers``. The receiving endpoint **must be idempotent** (delivery is at-least-once).

    ``proxy`` routes egress through a corporate **forward proxy** (ADR 0126): ``"default"`` uses the OS
    default web proxy, an ``http(s)://`` address is explicit, unset inherits ``[egress].proxy_url``.
    ``proxy_user``/``proxy_password`` (secret → ``env()``) authenticate to it (``proxy_auth_type``
    Basic/Digest); ``proxy_no_proxy`` lists intranet hosts to reach directly."""
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
            "capture_response_headers": capture_response_headers,
            "reingress_to": reingress_to,
            "dynamic_headers": dynamic_headers,
            "proxy_url": proxy,
            "proxy_user": proxy_user,
            "proxy_password": proxy_password,
            "proxy_auth_type": proxy_auth_type,
            "proxy_no_proxy": proxy_no_proxy,
        },
    )


def FHIR(
    *,
    url: str | EnvRef,  # the FHIR service BASE url, e.g. https://host/fhir (may be env())
    fhir_version: Literal[
        "R4B", "R5", "STU3"
    ] = "R4B",  # "R4B" (default) | "R5" | "STU3" — explicit, no autodetect
    format: Literal["json"] = "json",  # "json" (MVP); "xml" is deferred (ADR 0022 Options #5)
    interaction: Literal[
        "create", "update", "transaction", "batch"
    ] = "create",  # "create" (POST) | "update" (PUT) | "transaction" | "batch" (Bundle POST)
    conditional: Literal["if-none-exist", "conditional-update", "if-match"]
    | None = None,  # None | "if-none-exist" | "conditional-update" | "if-match"
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
    capture_response_headers: list[str]
    | None = None,  # #154: allow-list of response header names to capture (Location/ETag of a create)
    reingress_to: str
    | None = None,  # route the captured reply into this Loopback inbound (implies capture; ADR 0013)
    dynamic_headers: bool = False,  # #68: apply a Handler's per-message http.header.* SetMeta as headers
    # --- ADR 0126: outbound forward/egress web proxy (#112/#127/#128) ---
    proxy: str
    | None = None,  # #112: None = inherit [egress].proxy_url / off; "default" = system default web proxy; or an http(s):// address
    proxy_user: str | EnvRef | None = None,  # #127: forward-proxy auth username (use env())
    proxy_password: str
    | EnvRef
    | None = None,  # #127: forward-proxy auth password — secret, use env()
    proxy_auth_type: Literal["basic", "digest", "ntlm", "windows"]
    | None = None,  # #127: "basic" (default) | "digest" (http dest only); ntlm/windows deferred
    proxy_no_proxy: list[str]
    | None = None,  # #128: NO_PROXY-style bypass host list (intranet direct)
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
            "capture_response_headers": capture_response_headers,
            "reingress_to": reingress_to,
            "dynamic_headers": dynamic_headers,
            "proxy_url": proxy,
            "proxy_user": proxy_user,
            "proxy_password": proxy_password,
            "proxy_auth_type": proxy_auth_type,
            "proxy_no_proxy": proxy_no_proxy,
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
    tls_verify: bool = True,  # verify the server cert (#323); False (dev only) needs the escape
    tls_ca_file: str | EnvRef | None = None,  # PEM to verify the SMTP server against (not a secret)
    tls_check_hostname: bool = True,  # match the cert against `host` (leave on)
    timeout_seconds: float = 30.0,
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """An SMTP email endpoint (**outbound destination only** — IMAP/POP read is Phase 2, ADR 0029).
    The Handler produces the email **body** (content-agnostic — an HL7 string, a JSON/XML report, plain
    text); this delivers it as a plain-text SMTP message to ``host:port`` from ``sender`` to
    ``recipients`` with a static ``subject``. STARTTLS by default (``use_tls=True``) on the ``587``
    submission port; port ``465`` is implicit TLS (``SMTP_SSL``). Optional ``username``/``password`` do
    SMTP ``AUTH`` (over a **verified** TLS session only — a cleartext- or unverified-credential config
    is refused). Disabling TLS (``use_tls=False``) is MITM-able and refused unless
    ``MEFOR_ALLOW_INSECURE_TLS`` is set (loud warning), like LDAPS / SQL Server / MLLP.

    **The server certificate is verified** (``tls_verify=True``, #323) — chain, hostname and strict RFC
    5280 flags, anchored to the OS roots, a per-connection ``tls_ca_file``, or the instance-wide
    ``[tls].internal_ca_file`` (ADR 0093). ``smtplib``'s own default context verifies **nothing**
    (``CERT_NONE``/``check_hostname=False``), so before #323 ``use_tls=True`` bought encryption without
    authentication. Point ``tls_ca_file`` at your relay's CA PEM for a private-CA server;
    ``tls_verify=False`` is a trusted-network dev/test escape, refused on an enforcing production-PHI
    instance even with ``MEFOR_ALLOW_INSECURE_TLS``, and it also refuses SMTP ``AUTH``.
    The egress host is gated by ``[egress].allowed_smtp``. Put
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
            "tls_verify": tls_verify,
            "tls_ca_file": tls_ca_file,
            "tls_check_hostname": tls_check_hostname,
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
    tls_verify: bool = True,  # verify the relay's cert (#323); False (dev only) needs the escape
    tls_ca_file: str | EnvRef | None = None,  # PEM to verify the SMTP/HISP relay against
    tls_check_hostname: bool = True,  # match the cert against `host` (leave on)
    timeout_seconds: float = 30.0,
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """A Direct-Project **S/MIME-over-SMTP** endpoint (**outbound destination only** — inbound Direct
    mail, MDN, and DNS-CERT discovery are deferred, ADR 0085 PR1). The Handler produces the clinical
    **body** (content-agnostic — an HL7 string, a CDA/XML document, plain text); this **signs** it with
    ``signing_key``/``signing_cert``, **encrypts** the signed blob to the partner's ``recipient_cert``
    (which must chain to ``trust_anchor``), and submits the S/MIME message to ``host:port`` over
    STARTTLS. All cert/key material is loaded + validated at construction (fail loud).

    **The relay's TLS certificate is verified** (``tls_verify=True``, #323 — ``smtplib``'s own default
    verifies nothing). Note the two trust settings are unrelated and easy to confuse: ``trust_anchor``
    is the CA the **partner's S/MIME certificate** must chain to (message-layer), while ``tls_ca_file``
    is the CA the **SMTP relay's TLS certificate** must chain to (transport-layer). The S/MIME body
    protects the clinical payload either way, but the SMTP session still carries envelope metadata and
    any ``AUTH`` credential, which is why the transport hop is verified too. The egress host
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
            "tls_verify": tls_verify,
            "tls_ca_file": tls_ca_file,
            "tls_check_hostname": tls_check_hostname,
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
    # (None → any AE the peer-IP allowlist admits — this call's source_ip_allowlist is the IP gate)
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
    tls_crl_file: str
    | EnvRef
    | None = None,  # opt-in CRL for mTLS client certs (#1005) — CA bundle + CRL, PEM
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
    ``calling_ae_allowlist`` AE Titles (when set) from the peers allowed by the ``inbound(...)``
    ``source_ip_allowlist`` keyword (there is no ``[inbound].source_ip_allowlist`` service key), and
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
            "tls_crl_file": tls_crl_file,
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
    # --- ADR 0126: outbound forward/egress web proxy (#112/#127/#128) ---
    proxy: str
    | None = None,  # #112: None = inherit [egress].proxy_url / off; "default" = system default web proxy; or an http(s):// address
    proxy_user: str | EnvRef | None = None,  # #127: forward-proxy auth username (use env())
    proxy_password: str
    | EnvRef
    | None = None,  # #127: forward-proxy auth password — secret, use env()
    proxy_auth_type: Literal["basic", "digest", "ntlm", "windows"]
    | None = None,  # #127: "basic" (default) | "digest" (http dest only); ntlm/windows deferred
    proxy_no_proxy: list[str]
    | None = None,  # #128: NO_PROXY-style bypass host list (intranet direct)
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
            "proxy_url": proxy,
            "proxy_user": proxy_user,
            "proxy_password": proxy_password,
            "proxy_auth_type": proxy_auth_type,
            "proxy_no_proxy": proxy_no_proxy,
        },
    )


# A stored-procedure call: the ODBC call escape ``{ [? =] CALL proc(...) }`` or a T-SQL ``EXEC``/``EXECUTE``
# (which a scalar-return batch leads with a ``DECLARE @rv INT; EXEC @rv = proc; SELECT @rv`` preamble, so
# the keyword is not necessarily first). Used ONLY to gate DATABASE capture_out_params (#67) — the explicit
# opt-in must name an actual proc call so it can't mask a plain INSERT/UPDATE/DELETE (which carries neither
# CALL nor EXEC). Advisory, not a security boundary (binding stays parameterized). Lower-cased statement in.
_DB_PROC_CALL_RE = re.compile(r"\bexec(?:ute)?\b|\bcall\b", re.IGNORECASE | re.DOTALL)


def _is_db_proc_call(statement_lower: str) -> bool:
    """Whether ``statement_lower`` (an already-lower-cased SQL statement) is a stored-procedure call — an
    ODBC ``{ ... CALL ... }`` escape or a T-SQL ``EXEC``/``EXECUTE`` (#67, ADR 0013 amendment)."""
    return bool(_DB_PROC_CALL_RE.search(statement_lower))


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
    dialect: Literal[
        "sqlserver", "generic"
    ] = "sqlserver",  # 'sqlserver' preset (default) | 'generic' ODBC (#66)
    auth: Literal[
        "sql", "integrated", "entra"
    ] = "sql",  # sql | integrated | entra (SQL Server preset only)
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
    capture_out_params: bool = False,  # #67: capture a stored-proc CALL's OUT params + scalar RETURN value
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
    the top-level fields). The write **must be idempotent** (at-least-once).

    ``capture_response=True`` captures the statement's ``RETURNING``/``OUTPUT`` result-set (ADR 0013).
    ``capture_out_params=True`` (#67, ADR 0013 amendment) captures a **stored-procedure call's OUT params +
    scalar RETURN value** — for a proc that reports status through OUT/return rather than a result-set. It
    **implies** capture, requires the ``statement`` to be a stored-proc call (an ODBC ``{ … CALL … }`` escape
    or a leading ``EXEC``/``EXECUTE``), and reads the values back **pre-commit from the same cursor** via a
    trailing readback ``SELECT`` in the proc batch. The proc **must be idempotent and must not COMMIT/ROLLBACK
    internally**, or a crash-re-send may capture a divergent value (ADR 0013 amendment atomicity caveat)."""
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
            "capture_out_params": capture_out_params,
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
    dialect: Literal[
        "sqlserver", "generic"
    ] = "sqlserver",  # 'sqlserver' preset (default) | 'generic' ODBC (#66)
    mark_statement: str
    | None = None,  # UPDATE/DELETE run per row after the handler succeeds (:name)
    body_column: str | None = None,  # None → whole row as JSON; set → that column's value verbatim
    poll_seconds: float = 5.0,
    auth: Literal[
        "sql", "integrated", "entra"
    ] = "sql",  # sql | integrated | entra (SQL Server preset only)
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


#: A SOAP body-secret placeholder token: 16–64 chars of a URL/XML-safe alphabet. High entropy is the
#: author's responsibility (e.g. ``secrets.token_hex(12)``); the length floor makes an accidental
#: collision with real HL7-derived body content vanishingly unlikely (ADR 0015 amendment, #236).
_BODY_SECRET_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.@\-]{16,64}$")


def _hoist_body_secrets(body_secrets: Mapping[str, Any] | None) -> dict[str, Any]:
    """Desugar the author-facing ``body_secrets={placeholder_token: env(...)}`` map into **flat**
    top-level settings (ADR 0015 amendment, BACKLOG #236).

    The flat shape is load-bearing, not cosmetic: :func:`resolve_env_settings` resolves only
    **top-level** ``EnvRef`` values (a nested one is copied through verbatim — the tested
    ``_reject_envref_odbc_params`` ruling), so a nested ``{token: env()}`` would reach the connector as
    unresolved ``EnvRef`` *objects* and be spliced onto the wire as their ``repr``. Emitting
    ``body_secret_tokens: list[str]`` + ``body_secret_value_<i>: EnvRef`` keeps every secret a
    top-level ``EnvRef`` that the existing resolver materializes at connector build, that
    :func:`referenced_env_keys` sees (so the ADR 0050 missing-value gate arms), and that
    :func:`_is_secret_setting` redacts.

    **Code-first only.** Each value must be an ``env()`` ref with no ``default=`` (a fallback secret
    would leak through ``display_settings``) and no ``cast=``. A ``connections.toml`` ``[settings.
    body_secrets]`` table arrives here as raw ``{"env": ...}`` dicts (``parse_env_setting`` is
    top-level only and does not descend), so the ``isinstance(..., EnvRef)`` check below rejects it
    with a message pointing back to code-first — there is deliberately no TOML/GUI round-trip."""
    if not body_secrets:
        return {}
    if not isinstance(body_secrets, Mapping):
        raise WiringError(
            "SOAP body_secrets must be a mapping of {placeholder_token: env(secret_key)}"
        )
    tokens = sorted(body_secrets)
    for tok in tokens:
        if not isinstance(tok, str) or not _BODY_SECRET_TOKEN_RE.fullmatch(tok):
            raise WiringError(
                f"SOAP body_secrets placeholder {tok!r} must match {_BODY_SECRET_TOKEN_RE.pattern} "
                "(16–64 chars of [A-Za-z0-9_.@-]) — use a high-entropy token, e.g. secrets.token_hex(12)"
            )
    for shorter in tokens:
        for longer in tokens:
            if shorter != longer and shorter in longer:
                raise WiringError(
                    f"SOAP body_secrets placeholder {shorter!r} is a substring of {longer!r}; tokens "
                    "must be disjoint (a replace of the shorter would corrupt the longer)"
                )
    out: dict[str, Any] = {"body_secret_tokens": tokens}
    for i, tok in enumerate(tokens):
        value = body_secrets[tok]
        if not isinstance(value, EnvRef):
            raise WiringError(
                f"SOAP body_secrets[{tok!r}] must be an env() reference — secrets are never inline "
                "(CLAUDE.md §5), and body_secrets is code-first only (define this outbound as a Python "
                "Soap() call, not in connections.toml) (ADR 0015 amendment, #236)"
            )
        if value.default is not _UNSET:
            raise WiringError(
                f"SOAP body_secrets[{tok!r}] env() must not carry a default= — a fallback secret would "
                "be emitted by `graph --json` / the API metadata view; require it be set per environment"
            )
        if value.cast is not None:
            raise WiringError(
                f"SOAP body_secrets[{tok!r}] env() must not carry a cast= (a body secret is text)"
            )
        out[f"body_secret_value_{i}"] = value
    return out


def Soap(
    *,
    url: str | EnvRef,  # the SOAP endpoint (may be env())
    soap_action: str | EnvRef | None = None,  # SOAPAction (1.1 header / 1.2 content-type param)
    soap_version: Literal["1.1", "1.2"] = "1.1",  # "1.1" | "1.2"
    headers: dict[str, str] | None = None,  # static extra headers (no secrets — not env()-resolved)
    bearer_token: str | EnvRef | None = None,  # Authorization: Bearer … (use env() for the secret)
    basic_user: str | EnvRef | None = None,
    basic_password: str | EnvRef | None = None,
    timeout_seconds: float = 30.0,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    tls_allow_expired: bool = False,  # honour an EXPIRED server cert (chain+hostname still verified; #129)
    encoding: str = "utf-8",
    capture_response: bool = False,  # capture the SOAP response envelope as a reply (ADR 0013)
    capture_response_headers: list[str]
    | None = None,  # #154: allow-list of response header names to capture
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
    ws_password_type: Literal[
        "text", "digest"
    ] = "text",  # "text" (PasswordText; recommended over mTLS) | "digest"
    ws_addressing: bool = False,  # stamp <wsa:Action/To/MessageID> in send(); requires soap_version 1.2
    ws_timestamp_ttl_seconds: int = 300,  # Created→Expires window (must be >= max retry backoff)
    # ADR 0015 amendment (#236): {placeholder_token: env(secret)} substituted into the <Body> at send
    # time, so a config secret reaches a body-credential SOAP operation WITHOUT entering the message.
    body_secrets: Mapping[str, EnvRef] | None = None,
    # --- ADR 0126: outbound forward/egress web proxy (#112/#127/#128) ---
    proxy: str
    | None = None,  # #112: None = inherit [egress].proxy_url / off; "default" = system default web proxy; or an http(s):// address
    proxy_user: str | EnvRef | None = None,  # #127: forward-proxy auth username (use env())
    proxy_password: str
    | EnvRef
    | None = None,  # #127: forward-proxy auth password — secret, use env()
    proxy_auth_type: Literal["basic", "digest", "ntlm", "windows"]
    | None = None,  # #127: "basic" (default) | "digest" (http dest only); ntlm/windows deferred
    proxy_no_proxy: list[str]
    | None = None,  # #128: NO_PROXY-style bypass host list (intranet direct)
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
    ``[egress].allowed_http`` (shared with REST — **populate it for a PHI mTLS destination**).

    ``body_secrets={placeholder: env(secret)}`` (ADR 0015 amendment, #236) is for a partner whose
    operation carries credentials as **body elements** rather than a WS-Security header: the Handler
    emits the opaque ``placeholder`` token inside the ``<Body>`` (staying pure — it never holds the
    credential), and the transport substitutes the ``env()``-resolved secret in ``send()``, after the
    payload leaves the store and before the wire encode. The secret is therefore never in the
    ``Message``, the outbound/done/dead-letter rows, a replayed body, or ``dryrun`` output — the token
    is. **Check the live WSDL first:** if the service accepts a WS-Security ``UsernameToken`` header,
    use ``ws_security`` (above) and this is unnecessary. The
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
            "capture_response_headers": capture_response_headers,
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
            "proxy_url": proxy,
            "proxy_user": proxy_user,
            "proxy_password": proxy_password,
            "proxy_auth_type": proxy_auth_type,
            "proxy_no_proxy": proxy_no_proxy,
            # Desugared to flat top-level body_secret_tokens + body_secret_value_<i> so env() resolves
            # them (nested EnvRefs are NOT resolved). Absent → {} → byte-identical to before.
            **_hoist_body_secrets(body_secrets),
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
    after_read: Literal[
        "move", "delete", "leave"
    ] = "move",  # inbound: "move" (to processed_subdir) | "delete" | "leave" (process in place, #142)
    min_age_seconds: float = 0.0,  # inbound: skip files modified within this window (partial writes)
    max_file_bytes: int | None = 16 * 1024 * 1024,  # inbound: skip files over this (OOM guard)
    validate_directory: bool = False,  # both directions (#114): fail-fast at start on an unreachable remote dir, and never create it
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
    **must be idempotent**.

    ``validate_directory`` (#114, both directions) makes an unreachable/missing ``remote_dir`` **fail
    startup** — the connection is reported ``failed`` — instead of the default deferral to run time; on
    an outbound it additionally stops the upload directory from ever being created (on send, or by the
    on-demand test probe). Off by default: an intermittently-available remote dir must still start."""
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
            "validate_directory": validate_directory,
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
    after_read: Literal[
        "move", "delete", "leave"
    ] = "move",  # inbound: "move" (to processed_subdir) | "delete" | "leave" (process in place, #142)
    min_age_seconds: float = 0.0,  # inbound: skip files modified within this window (partial writes)
    max_file_bytes: int | None = 16 * 1024 * 1024,  # inbound: skip files over this (OOM guard)
    validate_directory: bool = False,  # both directions (#114): fail-fast at start on an unreachable remote dir, and never create it
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
    directions). At-least-once → downstreams **must be idempotent**. ``validate_directory`` behaves
    exactly as it does on :func:`Sftp`."""
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
            "validate_directory": validate_directory,
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

    def __post_init__(self) -> None:
        # Copy-on-Send (ADR 0104). When the engine has activated the run-scoped flag for this transform
        # run, snapshot the payload at THIS construction instant so a later mutation of the same object
        # (a divergent fan-out: set(); Send(); set(); Send()) does not leak into an already-constructed
        # Send. The flag is read from a run-scoped ContextVar — never a constructor argument — so this is
        # a single choke point the fused path (which calls transform_one WITHOUT run_context=) cannot
        # bypass. Flag OFF (the default, and any Send built outside a transform run — tests, dry-run) =>
        # the ContextVar default False => a no-op => Send stores the caller's exact reference =>
        # byte-identical to pre-ADR-0104. Frozen dataclass, so rebind via object.__setattr__.
        if snapshot_on_send_active():
            snap = snapshot_payload(self.message)
            if snap is not self.message:  # a str is returned as-is -> nothing to rebind
                object.__setattr__(self, "message", snap)


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
#: What a Handler returns: deliveries and/or writes (ADR 0005 state, ADR 0081 metadata) — a single
#: :class:`Send`/:class:`SetState`/:class:`SetMeta`, **any non-``str`` iterable** of them (list, tuple,
#: set, generator — BACKLOG #341), or ``None`` (filtered). ``Send``-only returns are unchanged —
#: backward compatible. ``Iterable`` is covariant, so a plain ``list[Send]`` is assignable here where
#: the invariant ``list[Send | SetState | SetMeta]`` used to be required.
HandlerResult = Send | SetState | SetMeta | Iterable[Send | SetState | SetMeta] | None
HandlerFn = Callable[[Payload], HandlerResult]


def handler_result_items(result: object) -> list[object] | None:
    """The elements of a Handler's returned **container**, or ``None`` — "this is a single value".

    The ONE materialization rule for a Handler return (BACKLOG #341). It lives here, beside
    :class:`Send`/:class:`SetState`/:class:`SetMeta`, because **both** consumers already import this
    module and neither gains a dependency: the in-process partitioner
    (:func:`messagefoundry.pipeline.dryrun._partition`) and the sandbox child
    (:mod:`messagefoundry.pipeline._sandbox_codec` / ``_sandbox_worker``). Sharing the rule is what
    keeps ``[sandbox].mode`` from ever changing WHICH ``Send``\\ s a Handler delivers (ADR 0087).

    A ``list``/``tuple``/``set``/generator of :class:`Send`\\ s all deliver the same ``Send``\\ s. The
    Router half (``dryrun._handler_names``) has always accepted any iterable; narrowing the Handler half
    to ``list`` made a returned tuple an **accept-and-drop** — the one thing CLAUDE.md §12 forbids
    outright. An EMPTY container yields ``[]``, so the documented ``return []`` / ``return ()`` filter
    idiom keeps filtering rather than delivering or raising.

    **Order is the container's, and a ``set`` has none.** The returned order is preserved verbatim and
    becomes the order the outbound rows are inserted in (``store.transform_handoff``) — i.e. the FIFO
    order of two ``Send``\\ s to the SAME outbound. A ``set``'s iteration order is unspecified:
    :class:`Send` is a frozen dataclass hashed on its fields and ``str`` hashing is seeded per process,
    so it differs between processes — which means between ``[sandbox].mode=off`` and ``mode=subprocess``
    (the child is a separate process) AND between a first pass and a **crash re-run**. Purity (CLAUDE.md
    §2) survives in the sense that carries the reliability invariant — a re-run re-derives the identical
    *multiset* of outbound rows, and each delivery is independent and idempotent — but their relative
    order is not reproducible. Ordered containers carry no such caveat, and the user-facing docs steer
    authors to them; a ``set`` is accepted so that the widen has no arbitrary hole, not recommended.

    Two deliberate carve-outs:

    * ``str``/``bytes``/``bytearray`` are iterable but are **not** containers of ``Send``\\ s —
      iterating one would partition its characters/bytes. They are single values.
    * The gate is ``isinstance(result, Iterable)`` — an explicit ``__iter__`` — **not** a duck-typed
      ``try: list(result)``. A :class:`~messagefoundry.parsing.message.Message` defines
      ``__getitem__(path: str)`` and no ``__iter__``, so ``list()`` would drive the legacy sequence
      protocol with an *int* index and raise out of a Handler that merely returned its message by
      mistake. That slip drops silently today, and this fix must not convert it into a new raise.
    """
    if isinstance(result, str | bytes | bytearray):
        return None
    if isinstance(result, Iterable):
        return list(result)
    return None


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


class MessageTypeError(ValueError):
    """A :func:`message_type_of` predicate met a body with no single usable MSH-9 — a
    :class:`~messagefoundry.parsing.message.RawMessage`, a BHS/FHS batch envelope, a bare multi-message
    batch (2+ ``MSH``), or an empty MSH-9.1 (ADR 0104).

    Raised **at run time** from inside the predicate. The ``accepts=`` predicate is called bare in the
    router stage, so this propagates out as a router-stage **content** fault → ``ERROR``/dead-letter —
    never a silent decline to ``UNROUTED``, never accept-and-drop. Deterministic on the same input, so
    it is re-run-stable. Subclasses :class:`ValueError` so a broad handler still classifies it as a
    content fault (parallel to :class:`WiringError` for the *author-time* grammar faults below)."""


def _parse_type_spec(spec: str) -> tuple[str | None, str | None]:
    """Validate + split one ``message_type_of`` spec at author time into ``(code, trigger)`` matchers.

    The spec string always uses a **literal** ``^`` (it is Python source, never the message's own
    separator); ``*`` in a component means "match any" (→ None). A third component (the structure id,
    e.g. ``ADT_A01``) is accepted but **ignored** — the match is MSH-9.1 + MSH-9.2 only. Raises
    :class:`WiringError` on a malformed spec (surfaced at config load / ``check``)."""
    if not isinstance(spec, str) or not spec:
        raise WiringError("message_type_of: each spec must be a non-empty str")
    parts = spec.split("^")
    if len(parts) > 3 or any(p == "" for p in parts[:2]):
        raise WiringError(
            f"message_type_of: malformed spec {spec!r} (expected 'CODE', 'CODE^TRIGGER', or "
            "'CODE^TRIGGER^STRUCTURE'; '*' is a wildcard component)"
        )
    code = None if parts[0] == "*" else parts[0]
    event = (None if parts[1] == "*" else parts[1]) if len(parts) >= 2 else None
    return code, event


def message_type_of(*specs: str) -> HandlerAccepts:
    """A pure :data:`HandlerAccepts` predicate (the ADR 0084 ``accepts=`` seam) that matches the HL7
    message type **component-wise** against the message's own MSH-2 separators (ADR 0104).

    Grammar (one or more specs; a message matching **any** is accepted): code-only ``"ADT"`` (any
    trigger); exact ``"ADT^A01"``; 3-component ``"ADT^A01^ADT_A01"`` (structure ignored); a ``"*"``
    wildcard component (``"ADT^*"`` / ``"*^A01"``); a variadic union
    ``message_type_of("ADT^A01", "ORU^R01")``. Use it as
    ``@handler("x", accepts=message_type_of("ADT^A01"))``.

    It matches on MSH-9.1 (:attr:`~messagefoundry.parsing.message.Message.message_code`) + MSH-9.2
    (:attr:`~messagefoundry.parsing.message.Message.trigger_event`), each read through the message's own
    MSH-2 and unescaped — never a whole-field caret-literal compare, so a conformant 3-component MSH-9
    and a custom component separator both match correctly. It **fails loud** (:class:`MessageTypeError`
    → ``ERROR``/dead-letter) on any body without exactly one usable MSH-9 (a ``RawMessage``, a BHS/FHS
    envelope, a multi-``MSH`` batch, or an empty MSH-9.1) rather than silently declining. HL7-only and
    optional; inheriting ADR 0084's ``FILTERED → UNROUTED`` shift, it is always a deliberate author
    choice. A malformed spec raises :class:`WiringError` at construction (config load / ``check``)."""
    if not specs:
        raise WiringError("message_type_of() requires at least one message-type spec")
    parsed = tuple(_parse_type_spec(s) for s in specs)  # eager author-time grammar validation

    def _pred(msg: Payload) -> bool:
        if not isinstance(msg, Message):  # narrows to Message for the rest (mypy-strict)
            raise MessageTypeError(
                f"message_type_of enforces an HL7 message type but received {type(msg).__name__} "
                f"(content_type={getattr(msg, 'content_type', '?')!r}); it has no MSH-9 to match"
            )
        segs = msg.segments()
        first = segs[0] if segs else None
        if first != "MSH":  # a BHS/FHS batch envelope (or an empty message) has no single MSH-9
            raise MessageTypeError(
                f"message_type_of: message does not lead with MSH (first segment {first!r}); a BHS/FHS "
                "batch envelope has no single MSH-9 to match"
            )
        msh_count = msg.count_segments("MSH")
        if msh_count != 1:  # a bare multi-message batch (2+ MSH) has no single message type
            raise MessageTypeError(
                f"message_type_of: message carries {msh_count} MSH segments (a batch); there is no "
                "single message type to match"
            )
        code = msg.message_code  # MSH-9.1 via the message's OWN MSH-2, unescaped
        if code is None:
            raise MessageTypeError(
                "message_type_of: MSH present but MSH-9.1 (message_code) is empty"
            )
        event = msg.trigger_event  # MSH-9.2 (may be None: a code-only MSH-9)
        for want_code, want_event in parsed:
            if want_code is not None and want_code != code:
                continue
            if want_event is None or want_event == event:
                return True
        return False

    return _pred


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
    # Present in the config but NOT deployed (#233, ADR 0111): True (the default) = wired and run exactly
    # as today; False = the connection stays in the graph (validate/check/graph --json all still see it)
    # but the engine never builds its connector, never resolves its env() values, and never spawns a
    # worker for it. Distinct from auto_start (deployed, just not up right now — startable at runtime),
    # from a DR/scheduler park (rows are RETAINED and retried), and from simulate (the lane IS built and
    # DOES take rows). deployed=False WINS over auto_start. Code-first AND connections.toml.
    deployed: bool = True
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
    # Per-inbound very-large-document streaming (#149, ADR 0105 Phase 1a). HL7v2 only.
    #   stream_threshold_bytes: None (default) = OFF, byte-identical to today (no detach, no attachment
    #     rows). Set (>0) = a received body at/above this size has each oversized OBX-5 ED base64 document
    #     DETACHED VERBATIM into the store's content-addressed attachment substrate and replaced in the
    #     stored skeleton by a small `mfdoc:v1:ref:` handle; below-threshold bodies stay on the byte-
    #     identical fast path. Requires a store whose supports_streaming_attachments is True — now all
    #     three backends (SQLite + SQL Server + Postgres, ADR 0105 Phase 4 go-live parity).
    #   max_message_bytes: None (default) = inherit the engine 16 MiB ingress ceiling; set = the
    #     per-connection TOTAL body cap (the OOM guard that replaces the frame-cap-as-only-guard — a body
    #     over it is rejected/NAK'd BEFORE detach). A streaming inbound raises this above 16 MiB (and its
    #     transport's max_frame_bytes) so the large frame is admitted, then detached under the cap.
    # Same override idiom as messages_days — code-first AND via connections.toml (ADR 0007).
    stream_threshold_bytes: int | None = None
    max_message_bytes: int | None = None
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
    # Operator "object of interest" flag (#131, ADR 0007 amendment). Purely a console/CLI display marker
    # — NO runtime path reads it — for the Flagged Objects filter. Console-settable ONLY on a
    # connections.toml-managed connection (the write seam persists it there); a code-first connection can
    # still declare flagged=True in Python, but the console flag-toggle refuses it (no TOML home). Default
    # False → byte-identical. Code-first AND connections.toml.
    flagged: bool = False
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
    # Present in the config but NOT deployed (#233, ADR 0111): True (the default) = wired and run exactly
    # as today; False = the connection stays in the graph (so validate/check/graph --json still see it and
    # its already-queued rows are never swept) but the engine never builds its connector, never resolves
    # its env() values, and spawns NO delivery worker — a Send to it is declined at the transform seam, so
    # no row can ever queue to it. Distinct from auto_start (deployed, just not up right now), from a
    # DR/scheduler park (rows RETAINED + retried), and from simulate (the lane IS built and DOES take
    # rows). deployed=False WINS over auto_start. Code-first AND connections.toml.
    deployed: bool = True
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
    # Operator "object of interest" flag (#131, ADR 0007 amendment) — see the InboundConnection note.
    # Display-only (no runtime path reads it); console-settable on a connections.toml-managed outbound.
    flagged: bool = False
    # Cosmetic per-message "Waiting for Reply" display delay (#136, ADR 0065 amendment): seconds after a
    # send before the connection is SHOWN awaiting a reply (the MLLP connector stamps a side-band marker
    # around its ACK read). DISPLAY ONLY — no delivery effect, independent of `timeout_seconds`/pacing.
    # Default 0.0. Threaded to the Destination by _dest_config. Code-first AND connections.toml.
    waiting_display_delay: float = 0.0
    # ADR 0153 decision 2: this outbound's hop is cleartext, is NOT secure, and the operator accepts
    # that (with a written reason). WARN, never ALLOW — crossed, but logged at every construction and
    # audited. The opposite claim to `tls_hop_attested` ("this hop IS secure by means the engine cannot
    # see"), deliberately kept a separate field so the audit trail can tell a proxy-terminated hop from
    # plaintext on a flat network. Outbound-only. Threaded to the Destination by _dest_config.
    cleartext_accepted: bool = False
    cleartext_reason: str | None = None
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
    ic: InboundConnection, *, bind_host: str, env_values: Mapping[str, Any]
) -> tuple[str | None, int] | None:
    """The ``(normalized_host, port)`` a listener inbound will bind, or ``None`` when it binds no
    checkable listening port (not a listening source, an inbound that is present-but-NOT-DEPLOYED, or an
    ``env()`` port with no value yet). The host is the per-connection ``bind_address`` else the service
    ``bind_host`` (matching ``_source_config``), normalized for overlap comparison.

    ``deployed=False`` (#233, ADR 0111) binds NO socket — ever — so it can contend for none. Excluding it
    here is what lets the superseded half of a retired/replacement pair keep its real port in the config
    (carrying the record IS the point of the state) without failing the port pre-flight against the
    successor that took the port over."""
    if ic.spec.type not in _LISTEN_TYPES or not ic.deployed:
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
    registry: Registry,
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
    # The Loopback inbound NAMES of the WHOLE config, pinned beside the shard identity by the same
    # filter (None on an unfiltered graph / single-shard config, where `inbound` IS the whole config).
    # A shard's `inbound` map holds only its OWN inbounds, but `reingress_to` is a fact about the
    # CONFIG, not about which shard owns the loopback — the runtime already spans the two (the
    # capturing outbound's shard produces the Stage.RESPONSE row; the loopback's shard drains it).
    # Names only, deliberately not the connections: every other reader of `inbound` must keep seeing
    # only this shard's, so a map here would re-leak foreign inbounds into filtered-only paths.
    all_loopback_inbound: frozenset[str] | None = None

    def loopback_inbound_names(self) -> frozenset[str]:
        """Every ``Loopback()`` inbound in the deployment — the pinned unfiltered set when this is one
        engine shard's filtered view, else derived from this graph's own inbounds. The single source of
        truth for the ADR 0013 cross-registry ``reingress_to`` rule, which must see the whole config so a
        shard that doesn't own the loopback still validates (and still rejects a typo)."""
        if self.all_loopback_inbound is not None:
            return self.all_loopback_inbound
        return frozenset(
            name for name, ic in self.inbound.items() if ic.spec.type is ConnectorType.LOOPBACK
        )

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
        start/reload). A ``deployed=False`` inbound (#233, ADR 0111) is excluded: it never binds, so it
        cannot collide — see :func:`resolve_listener_binding`, which excludes it on the resolved path."""
        bindings = [
            _Binding(conn.name, _normalize_bind_host(conn.bind_address), port)
            for conn in self.inbound.values()
            if conn.deployed
            and conn.spec.type in _LISTEN_TYPES
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


def accepted_cleartext_hops(registry: Registry) -> list[tuple[str, str]]:
    """Every connection that DECLARES ``cleartext_accepted``, as ``(name, reason)`` (ADR 0153).

    The SINGLE reader of the accepted set, shared by ``messagefoundry check``'s ``cleartext-accepted``
    surface and by the API's ``GET /security/posture`` loosening registry, so the two can never report
    different sets. Sorted by connection name for a stable, diffable list.

    It walks **both** connection tables that can cross a declared cleartext hop: ``outbound`` and
    ``fhir_lookups``. The lookups are not optional coverage — the read executor honours the declaration
    for a PHI-bearing read hop, so omitting them here would let a live cleartext hop cross while every
    visibility surface reported the accepted set as empty. Lookup names are prefixed ``fhir_lookup:``
    because they live in a separate namespace and could otherwise collide with an outbound's name.

    Pure — it reads the loaded graph and touches nothing else. It lives HERE, beside the ``Registry`` it
    reads, rather than in ``checks`` or ``api``, so neither of those has to import the other: the
    acceptance is connection-scoped by construction, which is exactly why the settings-scoped
    ``security_loosenings`` takes the resolved NAMES rather than a graph."""
    out = [
        (oc.name, oc.cleartext_reason or "(none recorded)")
        for oc in registry.outbound.values()
        if oc.cleartext_accepted
    ]
    for spec in registry.fhir_lookups.values():
        if spec.settings.get("cleartext_accepted"):
            reason = spec.settings.get("cleartext_reason")
            out.append((f"fhir_lookup:{spec.name}", str(reason) if reason else "(none recorded)"))
    return sorted(out)


def _peer_label(settings: Mapping[str, Any]) -> str:
    """A readable, secret-free peer address for a connection's settings — the ``url`` if it has one,
    else ``host``/``server`` with its ``port``, else ``"(unknown peer)"``.

    Three keys because the connectors genuinely use three: ``url`` (Rest/FHIR/Soap), ``host``
    (MLLP/DICOM/Ftp) and ``server`` (Database, which is also the ``[egress].allowed_db`` allowlist key).

    An unresolved :class:`EnvRef` renders as ``env(<key>)``: the KEY, never the value, because these
    labels land in a posture report and a resolved value can be a credentialed URL. A resolved ``url``
    is passed through :func:`_mask_url_userinfo` for the same reason — the password half of
    ``https://user:SECRET@host/`` must not ride into ``GET /security/posture``."""

    def one(value: object) -> str | None:
        if isinstance(value, EnvRef):
            return f"env({value.key})"
        return str(_mask_url_userinfo(value)) if value else None

    url = one(settings.get("url"))
    if url:
        return url
    host = one(settings.get("host")) or one(settings.get("server"))
    if not host:
        return "(unknown peer)"
    port = one(settings.get("port"))
    return f"{host}:{port}" if port else host


def expiry_relaxed_hops(registry: Registry) -> list[tuple[str, str]]:
    """Every OUTBOUND connection that declares ``tls_allow_expired``, as ``(name, peer)`` (#129 /
    ADR 0094, surfaced by #333).

    The sibling of :func:`accepted_cleartext_hops`, and the same contract: the SINGLE reader, so
    ``messagefoundry check``, ``security_loosenings()`` and ``GET /security/posture`` can never report
    different sets. Sorted by connection name for a stable, diffable list.

    The flag lands in the connection's ``spec.settings`` dict (the six outbound factories that take it
    — ``MLLP``/``Rest``/``FHIR``/``DICOM``/``Soap``/``Ftp``) rather than in a typed
    ``OutboundConnection`` field like ``cleartext_accepted``, so this reads the dict.

    **Outbound only, and that is a fact about the graph rather than a scoping choice.** ``FhirLookup``
    exposes ``verify_tls`` but no ``tls_allow_expired``, and no inbound factory takes it (an inbound
    verifies a CLIENT cert, which is a different question). Said here explicitly so that ADDING the
    parameter to a lookup or an inbound later cannot silently escape this reader: whoever adds it must
    extend this function, exactly as ``accepted_cleartext_hops`` had to grow its ``fhir_lookups`` arm.

    Pure — it reads the loaded graph and touches nothing else."""
    return sorted(
        (oc.name, _peer_label(oc.spec.settings))
        for oc in registry.outbound.values()
        if oc.spec.settings.get("tls_allow_expired")
    )


def unverified_generic_db_hops(registry: Registry) -> list[tuple[str, str]]:
    """Every generic-ODBC ``DATABASE`` connection whose ``odbc_params`` leave TLS unenforced, as
    ``(name, reason)`` (#66 / ADR 0092 amendment, surfaced by #333).

    On ``dialect='generic'`` MessageFoundry cannot introspect an arbitrary driver's TLS posture, so the
    posture-keyed weakened-TLS refusal does not apply and TLS is delegated to the operator's own driver
    keyword. ADR 0092 accepted that exemption on the strength of ONE mitigation — construction logs it —
    and a log line emitted once at startup is not the surface anyone queries three months later. This is
    that surface.

    The exemption itself is narrower since BACKLOG #1178: a hop this function reports is also refused at
    connector construction on an enforcing instance off-loopback, through the shared cleartext-hop
    authority. This remains the INVENTORY of delegated hops — a hop can appear here and still be
    crossed legitimately, on-box or under a declared attestation or acceptance — so read it as "who
    owns TLS on this hop", never as "who is crossing in the clear".

    It walks **both** connection tables, unlike :func:`accepted_cleartext_hops`: a ``DatabasePoll``
    inbound crosses the same hop in the same dialect with the same credential in the same DSN, so
    reading only ``outbound`` would report a live unenforced hop as absent. Inbound names are prefixed
    ``inbound:`` because the two tables are separate namespaces and a name could otherwise collide.

    ``registry.lookups`` is deliberately NOT walked, and the reason is a property of the code rather
    than a scoping choice: neither ``DatabaseLookup`` nor ``DatabaseRef`` takes a ``dialect`` or
    ``odbc_params`` parameter, and the ADR 0010 read executor calls ``_build_dsn`` directly, so a live
    lookup is SQL-Server-only and keeps that preset's posture-keyed refusal. Stated here so that giving
    a lookup the generic dialect later cannot silently escape this reader — whoever adds it must extend
    this function.

    The classification is :func:`~messagefoundry.transports.database.generic_odbc_tls_unenforced` — the
    same predicate the construction WARNING uses, imported here rather than restated, so this reader and
    that log line can never disagree. Imported lazily inside the function: ``config`` must not take a
    module-import dependency on ``transports`` (the one-way rule), and this reader runs on operator
    surfaces, never on the hot path.

    Pure — it reads the loaded graph and touches nothing else."""
    from messagefoundry.transports.database import generic_odbc_tls_unenforced

    def unenforced(settings: Mapping[str, Any]) -> str | None:
        if str(settings.get("dialect", "sqlserver")).lower() != "generic":
            return None
        params = settings.get("odbc_params") or {}
        return generic_odbc_tls_unenforced(params) if isinstance(params, Mapping) else None

    out: list[tuple[str, str]] = []
    for label, table in (
        ("", registry.outbound),
        ("inbound:", registry.inbound),
    ):
        for conn in table.values():
            if conn.spec.type is not ConnectorType.DATABASE:
                continue
            reason = unenforced(conn.spec.settings)
            if reason is not None:
                out.append((f"{label}{conn.name}", f"{reason} ({_peer_label(conn.spec.settings)})"))
    return sorted(out)


def overbroad_smart_scopes(registry: Registry) -> list[tuple[str, str]]:
    """Every SMART-authenticated connection whose requested ``smart_scope`` asks for permission letters
    its DECLARED shape cannot spend, as ``(name, detail)`` (#1159, ASVS 10.2.3).

    The SINGLE reader of the over-grant set, on the same contract as :func:`accepted_cleartext_hops` and
    :func:`expiry_relaxed_hops`, so ``messagefoundry check`` and any later surface cannot disagree.
    Sorted by connection name for a stable, diffable list. Lookup names are prefixed ``fhir_lookup:``
    because they live in a separate namespace and could otherwise collide with an outbound's name.

    Three predicates arrive by lazy import from ``transports``, on the precedent
    :func:`unverified_generic_db_hops` states for ``generic_odbc_tls_unenforced`` — restating any of
    them here would be a second definition that can silently disagree with the code that acts on it,
    and ``config`` must not take a module-import dependency on ``transports``:

    * ``smart_auth_configured`` — whether SMART auth is ON, shared with the code that builds the
      provider and with the mutual-exclusion screen. Three spellings of this test had already drifted.
    * ``smart_scope_letters`` — the scope grammar, beside the code that puts ``scope`` on the wire.
    * ``scope_letters_for_shape`` — the letters a declared shape can spend, beside the
      interaction/conditional dispatch it mirrors, which is what makes it read ``conditional`` FIRST.

    A ``FhirLookup`` is not passed through that last one: it has no ``ConnectionSpec``, no interaction,
    and is structurally GET-only (ADR 0043 — the read executor cannot mutate), so it spends ``r`` and
    ``s`` and nothing else. Stated here so that giving a lookup a write path later cannot silently
    escape this reader, exactly as ``accepted_cleartext_hops`` had to grow its ``fhir_lookups`` arm.

    **Over-grant only, never under-grant.** ASVS 10.2.3 asks that the client request only the scopes it
    requires; asking for MORE authority than the connection can spend is the thing that verb names. A
    connection that requests too LITTLE is a correctness defect and it is not this verb, so this reader
    stays silent on it: telling an operator to ADD a letter would tell them to request authority their
    authorization server may never have registered, which a conformant server refuses outright.
    Narrowing a request to a subset of what IS registered always succeeds, which is what makes the
    over-grant direction safe to advise.

    **Quiet wherever the shape does not determine the answer**, because an advisory that fires on a
    valid clinical configuration teaches operators to ignore it: SMART auth off; no ``smart_scope``
    set, so the server applies its registered default; ``transaction``/``batch``, a plain ``Rest()``
    composed with SMART auth, or any connector declaring no interaction; a scope string carrying no
    parseable FHIR resource scope; and the RESOURCE half, always.

    The generic OAuth2 leg (``oauth2_scope``) is deliberately NOT covered, and that is a finding rather
    than an omission: its scope vocabulary belongs to the partner (the shipped worked example is
    ``claims.write``), so there is no declared shape to compute a requirement from and any screen over
    it would be guessing at someone else's namespace.

    Pure — it reads the loaded graph and touches nothing else."""
    from messagefoundry.transports.fhir import scope_letters_for_shape
    from messagefoundry.transports.smart import smart_auth_configured, smart_scope_letters

    def one(
        name: str, settings: Mapping[str, Any], conn_type: ConnectorType | None
    ) -> tuple[str, str] | None:
        if not smart_auth_configured(settings):
            return None
        scope = settings.get("smart_scope")
        requested = smart_scope_letters(scope) if isinstance(scope, str) else None
        allowed: frozenset[str] | None
        if conn_type is None:  # a FhirLookup: structurally GET-only, so read and search
            allowed, shape = frozenset("rs"), "GET-only lookup"
        elif conn_type is ConnectorType.FHIR:
            allowed = scope_letters_for_shape(
                str(settings.get("interaction") or ""), settings.get("conditional")
            )
            shape = f"interaction={settings.get('interaction')!r}"
            if settings.get("conditional"):
                shape += f"/conditional={settings.get('conditional')!r}"
        else:
            return None  # a plain Rest() composed with SMART auth declares no interaction
        if requested is None or allowed is None:
            return None
        extra = requested - allowed
        if not extra:
            return None
        return (
            name,
            f"requests {'/'.join(sorted(extra))} which a {shape} connection cannot use "
            f"(scope={scope!r}, usable={'/'.join(sorted(allowed))})",
        )

    # Two loops rather than the one table-driven loop `unverified_generic_db_hops` uses, because its two
    # tables both hold connections carrying a `ConnectionSpec` and these two do not: an
    # `OutboundConnection` has `.spec.settings` and a typed connector, a `FhirLookupSpec` has bare
    # `.settings` and no connector type at all. Folding them costs a `getattr` that defeats the type
    # checker to save two lines.
    out = [
        hit
        for oc in registry.outbound.values()
        if (hit := one(oc.name, oc.spec.settings, oc.spec.type)) is not None
    ]
    out += [
        hit
        for spec in registry.fhir_lookups.values()
        if (hit := one(f"fhir_lookup:{spec.name}", spec.settings, None)) is not None
    ]
    return sorted(out)


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
    deployed: bool = True,
    schedule: Schedule | None = None,
    metadata: Mapping[str, Any] | None = None,
    bind_address: str | None = None,
    source_ip_allowlist: list[str] | None = None,
    capture_ack: bool | None = None,
    capture_connection_errors: bool | None = None,
    messages_days: int | None = None,
    prune_documents_after: int | None = None,
    prune_documents_min_bytes: int | None = None,
    stream_threshold_bytes: int | None = None,
    max_message_bytes: int | None = None,
    priority: Priority | None = None,
    shard: str | None = None,
    flagged: bool = False,
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
    if stream_threshold_bytes is not None:
        # Per-inbound very-large-document streaming (#149, ADR 0105 Phase 1a). None = OFF; a set value must
        # be a POSITIVE byte size and only applies to the HL7 path (the detach targets OBX-5 ED embeds).
        if stream_threshold_bytes <= 0:
            raise WiringError(
                f"inbound connection {name!r}: stream_threshold_bytes must be > 0 bytes "
                "(omit it to disable very-large-document streaming)"
            )
        if content_type is not ContentType.HL7V2:
            raise WiringError(
                f"inbound connection {name!r}: stream_threshold_bytes is HL7-specific (it detaches "
                f"OBX-5 documents) and can't apply to a {content_type.value!r} content_type"
            )
    if max_message_bytes is not None and max_message_bytes <= 0:
        # The per-connection total-body OOM guard (replaces the frame-cap-as-only-guard). None = inherit
        # the engine 16 MiB ceiling; a set value must be positive. Fail loud at wiring (dry-run / check).
        raise WiringError(
            f"inbound connection {name!r}: max_message_bytes must be > 0 bytes "
            "(omit it to inherit the engine ingress ceiling)"
        )
    if (
        stream_threshold_bytes is not None
        and max_message_bytes is not None
        and max_message_bytes < stream_threshold_bytes
    ):
        # A cap below the detach threshold is incoherent — a body large enough to detach would always be
        # rejected first, so streaming could never engage. Catch the likely-mistaken config loud.
        raise WiringError(
            f"inbound connection {name!r}: max_message_bytes ({max_message_bytes}) must be >= "
            f"stream_threshold_bytes ({stream_threshold_bytes}) — a lower cap rejects every message "
            "the threshold would detach"
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
        deployed=deployed,
        schedule=schedule,
        metadata=metadata,
        bind_address=bind_address,
        source_ip_allowlist=allowlist,
        capture_ack=capture_ack,
        capture_connection_errors=capture_connection_errors,
        messages_days=messages_days,
        prune_documents_after=prune_documents_after,
        prune_documents_min_bytes=prune_documents_min_bytes,
        stream_threshold_bytes=stream_threshold_bytes,
        max_message_bytes=max_message_bytes,
        priority=priority,
        shard=shard,
        flagged=flagged,
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
    deployed: bool = True,
    schedule: Schedule | None = None,
    metadata: Mapping[str, Any] | None = None,
    bind_address: str | None = None,
    source_ip_allowlist: list[str] | None = None,
    capture_ack: bool | None = None,
    capture_connection_errors: bool | None = None,
    messages_days: int | None = None,
    prune_documents_after: int | None = None,
    prune_documents_min_bytes: int | None = None,
    stream_threshold_bytes: int | None = None,
    max_message_bytes: int | None = None,
    priority: Priority | None = None,
    shard: str | None = None,
    flagged: bool = False,
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
    connection runs, never routing; also a ``connections.toml`` key (ADR 0007).

    ``deployed`` (#233, ADR 0111) declares the connection **present in the config but not deployed**:
    ``True`` (the default) is today's behaviour; ``False`` keeps it in the graph (``validate``/``check``/
    ``graph --json`` still see it) while the engine never builds it, never resolves its ``env()`` values
    and never runs it — so a retired or not-yet-live feed can stay in the config repo without failing the
    build or degrading the engine. It is stronger than ``auto_start=False`` (deployed, just not up right
    now — startable at runtime) and **wins** over it. Also a ``connections.toml`` key."""
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
            deployed=deployed,
            schedule=schedule,
            metadata=metadata,
            bind_address=bind_address,
            source_ip_allowlist=source_ip_allowlist,
            capture_ack=capture_ack,
            capture_connection_errors=capture_connection_errors,
            messages_days=messages_days,
            prune_documents_after=prune_documents_after,
            prune_documents_min_bytes=prune_documents_min_bytes,
            stream_threshold_bytes=stream_threshold_bytes,
            max_message_bytes=max_message_bytes,
            priority=priority,
            shard=shard,
            flagged=flagged,
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
    deployed: bool = True,
    schedule: Schedule | None = None,
    dead_letter_days: int | None = None,
    priority: Priority | None = None,
    metadata: Mapping[str, Any] | None = None,
    flagged: bool = False,
    waiting_display_delay: float = 0.0,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
    source_file: str | None = None,
    source_line: int | None = None,
) -> OutboundConnection:
    """Validate the outbound-connection invariants and build an :class:`OutboundConnection`.

    The shared core of code-first :func:`outbound` **and** the ``connections.toml`` loader (ADR 0007).
    Pure — it does not touch the active registry; the caller is responsible for ``add_outbound``."""
    # ADR 0153 decision 2: the cleartext-acceptance pair is coherence-checked HERE, the one choke point
    # both authoring surfaces pass through, so a flag with no reason (or a reason with no flag) fails at
    # `messagefoundry check` / dry-run rather than at connector construction. Re-raised as a WiringError
    # so it surfaces with the connection name attached, exactly like every other wiring invariant; the
    # Destination model re-validates it independently (defense in depth for a hand-built Destination).
    try:
        _check_cleartext_acceptance(cleartext_accepted, cleartext_reason)
    except ValueError as exc:
        raise WiringError(f"outbound connection {name!r}: {exc}") from exc
    if dead_letter_days is not None and dead_letter_days < 0:
        # Per-connection dead-letter retention override (#34, ADR 0027). None = inherit
        # [retention].dead_letter_days; 0 = keep forever; >0 = days. A negative window is meaningless —
        # fail loud at wiring (caught in dry-run / `messagefoundry check`).
        raise WiringError(
            f"outbound connection {name!r}: dead_letter_days must be >= 0 "
            "(0 = keep forever, omit to inherit the global [retention] window)"
        )
    if waiting_display_delay < 0:
        # #136 (ADR 0065 amendment): the cosmetic "Waiting for Reply" pre-display delay is seconds; a
        # negative value is meaningless (0.0 = show immediately). Fail loud at wiring (dry-run / check).
        raise WiringError(
            f"outbound connection {name!r}: waiting_display_delay must be >= 0 seconds "
            "(0 = show 'waiting for reply' immediately)"
        )
    send_pace = spec.settings.get("send_min_interval_seconds")
    if send_pace is not None and send_pace < 0:
        # BACKLOG #82: per-connection egress send pacing (min seconds between sends on this lane). A
        # negative interval is meaningless (None/0 = no pacing). Fail loud at wiring (dry-run / check).
        raise WiringError(
            f"outbound connection {name!r}: send_min_interval_seconds must be >= 0 seconds "
            "(None or 0 = no pacing)"
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
    # BACKLOG #114: validate_directory was rejected here while it was INBOUND-ONLY (no destination read
    # it, and DestinationConnector had no validate_startup hook, so accepting it was a silent no-op).
    # Both halves are built now — DestinationConnector.validate_startup, overridden by the FILE and
    # REMOTEFILE destinations and awaited on the runner's outbound start path — so the option is
    # honoured in both directions and there is nothing left to refuse.
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
    # #67 (ADR 0013 amendment): capturing a stored-proc's OUT params + scalar return value IMPLIES
    # capture, so the capture-validity guards below (and the connector) treat it as a capturing outbound.
    if spec.settings.get("capture_out_params"):
        spec.settings["capture_response"] = True
    # BACKLOG #117 (ADR 0124): fire-and-forward MLLP outbound. no_ack skips the ACK read entirely, so
    # there is nothing to capture, and it is MLLP-only (the generic Tcp()/X12() fire-and-forget is
    # expect_reply=false). Validate at check/dry-run — a config that can never do what it asks fails
    # before any store or socket. Runs AFTER the reingress→capture desugar above, so no_ack+reingress_to
    # is rejected via the capture_response check below too.
    if spec.settings.get("no_ack"):
        if spec.type is not ConnectorType.MLLP:
            raise WiringError(
                f"outbound connection {name!r}: no_ack is an MLLP-only fire-and-forward knob "
                f"(got {spec.type.value.upper()}) — the generic Tcp()/X12() fire-and-forget is "
                "expect_reply=false (BACKLOG #117)."
            )
        if spec.settings.get("capture_response"):
            raise WiringError(
                f"outbound connection {name!r}: MLLP no_ack=True skips the ACK read, so there is no "
                "ACK to capture — capture_response/reingress_to is incompatible with no_ack "
                "(ADR 0124 / BACKLOG #117)."
            )
        if spec.settings.get("verify_ack_control_id"):
            raise WiringError(
                f"outbound connection {name!r}: MLLP no_ack=True skips the ACK read, so there is no "
                "MSA-2 to match against the sent MSH-10 — verify_ack_control_id is incompatible with "
                "no_ack (BACKLOG #117 + #82)."
            )
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
            if spec.settings.get("capture_out_params"):
                # #67 (ADR 0013 amendment): a stored-proc CALL captures its OUT params / scalar RETURN
                # value via a pre-commit readback SELECT in the SAME batch, which may carry NEITHER a
                # RETURNING nor an OUTPUT token (a scalar `EXEC @rv = proc; SELECT @rv` batch). The
                # EXPLICIT opt-in flag — NOT a loosening of the substring test — authorizes capture, but
                # only for an actual stored-proc call, so the flag can't silently mask a plain
                # INSERT/UPDATE whose result-set would re-run non-idempotently.
                if not _is_db_proc_call(stmt):
                    raise WiringError(
                        f"outbound connection {name!r}: DATABASE capture_out_params=True requires the "
                        "statement to be a stored-procedure call (an ODBC '{ ... CALL ... }' escape or a "
                        "leading EXEC/EXECUTE), not a plain write (ADR 0013 amendment, #67)."
                    )
            elif "returning" not in stmt and "output" not in stmt:
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
        # ADR 0015 amendment (BACKLOG #236): body-secret substitution. The Handler emits placeholder
        # tokens; the transport swaps in the env()-resolved secret in send(), so the credential never
        # enters the persisted message. Refuse it together with reingress_to: re-ingress promotes the
        # (best-effort-scrubbed) partner reply into a first-class persisted message, and reingress_to
        # force-sets capture_response — widening the one surface the scrub can only cover best-effort.
        # (capture_response alone stays allowed: the feed needs its submit confirmation.)
        if spec.settings.get("body_secret_tokens") and spec.settings.get("reingress_to"):
            raise WiringError(
                f"outbound connection {name!r}: SOAP body_secrets is incompatible with reingress_to "
                "(re-ingress would persist a best-effort-scrubbed partner reply as a new message; "
                "use capture_response for reconciliation instead) (ADR 0015 amendment, #236)."
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
        deployed=deployed,
        schedule=schedule,
        dead_letter_days=dead_letter_days,
        priority=priority,
        metadata=metadata,
        flagged=flagged,
        waiting_display_delay=waiting_display_delay,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
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
    deployed: bool = True,
    schedule: Schedule | None = None,
    dead_letter_days: int | None = None,
    priority: Priority | None = None,
    metadata: Mapping[str, Any] | None = None,
    flagged: bool = False,
    waiting_display_delay: float = 0.0,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
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
    delivery.

    ``deployed`` (#233, ADR 0111) declares the connection **present in the config but not deployed**:
    ``True`` (the default) is today's behaviour; ``False`` keeps it in the graph (``validate``/``check``/
    ``graph --json`` still see it, and its already-queued rows are never swept) while the engine never
    builds it, never resolves its ``env()`` values and spawns no delivery worker — a ``Send`` to it is
    declined and logged rather than queued. Unlike ``simulate=True`` (the lane IS built and DOES take
    rows) and unlike a DR/scheduler park (rows are retained and retried), **nothing queues to it at
    all**. It **wins** over ``auto_start``. Also a ``connections.toml`` key.

    ``cleartext_accepted`` (ADR 0153) declares that **this** outbound's hop is cleartext, is NOT secure,
    and the operator accepts that — with a mandatory ``cleartext_reason`` recorded for the audit trail.
    It yields a loud WARN at every construction (never a silent ALLOW) and lets the hop cross even under
    ``[security].enforcement = enforce``. It is the opposite claim to a connection's ``tls_hop_attested``
    ("this hop *is* secure by means the engine cannot see", which ALLOWs), and the two are deliberately
    separate so the audit trail can tell a proxy-terminated hop from plaintext on a flat network. For
    ``Tcp()``/``X12()``, which have no TLS support at all, it is a **permanent, structural** declaration
    — there is no ``tls = true`` for them to migrate to (BACKLOG #311). Also a ``connections.toml`` key."""
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
            deployed=deployed,
            schedule=schedule,
            dead_letter_days=dead_letter_days,
            priority=priority,
            metadata=metadata,
            flagged=flagged,
            waiting_display_delay=waiting_display_delay,
            cleartext_accepted=cleartext_accepted,
            cleartext_reason=cleartext_reason,
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
    """Register a Handler: ``def handle(msg) -> Send | SetState | SetMeta | Iterable[...] | None``
    (``None`` => filtered; any non-``str`` iterable — list, tuple, set, generator — fans out, BACKLOG
    #341; :class:`SetState` declares a cross-message state write, ADR 0005; :class:`SetMeta` attaches a
    per-message metadata key/value, ADR 0081 — both applied exactly-once in the handoff).

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
