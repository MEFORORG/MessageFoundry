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
import os
import sys
import threading
from collections.abc import Callable, Mapping
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
    "File",
    "Rest",
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
    "InboundConnection",
    "OutboundConnection",
    "Registry",
    "WiringError",
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
    ``[sqlserver]`` extra + ODBC Driver 18 — **experimental**, like the DATABASE connector).

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
) -> ConnectionSpec:
    """An MLLP endpoint. Inbound uses port/max_connections/receive_timeout/max_frame_bytes (the
    bind interface comes from the service's ``[inbound].bind_host``, so ``host`` is rejected on an
    inbound); outbound uses host/port/connect_timeout/timeout_seconds/max_frame_bytes. ``encoding``
    applies to framing in both directions."""
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
) -> ConnectionSpec:
    """A SQL database endpoint (**outbound only** today; SQL Server via the ``[sqlserver]`` extra + ODBC
    Driver 18 — **experimental**). The Handler produces a JSON-object body; the connector binds its keys
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
    encoding: str = "utf-8",
) -> ConnectionSpec:
    """A SQL database polling **source** (inbound, ADR 0003 §3; SQL Server via the ``[sqlserver]`` extra +
    ODBC Driver 18 — **experimental**). Every ``poll_seconds`` it runs ``poll_statement`` (a ``SELECT``),
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
) -> ConnectionSpec:
    """A SOAP web-service endpoint (**outbound only**, ADR 0003). The Handler produces the full SOAP
    envelope; this POSTs it to ``url`` with the SOAP ``Content-Type`` (+ a ``SOAPAction`` header for
    1.1). A **Sender/Client** fault dead-letters; a **Receiver/Server** fault retries; otherwise the
    HTTP status decides. Put secrets in ``env()`` (``bearer_token``/``basic_*``); the host is gated by
    ``[egress].allowed_http`` (shared with REST). The operation **must be idempotent** (at-least-once)."""
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
    source_file: str | None = None
    source_line: int | None = None


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
        """Inbound connections sharing a literal bind port, as ``(port, first, colliding)`` tuples.

        Caught statically so a duplicate port surfaces at validate/``check`` time naming both
        connections, instead of aborting the whole engine with a bare bind ``OSError`` (review
        low-13). ``EnvRef`` ports resolve per-environment, so only ``int`` literals are checkable."""
        seen: dict[int, str] = {}
        out: list[tuple[int, str, str]] = []
        for conn in self.inbound.values():
            port = conn.spec.settings.get("port")
            if isinstance(port, int) and not isinstance(port, bool):
                if port in seen:
                    out.append((port, seen[port], conn.name))
                else:
                    seen[port] = conn.name
        return out


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


def build_inbound_connection(
    name: str,
    spec: ConnectionSpec,
    *,
    router: str,
    ack_mode: AckMode = AckMode.ORIGINAL,
    ack_after: AckAfter | None = None,
    strict: bool = False,
    hl7_version: str | None = None,
    content_type: ContentType = ContentType.HL7V2,
    source_file: str | None = None,
    source_line: int | None = None,
) -> InboundConnection:
    """Validate the inbound-connection invariants and build an :class:`InboundConnection`.

    The shared core of code-first :func:`inbound` **and** the ``connections.toml`` loader (ADR 0007),
    so both authoring surfaces enforce identical guards. Pure — it does not touch the active registry;
    the caller is responsible for ``add_inbound``."""
    if (
        spec.type in (ConnectorType.MLLP, ConnectorType.TCP)
        and spec.settings.get("host") is not None
    ):
        # The bind interface is an environment/service decision (which NIC this instance exposes),
        # not a per-connection one — and exposing an unauthenticated raw listener on 0.0.0.0 must be
        # an admin choice, not a developer default. Set it service-side via [inbound].bind_host.
        kind = spec.type.value.upper()
        raise WiringError(
            f"inbound connection {name!r}: {kind} inbound takes no host; the bind interface is a "
            f"service setting ([inbound].bind_host). Declare it as {kind.title()}(port=...)."
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
    return InboundConnection(
        name=name,
        spec=spec,
        router=router,
        ack_mode=ack_mode,
        ack_after=ack_after,
        validation=Validation(strict=strict, hl7_version=hl7_version),
        content_type=content_type,
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
    content_type: ContentType = ContentType.HL7V2,
) -> None:
    """Declare an inbound connection that feeds every received message to ``router``.

    ``ack_after`` selects ACK *timing* (staged pipeline, ADR 0001): the default ``INGEST``
    (ACK-on-receipt) is the only value supported in Step A — ``DELIVERED`` (defer the ACK until
    delivery) is not yet implemented and raises ``WiringError``. ``ack_after`` is distinct from
    ``ack_mode`` (the ACK code family).

    ``content_type`` (ADR 0004) selects the payload format: the default ``HL7V2`` runs the HL7
    peek/validate/ACK path and the Router/Handler receive a :class:`Message`; any other value skips HL7
    parsing and they receive a :class:`RawMessage` (``.raw``/``.text``/``.json()``). ``strict``
    validation is HL7-only, so it cannot combine with a non-HL7 ``content_type``."""
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
    source_file: str | None = None,
    source_line: int | None = None,
) -> OutboundConnection:
    """Validate the outbound-connection invariants and build an :class:`OutboundConnection`.

    The shared core of code-first :func:`outbound` **and** the ``connections.toml`` loader (ADR 0007).
    Pure — it does not touch the active registry; the caller is responsible for ``add_outbound``."""
    if spec.type in (ConnectorType.MLLP, ConnectorType.TCP) and spec.settings.get("host") is None:
        # Outbound MLLP/TCP dials a downstream peer, so a host is mandatory. (It's the value that
        # legitimately differs per environment — see env() for DEV/PROD-specific peers.)
        kind = spec.type.value.upper()
        raise WiringError(
            f"outbound connection {name!r}: {kind} outbound requires a host (the downstream peer), "
            f"e.g. {kind.title()}(host=..., port=...)."
        )
    return OutboundConnection(
        name=name,
        spec=spec,
        retry=retry,
        ordering=ordering,
        internal_error=internal_error,
        buildup=buildup,
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
) -> None:
    """Declare an outbound connection that Handlers can ``Send`` to.

    ``retry``/``ordering``/``internal_error``/``buildup`` override the global ``[delivery]`` defaults
    for this connection only (omit to inherit). ``ordering`` defaults to FIFO — strict in-order
    delivery per connection; ``internal_error`` defaults to continue (dead-letter a code-error row and
    advance); ``buildup`` sets the ``queue_buildup`` alert thresholds for this lane."""
    file, line = _call_site()
    _active_registry().add_outbound(
        build_outbound_connection(
            name,
            spec,
            retry=retry,
            ordering=ordering,
            internal_error=internal_error,
            buildup=buildup,
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
