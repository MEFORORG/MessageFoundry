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
    "File",
    "Rest",
    "Database",
    "DatabasePoll",
    "Soap",
    "Send",
    "EnvRef",
    "env",
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


@dataclass(frozen=True)
class Send:
    """A Handler's instruction to deliver ``message`` to a named outbound connection."""

    to: str
    message: Message | RawMessage | str


#: What a Router/Handler receives: a mutable HL7 :class:`Message`, or a :class:`RawMessage` for a
#: non-HL7 inbound (ADR 0004). The author knows which — a Router/Handler is bound to one inbound.
Payload = Message | RawMessage
RouterFn = Callable[[Payload], "list[str] | str | None"]
HandlerFn = Callable[[Payload], "Send | list[Send] | None"]


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

    def add_inbound(self, conn: InboundConnection) -> None:
        self._add(self.inbound, conn.name, conn, "inbound connection")

    def add_outbound(self, conn: OutboundConnection) -> None:
        self._add(self.outbound, conn.name, conn, "outbound connection")

    def add_router(self, name: str, fn: RouterFn) -> None:
        self._add(self.routers, name, fn, "router")

    def add_handler(self, name: str, fn: HandlerFn) -> None:
        self._add(self.handlers, name, fn, "handler")

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
    if spec.type is ConnectorType.MLLP and spec.settings.get("host") is not None:
        # The bind interface is an environment/service decision (which NIC this instance exposes),
        # not a per-connection one — and exposing unauthenticated MLLP on 0.0.0.0 must be an admin
        # choice, not a developer default. Set it service-side via [inbound].bind_host.
        raise WiringError(
            f"inbound connection {name!r}: MLLP inbound takes no host; the bind interface is a "
            "service setting ([inbound].bind_host). Declare it as MLLP(port=...)."
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
    file, line = _call_site()
    _active_registry().add_inbound(
        InboundConnection(
            name=name,
            spec=spec,
            router=router,
            ack_mode=ack_mode,
            ack_after=ack_after,
            validation=Validation(strict=strict, hl7_version=hl7_version),
            content_type=content_type,
            source_file=file,
            source_line=line,
        )
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
    if spec.type is ConnectorType.MLLP and spec.settings.get("host") is None:
        # Outbound MLLP dials a downstream peer, so a host is mandatory. (It's the value that
        # legitimately differs per environment — see env() for DEV/PROD-specific peers.)
        raise WiringError(
            f"outbound connection {name!r}: MLLP outbound requires a host (the downstream peer), "
            "e.g. MLLP(host=..., port=...)."
        )
    file, line = _call_site()
    _active_registry().add_outbound(
        OutboundConnection(
            name=name,
            spec=spec,
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
    """Register a Handler: ``def handle(msg) -> Send | list[Send] | None`` (None => filtered)."""

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
    """Hold the load lock, publish ``registry`` as the active declaration target, and install the
    sibling-helper import finder for ``directory`` — tearing all of it down (including any helper
    modules registered under their plain name) on exit."""
    global _active
    helpers: set[str] = set()
    finder = _SiblingHelperFinder(directory, helpers)
    with _load_lock:
        _active = registry
        sys.meta_path.insert(0, finder)
        try:
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
    with _loading(directory, registry):
        for path in sorted(p for p in directory.glob("*.py") if not p.name.startswith("_")):
            _exec_module(path)
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
    with _loading(directory, registry):
        for path in sorted(p for p in directory.glob("*.py") if not p.name.startswith("_")):
            try:
                _exec_module(path)
            except WiringError as exc:
                diagnostics.append(Diagnostic(message=str(exc), file=str(path)))
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
