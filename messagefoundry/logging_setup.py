# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Process-wide logging setup for the engine service.

Stdlib ``logging`` only (no structlog): a stdout stream handler with a timestamped text format by
default, optionally **structured JSON** (one object per line, ``[logging].format = "json"``), with
uvicorn's own loggers routed through the same handler. When the engine runs under NSSM as a Windows
service, NSSM captures stdout/stderr to rotating files, so we deliberately do **not** add file handlers
here. A copy of every record can also be **forwarded off-box** to a syslog/SIEM collector
(``[logging].forward_*``; sec-offbox-log, ASVS 16.x) so log evidence survives a host compromise; PHI
redaction + control-char scrubbing apply to the forwarded stream exactly as to stdout. The off-box
transport is UDP (RFC 5426), plaintext TCP (RFC 6587), or **native TLS** (RFC 5425 — an ``ssl``-wrapped
TCP socket, ADR 0080), so evidence can be encrypted on the wire without a local forwarding agent.

This module also exposes :func:`query_sntp_offset`, the bounded stdlib SNTP probe behind the opt-in
startup clock-sync gate (``[logging].require_time_sync``; ASVS 16.2.2) — cross-host log correlation
depends on synchronized clocks. The gate's *policy* (warn vs refuse) lives in ``__main__.serve``.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Any

from messagefoundry.redaction import redact

__all__ = [
    "configure_logging",
    "configure_stderr_logging",
    "set_runtime_level",
    "current_log_level",
    "silence_phi_prone_dependency_loggers",
    "scrub_control_chars",
    "ControlCharScrubFilter",
    "RedactionFilter",
    "JsonFormatter",
    "CredentialQueryScrubFilter",
    "SyslogForward",
    "query_sntp_offset",
    "LOG_LEVELS",
]

_log = logging.getLogger(__name__)

# Timestamps in UTC with a trailing 'Z' so log correlation across hosts/timezones is unambiguous
# (ASVS 16.2.2); the handler's formatter converter is set to time.gmtime below.
_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: Accepted ``--log-level`` values (used for argparse choices too).
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Logger names uvicorn configures itself; we route them through the root handler.
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")

# C0 control characters (and DEL) escaped to keep one log record on one line. CR/LF are the
# log-injection vector; tab (0x09) is left intact as benign whitespace.
_CTRL_TRANSLATION: dict[int, str] = {0x0A: "\\n", 0x0D: "\\r"}
for _i in range(0x20):
    if _i not in (0x09, 0x0A, 0x0D):
        _CTRL_TRANSLATION[_i] = f"\\x{_i:02x}"
_CTRL_TRANSLATION[0x7F] = "\\x7f"

#: Stamped on every physical line of a record's ``exc_text``/``stack_info`` (BACKLOG #335). A traceback
#: is multi-line by nature, so collapsing it the way the rendered message is collapsed would cost the
#: operator the readability an incident depends on. Its line breaks are kept and every line is indented
#: instead, so no traceback line starts at column 0 and none can impersonate the ``_LOG_FORMAT`` record
#: prefix (ASVS 16.4.1 — the readability call ADR 0034 §1 deferred).
_CONTINUATION_PREFIX = "    | "


def scrub_control_chars(text: str) -> str:
    """Escape C0 control characters and DEL (tab kept as benign whitespace) so no part of ``text`` can
    begin a new physical line or drive a terminal.

    The single definition of that translation. :class:`ControlCharScrubFilter` applies it to every
    record on a configured handler; a caller that assembles a record's content from an untrusted BYTE
    stream needs it at the point of assembly, because "one peer write is one log record" is that
    caller's own framing contract and cannot depend on how the host process configured logging — today
    the ADR 0166 sandbox stderr relay. Idempotent: the escaped forms contain no control characters."""
    return text.translate(_CTRL_TRANSLATION)


def _scrub_block(text: str) -> str:
    """Escape control characters in a multi-line block (``exc_text``/``stack_info``) while KEEPING its
    line breaks, indenting every line with :data:`_CONTINUATION_PREFIX`.

    The **first** line is indented too, so the guarantee does not rest on it being the stdlib
    ``Traceback (most recent call last):`` header: ``Formatter.formatException`` emits no header at all
    when the exception carries no ``__traceback__``, and that first line is then peer-derived text.

    Idempotent — the prefix is stripped before it is re-applied — because every handler carries its own
    filter chain, so a record dispatched to stdout *and* the off-box forwarder is scrubbed twice and the
    two sinks must not disagree."""
    return "\n".join(
        _CONTINUATION_PREFIX + scrub_control_chars(line.removeprefix(_CONTINUATION_PREFIX))
        for line in text.split("\n")
    )


class ControlCharScrubFilter(logging.Filter):
    """Neutralize CR/LF and other control characters in the rendered log message to prevent log
    injection / forging (ASVS 16.4.1).

    Untrusted MLLP peer data and HL7-derived exception text reach the general log; without this a
    crafted value containing a newline could inject a forged log line into NSSM's captured stdout.
    We render the message (applying ``%`` args) once, escape any control characters, and only then
    replace ``record.msg`` — clean messages keep their lazy ``msg``/``args`` untouched.

    ``record.exc_text`` and ``record.stack_info`` are covered too (BACKLOG #335, ADR 0034 §1), via
    :func:`_scrub_block`. This filter is installed **last** (see :func:`_install_phi_filters`), so
    :class:`RedactionFilter` has already rendered ``exc_info`` into ``exc_text`` and cleared it; a
    handler carrying this filter *without* that one would leave an unrendered ``exc_info`` for the
    formatter to expand unscrubbed."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        scrubbed = scrub_control_chars(message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        # The rendered message is only half the record: ``Formatter.format`` appends ``exc_text`` and
        # ``stack_info`` VERBATIM, so a CR/LF inside an exception message forged a whole line on the
        # text sink (BACKLOG #335). ``RedactionFilter`` is installed first and renders ``exc_info``
        # into ``exc_text``, so both fields are already populated when this filter runs.
        if record.exc_text:
            record.exc_text = _scrub_block(record.exc_text)
        if record.stack_info:
            record.stack_info = _scrub_block(record.stack_info)
        return True


# A throwaway formatter used only to render a record's exception into text for redaction.
# ``formatException`` is independent of any format string, so one shared instance is safe.
_EXC_RENDERER = logging.Formatter()


class RedactionFilter(logging.Filter):
    """Scrub HL7-shaped PHI from every emitted record — the rendered **message** and the formatted
    **exception traceback** (chained ``__cause__``/``__context__`` included) — via
    :func:`~messagefoundry.redaction.redact` (PHI.md §7, Gate #1).

    Inbound HL7 is PHI-bearing and a Router/Handler is user code that can ``raise ValueError(f"…{raw}")``;
    an outer-loop ``log.exception(...)`` / ``exc_info=`` (the delivery/router/transform catches, the
    ``_on_*_worker_done`` callbacks, the file/db/remotefile pollers, and the cluster leader-sweep /
    heartbeat loops) renders that exception's full traceback into the general log. Installing this as a
    **handler filter** redacts every such site *by construction* — current and future — so PHI safety
    doesn't depend on each call site remembering to pre-redact. ``redact`` rewrites only HL7-shaped spans
    (segment lines + runs carrying ≥2 ``|^~&`` delimiters), so ordinary operational messages pass through
    unchanged. Pair it with :class:`ControlCharScrubFilter` (added after, so it scrubs the redacted text).

    *Residual:* ``redact`` now also applies a conservative free-text heuristic — date/DOB runs and
    multi-token name runs (e.g. ``DOE JANE``) are scrubbed even without HL7 delimiters — so this flows
    through to both the stdout handler and the off-box forwarder by construction. The remaining residual
    is an adversarially-crafted *single-token* or non-name-shaped identifier, for which the "never put
    PHI in an exception message" convention remains the control (see :mod:`messagefoundry.redaction`)."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        scrubbed = redact(message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        # The realistic PHI vector is a chained exception carrying a raw body. Render the traceback
        # (chained causes included by default) and redact it; clear exc_info in BOTH paths so no
        # formatter (even a custom one ignoring exc_text) can re-render the raw exception.
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
            record.exc_info = None
        elif record.exc_info:
            record.exc_text = redact(_EXC_RENDERER.formatException(record.exc_info))
            record.exc_info = None
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


#: Query-string parameters that carry a credential and must never reach a log line. ``code`` and
#: ``state`` arrive on the OIDC callback's URL (ADR 0142 pins ``response_mode=query``), and uvicorn's
#: access logger emits the full request line *including* the query string.
_CREDENTIAL_QUERY_KEYS = ("code", "state", "id_token", "access_token", "token", "session_state")

_CREDENTIAL_QUERY_RE = re.compile(
    r"(?i)\b(" + "|".join(_CREDENTIAL_QUERY_KEYS) + r")=[^&\s\"']+",
)


class CredentialQueryScrubFilter(logging.Filter):
    """Redact credential-bearing **query parameters** from every emitted record (ADR 0142 AC-10).

    The motivating case is uvicorn's access log: ``GET /ui/oidc/callback?code=…&state=…`` is emitted at
    INFO by ``uvicorn.access``, which :func:`configure_logging` deliberately routes to the same stdout
    handler NSSM captures to disk and the off-box forwarder ships to a SIEM. AC-10 says the engine
    SHALL NOT log the authorization ``code``; a live (if short-lived, PKCE-bound) credential landing in
    a shipped log file is exactly what that forbids.

    Installed as a **handler filter**, like :class:`RedactionFilter`, so it covers current *and future*
    call sites by construction rather than depending on each one remembering to pre-scrub. The
    parameter NAME is kept so a log stays diagnosable — only the value is replaced.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        scrubbed = _CREDENTIAL_QUERY_RE.sub(lambda m: f"{m.group(1)}=<redacted>", message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    """Render each record as a single line of JSON — one object per line — for a log shipper / SIEM
    (sec-offbox-log).

    PHI redaction + control-char scrubbing run upstream as **handler filters** (see
    :func:`configure_logging`), so by the time ``format`` runs ``record.getMessage()`` and
    ``record.exc_text`` are already redacted; ``json.dumps`` additionally escapes any residual control
    characters, so a record can never break the one-object-per-line framing (ASVS 16.4.1). UTC ``Z``
    timestamps match the text formatter (16.2.2). The exception/stack fields are populated **and
    already redacted** by :class:`RedactionFilter` (which clears ``exc_info`` after rendering), so they
    are emitted from ``exc_text``/``stack_info`` without re-rendering the raw exception."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            # UTC ``Z`` timestamp, byte-for-byte parity with the text formatter (gmtime + _DATE_FORMAT).
            "time": time.strftime(_DATE_FORMAT, time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_text:
            payload["exception"] = record.exc_text
        elif record.exc_info:
            # Defensive: RedactionFilter normally pre-renders + redacts exc_text and clears exc_info,
            # so this branch is dead on the configured handlers. If JsonFormatter is ever attached to a
            # filter-less handler, redact here too so PHI safety doesn't depend on call-site discipline.
            payload["exception"] = redact(self.formatException(record.exc_info))
        if record.stack_info:
            payload["stack"] = record.stack_info
        return json.dumps(payload, ensure_ascii=False)


@dataclass(frozen=True)
class SyslogForward:
    """Off-box syslog forwarding target (sec-offbox-log). A primitive value object so this module stays
    free of a config import (``config.settings`` imports ``LOG_LEVELS`` from here — the dependency must
    not go the other way). ``protocol`` is ``"udp"`` (RFC 5426; fire-and-forget), ``"tcp"`` (RFC 6587),
    or ``"tls"`` (RFC 5425; ssl-wrapped TCP — ADR 0080); a down collector is tolerated for the
    connection-oriented protocols (see :func:`configure_logging`). ``fmt`` is ``"json"`` or ``"text"``
    and is independent of the stdout format. The ``tls_*`` fields apply only when ``protocol == "tls"``:
    ``tls_ca_file`` is the PEM trust anchor (only that CA is trusted; system roots are not loaded),
    ``tls_verify`` toggles certificate + hostname verification (default on), and ``tls_client_cert`` is
    an optional PEM cert+key chain for mutual TLS."""

    host: str
    port: int = 514
    protocol: str = "udp"
    fmt: str = "json"
    tls_ca_file: str | None = None
    tls_verify: bool = True
    tls_client_cert: str | None = None


#: Socket timeout (seconds) pinned on a **TCP** off-box forwarder. The engine logs synchronously from
#: asyncio workers on the event-loop thread, so an unbounded blocking ``sendall`` to a stalled-but-
#: connected collector (TCP back-pressure / a wedged SIEM) would block the whole event loop. With this
#: timeout, ``SysLogHandler.emit`` raises ``socket.timeout``, swallows it via ``handleError``, and drops
#: the record — so a stalled collector costs at most this many seconds per record, never an indefinite
#: stall. UDP is connectionless (fire-and-forget) and needs no timeout. For a high-volume feed prefer
#: UDP or a local forwarding agent; a synchronous TCP forward is best-effort by design.
_FORWARD_TCP_TIMEOUT = 5.0


class _TimeoutSysLogHandler(logging.handlers.SysLogHandler):
    """:class:`~logging.handlers.SysLogHandler` that pins a socket timeout on its socket — including on
    any reconnect inside ``emit`` — so a runtime send to a stalled TCP collector can't block the calling
    thread (the asyncio event loop) indefinitely."""

    def __init__(self, *args: Any, timeout: float | None = None, **kwargs: Any) -> None:
        self._sock_timeout = timeout
        # Forward the timeout to the stdlib ctor as well (BACKLOG #350). SysLogHandler.createSocket
        # applies `self.timeout` via settimeout() *before* sock.connect(), so this is the only thing
        # that bounds the STARTUP connect; our own settimeout in createSocket runs after connect has
        # already returned and can bound nothing but later sends/reconnects. Without this the startup
        # connect fell back to the OS default — on a collector host that DROPS rather than refuses,
        # that stalls engine start, contradicting this class's own "can't block the calling thread"
        # contract and _build_syslog_handler's docstring.
        # Routed through kwargs rather than passed explicitly: `timeout` is also SysLogHandler's 4th
        # POSITIONAL parameter, so `super().__init__(*args, timeout=...)` is a possible double-bind
        # that mypy rejects outright. Every construction site here is keyword-only, so this is
        # equivalent at runtime and honest to the checker.
        kwargs["timeout"] = timeout
        super().__init__(*args, **kwargs)  # SysLogHandler.__init__ calls createSocket() (3.11+)

    def createSocket(self) -> None:
        super().createSocket()
        # SysLogHandler.socket is set at runtime (not in typeshed); getattr keeps this mypy-clean
        # across typeshed versions without a fragile per-version type: ignore.
        sock = getattr(self, "socket", None)
        if self._sock_timeout is not None and sock is not None:
            sock.settimeout(self._sock_timeout)


def _build_tls_context(forward: SyslogForward) -> ssl.SSLContext:
    """Build the client :class:`ssl.SSLContext` for a ``protocol == "tls"`` forwarder (RFC 5425).

    ``create_default_context(cafile=...)`` trusts **only** the supplied CA anchor when one is given
    (system roots are NOT loaded) — an on-prem SIEM's private cert is anchored explicitly rather than
    silently accepting the public CA bundle. ``forward.tls_verify=False`` is the documented insecure
    opt-out (``CERT_NONE`` + no hostname check); ``tls_client_cert`` adds a client chain for mutual
    TLS. The settings validator guarantees a CA file is present when verification is on, so the default
    path is always CA-anchored + hostname-checked."""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=forward.tls_ca_file)
    if not forward.tls_verify:
        # Insecure opt-out: check_hostname must be cleared before verify_mode (ssl rejects the reverse).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if forward.tls_client_cert is not None:
        # Mutual TLS: a single PEM carrying both the client cert and its key (keyfile defaults to it).
        ctx.load_cert_chain(certfile=forward.tls_client_cert)
    return ctx


class _TlsSysLogHandler(_TimeoutSysLogHandler):
    """A TCP :class:`~logging.handlers.SysLogHandler` whose connected socket is wrapped in TLS (RFC
    5425 syslog-over-TLS). The wrap happens in ``createSocket`` *after* the base handler has connected
    and pinned the socket timeout, so the TLS handshake itself runs under ``_FORWARD_TCP_TIMEOUT`` — a
    collector that completes the TCP connect but stalls the handshake can't block the calling thread
    (the asyncio event loop) indefinitely. A handshake/verification failure raises ``ssl.SSLError``
    (a subclass of ``OSError``), so :func:`configure_logging` treats a bad-cert collector at startup as
    best-effort (skipped with a warning) exactly like an unreachable one."""

    def __init__(
        self, *args: Any, ssl_context: ssl.SSLContext, server_hostname: str, **kwargs: Any
    ) -> None:
        self._ssl_context = ssl_context
        self._server_hostname = server_hostname
        super().__init__(*args, **kwargs)

    def createSocket(self) -> None:
        super().createSocket()  # plain TCP connect + bounded timeout (inherited posture)
        sock = getattr(self, "socket", None)
        if sock is not None:
            # server_hostname drives SNI + hostname verification; harmless when verification is off.
            self.socket = self._ssl_context.wrap_socket(sock, server_hostname=self._server_hostname)


def _make_formatter(fmt: str) -> logging.Formatter:
    """A JSON formatter for ``fmt == "json"``, else the human-readable text formatter (the default)."""
    if fmt == "json":
        return JsonFormatter()
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
    formatter.converter = time.gmtime  # emit UTC timestamps (16.2.2)
    return formatter


def _install_phi_filters(handler: logging.Handler) -> None:
    """Attach the PHI-redaction + control-char-scrub filters to ``handler``.

    Order matters: redact PHI from the raw content first, then scrub control chars from the result.
    Applied to **every** handler (stdout and the off-box forwarder) so the forwarded stream is held to
    the same PHI-safety + log-injection guarantees as stdout. The filters are idempotent, so a record
    dispatched to multiple filtered handlers is safely re-scrubbed."""
    handler.addFilter(RedactionFilter())  # PHI redaction — message + exception traceback (Gate #1)
    handler.addFilter(CredentialQueryScrubFilter())  # OIDC code/state in a URL (ADR 0142 AC-10)
    handler.addFilter(ControlCharScrubFilter())  # log-injection defense (16.4.1)


def _build_syslog_handler(forward: SyslogForward) -> logging.handlers.SysLogHandler:
    """A :class:`logging.handlers.SysLogHandler` for ``forward``. For UDP the socket is created but not
    connected (never fails on a down collector, never blocks on send). For TCP/TLS the constructor
    connects (and, for TLS, completes the handshake) and may raise ``OSError`` if the collector is down
    or its certificate can't be verified at startup (:func:`configure_logging` treats that as best-
    effort — ``ssl.SSLError`` is an ``OSError`` subclass), and a runtime socket timeout
    (``_FORWARD_TCP_TIMEOUT``) is pinned so a stalled collector can't block the calling thread (the
    event loop) indefinitely — emit drops the record."""
    if forward.protocol == "tls":
        return _TlsSysLogHandler(
            address=(forward.host, forward.port),
            socktype=socket.SOCK_STREAM,
            timeout=_FORWARD_TCP_TIMEOUT,
            ssl_context=_build_tls_context(forward),
            server_hostname=forward.host,
        )
    if forward.protocol == "tcp":
        return _TimeoutSysLogHandler(
            address=(forward.host, forward.port),
            socktype=socket.SOCK_STREAM,
            timeout=_FORWARD_TCP_TIMEOUT,
        )
    return logging.handlers.SysLogHandler(
        address=(forward.host, forward.port), socktype=socket.SOCK_DGRAM
    )


def _resolve_level(level: str) -> int:
    resolved = logging.getLevelName(level.upper())
    if not isinstance(resolved, int):
        raise ValueError(f"unknown log level: {level!r}")
    return resolved


def configure_logging(
    level: str = "INFO",
    *,
    fmt: str = "text",
    forward: SyslogForward | None = None,
) -> bool:
    """Install the stdout handler on the root logger, route uvicorn through it, and optionally forward
    a copy of every record off-box to a syslog/SIEM collector. Returns whether the off-box forwarder
    was actually installed (so a caller's "forwarding enabled" log only fires when it is truly live).

    ``fmt`` selects the stdout rendering: ``"text"`` (default, human-readable) or ``"json"`` (one JSON
    object per line). ``forward`` adds a second handler shipping to a remote syslog collector; both
    handlers carry the same PHI-redaction + control-char-scrub filters, so the off-box stream is held
    to the same guarantees as stdout.

    The forwarder is **best-effort, never blocking the engine indefinitely**: UDP is fire-and-forget; a
    TCP collector that is **unreachable at startup** is skipped (the connect error is logged on stdout
    and the service starts without it), and a TCP collector that **stalls at runtime** is bounded by a
    socket timeout (``_FORWARD_TCP_TIMEOUT``) so a wedged SIEM costs at most that per record (the record
    is then dropped) rather than blocking the event-loop thread the engine logs from. The send is still
    synchronous, so for a high-volume feed prefer UDP or a local forwarding agent.

    Idempotent: replaces any handlers a previous call installed, so it is safe to call from tests as
    well as the CLI. Pair with ``uvicorn.run(..., log_config=None)`` so uvicorn's loggers propagate to
    these handlers instead of installing their own.
    """
    numeric = _resolve_level(level)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(_make_formatter(fmt))
    _install_phi_filters(stdout_handler)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(stdout_handler)
    root.setLevel(numeric)

    forwarder_installed = False
    if forward is not None:
        try:
            fwd_handler = _build_syslog_handler(forward)
        except OSError as exc:
            # A down TCP collector would otherwise crash startup at socket-connect time. Warn (now
            # visible on the just-installed stdout handler) and run without the forwarder.
            _log.warning(
                "off-box log forwarding to %s:%d (%s) is unavailable: %s; continuing without it",
                forward.host,
                forward.port,
                forward.protocol,
                exc,
            )
        else:
            fwd_handler.setFormatter(_make_formatter(forward.fmt))
            _install_phi_filters(fwd_handler)
            root.addHandler(fwd_handler)
            forwarder_installed = True

    # Let uvicorn's loggers flow to the root handler(s) (one shared format/stream/forwarder).
    for name in _UVICORN_LOGGERS:
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
        uvicorn_logger.setLevel(numeric)

    silence_phi_prone_dependency_loggers()
    return forwarder_installed


def configure_stderr_logging(level: int = logging.WARNING) -> logging.Handler:
    """Install a **stderr-only** root handler carrying the same PHI-redaction + control-char-scrub
    filter chain :func:`configure_logging` puts on stdout, and return it.

    For a MessageFoundry child process whose **stdout is a binary channel**: today the ADR 0087 sandbox
    worker, whose stdout carries the MFW2 IPC frames, so a stray log byte written there would corrupt a
    frame. The obvious way to express that — ``logging.basicConfig(stream=sys.stderr)`` — gets the
    stream right and the *filters* wrong. It installs a handler with **no filters at all**, and
    redaction here is a property of the **handler**, not of the logger or the call site (see
    :func:`_install_phi_filters`), so a child that builds its own handler builds an unfiltered one
    unless it asks for the chain: its records would reach the stderr the parent captures and relays
    (ADR 0166) with neither PHI redaction nor CR/LF neutralization (BACKLOG #1054). Every process that
    logs installs the chain, or it does not have it.

    The text formatter is the shared one, so a child line is byte-compatible with the parent's and
    :class:`ControlCharScrubFilter`'s "no line may impersonate the record prefix" guarantee is stated
    against the same prefix on both streams.

    Replaces any handlers already on the root logger, exactly as :func:`configure_logging` does, so it
    is idempotent and safe to call from a test.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_make_formatter("text"))
    _install_phi_filters(handler)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    return handler


def set_runtime_level(level: str) -> str:
    """Change the live root + uvicorn log level at runtime (BACKLOG #171, ADR 0130), WITHOUT rebuilding
    handlers — the surgical counterpart of :func:`configure_logging`, which owns the stream/off-box
    handlers + PHI/scrub filters. ``level`` is validated against :data:`LOG_LEVELS` (a ``ValueError`` is
    raised otherwise, so a caller can 4xx a bad value) and applied to the **root logger** and the three
    ``_UVICORN_LOGGERS`` — exactly the level surface ``configure_logging`` sets, so the override re-levels
    whatever handlers are installed (leaving room for a later file handler to build on this cleanly).

    The override is **process-in-memory and ephemeral**: a **process restart** re-runs
    ``configure_logging(settings.logging.level, …)`` and re-asserts the configured baseline, so the
    override is gone; a **``/config/reload`` does NOT re-run ``configure_logging``**, so a runtime override
    **survives a reload** and resets only on restart (ADR 0130 §1). Returns the normalized (upper-case)
    level name applied."""
    normalized = level.upper()
    if normalized not in LOG_LEVELS:
        raise ValueError(f"invalid log level: {level!r}; expected one of {', '.join(LOG_LEVELS)}")
    numeric = _resolve_level(normalized)
    logging.getLogger().setLevel(numeric)
    for name in _UVICORN_LOGGERS:
        logging.getLogger(name).setLevel(numeric)
    return normalized


def current_log_level() -> str:
    """The root logger's current effective level name (``"DEBUG"``…``"CRITICAL"``) — reflects the startup
    ``configure_logging`` baseline or a later :func:`set_runtime_level` override (BACKLOG #171)."""
    return logging.getLevelName(logging.getLogger().level)


def silence_phi_prone_dependency_loggers() -> None:
    """Silence third-party loggers that emit raw HL7 field values (PHI) into the general log.

    ``python-hl7`` (0.4.5) logs the **whole field** at ERROR on benign-but-unmapped escape sequences
    (``hl7/util.py`` ``unescape``: ``"Error decoding value [%s], field [%s]…"``; also a full segment
    line at ``util.py:64``) — a PHI leak hit on every message via :func:`~messagefoundry.parsing.summary.summarize`,
    landing in NSSM's captured stdout/stderr and violating the "never log full bodies at INFO+" rule
    (review finding C-1). Those loggers are named by module ``__file__`` (``getLogger(__file__)``), so
    ``logging.getLogger("hl7")`` does **not** reach them — we match by the package directory instead.

    We drop these records entirely (level ``CRITICAL``): they carry no operational signal the engine
    doesn't already record as an ``ERROR`` disposition with non-PHI text, and they are PHI by
    construction. Idempotent and best-effort (a missing/renamed dependency must never break logging).
    """
    try:
        import hl7
        import hl7.containers  # noqa: F401  (registers its __file__-named logger)
        import hl7.util  # noqa: F401
    except ImportError:
        return
    pkg_dir = os.path.normcase(os.path.dirname(os.path.abspath(hl7.__file__)))
    for name in list(logging.Logger.manager.loggerDict):
        # hl7 names its loggers getLogger(__file__) → an absolute path inside the hl7 package dir.
        if os.path.normcase(name).startswith(pkg_dir):
            logging.getLogger(name).setLevel(logging.CRITICAL)


#: Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01) — RFC 4330.
_NTP_UNIX_EPOCH_DELTA = 2_208_988_800
#: Default bound (seconds) on the startup SNTP probe so a silent/absent peer never blocks serve().
_SNTP_TIMEOUT = 2.0


def query_sntp_offset(peer: str, *, port: int = 123, timeout: float = _SNTP_TIMEOUT) -> float:
    """Query an SNTP server (RFC 4330) and return the local-minus-server clock offset, in seconds.

    A minimal stdlib UDP SNTP client (no new dependency): send a 48-byte client request, read the
    server's *transmit* timestamp from the reply, and return how far the local clock leads (positive)
    or lags (negative) the peer. **Bounded + best-effort:** the socket carries ``timeout`` so a silent
    or absent peer raises ``socket.timeout`` (a subclass of ``OSError``) instead of blocking. This
    powers the opt-in startup clock-sync gate (ASVS 16.2.2) only — it is never on the message path, and
    SNTP is unauthenticated (a coarse drift check for a trusted management network, not NTS).

    Raises ``OSError`` (incl. ``socket.timeout``/``socket.gaierror``) if the peer can't be reached or
    returns a short/invalid reply."""
    request = b"\x1b" + 47 * b"\x00"  # LI=0, VN=3, Mode=3 (client); remaining fields zero
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request, (peer, port))
        data, _ = sock.recvfrom(48)
    if len(data) < 48:
        raise OSError(f"short SNTP reply from {peer!r}: {len(data)} bytes")
    # Transmit timestamp is bytes 40..47: 32-bit seconds (NTP epoch) + 32-bit fractional seconds.
    seconds = int.from_bytes(data[40:44], "big")
    fraction = int.from_bytes(data[44:48], "big") / 2**32
    server_unix = (seconds - _NTP_UNIX_EPOCH_DELTA) + fraction
    return time.time() - server_unix
