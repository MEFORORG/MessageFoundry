# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Process-wide logging setup for the engine service.

Stdlib ``logging`` only (no structlog): a stdout stream handler with a timestamped text format by
default, optionally **structured JSON** (one object per line, ``[logging].format = "json"``), with
uvicorn's own loggers routed through the same handler. When the engine runs under NSSM as a Windows
service, NSSM captures stdout/stderr to rotating files, so we deliberately do **not** add file handlers
here. A copy of every record can also be **forwarded off-box** to a syslog/SIEM collector
(``[logging].forward_*``; sec-offbox-log, ASVS 16.x) so log evidence survives a host compromise; PHI
redaction + control-char scrubbing apply to the forwarded stream exactly as to stdout.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any

from messagefoundry.redaction import redact

__all__ = [
    "configure_logging",
    "silence_phi_prone_dependency_loggers",
    "ControlCharScrubFilter",
    "RedactionFilter",
    "JsonFormatter",
    "SyslogForward",
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


class ControlCharScrubFilter(logging.Filter):
    """Neutralize CR/LF and other control characters in the rendered log message to prevent log
    injection / forging (ASVS 16.4.1).

    Untrusted MLLP peer data and HL7-derived exception text reach the general log; without this a
    crafted value containing a newline could inject a forged log line into NSSM's captured stdout.
    We render the message (applying ``%`` args) once, escape any control characters, and only then
    replace ``record.msg`` — clean messages keep their lazy ``msg``/``args`` untouched."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        scrubbed = message.translate(_CTRL_TRANSLATION)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
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

    *Residual:* a bare free-text name a user invents (e.g. ``raise ValueError("DOE^JANE")`` with no
    surrounding segment) is not HL7-shaped and is not caught — the "never put PHI in an exception
    message" convention remains the control for that (see :mod:`messagefoundry.redaction`)."""

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
    not go the other way). ``protocol`` is ``"udp"`` (RFC 5426; fire-and-forget) or ``"tcp"`` (RFC 6587;
    a down collector is tolerated — see :func:`configure_logging`); ``fmt`` is ``"json"`` or ``"text"``
    and is independent of the stdout format."""

    host: str
    port: int = 514
    protocol: str = "udp"
    fmt: str = "json"


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
        super().__init__(*args, **kwargs)  # SysLogHandler.__init__ calls createSocket() (3.11+)

    def createSocket(self) -> None:
        super().createSocket()
        # SysLogHandler.socket is set at runtime (not in typeshed); getattr keeps this mypy-clean
        # across typeshed versions without a fragile per-version type: ignore.
        sock = getattr(self, "socket", None)
        if self._sock_timeout is not None and sock is not None:
            sock.settimeout(self._sock_timeout)


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
    handler.addFilter(ControlCharScrubFilter())  # log-injection defense (16.4.1)


def _build_syslog_handler(forward: SyslogForward) -> logging.handlers.SysLogHandler:
    """A :class:`logging.handlers.SysLogHandler` for ``forward``. For UDP the socket is created but not
    connected (never fails on a down collector, never blocks on send). For TCP the constructor connects
    and may raise ``OSError`` if the collector is down at startup (:func:`configure_logging` treats that
    as best-effort), and a runtime socket timeout (``_FORWARD_TCP_TIMEOUT``) is pinned so a stalled
    collector can't block the calling thread (the event loop) indefinitely — emit drops the record."""
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
