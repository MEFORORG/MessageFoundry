# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Process-wide logging setup for the engine service.

Stdlib ``logging`` only (no structlog): a stdout stream handler with a timestamped text format by
default, optionally **structured JSON** (one object per line, ``[logging].format = "json"``), with
uvicorn's own loggers routed through the same handler. When the engine runs under NSSM as a Windows
service, NSSM captures stdout/stderr to rotating files, so we add **no file handler by default** — the
supervisor owns those files. The one exception is opt-in and engine-owned end to end:
``[logging].file`` adds a second, size-rotating sink the engine itself opens, rotates and rolls
(BACKLOG #122, :mod:`messagefoundry.logging_guard`), and the settings validator refuses a path inside
``[logging].log_dir`` so the supervisor and the engine can never rotate the same file. Every sink is
wrapped in the two-stage write guard: a failed write rolls the sink, and only an unwritable
*replacement* stops this process's connections.
A copy of every record can also be **forwarded off-box** to a syslog/SIEM collector
(``[logging].forward_*``; sec-offbox-log, ASVS 16.x) so log evidence survives a host compromise; PHI
redaction + control-char scrubbing apply to the forwarded stream exactly as to stdout. The off-box
transport is UDP (RFC 5426), plaintext TCP (RFC 6587), or **native TLS** (RFC 5425 — an ``ssl``-wrapped
TCP socket, ADR 0080), so evidence can be encrypted on the wire without a local forwarding agent. That
socket is reached through a **bounded hand-off queue drained by its own thread**
(:class:`_ForwardQueueHandler`), so the network send never runs on the thread that logged the record.

This module also exposes :func:`query_sntp_offset`, the bounded stdlib SNTP probe behind the opt-in
startup clock-sync gate (``[logging].require_time_sync``; ASVS 16.2.2) — cross-host log correlation
depends on synchronized clocks. The gate's *policy* (warn vs refuse) lives in ``__main__.serve``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import logging.handlers
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from messagefoundry.config.tls_policy import harden_cipher_suites

# A LEAF MODULE, imported for its DEFINITION rather than its behaviour (BACKLOG #1273). controlchars
# imports nothing from this package, so there is no cycle -- checked by import, not assumed.
from messagefoundry.controlchars import _is_control_char
from messagefoundry.logging_guard import (
    GuardedFileHandler,
    GuardedStreamHandler,
    LogWriteGuard,
    set_active_guard,
)
from messagefoundry.redaction import redact

# THE OTHER LEAF IMPORTED FOR ITS DEFINITION (BACKLOG #1478): the credential-label vocabulary, held in
# one place so the write-time filters here and the read-time support-bundle redactor cannot disagree
# about what a credential looks like. Stdlib ``re`` only, so no cycle. Deliberately NOT the engine's
# credential REGISTRIES, which ``config/settings.py`` holds -- that module imports LOG_LEVELS from
# here, so the dependency must not go the other way.
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials

__all__ = [
    "LogFile",
    "build_stderr_handler",
    "configure_logging",
    "configure_stderr_logging",
    "ensure_logger_sink",
    "set_runtime_level",
    "current_log_level",
    "silence_phi_prone_dependency_loggers",
    "scrub_control_chars",
    "ControlCharScrubFilter",
    "RedactionFilter",
    "JsonFormatter",
    "CredentialQueryScrubFilter",
    "CredentialScrubFilter",
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
#
# THE ALPHABET IS controlchars._is_control_char's, MINUS TAB (BACKLOG #1273, limb 3). It used to be
# re-derived here as `range(0x20)` plus a separate `0x7F` line -- a second statement of the same set
# in a codebase whose controlchars module exists precisely to state it once. The two agreed, so
# nothing was mis-escaped; the cost is the future-tense one #1239 named and #1253 acted on, that a
# later widening applied to one copy silently does not apply to the other.
#
# THE SUBTRACTION IS THE POINT, so it is written as one. Documenting this as "excluded" and leaving
# the copy was considered and is refuted by the residual block on #1273: the parsing/sniff.py
# carve-out earns its separate definition by being BYTE-wise and subtracting a whole allowlist,
# while this is CHARACTER-wise, escapes CR/LF rather than tolerating them, and differs by EXACTLY
# ONE code point. Measured: controlchars 33 code points, this table 32, symmetric difference {0x09}.
# One code point of divergence is a subtraction, not a different predicate.
_CTRL_TRANSLATION: dict[int, str] = {0x0A: "\\n", 0x0D: "\\r"}
# RANGE 0x100, NOT 0x80, AND THAT IS THE DIFFERENCE BETWEEN A REAL FOLD AND A COSMETIC ONE. The
# alphabet is C0+DEL today, so both bounds produce the identical 32 entries -- proved by the
# byte-identity check in the commit. But `_is_control_char`'s docstring names widening to C1
# (U+0080-U+009F) as the deliberate change this shared module exists to make cheap, and a 0x80 bound
# would silently NOT follow it: the escape table would keep the old alphabet while every other call
# site moved, which is the exact two-copy drift limb 3 removes. Iterating past the current boundary
# costs 128 predicate calls at import and makes the widening propagate by construction.
for _i in range(0x100):
    # TAB IS THE ONLY SUBTRACTION and test_tab_is_the_only_control_character_left_intact pins it.
    # CR/LF are excluded from this loop because they get readable escapes above, not because they
    # are tolerated -- they are the injection vector this whole table exists for.
    if _is_control_char(chr(_i)) and _i not in (0x09, 0x0A, 0x0D):
        _CTRL_TRANSLATION[_i] = f"\\x{_i:02x}"

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
    the ADR 0176 sandbox stderr relay. Idempotent: the escaped forms contain no control characters."""
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


def _rewrite_record(
    record: logging.LogRecord,
    scrub: Callable[[str], str],
    *,
    block: Callable[[str], str] | None = None,
) -> None:
    """Apply ``scrub`` to every field of ``record`` that reaches a sink: the rendered message, and the
    two blocks ``Formatter.format`` appends VERBATIM (``exc_text``, ``stack_info``).

    THE WALK IS SHARED BECAUSE THE OMISSION WAS INVISIBLE WHILE IT WAS NOT (BACKLOG #1478). Three
    filters had hand-copied this body and the fourth, :class:`CredentialQueryScrubFilter`, had only
    the message half -- so an OIDC authorization code inside a traceback was scrubbed by nothing,
    and no reviewer comparing four separate ``filter`` methods would see the field that was missing
    from one of them. With one walk it cannot be written.

    ``block`` scrubs the two multi-line fields when they need different treatment from the rendered
    message; it defaults to ``scrub``. Only :class:`ControlCharScrubFilter` needs it: a traceback's
    line breaks must SURVIVE while every line is indented, which is a different function from the
    one that collapses a single rendered line.

    ``record.args`` is cleared whenever ``msg`` is rewritten, so the formatter cannot re-apply ``%``
    substitution to text that no longer carries the placeholders. A record that needed no change
    keeps its lazy ``msg``/``args`` untouched."""
    message = record.getMessage()
    scrubbed = scrub(message)
    if scrubbed != message:
        record.msg = scrubbed
        record.args = ()
    scrub_block = block if block is not None else scrub
    if record.exc_text:
        record.exc_text = scrub_block(record.exc_text)
    if record.stack_info:
        record.stack_info = scrub_block(record.stack_info)


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
        # The rendered message is only half the record: ``Formatter.format`` appends ``exc_text`` and
        # ``stack_info`` VERBATIM, so a CR/LF inside an exception message forged a whole line on the
        # text sink (BACKLOG #335). ``RedactionFilter`` is installed first and renders ``exc_info``
        # into ``exc_text``, so both fields are already populated when this filter runs.
        _rewrite_record(record, scrub_control_chars, block=_scrub_block)
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
#:
#: **``content`` and ``field_value`` are deliberately absent, and this tuple sits two tokens from
#: containing them** (BACKLOG #1184, ASVS 14.2.1). That is a ruled state, not an omission; the ruling
#: and its reasoning are ``docs/PHI.md`` §7 and this comment does not restate them. What stops the
#: two-token edit landing quietly is
#: ``tests/test_logging.py::test_an_undeclared_phi_needle_is_not_scrubbed_from_the_access_line``.
#: **Cite the ruling, not this sentence.**
_CREDENTIAL_QUERY_KEYS = ("code", "state", "id_token", "access_token", "token", "session_state")

_CREDENTIAL_QUERY_RE = re.compile(
    r"(?i)\b(" + "|".join(_CREDENTIAL_QUERY_KEYS) + r")=[^&\s\"']+",
)


def _scrub_credential_query(text: str) -> str:
    """Replace each credential-bearing query parameter's VALUE, keeping the parameter name.

    ``CREDENTIAL_PLACEHOLDER`` rather than a second literal ``<redacted>``: one log line must not be
    able to carry two spellings of "a credential was here", and a hand-copied literal is how it
    would."""
    return _CREDENTIAL_QUERY_RE.sub(lambda m: f"{m.group(1)}={CREDENTIAL_PLACEHOLDER}", text)


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

    It reached ONLY the rendered message until BACKLOG #1478, so an authorization ``code`` inside an
    exception traceback was scrubbed by nothing. That was not a decision — it was a hand-copied record
    walk missing one field, which is why the walk is now :func:`_rewrite_record` and shared.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        _rewrite_record(record, _scrub_credential_query)
        return True


class CredentialScrubFilter(logging.Filter):
    """Redact credential VALUES from every emitted record -- the rendered **message**, the formatted
    **exception traceback**, and ``stack_info`` -- via
    :func:`~messagefoundry.secretscrub.scrub_credentials` (BACKLOG #1478).

    THE GAP THIS CLOSES. Before it, the three filters :func:`_install_phi_filters` installed carried no
    credential vocabulary between them: seven engine credential shapes passed all three verbatim, with
    the OIDC ``code``/``state`` control scrubbing in the same run.
    ``tests/test_logging_credential_scrub.py`` holds that measurement and the fixtures it was taken
    with; :mod:`messagefoundry.secretscrub` holds the vocabulary and the boundary against
    :class:`CredentialQueryScrubFilter`, which is scoped to a URL query string and stays separate.

    ORDER. Installed **after** :class:`RedactionFilter` and **before**
    :class:`ControlCharScrubFilter`. After, because ``RedactionFilter`` is what renders ``exc_info``
    into ``exc_text`` and clears it -- running first would leave the realistic vector, a connection
    error whose traceback carries a DSN, entirely uncovered. Before, because ``ControlCharScrubFilter``
    must stay last (its own docstring says so)."""

    def filter(self, record: logging.LogRecord) -> bool:
        _rewrite_record(record, scrub_credentials)
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


#: Socket timeout (seconds) pinned on a **TCP** off-box forwarder.
#:
#: The send now runs on the forwarder's own listener thread (:class:`_ForwardQueueHandler`), never on
#: the thread that logged the record, so this timeout no longer stands between a stalled collector and
#: the engine's event loop — the queue does. It still bounds two things that would otherwise be
#: unbounded. **The drain:** an unbounded blocking ``sendall`` to a stalled-but-connected collector
#: (TCP back-pressure / a wedged SIEM) would park the listener for good, so the hand-off queue would
#: fill and the engine would drop records it could otherwise have shipped. **Shutdown:**
#: :meth:`_ForwardQueueListener.stop_within` waits out at most one in-flight send, and an unbounded one
#: would hold process exit open.
#:
#: On the timeout ``SysLogHandler.emit`` raises ``socket.timeout`` and routes it to ``handleError``,
#: which loses that record and drops the socket so the next one reconnects (see
#: :meth:`_TimeoutSysLogHandler.handleError`). UDP is connectionless (fire-and-forget) and needs no
#: timeout. Off-box forwarding is best-effort by design; a collector that never drains is a collector
#: that loses records, and the drop is reported rather than silent.
_FORWARD_TCP_TIMEOUT = 5.0

#: Depth of the hand-off queue between the engine's threads and the forwarder's listener thread.
#: Bounded on purpose: unbounded, a long collector outage becomes unbounded memory growth, which is a
#: worse failure than losing log lines. Sized an order of magnitude above
#: ``pipeline.alert_sinks._MAX_QUEUE`` because that queue carries rare operator alerts while this one
#: carries ordinary log traffic — at a few hundred bytes of rendered text per record this holds single-
#: digit megabytes at full depth.
#:
#: **The count-and-log invariant (CLAUDE.md §2) is not in play here.** That invariant governs received
#: *messages*, which are persisted before the ACK and never accepted-and-dropped. A log record is not a
#: message. Dropping one under back-pressure is a legitimate choice for this queue in a way that
#: dropping a message never is — provided the drop is **reported**, which
#: :meth:`_ForwardQueueHandler.enqueue` is what makes true.
_FORWARD_QUEUE_MAXSIZE = 10_000

#: Seconds :meth:`_ForwardQueueHandler.close` gives the listener to drain what is already queued before
#: it starts discarding the remainder. Shutdown must not hang on a wedged collector one send at a time.
_FORWARD_DRAIN_TIMEOUT = 5.0

#: Minimum seconds between two "records were dropped" warnings. The drop report is **itself a log
#: record**, so one per drop would be self-amplifying during the exact outage it reports on. This is
#: the one place this queue must not behave like ``alert_sinks._BackgroundDispatcher``, which warns per
#: dropped item because an alert is a rare, operator-facing event rather than log traffic.
_FORWARD_DROP_REPORT_INTERVAL = 60.0

#: How many queued records :meth:`_ForwardQueueListener.enqueue_sentinel` will discard to make room for
#: the stop sentinel before giving up and letting the bounded join report the thread instead.
_SENTINEL_PUT_ATTEMPTS = 100


class _TimeoutSysLogHandler(logging.handlers.SysLogHandler):
    """:class:`~logging.handlers.SysLogHandler` that pins a socket timeout on its socket — including on
    any reconnect inside ``emit`` — so a runtime send to a stalled TCP collector can't park the calling
    thread indefinitely. That thread is the forwarder's listener thread (:class:`_ForwardQueueHandler`);
    :data:`_FORWARD_TCP_TIMEOUT` says what the bound still buys once the send is off the event loop.

    It also makes ``emit``'s reconnect branch reachable — see :meth:`handleError`."""

    #: ANNOTATION ONLY (no value), so nothing is created at runtime and the base class's own attribute
    #: is inherited untouched. ``SysLogHandler.socket`` is set at runtime and is absent from typeshed,
    #: so without this line the checker infers the attribute's type from the first assignment it finds
    #: in this class — ``None`` in :meth:`handleError` — and then rejects the ``SSLSocket`` the TLS
    #: subclass legitimately assigns. ``Any`` states the runtime truth instead of encoding one arm.
    socket: Any

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

    def handleError(self, record: logging.LogRecord) -> None:
        """Drop the socket after a network error, so the **next** record reconnects (BACKLOG #1199).

        ``SysLogHandler.emit`` reconnects only under ``if not self.socket``, and it never clears
        ``self.socket`` when a send fails. On the shipped handler a stream forwarder that broke
        mid-run would therefore stay broken for the life of the process, and silently: ``emit``
        swallows the error through this method. Clearing the socket here is the whole of what turns
        that dead branch back into a reconnect loop.

        **Only an ``OSError`` resets it.** ``handleError`` also fires for a formatting error, which is
        not the socket's fault; reconnecting on one would buy nothing and would hide the real bug.

        A collector that is down then costs one bounded connect attempt per record. That is paid on
        the listener thread, and the bounded queue is what stops it costing anything else: it fills,
        and :meth:`_ForwardQueueHandler.enqueue` reports the drops. A backoff between attempts, and
        the on-disk spool that would let an outage survive at all, stay open on BACKLOG #1199.
        """
        if isinstance(sys.exception(), OSError):
            sock = getattr(self, "socket", None)
            if sock is not None:
                self.socket = None  # cleared first; a concurrent emit must not use a closing socket
                # Already-broken sockets raise here. Closing was housekeeping; the point (stop reusing
                # it) is achieved above, and logging from inside the logging error path would recurse.
                with contextlib.suppress(OSError):
                    sock.close()
        super().handleError(record)


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
    # Assert forward secrecy LAST, so it sees the final suite list (ASVS 12.1.2). This runs on the
    # tls_verify=False arm too: that opt-out drops peer AUTHENTICATION, and the log records still cross
    # the network encrypted, so the suite list still decides whether a recorded session stays private.
    harden_cipher_suites(ctx, connector="syslog TLS forwarder")
    return ctx


class _TlsSysLogHandler(_TimeoutSysLogHandler):
    """A TCP :class:`~logging.handlers.SysLogHandler` whose connected socket is wrapped in TLS (RFC
    5425 syslog-over-TLS). The wrap happens in ``createSocket`` *after* the base handler has connected
    and pinned the socket timeout, so the TLS handshake itself runs under ``_FORWARD_TCP_TIMEOUT`` — a
    collector that completes the TCP connect but stalls the handshake can't park the calling thread
    (the forwarder's listener thread) indefinitely. A handshake/verification failure raises
    ``ssl.SSLError`` (a subclass of ``OSError``), so :func:`configure_logging` treats a bad-cert
    collector at startup as best-effort (skipped with a warning) exactly like an unreachable one."""

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
    """Attach the PHI-redaction, credential-scrub and control-char-scrub filters to ``handler``.

    Order matters: redact PHI from the raw content first (which also renders ``exc_info`` into
    ``exc_text``, so the credential passes have a traceback to read), scrub credentials from the
    result, then scrub control chars last. Applied to **every** handler a logger carries (stdout,
    stderr, and the off-box forwarder's queue handler) so the forwarded stream is held to the same
    PHI-safety, secret-safety and log-injection guarantees as stdout. The filters are idempotent, so
    a record dispatched to multiple filtered handlers is safely re-scrubbed.

    For the forwarder this means the **queue** handler, on the near side of the hand-off, and the
    socket handler behind it carries no chain of its own — see :class:`_ForwardQueueHandler`, which is
    where that placement is argued."""
    handler.addFilter(RedactionFilter())  # PHI redaction — message + exception traceback (Gate #1)
    handler.addFilter(CredentialQueryScrubFilter())  # OIDC code/state in a URL (ADR 0142 AC-10)
    handler.addFilter(CredentialScrubFilter())  # credential labels + values (BACKLOG #1478)
    handler.addFilter(ControlCharScrubFilter())  # log-injection defense (16.4.1)


def _build_syslog_handler(forward: SyslogForward) -> logging.handlers.SysLogHandler:
    """A :class:`logging.handlers.SysLogHandler` for ``forward``. For UDP the socket is created but not
    connected (never fails on a down collector, never blocks on send). For TCP/TLS the constructor
    connects (and, for TLS, completes the handshake) and may raise ``OSError`` if the collector is down
    or its certificate can't be verified at startup (:func:`configure_logging` treats that as best-
    effort — ``ssl.SSLError`` is an ``OSError`` subclass), and a runtime socket timeout
    (``_FORWARD_TCP_TIMEOUT``) is pinned so a stalled collector can't park the listener thread
    indefinitely — that record is lost and the socket is dropped for a reconnect.

    The handler this returns is **not** attached to a logger directly. :func:`configure_logging` puts
    it behind :class:`_ForwardQueueHandler`, which is what keeps the send off the caller's thread.

    **The UDP arm stays the plain stdlib handler**, deliberately. Its socket is unconnected and it
    sends with ``sendto``, so there is no connection to lose mid-run and nothing for
    :meth:`_TimeoutSysLogHandler.handleError`'s reconnect to repair; the permanent-break defect that
    override closes is a stream-socket defect."""
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


class _ForwardQueueListener(logging.handlers.QueueListener):
    """The thread that owns the off-box socket. It takes rendered lines off the hand-off queue and
    hands them to the syslog handler, so every blocking network call belongs to this thread and to no
    other. :class:`_ForwardQueueHandler` is the near side and carries the reasoning for the split.

    Two stdlib behaviours are replaced because both fail on exactly the queue this design bounds.
    ``enqueue_sentinel`` uses ``put_nowait``, which raises on a **full** queue; and ``stop`` joins
    without a timeout, which on a wedged collector never returns."""

    #: Annotation only — the stdlib's own ``_sentinel = None`` is inherited untouched. Typeshed does
    #: not declare it, and :meth:`enqueue_sentinel` has to name it.
    _sentinel: Any

    def __init__(self, records: queue.Queue[Any], target: logging.Handler) -> None:
        super().__init__(records, target)
        #: The same object as ``self.queue``, typed. Typeshed narrows ``QueueListener.queue`` to a
        #: put-only protocol, and :meth:`enqueue_sentinel` needs ``get_nowait`` to make room.
        self._records = records
        #: Set by :meth:`stop_within`. Past it a still-queued record is counted and discarded rather
        #: than sent, so shutdown cannot be held open one bounded send at a time.
        self._drain_deadline: float | None = None
        #: Records the deadline above discarded. :meth:`_ForwardQueueHandler.close` reports it.
        self.undrained = 0
        #: Whether the stop sentinel is on the queue and not yet consumed. The sentinel occupies a
        #: slot, so ``qsize`` counts it — and the shutdown report would claim one more lost record
        #: than there is. Tracked rather than inferred.
        self._sentinel_queued = False

    def handle(self, record: logging.LogRecord) -> None:
        deadline = self._drain_deadline
        if deadline is not None and time.monotonic() >= deadline:
            self.undrained += 1
            return
        super().handle(record)

    def dequeue(self, block: bool) -> Any:
        record = super().dequeue(block)
        if record is self._sentinel:
            self._sentinel_queued = False
        return record

    def undelivered(self) -> int:
        """A **floor** on the records that did not reach the collector: what the drain deadline
        discarded, plus what is still on the queue, minus the sentinel's slot. A record already
        inside the target's ``emit`` is in neither count, which is why this is a floor."""
        pending = self._records.qsize() - (1 if self._sentinel_queued else 0)
        return max(0, self.undrained + pending)

    def enqueue_sentinel(self) -> None:
        """Put the stop sentinel on the queue **even when it is full**, by discarding queued records
        to make room.

        The stdlib's ``put_nowait`` raises ``queue.Full`` here, and a full queue is precisely the
        state a collector outage produces — so the shipped call would raise out of ``stop`` during
        shutdown and leave the listener thread running with its socket open. Losing a record already
        destined for a collector that is not draining costs nothing that the drop report has not
        already accounted for."""
        for _ in range(_SENTINEL_PUT_ATTEMPTS):
            try:
                self._records.put_nowait(self._sentinel)
                self._sentinel_queued = True
                return
            except queue.Full:
                # Empty may fire if another thread drained it between the two calls; the retry fits.
                with contextlib.suppress(queue.Empty):
                    self._records.get_nowait()
        # Out of attempts: a producer is refilling faster than this loop empties. Fall through — the
        # bounded join below reports the surviving thread rather than blocking on it.

    def stop_within(self, timeout: float) -> bool:
        """Drain for at most ``timeout`` seconds, then stop. Returns whether the thread actually ended.

        The join allows the drain window plus one :data:`_FORWARD_TCP_TIMEOUT`, because a send may
        already be in flight when the deadline is set and nothing can shorten that one; every record
        behind it is discarded by :meth:`handle` without touching the socket. The thread is a daemon
        (the stdlib makes it one), so a ``False`` here delays nothing at interpreter exit — it means
        the queued tail did not reach the collector, which is what the caller reports."""
        thread = self._thread
        if thread is None:
            return True
        self._drain_deadline = time.monotonic() + timeout
        self.enqueue_sentinel()
        thread.join(timeout + _FORWARD_TCP_TIMEOUT + 1.0)
        if thread.is_alive():
            return False
        self._thread = None
        return True


class _ForwardQueueHandler(logging.handlers.QueueHandler):
    """The near side of the off-box hand-off: the only forwarder handler a logger ever carries.

    **Why it exists.** The engine logs synchronously from asyncio workers on the event-loop thread.
    Attached directly, the syslog handler's ``sendall`` to a stalled-but-connected collector would run
    on that thread, so on a first deployment a wedged SIEM would cost the whole event loop up to
    :data:`_FORWARD_TCP_TIMEOUT` per record — and then lose the record anyway. This handler enqueues
    instead, and :class:`_ForwardQueueListener` does the sending on its own thread.

    **The filter chain is on THIS side of the queue, and that placement is the load-bearing decision.**
    :func:`_install_phi_filters` runs on the caller's thread, inline, before anything is enqueued, so
    what the queue holds is already redacted, credential-scrubbed and control-char-escaped. Filters on
    the far side would put PHI-bearing records into an in-memory queue — and into any later on-disk
    spool — unredacted, which is the opposite of what the chain is for. Two smaller consequences fall
    out the same way and both matter:

    * ``QueueHandler.prepare`` clears ``exc_info``/``exc_text``/``stack_info`` after formatting, so a
      :class:`RedactionFilter` on the far side would find no traceback left to redact. Its exception
      limb, which is the realistic PHI vector, would be dead.
    * A far-side chain would re-redact an already-rendered line. On the JSON format that is a known
      framing defect (an HL7-shaped run inside the rendered object reads as a segment and is cut to
      end of line, losing the closing brace), recorded on BACKLOG #1199 as pre-existing on the
      double-redacted audit-tee path. Filtering once, near side, does not reproduce it here.

    **The formatter is on this side too**, and the socket handler is left with an identity formatter,
    so the object on the queue is the exact line that goes on the wire. That is the strongest available
    statement about queue contents: not "a record that will be redacted later" but "the redacted text".
    It also keeps the rendering cost exactly where it is today — inline on the caller — so the only
    thing this change moves off that thread is the network.
    """

    def __init__(self, records: queue.Queue[Any], listener: _ForwardQueueListener) -> None:
        super().__init__(records)
        #: The same object as ``self.queue``, typed. Typeshed narrows ``QueueHandler.queue`` to a
        #: put-only protocol, and :meth:`close` needs ``qsize`` to report what it left behind.
        self._records = records
        self._listener = listener
        #: Cleared by :meth:`close` so producers stop refilling and the drain can terminate.
        self._accepting = True
        self._stopped = False
        self._counter_lock = threading.Lock()
        #: Records dropped for a full queue over the life of this handler. Read it for posture.
        self.dropped = 0
        self._dropped_since_report = 0
        self._last_drop_report: float | None = None
        #: Re-entrancy guard: the drop report is a log record that reaches this handler.
        self._reporting = threading.local()

    @property
    def targets(self) -> tuple[logging.Handler, ...]:
        """The handlers on the far side of the queue — the syslog forwarder itself."""
        return tuple(self._listener.handlers)

    def enqueue(self, record: logging.LogRecord) -> None:
        """Hand ``record`` to the listener, or **count and report** it when the queue is full.

        A full queue means the collector is not draining. The choice made here is to drop the
        **newest** record: it is one failed ``put_nowait`` rather than a non-atomic evict-then-insert,
        and it keeps the oldest evidence, which is the part an incident reconstruction needs first to
        establish what happened before the outage. Dropping the oldest would also silently rewrite
        evidence the engine had already accepted.

        The drop is never silent — that is what BACKLOG #1199 objects to — but the warning is rate
        limited to one per :data:`_FORWARD_DROP_REPORT_INTERVAL` and carries the batch count, because
        the report is itself a log record arriving at this same full queue."""
        if not self._accepting:
            self._count_drop()
            return
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self._count_drop()

    def _count_drop(self) -> None:
        with self._counter_lock:
            self.dropped += 1
            self._dropped_since_report += 1
            if getattr(self._reporting, "active", False):
                # We ARE the report. Counting is all we may do here; warning again would recurse.
                return
            now = time.monotonic()
            last = self._last_drop_report
            if last is not None and now - last < _FORWARD_DROP_REPORT_INTERVAL:
                return
            self._last_drop_report = now
            batch, total = self._dropped_since_report, self.dropped
            self._dropped_since_report = 0
        self._reporting.active = True
        try:
            _log.warning(
                "off-box log forwarding dropped %d record(s): the hand-off queue is full (depth %d) "
                "because the collector is not draining it; %d dropped since this process started. "
                "Evidence for this window does not reach the collector.",
                batch,
                _FORWARD_QUEUE_MAXSIZE,
                total,
            )
        finally:
            self._reporting.active = False

    def close(self) -> None:
        """Stop accepting, drain what is queued within :data:`_FORWARD_DRAIN_TIMEOUT`, then close the
        socket handler.

        **No new shutdown path was wired for this.** ``logging.shutdown`` is registered with ``atexit``
        by the standard library and closes every handler it ever handed out, newest first — and this
        handler is built after the syslog handler it wraps, so it drains before that socket closes. One
        hook covers every entry point at once, which a per-entry-point call would not.
        :func:`configure_logging` also calls this on its own previously-installed forwarder, so a
        second call cannot leak a thread and a socket."""
        if self._stopped:
            return
        self._stopped = True
        self._accepting = False
        drained = self._listener.stop_within(_FORWARD_DRAIN_TIMEOUT)
        undelivered = self._listener.undelivered()  # a floor, and the message says so
        for target in self.targets:
            target.close()
        if not drained or undelivered:
            _log.warning(
                "off-box log forwarding shut down with at least %d record(s) undelivered after "
                "%.1fs (listener stopped cleanly: %s); they did not reach the collector.",
                undelivered,
                _FORWARD_DRAIN_TIMEOUT,
                drained,
            )
        super().close()


def _build_queued_forwarder(target: logging.Handler, *, fmt: str) -> _ForwardQueueHandler:
    """Wrap ``target`` in a started :class:`_ForwardQueueListener` and return the handler to attach.

    ``target`` keeps an identity formatter on purpose: the line is rendered on the near side, by the
    formatter installed here, so the far side re-renders nothing. :class:`_ForwardQueueHandler` says
    why both halves of that arrangement matter."""
    target.setFormatter(logging.Formatter("%(message)s"))
    records: queue.Queue[Any] = queue.Queue(maxsize=_FORWARD_QUEUE_MAXSIZE)
    listener = _ForwardQueueListener(records, target)
    handler = _ForwardQueueHandler(records, listener)
    handler.setFormatter(_make_formatter(fmt))
    _install_phi_filters(handler)  # near side — see _ForwardQueueHandler for why that is the point
    listener.start()
    return handler


def _forward_targets(logger: logging.Logger) -> list[logging.Handler]:
    """The off-box handlers reachable from ``logger``, looked up **through** the queue hand-off.

    The forwarder is no longer a handler on the logger — the logger carries the queue handler and the
    socket lives on the listener — so the older
    ``[h for h in root.handlers if isinstance(h, SysLogHandler)]`` returns nothing on a forwarding
    engine. This is the replacement for that idiom."""
    targets: list[logging.Handler] = []
    for handler in logger.handlers:
        if isinstance(handler, _ForwardQueueHandler):
            targets.extend(handler.targets)
    return targets


def _resolve_level(level: str) -> int:
    resolved = logging.getLevelName(level.upper())
    if not isinstance(resolved, int):
        raise ValueError(f"unknown log level: {level!r}")
    return resolved


@dataclass(frozen=True, slots=True)
class LogFile:
    """``[logging].file`` — the OPT-IN application-log file the ENGINE owns end to end (#122, ADR 0162).

    Distinct from ``[logging].log_dir``, which is where the SUPERVISOR (NSSM) parks and rotates the
    captured stdout: the engine opens this path, size-rotates it, and rolls it aside on a write
    failure. The settings validator refuses a ``file`` inside ``log_dir`` so the two rotation owners
    can never collide on one directory (docs/SERVICE.md)."""

    path: str
    max_bytes: int = 50_000_000
    backup_count: int = 5


def configure_logging(
    level: str = "INFO",
    *,
    fmt: str = "text",
    forward: SyslogForward | None = None,
    log_file: LogFile | None = None,
    stop_on_write_failure: bool = True,
) -> bool:
    """Install the stdout handler on the root logger, route uvicorn through it, and optionally forward
    a copy of every record off-box to a syslog/SIEM collector. Returns whether the off-box forwarder
    was actually installed (so a caller's "forwarding enabled" log only fires when it is truly live).

    ``fmt`` selects the stdout rendering: ``"text"`` (default, human-readable) or ``"json"`` (one JSON
    object per line). ``forward`` adds a second handler shipping to a remote syslog collector; both
    handlers carry the same PHI-redaction + control-char-scrub filters, so the off-box stream is held
    to the same guarantees as stdout.

    The forwarder is **best-effort and never blocks the engine**: UDP is fire-and-forget; a TCP
    collector that is **unreachable at startup** is skipped (the connect error is logged on stdout and
    the service starts without it); and the send itself runs on the forwarder's own listener thread
    (:class:`_ForwardQueueHandler`), so a collector that **stalls at runtime** costs the engine's
    threads nothing at all. A stalled collector instead fills a bounded hand-off queue, and records
    that no longer fit are dropped **with a rate-limited warning** rather than silently.

    That is the durability half of BACKLOG #1199. **Two pieces of it are not built:** there is no
    on-disk spool, so records queued at process exit or dropped for a full queue are gone; and the
    reconnect (:meth:`_TimeoutSysLogHandler.handleError`) retries per record with no backoff.

    ``log_file`` adds the OPT-IN engine-managed application-log file (``[logging].file``, #122/ADR
    0162) alongside stdout. Unlike the forwarder it is **NOT best-effort**: a path the engine cannot
    open raises here, so the service refuses to start rather than starting unable to log — the same
    fail-closed reasoning as ``stop_on_write_failure`` itself, applied at configuration time.

    Both sinks are wrapped in the two-stage write guard
    (:mod:`~messagefoundry.logging_guard`): a write failure rolls the sink and heals; only an
    unwritable *replacement* escalates, and ``stop_on_write_failure`` decides whether that escalation
    stops this process's connections. The guard is installed process-wide
    (:func:`~messagefoundry.logging_guard.set_active_guard`); the engine's ``RegistryRunner`` wires
    itself to it at start, so a process with no engine (a CLI subcommand, a test) rolls and reports on
    stderr but stops nothing.

    Idempotent: replaces any handlers a previous call installed, so it is safe to call from tests as
    well as the CLI. Pair with ``uvicorn.run(..., log_config=None)`` so uvicorn's loggers propagate to
    these handlers instead of installing their own.
    """
    numeric = _resolve_level(level)

    guard = LogWriteGuard(stop_on_unwritable=stop_on_write_failure)
    stdout_handler = GuardedStreamHandler(sys.stdout, guard=guard, sink="stdout")
    stdout_handler.setFormatter(_make_formatter(fmt))
    _install_phi_filters(stdout_handler)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
        if isinstance(existing, _ForwardQueueHandler):
            # OURS, and it owns a live thread and an open socket, so removing it is not enough. Only
            # ours is closed: a handler this function did not install is removed, never closed, since
            # a caller (pytest, an embedding host) may still be using it.
            existing.close()
    root.addHandler(stdout_handler)
    root.setLevel(numeric)

    if log_file is not None:
        # No try/except: an OSError here means the operator named a path the engine cannot write, and
        # starting anyway would ship exactly the silent blindness #122 exists to end.
        file_handler = GuardedFileHandler(
            log_file.path,
            guard=guard,
            sink="file",
            max_bytes=log_file.max_bytes,
            backup_count=log_file.backup_count,
        )
        file_handler.setFormatter(_make_formatter(fmt))
        _install_phi_filters(file_handler)
        root.addHandler(file_handler)

    # Published LAST, so a concurrently-starting engine never wires itself to a half-built guard.
    set_active_guard(guard)

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
            # The formatter and the PHI filter chain go on the QUEUE handler, not on fwd_handler.
            # _ForwardQueueHandler carries the reasoning; the short form is that a record must be
            # redacted before it is queued, not after.
            root.addHandler(_build_queued_forwarder(fwd_handler, fmt=forward.fmt))
            forwarder_installed = True

    # Let uvicorn's loggers flow to the root handler(s) (one shared format/stream/forwarder).
    for name in _UVICORN_LOGGERS:
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
        uvicorn_logger.setLevel(numeric)

    silence_phi_prone_dependency_loggers()
    return forwarder_installed


def build_stderr_handler() -> logging.Handler:
    """A **stderr** handler carrying the shared text formatter and the PHI-redaction + control-char-
    scrub filter chain — the single definition of "a MessageFoundry log sink on stderr".

    Redaction here is a property of the **handler**, not of the logger or the call site (see
    :func:`_install_phi_filters`), so anything that builds its own stderr handler builds an
    *unfiltered* one unless it asks for the chain. At least two callers need one:
    :func:`configure_stderr_logging`, for a process whose stdout is a binary channel, and
    :func:`ensure_logger_sink`, for a process that installed no handler at all. Stating the chain
    once means they cannot drift apart.

    The handler level is left at ``NOTSET`` — matching the handlers :func:`configure_logging`
    installs, so a record's only level gate is its logger's. ``sys.stderr`` is bound at build time,
    exactly as :func:`configure_logging` binds ``sys.stdout``.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_make_formatter("text"))
    _install_phi_filters(handler)
    return handler


def _fallback_sink_name(logger: logging.Logger) -> str:
    """The handler name :func:`ensure_logger_sink` tags its own sink with, derived from ``logger``.

    Deliberately **not** spelled "last resort", though that is what it is: this package already has a
    ``messagefoundry.last_resort`` logger for excepthook reporting, and the standard library has
    ``logging.lastResort``. Three unrelated things under one grep is the adjacent-name confusion
    CLAUDE.md §11 keeps apart by rule.
    """
    return f"{logger.name}.fallback-sink"


def ensure_logger_sink(logger: logging.Logger) -> None:
    """Guarantee the next record on ``logger`` reaches a handler, in a process that configured none
    (BACKLOG #1199). Idempotent, and self-removing once the process configures a real sink.

    **The defect this closes.** Only two call sites in the package install a root handler — the
    ``serve`` and ``supervise`` subcommands, both in :mod:`messagefoundry.__main__`. Every other
    subcommand runs with an EMPTY root handler list, and ``logging.lastResort`` is WARNING-only, so
    an INFO record is dropped outright rather than degraded. The measured instance is the off-box
    audit tee (:mod:`messagefoundry.store.audit_tee`), whose whole purpose is that a copy of every
    audit record leaves the box.

    **What it does.** Takes our own handler off ``logger``, then asks ``logging.Logger.hasHandlers``
    whether anything else would receive the record. That predicate is not an approximation of the
    question: checked against the interpreter's source, it walks the chain — own handlers, then each
    parent while ``propagate`` holds — with the SAME stop condition ``callHandlers`` uses, so it is
    true exactly when ``callHandlers`` would find at least one handler, which is the condition that
    decides whether the standard library diverts to its last resort. Handler LEVEL is deliberately
    not consulted, for the same reason ``callHandlers`` does not consult it in that count: the
    question is whether the process configured a sink at all, not whether that sink chose to keep
    this record. On false, put ours back — the standard library's idea, at ``NOTSET`` instead of
    WARNING and carrying the PHI filter chain. On true, ours simply stays off.

    Removing first is what lets the standard library answer the question — ``hasHandlers`` cannot be
    told to ignore one handler — and the removed object goes straight back rather than being rebuilt,
    so a handler-less process builds one handler for its lifetime, not one per call.

    **Lazy and per-call, unlike the two shipped patterns**, which are entry-point configuration
    (``pipeline/_sandbox_worker``) and import-time remediation (``parsing/__init__``). Neither works
    here: :func:`configure_logging` clears the **root** logger's handlers and never touches a named
    one, so a sink installed once at import or at an entry point would survive into ``serve`` and
    double-emit for the life of the service. Re-checking is what makes self-removal possible.

    **Stderr, not stdout**, and that is a requirement rather than a preference: subcommands print a
    machine-readable payload to stdout under ``--json``, and a log line there would corrupt the
    document a caller parses.

    **Not a forwarder.** This puts the record in front of an operator and into whatever the service
    manager captures; it does not transmit anything off the host. The durable off-box forwarder, and
    the question of what ASVS 16.4.3 requires beyond it, stay open on BACKLOG #1199.

    Costs nothing on a configured process: it takes the ``hasHandlers`` branch and builds nothing, so
    no new work lands on the event-loop thread a caller may be running on.
    """
    name = _fallback_sink_name(logger)
    ours = [h for h in logger.handlers if h.name == name]
    for handler in ours:
        logger.removeHandler(handler)
    if logger.hasHandlers():
        return
    if ours:
        logger.addHandler(ours[0])
        return
    # Unsynchronized on purpose. Two threads racing here both install, and the loser's handler is
    # dropped on the next call — so the worst case is ONE duplicated line, never a dropped one, and it
    # self-heals. A lock on every call would buy nothing against that, and the shipped processes that
    # reach this branch (the CLI subcommands) are single-threaded anyway.
    handler = build_stderr_handler()
    handler.set_name(name)
    logger.addHandler(handler)


def configure_stderr_logging(level: int = logging.WARNING) -> logging.Handler:
    """Install a **stderr-only** root handler carrying the same PHI-redaction + control-char-scrub
    filter chain :func:`configure_logging` puts on stdout, and return it.

    For a MessageFoundry process whose **stdout is not a log channel**. Two shapes reach here, and the
    second is why this is not sandbox-specific machinery. (1) A child whose stdout is a **binary
    channel**: the ADR 0087 sandbox worker, whose stdout carries the MFW2 IPC frames, so a stray log
    byte written there would corrupt a frame. (2) A **CLI subcommand invoked with ``--json``**, whose
    stdout carries one machine-parsed document; ``__main__.main`` calls this before dispatch and
    carries the measurement (BACKLOG #1489). The obvious way to express either,
    ``logging.basicConfig(stream=sys.stderr)``, gets the stream right and the *filters* wrong: it
    installs a handler with **no filters at all**, so a child's records would reach the stderr the
    parent captures and relays (ADR 0176) with neither PHI redaction nor CR/LF neutralization
    (BACKLOG #1054). :func:`build_stderr_handler` is what supplies the chain and the shared text
    formatter here, and says why that has to be asked for.

    Replaces any handlers already on the root logger, exactly as :func:`configure_logging` does, so it
    is idempotent and safe to call from a test.
    """
    handler = build_stderr_handler()

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
