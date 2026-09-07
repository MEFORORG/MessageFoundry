# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for logging setup and the serve ``--log-level`` flag."""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys
import threading
import time
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry import __main__
from messagefoundry.logging_setup import (
    _CREDENTIAL_QUERY_KEYS,
    ControlCharScrubFilter,
    CredentialQueryScrubFilter,
    JsonFormatter,
    RedactionFilter,
    SyslogForward,
    _build_queued_forwarder,
    _forward_targets,
    _ForwardQueueHandler,
    _install_phi_filters,
    _make_formatter,
    configure_logging,
    configure_stderr_logging,
)

#: Synthetic HL7 (never real PHI) embedded in a log record so a redaction assertion has something to
#: find. HL7-shaped, so ``redact`` rewrites the span rather than passing it through.
SYNTHETIC_PHI = "PID|1||100^^^H^MR||DOE^JANE^Q||19800101|F"


@pytest.fixture(autouse=True)
def _restore_root_logger() -> Iterator[None]:
    """configure_logging mutates the global root logger; snapshot and restore it."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_set = set(saved_handlers)
    saved_level = root.level
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            if handler not in saved_set:
                handler.close()  # release sockets (the off-box forwarder) even if a test asserted out
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)


# --- configure_logging -------------------------------------------------------


def test_installs_single_stdout_handler() -> None:
    configure_logging("INFO")
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0], logging.StreamHandler)
    assert root.level == logging.INFO


def test_level_is_case_insensitive() -> None:
    configure_logging("debug")
    assert logging.getLogger().level == logging.DEBUG


def test_idempotent_does_not_stack_handlers() -> None:
    configure_logging("INFO")
    configure_logging("WARNING")
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert root.level == logging.WARNING


def test_unknown_level_raises() -> None:
    with pytest.raises(ValueError):
        configure_logging("LOUD")


def test_routes_uvicorn_loggers_to_root() -> None:
    configure_logging("INFO")
    uvicorn_logger = logging.getLogger("uvicorn.error")
    assert uvicorn_logger.handlers == []
    assert uvicorn_logger.propagate is True


# --- serve --log-level -------------------------------------------------------


# --- C-1: python-hl7 PHI-to-log suppression ----------------------------------


def test_silences_hl7_value_loggers_phi_leak() -> None:
    import hl7
    import hl7.containers  # noqa: F401  (so hl7.containers.__file__ resolves)
    import hl7.util  # noqa: F401

    from messagefoundry.logging_setup import silence_phi_prone_dependency_loggers

    util_logger = logging.getLogger(hl7.util.__file__)
    containers_logger = logging.getLogger(hl7.containers.__file__)
    # Reset to permissive so this proves the silencer, not parsing-import's side effect.
    util_logger.setLevel(logging.NOTSET)
    containers_logger.setLevel(logging.NOTSET)

    silence_phi_prone_dependency_loggers()
    assert util_logger.level == logging.CRITICAL
    assert containers_logger.level == logging.CRITICAL

    # Behavior: an unmapped escape makes python-hl7's unescape() log the WHOLE field at ERROR; with
    # the loggers silenced, no such record (and no PHI) reaches a handler.
    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    root = logging.getLogger()
    handler = _Capture(logging.DEBUG)
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        msg = hl7.parse(
            "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\rPID|1||MRN123||DOE\\Z9\\JANE\r"
        )
        msg.unescape("DOE\\Z9\\JANE")  # → "Error decoding value [Z9], field [DOE\\Z9\\JANE]…"
    finally:
        root.removeHandler(handler)

    leaked = [r for r in captured if "DOE" in r.getMessage() or "JANE" in r.getMessage()]
    assert leaked == [], f"python-hl7 leaked PHI to logs: {[r.getMessage() for r in leaked]}"


# --- serve --log-level -------------------------------------------------------


def test_serve_rejects_unknown_log_level() -> None:
    # argparse choices -> SystemExit(2) before any work happens.
    with pytest.raises(SystemExit):
        __main__.main(["serve", "--log-level", "LOUD"])


def test_serve_applies_log_level(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    import uvicorn

    captured: dict[str, Any] = {}

    # serve imports these lazily, so patch them at the source (looked up at call time).
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare synthetic (env opt-out) to keep PHI gates quiet.
    monkeypatch.setenv("MEFOR_SECURITY_HANDLES_REAL_PATIENT_DATA", "false")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kw))

    rc = __main__.main(
        [
            "serve",
            "--config",
            str(tmp_path),
            "--db",
            str(tmp_path / "x.db"),
            "--env",
            "dev",  # DEBUG is refused in 'prod' (the default env) — Gate #1; dev allows it
            "--log-level",
            "DEBUG",
        ]
    )

    assert rc == 0
    assert logging.getLogger().level == logging.DEBUG
    # uvicorn must defer to our root handler, not install its own.
    assert captured["log_config"] is None


# --- C1: RedactionFilter (PHI scrub of message + exception traceback) ---------

_PHI_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||Z9998887^^^H^MR||DOE^JANE\r"


def _format_with_redaction(record: logging.LogRecord) -> str:
    """Run a record through RedactionFilter (as a handler filter would) and format it like production."""
    RedactionFilter().filter(record)
    return logging.Formatter("%(levelname)s %(name)s: %(message)s").format(record)


def test_redaction_filter_scrubs_hl7_body_from_message() -> None:
    rec = logging.LogRecord("t", logging.WARNING, __file__, 1, "bad message: %s", (_PHI_RAW,), None)
    out = _format_with_redaction(rec)
    assert "DOE" not in out and "JANE" not in out and "Z9998887" not in out
    assert "[redacted]" in out  # HL7 spans were scrubbed, not silently dropped


def test_redaction_filter_scrubs_chained_exception_traceback() -> None:
    # The realistic vector: a Handler raises carrying the body; an outer log.exception renders the full
    # chained traceback. The filter must scrub the body but keep the exception type + non-PHI context.
    try:
        try:
            raise ValueError(f"cannot transform {_PHI_RAW}")  # body in the chained __context__
        except ValueError as inner:
            raise RuntimeError("handler error") from inner
    except RuntimeError:
        rec = logging.LogRecord(
            "t", logging.ERROR, __file__, 1, "transform worker failed", (), sys.exc_info()
        )
    out = _format_with_redaction(rec)
    assert "DOE" not in out and "JANE" not in out and "Z9998887" not in out
    assert "ValueError" in out and "RuntimeError" in out  # exception types kept (useful, non-PHI)
    assert "cannot transform" in out  # the non-PHI prefix survives; only the HL7 body is cut


def test_redaction_filter_leaves_ordinary_messages_unchanged() -> None:
    rec = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "connection %s stopped", ("OB_ACME",), None
    )
    RedactionFilter().filter(rec)
    assert rec.getMessage() == "connection OB_ACME stopped"  # no over-redaction


def test_configure_logging_installs_redaction_filter() -> None:
    configure_logging("INFO")
    handler = logging.getLogger().handlers[0]
    assert any(isinstance(f, RedactionFilter) for f in handler.filters)


def test_redaction_filter_scrubs_bare_field_run() -> None:
    # A field/component dump with ≥2 delimiters but NO segment header must still be caught by the
    # _HL7_FIELD_RUN rule (isolates it from the segment rule so a regression in either is visible).
    rec = logging.LogRecord(
        "t", logging.WARNING, __file__, 1, "bad data: %s", ("100^^^H^MR",), None
    )
    out = _format_with_redaction(rec)
    assert "100^^^H^MR" not in out and "[redacted]" in out


def test_redaction_filter_scrubs_stack_info() -> None:
    rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "stack dump", (), None)
    rec.stack_info = f"Stack (most recent call last):\n  context: {_PHI_RAW}"
    RedactionFilter().filter(rec)
    assert rec.stack_info is not None
    assert "DOE" not in rec.stack_info and "JANE" not in rec.stack_info
    assert "[redacted]" in rec.stack_info


def test_redaction_filter_residual_bare_name_not_caught() -> None:
    # DOCUMENTED RESIDUAL (redaction.py / PHI.md §7): a bare free-text name with <2 HL7 delimiters and
    # no segment header is not HL7-shaped, so the filter does NOT catch it — the "never put PHI in an
    # exception message" convention is the control. Pin the boundary so a future change is deliberate.
    rec = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "invalid patient %s", ("DOE^JANE",), None
    )
    out = _format_with_redaction(rec)
    assert "DOE^JANE" in out  # accepted residual: a single-delimiter bare name passes through


# --- BACKLOG #335: the control-char scrub covers exc_text / stack_info -------

#: A payload shaped exactly like a real record under ``_LOG_FORMAT`` (level padded to eight columns).
_FORGED_RECORD = "2026-08-01T00:00:00Z INFO     messagefoundry.auth: FORGED admin login ok"
#: Matches a line that OPENS with the production record prefix (a UTC stamp at column 0).
_RECORD_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ")


def _production_lines(record: logging.LogRecord) -> list[str]:
    """Render ``record`` the way a text sink does: the production filter chain, in the order
    ``_install_phi_filters`` installs it, then the production text formatter."""
    for scrub in (RedactionFilter(), CredentialQueryScrubFilter(), ControlCharScrubFilter()):
        scrub.filter(record)
    return _make_formatter("text").format(record).split("\n")


def test_control_char_filter_scrubs_exception_traceback() -> None:
    # ADR 0034 §1: ``Formatter.format`` appends exc_text VERBATIM, so a CR/LF inside an exception
    # message used to land a forged record at column 0 on the text sink (stdout/NSSM, and a
    # forward_format="text" collector). Exactly ONE line may open with the record prefix.
    try:
        raise ValueError(f"boom\n{_FORGED_RECORD}")
    except ValueError:
        rec = logging.LogRecord(
            "mefor.demo", logging.ERROR, __file__, 1, "delivery failed", (), sys.exc_info()
        )
    lines = _production_lines(rec)
    assert _RECORD_PREFIX_RE.match(lines[0])  # the real record — proves the matcher can SEE one
    assert [ln for ln in lines[1:] if _RECORD_PREFIX_RE.match(ln)] == []
    assert "FORGED admin login ok" in "\n".join(lines)  # neutralized, not dropped
    assert len(lines) > 3, "the traceback must stay multi-line — readability is the deferred call"


def test_control_char_filter_scrubs_stack_info() -> None:
    # The same vector via stack_info, which the formatter also appends verbatim.
    rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "stack dump", (), None)
    rec.stack_info = f"Stack (most recent call last):\n{_FORGED_RECORD}"
    lines = _production_lines(rec)
    assert [ln for ln in lines[1:] if _RECORD_PREFIX_RE.match(ln)] == []


def test_control_char_block_scrub_is_idempotent() -> None:
    # Every handler carries its OWN chain, so a record dispatched to stdout AND the off-box forwarder
    # is scrubbed twice; a second pass must not re-indent an already-indented block, or the two sinks
    # would print different text for the same record.
    rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "x", (), None)
    rec.exc_text = f"Traceback (most recent call last):\n{_FORGED_RECORD}"
    ControlCharScrubFilter().filter(rec)
    once = rec.exc_text
    ControlCharScrubFilter().filter(rec)
    assert rec.exc_text == once


# --- BACKLOG #1184: the access-log residual, pinned as a measurement ---------

#: A synthetic, non-realistic needle. Never a real or realistic patient identifier (PHI.md).
_SYNTHETIC_NEEDLE = "ZZQ9X7"


def test_an_undeclared_phi_needle_is_not_scrubbed_from_the_access_line() -> None:
    """The residual BACKLOG #1184 (ASVS 14.2.1) leaves open, measured rather than described.

    Uvicorn builds its access line from the raw ASGI ``query_string``
    (``uvicorn/protocols/utils.py::get_path_with_query_string``), never from the parameters a route
    binds. So a hand-crafted ``?content=`` reaches the log even though no GET signature declares it
    any more, and the filter chain does not scrub it.

    **That is a ruled state, not an omission** — the ruling is ``docs/PHI.md`` §7 and this test does
    not restate it. What this holds is the measurement the ruling rests on, the way
    :func:`test_redaction_filter_residual_bare_name_not_caught` holds its own documented residual.
    The ruled-against EDIT is pinned separately, one test below: this assertion reads a *rendering*,
    so it also reds on a control that is not the one #1184 rejected.
    """
    line = f'127.0.0.1:0 - "GET /messages/search?content={_SYNTHETIC_NEEDLE} HTTP/1.1" 200'
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, line, (), None)
    rendered = "\n".join(_production_lines(rec))
    assert f"content={_SYNTHETIC_NEEDLE}" in rendered, (
        "the access line no longer carries an undeclared `content=` verbatim. This is a MEASUREMENT, "
        "not a prohibition. If a name denylist now scrubs it, read BACKLOG #1184 -- that was ruled "
        "against. If a DIFFERENT control landed (an allowlist over query values, say), the ruling "
        "does not reach it: delete this measurement and correct docs/PHI.md section 7."
    )

    # Positive control on a SECOND record: the keys the chain DOES cover are scrubbed, so a green
    # above cannot mean the filters never ran.
    callback = f'127.0.0.1:0 - "GET /ui/oidc/callback?code={_SYNTHETIC_NEEDLE} HTTP/1.1" 302'
    cred = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, callback, (), None)
    assert "code=<redacted>" in "\n".join(_production_lines(cred)), (
        "the credential scrub is inert, so the measurement above is void"
    )


def test_the_phi_needle_names_stay_out_of_the_credential_scrub_list() -> None:
    """The two-token edit BACKLOG #1184 ruled against, pinned at the tuple, not at a rendering.

    The measurement above reds on any control over the access line's query string, including one the
    ruling does not reach. This reds only on the ruled-against edit, so the PAIR discriminates:
    **both red** means a needle name went into the tuple; **the measurement alone** means some other
    control landed, which the ruling does not cover.
    """
    assert not {"content", "field_value"} & set(_CREDENTIAL_QUERY_KEYS), (
        "`content`/`field_value` were added to _CREDENTIAL_QUERY_KEYS. BACKLOG #1184 ruled against a "
        "name denylist here: whoever hand-crafts such a URL also picks the name, so `?patient=` "
        "passes the entry untouched while the entry reads as a protection this log does not have. "
        "The ruling is docs/PHI.md section 7."
    )


# --- C2: prod-DEBUG serve guard ----------------------------------------------


def test_serve_refuses_debug_in_prod(tmp_path: Any) -> None:
    # Gate #1: DEBUG can surface PHI (full bodies / raw fields); serve refuses it fail-closed in a
    # 'prod' environment (the guard returns before configure_logging / uvicorn, so no mocks needed).
    rc = __main__.main(
        [
            "serve",
            "--config",
            str(tmp_path),
            "--db",
            str(tmp_path / "x.db"),
            "--env",
            "prod",
            "--log-level",
            "DEBUG",
        ]
    )
    assert rc == 2


def test_serve_allows_debug_in_staging(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    # The guard is prod-ONLY: staging (which may carry PHI but is an operator's diagnostic env) and dev
    # are allowed to use DEBUG. Proves the condition isn't accidentally widened to staging.
    import uvicorn

    # staging is a PHI environment, so the H3 keyless-start refusal would fire first; configure a key so
    # this test exercises the DEBUG posture (not the keyless gate).
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    # The DEBUG guard is keyed on the production TIER fact (not [security].enforcement) — but under the
    # default enforce a staging PHI instance also refuses at the retention/notify gates (the security
    # dial is decoupled from the tier, GIVEN 2 / ADR 0148). Run at warn to isolate the DEBUG posture (a
    # staging diagnostic env runs at warn); the guard must still ALLOW DEBUG because staging is non-prod.
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    rc = __main__.main(
        [
            "serve",
            "--config",
            str(tmp_path),
            "--db",
            str(tmp_path / "x.db"),
            "--env",
            "staging",
            "--log-level",
            "DEBUG",
        ]
    )
    assert rc == 0


# --- sec-offbox-log: structured JSON + off-box (syslog) forwarding ------------


def test_json_formatter_emits_one_json_object() -> None:
    rec = logging.LogRecord(
        "mefor", logging.INFO, __file__, 1, "connection %s up", ("OB_ACME",), None
    )
    line = JsonFormatter().format(rec)
    assert "\n" not in line  # one object per line — never breaks the framing
    obj = json.loads(line)
    assert obj["level"] == "INFO"
    assert obj["logger"] == "mefor"
    assert obj["message"] == "connection OB_ACME up"
    # Lock the documented UTC shape (not just a trailing 'Z', which is a literal in the format string):
    # a regression to localtime or a layout change must fail here (ASVS 16.2.2).
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", obj["time"])
    assert obj["time"] == time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(rec.created))


def test_json_formatter_escapes_embedded_newlines_keeping_one_line() -> None:
    # The framing guarantee (ASVS 16.4.1) is that json.dumps escapes a hostile newline-bearing value,
    # so one record stays one line. Feed an embedded CR/LF directly (the vacuous case has no newline).
    rec = logging.LogRecord("t", logging.WARNING, __file__, 1, "line1\nline2\rx", (), None)
    line = JsonFormatter().format(rec)
    assert "\n" not in line and "\r" not in line  # framing intact for a hostile value
    assert json.loads(line)["message"] == "line1\nline2\rx"  # round-trips losslessly


def test_json_formatter_redacts_phi_via_filter() -> None:
    # The handler filter runs before the formatter; together they must scrub HL7 PHI and stay valid JSON.
    rec = logging.LogRecord("t", logging.WARNING, __file__, 1, "bad message: %s", (_PHI_RAW,), None)
    RedactionFilter().filter(rec)
    obj = json.loads(JsonFormatter().format(rec))
    assert "DOE" not in obj["message"] and "Z9998887" not in obj["message"]
    assert "[redacted]" in obj["message"]


def test_json_formatter_includes_redacted_exception() -> None:
    try:
        try:
            raise ValueError(f"cannot transform {_PHI_RAW}")
        except ValueError as inner:
            raise RuntimeError("handler error") from inner
    except RuntimeError:
        rec = logging.LogRecord(
            "t", logging.ERROR, __file__, 1, "worker failed", (), sys.exc_info()
        )
    RedactionFilter().filter(rec)
    obj = json.loads(JsonFormatter().format(rec))
    assert "exception" in obj
    assert "DOE" not in obj["exception"] and "Z9998887" not in obj["exception"]
    assert "ValueError" in obj["exception"] and "RuntimeError" in obj["exception"]


def _has(filters: list[logging.Filter], cls: type) -> bool:
    return any(isinstance(f, cls) for f in filters)


def _forwarder(root: logging.Logger | None = None) -> _ForwardQueueHandler:
    """The off-box forwarder's queue handler on ``root``, asserting there is exactly one.

    BACKLOG #1199: the syslog handler is no longer a root handler — the root carries this queue
    handler and the socket lives on the listener thread behind it — so a test that wants the
    forwarder asks for it here rather than scanning ``root.handlers`` for a ``SysLogHandler``."""
    handlers = (root or logging.getLogger()).handlers
    queued = [h for h in handlers if isinstance(h, _ForwardQueueHandler)]
    assert len(queued) == 1, f"expected exactly one queued forwarder, got {queued}"
    return queued[0]


def test_configure_logging_json_format_installs_json_formatter() -> None:
    installed = configure_logging("INFO", fmt="json")
    assert installed is False  # no forwarder configured
    handler = logging.getLogger().handlers[0]
    assert isinstance(handler.formatter, JsonFormatter)
    # Both PHI filters must be on stdout (redaction + log-injection scrub), not just one.
    assert _has(handler.filters, RedactionFilter) and _has(handler.filters, ControlCharScrubFilter)


def test_configure_logging_adds_off_box_forwarder() -> None:
    # UDP: the socket is created but not connected, so no live collector is needed in the test.
    installed = configure_logging(
        "INFO", forward=SyslogForward(host="127.0.0.1", port=5514, protocol="udp")
    )
    assert installed is True
    handlers = logging.getLogger().handlers
    assert len(handlers) == 2  # stdout + the forwarder's queue handler
    fwd = _forwarder()
    # The socket handler sits BEHIND the queue, on the listener thread, and is reachable only there.
    targets = _forward_targets(logging.getLogger())
    assert len(targets) == 1 and isinstance(targets[0], logging.handlers.SysLogHandler)
    # The forwarder carries the SAME two PHI filters as stdout (the hard rule: every sink, both
    # filters) — and carries them on the NEAR side, so nothing unredacted is ever enqueued.
    assert _has(fwd.filters, RedactionFilter) and _has(fwd.filters, ControlCharScrubFilter)
    assert isinstance(fwd.formatter, JsonFormatter)  # JSON is the off-box default


def test_configure_logging_forwarder_text_format_uses_plain_formatter() -> None:
    # forward_format="text" must select a plain text Formatter, NOT JsonFormatter (independent of stdout).
    #
    # Asserted on the QUEUE handler, which is where the rendering happens. Asserting it on the socket
    # handler would now pass for BOTH formats — that handler carries the identity formatter either
    # way — so the older spelling of this test would have kept passing while measuring nothing.
    installed = configure_logging(
        "INFO", forward=SyslogForward(host="127.0.0.1", port=5514, protocol="udp", fmt="text")
    )
    assert installed is True
    fwd = _forwarder()
    assert isinstance(fwd.formatter, logging.Formatter)
    assert not isinstance(fwd.formatter, JsonFormatter)


def test_configure_logging_tolerates_unreachable_tcp_collector(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A down TCP collector must not crash startup: configure_logging warns and runs without it, so the
    # engine's availability never hinges on the SIEM.
    #
    # The refusal is injected at the syscall seam instead of by connecting to a "known-closed" port,
    # because no port is reliably closed here (BACKLOG #349). SysLogHandler.createSocket issues a BLIND
    # connect — it never bind()s — so the kernel draws its SOURCE port from the dynamic range that any
    # hardcoded high port also sits in. When the allocator hands the socket the destination port, TCP
    # simultaneous open connects it to ITSELF: connect() returns success with nothing listening anywhere
    # and `installed` is True. That fired once on windows-2022 and read as the PR's own defect.
    # The contract under test is "an OSError while BUILDING the handler is tolerated" — not "port X is
    # closed" — so removing the network makes it deterministic instead of merely improbable.
    from messagefoundry.logging_setup import _TimeoutSysLogHandler

    def _refuse(self: Any) -> None:
        raise ConnectionRefusedError("collector down")

    # Patch createSocket, NOT socket.create_connection: SysLogHandler uses getaddrinfo + socket() +
    # sock.connect() and never touches create_connection, so that patch would intercept nothing and
    # leave the flake shipping. The port below is inert — nothing connects.
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _refuse)
    installed = configure_logging(
        "INFO", forward=SyslogForward(host="127.0.0.1", port=514, protocol="tcp")
    )
    assert installed is False  # the forwarder was NOT installed…
    assert len(logging.getLogger().handlers) == 1  # …only stdout remains
    assert "unavailable" in capsys.readouterr().out  # …and the gap was logged, not silent


def test_serve_wires_off_box_forwarder_and_logs_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    # End-to-end: serve builds a SyslogForward from [logging].forward_* and configure_logging installs
    # it; the 'enabled' line fires only because the (UDP) forwarder really installed.
    import uvicorn

    monkeypatch.chdir(tmp_path)
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare synthetic to keep the PHI gates quiet.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n"
        '[logging]\nforward_enabled = true\nforward_host = "127.0.0.1"\nforward_port = 5514\n'
        'forward_protocol = "udp"\nforward_format = "text"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    rc = __main__.main(
        ["serve", "--config", str(tmp_path), "--db", str(tmp_path / "x.db"), "--env", "dev"]
    )
    assert rc == 0
    assert len(_forward_targets(logging.getLogger())) == 1
    assert not isinstance(_forwarder().formatter, JsonFormatter)  # forward_format="text" honored
    assert "off-box log forwarding enabled" in capsys.readouterr().out


# --- ADR 0080: native TLS-syslog transport ------------------------------------


def _make_tls_certs(dir_path: Any) -> SimpleNamespace:
    """Generate a self-signed cert (IP SAN 127.0.0.1) usable as a syslog collector's cert, its private
    key, and a combined cert+key PEM (usable as a client chain for mutual-TLS tests). No PHI."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    ca = dir_path / "ca.pem"
    ca.write_bytes(cert_pem)
    keyf = dir_path / "key.pem"
    keyf.write_bytes(key_pem)
    combined = dir_path / "client.pem"
    combined.write_bytes(key_pem + cert_pem)
    return SimpleNamespace(ca=str(ca), key=str(keyf), combined=str(combined))


class _TlsSyslogServer:
    """A minimal one-connection TLS syslog collector for the roundtrip test. Accepts a single TLS
    client, reads everything it sends, and records the plaintext bytes."""

    def __init__(self, certfile: str, keyfile: str) -> None:
        import socket
        import ssl
        import threading

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self._ctx = ctx
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self.received = bytearray()
        self._got_data = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(10.0)
        try:
            raw, _ = self._sock.accept()
        except OSError:
            return
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(10.0)
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    self.received += chunk
                    self._got_data.set()
        except OSError:
            pass  # client hangup / handshake abort — the test asserts on what arrived

    def wait_for_data(self, timeout: float = 10.0) -> bool:
        return self._got_data.wait(timeout)

    def close(self) -> None:
        try:  # noqa: SIM105
            self._sock.close()
        except OSError:
            pass


def test_build_tls_context_verify_off_disables_checks() -> None:
    import ssl

    from messagefoundry.logging_setup import _build_tls_context

    ctx = _build_tls_context(SyslogForward(host="h", protocol="tls", tls_verify=False))
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


def test_build_tls_context_anchors_only_the_given_ca(tmp_path: Any) -> None:
    import ssl

    from messagefoundry.logging_setup import _build_tls_context

    certs = _make_tls_certs(tmp_path)
    ctx = _build_tls_context(
        SyslogForward(host="127.0.0.1", protocol="tls", tls_ca_file=certs.ca, tls_verify=True)
    )
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    # Only the supplied CA is trusted — the ~hundreds of public system roots are NOT loaded, so exactly
    # one X509 sits in the trust store (the roundtrip test proves this anchor verifies end-to-end).
    assert ctx.cert_store_stats()["x509"] == 1


def test_build_tls_context_loads_client_cert(tmp_path: Any) -> None:
    from messagefoundry.logging_setup import _build_tls_context

    certs = _make_tls_certs(tmp_path)
    # A bad/missing client chain would raise inside load_cert_chain; a clean return proves it loaded.
    ctx = _build_tls_context(
        SyslogForward(
            host="127.0.0.1",
            protocol="tls",
            tls_ca_file=certs.ca,
            tls_verify=True,
            tls_client_cert=certs.combined,
        )
    )
    assert ctx.verify_mode.name == "CERT_REQUIRED"


def test_build_syslog_handler_selects_tls_and_wires_context(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The tls branch must build a _TlsSysLogHandler carrying the ssl context + SNI hostname, WITHOUT a
    # live collector — stub createSocket so no connect happens.
    from messagefoundry.logging_setup import _build_syslog_handler, _TlsSysLogHandler

    monkeypatch.setattr(_TlsSysLogHandler, "createSocket", lambda self: None)
    certs = _make_tls_certs(tmp_path)
    handler = _build_syslog_handler(
        SyslogForward(host="127.0.0.1", port=6514, protocol="tls", tls_ca_file=certs.ca)
    )
    assert isinstance(handler, _TlsSysLogHandler)
    assert handler._server_hostname == "127.0.0.1"
    assert handler._ssl_context.check_hostname is True


def test_configure_logging_tolerates_unreachable_tls_collector(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A down TLS collector must be best-effort exactly like TCP: an OSError raised before/at the
    # handshake leaves configure_logging warning and running without the forwarder.
    #
    # Same seam, same reason as the TCP sibling (BACKLOG #349): the old hardcoded 65501 was in the
    # dynamic range and self-connectable. This one merely *looked* safe — after a self-connect the
    # client reads back its own ClientHello and dies with ssl.SSLError, an OSError subclass, so the
    # assertions still passed. It was self-healing by accident, which is not a property to rely on.
    from messagefoundry.logging_setup import _TlsSysLogHandler

    def _refuse(self: Any) -> None:
        raise ConnectionRefusedError("collector down")

    monkeypatch.setattr(_TlsSysLogHandler, "createSocket", _refuse)
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(host="127.0.0.1", port=6514, protocol="tls", tls_verify=False),
    )
    assert installed is False
    assert len(logging.getLogger().handlers) == 1  # only stdout remains
    assert "unavailable" in capsys.readouterr().out


def test_configure_logging_tls_forwarder_roundtrip(tmp_path: Any) -> None:
    # End-to-end over real TLS: a verified handshake against the private CA must succeed (installed) and
    # an emitted record must arrive at the collector encrypted-in-transit / decrypted server-side.
    certs = _make_tls_certs(tmp_path)
    server = _TlsSyslogServer(certs.ca, certs.key)
    server.start()
    try:
        installed = configure_logging(
            "INFO",
            forward=SyslogForward(
                host="127.0.0.1",
                port=server.port,
                protocol="tls",
                tls_ca_file=certs.ca,
                tls_verify=True,
                fmt="text",
            ),
        )
        assert installed is True  # CA-verified, hostname-checked handshake succeeded
        assert len(_forward_targets(logging.getLogger())) == 1
        logging.getLogger("mefor.tls").warning("tls_marker_%s", "OB_ACME")
        # The send is on the listener thread now, so the record arrives asynchronously — the wait
        # below is what makes that a bounded assertion rather than a race.
        assert server.wait_for_data(timeout=10.0), "collector received no data"
        assert b"tls_marker_OB_ACME" in bytes(server.received)
    finally:
        server.close()


# --- BACKLOG #1199: the durable off-box hand-off (queue handler + listener) ----
# The defect these cover: attached directly to the root logger, the syslog handler's blocking send ran
# on the thread that logged the record -- the asyncio event loop. On a first deployment a stalled-but-
# connected collector would therefore cost the whole event loop up to _FORWARD_TCP_TIMEOUT per record
# and then lose the record anyway. The forwarder now sits behind a bounded queue drained by its own
# thread. What is NOT built here: the on-disk spool, and a backoff between reconnect attempts.


class _CapturingHandler(logging.Handler):
    """Stands in for the syslog socket handler on the far side of the queue.

    Records what the listener thread hands it, optionally after waiting on a gate — which is how a
    test holds the drain open to model a stalled-but-connected collector."""

    def __init__(
        self, gate: threading.Event | None = None, wait: float = 30.0, delay: float = 0.0
    ) -> None:
        super().__init__()
        self.gate = gate
        self.wait = wait
        self.delay = delay  # a slow-but-working collector, for the drain-on-shutdown assertion
        self.seen: list[logging.LogRecord] = []
        self.closed = False

    def emit(self, record: logging.LogRecord) -> None:
        if self.gate is not None:
            self.gate.wait(self.wait)
        if self.delay:
            time.sleep(self.delay)
        self.seen.append(record)

    def close(self) -> None:
        self.closed = True
        super().close()


class _FakeSocket:
    """Stands in for the forwarder's connected socket, so a mid-run send failure is deterministic
    rather than dependent on a real collector going away at the right moment."""

    def __init__(self) -> None:
        self.fail: BaseException | None = None
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        if self.fail is not None:
            raise self.fail
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def forward_logger() -> Iterator[logging.Logger]:
    """A private, NON-propagating logger plus teardown that closes whatever the test attached.

    Non-propagating so the test's own (PHI-bearing) records never reach pytest's root handlers, which
    leaves ``caplog`` holding only the forwarder's own warnings — the thing these tests assert on."""
    logger = logging.getLogger("mefor.test.forward")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield logger
    finally:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()  # stops the listener thread and closes the target


def _drain_queue(handler: _ForwardQueueHandler) -> list[logging.LogRecord]:
    """Everything sitting in the hand-off queue, taken off it. Only meaningful with the listener
    already stopped, which is how the callers below make the assertion race-free."""
    return [handler._records.get_nowait() for _ in range(handler._records.qsize())]


def test_a_forwarded_record_is_redacted_before_it_enters_the_queue(
    forward_logger: logging.Logger,
) -> None:
    """THE load-bearing property of the hand-off. The PHI chain runs on the NEAR side, inline on the
    caller, so what the queue holds is already redacted. Filters on the far side would leave PHI
    sitting in an in-memory queue — and in any later on-disk spool — which is the opposite of what
    the chain exists for.

    This reads the queue itself rather than the far side, because "what is IN the queue" is the claim.
    """
    target = _CapturingHandler()
    fwd = _build_queued_forwarder(target, fmt="text")
    forward_logger.addHandler(fwd)
    # Stop the listener FIRST so nothing drains: what the caller enqueues stays put, and the
    # assertion is about the queue's contents rather than a race with a background thread.
    assert fwd._listener.stop_within(1.0)

    forward_logger.warning("transform failed for %s", SYNTHETIC_PHI)

    queued = _drain_queue(fwd)
    assert len(queued) == 1
    line = queued[0].getMessage()
    assert "DOE" not in line and "JANE" not in line and "19800101" not in line
    assert "[redacted]" in line
    # The RENDERED line, not a lazy msg/args pair — the formatter is on this side too, so the object
    # on the queue is the exact text that goes on the wire.
    assert line.startswith(time.strftime("%Y-%m-%dT", time.gmtime(queued[0].created)))
    # …and the far side carries no chain of its own. Moving the filters there reds the assertions
    # above instead of quietly passing on a second, later redaction.
    assert target.filters == []


def test_a_forwarded_exception_traceback_is_redacted_before_it_enters_the_queue(
    forward_logger: logging.Logger,
) -> None:
    """The realistic PHI vector, and the reason far-side filters could not work even if the queue's
    contents did not matter: ``QueueHandler.prepare`` clears ``exc_info``/``exc_text`` after
    formatting, so a ``RedactionFilter`` behind the queue would find no traceback left to redact and
    its exception limb would be dead."""
    target = _CapturingHandler()
    fwd = _build_queued_forwarder(target, fmt="text")
    forward_logger.addHandler(fwd)
    assert fwd._listener.stop_within(1.0)

    try:
        raise ValueError(f"cannot transform {SYNTHETIC_PHI}")
    except ValueError:
        forward_logger.exception("handler failed")

    queued = _drain_queue(fwd)
    assert len(queued) == 1
    line = queued[0].getMessage()
    assert "ValueError" in line  # the traceback really did make it into the queued text…
    assert "DOE" not in line and "19800101" not in line  # …and it is redacted there
    # The structural half of the same point: nothing is left for a far-side filter to work on.
    assert queued[0].exc_info is None and queued[0].exc_text is None


def test_the_queued_forwarder_renders_exactly_what_the_direct_attachment_rendered(
    forward_logger: logging.Logger,
) -> None:
    """The chain is IDENTICAL, not merely similar.

    The control is the pre-#1199 arrangement built from the same two shared pieces
    (``_install_phi_filters`` + ``_make_formatter``) that ``configure_logging`` used to put straight
    on the socket handler. Its output is compared byte for byte with what now reaches the far side."""
    target = _CapturingHandler()
    fwd = _build_queued_forwarder(target, fmt="json")
    forward_logger.addHandler(fwd)

    control = logging.Handler()
    control.setFormatter(_make_formatter("json"))
    _install_phi_filters(control)

    def _record() -> logging.LogRecord:
        return logging.LogRecord(
            "mefor.fwd", logging.WARNING, __file__, 1, "bad message: %s", (SYNTHETIC_PHI,), None
        )

    through_queue, direct = _record(), _record()
    direct.created = through_queue.created  # the rendered timestamp is per-second; pin it

    fwd.handle(through_queue)
    # The sentinel goes on the TAIL of the queue, so stopping drains everything ahead of it first.
    assert fwd._listener.stop_within(5.0)
    assert len(target.seen) == 1
    assert control.filter(direct)

    try:
        assert target.format(target.seen[0]) == control.format(direct)
    finally:
        control.close()


def test_a_stalled_collector_does_not_block_the_caller(forward_logger: logging.Logger) -> None:
    """The whole point of the hand-off, with the control that makes it mean something.

    On a first deployment a wedged SIEM attached directly would hold the calling thread — the
    event loop — for the socket timeout, per record. Behind the queue the caller pays a
    ``put_nowait``. The control arm is the SAME blocking handler attached the old way, so a green
    result cannot come from the stand-in simply failing to block."""
    gate = threading.Event()
    stalled = _CapturingHandler(gate=gate, wait=30.0)
    fwd = _build_queued_forwarder(stalled, fmt="text")
    forward_logger.addHandler(fwd)
    try:
        start = time.monotonic()
        for i in range(5):
            forward_logger.warning("record %d", i)
        queued_elapsed = time.monotonic() - start
    finally:
        gate.set()  # release the listener thread so the fixture's close() can drain
    assert queued_elapsed < 0.5, f"the caller waited {queued_elapsed:.2f}s on a stalled collector"

    # CONTROL: the same blocking emit, attached the old way, DOES hold the caller.
    control_logger = logging.getLogger("mefor.test.forward.control")
    control_logger.setLevel(logging.DEBUG)
    control_logger.propagate = False
    blocking = _CapturingHandler(gate=threading.Event(), wait=0.5)  # never set — waits it out
    control_logger.addHandler(blocking)
    try:
        start = time.monotonic()
        control_logger.warning("record")
        direct_elapsed = time.monotonic() - start
    finally:
        control_logger.removeHandler(blocking)
        blocking.close()
    assert direct_elapsed >= 0.4, "the control did not block, so the queued arm measures nothing"


def test_the_hand_off_queue_is_bounded_and_reports_what_it_drops(
    forward_logger: logging.Logger,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unbounded queue turns a long collector outage into unbounded memory growth. This one has a
    depth, and what does not fit is dropped WITH A REPORT rather than silently — a silent drop is
    what BACKLOG #1199 objects to.

    The count-and-log invariant (CLAUDE.md §2) governs received MESSAGES, not log records, so
    dropping a record here is a legitimate choice in a way that dropping a message never is."""
    from messagefoundry import logging_setup

    monkeypatch.setattr(logging_setup, "_FORWARD_QUEUE_MAXSIZE", 3)
    target = _CapturingHandler()
    fwd = _build_queued_forwarder(target, fmt="text")
    forward_logger.addHandler(fwd)
    assert fwd._listener.stop_within(1.0)  # nothing drains, so the arithmetic below is exact

    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        for i in range(10):
            forward_logger.warning("record %d", i)

    assert fwd._records.qsize() == 3  # the bound held…
    assert fwd.dropped == 7  # …and the rest were counted, not quietly lost
    drops = [r for r in caplog.records if "hand-off queue is full" in r.getMessage()]
    # ONE report for seven drops. The report is itself a log record, so one per drop would amplify
    # the outage it reports on. The FIRST drop reports immediately (an operator should not wait a
    # minute to hear that evidence is being lost), so its batch is 1 and the six behind it are held.
    assert len(drops) == 1
    assert "dropped 1 record(s)" in drops[0].getMessage()
    assert "depth 3" in drops[0].getMessage()

    # The held six are not forgotten — the NEXT report carries them. Collapsing the interval is what
    # makes that assertable in a test; without it this arm would just be the same single report.
    monkeypatch.setattr(logging_setup, "_FORWARD_DROP_REPORT_INTERVAL", 0.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        forward_logger.warning("one more")
    later = [r for r in caplog.records if "hand-off queue is full" in r.getMessage()]
    assert len(later) == 2
    assert "dropped 7 record(s)" in later[1].getMessage()
    assert "8 dropped since this process started" in later[1].getMessage()


def test_the_drop_report_does_not_recurse_on_the_root_logger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``configure_logging`` attaches the forwarder to the ROOT logger, so the drop warning is itself
    a record arriving at the very queue that produced it. Without the re-entrancy guard that is
    unbounded recursion, on the outage path, in a process that is already degraded.

    **The report interval is collapsed to zero on purpose.** At its shipped value the rate limiter
    also stops the recursion, because it stamps the clock before it warns — so this test passed with
    the guard removed and measured nothing. Zero takes the rate limiter out of the answer and leaves
    the guard as the only thing standing between the drop path and a ``RecursionError``.

    **The assertion counts REPORTS rather than watching for an exception**, for the same reason: a
    ``RecursionError`` raised deep in the cascade is caught by ``QueueHandler.emit``'s own
    ``except Exception`` and routed to ``handleError``, so nothing escapes to the caller and the
    stack still blew. One report per originating drop is the observable difference."""
    from messagefoundry import logging_setup

    monkeypatch.setattr(logging_setup, "_FORWARD_QUEUE_MAXSIZE", 2)
    monkeypatch.setattr(logging_setup, "_FORWARD_DROP_REPORT_INTERVAL", 0.0)
    monkeypatch.setattr(logging, "raiseExceptions", False)  # keep a defeated run's output readable
    installed = configure_logging(
        "INFO", forward=SyslogForward(host="127.0.0.1", port=5514, protocol="udp")
    )
    assert installed is True
    fwd = _forwarder()
    assert fwd._listener.stop_within(1.0)

    reports = _CapturingHandler()
    logging.getLogger().addHandler(reports)
    try:
        for i in range(6):
            logging.getLogger("mefor.recursion").warning("record %d", i)
    finally:
        logging.getLogger().removeHandler(reports)

    assert fwd._records.qsize() == 2  # records 0 and 1 fit; 2 through 5 do not
    assert fwd.dropped >= 4
    # EXACTLY four: one report per dropped record, and each report's own drop reports nothing. Without
    # the guard each report re-enters the drop path and the count runs to the recursion limit.
    full = [r for r in reports.seen if "hand-off queue is full" in r.getMessage()]
    assert len(full) == 4, f"expected one report per drop, got {len(full)}"


def test_shutdown_drains_what_is_already_queued(forward_logger: logging.Logger) -> None:
    """The listener must stop without throwing away records it could still deliver. ``close`` is the
    hook the standard library's own ``logging.shutdown`` atexit handler calls, so this is the path
    every entry point takes at process exit.

    The collector is deliberately SLOW rather than instant. Against an instant one, a ``close`` that
    drained nothing still passed, because the listener finished on its own between the last record
    and the assertion — a race that read as a green result and measured nothing."""
    target = _CapturingHandler(delay=0.05)  # five records take about 250ms to deliver
    fwd = _build_queued_forwarder(target, fmt="text")
    forward_logger.addHandler(fwd)
    for i in range(5):
        forward_logger.warning("record %d", i)

    fwd.close()

    assert fwd._listener._thread is None  # close() JOINED the listener, it did not leave it running
    assert (
        len(target.seen) == 5
    )  # every queued record reached the collector before the thread ended
    assert fwd._listener.undrained == 0
    assert target.closed  # …and the socket handler behind the queue was closed too


def test_shutdown_does_not_hang_on_a_wedged_collector(
    forward_logger: logging.Logger,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Draining must be bounded. A collector that never answers would otherwise hold process exit
    open one send at a time, and ``QueueListener.stop`` joins without a timeout."""
    from messagefoundry import logging_setup

    monkeypatch.setattr(logging_setup, "_FORWARD_DRAIN_TIMEOUT", 0.2)
    monkeypatch.setattr(logging_setup, "_FORWARD_TCP_TIMEOUT", 0.2)
    gate = threading.Event()
    target = _CapturingHandler(gate=gate, wait=30.0)
    fwd = _build_queued_forwarder(target, fmt="text")
    forward_logger.addHandler(fwd)
    try:
        for i in range(5):
            forward_logger.warning("record %d", i)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
            start = time.monotonic()
            fwd.close()
            elapsed = time.monotonic() - start
    finally:
        gate.set()  # let the orphaned listener finish so it does not outlive the test

    assert elapsed < 5.0, f"close() took {elapsed:.2f}s against a collector that never answers"
    losses = [r for r in caplog.records if "undelivered" in r.getMessage()]
    assert losses, "shutdown dropped records without saying so"
    assert "at least 4 record(s)" in losses[0].getMessage()


def test_a_full_queue_still_accepts_the_stop_sentinel(
    forward_logger: logging.Logger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stdlib's ``enqueue_sentinel`` uses ``put_nowait``, which raises ``queue.Full`` — and a full
    queue is exactly the state a collector outage produces. Unreplaced, that would raise out of
    ``stop`` during shutdown and leave the listener thread running with its socket open.

    The queue has to be full **while the listener is alive**, which is why the collector here is
    gated rather than merely absent. An earlier spelling stopped the listener first and then filled
    the queue; restarting it drained everything before ``close`` ran, so the sentinel always fit and
    the test passed with the stdlib behaviour restored."""
    from messagefoundry import logging_setup

    monkeypatch.setattr(logging_setup, "_FORWARD_QUEUE_MAXSIZE", 2)
    monkeypatch.setattr(logging_setup, "_FORWARD_DRAIN_TIMEOUT", 0.2)
    monkeypatch.setattr(logging_setup, "_FORWARD_TCP_TIMEOUT", 0.2)
    gate = threading.Event()
    target = _CapturingHandler(gate=gate, wait=30.0)
    fwd = _build_queued_forwarder(target, fmt="text")
    forward_logger.addHandler(fwd)
    try:
        for i in range(8):
            forward_logger.warning("record %d", i)
        # The listener parks inside emit on the first record it takes; everything behind it stays on
        # the queue. Wait for that steady state rather than assuming the thread has been scheduled.
        deadline = time.monotonic() + 5.0
        while fwd._records.qsize() < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert fwd._records.qsize() == 2, (
            "the queue never filled, so the sentinel is not under test"
        )

        fwd.close()  # must not raise queue.Full
    finally:
        gate.set()
    assert fwd._stopped


def test_a_broken_stream_forwarder_reconnects_on_the_next_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``SysLogHandler.emit`` reconnects only under ``if not self.socket``, and never clears the
    socket when a send fails — so on the shipped handler a stream forwarder that broke mid-run would
    stay broken for the life of the process, silently (BACKLOG #1199). ``handleError`` now drops the
    dead socket, which is the whole of what makes that branch reachable again."""
    import socket as socket_mod

    from messagefoundry.logging_setup import _TimeoutSysLogHandler

    monkeypatch.setattr(
        logging, "raiseExceptions", False
    )  # handleError prints a traceback otherwise
    made: list[_FakeSocket] = []

    def _fake_create(self: Any) -> None:
        # unixsocket is set by the REAL createSocket, and emit reads it before it sends. A fake that
        # leaves it unset makes emit die on an AttributeError instead of the socket error under test,
        # which reads as "the reconnect did not fire".
        self.unixsocket = False
        sock = _FakeSocket()
        made.append(sock)
        self.socket = sock

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _fake_create)
    handler = _TimeoutSysLogHandler(
        address=("127.0.0.1", 514), socktype=socket_mod.SOCK_STREAM, timeout=0.1
    )
    assert len(made) == 1  # the constructor connected

    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "first", (), None)
    made[0].fail = ConnectionResetError("collector went away")
    handler.emit(record)
    assert handler.socket is None and made[0].closed  # the dead socket was dropped

    handler.emit(record)
    assert len(made) == 2, "the next record did not reconnect"
    assert made[1].sent, "the reconnected socket carried the record"

    # CONTROL: a non-network error must NOT drop the socket. Reconnecting on a formatting bug would
    # buy nothing and would hide the bug.
    class _BadFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            raise ValueError("formatter is broken")

    handler.setFormatter(_BadFormatter())
    handler.emit(record)
    assert handler.socket is made[1] and len(made) == 2
    handler.close()


def test_reconfiguring_closes_the_previous_forwarder_rather_than_leaking_it() -> None:
    """``configure_logging`` is documented as idempotent. The forwarder now owns a thread and a
    socket, so removing its handler is no longer enough to keep that true."""
    configure_logging("INFO", forward=SyslogForward(host="127.0.0.1", port=5514, protocol="udp"))
    first = _forwarder()
    first_target = first.targets[0]

    configure_logging("INFO", forward=SyslogForward(host="127.0.0.1", port=5514, protocol="udp"))
    second = _forwarder()

    assert second is not first
    assert first._listener._thread is None  # the old listener was joined, not orphaned
    assert getattr(first_target, "socket", "unset") is None  # …and its socket closed


# --- configure_stderr_logging (BACKLOG #1054) ---------------------------------
# The child-process variant: same filter chain as configure_logging, bound to stderr because the
# caller's stdout is a binary IPC channel. A bare basicConfig gets the stream right and the filters
# wrong, which is the defect these cover.


def test_configure_stderr_logging_installs_the_filter_chain() -> None:
    handler = configure_stderr_logging()
    root = logging.getLogger()
    assert root.handlers == [handler]  # replaces, never stacks (same contract as configure_logging)
    assert root.level == logging.WARNING
    assert isinstance(handler, logging.StreamHandler)
    # Bound to stderr: a child whose stdout carries binary frames must never get a stdout handler.
    assert handler.stream is sys.stderr
    assert [type(f) for f in handler.filters] == [
        RedactionFilter,
        CredentialQueryScrubFilter,
        ControlCharScrubFilter,
    ]


def test_configure_stderr_logging_redacts_phi_and_scrubs_crlf(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_stderr_logging()
    logging.getLogger("mefor.child").warning(
        "request failed on %s", SYNTHETIC_PHI + "\r\nWARNING mefor.child: forged-record"
    )
    err = capsys.readouterr().err

    assert "[redacted]" in err  # the HL7 span was rewritten...
    for token in ("DOE", "JANE", "19800101", "100^^^H^MR"):
        assert token not in err
    # ...and the CR/LF was escaped rather than emitted raw, so the injected text cannot start its own
    # physical line and impersonate a record. One record on the wire is one line on the stream.
    assert "\\r\\n" in err
    assert "forged-record" in err  # kept and diagnosable, just not at column 0
    assert len([line for line in err.splitlines() if line.strip()]) == 1


def test_configure_stderr_logging_redacts_an_exception_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The realistic child vector: a raise that quoted the message body, rendered by log.exception.
    configure_stderr_logging()
    try:
        raise ValueError(SYNTHETIC_PHI)
    except ValueError:
        logging.getLogger("mefor.child").exception("dispatch failed")
    err = capsys.readouterr().err
    assert "ValueError" in err  # the exception TYPE survives — the log stays diagnosable
    assert "DOE" not in err and "JANE" not in err


# --- ADR 0080: SNTP probe (query_sntp_offset) ---------------------------------


def _fake_udp_reply(server_unix: float) -> bytes:
    """A 48-byte SNTP reply whose transmit timestamp encodes ``server_unix`` (Unix seconds)."""
    from messagefoundry.logging_setup import _NTP_UNIX_EPOCH_DELTA

    ntp_seconds = int(server_unix + _NTP_UNIX_EPOCH_DELTA)
    return bytes(40) + ntp_seconds.to_bytes(4, "big") + (0).to_bytes(4, "big")


class _FakeUDPSocket:
    def __init__(self, reply: bytes) -> None:
        self._reply = reply

    def __enter__(self) -> _FakeUDPSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def settimeout(self, _t: float) -> None:
        pass

    def sendto(self, _data: bytes, _addr: Any) -> None:
        pass

    def recvfrom(self, _n: int) -> tuple[bytes, Any]:
        return self._reply, ("127.0.0.1", 123)


def test_query_sntp_offset_computes_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry import logging_setup

    # Server clock 30s BEHIND local → local leads → positive offset ≈ +30s.
    reply = _fake_udp_reply(time.time() - 30.0)
    # String target so mypy doesn't need `socket` re-exported from logging_setup's namespace.
    monkeypatch.setattr(
        "messagefoundry.logging_setup.socket.socket", lambda *a, **k: _FakeUDPSocket(reply)
    )
    offset = logging_setup.query_sntp_offset("ntp.local")
    assert 25.0 < offset < 35.0


def test_query_sntp_offset_short_reply_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry import logging_setup

    monkeypatch.setattr(
        "messagefoundry.logging_setup.socket.socket", lambda *a, **k: _FakeUDPSocket(b"\x00" * 10)
    )
    with pytest.raises(OSError):
        logging_setup.query_sntp_offset("ntp.local")


def test_query_sntp_offset_timeout_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry import logging_setup

    class _Timing(_FakeUDPSocket):
        def recvfrom(self, _n: int) -> tuple[bytes, Any]:
            raise TimeoutError(
                "timed out"
            )  # socket.timeout is an alias for TimeoutError (⊂ OSError)

    monkeypatch.setattr("messagefoundry.logging_setup.socket.socket", lambda *a, **k: _Timing(b""))
    with pytest.raises(OSError):
        logging_setup.query_sntp_offset("ntp.local")


# --- ADR 0080: startup clock-sync gate in serve() -----------------------------


def _write_timesync_toml(tmp_path: Any, *, fail_closed: bool) -> None:
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare synthetic to keep the PHI gates quiet — these
    # tests probe the clock-sync gate, not the security posture.
    body = (
        "security.handles_real_patient_data = false\n"
        '[logging]\nrequire_time_sync = true\nntp_peer = "ntp.example.test"\n'
        "time_sync_max_skew_seconds = 1.0\n"
    )
    if fail_closed:
        body += "time_sync_fail_closed = true\n"
    (tmp_path / "messagefoundry.toml").write_text(body, encoding="utf-8")


def test_serve_time_sync_fail_closed_refuses_on_skew(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_timesync_toml(tmp_path, fail_closed=True)
    monkeypatch.setattr("messagefoundry.__main__.query_sntp_offset", lambda peer, **kw: 30.0)
    rc = __main__.main(
        ["serve", "--config", str(tmp_path), "--db", str(tmp_path / "x.db"), "--env", "dev"]
    )
    assert rc == 2


def test_serve_time_sync_fail_closed_refuses_on_unreachable_peer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_timesync_toml(tmp_path, fail_closed=True)

    def _unreachable(peer: str, **kw: Any) -> float:
        raise OSError("no route to host")

    monkeypatch.setattr("messagefoundry.__main__.query_sntp_offset", _unreachable)
    rc = __main__.main(
        ["serve", "--config", str(tmp_path), "--db", str(tmp_path / "x.db"), "--env", "dev"]
    )
    assert rc == 2


def test_serve_time_sync_warns_but_starts_when_not_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn

    monkeypatch.chdir(tmp_path)
    _write_timesync_toml(tmp_path, fail_closed=False)
    monkeypatch.setattr("messagefoundry.__main__.query_sntp_offset", lambda peer, **kw: 30.0)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    rc = __main__.main(
        ["serve", "--config", str(tmp_path), "--db", str(tmp_path / "x.db"), "--env", "dev"]
    )
    assert rc == 0  # warn-only: the engine still starts
    out = capsys.readouterr().out
    assert "clock-sync" in out  # the skew warning surfaced on the general log


def test_serve_time_sync_ok_within_threshold_starts_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    import uvicorn

    monkeypatch.chdir(tmp_path)
    _write_timesync_toml(
        tmp_path, fail_closed=True
    )  # even fail-closed must NOT trip within threshold
    monkeypatch.setattr("messagefoundry.__main__.query_sntp_offset", lambda peer, **kw: 0.05)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    rc = __main__.main(
        ["serve", "--config", str(tmp_path), "--db", str(tmp_path / "x.db"), "--env", "dev"]
    )
    assert rc == 0


# --- BACKLOG #1273 limb 3: ONE definition of the alphabet, with the tab subtraction pinned -------
#
# `_CTRL_TRANSLATION` used to re-derive the control-character set as `range(0x20)` plus a separate
# `0x7F` line -- a second statement of the set that `controlchars` exists to state once. The two
# agreed, so nothing was mis-escaped. The cost was the future-tense one: a later widening applied to
# one copy silently does not apply to the other, and nothing reports the omission.
#
# These tests pin the RELATIONSHIP rather than either set's contents, which is what survives a
# deliberate widening: widen `_is_control_char` and the table follows automatically, and if it does
# not, the first test goes red naming the code points that drifted.


def test_the_log_escape_table_is_the_controlchars_alphabet_minus_tab() -> None:
    """The whole of limb 3, as one assertion about the DIFFERENCE.

    Not "the table has 32 entries" -- that pins a number and would have to be edited by whoever
    widens the alphabet, which is precisely the person who should be told rather than asked to
    update a constant. This pins the SUBTRACTION, so a legitimate widening passes untouched and a
    divergence names its own code points.
    """
    from messagefoundry.controlchars import _is_control_char
    from messagefoundry.logging_setup import _CTRL_TRANSLATION

    alphabet = {cp for cp in range(0x80) if _is_control_char(chr(cp))}
    escaped = set(_CTRL_TRANSLATION)

    assert alphabet - escaped == {0x09}, (
        f"the log escape table and controlchars have drifted: "
        f"{sorted(hex(c) for c in (alphabet - escaped) - {0x09})} are screened as control "
        f"characters but not escaped in a log line"
    )
    assert not escaped - alphabet, (
        f"the log table escapes {sorted(hex(c) for c in escaped - alphabet)}, which controlchars "
        f"does not treat as control characters -- one of the two has been widened alone"
    )


def test_tab_is_the_only_control_character_left_intact() -> None:
    """Tab is benign whitespace in a log line; CR/LF are the injection vector and must not join it.

    The asymmetry is the reason this is a separate test from the one above: that one would still
    pass if tab were swapped for CR in the subtraction, because the difference would still be a
    single code point.
    """
    from messagefoundry.logging_setup import _CTRL_TRANSLATION

    assert 0x09 not in _CTRL_TRANSLATION, "tab must survive a log line unescaped"
    assert _CTRL_TRANSLATION[0x0A] == "\\n", "LF is the injection vector and must be escaped"
    assert _CTRL_TRANSLATION[0x0D] == "\\r", "CR is the injection vector and must be escaped"
    assert _CTRL_TRANSLATION[0x00] == "\\x00"
    assert _CTRL_TRANSLATION[0x7F] == "\\x7f", "DEL is in the alphabet and must still be escaped"


def test_a_tab_survives_the_real_scrub_and_a_newline_does_not() -> None:
    """Drives the shipped filter rather than the table, so the two cannot agree while the code differs."""
    from messagefoundry.logging_setup import _CTRL_TRANSLATION

    scrubbed = "before\tafter\nnext".translate(_CTRL_TRANSLATION)
    assert "\t" in scrubbed, "the tab was escaped; a log line lost its benign whitespace"
    assert "\n" not in scrubbed, "a real newline survived; one record can now forge a second line"
    assert scrubbed == "before\tafter\\nnext"
