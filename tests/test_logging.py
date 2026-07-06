# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for logging setup and the serve ``--log-level`` flag."""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys
import time
from typing import Any, Iterator

import pytest

from messagefoundry import __main__
from messagefoundry.logging_setup import (
    ControlCharScrubFilter,
    JsonFormatter,
    RedactionFilter,
    SyslogForward,
    configure_logging,
)


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
    assert len(handlers) == 2  # stdout + forwarder
    fwd = [h for h in handlers if isinstance(h, logging.handlers.SysLogHandler)]
    assert len(fwd) == 1
    # The forwarder carries the SAME two PHI filters as stdout (the hard rule: every sink, both filters).
    assert _has(fwd[0].filters, RedactionFilter) and _has(fwd[0].filters, ControlCharScrubFilter)
    assert isinstance(fwd[0].formatter, JsonFormatter)  # JSON is the off-box default


def test_configure_logging_forwarder_text_format_uses_plain_formatter() -> None:
    # forward_format="text" must select a plain text Formatter, NOT JsonFormatter (independent of stdout).
    installed = configure_logging(
        "INFO", forward=SyslogForward(host="127.0.0.1", port=5514, protocol="udp", fmt="text")
    )
    assert installed is True
    fwd = [h for h in logging.getLogger().handlers if isinstance(h, logging.handlers.SysLogHandler)]
    assert len(fwd) == 1
    assert isinstance(fwd[0].formatter, logging.Formatter)
    assert not isinstance(fwd[0].formatter, JsonFormatter)


def test_configure_logging_tolerates_unreachable_tcp_collector(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A down TCP collector must not crash startup: configure_logging warns and runs without it, so the
    # engine's availability never hinges on the SIEM. Port 65500 is unbound → connect raises OSError.
    installed = configure_logging(
        "INFO", forward=SyslogForward(host="127.0.0.1", port=65500, protocol="tcp")
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
    (tmp_path / "messagefoundry.toml").write_text(
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
    fwd = [h for h in logging.getLogger().handlers if isinstance(h, logging.handlers.SysLogHandler)]
    assert len(fwd) == 1
    assert not isinstance(fwd[0].formatter, JsonFormatter)  # forward_format="text" honored
    assert "off-box log forwarding enabled" in capsys.readouterr().out
