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
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry import __main__
from messagefoundry.logging_setup import (
    ControlCharScrubFilter,
    CredentialQueryScrubFilter,
    JsonFormatter,
    RedactionFilter,
    SyslogForward,
    _make_formatter,
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
    fwd = [h for h in logging.getLogger().handlers if isinstance(h, logging.handlers.SysLogHandler)]
    assert len(fwd) == 1
    assert not isinstance(fwd[0].formatter, JsonFormatter)  # forward_format="text" honored
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
        fwd = [
            h for h in logging.getLogger().handlers if isinstance(h, logging.handlers.SysLogHandler)
        ]
        assert len(fwd) == 1
        logging.getLogger("mefor.tls").warning("tls_marker_%s", "OB_ACME")
        assert server.wait_for_data(timeout=10.0), "collector received no data"
        assert b"tls_marker_OB_ACME" in bytes(server.received)
    finally:
        server.close()


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
