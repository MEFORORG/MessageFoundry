# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The on-disk spool behind the off-box log forwarder (BACKLOG #1966, ADR 0200).

Synthetic HL7 only. The planted value is a made-up PID segment, never real PHI.
"""

from __future__ import annotations

import contextlib
import errno
import json
import logging
import logging.handlers
import os
import queue
import socket
import ssl
import stat
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import log_spool, logging_setup
from messagefoundry.log_spool import SPOOL_FORMAT_VERSION, LogSpool, SpoolEntry, SpoolUnavailable
from messagefoundry.logging_setup import (
    _SPOOL_IN_USE_FACTS,
    SyslogForward,
    _build_queued_forwarder,
    _build_syslog_handler,
    _ForwardQueueHandler,
    _ForwardQueueListener,
    _open_forward_spool,
    _TimeoutSysLogHandler,
    _TlsSysLogHandler,
    configure_logging,
    forwarder_status,
    is_permanent_connect_error,
)

#: A PHI-shaped value the redaction filter must catch. Synthetic.
_PLANTED = "PID|1||Z7771234^^^H^MR||SPOOLTEST^PLANTED^Q||19700101|F"


def _entry(n: int) -> SpoolEntry:
    return SpoolEntry(level="WARNING", line=f"record {n:04d}")


def _drain(spool: LogSpool) -> list[str]:
    out: list[str] = []
    while (entry := spool.peek()) is not None:
        out.append(entry.line)
        spool.advance()
    return out


def _segments(directory: Path) -> list[Path]:
    return sorted(directory.glob("spool-*.jsonl"))


@pytest.fixture
def spool_dir(tmp_path: Path) -> Path:
    return tmp_path / "spool"


@pytest.fixture(autouse=True)
def _restore_root_logger() -> Iterator[None]:
    """configure_logging mutates the global root logger; snapshot and restore it."""
    root = logging.getLogger()
    saved = root.handlers[:]
    level = root.level
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            if handler not in saved:
                handler.close()
        for handler in saved:
            root.addHandler(handler)
        root.setLevel(level)


# --- the spool on its own -------------------------------------------------------------------------


def test_replay_is_fifo_across_segments_and_a_drained_spool_holds_no_segments(
    spool_dir: Path,
) -> None:
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=120)
    spool.open()
    try:
        for n in range(20):
            assert spool.append(_entry(n))
        assert len(_segments(spool_dir)) > 1  # the small segment size forced rotation
        assert _drain(spool) == [f"record {n:04d}" for n in range(20)]
        assert _segments(spool_dir) == []
        assert spool.bytes_used == 0
    finally:
        spool.close()


def test_the_file_format_is_versioned_jsonl_one_entry_per_line(spool_dir: Path) -> None:
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    try:
        assert spool.append(SpoolEntry(level="ERROR", line="line with\nan embedded newline"))
    finally:
        spool.close()
    (segment,) = _segments(spool_dir)
    lines = segment.read_bytes().split(b"\n")
    assert lines[-1] == b""  # every entry ends in a newline
    assert len(lines) == 2  # JSON escaping kept the embedded newline inside one physical line
    assert json.loads(lines[0]) == {
        "v": SPOOL_FORMAT_VERSION,
        "level": "ERROR",
        "line": "line with\nan embedded newline",
    }


def test_a_full_spool_drops_the_newest_entry_and_keeps_the_oldest(spool_dir: Path) -> None:
    size = len(_entry(0).encode())
    spool = LogSpool(spool_dir, max_bytes=size * 3)
    spool.open()
    try:
        results = [spool.append(_entry(n)) for n in range(5)]
        assert results == [True, True, True, False, False]
        assert spool.dropped == 2
        assert _drain(spool) == ["record 0000", "record 0001", "record 0002"]
    finally:
        spool.close()


def test_a_restart_replays_what_the_last_process_left_in_order(spool_dir: Path) -> None:
    first = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    first.open()
    for n in range(6):
        first.append(_entry(n))
    first.close()  # the entries stay on disk for the next start

    second = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    second.open()
    try:
        before = {p.name for p in _segments(spool_dir)}
        second.append(_entry(6))
        # A restart never extends a segment whose tail may be torn: the append opened a new one.
        assert {p.name for p in _segments(spool_dir)} - before
        assert _drain(second) == [f"record {n:04d}" for n in range(7)]
    finally:
        second.close()


def test_a_torn_or_foreign_line_is_skipped_and_counted_never_guessed(spool_dir: Path) -> None:
    spool_dir.mkdir()
    good = _entry(1).encode()
    foreign = json.dumps({"v": 99, "level": "INFO", "line": "future"}).encode() + b"\n"
    (spool_dir / "spool-000000000001.jsonl").write_bytes(
        _entry(0).encode() + b"{not json\n" + foreign + good + b'{"v": 1, "le'
    )
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    try:
        assert _drain(spool) == ["record 0000", "record 0001"]
        assert spool.unreadable == 3  # the malformed line, the other version, the torn tail
    finally:
        spool.close()


def test_a_second_process_on_the_same_directory_is_refused(spool_dir: Path) -> None:
    first = LogSpool(spool_dir, max_bytes=100_000)
    first.open()
    try:
        with pytest.raises(SpoolUnavailable, match="in use by another process"):
            LogSpool(spool_dir, max_bytes=100_000).open()
    finally:
        first.close()
    reopened = LogSpool(spool_dir, max_bytes=100_000)
    reopened.open()  # the lock was released with the first
    reopened.close()


# --- the spool behind the forwarder -----------------------------------------------------------------


class _FlakyCollector(logging.Handler):
    """Stands in for the syslog handler: ``down`` makes every send fail the way a network error does
    (the flag the real handler's ``handleError`` sets), and a working send records the line."""

    def __init__(self) -> None:
        super().__init__()
        self.down = True
        self.sent: list[str] = []
        self.send_failed = False

    def emit(self, record: logging.LogRecord) -> None:
        self.send_failed = self.down
        if not self.down:
            self.sent.append(record.getMessage())


def _wait_for(predicate: Callable[[], bool], timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_a_down_collector_spools_in_order_and_replays_when_it_answers(spool_dir: Path) -> None:
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    collector = _FlakyCollector()
    fwd = _build_queued_forwarder(collector, fmt="text", spool=spool)
    logger = logging.getLogger("mefor.test.spool.replay")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(fwd)
    try:
        for n in range(5):
            logger.warning("event %d", n)
        assert _wait_for(lambda: fwd._records.qsize() == 0 and len(_segments(spool_dir)) == 1)
        assert collector.sent == []

        collector.down = False
        fwd._listener._retry_at = 0.0  # skip the backoff; the idle poll replays within a second
        assert _wait_for(lambda: len(collector.sent) == 5)
        assert [line.rsplit(" ", 1)[-1] for line in collector.sent] == ["0", "1", "2", "3", "4"]
        assert _wait_for(lambda: _segments(spool_dir) == [])
    finally:
        logger.removeHandler(fwd)
        fwd.close()


def _refuse(self: Any) -> None:
    raise ConnectionRefusedError("collector down")


def test_a_collector_down_at_start_is_deferred_and_the_spool_holds_only_redacted_text(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The REQUIRED property: the spool sits after the PHI, credential and control-character
    filters, so a PHI-shaped value logged through the engine lands on disk only redacted.

    The control proves the value was really in the record before the filters: a raw handler with
    no filters, on the same root logger, sees it whole. Without it a planted value that never
    reached the logger would pass the redaction assertion vacuously."""
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _refuse)
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(
            host="127.0.0.1",
            port=6514,
            protocol="tcp",
            fmt="text",
            spool_dir=str(spool_dir),
            spool_max_bytes=1_000_000,
        ),
    )
    # Deferred, not skipped: a collector down at start no longer costs the process its forwarder.
    assert installed is True
    root = logging.getLogger()
    (fwd,) = [h for h in root.handlers if isinstance(h, _ForwardQueueHandler)]
    # Leave the forwarder as the ONLY handler. The handler filters rewrite the record in place, so
    # with stdout's chain in front of it the spool would read redacted text even if the forwarder's
    # own chain were gone, and this test could not tell the difference. Measured: it could not.
    for other in [h for h in root.handlers if h is not fwd]:
        root.removeHandler(other)

    raw: queue.Queue[str] = queue.Queue()

    def _capture(record: logging.LogRecord) -> bool:
        # A LOGGER filter runs before any handler, so it sees the record before the handler
        # filters rewrite it in place. A handler added beside the others would not.
        raw.put(record.getMessage())
        return True

    source = logging.getLogger("mefor.test.spool.phi")
    source.addFilter(_capture)
    try:
        source.error("transform failed for %s", _PLANTED)
    finally:
        source.removeFilter(_capture)
    assert "SPOOLTEST^PLANTED" in raw.get_nowait()  # control: present before the filters

    root.removeHandler(fwd)
    fwd.close()  # drains the queue into the spool, then releases it

    spooled = b"".join(p.read_bytes() for p in _segments(spool_dir)).decode("utf-8")
    assert "transform failed for" in spooled  # the record did land in the spool
    assert "SPOOLTEST" not in spooled and "Z7771234" not in spooled and "19700101" not in spooled
    assert "[redacted]" in spooled


def test_a_failed_tls_handshake_leaves_no_plain_socket_behind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deferred TLS handler survives its failed handshake. The connected PLAIN socket must go with
    the failure, or the next record would be sent over it in cleartext."""

    class _Sock:
        closed = False

        def settimeout(self, timeout: float | None) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    plain = _Sock()

    def _connect(self: Any) -> None:
        self.socket = plain

    class _FailingContext:
        def wrap_socket(self, sock: Any, server_hostname: str) -> Any:
            raise ssl.SSLError("handshake failed")

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _connect)
    handler = _TlsSysLogHandler(
        address=("127.0.0.1", 6514),
        timeout=1.0,
        ssl_context=_FailingContext(),  # type: ignore[arg-type]
        server_hostname="127.0.0.1",
        defer_connect=True,
    )
    try:
        assert isinstance(handler.startup_error, ssl.SSLError)
        assert handler.socket is None
        assert plain.closed
    finally:
        handler.close()


def test_no_spool_keeps_the_old_skip_on_a_down_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``spool_max_bytes = 0`` turns the spool off, and with it the deferral."""
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _refuse)
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(host="127.0.0.1", port=6514, protocol="tcp", spool_max_bytes=0),
    )
    assert installed is False


def test_a_lone_surrogate_is_spooled_as_its_escape_not_raised(spool_dir: Path) -> None:
    """A UnicodeEncodeError here would escape on the listener thread and end it for good."""
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    try:
        assert spool.append(SpoolEntry(level="ERROR", line="bad byte \udc80 here"))
        assert _drain(spool) == ["bad byte \udc80 here"]
    finally:
        spool.close()


def test_non_ascii_text_costs_its_utf8_bytes_against_the_cap_and_round_trips(
    spool_dir: Path,
) -> None:
    """BACKLOG #2279: the default JSON escaping wrote six bytes for each non-ASCII character, so a
    spool of such text filled, and dropped, well before the cap said it should."""
    # 2-, 3- and 4-byte characters, built by code point so this file stays ASCII.
    line = f"Zo{chr(0xEB)} {chr(0x4E2D)} {chr(0x1F5C4)}"
    plain = SpoolEntry(level="INFO", line="x")
    entry = SpoolEntry(level="INFO", line=line)
    assert len(entry.encode()) - len(plain.encode()) == len(line.encode("utf-8")) - 1
    assert line in entry.encode().decode("utf-8")  # written as itself, not as escapes

    spool = LogSpool(spool_dir, max_bytes=len(entry.encode()))  # room for exactly one, in UTF-8
    spool.open()
    try:
        assert spool.append(entry)
        assert spool.bytes_used == sum(p.stat().st_size for p in _segments(spool_dir))
        assert _drain(spool) == [line]
    finally:
        spool.close()


def test_a_segment_number_is_never_reused(spool_dir: Path) -> None:
    """A segment whose unlink failed stays on disk; reusing its number would collide on O_EXCL."""
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    try:
        spool.append(_entry(0))
        (first,) = _segments(spool_dir)
        assert _drain(spool) == ["record 0000"]
        first.write_bytes(b"")  # an orphan left on disk, as if its unlink had failed
        assert spool.append(_entry(1))
        assert _segments(spool_dir)[-1].name > first.name
    finally:
        spool.close()


def _simulate_cpython_3149_syslog_init(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``SysLogHandler.__init__`` swallow a ``socket.gaierror`` from ``createSocket``, as
    CPython 3.14.9 does (see ``_TimeoutSysLogHandler.__init__``), whatever Python runs the test."""
    real_init = logging.handlers.SysLogHandler.__init__

    def _init(self: logging.handlers.SysLogHandler, *args: Any, **kwargs: Any) -> None:
        create = self.createSocket

        def _swallow() -> None:
            with contextlib.suppress(socket.gaierror):
                create()

        self.createSocket = _swallow  # type: ignore[method-assign]
        try:
            real_init(self, *args, **kwargs)
        finally:
            vars(self).pop("createSocket", None)

    monkeypatch.setattr(logging.handlers.SysLogHandler, "__init__", _init)


def test_the_cpython_3149_simulation_swallows_the_lookup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The positive control for the simulated cases below: the simulation really swallows."""

    def _no_such_name(self: Any) -> None:
        raise socket.gaierror(11001, "getaddrinfo failed")

    _simulate_cpython_3149_syslog_init(monkeypatch)
    monkeypatch.setattr(logging.handlers.SysLogHandler, "createSocket", _no_such_name)
    handler = logging.handlers.SysLogHandler(
        address=("siem.example.org", 6514), socktype=socket.SOCK_STREAM
    )
    assert getattr(handler, "socket", None) is None
    handler.close()


@pytest.mark.parametrize("cpython_3149", [False, True], ids=["native", "simulated-3.14.9"])
@pytest.mark.parametrize(
    "error",
    [
        ssl.SSLCertVerificationError("certificate verify failed"),
        socket.gaierror(11001, "getaddrinfo failed"),
    ],
    ids=["certificate", "name"],
)
def test_a_permanent_connect_failure_is_reported_at_error_and_not_deferred(
    spool_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: OSError,
    cpython_3149: bool,
) -> None:
    """Waiting cannot fix a bad certificate or a name that does not resolve, so a spool must not
    turn either into "not reachable yet", on CPython 3.14.9 too."""
    if cpython_3149:
        _simulate_cpython_3149_syslog_init(monkeypatch)

    def _fail(self: Any) -> None:
        raise error

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _fail)
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(
            host="siem.example.org",
            port=6514,
            protocol="tcp",
            spool_dir=str(spool_dir),
            spool_max_bytes=1_000_000,
        ),
    )
    out = capsys.readouterr().out
    assert installed is False
    assert "ERROR" in out and "failed permanently" in out
    assert "not reachable yet" not in out
    _assert_reads_not_installed_permanently()
    # The spool was released, so a later configure in this process can take it.
    again = LogSpool(spool_dir, max_bytes=1_000)
    again.open()
    again.close()


@pytest.mark.parametrize("spool", [False, True], ids=["no-spool", "spool"])
@pytest.mark.parametrize("protocol", ["udp", "tcp", "tls"])
def test_a_name_that_does_not_resolve_fails_permanently_under_the_real_create_socket(
    spool_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    protocol: str,
    spool: bool,
) -> None:
    """The stdlib ``createSocket`` runs for real here and only the lookup is faked, so every arm,
    UDP included, is held to the simulated 3.14.9 behavior as well, with a spool behind it or not
    (BACKLOG #4063: a spool must not turn the name into "not reachable yet")."""

    def _no_such_name(*args: Any, **kwargs: Any) -> Any:
        raise socket.gaierror(socket.EAI_NONAME, "getaddrinfo failed")

    _simulate_cpython_3149_syslog_init(monkeypatch)
    monkeypatch.setattr(socket, "getaddrinfo", _no_such_name)
    spooling: dict[str, Any] = (
        {"spool_dir": str(spool_dir), "spool_max_bytes": 1_000_000}
        if spool
        else {"spool_max_bytes": 0}
    )
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(
            host="siem.example.org", port=514, protocol=protocol, tls_verify=False, **spooling
        ),
    )
    out = capsys.readouterr().out
    assert installed is False
    assert "ERROR" in out and "failed permanently" in out
    _assert_reads_not_installed_permanently()


def _assert_reads_not_installed_permanently() -> None:
    """What the health surface reads after a permanent start failure: configured, not installed,
    and the fixed word ``permanent`` (vault BACKLOG #4083 finding 11)."""
    status = forwarder_status()
    assert (status.configured, status.installed, status.start_failure) == (True, False, "permanent")
    assert status.state == "not_installed"


@pytest.mark.parametrize("protocol", ["tcp", "tls", "udp"])
def test_a_transient_lookup_failure_is_still_deferred_on_cpython_3149(
    spool_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    protocol: str,
) -> None:
    """A lookup that failed for a temporary reason is deferred to the spool, as before 3.14.9. UDP
    too since BACKLOG #5923: its arm reports send failures now, so a spool can wait behind it."""

    def _try_again(*args: Any, **kwargs: Any) -> Any:
        raise socket.gaierror(socket.EAI_AGAIN, "temporary failure in name resolution")

    _simulate_cpython_3149_syslog_init(monkeypatch)
    monkeypatch.setattr(socket, "getaddrinfo", _try_again)
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(
            host="siem.example.org",
            port=6514,
            protocol=protocol,
            tls_verify=False,
            spool_dir=str(spool_dir),
            spool_max_bytes=1_000_000,
        ),
    )
    out = capsys.readouterr().out
    assert installed is True
    assert "not reachable yet" in out
    assert "failed permanently" not in out


def test_a_transient_connect_failure_is_still_deferred(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for ``test_a_permanent_connect_failure_is_reported_at_error_and_not_deferred``: a
    refused connect IS deferred, so that test's refusal to defer is about the error class, not about
    deferral being broken."""
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _refuse)
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(
            host="siem.example.org",
            port=6514,
            protocol="tcp",
            spool_dir=str(spool_dir),
            spool_max_bytes=1_000_000,
        ),
    )
    assert installed is True
    assert "not reachable yet" in capsys.readouterr().out


def _collector_lookups(monkeypatch: pytest.MonkeyPatch, answers: list[Any]) -> list[object]:
    """Answer the lookups of ``siem.example.org`` in turn from ``answers``: an exception is raised,
    anything else returned, and the last answer repeats. Any other host goes to the real lookup.
    Returns that host's lookups."""
    real_getaddrinfo = socket.getaddrinfo
    lookups: list[object] = []

    def _getaddrinfo(host: object, *args: Any, **kwargs: Any) -> Any:
        if host != "siem.example.org":
            return real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]
        lookups.append(host)
        answer = answers[min(len(lookups), len(answers)) - 1]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
    return lookups


def _try_again() -> socket.gaierror:
    return socket.gaierror(socket.EAI_AGAIN, "temporary failure in name resolution")


def _loopback(socktype: int, port: int) -> list[Any]:
    proto = socket.IPPROTO_UDP if socktype == socket.SOCK_DGRAM else socket.IPPROTO_TCP
    return [(socket.AF_INET, socktype, proto, "", ("127.0.0.1", port))]


class _Wrapped:
    """What :class:`_RecordingContext` hands back, so the handler is seen to keep it."""

    def __init__(self, sock: Any) -> None:
        self.sock = sock

    def gettimeout(self) -> float | None:
        return float(self.sock.gettimeout())

    def close(self) -> None:
        self.sock.close()


class _RecordingContext:
    """A stand-in TLS context: records each wrap and does no handshake."""

    def __init__(self) -> None:
        self.wrapped: list[tuple[Any, str]] = []

    def wrap_socket(self, sock: Any, server_hostname: str) -> Any:
        self.wrapped.append((sock, server_hostname))
        return _Wrapped(sock)


def _handler(
    monkeypatch: pytest.MonkeyPatch, protocol: str, port: int, *, defer_connect: bool
) -> _TimeoutSysLogHandler:
    """The forwarder arm :func:`_build_syslog_handler` builds for ``siem.example.org``, with a
    stand-in TLS context so no handshake runs."""
    monkeypatch.setattr(logging_setup, "_build_tls_context", lambda forward: _RecordingContext())
    handler = _build_syslog_handler(
        SyslogForward(host="siem.example.org", port=port, protocol=protocol),
        defer_connect=defer_connect,
    )
    assert isinstance(handler, _TimeoutSysLogHandler)
    return handler


def _assert_wrapped_for_the_collector(handler: _TimeoutSysLogHandler) -> None:
    """The TLS override wrapped the socket for the configured server name, and the handler kept
    the wrapped socket."""
    assert isinstance(handler, _TlsSysLogHandler)
    assert isinstance(handler.socket, _Wrapped)
    context = handler._ssl_context
    assert isinstance(context, _RecordingContext)
    assert context.wrapped == [(handler.socket.sock, "siem.example.org")]


@pytest.mark.parametrize("defer", [False, True], ids=["no-spool", "spool"])
@pytest.mark.parametrize("protocol", ["udp", "tcp", "tls"])
def test_a_swallowed_lookup_error_is_the_one_raised_with_no_second_lookup(
    monkeypatch: pytest.MonkeyPatch, protocol: str, defer: bool
) -> None:
    """BACKLOG #4063: on CPython 3.14.9 the constructor raises the lookup error the stdlib
    swallowed, and looks the name up only once. A second lookup would pay a resolver stall twice,
    and here, where the second lookup would answer, it would hide the failure altogether."""
    _simulate_cpython_3149_syslog_init(monkeypatch)
    socktype = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        lookups = _collector_lookups(monkeypatch, [_try_again(), _loopback(socktype, port)])
        if defer:
            handler = _handler(monkeypatch, protocol, port, defer_connect=True)
            try:
                assert isinstance(handler.startup_error, socket.gaierror)
                assert handler.startup_error.errno == socket.EAI_AGAIN
                assert handler.socket is None
            finally:
                handler.close()
        else:
            with pytest.raises(socket.gaierror) as raised:
                _handler(monkeypatch, protocol, port, defer_connect=False)
            assert raised.value.errno == socket.EAI_AGAIN
    assert len(lookups) == 1


@pytest.mark.parametrize("protocol", ["udp", "tcp", "tls"])
def test_a_flapping_resolver_cannot_turn_a_missing_name_into_a_deferral(
    spool_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    protocol: str,
) -> None:
    """BACKLOG #4063 (Lander finding 1): the first lookup says the name does not exist and a second
    would say "try again". The permanent reading is the first lookup's, so a spool does not defer a
    misconfigured name as "not reachable yet"."""
    _simulate_cpython_3149_syslog_init(monkeypatch)
    _collector_lookups(
        monkeypatch, [socket.gaierror(socket.EAI_NONAME, "name not known"), _try_again()]
    )
    installed = configure_logging(
        "INFO",
        forward=SyslogForward(
            host="siem.example.org",
            port=6514,
            protocol=protocol,
            tls_verify=False,
            spool_dir=str(spool_dir),
            spool_max_bytes=1_000_000,
        ),
    )
    out = capsys.readouterr().out
    assert installed is False
    assert "failed permanently" in out
    assert "not reachable yet" not in out


@pytest.mark.parametrize("cpython_3149", [False, True], ids=["native", "simulated-3.14.9"])
@pytest.mark.parametrize("protocol", ["udp", "tcp", "tls"])
def test_a_construction_that_connects_creates_one_socket(
    monkeypatch: pytest.MonkeyPatch, protocol: str, cpython_3149: bool
) -> None:
    """BACKLOG #4063 (Lander finding 5): a lookup that answers at once costs one lookup and one
    stdlib ``createSocket``. A broken ``socket is None`` guard would connect a second socket and
    leak the first."""
    if cpython_3149:
        _simulate_cpython_3149_syslog_init(monkeypatch)
    real_create = logging.handlers.SysLogHandler.createSocket
    creates: list[object] = []

    def _counting_create(self: logging.handlers.SysLogHandler) -> None:
        creates.append(self)
        real_create(self)

    monkeypatch.setattr(logging.handlers.SysLogHandler, "createSocket", _counting_create)
    socktype = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        lookups = _collector_lookups(monkeypatch, [_loopback(socktype, port)])
        handler = _handler(monkeypatch, protocol, port, defer_connect=True)
        try:
            assert len(lookups) == 1
            assert creates == [handler]
            assert handler.startup_error is None
            assert handler.socket is not None
            if protocol != "udp":
                assert handler.socket.gettimeout() == logging_setup._FORWARD_TCP_TIMEOUT
            if protocol == "tls":
                _assert_wrapped_for_the_collector(handler)
        finally:
            handler.close()


def test_a_send_error_that_is_not_a_network_error_is_never_counted_as_sent(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The entry is dropped as undeliverable and counted, never reported as delivered."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    target = _TimeoutSysLogHandler(address=("127.0.0.1", 9), socktype=socket.SOCK_DGRAM)

    def _bad_emit(self: Any, record: logging.LogRecord) -> None:
        try:
            raise ValueError("formatting bug")
        except ValueError:
            self.handleError(record)

    monkeypatch.setattr(_TimeoutSysLogHandler, "emit", _bad_emit)
    monkeypatch.setattr(logging, "raiseExceptions", False)
    fwd = _build_queued_forwarder(target, fmt="text", spool=spool)
    try:
        assert fwd._listener.stop_within(1.0)  # drive the listener by hand, deterministically
        record = logging.makeLogRecord({"msg": "one", "levelname": "WARNING", "levelno": 30})
        # Consumed, so a FIFO spool is not wedged behind it, and counted as undeliverable.
        assert fwd._listener._send(record) is True
        assert fwd._listener.undeliverable == 1
    finally:
        fwd.close()


def _not_yet_valid() -> ssl.SSLCertVerificationError:
    exc = ssl.SSLCertVerificationError("certificate is not yet valid")
    exc.verify_code = 9  # X509_V_ERR_CERT_NOT_YET_VALID
    return exc


@pytest.mark.parametrize(
    ("error", "permanent"),
    [
        (socket.gaierror(11001, "host not found"), True),
        # The platform's own EAI_NONAME: -2 on Linux, where a bare 11001 exercises nothing.
        (socket.gaierror(socket.EAI_NONAME, "name or service not known"), True),
        # BACKLOG #4063: "no address record", Linux EAI_NODATA (-5) and Windows WSANO_DATA
        # (11004), stays transient, since a resolver not yet up can return either; the reason is
        # at _EAI_NO_SUCH_NAME. Literals, so each runs on every platform.
        (socket.gaierror(-5, "no address associated with hostname"), False),
        (socket.gaierror(11004, "valid name, no data record"), False),
        (socket.gaierror(getattr(socket, "EAI_AGAIN", -3), "temporary failure"), False),
        (ssl.SSLCertVerificationError("certificate verify failed"), True),
        (_not_yet_valid(), False),
        (ConnectionRefusedError("refused"), False),
    ],
    ids=[
        "no-such-name",
        "eai-noname",
        "eai-nodata",
        "wsano-data",
        "dns-try-again",
        "bad-cert",
        "clock-not-synced",
        "refused",
    ],
)
def test_only_a_missing_name_or_a_bad_certificate_is_permanent(
    error: OSError, permanent: bool
) -> None:
    """A temporary DNS failure or a not-yet-valid certificate (a clock not synced at boot) must be
    deferred to the spool, not turn the forwarder off for the life of the process."""
    assert is_permanent_connect_error(error) is permanent


# --- BACKLOG #2278: a read fault is kept, counted and reported as a read fault ----------------------


def _deny_open(*args: Any, **kwargs: Any) -> Any:
    raise PermissionError(13, "sharing violation")


def test_a_read_that_fails_for_another_reason_keeps_every_segment(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """peek()'s split: only a segment that is GONE is retired. A revert to "retire on any error"
    would delete undelivered records, and this is the test that would see it."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        before = _segments(spool_dir)
        assert len(before) > 1
        with monkeypatch.context() as patch:
            patch.setattr(log_spool, "open", _deny_open, raising=False)
            assert spool.peek() is None
            assert spool.peek() is None
        assert spool.read_errors == 2 and spool.read_faulted
        assert spool.unreadable == 0
        assert _segments(spool_dir) == before
        # The fault cleared: everything is still there, in order.
        assert _drain(spool) == [f"record {n:04d}" for n in range(6)]
        assert (
            spool.read_errors == 2 and not spool.read_faulted
        )  # the count stays; the state clears
    finally:
        spool.close()


def test_a_segment_that_is_gone_is_retired_and_the_rest_still_replays(spool_dir: Path) -> None:
    """The other arm of the split, and the control for the test above: a missing file IS retired,
    counted as unreadable and not as a read error."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        first = _segments(spool_dir)[0]
        lost = [json.loads(line)["line"] for line in first.read_bytes().splitlines()]
        first.unlink()
        expected = [f"record {n:04d}" for n in range(6) if f"record {n:04d}" not in lost]
        # The pass that finds it gone moves on to the next segment rather than reading as drained
        # (BACKLOG #5811). NEGATIVE CONTROL: before the fix this peek answered None and `pending`
        # read False with five records still spooled.
        entry = spool.peek()
        assert entry is not None and entry.line == expected[0]
        assert spool.pending
        assert spool.unreadable == 1
        assert spool.read_errors == 0
        assert lost and _drain(spool) == expected
    finally:
        spool.close()


def test_a_spool_directory_out_of_reach_retires_nothing(spool_dir: Path) -> None:
    """A missing directory is a read fault, not a gone segment: every segment stays in the order
    and the cap, and the spool replays whole once the directory is back."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        used = spool.bytes_used
        spool.directory = spool_dir / "out-of-reach"
        assert spool.peek() is None
        assert spool.read_faulted and spool.read_errors == 1 and spool.unreadable == 0
        assert spool.bytes_used == used
        # The writer was closed, so an append while the directory is gone is refused and counted,
        # never written into a file the directory no longer holds.
        assert not spool.append(_entry(99))
        assert spool.dropped == 1
        spool.directory = spool_dir
        assert _drain(spool) == [f"record {n:04d}" for n in range(6)]
    finally:
        spool.close()


def _windows_error(winerror: int | None) -> OSError:
    """An ``OSError`` as Windows raises it for a network fault: ``EINVAL`` with ``winerror`` set.
    Built by hand so the case runs on every platform."""
    exc = OSError(errno.EINVAL, "network fault")
    if winerror is not None:
        setattr(exc, "winerror", winerror)  # noqa: B010 - typeshed declares it on win32 only
    return exc


@pytest.mark.parametrize(
    ("error", "closes_writer"),
    [
        (NotADirectoryError(errno.ENOTDIR, "not a directory"), True),
        (OSError(errno.ENOTCONN, "mount dropped"), True),
        (OSError(errno.ESTALE, "stale handle"), True),
        # BACKLOG #5811: a dropped SMB share, which Python maps to EINVAL. NEGATIVE CONTROL: on
        # ce55b5324d both read as one file failing and left the writer open.
        (_windows_error(64), True),
        (_windows_error(59), True),
        (_windows_error(None), False),
        (OSError(errno.EMFILE, "too many open files"), False),
    ],
)
def test_a_read_error_that_means_the_directory_is_out_of_reach_closes_the_writer(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, error: OSError, closes_writer: bool
) -> None:
    """An error that says the directory itself is gone or out of reach closes the writer, as a
    missing directory does; one file failing does not. Either way nothing is retired.
    NEGATIVE CONTROL: on 0a71e8b23f only a missing directory closed the writer."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(3):
            assert spool.append(_entry(n))
        assert spool._writer is not None
        used = spool.bytes_used

        def refuse(seq: int) -> None:
            raise error

        monkeypatch.setattr(spool, "_open_reader", refuse)
        assert spool.peek() is None
        assert spool.read_faulted and spool.read_errors == 1 and spool.unreadable == 0
        assert spool.bytes_used == used
        assert (spool._writer is None) is closes_writer
    finally:
        spool.close()


def test_a_transient_file_not_found_on_a_segment_still_there_retires_nothing(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An open that says ENOENT for a segment whose file is still there (an SMB share
    reconnecting) is a read fault: nothing is retired or unlinked, and the spool replays whole
    once the open works again. NEGATIVE CONTROL: on 254672242d the directory still existed, so
    every head segment was retired and unlinked in one peek."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        segments = _segments(spool_dir)
        assert len(segments) >= 2
        used = spool.bytes_used
        real_open = spool._open_reader

        def transient(seq: int) -> None:
            raise FileNotFoundError(errno.ENOENT, "network path not found")

        monkeypatch.setattr(spool, "_open_reader", transient)
        assert spool.peek() is None
        assert spool.read_faulted and spool.read_errors == 1 and spool.unreadable == 0
        assert spool.bytes_used == used
        assert _segments(spool_dir) == segments
        monkeypatch.setattr(spool, "_open_reader", real_open)
        assert _drain(spool) == [f"record {n:04d}" for n in range(6)]
    finally:
        spool.close()


def _windows_not_found(winerror: int | None) -> FileNotFoundError:
    """A ``FileNotFoundError`` as Windows raises it, ``winerror`` set (or not). Built by hand so
    the case runs on every platform."""
    exc = FileNotFoundError(errno.ENOENT, "not found")
    if winerror is not None:
        setattr(exc, "winerror", winerror)  # noqa: B010 - typeshed declares it on win32 only
    return exc


def _peek_with_segment_lstat_raising(
    spool: LogSpool, monkeypatch: pytest.MonkeyPatch, exc: FileNotFoundError
) -> SpoolEntry | None:
    """``peek()`` with the head segment's open and its own lstat both raising ``exc``."""

    class _Path:
        def lstat(self) -> None:
            raise exc

    def refuse(seq: int) -> None:
        raise exc

    with monkeypatch.context() as patch:
        patch.setattr(spool, "_open_reader", refuse)
        patch.setattr(spool, "_path", lambda seq: _Path())
        return spool.peek()


@pytest.mark.parametrize("winerror", [None, 3, 53, 67, 64])
def test_on_windows_only_winerror_2_confirms_a_segment_gone(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, winerror: int | None
) -> None:
    """On Windows a FileNotFoundError from the segment's own lstat confirms it gone only with
    ``winerror`` 2. Path-not-found (3), a network path (53, 67), a share out of reach (64) and
    no ``winerror`` at all are read faults: nothing is retired or unlinked. NEGATIVE CONTROL: on
    5c4efdd3a1 None and 3 retired the head segment."""
    monkeypatch.setattr(log_spool, "_WINDOWS", True)
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        segments = _segments(spool_dir)
        used = spool.bytes_used
        assert (
            _peek_with_segment_lstat_raising(spool, monkeypatch, _windows_not_found(winerror))
            is None
        )
        assert spool.read_faulted and spool.read_errors == 1 and spool.unreadable == 0
        assert spool.bytes_used == used
        assert _segments(spool_dir) == segments
        assert _drain(spool) == [f"record {n:04d}" for n in range(6)]
    finally:
        spool.close()


def test_on_windows_winerror_2_does_confirm_a_segment_gone(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: ``winerror`` 2 retires the head segment."""
    monkeypatch.setattr(log_spool, "_WINDOWS", True)
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        _peek_with_segment_lstat_raising(spool, monkeypatch, _windows_not_found(2))
        assert spool.unreadable >= 1 and spool.read_errors == 0
    finally:
        spool.close()


@pytest.mark.parametrize("winerror", [2, 3])
def test_a_dangling_symlink_segment_is_retired_and_its_link_unlinked(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, winerror: int
) -> None:
    """A head segment whose path is a dangling symlink (lstat shows a link, stat says not found)
    cannot be opened now, so it counts as gone: it is retired, the link itself is unlinked, and
    the read moves on. On Windows a link into a missing directory gives winerror 3, which counts
    here too. NEGATIVE CONTROL: on cf6bfe2d12 the link was not unlinked, and winerror 3 wedged
    the spool."""
    monkeypatch.setattr(log_spool, "_WINDOWS", True)
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        segments = _segments(spool_dir)
        assert len(segments) >= 2
        head_seq = spool._segments[0]
        lost = [json.loads(line)["line"] for line in segments[0].read_bytes().splitlines()]
        real_open, real_path = spool._open_reader, spool._path
        unlinked: list[int] = []

        class _DanglingLink:
            def lstat(self) -> os.stat_result:
                return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))

            def stat(self) -> None:
                raise _windows_not_found(winerror)

        def open_reader(seq: int) -> None:
            if seq == head_seq:
                raise _windows_not_found(2)
            real_open(seq)

        def path_for(seq: int) -> Any:
            return _DanglingLink() if seq == head_seq else real_path(seq)

        def record_unlink(seq: int) -> bool:
            unlinked.append(seq)
            return True

        with monkeypatch.context() as patch:
            patch.setattr(spool, "_open_reader", open_reader)
            patch.setattr(spool, "_path", path_for)
            patch.setattr(spool, "_unlink", record_unlink)
            entry = spool.peek()
            assert entry is not None and entry.line not in lost
            assert spool.unreadable == 1 and spool.read_errors == 0
            assert unlinked == [head_seq]
    finally:
        spool.close()


def test_a_spool_with_a_retired_dangling_link_opens_again_and_sends_the_rest(
    spool_dir: Path, tmp_path: Path
) -> None:
    """A real dangling symlink at the head: peek retires it and removes the link, so the next
    start's open() does not refuse the spool, and every other undelivered segment is sent.
    NEGATIVE CONTROL: on cf6bfe2d12 the link stayed and the restart raised SpoolUnavailable."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        head = _segments(spool_dir)[0]
        lost = [json.loads(line)["line"] for line in head.read_bytes().splitlines()]
        head.unlink()
        try:
            os.symlink(tmp_path / "nowhere" / "target.jsonl", head)
        except (OSError, NotImplementedError) as exc:  # Windows without symlink rights
            pytest.skip(f"cannot create a symlink here: {type(exc).__name__}")
        entry = spool.peek()
        assert entry is not None and entry.line not in lost
        assert not os.path.lexists(head)
    finally:
        spool.close()
    restarted = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    restarted.open()
    try:
        expected = [f"record {n:04d}" for n in range(6) if f"record {n:04d}" not in lost]
        assert _drain(restarted) == expected
    finally:
        restarted.close()


def test_a_directory_that_drops_between_the_checks_retires_nothing(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The segment's lstat says gone, but the directory is out of reach by the time it is checked
    after it: a read fault that retires nothing and closes the writer. NEGATIVE CONTROL: on
    5c4efdd3a1 the directory was checked first and read present, so the segment was retired."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        segments = _segments(spool_dir)
        used = spool.bytes_used

        class _DropsThenGone:
            def lstat(self) -> None:
                spool.directory = spool_dir / "dropped"  # the share drops here
                raise _windows_not_found(2)

        def refuse(seq: int) -> None:
            raise _windows_not_found(2)

        with monkeypatch.context() as patch:
            patch.setattr(spool, "_open_reader", refuse)
            patch.setattr(spool, "_path", lambda seq: _DropsThenGone())
            assert spool.peek() is None
        assert spool.read_faulted and spool.read_errors == 1 and spool.unreadable == 0
        assert spool.bytes_used == used
        assert spool._writer is None
        spool.directory = spool_dir
        assert _segments(spool_dir) == segments
        assert _drain(spool) == [f"record {n:04d}" for n in range(6)]
    finally:
        spool.close()


def test_a_read_error_with_no_winerror_closes_the_writer_when_the_directory_is_unreachable(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows a read error from open() carries no ``winerror``, so the directory is probed:
    one out of reach closes the writer. NEGATIVE CONTROL: on 5c4efdd3a1 the writer stayed open."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(3):
            assert spool.append(_entry(n))
        assert spool._writer is not None

        def refuse(seq: int) -> None:
            spool.directory = spool_dir / "dropped"
            raise OSError(errno.EINVAL, "network fault")

        with monkeypatch.context() as patch:
            patch.setattr(spool, "_open_reader", refuse)
            assert spool.peek() is None
        assert spool.read_faulted and spool.unreadable == 0
        assert spool._writer is None
    finally:
        spool.directory = spool_dir
        spool.close()


def test_a_segment_confirmed_gone_is_never_unlinked_or_reclaimed(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A segment retired as confirmed missing is not unlinked and not queued for reclaim(), so a
    file the confirmation missed is never deleted. NEGATIVE CONTROL: on d02d8b8f3e the retire
    unlinked it, and a failed unlink queued it for reclaim()."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(6):
            assert spool.append(_entry(n))
        first = _segments(spool_dir)[0]
        held = first.read_bytes()
        first.unlink()
        unlinked: list[int] = []
        real_unlink = spool._unlink

        def failing_unlink(seq: int) -> bool:
            unlinked.append(seq)
            return False

        monkeypatch.setattr(spool, "_unlink", failing_unlink)
        assert spool.peek() is not None
        assert spool.unreadable == 1
        assert unlinked == []
        monkeypatch.setattr(spool, "_unlink", real_unlink)
        # The file the confirmation called gone turns out to be there after all.
        first.write_bytes(held)
        spool.reclaim()
        assert first.read_bytes() == held
    finally:
        spool.close()


def test_two_segments_gone_in_a_row_are_both_passed_over(spool_dir: Path) -> None:
    """One peek walks past every missing segment at the head, however many, to the oldest one left."""
    spool = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=60)
    spool.open()
    try:
        for n in range(8):
            assert spool.append(_entry(n))
        segments = _segments(spool_dir)
        assert len(segments) >= 3
        gone = [
            json.loads(line)["line"]
            for path in segments[:2]
            for line in path.read_bytes().splitlines()
        ]
        for path in segments[:2]:
            path.unlink()
        expected = [f"record {n:04d}" for n in range(8) if f"record {n:04d}" not in gone]
        entry = spool.peek()
        assert entry is not None and entry.line == expected[0]
        assert spool.unreadable == 2
        assert _drain(spool) == expected
    finally:
        spool.close()


def _idle_listener(spool: LogSpool) -> tuple[_ForwardQueueListener, _FlakyCollector]:
    """A listener that is never started, so the test drives it on its own thread."""
    collector = _FlakyCollector()
    return _ForwardQueueListener(queue.Queue(), collector, spool=spool), collector


def test_a_spool_read_fault_is_reported_as_one_rate_limited_and_without_record_text(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    listener, _ = _idle_listener(spool)
    try:
        assert spool.append(SpoolEntry(level="ERROR", line="secret-marker-2278"))
        monkeypatch.setattr(log_spool, "open", _deny_open, raising=False)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
            for _ in range(5):
                listener._replay()
        reports = [r.getMessage() for r in caplog.records if "could not read" in r.getMessage()]
        assert len(reports) == 1  # five faults, one line
        assert str(spool_dir) in reports[0] and "1 read(s) failed" in reports[0]
        assert "is full" not in reports[0]
        assert "secret-marker-2278" not in caplog.text
        assert spool.read_errors == 5

        # Past the interval the next report carries what the first one did not.
        listener._last_spool_read_report = time.monotonic() - 3600
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
            listener._replay()
        (later,) = [r.getMessage() for r in caplog.records if "could not read" in r.getMessage()]
        assert "5 read(s) failed (6 since this process started)" in later
    finally:
        spool.close()


def test_a_drained_spool_reports_no_read_fault(
    spool_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The control: peek() also returns None for a drained spool, and that is not a fault."""
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    listener, _ = _idle_listener(spool)
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
            listener._replay()
        assert "could not read" not in caplog.text
    finally:
        spool.close()


@pytest.mark.parametrize("faulted", [True, False], ids=["after-a-read-fault", "plain-full"])
def test_the_full_spool_report_names_a_read_fault_only_when_there_was_one(
    spool_dir: Path, caplog: pytest.LogCaptureFixture, faulted: bool
) -> None:
    size = len(_entry(0).encode())
    spool = LogSpool(spool_dir, max_bytes=size)
    spool.open()
    listener, _ = _idle_listener(spool)
    try:
        assert spool.append(_entry(0))
        spool.read_faulted = faulted
        record = logging.makeLogRecord({"msg": "next", "levelname": "WARNING", "levelno": 30})
        with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
            assert listener._spool_record(record) is False
        (report,) = [r.getMessage() for r in caplog.records if "dropped" in r.getMessage()]
        assert ("cannot be read just now" in report) is faulted
    finally:
        spool.close()


# --- BACKLOG #2279: follow-ups from the two review rounds of engine PR 1725 -------------------------


def _deny_unlink(self: Path, missing_ok: bool = False) -> None:
    raise PermissionError(13, "file in use")


def test_a_segment_whose_delete_failed_still_counts_against_the_cap(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sent segment that would not delete is still on disk. Forgetting its size let the directory
    grow past the cap by one segment per failed delete."""
    size = len(_entry(0).encode())
    spool = LogSpool(spool_dir, max_bytes=size * 2, segment_bytes=size)
    spool.open()
    try:
        assert spool.append(_entry(0)) and spool.append(_entry(1))
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", _deny_unlink)
            assert _drain(spool) == ["record 0000", "record 0001"]
            assert spool.undeleted_segments == 2
            on_disk = sum(p.stat().st_size for p in _segments(spool_dir))
            assert spool.bytes_used == on_disk == size * 2
            assert spool.append(_entry(2)) is False  # the cap still holds
            assert spool.dropped == 1
        # Deletes work again: one reclaim frees the space, and the next append fits.
        spool.reclaim()
        assert spool.undeleted_segments == 0
        assert spool.append(_entry(2))
        assert spool.bytes_used == sum(p.stat().st_size for p in _segments(spool_dir)) == size
        assert _drain(spool) == ["record 0002"]  # the sent entries are not sent again
    finally:
        spool.close()


class _FullDiskWriter:
    """A segment writer on a full disk: the file was created, and every write is refused."""

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def write(self, data: bytes) -> int:
        raise OSError(28, "No space left on device")

    def flush(self) -> None:
        pass

    def close(self) -> None:
        os.close(self._fd)


def test_a_full_disk_leaves_no_empty_segments_and_burns_no_sequence_numbers(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "fdopen", lambda fd, mode: _FullDiskWriter(fd))
            assert [spool.append(_entry(n)) for n in range(3)] == [False, False, False]
        assert spool.dropped == 3
        assert _segments(spool_dir) == []  # was: three empty files
        assert spool.bytes_used == 0
        # The disk has room again: the first real segment takes the first number.
        assert spool.append(_entry(3))
        assert [p.name for p in _segments(spool_dir)] == ["spool-000000000001.jsonl"]
        assert _drain(spool) == ["record 0003"]
    finally:
        spool.close()


def test_a_failed_write_that_left_bytes_keeps_the_segment_and_counts_them(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: only an EMPTY segment is removed. A torn write stays on
    disk, is counted against the cap, and is skipped as unreadable on replay."""

    class _TornWriter(_FullDiskWriter):
        def write(self, data: bytes) -> int:
            os.write(self._fd, data[:5])
            raise OSError(28, "No space left on device")

    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "fdopen", lambda fd, mode: _TornWriter(fd))
            assert spool.append(_entry(0)) is False
        assert len(_segments(spool_dir)) == 1
        assert spool.bytes_used == 5
        assert spool.append(_entry(1))
        assert len(_segments(spool_dir)) == 2  # never appended after the torn line
        assert _drain(spool) == ["record 0001"]
        assert spool.unreadable == 1
    finally:
        spool.close()


def _bad_certificate(self: Any) -> None:
    raise ssl.SSLCertVerificationError("certificate verify failed")


def _forward_to(spool_dir: Path, *, spool_max_bytes: int = 1_000_000) -> SyslogForward:
    return SyslogForward(
        host="siem.example.org",
        port=6514,
        protocol="tcp",
        spool_dir=str(spool_dir),
        spool_max_bytes=spool_max_bytes,
    )


def test_a_handler_that_fails_to_build_leaves_no_spool_directory_or_lock_behind(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spool is opened before the handler is built. When the build fails for good, the
    directory and ``spool.lock`` that open created must not outlive it."""
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _bad_certificate)
    assert configure_logging("INFO", forward=_forward_to(spool_dir)) is False
    assert not spool_dir.exists()


def test_that_cleanup_never_removes_a_directory_or_segments_that_were_there_before(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: undelivered segments from an earlier run, and the directory that holds them,
    are kept. An empty directory that already existed is kept too, without the new lock file."""
    earlier = LogSpool(spool_dir, max_bytes=100_000)
    earlier.open()
    earlier.append(_entry(0))
    earlier.close()
    (spool_dir / "spool.lock").unlink()  # so the open below is the one that creates it
    kept = [(p.name, p.read_bytes()) for p in _segments(spool_dir)]
    assert kept

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _bad_certificate)
    assert configure_logging("INFO", forward=_forward_to(spool_dir)) is False
    assert [(p.name, p.read_bytes()) for p in _segments(spool_dir)] == kept

    empty = spool_dir.parent / "already-there"
    empty.mkdir()
    assert configure_logging("INFO", forward=_forward_to(empty)) is False
    assert empty.is_dir() and list(empty.iterdir()) == []


@pytest.mark.parametrize("leftover", [2, 0], ids=["segments-left", "nothing-left"])
def test_a_spool_turned_off_warns_once_about_segments_it_leaves_and_deletes_none(
    spool_dir: Path, caplog: pytest.LogCaptureFixture, leftover: int
) -> None:
    earlier = LogSpool(spool_dir, max_bytes=100_000, segment_bytes=1)
    earlier.open()
    for n in range(leftover):
        earlier.append(_entry(n))
    earlier.close()
    before = [(p.name, p.read_bytes()) for p in _segments(spool_dir)]
    assert len(before) == leftover

    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        assert _open_forward_spool(_forward_to(spool_dir, spool_max_bytes=0)) is None
    warnings = [r.getMessage() for r in caplog.records if "turned off" in r.getMessage()]
    assert len(warnings) == (1 if leftover else 0)
    if leftover:
        assert str(spool_dir) in warnings[0] and "2 spool segment(s)" in warnings[0]
    assert [(p.name, p.read_bytes()) for p in _segments(spool_dir)] == before


class _ListCollector(logging.Handler):
    """Stands in for the collector socket: keeps every record the forwarder hands it."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _start_forwarding_to_a_list(
    monkeypatch: pytest.MonkeyPatch, forward: SyslogForward, *, level: str = "INFO"
) -> _ListCollector:
    collector = _ListCollector()
    monkeypatch.setattr(logging_setup, "_build_syslog_handler", lambda _forward, **_kw: collector)
    assert configure_logging(level, forward=forward) is True
    root = logging.getLogger()
    (fwd,) = [h for h in root.handlers if isinstance(h, _ForwardQueueHandler)]
    root.removeHandler(fwd)
    fwd.close()  # drains the hand-off queue into the collector
    return collector


_NO_LOSS_PROTECTION = "runs without loss protection"


@pytest.mark.parametrize("level", ["INFO", "ERROR"])
def test_a_spool_turned_off_says_once_to_the_collector_that_it_has_no_loss_protection(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, level: str
) -> None:
    """Vault BACKLOG #1199, ASVS 16.4.3 gap (iii): a clean spool-off start used to say nothing.

    Read off the collector, not caplog, because the separate system is the reader that counts.
    At ERROR too: a level above WARNING must not make the start silent again."""
    collector = _start_forwarding_to_a_list(
        monkeypatch, _forward_to(spool_dir, spool_max_bytes=0), level=level
    )
    said = [r for r in collector.records if _NO_LOSS_PROTECTION in r.getMessage()]
    assert len(said) == 1
    assert said[0].levelno == logging.WARNING
    assert "siem.example.org:6514 (tcp)" in said[0].getMessage()
    assert "forward_spool_max_bytes = 0" in said[0].getMessage()


def test_a_spool_that_opens_does_not_say_it_has_no_loss_protection(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = _start_forwarding_to_a_list(monkeypatch, _forward_to(spool_dir))
    assert not [r for r in collector.records if _NO_LOSS_PROTECTION in r.getMessage()]


def test_a_spool_off_start_whose_forwarder_does_not_install_does_not_say_it_runs(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No forwarder, no claim that forwarding runs: the 'unavailable' line says what happened."""
    seen: list[str] = []

    class _Seen(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            seen.append(record.getMessage())
            return True

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _refuse)
    watcher = _Seen()
    logging_setup._log.addFilter(watcher)
    try:
        assert configure_logging("INFO", forward=_forward_to(spool_dir, spool_max_bytes=0)) is False
    finally:
        logging_setup._log.removeFilter(watcher)
    assert any("is unavailable" in m for m in seen)  # control: the filter sees this logger
    assert not [m for m in seen if _NO_LOSS_PROTECTION in m]


def test_records_spooled_at_shutdown_are_reported_once_with_their_count(
    spool_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    fwd = _build_queued_forwarder(_FlakyCollector(), fmt="text", spool=spool)
    listener = fwd._listener
    assert listener.stop_within(1.0)  # the thread has ended; drive the listener by hand
    listener._drain_deadline = time.monotonic() - 1.0  # the drain window has closed
    for n in range(3):
        listener.handle(
            logging.makeLogRecord({"msg": f"late {n}", "levelname": "WARNING", "levelno": 30})
        )
    assert listener.spooled_at_stop == 3
    with caplog.at_level(logging.INFO, logger="messagefoundry.logging_setup"):
        fwd.close()
        fwd.close()  # idempotent: no second report
    reports = [r.getMessage() for r in caplog.records if "drain deadline" in r.getMessage()]
    assert len(reports) == 1
    assert "moved at least 3 record(s)" in reports[0] and str(spool_dir) in reports[0]
    assert "late" not in caplog.text  # a count and a directory, never a record
    assert len(_segments(spool_dir)) == 1  # and they are on disk for the next start


def test_the_shutdown_report_is_not_counted_as_a_dropped_record(spool_dir: Path) -> None:
    """logging.shutdown() closes the handler while it is still on the root logger, so the report
    comes straight back to it. Counting that as a drop logged a false "queue is full" warning on
    a shutdown that lost nothing."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    fwd = _build_queued_forwarder(_FlakyCollector(), fmt="text", spool=spool)
    root = logging.getLogger()
    root.addHandler(fwd)
    saved = root.level
    root.setLevel(logging.INFO)
    try:
        listener = fwd._listener
        assert listener.stop_within(1.0)
        listener._drain_deadline = time.monotonic() - 1.0
        listener.handle(logging.makeLogRecord({"msg": "late", "levelname": "INFO", "levelno": 20}))
        assert listener.spooled_at_stop == 1  # so close() has something to report
        fwd.close()
        assert fwd.dropped == 0
        # The control: a record that is NOT the handler's own report is still counted.
        root.info("after close")
        assert fwd.dropped == 1
    finally:
        root.removeHandler(fwd)
        root.setLevel(saved)


def test_close_makes_a_last_try_at_a_segment_whose_delete_failed(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sent segment left on disk is replayed whole by the next start, which cannot tell it from
    a waiting one. close() is the last chance to remove it."""
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    spool.append(_entry(0))
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", _deny_unlink)
        assert _drain(spool) == ["record 0000"]
    assert len(_segments(spool_dir)) == 1 and spool.undeleted_segments == 1
    spool.close()
    assert _segments(spool_dir) == []

    again = LogSpool(spool_dir, max_bytes=100_000)
    again.open()
    try:
        assert _drain(again) == []  # nothing is sent twice
    finally:
        again.close()


def test_the_listener_retries_a_failed_delete_at_most_once_per_interval(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    listener, _ = _idle_listener(spool)
    tries: list[int] = []
    monkeypatch.setattr(spool, "reclaim", lambda: tries.append(1))
    try:
        listener._reclaim_spool()
        assert tries == []  # nothing is left over, so nothing is tried
        spool.append(_entry(0))
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", _deny_unlink)
            assert _drain(spool) == ["record 0000"]
        for _ in range(50):
            listener._reclaim_spool()
        assert tries == [1]  # fifty passes, one try
        first_wait = listener._reclaim_at
        listener._reclaim_at = 0.0  # the wait has passed
        listener._reclaim_spool()
        assert tries == [1, 1]
        assert listener._reclaim_delay > 1.0 and listener._reclaim_at > first_wait  # it backs off
    finally:
        spool.close()


def test_the_full_spool_report_names_sent_segments_that_would_not_delete(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    size = len(_entry(0).encode())
    spool = LogSpool(spool_dir, max_bytes=size)
    spool.open()
    listener, _ = _idle_listener(spool)
    try:
        assert spool.append(_entry(0))
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", _deny_unlink)
            assert _drain(spool) == ["record 0000"]
            record = logging.makeLogRecord({"msg": "next", "levelname": "WARNING", "levelno": 30})
            with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
                assert listener._spool_record(record) is False
        (report,) = [r.getMessage() for r in caplog.records if "dropped" in r.getMessage()]
        assert "1 segment(s) already sent could not be deleted" in report
    finally:
        spool.close()


def test_a_failed_start_also_removes_the_parent_directories_it_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default spool directory is two levels below the store directory, and both are new."""
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _bad_certificate)
    forward = _forward_to(store_dir / "log-spool" / "engine")
    assert configure_logging("INFO", forward=forward) is False
    assert list(store_dir.iterdir()) == []


def test_a_failed_start_names_the_segments_an_earlier_run_left(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    earlier = LogSpool(spool_dir, max_bytes=100_000)
    earlier.open()
    earlier.append(_entry(0))
    earlier.close()
    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _bad_certificate)
    assert configure_logging("INFO", forward=_forward_to(spool_dir)) is False
    out = capsys.readouterr().out
    assert "did not start" in out and "still holds 1 spool segment(s)" in out
    assert len(_segments(spool_dir)) == 1


def test_a_spool_directory_that_cannot_be_listed_is_reported_not_read_as_empty(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    spool_dir.mkdir()

    def _deny_iterdir(self: Path) -> Any:
        raise PermissionError(13, "access denied")

    monkeypatch.setattr(Path, "iterdir", _deny_iterdir)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        assert _open_forward_spool(_forward_to(spool_dir, spool_max_bytes=0)) is None
    assert "could not be checked" in caplog.text


def test_the_running_listener_frees_a_sent_segment_once_deletes_work_again(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through handle(), not by calling the retry directly: handle() and the idle poll are the only
    things that free such a segment while the engine runs."""
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    listener, collector = _idle_listener(spool)
    collector.down = False
    try:
        spool.append(_entry(0))
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", _deny_unlink)
            listener._replay()  # sends it; the delete fails
            assert spool.undeleted_segments == 1
            listener.handle(logging.makeLogRecord({"msg": "a", "levelname": "INFO", "levelno": 20}))
            assert spool.undeleted_segments == 1  # still held
        listener._reclaim_at = 0.0  # the wait has passed, and deletes work again
        listener.handle(logging.makeLogRecord({"msg": "b", "levelname": "INFO", "levelno": 20}))
        assert spool.undeleted_segments == 0 and _segments(spool_dir) == []
        assert listener._reclaim_delay == 1.0  # and the backoff starts over
    finally:
        spool.close()


def test_shutdown_tries_the_delete_before_dropping_a_record_for_space(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    size = len(_entry(0).encode())
    spool = LogSpool(spool_dir, max_bytes=size)
    spool.open()
    listener, _ = _idle_listener(spool)
    try:
        assert spool.append(_entry(0))
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", _deny_unlink)
            assert _drain(spool) == ["record 0000"]
            listener._reclaim_spool()  # fails, and sets a wait
        assert listener._reclaim_at > time.monotonic()
        listener._drain_deadline = time.monotonic() - 1.0
        listener.handle(
            logging.makeLogRecord({"msg": "record 0001", "levelname": "INFO", "levelno": 20})
        )
        assert (listener.spooled_at_stop, listener.undrained) == (1, 0)
    finally:
        spool.close()


def test_a_sent_segment_still_undeletable_at_close_is_reported(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    spool = LogSpool(spool_dir, max_bytes=100_000)
    spool.open()
    fwd = _build_queued_forwarder(_FlakyCollector(), fmt="text", spool=spool)
    assert fwd._listener.stop_within(1.0)
    spool.append(_entry(0))
    monkeypatch.setattr(Path, "unlink", _deny_unlink)
    assert _drain(spool) == ["record 0000"]
    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        fwd.close()
    monkeypatch.undo()
    assert "left 1 spool segment(s)" in caplog.text and "sends them again" in caplog.text


def test_a_spool_that_cannot_be_opened_names_the_segments_it_strands(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """And the control: a directory another process holds is NOT named, because that process sends
    what it holds. Its WARNING adds facts instead, never a procedure (BACKLOG #5400): it cannot say
    who holds the lock, so any instruction would be wrong for some deployment. An unusable
    directory's WARNING adds none of them. Either way the opener returns ``None``, so the forwarder
    runs without a spool (#1966)."""
    from messagefoundry.config.settings import load_settings

    # The names the WARNING gives are the real ones: the variable reaches the setting.
    named = load_settings(environ={"MEFOR_LOGGING_FORWARD_SPOOL_DIR": "other"}, default_file=False)
    assert named.logging.forward_spool_dir == "other"

    earlier = LogSpool(spool_dir, max_bytes=100_000)
    earlier.open()
    earlier.append(_entry(0))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        assert _open_forward_spool(_forward_to(spool_dir)) is None  # held by `earlier`
    assert "in use by another process" in caplog.text and "still holds" not in caplog.text
    [in_use] = [r for r in caplog.records if "in use by another process" in r.getMessage()]
    assert in_use.levelno == logging.WARNING
    message = in_use.getMessage()
    _, prefix, facts = message.partition("off-box log forwarding runs without an on-disk spool")
    assert prefix, message
    assert facts == _SPOOL_IN_USE_FACTS  # the constant the control below looks for
    # ``_try_lock`` reads any lock fault as contention, so the holder is only the usual cause.
    assert "Another process usually holds the lock, but a fault taking the lock reads" in facts
    # ``_open_forward_spool`` runs once, at configure time, so only a restart retries the lock.
    assert "runs without an on-disk spool until it restarts with a spool it can lock." in facts
    # The stranding fact, over every way a process's directory can change: the setting, its
    # variable, and the default ``__main__._forward_spool_dir`` derives.
    assert (
        "Only the process holding a spool directory's lock sends that directory's segments."
        in facts
    )
    assert (
        "any change to a process's spool directory leaves the segments in its old directory unsent "
        "until a process opens that directory again." in facts
    )
    assert (
        "[logging].forward_spool_dir (environment variable MEFOR_LOGGING_FORWARD_SPOOL_DIR)"
        in facts
    )
    assert "the store path or the shard id the default directory is derived from." in facts
    assert 'One directory serves one process (ADR 0200, "One process per directory").' in facts
    # No branch of a procedure: each of these was wrong for some deployment.
    lowered = facts.lower()
    for imperative in (
        "stop one",
        "stop the duplicate",
        "give this process",
        "give that one",
        "restart this one",
        "each of the others",
        "Never change",
        "Leave the process",
        "where it is",
    ):
        assert imperative.lower() not in lowered, imperative
    assert message.endswith(".")
    earlier.close()

    def _deny_lock(path: Any, flags: int, mode: int = 0o777) -> int:
        raise PermissionError(13, "read-only directory")

    caplog.clear()
    monkeypatch.setattr(os, "open", _deny_lock)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
        assert _open_forward_spool(_forward_to(spool_dir)) is None
    monkeypatch.undo()
    assert (
        "could not be opened, but" in caplog.text
        and "still holds 1 spool segment(s)" in caplog.text
    )
    assert "is not usable" in caplog.text
    # The positive control: an unusable directory gets none of the in-use facts.
    assert "MEFOR_LOGGING_FORWARD_SPOOL_DIR" not in caplog.text
    assert _SPOOL_IN_USE_FACTS not in caplog.text


def test_open_removes_only_the_directories_it_made_when_it_fails_partway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "log-spool" / "engine"
    real_mkdir = os.mkdir

    def _mkdir(path: Any, mode: int = 0o777) -> None:
        if Path(path) == target:
            raise PermissionError(13, "cannot create the leaf")
        real_mkdir(path, mode)

    monkeypatch.setattr(os, "mkdir", _mkdir)
    with pytest.raises(SpoolUnavailable):
        LogSpool(target, max_bytes=1_000).open()
    monkeypatch.undo()
    assert list(tmp_path.iterdir()) == []  # the parent it made on the way is gone too


def test_open_makes_its_parents_with_no_group_or_other_write_bit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #5636. The spool sits under the store directory and often creates it, before
    the TLS mint does, so a parent gets 0o755 and the leaf 0o700: never a mode that lets the umask
    leave a group write bit on the directory the engine's own key goes into."""
    target = tmp_path / "store" / "log-spool" / "engine"
    real_mkdir = os.mkdir
    asked: dict[Path, int] = {}

    def _mkdir(path: Any, mode: int = 0o777) -> None:
        asked[Path(path)] = mode
        real_mkdir(path, mode)

    monkeypatch.setattr(os, "mkdir", _mkdir)
    spool = LogSpool(target, max_bytes=1_000)
    spool.open()
    spool.close()
    monkeypatch.undo()
    assert asked == {
        tmp_path / "store": 0o755,
        tmp_path / "store" / "log-spool": 0o755,
        target: 0o700,
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes and umask")
def test_a_store_directory_the_spool_makes_under_umask_002_passes_the_key_check(
    tmp_path: Path,
) -> None:
    """The same, for real: under umask 002 the store directory the spool creates is 0755, and a
    key the engine mints there passes the key-file check."""
    import stat

    from messagefoundry.restricted_file import broad_access_problem, write_restricted_file

    store = tmp_path / "store"
    old = os.umask(0o002)
    try:
        spool = LogSpool(store / "log-spool" / "engine", max_bytes=1_000)
        spool.open()
        spool.close()
    finally:
        os.umask(old)
    assert stat.S_IMODE(store.stat().st_mode) == 0o755
    key = store / "api-generated-key.pem"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None


def test_a_replayed_lone_surrogate_is_sent_escaped_not_dropped(spool_dir: Path) -> None:
    """BACKLOG #2279 item 2a. The spool writes a raw caller's lone surrogate (the encode fallback),
    but the send's UTF-8 encode refused it, so replay dropped the entry as undeliverable. Replay
    now escapes the surrogate the way the near-side scrub would, and nothing else: a spooled
    text-format traceback keeps its real line breaks, as the same record sent live does."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as collector:
        collector.bind(("127.0.0.1", 0))
        collector.settimeout(5.0)
        target = _TimeoutSysLogHandler(
            address=("127.0.0.1", collector.getsockname()[1]), socktype=socket.SOCK_DGRAM
        )
        fwd = _build_queued_forwarder(target, fmt="text", spool=spool)
        try:
            assert fwd._listener.stop_within(1.0)  # drive the listener by hand, deterministically
            fwd._listener._drain_deadline = None  # replay runs only outside a drain
            fwd._listener._retry_at = 0.0
            assert spool.append(SpoolEntry(level="WARNING", line="bad byte \udc80 here"))
            block = "failed \\u0085\n    | Traceback (most recent call last):\n    | ValueError: x"
            assert spool.append(SpoolEntry(level="ERROR", line=block))
            fwd._listener._replay()
            first, second = collector.recv(4096), collector.recv(4096)
            assert fwd._listener.undeliverable == 0
            assert first.endswith(b"bad byte \\\\udc80 here\x00")
            assert second.endswith(block.encode("ascii") + b"\x00")  # sent as spooled
            assert not spool.pending
        finally:
            fwd.close()


# --- BACKLOG #5923: the UDP arm reports its own send errors, and handleError prints nothing ------


class _FailingDatagramSocket:
    """A UDP socket whose ``sendto`` raises ``error``, recording what it was handed."""

    def __init__(self, error: OSError) -> None:
        self.error = error
        self.sent: list[bytes] = []

    def sendto(self, data: bytes, _address: Any) -> int:
        self.sent.append(data)
        raise self.error

    def close(self) -> None:
        pass


def _swap_socket(target: Any, fake: _FailingDatagramSocket) -> None:
    """Put ``fake`` in place of ``target``'s real socket, closing the real one so it does not leak."""
    target.socket.close()
    target.socket = fake


def _udp_forwarder(spool: LogSpool | None) -> tuple[Any, _ForwardQueueHandler]:
    """A UDP forwarder whose listener is stopped, so a test drives it by hand."""
    target = _build_syslog_handler(SyslogForward(host="127.0.0.1", port=9, protocol="udp"))
    fwd = _build_queued_forwarder(target, fmt="text", spool=spool)
    if not fwd._listener.stop_within(1.0):
        fwd.close()
        raise AssertionError("the forwarder's listener did not stop")
    fwd._listener._drain_deadline = None  # replay runs only outside a drain
    fwd._listener._retry_at = 0.0
    return target, fwd


def test_the_udp_arm_is_the_flagged_handler_so_the_listener_reads_its_failures() -> None:
    handler = _build_syslog_handler(SyslogForward(host="127.0.0.1", port=514, protocol="udp"))
    try:
        assert isinstance(handler, _TimeoutSysLogHandler)
        assert handler.socktype == socket.SOCK_DGRAM
    finally:
        handler.close()


def test_a_failed_udp_send_keeps_the_spooled_record_instead_of_deleting_it(
    spool_dir: Path,
) -> None:
    """A ``sendto`` that raises a network error (``ENETUNREACH`` here) must not read as delivered:
    replay would then advance past the entry and delete spooled log evidence that never left."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    target, fwd = _udp_forwarder(spool)
    try:
        assert spool.append(SpoolEntry(level="WARNING", line="spooled at stop"))
        _swap_socket(target, _FailingDatagramSocket(OSError(errno.ENETUNREACH, "unreachable")))
        fwd._listener._replay()
        assert spool.pending, "the entry was deleted although it was never sent"
        assert fwd._listener.send_failing is True
        assert fwd._listener.send_failures == 1
        assert fwd._listener.undeliverable == 0
    finally:
        fwd.close()


def test_a_failed_udp_send_with_no_spool_is_counted_as_unsent() -> None:
    target, fwd = _udp_forwarder(None)
    try:
        _swap_socket(target, _FailingDatagramSocket(OSError(errno.ENETUNREACH, "unreachable")))
        fwd._listener.handle(logging.makeLogRecord({"msg": "live", "levelname": "WARNING"}))
        assert fwd._listener.unsent == 1
    finally:
        fwd.close()


def test_an_oversized_udp_datagram_is_undeliverable_so_replay_does_not_wedge(
    spool_dir: Path,
) -> None:
    """On EMSGSIZE a retry resends the same entry as the same datagram. Marked as a network
    failure it would hold every later spooled entry behind it while the size limit stands, so it is
    dropped as undeliverable and the next entry is sent."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    target, fwd = _udp_forwarder(spool)
    try:
        assert spool.append(SpoolEntry(level="WARNING", line="too big"))
        assert spool.append(SpoolEntry(level="WARNING", line="next"))
        failing = _FailingDatagramSocket(OSError(errno.EMSGSIZE, "message too long"))
        _swap_socket(target, failing)
        fwd._listener._replay()
        assert len(failing.sent) == 2  # the second entry was tried: nothing wedged
        assert fwd._listener.undeliverable == 2
        assert fwd._listener.send_failures == 0
        assert not spool.pending
    finally:
        fwd.close()


class _DeliveringDatagramSocket:
    """A UDP socket whose every ``sendto`` delivers, recording what it was handed."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendto(self, data: bytes, _address: Any) -> int:
        self.sent.append(data)
        return len(data)

    def close(self) -> None:
        pass


# The errnos an earlier revision dropped as undeliverable, under their POSIX and Winsock values;
# CPython on Windows passes some Winsock codes through unmapped.
_ROUTE_LEVEL_UDP_ERRNOS = sorted(
    {
        getattr(errno, name)
        for name in (
            "EACCES",
            "EADDRNOTAVAIL",
            "EAFNOSUPPORT",
            "EINVAL",
            "WSAEACCES",
            "WSAEADDRNOTAVAIL",
            "WSAEAFNOSUPPORT",
            "WSAEINVAL",
        )
        if hasattr(errno, name)
    }
)


@pytest.mark.parametrize("error", _ROUTE_LEVEL_UDP_ERRNOS)
def test_a_udp_collector_every_send_to_which_fails_keeps_the_spool(
    spool_dir: Path, error: int
) -> None:
    """An errno such as ``EACCES`` on UDP is read as belonging to the destination or the route,
    not the record: a Linux ``prohibit`` route raises it, for one. Every send to that collector
    fails alike, so nothing good waits behind the head, and the cause can clear. The spool keeps
    every entry while it holds, and delivers them in order once sends succeed; dropping them would
    lose the log evidence (ADR 0200 Amendment B)."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    target, fwd = _udp_forwarder(spool)
    try:
        assert spool.append(SpoolEntry(level="WARNING", line="first"))
        assert spool.append(SpoolEntry(level="WARNING", line="second"))
        blocked = _FailingDatagramSocket(OSError(error, "refused on this host"))
        _swap_socket(target, blocked)
        for _ in range(3):  # each retry fails alike; none drops an entry
            fwd._listener._retry_at = 0.0
            fwd._listener._replay()
        assert len(blocked.sent) == 3  # only the head was tried, once per retry
        assert spool.pending
        assert fwd._listener.send_failing is True
        assert fwd._listener.send_failures == 3
        assert fwd._listener.undeliverable == 0

        delivering = _DeliveringDatagramSocket()
        target.socket = delivering
        fwd._listener._retry_at = 0.0
        fwd._listener._replay()
        assert len(delivering.sent) == 2
        assert b"first" in delivering.sent[0] and b"second" in delivering.sent[1]
        assert not spool.pending
        assert fwd._listener.send_failing is False
        assert fwd._listener.undeliverable == 0
    finally:
        fwd.close()


@pytest.mark.parametrize("error", [errno.EACCES, errno.EMSGSIZE])
def test_a_stream_arm_send_error_reconnects_and_retries(
    monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    """On TCP a send error such as ``EACCES``, and ``EMSGSIZE`` too, keeps the reconnect-and-retry
    path, so the record is a failed send, not an undeliverable one, and the socket is dropped for a
    reconnect: a ``sendall`` that raised may have written part of a frame."""

    def _no_connect(self: Any) -> None:
        self.socket = None  # no real connect, so nothing to leak and no refused-SYN wait

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _no_connect)
    handler = _TimeoutSysLogHandler(
        address=("127.0.0.1", 9), socktype=socket.SOCK_STREAM, defer_connect=True
    )
    try:

        class _Refusing:
            def sendall(self, _data: bytes) -> None:
                raise OSError(error, "refused")

            def close(self) -> None:
                pass

        handler.socket = _Refusing()
        handler.emit(logging.makeLogRecord({"msg": "one", "levelname": "WARNING"}))
        assert handler.send_failed is True
        assert handler.send_error is False
        assert handler.socket is None  # dropped for a reconnect
    finally:
        handler.close()


def test_a_failed_udp_send_rebuilds_a_socket_older_than_the_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5923 step 2: a UDP socket that went bad was never rebuilt, since only a stream
    socket was dropped after a failed send. One older than the rebuild interval is now dropped, and
    the next send builds a fresh one that delivers. NEGATIVE CONTROL: on 33870a40944, with
    ``_UDP_SOCKET_REBUILD_SECONDS`` added to logging_setup by hand so the setattr applies, the bad
    socket stayed in place and took the second send too."""
    handler = _TimeoutSysLogHandler(
        address=("127.0.0.1", 9), socktype=socket.SOCK_DGRAM, defer_connect=True
    )
    try:
        bad = _FailingDatagramSocket(OSError(errno.EBADF, "bad file descriptor"))
        _swap_socket(handler, bad)
        monkeypatch.setattr(logging_setup, "_UDP_SOCKET_REBUILD_SECONDS", 0.0)
        handler.emit(logging.makeLogRecord({"msg": "one", "levelname": "WARNING"}))
        assert handler.send_failed is True
        handler.send_failed = False
        handler.emit(logging.makeLogRecord({"msg": "two", "levelname": "WARNING"}))
        assert len(bad.sent) == 1, "the bad socket took the next send too"
        assert handler.send_failed is False
        assert handler.socket is not None and handler.socket is not bad
    finally:
        handler.close()


@pytest.mark.parametrize("error", [OSError(errno.EBADF, "bad"), socket.gaierror(-2, "lookup")])
def test_a_failed_udp_send_keeps_a_young_socket_or_one_a_lookup_failed(
    monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    """The controls for the test above: a socket younger than the interval is kept, so an outage
    does not cost a socket per record, and a failed name lookup keeps the socket whatever its age,
    since a new socket would not fix it."""
    handler = _TimeoutSysLogHandler(
        address=("127.0.0.1", 9), socktype=socket.SOCK_DGRAM, defer_connect=True
    )
    try:
        bad = _FailingDatagramSocket(error)
        _swap_socket(handler, bad)
        if isinstance(error, socket.gaierror):
            monkeypatch.setattr(logging_setup, "_UDP_SOCKET_REBUILD_SECONDS", 0.0)
        for n in range(3):
            handler.emit(logging.makeLogRecord({"msg": f"m{n}", "levelname": "WARNING"}))
        assert len(bad.sent) == 3
        assert handler.socket is bad
    finally:
        handler.socket = None
        handler.close()


#: How many replay retries the head-holding test below drives. Each retry clears the backoff, so
#: the test rules out a head drop keyed to fewer failed retries than this, and nothing keyed to time.
_HEAD_RETRIES = 15


def _stream_listener(
    spool: LogSpool, monkeypatch: pytest.MonkeyPatch, connect: Callable[[Any], None]
) -> tuple[_ForwardQueueListener, _TimeoutSysLogHandler]:
    """A stopped listener over a TCP handler whose connect is ``connect``, so a test drives
    replay by hand with no network."""
    monkeypatch.setattr(logging.handlers.SysLogHandler, "createSocket", connect)
    handler = _TimeoutSysLogHandler(
        address=("127.0.0.1", 9), socktype=socket.SOCK_STREAM, defer_connect=True
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    return _ForwardQueueListener(queue.Queue(), handler, spool=spool), handler


def _replay_retries(listener: _ForwardQueueListener, times: int) -> None:
    for _ in range(times):
        listener._retry_at = 0.0
        listener._replay()


class _FailingStream:
    """A connected stream socket whose every ``sendall`` raises a fresh error from ``make``, so no
    one exception object gathers a traceback across retries."""

    def __init__(self, make: Callable[[], OSError]) -> None:
        self.make = make

    def sendall(self, data: bytes) -> None:
        raise self.make()

    def close(self) -> None:
        pass


def _connect_refused() -> OSError:
    return ConnectionRefusedError(errno.ECONNREFUSED, "refused")


@pytest.mark.parametrize(
    ("on_connect", "make"),
    [
        (True, _connect_refused),
        (False, lambda: TimeoutError("timed out")),
        (False, lambda: OSError(errno.ENETUNREACH, "unreachable")),
        (False, lambda: ConnectionResetError(errno.ECONNRESET, "the collector reset it")),
    ],
    ids=["connect-refused", "send-timeout", "send-unreachable", "send-reset"],
)
def test_a_failing_collector_keeps_the_spool_head_in_place(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, on_connect: bool, make: Callable[[], OSError]
) -> None:
    """Controls for the spool head (BACKLOG #5923). A collector that is down, or a send on a
    connection that was up but timed out, could not route or was reset on every frame, fails every
    retry: the head stays first, nothing is dropped, each failed retry is counted, and both entries
    are still there in order. The reset case resets every frame, so it is a down collector, not
    the one-frame reset ADR 0200 Amendment B leaves unmeasured. NEGATIVE CONTROL: on 2026-11-25 a
    test plugin that advanced the spool past the head after five failed retries turned every case
    red."""

    def connect(self: Any) -> None:
        if on_connect:
            raise make()
        self.socket = _FailingStream(make)

    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    try:
        listener, handler = _stream_listener(spool, monkeypatch, connect)
        try:
            assert spool.append(SpoolEntry(level="WARNING", line="head"))
            assert spool.append(SpoolEntry(level="WARNING", line="behind"))
            _replay_retries(listener, _HEAD_RETRIES)
            assert listener.undeliverable == 0
            assert listener.send_failures == _HEAD_RETRIES
            assert _drain(spool) == ["head", "behind"]
        finally:
            handler.close()
    finally:
        spool.close()


@pytest.mark.parametrize(
    "code", [getattr(errno, "WSAEAFNOSUPPORT", errno.EAFNOSUPPORT), errno.EMSGSIZE]
)
def test_a_udp_lookup_error_is_a_failed_send_and_is_retried(code: int) -> None:
    """A ``socket.gaierror`` carries a lookup code from another namespace, so its code is never
    read as an errno: not even one equal to ``EMSGSIZE``. It is a failed send, kept for a retry,
    never an undeliverable record."""
    handler = _TimeoutSysLogHandler(
        address=("127.0.0.1", 9), socktype=socket.SOCK_DGRAM, defer_connect=True
    )
    try:
        _swap_socket(
            handler,
            _FailingDatagramSocket(socket.gaierror(code, "lookup")),
        )
        handler.emit(logging.makeLogRecord({"msg": "one", "levelname": "WARNING"}))
        assert handler.send_failed is True
        assert handler.send_error is False
    finally:
        handler.close()


@pytest.mark.parametrize("error", [errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED])
def test_a_transient_udp_send_error_is_retried_and_holds_the_spool_head(
    spool_dir: Path, error: int
) -> None:
    """A network error may clear, so the head entry is kept for a retry and nothing behind it is
    sent past it."""
    spool = LogSpool(spool_dir, max_bytes=1_000_000)
    spool.open()
    target, fwd = _udp_forwarder(spool)
    try:
        assert spool.append(SpoolEntry(level="WARNING", line="head"))
        assert spool.append(SpoolEntry(level="WARNING", line="next"))
        failing = _FailingDatagramSocket(OSError(error, "transient"))
        _swap_socket(target, failing)
        fwd._listener._replay()
        assert len(failing.sent) == 1
        assert fwd._listener.send_failing is True
        assert fwd._listener.undeliverable == 0
        assert spool.pending
    finally:
        fwd.close()


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_a_failed_send_prints_no_traceback_and_no_record_content_to_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    protocol: str,
) -> None:
    """The stdlib ``handleError`` writes a traceback, the call stack and the record's message and
    arguments to stderr on every failed send, outside every log control (CLAUDE.md section 9). Now
    the listener reports once per interval, with no record content, whatever ``raiseExceptions``
    says, and the running count carries the failures the throttle held back."""
    monkeypatch.setattr(logging, "raiseExceptions", True)

    def _no_connect(self: Any) -> None:
        self.socket = None
        if self.socktype == socket.SOCK_DGRAM:
            self.socket = _FailingDatagramSocket(OSError(errno.ENETUNREACH, "unreachable"))
        else:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _no_connect)
    target = _TimeoutSysLogHandler(
        address=("127.0.0.1", 9),
        socktype=socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM,
        defer_connect=True,
    )
    fwd = _build_queued_forwarder(target, fmt="text", spool=None)
    try:
        assert fwd._listener.stop_within(1.0)  # drive the listener by hand, deterministically
        fwd._listener._drain_deadline = None
        with caplog.at_level(logging.WARNING, logger="messagefoundry.logging_setup"):
            for n in range(5):
                record = logging.makeLogRecord(
                    {"msg": f"PID|1||MRN{n}^^^SECRET", "levelname": "WARNING"}
                )
                fwd._listener.handle(record)
        assert capsys.readouterr().err == ""
        reports = [r for r in caplog.records if "off-box log forwarding" in r.getMessage()]
        assert len(reports) == 1  # throttled
        text = reports[0].getMessage()
        assert "MRN" not in text and "SECRET" not in text
        assert "errno" in text  # the cause, as type and errno
        assert fwd._listener.unsent == 5
    finally:
        fwd.close()


def test_handle_error_logs_nothing_itself(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``handleError`` runs under the target's lock, mid-send, so it logs nothing. It only
    records the cause; the listener reports after the send returns, throttled."""
    monkeypatch.setattr(logging, "raiseExceptions", True)

    def _failing(self: Any) -> None:
        self.socket = _FailingDatagramSocket(OSError(errno.ENETUNREACH, "unreachable"))

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _failing)
    handler = _TimeoutSysLogHandler(address=("127.0.0.1", 9), socktype=socket.SOCK_DGRAM)
    try:
        with caplog.at_level(logging.DEBUG):
            handler.emit(logging.makeLogRecord({"msg": "PID|1||MRN1", "levelname": "WARNING"}))
        assert caplog.records == []
        assert capsys.readouterr().err == ""
        assert handler.send_failed is True
        assert handler.send_error_cause == f"OSError, errno {errno.ENETUNREACH}"
    finally:
        handler.close()


@pytest.mark.timeout(60)  # a regression deadlocks; fail it rather than hang the run
def test_a_failed_send_during_the_shutdown_drain_does_not_deadlock() -> None:
    """What ``logging.shutdown`` does, against a TCP collector that refuses: hold the queue
    handler's lock, then close it. The listener's failed send must not wait on that lock while it
    holds the target's, or close() never returns."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]  # closed again below, so nothing listens there
    target = _TimeoutSysLogHandler(
        address=("127.0.0.1", port),
        socktype=socket.SOCK_STREAM,
        timeout=1.0,
        defer_connect=True,
    )
    fwd = _build_queued_forwarder(target, fmt="text", spool=None)
    # On the root logger, as configure_logging puts it, so a report the failed send raises comes
    # back through this queue handler, as it does in a running engine.
    root = logging.getLogger()
    root.addHandler(fwd)
    done: list[bool] = []

    def _shutdown_like() -> None:
        fwd.acquire()
        try:
            fwd.close()
        finally:
            fwd.release()
        done.append(True)

    closer = threading.Thread(target=_shutdown_like, daemon=True)
    try:
        fwd.handle(logging.makeLogRecord({"msg": "one", "levelname": "WARNING"}))
        started = time.monotonic()
        closer.start()
        closer.join(30.0)
    finally:
        root.removeHandler(fwd)
        # Close it when the closer never ran; one still parked under the lock is left alone, since
        # a second close() would park beside it.
        if not done and not closer.is_alive():
            fwd.close()
    assert done == [True], "close() under the queue handler's lock did not return"
    # Not just "returned": a listener parked on the lock would return only after the join gave up
    # (about 11 s here), and would be left running.
    assert fwd._listener._thread is None, "the listener did not stop cleanly"
    assert time.monotonic() - started < 5.0


class _GatedDatagramSocket(_FailingDatagramSocket):
    """A UDP socket whose ``sendto`` waits for ``gate`` before raising, so the send is in flight
    when the test's shutdown takes the queue handler's lock."""

    def __init__(self, error: OSError, gate: threading.Event) -> None:
        super().__init__(error)
        self.gate = gate
        self.entered = threading.Event()

    def sendto(self, data: bytes, _address: Any) -> int:
        self.entered.set()
        self.gate.wait(10.0)
        return super().sendto(data, _address)


class _ReportSeen(logging.Handler):
    """Sets ``event`` when the forwarder's own send report reaches the root logger."""

    def __init__(self, event: threading.Event) -> None:
        super().__init__(logging.ERROR)
        self.event = event

    def emit(self, record: logging.LogRecord) -> None:
        if record.getMessage().startswith("off-box log forwarding"):
            self.event.set()


@pytest.mark.timeout(60)  # a regression parks the listener for the whole join; fail it, not hang
@pytest.mark.parametrize("when", ["before_close", "during_close"])
@pytest.mark.parametrize("error", [errno.EMSGSIZE, errno.ENETUNREACH])
def test_a_send_report_raised_while_shutdown_holds_the_lock_does_not_park_the_listener(
    error: int, when: str
) -> None:
    """What ``logging.shutdown`` does while a send is in flight: hold the queue handler's lock,
    then close it. The send then fails, before close() starts or during its join, and the listener
    reports it, EMSGSIZE as undeliverable and a network error as a failed send. That report comes
    back to this queue handler through the root logger. It must not wait on the lock shutdown
    holds, or close() returns only once the join gives up (about 11 s) with the listener running;
    and arriving while close() runs, it is not a record the full queue dropped."""
    gate = threading.Event()
    target = _build_syslog_handler(SyslogForward(host="127.0.0.1", port=9, protocol="udp"))
    gated = _GatedDatagramSocket(OSError(error, "failed"), gate)
    _swap_socket(target, gated)
    fwd = _build_queued_forwarder(target, fmt="text", spool=None)
    reported = threading.Event()
    seen = _ReportSeen(reported)
    root = logging.getLogger()
    # The witness goes on root ahead of the queue handler, so it sees the report before the report
    # reaches the queue handler.
    root.addHandler(seen)
    root.addHandler(fwd)
    opener = threading.Timer(0.2, gate.set)
    try:
        fwd.handle(logging.makeLogRecord({"msg": "one", "levelname": "WARNING"}))
        assert gated.entered.wait(10.0), "the listener never sent the record"
        fwd.acquire()
        try:
            if when == "before_close":
                gate.set()  # the send fails now, with shutdown's lock held
                assert reported.wait(10.0), "the listener never reported the failed send"
            else:
                opener.start()  # the send fails while close() is in its join
            started = time.monotonic()
            fwd.close()
            elapsed = time.monotonic() - started
        finally:
            fwd.release()
    finally:
        opener.cancel()
        gate.set()
        fwd.close()  # a no-op once closed; stops the listener when an assert above failed
        root.removeHandler(fwd)
        root.removeHandler(seen)
        seen.close()
    assert reported.is_set(), "the listener never reported the failed send"
    assert fwd._listener._thread is None, "the listener did not stop cleanly"
    # Measured well under 1 s; a parked listener holds close() for about 11 s. The bound sits
    # between the two with room for a loaded runner.
    assert elapsed < 3.0, f"close() took {elapsed:.1f}s"
    assert fwd.dropped == 0, "the listener's own report was counted as a queue-full drop"
