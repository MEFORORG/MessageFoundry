# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The on-disk spool behind the off-box log forwarder (BACKLOG #1966, ADR 0200).

Synthetic HL7 only. The planted value is a made-up PID segment, never real PHI.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import ssl
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.log_spool import SPOOL_FORMAT_VERSION, LogSpool, SpoolEntry, SpoolUnavailable
from messagefoundry.logging_setup import (
    SyslogForward,
    _build_queued_forwarder,
    _ForwardQueueHandler,
    _TimeoutSysLogHandler,
    _TlsSysLogHandler,
    configure_logging,
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
) -> None:
    """Waiting cannot fix a bad certificate or a name that does not resolve, so a spool must not
    turn either into "not reachable yet"."""

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
    # The spool was released, so a later configure in this process can take it.
    again = LogSpool(spool_dir, max_bytes=1_000)
    again.open()
    again.close()


def test_a_transient_connect_failure_is_still_deferred(
    spool_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for the test above: a refused connect IS deferred, so that test's refusal to
    defer is about the error class, not about deferral being broken."""
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
        (socket.gaierror(getattr(socket, "EAI_AGAIN", -3), "temporary failure"), False),
        (ssl.SSLCertVerificationError("certificate verify failed"), True),
        (_not_yet_valid(), False),
        (ConnectionRefusedError("refused"), False),
    ],
    ids=["no-such-name", "dns-try-again", "bad-cert", "clock-not-synced", "refused"],
)
def test_only_a_missing_name_or_a_bad_certificate_is_permanent(
    error: OSError, permanent: bool
) -> None:
    """A temporary DNS failure or a not-yet-valid certificate (a clock not synced at boot) must be
    deferred to the spool, not turn the forwarder off for the life of the process."""
    assert is_permanent_connect_error(error) is permanent
