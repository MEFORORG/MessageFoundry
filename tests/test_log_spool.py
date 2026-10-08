# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The on-disk spool behind the off-box log forwarder (BACKLOG #1966, ADR 0200).

Synthetic HL7 only. The planted value is a made-up PID segment, never real PHI.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import ssl
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import log_spool
from messagefoundry.log_spool import SPOOL_FORMAT_VERSION, LogSpool, SpoolEntry, SpoolUnavailable
from messagefoundry.logging_setup import (
    SyslogForward,
    _build_queued_forwarder,
    _ForwardQueueHandler,
    _ForwardQueueListener,
    _open_forward_spool,
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
        # The platform's own EAI_NONAME: -2 on Linux, where a bare 11001 exercises nothing.
        (socket.gaierror(socket.EAI_NONAME, "name or service not known"), True),
        (socket.gaierror(getattr(socket, "EAI_AGAIN", -3), "temporary failure"), False),
        (ssl.SSLCertVerificationError("certificate verify failed"), True),
        (_not_yet_valid(), False),
        (ConnectionRefusedError("refused"), False),
    ],
    ids=["no-such-name", "eai-noname", "dns-try-again", "bad-cert", "clock-not-synced", "refused"],
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
        assert spool.peek() is None  # the pass that finds it gone
        assert spool.unreadable == 1
        assert spool.read_errors == 0
        expected = [f"record {n:04d}" for n in range(6) if f"record {n:04d}" not in lost]
        assert lost and _drain(spool) == expected
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
    assert "moved 3 record(s)" in reports[0] and str(spool_dir) in reports[0]
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
        listener._reclaim_at = 0.0  # the interval has passed
        listener._reclaim_spool()
        assert tries == [1, 1]
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
