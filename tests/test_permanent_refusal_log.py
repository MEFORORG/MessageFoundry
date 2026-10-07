# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3043: a permanent refusal that dead-letters writes one content-free WARNING.

The delivery worker's ``except NegativeAckError`` arm used to dead-letter a permanent refusal with
no log line at all, on the single-row path and the batch path. These tests drive the REAL worker
(the runner's own delivery loop, or its batch body) and read what it logged. Each one plants a
distinctive token in the message and asserts no captured record carries it anywhere: message, args,
the record's other attributes, exc_info or stack_info. Where the connector's own refusal text
carries the token too, as a partner echoing the message in its reject would, the same assertion
proves the line does not log the refusal's text either.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.config.models import BatchConfig, ConnectorType, Destination, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _RefusalLog
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.transports.base import DestinationConnector, NegativeAckError
from messagefoundry.transports.mllp import MLLPDestination
from tests._refusal_log_capture import TOKEN
from tests._refusal_log_capture import assert_no_token as _assert_no_token

OUT = "file_out"
LOGGER = "messagefoundry.pipeline.wiring_runner"


def _adt(n: int, name: str = TOKEN) -> str:
    return (
        f"MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG{n}|P|2.5.1\r"
        "EVN|A01|20260604\r"
        f"PID|1||{n}00^^^H^MR||{name}^JANE\r"
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(inbox: Path, outdir: Path, **out_settings: object) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            OUT,
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(outdir), "filename": "{MSH-10}.hl7", **out_settings},
            ),
            retry=RetryPolicy(),  # retry forever: only the permanent arm can dead-letter here
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(OUT, m))
    return reg


async def _until_dead(store: MessageStore, expected: int, timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while (await store.stats()).get(OutboxStatus.DEAD.value, 0) != expected:
        if loop.time() > deadline:
            raise AssertionError(f"{expected} dead row(s) not reached within {timeout}s")
        await asyncio.sleep(0.02)


class _Refuses:
    """A stub connector whose refusal TEXT echoes a value from the message, as a partner's reject
    reason can (MSA-3 "unknown patient X"). Plain text, not an HL7 shape, so ``safe_exc`` cannot
    scrub it: logging ``safe_exc(exc)`` fails these tests, which is the mutation they guard."""

    def __init__(self, code: str = "AR") -> None:
        self.code = code
        self.calls = 0

    async def send(self, payload: str) -> None:
        self.calls += 1
        assert TOKEN in payload  # the echoed value really is the message's
        raise NegativeAckError(
            f"negative ACK (MSA-1=AR): unknown patient {TOKEN}", code=self.code, permanent=True
        )

    async def aclose(self) -> None:
        return None


def _refusal_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == LOGGER and r.levelno == logging.WARNING and "refused permanently" in r.msg
    ]


def _file_runner(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture, **out_settings: object
) -> tuple[RegistryRunner, Path, Path]:
    # Engine loggers at DEBUG, so every record they write is scanned. Not the root: aiosqlite's DEBUG
    # lines echo SQL parameters, payloads included, and they are not the engine's own log.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    runner = RegistryRunner(
        _registry(inbox, outdir, **out_settings),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
    )
    return runner, inbox, outdir


async def test_charset_refusal_through_the_real_worker_logs_one_content_free_warning(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The Lander's measured shape, on a real File connector: a payload the outbound's charset cannot
    # encode is a permanent refusal (code "encoding"). It used to dead-letter with zero WARNING lines.
    runner, inbox, outdir = _file_runner(store, tmp_path, caplog, encoding="ascii")
    await runner.start()
    (inbox / "a.hl7").write_bytes(_adt(1, name=TOKEN + "é").encode("utf-8"))
    try:
        await _until_dead(store, 1)
    finally:
        await runner.stop()

    (msg,) = await store.list_messages(channel_id="file_in", allowed_channels=None)
    assert msg["status"] == MessageStatus.ERROR.value  # the dead-letter itself is unchanged
    (line,) = _refusal_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and str(msg["id"]) in text
    assert "NegativeAckError" in text and "code 'encoding'" in text
    assert "dead-lettered" in text
    assert not outdir.exists() or not any(outdir.iterdir())  # nothing was written
    _assert_no_token(caplog.records)


async def test_a_refusal_whose_text_echoes_the_payload_logs_none_of_it(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The refusal's own text carries the token here, so this also proves the line logs neither
    # str(exc) nor safe_exc(exc).
    runner, inbox, _ = _file_runner(store, tmp_path, caplog)
    await runner.start()
    dest = _Refuses()
    await runner._destinations[OUT].aclose()  # the File connector start() built
    runner._destinations[OUT] = cast(DestinationConnector, dest)
    (inbox / "a.hl7").write_bytes(_adt(1).encode("utf-8"))
    try:
        await _until_dead(store, 1)
    finally:
        await runner.stop()

    assert dest.calls == 1
    (line,) = _refusal_lines(caplog)
    assert "code 'AR'" in line.getMessage()
    _assert_no_token(caplog.records)


async def test_the_warning_is_throttled_per_connection_and_code_and_reports_what_it_held(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    runner, inbox, _ = _file_runner(store, tmp_path, caplog)
    now = [1000.0]
    runner._refusal_log = _RefusalLog(window=60.0, clock=lambda: now[0])
    await runner.start()
    await runner._destinations[OUT].aclose()  # the File connector start() built
    runner._destinations[OUT] = cast(DestinationConnector, _Refuses())
    try:
        for n in (1, 2, 3):
            (inbox / f"{n}.hl7").write_bytes(_adt(n).encode("utf-8"))
        await _until_dead(store, 3)
        # Every refused row was still dead-lettered: only the log line is throttled.
        (only,) = _refusal_lines(caplog)
        assert "more row(s) refused" not in only.getMessage()

        now[0] += 61.0  # past the window: the next refusal logs and reports the two it held
        (inbox / "4.hl7").write_bytes(_adt(4).encode("utf-8"))
        await _until_dead(store, 4)
    finally:
        await runner.stop()

    _first, second = _refusal_lines(caplog)
    assert "(2 more row(s) refused with this code on this connection" in second.getMessage()
    _assert_no_token(caplog.records)


def _nak(code: str) -> NegativeAckError:
    return NegativeAckError(f"refused {TOKEN}", code=code, permanent=True)


_COUNTED = "; more with this code in the next 60 s are counted, not logged"


def test_the_throttle_keys_on_connection_and_code_and_counts_rows(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    now = [0.0]
    refusals = _RefusalLog(window=60.0, clock=lambda: now[0])
    for name, code in [("a", "AR"), ("a", "AR"), ("a", "encoding"), ("b", "AR"), ("a", "AR")]:
        refusals.warning(name, _nak(code), 1, "refused on %s", name)
    assert [r.getMessage() for r in caplog.records] == [
        "refused on a (NegativeAckError, code 'AR')" + _COUNTED,
        "refused on a (NegativeAckError, code 'encoding')" + _COUNTED,
        "refused on b (NegativeAckError, code 'AR')" + _COUNTED,
    ]
    now[0] = 59.9  # still inside ("a", "AR")'s window: a batch of 20 adds 20 rows, not 1
    refusals.warning("a", _nak("AR"), 20, "refused on %s", "a")
    assert len(caplog.records) == 3
    now[0] = 60.0  # the window has closed: logs, with the 22 rows held since the first line
    refusals.warning("a", _nak("AR"), 1, "refused on %s", "a")
    assert caplog.records[-1].getMessage() == (
        "refused on a (NegativeAckError, code 'AR') (22 more row(s) refused with this code on "
        "this connection since its last line)" + _COUNTED
    )
    now[0] = 60.0 + 60.0  # a fresh window, nothing held: no count suffix
    refusals.warning("a", _nak("AR"), 1, "refused on %s", "a")
    assert (
        caplog.records[-1].getMessage() == "refused on a (NegativeAckError, code 'AR')" + _COUNTED
    )
    _assert_no_token(caplog.records)


class _CodelessRefusal(NegativeAckError):
    """A connector's subclass that never called the base initialiser, so it has no ``code``."""

    def __init__(self) -> None:  # deliberately skips NegativeAckError.__init__
        Exception.__init__(self, f"refused {TOKEN}")
        self.permanent = True


def test_a_refusal_with_no_code_still_logs(caplog: pytest.LogCaptureFixture) -> None:
    # _lane_stopping_fault reads its markers with getattr for this case; the log must not raise
    # either, or the fail-fast dead-letter's caller would see an AttributeError instead.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    _RefusalLog().warning("a", _CodelessRefusal(), 1, "refused on %s", "a")
    (record,) = caplog.records
    assert "(_CodelessRefusal, code '?')" in record.getMessage()
    _assert_no_token(caplog.records)


def _batch_runner(store: MessageStore, connector: object) -> RegistryRunner:
    runner = RegistryRunner(
        Registry(), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    runner._batch[OUT] = BatchConfig(max_count=5, max_wait_ms=1)
    runner._destinations[OUT] = cast(DestinationConnector, connector)
    runner._retry[OUT] = RetryPolicy()
    runner._simulate[OUT] = False
    return runner


async def _run_one_batch(store: MessageStore, runner: RegistryRunner, bodies: list[str]) -> str:
    for n, body in enumerate(bodies, start=1):
        await store.enqueue_message(
            channel_id="c1", raw=body, deliveries=[(OUT, body)], now=100.0 + n
        )
    head = await store.claim_next_fifo(OUT)
    cfg = runner._batch[OUT]
    assert head is not None and cfg is not None
    await runner._process_delivery_batch(OUT, head, cfg)
    return head.id


async def test_a_permanently_refused_batch_logs_one_content_free_warning(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    runner = _batch_runner(store, _Refuses())
    head_id = await _run_one_batch(store, runner, [_adt(n) for n in (1, 2, 3)])

    assert await store.count_dead(allowed_channels=None) == 3  # the batch dead-letter is unchanged
    (line,) = _refusal_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and "a batch of 3" in text and head_id in text
    assert "NegativeAckError" in text and "code 'AR'" in text
    _assert_no_token(caplog.records)


class _MllpRecorder(MLLPDestination):
    """A real MLLP destination, so ``check_frame`` is the real one, whose send only records."""

    def __init__(self) -> None:
        super().__init__(
            Destination(
                name=OUT, type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 1}
            )
        )
        self.sent: list[str] = []

    async def send(self, payload: str, *, metadata: object = None) -> None:
        self.sent.append(payload)


async def test_a_batch_member_the_frame_refuses_logs_the_same_content_free_warning(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # ADR 0205 rule 1: one member holding a frame byte is dead-lettered alone. Its line shares the
    # phrase and the throttle of the other permanent-refusal lines.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    rec = _MllpRecorder()
    runner = _batch_runner(store, rec)
    bad = _adt(2, name=TOKEN + chr(0x1C))
    await _run_one_batch(store, runner, [_adt(1, name="DOE"), bad, _adt(3, name="DOE")])

    assert len(rec.sent) == 1 and await store.count_dead(allowed_channels=None) == 1
    (line,) = _refusal_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and "batch member" in text and "dead-lettered alone" in text
    assert "NegativeAckError" in text
    _assert_no_token(caplog.records)


class _SplitThenTransient(DestinationConnector):
    """Frames: refuses member 2 permanently, then member 3 transiently, so the whole batch re-pends."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    def check_frame(self, payload: str, *, rewrite: bool = True) -> None:
        if "MSG2" in payload:
            raise NegativeAckError("frame byte", code="framing", permanent=True)
        if "MSG3" in payload:
            raise NegativeAckError("try later", code="AE", permanent=False)

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        self.sent.append(payload)

    async def aclose(self) -> None:
        return None


async def test_a_refused_member_sent_back_with_its_batch_is_not_logged_as_dead_lettered(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # A later member's transient refusal re-pends the WHOLE batch, member 2 included. The member line
    # used to be written in the split, before any write, so it claimed a dead-letter that never ran.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    rec = _SplitThenTransient()
    runner = _batch_runner(store, rec)
    await _run_one_batch(store, runner, [_adt(n) for n in (1, 2, 3)])

    assert rec.sent == [] and await store.count_dead(allowed_channels=None) == 0
    assert (await store.pending_depth(OUT))[0] == 3  # the whole batch went back, member 2 too
    assert _refusal_lines(caplog) == []


def test_the_cross_pair_cap_holds_a_peer_that_cycles_its_code(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A peer can vary its code (an HTTP status, a DICOM status). Past the cap the pair is counted,
    # not logged, and keeps no delay: its next line, in the next window, reports what it held.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    now = [0.0]
    refusals = _RefusalLog(window=60.0, clock=lambda: now[0], max_lines=3)
    for status in range(500, 510):
        refusals.warning("a", _nak(str(status)), 1, "refused on %s", "a")
    assert len(caplog.records) == 3
    now[0] = 60.0
    refusals.warning("a", _nak("509"), 1, "refused on %s", "a")
    assert "(1 more row(s) refused with this code" in caplog.records[-1].getMessage()


def test_the_table_forgets_only_pairs_that_carry_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    now = [0.0]
    refusals = _RefusalLog(window=60.0, clock=lambda: now[0], max_pairs=3)
    refusals.warning("a", _nak("AR"), 1, "refused on %s", "a")
    refusals.warning("a", _nak("AR"), 5, "refused on %s", "a")  # held: 5 rows
    refusals.warning("b", _nak("AR"), 1, "refused on %s", "b")
    refusals.warning("c", _nak("AR"), 1, "refused on %s", "c")
    now[0] = 60.0  # every window has closed; the table is full, so this line prunes
    refusals.warning("d", _nak("AR"), 1, "refused on %s", "d")
    assert set(refusals._state) == {("a", "AR"), ("d", "AR")}  # b and c held nothing
    refusals.warning("a", _nak("AR"), 1, "refused on %s", "a")
    assert "(5 more row(s) refused with this code" in caplog.records[-1].getMessage()
