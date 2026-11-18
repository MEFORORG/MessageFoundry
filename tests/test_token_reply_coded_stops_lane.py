# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A token endpoint answering in a content coding stops the lane and keeps the queue (BACKLOG #5910).

Every queued row mints its bearer through the same endpoint, so every row would meet the same
refusal. ``request_token`` marks it a configuration fault, and the delivery worker's existing
lane-stopping route takes it: owner ruling 2026-11-18 on PR 3069, "Stop the lane." These tests drive
the real token path (an OAuth2 provider over a gzip-coded reply) through the real delivery worker,
on the single-row path and the batch path, with an unmarked permanent refusal as the control that
still dead-letters.
"""

from __future__ import annotations

import asyncio
import http.client
import io
import urllib.request
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.config.models import BatchConfig, ConnectorType, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.transports.base import DestinationConnector, NegativeAckError
from messagefoundry.transports.http_auth import OAuth2ClientCredentialsProvider
from tests._mllp_recorder import run_one_batch
from tests._refusal_log_capture import until

OUT = "OB_TOKEN"

_CODED_TOKEN_REPLY = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello"


def _adt(n: int) -> str:
    return (
        f"MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG{n}|P|2.5.1\r"
        "EVN|A01|20260604\r"
        f"PID|1||{n}00^^^H^MR||DOE^JANE\r"
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


class _CodedTokenOpener:
    """Answers every token request with a fresh reply in a content coding."""

    def __init__(self) -> None:
        self.mints = 0

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> object:
        self.mints += 1

        class _Sock:
            def makefile(self, *a: object, **k: object) -> io.BytesIO:
                return io.BytesIO(_CODED_TOKEN_REPLY)

            def close(self) -> None:
                pass

        resp = http.client.HTTPResponse(_Sock(), method="POST")  # type: ignore[arg-type]
        resp.begin()
        return resp


class _MintsThroughACodedTokenEndpoint:
    """A connector that mints its bearer through the real token path before each send, as the HTTP
    family does, against an endpoint whose every reply is content-coded."""

    def __init__(self) -> None:
        self.opener = _CodedTokenOpener()
        self.provider = OAuth2ClientCredentialsProvider(
            token_url="https://auth.example.com/token", client_id="cid", client_secret="s3cr3t"
        )
        self.provider._opener = self.opener  # type: ignore[assignment]
        self.sends = 0

    async def send(self, payload: str) -> None:
        self.sends += 1
        self.provider.access_token()

    async def aclose(self) -> None:
        return None


class _UnmarkedRefusal:
    """The control: a permanent refusal with no fault marker, an ordinary partner reject."""

    def __init__(self) -> None:
        self.sends = 0

    async def send(self, payload: str) -> None:
        self.sends += 1
        raise NegativeAckError("negative ACK (MSA-1=AR)", code="AR", permanent=True)

    async def aclose(self) -> None:
        return None


class _RecordsStops(LoggingAlertSink):
    def __init__(self) -> None:
        super().__init__()
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


async def _outbound_rows(store: MessageStore) -> list[tuple[str, int, str | None]]:
    """``(status, attempts, last_error)`` of every outbound row on ``OUT``, oldest first."""
    cur = await store._db.execute(
        "SELECT status, attempts, last_error FROM queue WHERE stage='outbound' "
        "AND destination_name=? ORDER BY created_at",
        (OUT,),
    )
    rows = await cur.fetchall()
    return [(str(r[0]), int(r[1]), None if r[2] is None else str(r[2])) for r in rows]


async def _until_rows(store: MessageStore, n: int, timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while len(await _outbound_rows(store)) != n:
        if loop.time() > deadline:
            raise AssertionError(f"{n} outbound row(s) not reached within {timeout}s")
        await asyncio.sleep(0.02)


def _registry(inbox: Path, outdir: Path) -> Registry:
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
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            retry=RetryPolicy(),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(OUT, m))
    return reg


async def _run_three_through_the_worker(
    store: MessageStore, tmp_path: Path, connector: object
) -> tuple[RegistryRunner, _RecordsStops]:
    """Queue three messages behind ``connector`` on a started runner, then let its worker run."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    sink = _RecordsStops()
    runner = RegistryRunner(
        _registry(inbox, outdir),
        store,
        poll_interval=0.02,
        alert_sink=sink,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    await runner._destinations[OUT].aclose()  # the File connector start() built
    runner._destinations[OUT] = cast(DestinationConnector, connector)
    for n in (1, 2, 3):
        (inbox / f"{n}.hl7").write_bytes(_adt(n).encode("utf-8"))
    return runner, sink


async def test_a_coded_token_reply_stops_the_lane_and_keeps_every_queued_row(
    store: MessageStore, tmp_path: Path
) -> None:
    connector = _MintsThroughACodedTokenEndpoint()
    runner, sink = await _run_three_through_the_worker(store, tmp_path, connector)
    try:
        await until(lambda: sink.stopped != [], "the lane stopped")
        await _until_rows(store, 3)
        # Several poll intervals with the other two rows queued: a lane still running would send.
        await asyncio.sleep(0.3)
        assert runner.outbound_stop_held(OUT)
        stopped = list(sink.stopped)  # before stop(), which raises its own shutdown alerts
    finally:
        await runner.stop()

    assert connector.sends == 1 and connector.opener.mints == 1  # stopped after the first
    # Every row is still queued, un-errored, its claim given back; none is dead-lettered.
    assert await _outbound_rows(store) == [(OutboxStatus.PENDING.value, 0, None)] * 3
    assert await store.count_dead(allowed_channels=None) == 0
    # The alert a stopped lane already raises, naming a configuration fault and the code.
    # The worker's exit adds its own "outbound lane stopped" alert after this one.
    assert {name for name, _ in stopped} == {OUT}
    detail = stopped[0][1]
    assert "configuration fault (token-reply-coded)" in detail
    assert "queue retained" in detail


async def test_an_unmarked_permanent_refusal_still_dead_letters_each_row(
    store: MessageStore, tmp_path: Path
) -> None:
    # The control: only a fault the transport marks stops the lane. An ordinary reject is the
    # partner's answer about one message, so each row dead-letters and the lane runs on.
    connector = _UnmarkedRefusal()
    runner, sink = await _run_three_through_the_worker(store, tmp_path, connector)
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5.0
        while await store.count_dead(allowed_channels=None) != 3:
            if loop.time() > deadline:
                raise AssertionError("three dead rows not reached")
            await asyncio.sleep(0.02)
        assert not runner.outbound_stop_held(OUT)
        assert sink.stopped == []
    finally:
        await runner.stop()

    assert connector.sends == 3


def _batch_runner(store: MessageStore, connector: object, sink: _RecordsStops) -> RegistryRunner:
    runner = RegistryRunner(
        Registry(),
        store,
        poll_interval=0.02,
        alert_sink=sink,
        egress=EgressSettings(deny_by_default=False),
    )
    runner._batch[OUT] = BatchConfig(max_count=5, max_wait_ms=1)
    runner._destinations[OUT] = cast(DestinationConnector, connector)
    runner._retry[OUT] = RetryPolicy()
    runner._simulate[OUT] = False
    return runner


@pytest.mark.parametrize("marked", [True, False], ids=["coded-token-reply", "unmarked-reject"])
async def test_a_coded_token_reply_on_a_batch_stops_the_lane_and_keeps_every_member(
    store: MessageStore, marked: bool
) -> None:
    sink = _RecordsStops()
    connector: _MintsThroughACodedTokenEndpoint | _UnmarkedRefusal = (
        _MintsThroughACodedTokenEndpoint() if marked else _UnmarkedRefusal()
    )
    runner = _batch_runner(store, connector, sink)
    for n in (1, 2, 3):
        body = _adt(n)
        await store.enqueue_message(
            channel_id="c1", raw=body, deliveries=[(OUT, body)], now=100.0 + n
        )
    await run_one_batch(runner, OUT)

    assert connector.sends == 1  # one envelope
    if marked:
        assert await _outbound_rows(store) == [(OutboxStatus.PENDING.value, 0, None)] * 3
        assert await store.count_dead(allowed_channels=None) == 0
        assert [name for name, _ in sink.stopped] == [OUT]
        assert runner.outbound_stop_held(OUT)
    else:
        assert await store.count_dead(allowed_channels=None) == 3
        assert sink.stopped == []


async def test_under_the_dead_letter_policy_a_coded_token_reply_dead_letters_as_any_config_fault(
    store: MessageStore,
) -> None:
    # credential_fault_policy = "dead_letter" opts every configuration fault back into the
    # fail-fast dead-letter, and the coded token reply follows it: the lane does not stop.
    sink = _RecordsStops()
    runner = RegistryRunner(
        Registry(),
        store,
        poll_interval=0.02,
        alert_sink=sink,
        credential_fault_policy="dead_letter",
        egress=EgressSettings(deny_by_default=False),
    )
    connector = _MintsThroughACodedTokenEndpoint()
    runner._destinations[OUT] = cast(DestinationConnector, connector)
    runner._retry[OUT] = RetryPolicy()
    runner._simulate[OUT] = False
    body = _adt(1)
    await store.enqueue_message(channel_id="c1", raw=body, deliveries=[(OUT, body)], now=101.0)
    item = await store.claim_next_fifo(OUT)
    assert item is not None
    await runner._process_delivery_item(OUT, item)

    assert await store.count_dead(allowed_channels=None) == 1
    assert sink.stopped == []
    assert not runner.outbound_stop_held(OUT)
