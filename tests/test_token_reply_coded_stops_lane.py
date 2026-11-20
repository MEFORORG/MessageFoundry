# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A coded 2xx token reply (scoped on smart.request_token) stops the lane and keeps the queue (#5910).

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
from typing import Any, cast

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
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.transports.base import DeliveryError, DestinationConnector, NegativeAckError
from messagefoundry.transports.http_auth import OAuth2ClientCredentialsProvider
from tests._mllp_recorder import run_one_batch
from tests._refusal_log_capture import until
from tests.test_alert_control import _drain as _drain_pages
from tests.test_alert_control import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore

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
        self.errors: list[tuple[str, str, str | None]] = []
        self.restored: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def connection_error(
        self, name: str, *, kind: str, detail: str | None = None, error_class: str | None = None
    ) -> None:
        self.errors.append((name, kind, error_class))

    def connection_restored(self, name: str, *, kind: str = "connection_lost") -> None:
        self.restored.append((name, kind))


#: The one alert a dead-lettering configuration fault raises for its lane (ADR 0095 B.2).
_CONFIG_FAULT_ALERT = (OUT, "config_fault", "NegativeAckError")


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
    try:
        await runner._destinations[OUT].aclose()  # the File connector start() built
        runner._destinations[OUT] = cast(DestinationConnector, connector)
        for n in (1, 2, 3):
            (inbox / f"{n}.hl7").write_bytes(_adt(n).encode("utf-8"))
    except BaseException:
        await runner.stop()  # the caller's finally is not entered yet
        raise
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
    # It names where to fix it, the transport's remedy, not the connection's configuration.
    assert "fix the token endpoint, or a proxy in front of it" in detail
    assert "#2083" not in detail


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
        assert sink.errors == []  # an ordinary reject is no connection error
    finally:
        await runner.stop()

    assert connector.sends == 3


def _runner(
    store: MessageStore, connector: object, sink: _RecordsStops, *, policy: str = "stop"
) -> RegistryRunner:
    """An unstarted runner with ``connector`` wired on ``OUT``, for a test that drives one delivery
    body directly. The test stops it, and closes the connector, when it is done."""
    runner = RegistryRunner(
        Registry(),
        store,
        poll_interval=0.02,
        alert_sink=sink,
        credential_fault_policy=policy,
        egress=EgressSettings(deny_by_default=False),
    )
    runner._destinations[OUT] = cast(DestinationConnector, connector)
    runner._retry[OUT] = RetryPolicy()
    runner._simulate[OUT] = False
    return runner


def _batch_runner(
    store: MessageStore, connector: object, sink: _RecordsStops, *, policy: str = "stop"
) -> RegistryRunner:
    runner = _runner(store, connector, sink, policy=policy)
    runner._batch[OUT] = BatchConfig(max_count=5, max_wait_ms=1)
    return runner


async def _enqueue(store: MessageStore, count: int) -> None:
    for n in range(1, count + 1):
        body = _adt(n)
        await store.enqueue_message(
            channel_id="c1", raw=body, deliveries=[(OUT, body)], now=100.0 + n
        )


@pytest.mark.parametrize("marked", [True, False], ids=["coded-token-reply", "unmarked-reject"])
async def test_a_batch_keeps_every_member_on_a_coded_token_reply_and_dead_letters_on_a_reject(
    store: MessageStore, marked: bool
) -> None:
    sink = _RecordsStops()
    connector: _MintsThroughACodedTokenEndpoint | _UnmarkedRefusal = (
        _MintsThroughACodedTokenEndpoint() if marked else _UnmarkedRefusal()
    )
    runner = _batch_runner(store, connector, sink)
    await _enqueue(store, 3)
    try:
        await run_one_batch(runner, OUT)  # closes the connector
        assert connector.sends == 1  # one envelope
        if marked:
            assert await _outbound_rows(store) == [(OutboxStatus.PENDING.value, 0, None)] * 3
            assert await store.count_dead(allowed_channels=None) == 0
            assert [name for name, _ in sink.stopped] == [OUT]
            assert runner.outbound_stop_held(OUT)
        else:
            assert await store.count_dead(allowed_channels=None) == 3
            assert sink.stopped == []
            assert sink.errors == []  # an ordinary reject is no connection error
    finally:
        await runner.stop()


@pytest.mark.parametrize("batched", [False, True], ids=["single-row", "batch"])
async def test_under_the_dead_letter_policy_a_coded_token_reply_dead_letters_as_any_config_fault(
    store: MessageStore, batched: bool
) -> None:
    # credential_fault_policy = "dead_letter" opts every configuration fault back into the
    # fail-fast dead-letter, and the coded token reply follows it: the lane does not stop. It alerts
    # the lane, so connection_error fires once across every row, not per row (owner ruling
    # 2026-11-18 on PR 3069: "Yes, keep one connection_error alert on that path.").
    sink = _RecordsStops()
    connector = _MintsThroughACodedTokenEndpoint()
    if batched:
        # Two batches, of two members and then one, so the edge trigger is tested across sends.
        runner = _batch_runner(store, connector, sink, policy="dead_letter")
        runner._batch[OUT] = BatchConfig(max_count=2, max_wait_ms=1)
    else:
        runner = _runner(store, connector, sink, policy="dead_letter")
    await _enqueue(store, 3)
    try:
        if batched:
            await run_one_batch(runner, OUT)
            await run_one_batch(runner, OUT)
        else:
            for _ in range(3):
                item = await store.claim_next_fifo(OUT)
                assert item is not None
                await runner._process_delivery_item(OUT, item)
        assert connector.sends == (2 if batched else 3)
        assert await store.count_dead(allowed_channels=None) == 3
        assert sink.stopped == []
        assert not runner.outbound_stop_held(OUT)
        assert sink.errors == [_CONFIG_FAULT_ALERT]  # exactly one, for the lane
    finally:
        await runner.stop()
        await connector.aclose()


class _RetiredMidSend(_MintsThroughACodedTokenEndpoint):
    """Swaps itself out of the lane while it mints, as a reload landing mid-send would."""

    def __init__(self) -> None:
        super().__init__()
        self.runner: RegistryRunner | None = None

    async def send(self, payload: str) -> None:
        assert self.runner is not None
        self.runner._destinations[OUT] = cast(DestinationConnector, _UnmarkedRefusal())
        await super().send(payload)


@pytest.mark.parametrize("batched", [False, True], ids=["single-row", "batch"])
async def test_a_coded_token_reply_from_a_retired_connector_goes_back_to_the_new_one(
    store: MessageStore, batched: bool
) -> None:
    # A reload that swaps the connector mid-send may be the fix, so the old connector's
    # configuration fault is not this lane's: the rows go back un-charged for the new connector,
    # and the lane does not stop (BACKLOG #5718).
    sink = _RecordsStops()
    connector = _RetiredMidSend()
    runner = _batch_runner(store, connector, sink) if batched else _runner(store, connector, sink)
    connector.runner = runner
    count = 3 if batched else 1
    await _enqueue(store, count)
    try:
        if batched:
            await run_one_batch(runner, OUT)  # closes the connector it found at the start
        else:
            item = await store.claim_next_fifo(OUT)
            assert item is not None
            await runner._process_delivery_item(OUT, item)
        assert connector.sends == 1
        assert await _outbound_rows(store) == [(OutboxStatus.PENDING.value, 0, None)] * count
        assert await store.count_dead(allowed_channels=None) == 0
        assert sink.stopped == []
        assert not runner.outbound_stop_held(OUT)
    finally:
        await runner.stop()
        await connector.aclose()


class _Delivers:
    """A connector that delivers every payload."""

    def __init__(self) -> None:
        self.sends = 0

    async def send(self, payload: str) -> None:
        self.sends += 1

    async def aclose(self) -> None:
        return None


async def _deliver_one(store: MessageStore, runner: RegistryRunner, n: int) -> None:
    body = _adt(n)
    await store.enqueue_message(channel_id="c1", raw=body, deliveries=[(OUT, body)], now=200.0 + n)
    item = await store.claim_next_fifo(OUT)
    assert item is not None
    await runner._process_delivery_item(OUT, item)


async def test_a_prior_transport_fault_neither_suppresses_nor_replaces_the_config_fault_alert(
    store: MessageStore,
) -> None:
    # The transport edge is already down (an unreachable token endpoint), then the endpoint comes
    # back behind a proxy that codes its replies. The configuration fault still alerts, once, under
    # its own kind: it is not folded into the open connection_lost.
    sink = _RecordsStops()
    connector = _MintsThroughACodedTokenEndpoint()
    runner = _runner(store, connector, sink, policy="dead_letter")
    runner._note_lane_unhealthy(OUT, "m0", DeliveryError("token endpoint unreachable"))
    assert [kind for _, kind, _ in sink.errors] == ["connection_lost"]
    try:
        for n in (1, 2, 3):
            await _deliver_one(store, runner, n)
        assert await store.count_dead(allowed_channels=None) == 3
        assert sink.errors[1:] == [_CONFIG_FAULT_ALERT]
    finally:
        await runner.stop()
        await connector.aclose()


@pytest.mark.parametrize("batched", [False, True], ids=["single-row", "batch"])
async def test_a_delivery_clears_the_config_fault_edge_and_a_new_episode_alerts_again(
    store: MessageStore, batched: bool
) -> None:
    sink = _RecordsStops()
    make = _batch_runner if batched else _runner
    runner = make(store, _Delivers(), sink, policy="dead_letter")

    async def _one(connector: object, n: int) -> None:
        runner._destinations[OUT] = cast(DestinationConnector, connector)
        if batched:
            body = _adt(n)
            await store.enqueue_message(
                channel_id="c1", raw=body, deliveries=[(OUT, body)], now=200.0 + n
            )
            await run_one_batch(runner, OUT)  # closes the connector
        else:
            await _deliver_one(store, runner, n)
            await cast(DestinationConnector, connector).aclose()

    try:
        await _one(_MintsThroughACodedTokenEndpoint(), 1)
        await _one(_MintsThroughACodedTokenEndpoint(), 2)
        assert sink.errors == [_CONFIG_FAULT_ALERT] and sink.restored == []
        await _one(_Delivers(), 3)  # the fix
        assert sink.restored == [(OUT, "config_fault")]  # its own alert resolves
        await _one(_MintsThroughACodedTokenEndpoint(), 4)  # the fault comes back
        assert sink.errors == [_CONFIG_FAULT_ALERT, _CONFIG_FAULT_ALERT]
    finally:
        await runner.stop()


async def test_under_the_dead_letter_policy_an_unmarked_reject_raises_no_connection_error(
    store: MessageStore,
) -> None:
    sink = _RecordsStops()
    connector = _UnmarkedRefusal()
    runner = _runner(store, connector, sink, policy="dead_letter")
    try:
        for n in (1, 2, 3):
            await _deliver_one(store, runner, n)
        assert await store.count_dead(allowed_channels=None) == 3
        assert sink.errors == []
    finally:
        await runner.stop()
        await connector.aclose()


@pytest.mark.parametrize("batched", [False, True], ids=["single-row", "batch"])
@pytest.mark.parametrize("when", ["mid-send", "during-dead-letter"])
async def test_under_the_dead_letter_policy_a_retired_connectors_config_fault_does_not_alert(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, when: str, batched: bool
) -> None:
    # A reload that retires the connector, while it mints or while its rows are being
    # dead-lettered, may be the fix, so the old connector's fault raises no alert.
    sink = _RecordsStops()
    connector: _MintsThroughACodedTokenEndpoint
    make = _batch_runner if batched else _runner
    if when == "mid-send":
        retiring = _RetiredMidSend()
        connector = retiring
        runner = make(store, connector, sink, policy="dead_letter")
        retiring.runner = runner
    else:
        connector = _MintsThroughACodedTokenEndpoint()
        runner = make(store, connector, sink, policy="dead_letter")
        write = "dead_letter_batch" if batched else "dead_letter_now"
        dead_letter = getattr(store, write)

        async def _reload_lands_in_the_write(*args: object) -> None:
            runner._destinations[OUT] = cast(DestinationConnector, _Delivers())
            await dead_letter(*args)

        monkeypatch.setattr(store, write, _reload_lands_in_the_write)
    try:
        if batched:
            await _enqueue(store, 2)
            await run_one_batch(runner, OUT)
        else:
            await _deliver_one(store, runner, 1)
        assert await store.count_dead(allowed_channels=None) == (2 if batched else 1)
        assert sink.errors == []
    finally:
        await runner.stop()
        await connector.aclose()


@pytest.mark.parametrize("first", ["connection_lost", None], ids=["after-transport-alert", "alone"])
async def test_on_the_notifier_a_config_fault_alert_keeps_its_own_throttle_and_instance(
    first: str | None,
) -> None:
    # The real sink, not a recorder: a transport alert inside the cooldown must neither throttle
    # the config_fault page nor take its instance, and each clear resolves only its own instance.
    pages = _RecordingTransport()
    state = _RecordingStore()
    sink = NotifierAlertSink([pages], store=cast(Any, state), realert_seconds=300.0)
    if first is not None:
        sink.connection_error(OUT, kind=first, detail="unreachable", error_class="DeliveryError")
    sink.connection_error(OUT, kind="config_fault", detail="coded", error_class="NegativeAckError")
    await _drain_state(sink)
    sink.connection_restored(OUT, kind="config_fault")
    sink.connection_restored(OUT)
    await _drain_state(sink)
    await _drain_pages(sink)

    expected = ([first] if first is not None else []) + ["config_fault"]
    assert [e.get("kind") for e in pages.events] == expected
    instances = [(u["event_type"], u["reason"]) for u in state.upserts]
    transport = [("connection_error", "unreachable")] if first is not None else []
    assert instances == [*transport, ("connection_error.config_fault", "coded")]
    assert [r["event_type"] for r in state.resolves] == [
        "connection_error.config_fault",
        "connection_error",
    ]
