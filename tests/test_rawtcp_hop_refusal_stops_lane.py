# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An MLLP or X12 outbound's send-time hop refusal stops the lane and keeps the queue.

BACKLOG #5719 (MLLP) and #5718 (X12). The send-time backstop, ``InsecureHopGuard.assert_send``, raised a bare
``InsecureHopRefused``, a ``ValueError``. The delivery worker files an unclassified exception as an
internal error and, under the default ``internal_error`` policy, dead-letters the row, so a
configuration refusal that every queued row would meet would have emptied the lane's queue into the
dead-letter queue one row at a time. ``InsecureHopGuard.assert_delivery`` raises it instead as the
permanent configuration fault the HTTP family already raises (``assert_delivery_url``), which the
worker answers by stopping the lane and releasing the row un-errored.

BACKLOG #5718 also covers the reload half on the X12 side: a send that reaches a connector the
reload already closed retries on the replacement, before the hop guard can stop the lane, and
``aclose`` closes a connect-per-send socket in flight, as it already closed the persistent one, so
that send fails as a retryable ``DeliveryError`` instead of running on to its full timeout.

Synthetic HL7 and X12 only. The refusal tests open no socket, because the refusal fires before any
dial; the in-flight test uses a loopback peer.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, InsecureHopRefused
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports.base import (
    INSECURE_HOP_REFUSED_CODE,
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
)
from messagefoundry.transports.mllp import InsecureHopGuard, MLLPDestination
from messagefoundry.transports.x12 import X12Destination

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"
CHANNEL = "IB_TEST"
REMOTE = "10.0.0.5"  # never dialed: the refusal fires before any socket opens
LOOPBACK = "127.0.0.1"


def _refusing_guard(connection: str) -> InsecureHopGuard:
    """A guard whose captured posture REFUSES: enforcing, off-box, unattested, unaccepted."""
    return InsecureHopGuard(
        host=REMOTE,
        port=5000,
        cell="test outbound",
        description="cleartext egress",
        attested=False,
        attested_reason=None,
        posture=HopPosture(enforcing=True),
        connection=connection,
    )


#: A synthetic, PHI-free interchange envelope. The refusal tests never parse it.
X12 = (
    "ISA*00*          *00*          *ZZ*SENDERID       *ZZ*RECEIVERID     *240101*1200*^*00501"
    "*000000001*0*P*:~IEA*1*000000001~"
)


def _mllp() -> MLLPDestination:
    # Built on loopback with no stamped posture, so construction passes; the refusing guard is
    # swapped in after, standing in for a posture that changed after construction.
    dest = MLLPDestination(
        Destination(
            name="OB_MLLP", type=ConnectorType.MLLP, settings={"host": LOOPBACK, "port": 5000}
        )
    )
    dest._hop_guard = _refusing_guard("OB_MLLP")
    return dest


def _x12(**settings: object) -> X12Destination:
    """An X12 outbound built as :func:`_mllp` builds MLLP's, refusing guard swapped in."""
    dest = X12Destination(
        Destination(
            name="OB_X12",
            type=ConnectorType.X12,
            settings={"host": LOOPBACK, "port": 5000, **settings},
        )
    )
    dest._hop_guard = _refusing_guard("OB_X12")
    return dest


#: (build, payload, connection name, connector label) for each outbound the two rows fixed.
_REFUSING = [
    pytest.param(_mllp, RAW, "OB_MLLP", "MLLP", id="mllp-5719"),
    pytest.param(_x12, X12, "OB_X12", "X12", id="x12-5718"),
]


def _assert_config_fault(err: NegativeAckError, connector: str) -> None:
    assert err.code == INSECURE_HOP_REFUSED_CODE
    assert (err.permanent, err.config_fault, err.credential_fault) == (True, True, False)
    assert isinstance(err.__cause__, InsecureHopRefused)
    assert str(err).startswith(f"{connector} send refused: ")


def test_assert_delivery_classifies_the_refusal() -> None:
    with pytest.raises(NegativeAckError) as refused:
        _refusing_guard("OB_X").assert_delivery(connector="MLLP")
    _assert_config_fault(refused.value, "MLLP")
    # The text is the guard's own: connection, cell, host and port, and no message content.
    assert "OB_X" in str(refused.value)
    assert f"{REMOTE}:5000" in str(refused.value)


@pytest.mark.parametrize(
    ("host", "posture"),
    [(REMOTE, None), (LOOPBACK, HopPosture(enforcing=True))],
    ids=["unstamped", "loopback"],
)
def test_assert_delivery_is_silent_where_assert_send_is(
    host: str, posture: HopPosture | None
) -> None:
    InsecureHopGuard(
        host=host,
        port=5000,
        cell="t",
        description="d",
        attested=False,
        attested_reason=None,
        posture=posture,
    ).assert_delivery(connector="MLLP")


@pytest.mark.parametrize(("build", "payload", "name", "label"), _REFUSING)
async def test_send_raises_the_configuration_fault(
    build: Callable[[], DestinationConnector], payload: str, name: str, label: str
) -> None:
    with pytest.raises(NegativeAckError) as refused:
        await build().send(payload)
    _assert_config_fault(refused.value, label)


class _Stops(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


async def _deliver_one(
    tmp_path: Path, dest_name: str, connector: DestinationConnector
) -> tuple[_ItemOutcome, str, _Stops]:
    """Queue one outbound row for ``dest_name``, deliver it through ``connector``, and return the
    outcome, the row's status and the alert sink."""
    store = await MessageStore.open(tmp_path / "hop.db")
    try:
        mid = await store.enqueue_ingress(channel_id=CHANNEL, raw=RAW, now=0.0)
        ing = await store.claim_next_fifo(CHANNEL, stage=Stage.INGRESS.value, now=0.0)
        assert ing is not None
        await store.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id=CHANNEL,
            handlers=[("h1", RAW)],
            disposition=MessageStatus.ROUTED,
            now=0.0,
        )
        routed = await store.claim_next_fifo(CHANNEL, stage=Stage.ROUTED.value, now=0.0)
        assert routed is not None
        await store.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id=CHANNEL,
            deliveries=[(dest_name, RAW)],
            now=0.0,
        )
        sink = _Stops()
        runner = RegistryRunner(
            Registry(),
            store,
            poll_interval=0.02,
            alert_sink=sink,
            egress=EgressSettings(deny_by_default=False),
        )
        runner._destinations[dest_name] = connector
        item = await store.claim_next_fifo(dest_name, now=1.0)
        assert item is not None
        outcome = await runner._process_delivery_item(dest_name, item)
        cur = await store._db.execute(
            "SELECT status FROM queue WHERE message_id=? AND stage=?", (mid, Stage.OUTBOUND.value)
        )
        row = await cur.fetchone()
        assert row is not None
        return outcome[0], str(row[0]), sink
    finally:
        await store.close()


@pytest.mark.parametrize(("build", "payload", "name", "label"), _REFUSING)
async def test_a_send_time_refusal_stops_the_lane_and_keeps_the_row(
    tmp_path: Path,
    build: Callable[[], DestinationConnector],
    payload: str,
    name: str,
    label: str,
) -> None:
    outcome, status, sink = await _deliver_one(tmp_path, name, build())
    assert outcome is _ItemOutcome.STOPPED
    assert status == OutboxStatus.PENDING.value, "the row was not kept for the operator"
    assert [stopped for stopped, _ in sink.stopped] == [name]
    assert f"configuration fault ({INSECURE_HOP_REFUSED_CODE})" in sink.stopped[0][1]


# --- BACKLOG #5718: the reload half, X12 ----------------------------------------------------------


def _mllp_with(persistent: bool) -> MLLPDestination:
    dest = MLLPDestination(
        Destination(
            name="OB_MLLP",
            type=ConnectorType.MLLP,
            settings={"host": LOOPBACK, "port": 5000, "persistent": persistent},
        )
    )
    dest._hop_guard = _refusing_guard("OB_MLLP")
    return dest


@pytest.mark.parametrize(
    ("build", "payload"),
    [
        pytest.param(lambda: _x12(persistent=False), X12, id="x12-connect-per-send"),
        pytest.param(lambda: _x12(persistent=True), X12, id="x12-persistent"),
        pytest.param(lambda: _mllp_with(False), RAW, id="mllp-connect-per-send"),
        pytest.param(lambda: _mllp_with(True), RAW, id="mllp-persistent"),
    ],
)
async def test_a_closed_connector_retries_before_its_guard_can_stop_the_lane(
    build: Callable[[], DestinationConnector], payload: str
) -> None:
    """A reload swaps the connector out and closes it. A send that still reaches the old one is a
    retry on the replacement, never the old guard's lane-stopping refusal: the replacement may
    deliver where the stale one refuses (BACKLOG #5718 for X12, #5719 for MLLP)."""
    dest = build()
    await dest.aclose()
    with pytest.raises(DeliveryError) as raised:
        await dest.send(payload)
    assert not isinstance(raised.value, NegativeAckError)
    assert "is closed (stop/reload)" in str(raised.value)


async def test_aclose_closes_a_connect_per_send_in_flight() -> None:
    """The reload half of BACKLOG #5718. The peer reads the interchange and never answers, so the
    send waits on its reply. Before the fix aclose closed only the cached persistent socket, so this
    send ran on against the replaced connector until its 30 second timeout."""
    received = asyncio.Event()

    async def silent_peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(4096)
        received.set()
        try:
            await reader.read(4096)  # until the sender's socket closes
        finally:
            writer.close()

    server = await asyncio.start_server(silent_peer, LOOPBACK, 0)
    port = int(server.sockets[0].getsockname()[1])
    dest = X12Destination(
        Destination(
            name="OB_X12",
            type=ConnectorType.X12,
            settings={"host": LOOPBACK, "port": port, "expect_reply": True, "timeout_seconds": 30},
        )
    )
    send = asyncio.create_task(dest.send(X12))
    try:
        await asyncio.wait_for(received.wait(), 5)
        await dest.aclose()
        with pytest.raises(DeliveryError) as raised:
            await asyncio.wait_for(asyncio.shield(send), 5)
        # The engine closed the socket, so the error names that close and never blames the peer,
        # and says the interchange may have landed.
        assert "is closed (stop/reload) after the payload was written" in str(raised.value)
        assert "delivery indeterminate" in str(raised.value)
        assert dest._inflight is None
    finally:
        # A failure above must not leave the send holding the socket the silent peer waits on, or
        # server.wait_closed() would wait out its bound and mask the real assertion.
        send.cancel()
        await asyncio.gather(send, return_exceptions=True)
        server.close()
        await asyncio.wait_for(server.wait_closed(), 5)


async def test_a_partner_fault_read_before_the_close_keeps_its_own_error() -> None:
    """Only the engine's own close is relabelled. A reply over the size cap, sent by the partner
    before the reload closed the connector, keeps its own error: blaming the close would hide it."""
    sent = asyncio.Event()

    async def oversize_peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(4096)
        writer.write(b"ISA*" + b"0" * 8192)
        await writer.drain()
        sent.set()
        try:
            await reader.read(4096)
        finally:
            writer.close()

    server = await asyncio.start_server(oversize_peer, LOOPBACK, 0)
    port = int(server.sockets[0].getsockname()[1])
    dest = X12Destination(
        Destination(
            name="OB_X12",
            type=ConnectorType.X12,
            settings={
                "host": LOOPBACK,
                "port": port,
                "expect_reply": True,
                "max_interchange_bytes": 1024,
            },
        )
    )
    real_read = dest._read_reply

    async def read_after_close(reader: asyncio.StreamReader) -> bytes:
        # The partner's oversized reply is on the wire before the reload marks the connector closed.
        await sent.wait()
        dest._closed = True
        return await real_read(reader)

    dest._read_reply = read_after_close  # type: ignore[method-assign]
    try:
        with pytest.raises(DeliveryError) as raised:
            await asyncio.wait_for(dest._send_once(X12), 5)
        assert "is closed (stop/reload)" not in str(raised.value)
    finally:
        server.close()
        await asyncio.wait_for(server.wait_closed(), 5)


@pytest.mark.parametrize("persistent", [False, True], ids=["connect-per-send", "persistent"])
async def test_aclose_during_the_dial_never_delivers_on_the_replaced_connector(
    persistent: bool,
) -> None:
    """aclose() cannot see a socket that is still being dialed. The send must notice the close once
    the dial returns, close the new socket and retry on the replacement, never write the
    interchange to the replaced connector's peer (BACKLOG #5718)."""
    got: list[bytes] = []
    peer_done = asyncio.Event()

    async def peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            got.append(await reader.read(4096))
        finally:
            writer.close()
            peer_done.set()

    server = await asyncio.start_server(peer, LOOPBACK, 0)
    port = int(server.sockets[0].getsockname()[1])
    dest = X12Destination(
        Destination(
            name="OB_X12",
            type=ConnectorType.X12,
            settings={"host": LOOPBACK, "port": port, "persistent": persistent},
        )
    )
    real_dial = dest._dial

    async def dial_then_reload() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        conn = await real_dial()
        await dest.aclose()  # the reload lands while the dial is still pending
        return conn

    dest._dial = dial_then_reload  # type: ignore[method-assign]
    try:
        with pytest.raises(DeliveryError) as raised:
            await asyncio.wait_for(dest.send(X12), 5)
        assert not isinstance(raised.value, NegativeAckError)
        assert "is closed (stop/reload)" in str(raised.value)
        await asyncio.wait_for(peer_done.wait(), 5)
        assert got == [b""], "the interchange reached the replaced connector's peer"
        assert dest._conn is None
        assert dest._inflight is None
    finally:
        server.close()
        await asyncio.wait_for(server.wait_closed(), 5)


@pytest.mark.parametrize("no_ack", [False, True], ids=["ack", "no-ack"])
async def test_aclose_during_an_mllp_persistent_dial_never_delivers(no_ack: bool) -> None:
    """The MLLP twin of the X12 dial race. MLLP checked the close only at the top of its persistent
    paths, which send() now reaches with no await in between, so the window that mattered, the
    dial, was open: the send cached the new socket and delivered on the replaced connector."""
    got: list[bytes] = []
    peer_done = asyncio.Event()

    async def peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            got.append(await reader.read(4096))
        finally:
            writer.close()
            peer_done.set()

    server = await asyncio.start_server(peer, LOOPBACK, 0)
    port = int(server.sockets[0].getsockname()[1])
    dest = MLLPDestination(
        Destination(
            name="OB_MLLP",
            type=ConnectorType.MLLP,
            settings={"host": LOOPBACK, "port": port, "persistent": True, "no_ack": no_ack},
        )
    )
    real_dial = dest._dial

    async def dial_then_reload() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        conn = await real_dial()
        await dest.aclose()  # the reload lands while the dial is still pending
        return conn

    dest._dial = dial_then_reload  # type: ignore[method-assign]
    try:
        with pytest.raises(DeliveryError) as raised:
            await asyncio.wait_for(dest.send(RAW), 5)
        assert not isinstance(raised.value, NegativeAckError)
        assert "is closed (stop/reload)" in str(raised.value)
        await asyncio.wait_for(peer_done.wait(), 5)
        assert got == [b""], "the message reached the replaced connector's peer"
        assert dest._conn is None
    finally:
        server.close()
        await asyncio.wait_for(server.wait_closed(), 5)
