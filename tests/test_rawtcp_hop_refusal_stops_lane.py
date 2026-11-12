# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A raw-TCP outbound's send-time hop refusal stops the lane and keeps the queue.

BACKLOG #5719 (MLLP). The send-time backstop, ``InsecureHopGuard.assert_send``, raised a bare
``InsecureHopRefused``, a ``ValueError``. The delivery worker files an unclassified exception as an
internal error and, under the default ``internal_error`` policy, dead-letters the row, so a
configuration refusal that every queued row would meet would have emptied the lane's queue into the
dead-letter queue one row at a time. ``InsecureHopGuard.assert_delivery`` raises it instead as the
permanent configuration fault the HTTP family already raises (``assert_delivery_url``), which the
worker answers by stopping the lane and releasing the row un-errored.

Synthetic HL7 only; no socket is opened, because the refusal fires before any dial.
"""

from __future__ import annotations

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
    DestinationConnector,
    NegativeAckError,
)
from messagefoundry.transports.mllp import InsecureHopGuard, MLLPDestination

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


def _mllp(name: str = "OB_MLLP") -> MLLPDestination:
    # Built on loopback with no stamped posture, so construction passes; the refusing guard is
    # swapped in after, standing in for a posture that changed after construction.
    dest = MLLPDestination(
        Destination(name=name, type=ConnectorType.MLLP, settings={"host": LOOPBACK, "port": 5000})
    )
    dest._hop_guard = _refusing_guard(name)
    return dest


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


def test_assert_delivery_is_silent_where_assert_send_is() -> None:
    InsecureHopGuard(
        host=REMOTE,
        port=5000,
        cell="t",
        description="d",
        attested=False,
        attested_reason=None,
        posture=None,
    ).assert_delivery(connector="MLLP")
    InsecureHopGuard(
        host=LOOPBACK,
        port=5000,
        cell="t",
        description="d",
        attested=False,
        attested_reason=None,
        posture=HopPosture(enforcing=True),
    ).assert_delivery(connector="MLLP")


async def test_mllp_send_raises_the_configuration_fault() -> None:
    with pytest.raises(NegativeAckError) as refused:
        await _mllp().send(RAW)
    _assert_config_fault(refused.value, "MLLP")


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


async def test_an_mllp_send_time_refusal_stops_the_lane_and_keeps_the_row(tmp_path: Path) -> None:
    outcome, status, sink = await _deliver_one(tmp_path, "OB_MLLP", _mllp())
    assert outcome is _ItemOutcome.STOPPED
    assert status == OutboxStatus.PENDING.value, "the row was not kept for the operator"
    assert [name for name, _ in sink.stopped] == ["OB_MLLP"]
    assert f"configuration fault ({INSECURE_HOP_REFUSED_CODE})" in sink.stopped[0][1]
