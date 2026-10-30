# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2814: a FILE or REMOTEFILE write failure never carries the name rendered from the
message into the error text.

The template here names the file after PID-3.1 and PID-5.1, so the rendered name holds a synthetic
MRN. A write failure's text reaches the outbox row's ``last_error``, the ``connection_lost`` event
and the ``connection_error`` alert, and the identifier must reach none of them. The FILE case uses
a real OS error: a directory sits at the target name, so the publish's replace fails, and the OS
quotes the path, name included. Synthetic data only (CLAUDE.md section 9).
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.config.models import ConnectorType, Destination, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, OutboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.redaction import safe_exc
from messagefoundry.store import MessageStore
from messagefoundry.transports import file as file_transport
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
    build_destination,
)
from messagefoundry.transports.file import FileDestination
from messagefoundry.transports.remotefile import _RemoteError
from tests.test_remotefile_transport import _dest, _FakeClient

MRN = "SYN900002"
OUT = "OB_FILE_ADT"
TEMPLATE = "{PID-3.1}_{PID-5.1}.hl7"
NAME = f"{MRN}_SYNTHETIC.hl7"
BODY = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    f"PID|1||{MRN}^^^H^MR||SYNTHETIC^PAT\r"
)


class _Sink:
    """Records the connection_error alert's detail; every other alert is ignored."""

    def __init__(self) -> None:
        self.details: list[str | None] = []

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        self.details.append(detail)

    def __getattr__(self, name: str) -> object:
        return lambda *args, **kwargs: None


def _file_destination(directory: Path) -> FileDestination:
    spec = ConnectionSpec(
        ConnectorType.FILE, {"directory": str(directory), "filename": TEMPLATE, "overwrite": True}
    )
    d = build_destination(
        Destination(name=OUT, type=ConnectorType.FILE, settings=spec.settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, FileDestination)
    return d


def _blocked(tmp_path: Path) -> Path:
    """A destination directory where the rendered name is taken by a directory, so a replace onto
    it fails with a real OS error that quotes the target path."""
    out = tmp_path / "out"
    (out / NAME).mkdir(parents=True)
    return out


async def test_a_real_os_error_leaves_no_rendered_name(tmp_path: Path) -> None:
    dest = _file_destination(_blocked(tmp_path))
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    # Positive control: the OS error under it quoted the name, so this test can see a leak.
    cause = raised.value.__cause__
    assert isinstance(cause, OSError) and MRN in str(cause)
    text = str(raised.value)
    assert text.startswith("file write failed: ") and type(cause).__name__ in text
    assert MRN not in text and MRN not in safe_exc(raised.value)


def _refuse_publish(monkeypatch: pytest.MonkeyPatch) -> list[OSError]:
    """Fail the publish step's replace with the error a share that refuses the write raises,
    quoting the target. The directory is relative, so the text stays short: with an absolute temp
    path the store's 200-character bound cut the name off on the unfixed code, which then passed."""
    raised: list[OSError] = []

    def refuse(src: object, dst: object) -> None:
        raised.append(PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(dst)))
        raise raised[-1]

    monkeypatch.setattr(file_transport.os, "replace", refuse)
    return raised


async def test_the_runner_stores_and_alerts_no_rendered_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    monkeypatch.chdir(tmp_path)
    out = Path("out")
    forced = _refuse_publish(monkeypatch)
    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        reg = Registry()
        reg.add_outbound(
            OutboundConnection(
                OUT,
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(out), "filename": TEMPLATE, "overwrite": True},
                ),
            )
        )
        sink = _Sink()
        runner = RegistryRunner(
            reg, store, alert_sink=sink, egress=EgressSettings(deny_by_default=False)
        )
        runner._destinations[OUT] = cast(DestinationConnector, _file_destination(out))
        runner._retry[OUT] = RetryPolicy(max_attempts=5)
        runner._simulate[OUT] = False
        runner._conn_event_q = asyncio.Queue(maxsize=10)  # normally created in start()
        mid = await store.enqueue_message(
            channel_id="c1", raw=BODY, deliveries=[(OUT, BODY)], now=100.0
        )
        item = await store.claim_next_fifo(OUT, now=1e12)
        assert item is not None
        await runner._process_delivery_item(OUT, item)

        (row,) = await store.outbox_for(mid)
        events = []
        while not runner._conn_event_q.empty():
            events.append(runner._conn_event_q.get_nowait())
        await store.record_connection_events(events)
        (event,) = await store.list_connection_events(connection=OUT, allowed_channels=None)
    finally:
        await store.close()

    # Positive control: the forced error quoted the name, and the text the destination built from
    # it before this fix kept the name through the store's scrub and bound.
    (cause,) = forced
    assert MRN in safe_exc(DeliveryError(f"file write failed: {cause}"))
    # Each copy is present, so an absent identifier is a scrubbed text and not a missing one.
    assert row["last_error"] and "file write failed" in row["last_error"]
    assert event.kind == "connection_lost" and event.reason
    (detail,) = sink.details
    assert detail
    for text in (row["last_error"], event.reason, detail):
        assert MRN not in text
    assert not [r for r in caplog.records if MRN in r.getMessage()]


class _EchoingClient(_FakeClient):
    """A server whose refusals quote the paths they name, as an FTP 550 reply can."""

    def __init__(self, *, permanent: bool) -> None:
        super().__init__()
        self.permanent = permanent

    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        self.ops.append(("publish", src))
        raise _RemoteError(
            f"FTP rejected the operation: 550 {src} -> {candidates[0]}, {candidates[1]}: "
            "Permission denied",
            permanent=self.permanent,
            credential_fault=self.permanent,
        )


@pytest.mark.parametrize("permanent", [False, True], ids=["transient", "permanent"])
async def test_the_remotefile_error_text_holds_no_rendered_name(
    monkeypatch: pytest.MonkeyPatch, permanent: bool
) -> None:
    client = _EchoingClient(permanent=permanent)
    dest = _dest(monkeypatch, client, filename=TEMPLATE)
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    assert ("publish", client.ops[-1][1]) in client.ops and MRN in client.ops[-1][1]
    text = str(raised.value)
    assert text.startswith("FTP rejected the operation: 550 ") and "Permission denied" in text
    assert MRN not in text and MRN not in safe_exc(raised.value)
    # The markers survive the scrub: a permanent credential refusal still stops the lane.
    assert isinstance(raised.value, NegativeAckError) is permanent
    if permanent:
        assert cast(NegativeAckError, raised.value).credential_fault


def test_without_names_keeps_text_that_names_no_file() -> None:
    exc = _RemoteError("FTP operation failed: timed out", permanent=False, config_fault=True)
    scrubbed = exc.without_names([f"/in/{NAME}"])
    assert str(scrubbed) == str(exc) and scrubbed.config_fault and not scrubbed.permanent
