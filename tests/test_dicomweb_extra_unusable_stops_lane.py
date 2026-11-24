# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DICOMweb outbound whose installed ``[dicom]`` extra does not load stops the lane (#5914).

Every queued row would meet the same load failure, so ``dicomweb._dicom_extra_unusable`` marks it a
configuration fault (ADR 0095 Amendment B.3, Manager decision of 2026-11-24), and the delivery
worker's lane-stopping route takes it: the lane stops and every row stays queued, un-errored. Left
an internal error, the default ``internal_error="continue"`` would dead-letter each row in turn
with no lane alert. This drives a real DICOMweb destination, its extra's load patched to fail as a
broken ``pydicom`` does, through the real delivery worker.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.transports import dicomweb
from tests._refusal_log_capture import until
from tests.test_dicomweb import PAYLOAD, STORED_OK, _dest, _FakeOpener
from tests.test_token_reply_coded_stops_lane import (
    OUT,
    _outbound_rows,
    _run_three_through_the_worker,
    _until_rows,
)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


class _DicomWebOnABrokenExtraHost:
    """A real DICOMweb destination on a host whose ``pydicom`` is found but does not load. The
    worker's HL7 payload is swapped for a carried DICOM object, the one the destination's own tests
    send, so the send reaches the extra's load."""

    def __init__(self) -> None:
        self.dest = _dest()
        self.opener = _FakeOpener(body=STORED_OK.encode(), status=200)
        self.dest._opener = self.opener  # type: ignore[assignment]
        self.sends = 0

    async def send(self, payload: str) -> None:
        self.sends += 1
        await self.dest.send(PAYLOAD)

    async def aclose(self) -> None:
        await self.dest.aclose()


async def test_an_unloadable_dicom_extra_stops_the_lane_and_keeps_every_queued_row(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def load() -> object:
        raise RuntimeError("a broken pydicom")

    monkeypatch.setattr(dicomweb, "_dicom_extra_installed", lambda: True)
    monkeypatch.setattr(dicomweb, "load_dcmread", load)
    connector = _DicomWebOnABrokenExtraHost()
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

    assert connector.sends == 1  # stopped after the first
    assert connector.opener.requests == []  # nothing was sent
    # Every row is still queued, un-errored, its claim given back; none is dead-lettered.
    assert await _outbound_rows(store) == [(OutboxStatus.PENDING.value, 0, None)] * 3
    assert await store.count_dead(allowed_channels=None) == 0
    assert {name for name, _ in stopped} == {OUT}
    detail = stopped[0][1]
    assert "configuration fault (dicom-extra-unusable)" in detail
    assert "queue retained" in detail
    # The remedy says the extra is installed but does not load, not to install it.
    assert "installed but does not load" in detail
    assert "pip install" not in detail
