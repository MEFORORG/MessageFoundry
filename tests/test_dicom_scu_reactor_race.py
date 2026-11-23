# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The outbound SCU and pynetdicom 3.0.4's reactor race (vault BACKLOG #6637, item 19; engine PR
3130 describes it). A send pauses the association's reactor by clearing a checkpoint and waiting
for ``_is_paused``. A reactor just past that checkpoint still reads ``True`` there, runs one more
pass, and can take the DIMSE response off the queue and drop it. The send then waits out its DIMSE
timeout and the object is retried, though the peer stored it.

The delays below hold that window open, so the race does not depend on a loaded machine. Every
object is a synthetic SR from ``tests/_dicom_sample.py``, on a loopback listener.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence: see
the note at the top of ``tests/test_dicom_scp_admission.py``.
"""

from __future__ import annotations

import contextlib
import inspect
import logging
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pydicom", reason="DICOM SCU tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCU tests need the [dicom] extra")

from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from messagefoundry.transports.base import DeliveryError  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402
from tests.test_dicom_scu import _carry, _scu, _storage_scp  # noqa: E402


class _StalledCheckpoint(threading.Event):
    """A reactor checkpoint whose ``wait`` stalls after it returns, which holds open the window in
    which ``_is_paused`` still reads ``True`` for a reactor that is about to run a pass."""

    def wait(self, timeout: float | None = None) -> bool:
        passed = super().wait(timeout)
        time.sleep(0.2)
        return passed


def _dropped(caplog: pytest.LogCaptureFixture) -> list[str]:
    """pynetdicom's line for each response its reactor took and could not serve."""
    return [r.getMessage() for r in caplog.records if "Received unexpected" in r.getMessage()]


@pytest.fixture
def stalled(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """Delays that put the reactor in the window as the send starts and the caller behind it when
    the response lands, with pynetdicom's WARNING lines captured."""
    from pynetdicom.association import Association
    from pynetdicom.dimse import DIMSEServiceProvider

    build, store, read = (
        Association.__init__,
        Association.send_c_store,
        DIMSEServiceProvider.get_msg,
    )

    def stalled_build(self: Any, *args: Any, **kwargs: Any) -> None:
        build(self, *args, **kwargs)
        self._reactor_checkpoint = _StalledCheckpoint()
        self._reactor_checkpoint.set()

    def late_store(self: Any, *args: Any, **kwargs: Any) -> Any:
        time.sleep(0.01)  # so the reactor has reached its checkpoint before the send starts
        return store(self, *args, **kwargs)

    def late_read(self: Any, block: bool = False) -> Any:
        if block:
            time.sleep(0.5)  # so the response is on the queue when the reactor wakes
        return read(self, block=block)

    monkeypatch.setattr(Association, "__init__", stalled_build)
    monkeypatch.setattr(Association, "send_c_store", late_store)
    monkeypatch.setattr(DIMSEServiceProvider, "get_msg", late_read)
    with caplog.at_level(logging.WARNING, logger="pynetdicom.association"):
        yield


@pytest.mark.usefixtures("stalled")
async def test_the_reactor_never_takes_the_response_to_the_one_store(
    caplog: pytest.LogCaptureFixture,
) -> None:
    data = _carry(make_sr_part10())
    with _storage_scp() as port:
        scu = _scu(port, timeout_seconds=2.0)
        for _ in range(3):
            await scu.send(data)  # a dropped response would raise DeliveryError here
    assert _dropped(caplog) == []


@pytest.mark.usefixtures("stalled")
async def test_the_same_stalls_lose_a_response_without_the_hold(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The CONTROL for the test above: without the hold, these delays do reproduce the race.
    monkeypatch.setattr(dicom_module, "_hold_the_reactor", lambda event: None)
    data = _carry(make_sr_part10())
    with _storage_scp() as port:
        scu = _scu(port, timeout_seconds=1.0)
        for _ in range(8):
            with contextlib.suppress(DeliveryError):
                await scu.send(data)
            if _dropped(caplog):
                break
    assert _dropped(caplog), (
        "the stalls never reproduced the race, so the test above proves nothing"
    )


def test_the_reactor_seams_the_hold_uses_are_still_pynetdicoms() -> None:
    from pynetdicom import acse
    from pynetdicom.association import Association

    reactor = inspect.getsource(Association._run_reactor)
    assert "self._is_paused = True\n            self._reactor_checkpoint.wait()" in reactor
    assert "context_id, msg = self.dimse.get_msg(block=False)" in reactor
    negotiate = inspect.getsource(acse.ACSE._negotiate_as_requestor)
    # The hold has to run before a caller can see the association as established.
    assert negotiate.index("evt.EVT_ACCEPTED") < negotiate.index("self.assoc.is_established = True")
