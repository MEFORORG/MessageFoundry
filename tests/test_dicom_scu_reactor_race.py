# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The outbound SCU and pynetdicom 3.0.4's reactor race (vault BACKLOG #6637, item 19; engine PR
3130 describes it). A send pauses the association's reactor by clearing a checkpoint and waiting
for ``_is_paused``. A reactor just past that checkpoint still reads ``True`` there, runs one more
pass, and can take the DIMSE response off the queue and drop it. The send then waits out its DIMSE
timeout and the object is retried, though the peer stored it.

The ``gated`` fixture below orders each step of that interleaving on threading events, where a
sleep-based version only made it likely. That version lost the race on a loaded CI runner and
failed its control. The gate's one time-based step is a 1 ms poll for the response to reach the
queue. Each wait the gate adds is bounded, and a bound that runs out is a recorded fault the tests
fail on. The SCU's own timeouts still apply: the control's 1 s also bounds association setup.
Every object is a synthetic SR from ``tests/_dicom_sample.py``, on a loopback listener.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence: see
the note at the top of ``tests/test_dicom_scp_admission.py``.
"""

from __future__ import annotations

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

# How long the fixture waits for a step it is sequencing. Every step is loopback work of a few
# milliseconds, so a wait that runs out means the fixture lost track of the reactor. It records a
# fault, which the tests assert on before anything else, so the failure names the lost step.
_STEP_BOUND = 10.0


class _GatedCheckpoint(threading.Event):
    """An SCU association's reactor checkpoint that sequences the reactor's FIRST pass.

    Held (the checkpoint is clear when the reactor reaches it, which is what the hold does), the
    reactor blocks here as pynetdicom intends, until the send's own ``set()``. Not held, the wait
    returns at once and the reactor then stays in the window, ``_is_paused`` still ``True``, until
    the send's response is on the queue. Only then does it run the pass that reads the queue, and
    ``pass_done`` is set when it comes back to its checkpoint, after it has served what it read."""

    def __init__(self) -> None:
        super().__init__()
        self.set()  # as pynetdicom builds it: the reactor runs until something pauses it
        self.faults: list[str] = []
        self.reached = threading.Event()  # the reactor is at, or past, its first checkpoint
        self.go = threading.Event()  # the send lets a reactor held in the window run its pass
        self.pass_done = threading.Event()  # the reactor is back at its checkpoint after that pass
        self.in_window = False  # the reactor passed its first checkpoint without being held
        self._calls = 0

    def wait(self, timeout: float | None = None) -> bool:
        self._calls += 1  # only the reactor thread waits on its checkpoint
        if self._calls == 2:
            self.pass_done.set()
        if self._calls != 1:
            return super().wait(timeout)
        if not self.is_set():
            self.reached.set()
            return super().wait(timeout)
        passed = super().wait(timeout)
        self.in_window = True
        self.reached.set()
        if not self.go.wait(_STEP_BOUND):
            self.faults.append("the send never let the reactor out of the window")
        return passed


def _dropped(caplog: pytest.LogCaptureFixture) -> list[str]:
    """pynetdicom's line for each response its reactor took and could not serve."""
    return [r.getMessage() for r in caplog.records if "Received unexpected" in r.getMessage()]


@pytest.fixture
def gated(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> Iterator[list[_GatedCheckpoint]]:
    """Each SCU association's reactor reaches its first checkpoint before the send starts, and a
    reactor that passes it unheld runs its next pass only once the response is on the queue. The
    SCP's own associations are left alone. pynetdicom's WARNING lines are captured. Yields the SCU
    associations' checkpoints; ``faults`` on each names any step that never happened."""
    from pynetdicom.association import Association
    from pynetdicom.dimse import DIMSEServiceProvider

    checkpoints: list[_GatedCheckpoint] = []
    build, store, read = (
        Association.__init__,
        Association.send_c_store,
        DIMSEServiceProvider.get_msg,
    )

    def gated_build(self: Any, *args: Any, **kwargs: Any) -> None:
        build(self, *args, **kwargs)
        if self.is_requestor:
            checkpoint = _GatedCheckpoint()
            self._reactor_checkpoint = checkpoint
            checkpoints.append(checkpoint)

    def gated_store(self: Any, *args: Any, **kwargs: Any) -> Any:
        checkpoint = self._reactor_checkpoint
        if isinstance(checkpoint, _GatedCheckpoint) and not checkpoint.reached.wait(_STEP_BOUND):
            checkpoint.faults.append("the reactor never reached its first checkpoint")
            # Not the real send: its spin on _is_paused has no bound of its own.
            raise RuntimeError(checkpoint.faults[-1])
        return store(self, *args, **kwargs)

    def gated_read(self: Any, block: bool = False) -> Any:
        checkpoint = self.assoc._reactor_checkpoint
        # The send's first read of its response, with the reactor in the window behind it.
        if (
            block
            and isinstance(checkpoint, _GatedCheckpoint)
            and checkpoint.in_window
            and not checkpoint.go.is_set()
        ):
            deadline = time.monotonic() + _STEP_BOUND
            while self.msg_queue.empty():
                if time.monotonic() > deadline:
                    checkpoint.faults.append("the response never reached the queue")
                    break
                time.sleep(0.001)
            closed = not checkpoint.faults and self.peek_msg()[1] is None
            if closed:
                checkpoint.faults.append("the connection closed before the response came")
            checkpoint.go.set()
            # A reactor that takes the closed connection's marker leaves without coming back.
            if not closed and not checkpoint.pass_done.wait(_STEP_BOUND):
                checkpoint.faults.append("the reactor in the window never finished its pass")
        return read(self, block=block)

    monkeypatch.setattr(Association, "__init__", gated_build)
    monkeypatch.setattr(Association, "send_c_store", gated_store)
    monkeypatch.setattr(DIMSEServiceProvider, "get_msg", gated_read)
    with caplog.at_level(logging.WARNING, logger="pynetdicom.association"):
        try:
            yield checkpoints
        finally:
            for checkpoint in checkpoints:  # no reactor stays in the window past its test
                checkpoint.go.set()


async def test_the_reactor_never_takes_the_response_to_the_one_store(
    gated: list[_GatedCheckpoint], caplog: pytest.LogCaptureFixture
) -> None:
    data = _carry(make_sr_part10())
    failure: DeliveryError | None = None
    with _storage_scp() as port:
        try:
            await _scu(port, timeout_seconds=2.0).send(data)
        except DeliveryError as exc:  # a dropped response raises here; read the gate first
            failure = exc
    assert [c.faults for c in gated] == [[]]
    # The reactor was at its checkpoint before the send started, and the hold kept it there.
    assert [c.in_window for c in gated] == [False]
    assert failure is None
    assert _dropped(caplog) == []


async def test_the_same_gate_loses_a_response_without_the_hold(
    gated: list[_GatedCheckpoint], caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The CONTROL for the test above: without the hold, the same gate reproduces the race, on
    # every run. If it ever does not, the test above proves nothing.
    monkeypatch.setattr(dicom_module, "_hold_the_reactor", lambda event: None)
    data = _carry(make_sr_part10())
    failure: DeliveryError | None = None
    with _storage_scp() as port:
        try:
            await _scu(port, timeout_seconds=1.0).send(data)
        except DeliveryError as exc:
            failure = exc
    assert [c.faults for c in gated] == [[]]
    assert [c.in_window for c in gated] == [True]
    assert len(_dropped(caplog)) == 1, "the gate did not reproduce the race"
    assert failure is not None
    assert "got no response status" in str(failure)


def test_the_reactor_seams_the_hold_uses_are_still_pynetdicoms() -> None:
    from pynetdicom import acse
    from pynetdicom.association import Association
    from pynetdicom.dimse import DIMSEServiceProvider

    reactor = inspect.getsource(Association._run_reactor)
    pause = "self._is_paused = True\n            self._reactor_checkpoint.wait()"
    take = "context_id, msg = self.dimse.get_msg(block=False)"
    assert pause in reactor
    assert take in reactor
    # The gate's window sits between these two: the reactor reads the queue after its checkpoint.
    assert reactor.index(pause) < reactor.index(take)
    negotiate = inspect.getsource(acse.ACSE._negotiate_as_requestor)
    # The hold has to run before a caller can see the association as established.
    assert negotiate.index("evt.EVT_ACCEPTED") < negotiate.index("self.assoc.is_established = True")
    send = inspect.getsource(Association.send_c_store)
    clear, wait_for_response = "self._reactor_checkpoint.clear()", "get_msg(block=True)"
    assert clear in send
    assert wait_for_response in send
    # The gate's sequencing rests on the send clearing the checkpoint, then reading with block=True.
    assert send.index(clear) < send.index(wait_for_response)
    get_msg = inspect.getsource(DIMSEServiceProvider.get_msg)
    assert "self.msg_queue.get(" in get_msg  # the queue the gate watches for the response
