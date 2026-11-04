# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DICOM C-STORE SCP's deadline per DIMSE message (vault BACKLOG #5080): a peer that keeps one
message incomplete with slow fragments, each PDU inside the per-read deadline, is ended at
``timeout_seconds`` plus its data set bytes at ``_MIN_MESSAGE_BYTES_PER_SECOND``, and gives its
``max_associations`` slot back.

Every listener here binds ``127.0.0.1`` on an ephemeral port. Every object is a synthetic SR from
``tests/_dicom_sample.py``; none holds real PHI.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence: see
the note at the top of ``tests/test_dicom_scp_admission.py``.

**Runner speed.** The end-to-end test asserts a floor that holds whatever the runner's speed, since
the SCP cannot end the message before its deadline, and a ceiling with one ``timeout_seconds`` of
overshoot plus slack, since the check runs only when a PDU lands. A slow runner can only push the
end later, toward that ceiling, never under the floor. The deadline arithmetic itself is pinned on
a clock the test owns, in the tally tests, where no runner can move it.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from pathlib import Path

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402
from tests.test_dicom_scp import _scu_cstore  # noqa: E402
from tests.test_dicom_scp_admission import _LOG, _running_scp, _send_slowly, _until  # noqa: E402
from tests.test_dicom_scp_pre_association import _a_held_association  # noqa: E402
from tests.test_dicom_scp_receipt_bounds import _c_store_command, _p_data  # noqa: E402

#: The floor the end-to-end test patches in, so that its deadline is ``timeout_seconds`` and a few
#: hundredths of a second, rather than the shipped constant's seconds per MiB.
_TEST_FLOOR = 1024


class _Clock:
    """A monotonic clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _tally(clock: _Clock, *, timeout: float = 30.0) -> dicom_module._ReceiptTally:
    return dicom_module._ReceiptTally(
        max_data_set_bytes=10 * 1024 * 1024, timeout_seconds=timeout, clock=clock
    )


_DEADLINE_REASON = "a message did not arrive within timeout_seconds plus its data set"


# --- The deadline's arithmetic, on a clock the test owns ----------------------------------------


def test_a_message_has_timeout_seconds_plus_its_data_set_at_the_floor() -> None:
    clock = _Clock()
    tally = _tally(clock)
    floor = dicom_module._MIN_MESSAGE_BYTES_PER_SECOND
    assert tally.take(_p_data(0x03, _c_store_command())[6:]) is None  # the clock starts here
    fragment = b"\x00" * 4096
    assert tally.take(_p_data(0x00, fragment)[6:]) is None
    # Exactly at the deadline is inside it; anything past it ends the association.
    clock.now += 30.0 + len(fragment) / floor
    assert tally.take(_p_data(0x00, b"")[6:]) is None
    clock.now += 0.001
    ended = tally.take(_p_data(0x00, b"")[6:])
    assert ended is not None
    assert ended[0] == dicom_module._ABORT_OVER_LIMIT
    assert ended[1].startswith(_DEADLINE_REASON), ended
    assert str(len(fragment)) not in ended[1], "the reason repeats a count the peer's sending made"


def test_a_message_that_completes_is_never_ended_and_the_next_starts_its_own_clock() -> None:
    # The CONTROL for the deadline. The check is for a message still in progress: one whose last
    # fragment lands, even long past its deadline, is whole and pynetdicom serves it, so ending the
    # association there would drop a finished object. The next message's deadline then runs from
    # its own first fragment, not from the association's start.
    clock = _Clock()
    tally = _tally(clock)
    assert tally.take(_p_data(0x03, _c_store_command())[6:]) is None
    clock.now += 60.0
    assert tally.take(_p_data(0x02, b"\x00" * 16)[6:]) is None  # the last fragment, late
    assert tally.began is None
    clock.now += 3600.0  # an hour between messages: no message is in progress, nothing runs
    assert tally.take(_p_data(0x03, _c_store_command())[6:]) is None
    clock.now += 29.0
    assert tally.take(_p_data(0x00, b"\x00" * 16)[6:]) is None
    clock.now += 2.0
    ended = tally.take(_p_data(0x00, b"\x00" * 16)[6:])
    assert ended is not None and ended[1].startswith(_DEADLINE_REASON), ended


def test_a_command_set_sent_in_slow_fragments_has_timeout_seconds() -> None:
    # A command set carries no data set bytes, so its deadline is timeout_seconds alone. Before
    # this, its fragments were bounded only in size, at 64 KiB.
    clock = _Clock()
    tally = _tally(clock, timeout=5.0)
    command = _c_store_command()
    assert tally.take(_p_data(0x01, command[:10])[6:]) is None
    clock.now += 5.5
    ended = tally.take(_p_data(0x01, command[10:20])[6:])
    assert ended is not None and ended[1].startswith(_DEADLINE_REASON), ended


# --- The end-to-end bound ------------------------------------------------------------------------


async def test_slow_fragments_of_one_object_end_the_association_and_free_its_slot(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The reading the row was filed on: a peer that finishes each PDU inside the per-read deadline,
    # and never finishes the message, held its max_associations slot for as long as it sent. Here
    # each PDU takes about 0.6 s to dribble in, a byte every 0.03 s, against a 2 s read deadline,
    # and pynetdicom's idle timer restarts on each one.
    monkeypatch.setattr(dicom_module, "_MIN_MESSAGE_BYTES_PER_SECOND", _TEST_FLOOR)
    timeout = 2.0
    fragment_pdu = _p_data(0x00, b"\x00" * 8)
    pending = fragment_pdu * 200  # far more than the bound lets through
    async with _running_scp({"timeout_seconds": timeout, "max_associations": 1}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                started = time.monotonic()
                sock.sendall(_p_data(0x03, _c_store_command()))  # the message begins
                sock.settimeout(0.03)
                closed = await asyncio.to_thread(_send_slowly, sock, pending, give_up=15.0)
                took = time.monotonic() - started
                await _until(lambda: scp._ended_log.refusals == 1)
        finally:
            sock.close()
        assert closed is not None, "a message kept incomplete held its association past 15 s"
        # ``took`` counts from before the command's send, so it is at least the SCP's own time
        # since it counted that PDU, and the SCP cannot end the message before its deadline, which
        # is ``timeout`` and the few bytes sent at the patched floor. The check runs as a PDU lands,
        # so the end may come up to one PDU's reads later, each bounded by ``timeout``; the last
        # second is slack for a loaded runner.
        assert timeout <= took < 2 * timeout + 1.0 + 1.0, f"ended after {took:.2f}s"
        await _until(lambda: scp._server.active_associations == [])
        # The slot is back: at max_associations=1, a real sender is served at once.
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10()) == (
            True,
            0x0000,
        )
    ended = [
        r.getMessage() for r in caplog.records if r.name == _LOG and "ended an" in r.getMessage()
    ]
    assert len(ended) == 1, caplog.text
    assert _DEADLINE_REASON in ended[0], ended


async def test_an_object_sent_at_normal_speed_completes_under_the_same_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The CONTROL for the test above: the same patched floor and timeout, and an object sent at
    # loopback speed, which completes long before its deadline and is stored.
    monkeypatch.setattr(dicom_module, "_MIN_MESSAGE_BYTES_PER_SECOND", _TEST_FLOOR)
    captured: list[bytes] = []
    async with _running_scp(
        {"timeout_seconds": 2.0, "max_associations": 1}, captured=captured
    ) as scp:
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10()) == (True, 0)
        assert scp._ended_log.refusals == 0
    assert len(captured) == 1


# --- The pins ------------------------------------------------------------------------------------


def test_pynetdicoms_idle_timer_restarts_on_each_pdu() -> None:
    """Why the read deadline and pynetdicom's own timers do not reach a slow message: the DUL
    restarts its idle timer whenever it receives a PDU. Read against 3.0.4."""
    from pynetdicom.dul import DULServiceProvider

    run = inspect.getsource(DULServiceProvider.run_reactor)
    assert "elif self._is_transport_event():" in run
    assert run.index("elif self._is_transport_event():") < run.index("self._idle_timer.restart()")


def test_the_doc_states_the_message_deadline() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "DICOM.md").read_text(encoding="utf-8")
    floor_kib = dicom_module._MIN_MESSAGE_BYTES_PER_SECOND // 1024
    assert f"{floor_kib} KiB a second" in doc
    assert "per message, not per association" in doc
    assert "C-ECHO every few seconds" in doc
