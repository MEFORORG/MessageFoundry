# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DICOM C-STORE SCP's deadline per DIMSE message (vault BACKLOG #5080): a peer that keeps one
message incomplete with slow fragments, each PDU inside the per-read deadline, is ended at
``timeout_seconds`` plus its data set bytes at ``_DEFAULT_MESSAGE_BYTES_PER_SECOND``, and gives its
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
import contextlib
import inspect
import logging
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from messagefoundry.transports.base import DeliveryError  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402
from tests.test_dicom_scp import _SCP_AE, _build_scp, _scu_cstore  # noqa: E402
from tests.test_dicom_scp_admission import _LOG, _running_scp, _send_slowly, _until  # noqa: E402
from tests.test_dicom_scp_disposition import _big_sr  # noqa: E402
from tests.test_dicom_scp_pre_association import _a_held_association  # noqa: E402
from tests.test_dicom_scp_receipt_bounds import _c_store_command, _p_data  # noqa: E402
from tests.test_dicom_scu import _carry, _scu  # noqa: E402

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
        max_data_set_bytes=10 * 1024 * 1024,
        timeout_seconds=timeout,
        min_bytes_per_second=dicom_module._DEFAULT_MESSAGE_BYTES_PER_SECOND,
        clock=clock,
    )


_DEADLINE_REASON = "a message did not arrive within timeout_seconds plus its data set"


# --- The deadline's arithmetic, on a clock the test owns ----------------------------------------


def test_a_message_has_timeout_seconds_plus_its_data_set_at_the_floor() -> None:
    clock = _Clock()
    tally = _tally(clock)
    floor = dicom_module._DEFAULT_MESSAGE_BYTES_PER_SECOND
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
    monkeypatch.setattr(dicom_module, "_DEFAULT_MESSAGE_BYTES_PER_SECOND", _TEST_FLOOR)
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
    monkeypatch.setattr(dicom_module, "_DEFAULT_MESSAGE_BYTES_PER_SECOND", _TEST_FLOOR)
    captured: list[bytes] = []
    async with _running_scp(
        {"timeout_seconds": 2.0, "max_associations": 1}, captured=captured
    ) as scp:
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10()) == (True, 0)
        assert scp._ended_log.refusals == 0
    assert len(captured) == 1


# --- A link slower than the floor (vault BACKLOG #6637) -------------------------------------------

#: The row's link rate, half the shipped floor. The relay holds a sender to it from the first byte,
#: so a loaded runner can only make the link slower, never faster.
_LINK_BYTES_PER_SECOND = 32 * 1024
#: Inside the band at the two-second timeout below: over ``T * r * f / (f - r)``, about 128 KiB, by
#: enough that the cut lands well before the last fragment; 6.25 s on the link.
_BAND_OBJECT_BYTES = 200 * 1024


def _relay(source: socket.socket, sink: socket.socket, rate: int | None) -> None:
    """Copy ``source`` to ``sink``, at most ``rate`` bytes a second from the first byte."""
    sent, began = 0, time.monotonic()
    with contextlib.suppress(OSError):
        while data := source.recv(1024 if rate else 65536):
            if rate:
                sent += len(data)
                time.sleep(max(0.0, began + sent / rate - time.monotonic()))
            sink.sendall(data)
    for end in (source, sink):
        with contextlib.suppress(OSError):
            end.shutdown(socket.SHUT_RDWR)


@contextlib.contextmanager
def _throttled_link(target_port: int, rate: int) -> Iterator[int]:
    """A loopback port that forwards to ``target_port``, holding the sender's direction to ``rate``."""
    listener = socket.create_server(("127.0.0.1", 0))
    opened: list[socket.socket] = []

    def accept() -> None:
        with contextlib.suppress(OSError):
            while True:
                near, _ = listener.accept()
                far = socket.create_connection(("127.0.0.1", target_port))
                opened.extend((near, far))
                threading.Thread(target=_relay, args=(near, far, rate), daemon=True).start()
                threading.Thread(target=_relay, args=(far, near, None), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    try:
        yield listener.getsockname()[1]
    finally:
        with contextlib.suppress(OSError):
            listener.shutdown(socket.SHUT_RDWR)  # close alone leaves accept() blocked on Linux
        listener.close()
        for end in opened:
            end.close()


async def _send_over_the_link(settings: dict[str, object], data: bytes) -> tuple[list[bytes], int]:
    """One delivery attempt by the engine's own SCU, whose ``timeout_seconds`` covers the object's
    time on the link, so that only the SCP's deadline can cut it. Returns what the SCP stored and
    how many associations it ended."""
    captured: list[bytes] = []
    base: dict[str, object] = {"timeout_seconds": 2.0, "max_pdu_size": 4096}
    async with _running_scp({**base, **settings}, captured=captured) as scp:
        with _throttled_link(scp.sockport, _LINK_BYTES_PER_SECOND) as port:
            scu = _scu(port, timeout_seconds=30.0, called_ae_title=_SCP_AE)
            try:
                await scu.send(_carry(data))
            except DeliveryError:
                assert captured == []
        await _until(lambda: scp._server.active_associations == [])
        return captured, scp._ended_log.refusals


async def test_an_object_in_the_band_is_delivered_once_the_floor_is_set_under_the_link(
    caplog: pytest.LogCaptureFixture,
) -> None:
    data = _big_sr(_BAND_OBJECT_BYTES)
    with caplog.at_level(logging.WARNING, logger=_LOG):
        stored, ended = await _send_over_the_link({}, data)  # CONTROL: the shipped floor cuts it
    assert (stored, ended) == ([], 1)
    lines = [r.getMessage() for r in caplog.records if "ended an" in r.getMessage()]
    assert len(lines) == 1 and _DEADLINE_REASON in lines[0], lines
    assert "min_message_bytes_per_second" in lines[0], "the line names the remedy"
    stored, ended = await _send_over_the_link(
        {"min_message_bytes_per_second": _LINK_BYTES_PER_SECOND // 2}, data
    )
    assert ended == 0
    assert len(stored) == 1
    assert len(stored[0]) >= _BAND_OBJECT_BYTES


def test_the_floor_setting_moves_the_deadline() -> None:
    clock = _Clock()
    tally = dicom_module._ReceiptTally(
        max_data_set_bytes=10 * 1024 * 1024,
        timeout_seconds=30.0,
        min_bytes_per_second=16 * 1024,
        clock=clock,
    )
    assert tally.take(_p_data(0x03, _c_store_command())[6:]) is None
    fragment = b"\x00" * 16384
    assert tally.take(_p_data(0x00, fragment)[6:]) is None
    clock.now += (
        30.0 + 1.0
    )  # a second for its 16 KiB at the setting; a quarter at the shipped floor
    assert tally.take(_p_data(0x00, b"")[6:]) is None
    clock.now += 0.001
    ended = tally.take(_p_data(0x00, b"")[6:])
    assert ended is not None and ended[1].startswith(_DEADLINE_REASON), ended
    assert "16384 bytes a second" in ended[1]


def test_the_shipped_floor_is_unchanged_and_unset_means_it() -> None:
    assert dicom_module._DEFAULT_MESSAGE_BYTES_PER_SECOND == 64 * 1024
    assert _build_scp([])._min_message_bytes_per_second == 64 * 1024


@pytest.mark.parametrize("value", [8 * 1024, "8192", 16 * 1024, 64 * 1024, 1024 * 1024])
def test_the_floor_setting_takes_a_rate_at_or_over_its_minimum(value: object) -> None:
    built = _build_scp([], min_message_bytes_per_second=value)
    assert built._min_message_bytes_per_second == int(str(value))


@pytest.mark.parametrize(
    "value",
    [0, "0", -1, 1, 8 * 1024 - 1, None, "", True, False, 8192.5, float("inf"), float("nan"), "off"],
)
def test_no_value_can_switch_the_per_message_deadline_off(value: object) -> None:
    # The deadline is the slow-sender defence (vault BACKLOG #5080): a site may lower its rate, and
    # no spelling of "off" or of a rate under the minimum builds.
    with pytest.raises(ValueError, match="min_message_bytes_per_second"):
        _build_scp([], min_message_bytes_per_second=value)


@pytest.mark.parametrize("value", [0, 16 * 1024])
def test_the_setting_on_an_outbound_is_refused_rather_than_ignored(value: int) -> None:
    with pytest.raises(ValueError, match="min_message_bytes_per_second"):
        _scu(1, min_message_bytes_per_second=value)


def test_the_factory_passes_the_setting_and_writes_none_it_was_not_given() -> None:
    from messagefoundry.config.wiring import DICOM

    assert "min_message_bytes_per_second" not in DICOM(ae_title="X").settings
    spec = DICOM(ae_title="X", min_message_bytes_per_second=16 * 1024)
    assert spec.settings["min_message_bytes_per_second"] == 16 * 1024


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
    floor_kib = dicom_module._DEFAULT_MESSAGE_BYTES_PER_SECOND // 1024
    assert f"{floor_kib} KiB a second" in doc
    assert "per message, not per association" in doc
    assert "C-ECHO every few seconds" in doc
    assert "`min_message_bytes_per_second`" in doc
