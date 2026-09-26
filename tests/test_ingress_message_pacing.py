# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 2.4.1 / 15.2.2 — message-rate pacing on the raw-TCP, X12 and HTTP intakes (BACKLOG #1114).

The pacer was built for MLLP and reachable there alone. Measured at ``2b8bccb4``:
``MLLP(port=1, max_messages_per_second=10)`` constructed while ``Tcp``, ``X12``, ``Http``, ``DICOM``
and ``File`` each raised ``TypeError`` on the same keyword, and ``transports/mllp.py`` carried every
pacer hit in the package against zero in the sibling connectors. So four listen intakes had no rate
control **in any configuration** — not off, unavailable.

This file covers the three that got it. **The load-bearing test is not that pacing happens**; it is
:func:`test_tcp_pacing_never_drops_a_message` and its two siblings — every message a paced sender
sends still arrives, in order. The count-and-log invariant forbids accept-and-drop, so a limiter that
discarded would pass a "rate is bounded" assertion while breaking the thing that matters.

**The off default is ruled, not accidental** (``mllp.py`` ``DEFAULT_MAX_MESSAGES_PER_SECOND``, ruled
2026-08-11): a rate on a clinical interface is only safe at a number from a real feed profile. This
work changed REACHABILITY, never the default, and :func:`test_a_default_install_still_has_no_rate_bound`
is what stops the port turning into a flip.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from _ingress_pace_probe import (
    install_ingress_pace_probe,
    listener_waits,
    stream_debt_seconds,
)

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import http_listener, tcp, x12
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.mllp import _MessagePacer
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source

# --- fixtures: PHI-free synthetic payloads -------------------------------------------------------

_STX, _ETX = 0x02, 0x03


def _tcp_frame(payload: str) -> bytes:
    """One ``stx_etx``-framed message, the raw-TCP connector's default framing."""
    return bytes([_STX]) + payload.encode("utf-8") + bytes([_ETX])


def _isa(control: str) -> str:
    """A fixed-length (106-char) ISA header with delimiters ``* ^ : ~``, version 00501."""
    el = "*"
    segment = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + "SENDERID".ljust(15)
        + el
        + "ZZ"
        + el
        + "RECEIVERID".ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + "^"
        + el
        + "00501"
        + el
        + control
        + el
        + "0"
        + el
        + "P"
        + el
        + ":"
    )
    assert len(segment) == 105, f"ISA pre-terminator length {len(segment)} (want 105)"
    return segment + "~"


def _interchange(control: str) -> str:
    """A complete, synthetic, PHI-free 270 eligibility interchange (one GS, one ST)."""
    return (
        _isa(control)
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*270*0001~"
        + "BHT*0022*13*10001234*20240101*1200~"
        + "HL*1**20*1~"
        + "SE*4*0001~"
        + "GE*1*1~"
        + f"IEA*1*{control}~"
    )


# --- source builders (raw settings; the factory surface is exercised separately below) ------------


def _tcp_source(**settings: object) -> TcpSource:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0, "framing": "stx_etx"}
    base.update(settings)
    return TcpSource(Source(name="IB_TCP", type=ConnectorType.TCP, settings=base))


def _x12_source(**settings: object) -> X12Source:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0}
    base.update(settings)
    return X12Source(Source(name="IB_X12", type=ConnectorType.X12, settings=base))


def _http_source(**settings: object) -> HttpSource:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0}
    base.update(settings)
    return HttpSource(Source(name="IB_HTTP", type=ConnectorType.HTTP, settings=base))


# --- the shipped default: OFF, on every one of the three -----------------------------------------


def test_a_default_install_still_has_no_rate_bound() -> None:
    """The port must not flip the ruled-off default on any intake it reaches.

    Pinned per connector rather than once, because each reads the key itself: a connector that
    defaulted its own fallback to a number would ship a guessed rate on a clinical interface, which
    the 2026-08-11 ruling judged worse than the unbounded intake it would be guarding.
    """
    assert _tcp_source().max_messages_per_second is None
    assert _x12_source().max_messages_per_second is None
    assert _http_source().max_messages_per_second is None
    assert _http_source()._pacer is None, "no bound configured must mean no pacer object at all"


@pytest.mark.parametrize("build", [_tcp_source, _x12_source, _http_source])
def test_burst_defaults_to_one_seconds_worth(build: Any) -> None:
    """Setting only the rate must not leave the burst at zero, which would pace the first message."""
    src = build(max_messages_per_second=25)
    assert src.max_messages_per_second == 25.0
    assert src.message_burst == 25.0


@pytest.mark.parametrize("build", [_tcp_source, _x12_source, _http_source])
def test_an_explicit_burst_is_honoured(build: Any) -> None:
    assert build(max_messages_per_second=25, message_burst=100).message_burst == 100.0


# --- the stream intakes (raw TCP, X12): end to end on a real socket -------------------------------
#
# One harness, because TcpSource and X12Source differ only in the bytes that make a frame. The HTTP
# harness below is genuinely separate: it opens a connection per request and reads a status back.


async def _run_stream(src: TcpSource | X12Source, frames: list[bytes]) -> tuple[list[bytes], float]:
    """Write every frame down ONE connection; return what the handler got and the elapsed seconds.

    Elapsed comes back with the payloads so one paced run answers both questions a caller has --
    that nothing was dropped, and that the box really slept off the waits its pacer decided. Running
    the same 0.5s scenario twice to ask them separately would buy nothing but a slower suite.
    """
    seen: list[bytes] = []
    done = asyncio.Event()

    async def handler(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) == len(frames):
            done.set()
        return None

    loop = asyncio.get_running_loop()
    await src.start(handler)
    start = loop.time()
    _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        for chunk in frames:
            writer.write(chunk)
        await writer.drain()
        # Bounded, not polled: the pacer DELAYS, so waiting is expected and a timeout is the bug.
        await asyncio.wait_for(done.wait(), 20.0)
    except TimeoutError:
        pass  # let the assertion in the caller report what actually arrived
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        await src.stop()
    return seen, loop.time() - start


# 12 messages, burst 2, 20/s -> exactly (12-2)/20 = 0.5s of debt.
#
# **The timing arms below read the pacer's own arithmetic, not a constant (BACKLOG #1538).** They
# used to assert `elapsed >= 0.3`, and elapsed seconds are pacing plus the runner's work with nothing
# to tell them apart: a box slow enough to spend 0.3s framing twelve messages passed with the pacer
# deleted. Raising the constant does not fix it, because the debt SHRINKS as the runner slows -- the
# bucket refills on the same wall clock the work is spent on -- so a higher floor turns into a false
# red on exactly the hosts a lower one is vacuous on. `tests/_ingress_pace_probe.py` puts the bucket
# on a clock the test owns, which takes the runner out of the arithmetic and makes the schedule exact.
#
# Two arms per site, and each catches what the other cannot. The DECISION arm says the wait came from
# pacing rather than from work; the WALL-CLOCK arm, bounded by what that run decided rather than by a
# constant, says the box actually slept it off.
_PACED: dict[str, float] = {"max_messages_per_second": 20.0, "message_burst": 2.0}
#: Derived from `_PACED` rather than restated. Spelling the pair twice lets somebody move the burst
#: on the connector while the timing arms keep checking a scenario it is no longer running.
_RATE, _BURST = _PACED["max_messages_per_second"], _PACED["message_burst"]
_MESSAGES = 12


async def test_tcp_pacing_never_drops_a_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE test for this control on raw TCP. A paced sender is SLOWED, never truncated.

    Rate 20/s with burst 2 against 12 messages guarantees the pacer engages. Every message must still
    reach the handler, and in order -- pacing must not reorder either, since FIFO is the project's
    ordering model.
    """
    probe = install_ingress_pace_probe(monkeypatch, tcp)
    frames = [_tcp_frame(f"MSG-{i}") for i in range(_MESSAGES)]
    seen, elapsed = await _run_stream(_tcp_source(**_PACED), frames)
    assert [b.decode() for b in seen] == [f"MSG-{i}" for i in range(_MESSAGES)]
    assert probe.built == 1, "the probe never replaced the pacer this intake builds"
    assert sum(probe.decided) == pytest.approx(stream_debt_seconds(_MESSAGES, _BURST, _RATE))
    assert elapsed >= sum(probe.taken)


async def test_tcp_pacing_off_delivers_everything_unchanged() -> None:
    frames = [_tcp_frame(f"MSG-{i}") for i in range(12)]
    seen, _ = await _run_stream(_tcp_source(), frames)
    assert len(seen) == 12


async def test_x12_pacing_never_drops_an_interchange(monkeypatch: pytest.MonkeyPatch) -> None:
    """A paced X12 partner is slowed, never truncated -- and the interchanges stay in order."""
    probe = install_ingress_pace_probe(monkeypatch, x12)
    frames = [_interchange(f"{i:09d}").encode("utf-8") for i in range(_MESSAGES)]
    seen, elapsed = await _run_stream(_x12_source(**_PACED), frames)
    assert len(seen) == _MESSAGES
    assert [b.decode("utf-8")[90:99] for b in seen] == [f"{i:09d}" for i in range(_MESSAGES)]
    assert probe.built == 1, "the probe never replaced the pacer this intake builds"
    assert sum(probe.decided) == pytest.approx(stream_debt_seconds(_MESSAGES, _BURST, _RATE))
    assert elapsed >= sum(probe.taken)


async def test_x12_pacing_off_delivers_everything_unchanged() -> None:
    frames = [_interchange(f"{i:09d}").encode("utf-8") for i in range(12)]
    seen, _ = await _run_stream(_x12_source(), frames)
    assert len(seen) == 12


# --- HTTP: end to end, where the bucket has to be LISTENER-wide -----------------------------------


async def _post(port: int, body: bytes, *, method: str = "POST") -> int:
    """One request on its own connection (the connector closes after each). Returns the status."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        head = [f"{method} /ingest HTTP/1.1", "Host: localhost"]
        if method in ("POST", "PUT", "PATCH"):
            head.append(f"Content-Length: {len(body)}")
        head.extend(["", ""])
        writer.write("\r\n".join(head).encode("ascii") + (body if method == "POST" else b""))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), 30.0)
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
    return int(data.split(b" ", 2)[1])


async def _run_http(
    src: HttpSource, count: int, *, method: str = "POST", decline: bool = False
) -> tuple[list[bytes], int]:
    """Send ``count`` requests, each on its own connection, and return the bodies + last status.

    ``decline`` makes the handler refuse every body, as the runner does after recording ERROR."""
    seen: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        seen.append(raw)
        return None if decline else f"msg-{len(seen)}"

    await src.start(handler)
    status = 0
    try:
        for i in range(count):
            status = await _post(src.sockport, f"BODY-{i}".encode(), method=method)
    finally:
        await src.stop()
    return seen, status


async def test_http_pacing_never_drops_a_message() -> None:
    """THE test for this control on HTTP. Every paced POST is still committed and still answered.

    Nothing is refused: the partner waits and is then served in full, so the ``202`` receipt is
    delayed rather than replaced by a rejection. A limiter that answered ``429`` instead would move
    the loss outside the boundary the count-and-log invariant covers.
    """
    seen, status = await _run_http(_http_source(**_PACED), _MESSAGES)
    assert [b.decode() for b in seen] == [f"BODY-{i}" for i in range(12)]
    assert status == 202


async def test_http_pacing_off_delivers_everything_unchanged() -> None:
    seen, status = await _run_http(_http_source(), 12)
    assert len(seen) == 12
    assert status == 202


async def test_http_pacing_is_listener_wide_not_per_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The property that makes the HTTP pacer real rather than decorative.

    This connector answers exactly ONE request per connection (``build_response`` hardcodes
    ``Connection: close``), so a per-connection bucket would be charged once and thrown away: with
    any burst of 1 or more it could never pace anything, and the knob would read as a rate bound
    while bounding nothing. Twelve requests here arrive on twelve separate connections.

    **The probe states that property directly rather than inferring it from a delay.** One pacer was
    built for the whole listener, and the schedule it decided is the flat run only a bucket carried
    ACROSS those twelve connections can produce -- a fresh bucket per connection would decide nothing
    at all. The wall-clock arm then says the partner really waited.
    """
    probe = install_ingress_pace_probe(monkeypatch, http_listener)
    loop = asyncio.get_running_loop()
    start = loop.time()
    seen, _ = await _run_http(_http_source(**_PACED), _MESSAGES)
    elapsed = loop.time() - start
    assert len(seen) == _MESSAGES
    assert probe.built == 1, "twelve connections must share ONE listener-wide bucket"
    assert probe.decided == pytest.approx(listener_waits(_MESSAGES, _BURST, _RATE))
    assert elapsed >= sum(probe.decided)


async def test_http_health_probes_wait_but_charge_nothing() -> None:
    """A peer that submits no message must not spend the budget of one that does.

    Charging before the read would be the easy shape and the wrong one: it would let anybody who
    opens a connection and sends a probe — or nothing at all — starve the real partners, turning the
    limiter into the denial of service it exists to prevent. So a ``GET``/``HEAD`` probe is subject
    to an outstanding wait but adds no debt of its own.
    """
    src = _http_source(max_messages_per_second=1, message_burst=1)
    assert src._pacer is not None
    seen, status = await _run_http(src, 5, method="GET")
    assert status == 200
    assert seen == [], "a health probe must never reach the ingress handler"
    assert src._pacer.deficit(now=time.monotonic()) == 0.0, "five probes charged the budget"


async def test_a_committed_post_does_charge_the_budget() -> None:
    """Positive control on the test above: if nothing ever charged, that assertion would be vacuous."""
    src = _http_source(max_messages_per_second=1, message_burst=1)
    assert src._pacer is not None
    seen, _ = await _run_http(src, 2)
    assert len(seen) == 2
    assert src._pacer.deficit(now=time.monotonic()) > 0.0


async def test_a_body_refused_at_ingress_still_charges_the_budget() -> None:
    """A body the handler reads, records as ERROR and refuses (answered 422, BACKLOG #1960) cost the
    engine the same work a committed one did, so it spends the budget too. Pinned because the charge
    sits above the 422 branch, and moving it below would stop refused bodies being paced at all."""
    src = _http_source(max_messages_per_second=1, message_burst=1)
    assert src._pacer is not None
    seen, status = await _run_http(src, 2, decline=True)
    assert len(seen) == 2
    assert status == 422
    assert src._pacer.deficit(now=time.monotonic()) > 0.0


# --- the pacer method the HTTP scope needed ------------------------------------------------------


def test_deficit_reports_the_debt_without_charging_for_it() -> None:
    """``deficit`` must be a pure read: repeated calls cannot deepen the debt they report."""
    pacer = _MessagePacer(10.0, 10.0, now=0.0)
    assert pacer.deficit(now=0.0) == 0.0
    pacer.charge(15, now=0.0)  # 10 absorbed by the burst, 5 over at 10/s -> 0.5s owed
    assert pacer.deficit(now=0.0) == pytest.approx(0.5)
    assert pacer.deficit(now=0.0) == pytest.approx(0.5)
    assert pacer.deficit(now=0.0) == pytest.approx(0.5)


def test_deficit_still_refills_with_elapsed_time() -> None:
    """It reads the bucket as of ``now``, so waiting out the debt clears it."""
    pacer = _MessagePacer(10.0, 10.0, now=0.0)
    pacer.charge(15, now=0.0)
    assert pacer.deficit(now=0.5) == 0.0


# --- REACHABILITY: the authoring surfaces that could not populate the pacer -----------------------
#
# Everything above builds a source from a raw settings dict. That is exactly how a control with tests
# stayed unreachable on MLLP for two months (BACKLOG #1249): the tests proved the PACER worked by
# injecting settings the only authoring surface could not produce. These go through the factory on
# purpose, because a connector that reads a key no author can write is not a shipped control.


@pytest.mark.parametrize("name", ["Tcp", "X12", "Http"])
def test_the_factory_now_reaches_the_pacer(name: str) -> None:
    """Measured before this change: each of the three raised ``TypeError`` on both keys."""
    from messagefoundry.config import wiring

    spec = getattr(wiring, name)(port=2575, max_messages_per_second=9.5, message_burst=30.0)
    assert spec.settings["max_messages_per_second"] == 9.5
    assert spec.settings["message_burst"] == 30.0


@pytest.mark.parametrize("transport", ["tcp", "http"])
def test_the_toml_surface_reaches_them_too(transport: str) -> None:
    """``connections.toml`` desugars through the SAME factory — ``return factory(**settings)``, with
    the factory as the schema and no second source of truth. This is what makes that claim checkable
    rather than asserted in a docstring."""
    from messagefoundry.config.connections_file import _TRANSPORTS

    spec = _TRANSPORTS[transport](port=2575, max_messages_per_second=7.0, message_burst=21.0)
    assert spec.settings["max_messages_per_second"] == 7.0
    assert spec.settings["message_burst"] == 21.0


def test_x12_has_no_toml_surface_at_all_which_is_a_separate_gap() -> None:
    """Recorded so the missing ``x12`` row above reads as a measurement, not an oversight.

    ``X12`` is absent from ``_TRANSPORTS`` entirely, so **no** X12 setting is expressible in
    ``connections.toml`` — the pacing keys are not a special case of that, and closing it means
    adding the transport, which is a different decision from this port. The code-first surface
    reaches the pacer on X12 today; the data surface reaches nothing on X12 today.
    """
    from messagefoundry.config.connections_file import _TRANSPORTS

    assert "x12" not in _TRANSPORTS
    assert "tcp" in _TRANSPORTS, "positive control — the map is populated"


@pytest.mark.parametrize("name", ["Tcp", "X12", "Http"])
def test_the_factory_still_rejects_an_unknown_key(name: str) -> None:
    """Positive control on the two tests above. If these factories swallowed arbitrary keyword
    arguments, every assertion there would pass without the parameters existing at all."""
    from messagefoundry.config import wiring

    with pytest.raises(TypeError):
        getattr(wiring, name)(port=2575, mefor_no_such_pacing_key_1114=1.0)


@pytest.mark.parametrize("name", ["Tcp", "X12", "Http"])
def test_the_factory_default_is_still_off(name: str) -> None:
    """Exposing the keys must NOT turn pacing on. If a factory ever defaulted one of these to a
    number, every deployment of that connector would inherit a guessed clinical rate."""
    from messagefoundry.config import wiring

    spec = getattr(wiring, name)(port=2575)
    assert spec.settings["max_messages_per_second"] is None
    assert spec.settings["message_burst"] is None
