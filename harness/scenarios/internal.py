# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Scenarios for the inbound kinds with no external peer of their own, against
``harness/config/internal.py``: TIMER, PassThrough and Loopback.

None of the three can be injected into directly, so each is driven from its natural source:

- **TIMER** fires on its own clock. Nothing is injected; the scenario starts a File sink, notes
  the time, and waits for timer messages the engine recorded AFTER that time to reach
  ``processed`` and for their archived copies to arrive. The body is fixed config, so matching by
  time rather than by control id is what keeps an earlier run's rows out.
- **PassThrough** is fed by a handler ``Send`` into it. The scenario injects over MLLP at the entry
  inbound, then asserts the RE-INGRESSED record on the PassThrough inbound's own channel, and what
  its handler forwarded to a sink.
- **Loopback** is fed by a capturing outbound's reply (``reingress_to``). The harness sink that
  outbound dials IS the peer, and the ACK it answers with is the message that re-enters on the
  Loopback inbound. The scenario asserts that record's disposition, and that the forwarded copy is
  that ACK (MSA-2 naming the control id sent), not the original message.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass

from harness import drivers, sinks
from harness.endpoints import internal as names
from harness.scenarios._core import (
    _TERMINAL,
    INBOUND,
    BaseScenario,
    Coverage,
    Scenario,
    ScenarioContext,
    ScenarioResult,
    _send_error_suffix,
    control_id_of,
)
from harness.sinks.mllp import MLLPSink
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.parsing import HL7PeekError
from messagefoundry.parsing.message import Message

_PROCESSED = "processed"


@dataclass(frozen=True)
class TimerScenario(BaseScenario):
    """Wait for ``arrivals`` timer messages recorded on ``inbound`` after the scenario started to
    reach ``processed``, and for as many copies carrying ``control_id`` to reach the File sink."""

    name: str
    description: str
    inbound: str = names.TIMER_INBOUND
    control_id: str = names.TIMER_CONTROL_ID
    sink_endpoint: str = "internal_timer_out"
    arrivals: int = 2

    @property
    def covers(self) -> frozenset[Coverage]:
        # Claims only the internal kind. The File and MLLP legs here are asserted, but those rows
        # belong to the coverage scenarios (tests/test_harness_scenarios.py pins their exact lists).
        return frozenset({("timer", INBOUND)})

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        with sinks.build("file", ctx.endpoints, self.sink_endpoint) as sink:
            # The sink ignores files already present, and the clock reading is taken after it
            # started, so neither half can be satisfied by an earlier run. A fire just before this
            # reading can still land its file after the sink started; fires are 2 s apart, so at
            # most one such file counts. received_at is the engine's clock: the harness assumes
            # the engine runs on this host, as every harness endpoint does.
            started = time.time()
            deadline = time.monotonic() + ctx.timeout
            while True:
                try:
                    statuses = self._statuses_since(ctx.client, started)
                except ApiError as exc:
                    return ScenarioResult(self, False, f"API error: {exc}")
                delivered = sum(
                    1 for r in sink.records() if control_id_of(r.payload) == self.control_id
                )
                processed = statuses.count(_PROCESSED)
                done = processed >= self.arrivals and delivered >= self.arrivals
                if done or time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
        others = sorted({s for s in statuses if s in _TERMINAL and s != _PROCESSED})
        ok = processed >= self.arrivals and delivered >= self.arrivals and not others
        detail = (
            f"{processed}/{self.arrivals} timer messages since start reached {_PROCESSED!r} on "
            f"{self.inbound}; {delivered}/{self.arrivals} delivered to the file sink"
        )
        if others:
            detail += f"; other terminal statuses seen: {others}"
        return ScenarioResult(self, ok, detail)

    def _statuses_since(self, client: EngineClient, started: float) -> list[str]:
        # Newest first, one row per 2 s tick: a 200-row page covers a timeout of about 400 s.
        listing = client.list_messages(channel_id=self.inbound, limit=200)
        return [
            m.status
            for m in listing.messages
            if m.received_at >= started and m.control_id == self.control_id
        ]


@dataclass(frozen=True)
class SinkCheck:
    """One MLLP harness sink a hop scenario runs. ``reply`` is what it answers each frame with
    (see :class:`MLLPSink`). With ``expect_ack`` set, each control id must arrive as an ACK whose
    MSA-2 names it; otherwise it must arrive as the message itself (MSH-10)."""

    endpoint: str
    reply: str | None = "AA"
    expect_ack: bool = False

    def arrived(self, payloads: Sequence[bytes], wanted: set[str]) -> set[str]:
        read = _acknowledged_control_id if self.expect_ack else control_id_of
        return {cid for payload in payloads if (cid := read(payload)) in wanted}


def _acknowledged_control_id(payload: bytes) -> str | None:
    """MSA-2 of an HL7 ACK, or None when the payload is not an ACK."""
    try:
        message = Message.parse(payload.decode("utf-8", errors="replace"))
    except HL7PeekError:
        return None
    if message["MSH-9.1"] != "ACK":
        return None
    return message["MSA-2"] or None


@dataclass(frozen=True)
class HopScenario(BaseScenario):
    """Inject ``count`` fresh ``code^trigger`` messages over MLLP at ``entry``; expect each one's
    record on every inbound in ``channels`` to reach ``processed``, and each to arrive at every
    sink in ``sink_checks``. ``kinds`` names the internal inbound kind the hop exercises.

    A channel named in ``by_body`` is matched by reading each record's body instead of by the
    control id the engine recorded, for an inbound whose records carry none (see
    :data:`PASSTHROUGH`)."""

    name: str
    description: str
    entry: str
    channels: tuple[str, ...]
    sink_checks: tuple[SinkCheck, ...]
    kinds: tuple[str, ...]
    by_body: tuple[str, ...] = ()
    code: str = "ADT"
    trigger: str = "A04"
    count: int = 3

    @property
    def covers(self) -> frozenset[Coverage]:
        # The internal kind only, for the reason TimerScenario.covers gives.
        return frozenset((kind, INBOUND) for kind in self.kinds)

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        # Fresh control ids per run, so a long-lived store cannot satisfy this run.
        payloads, control_ids = Scenario(
            self.name, self.description, self.code, self.trigger, self.count
        ).payloads()
        with ExitStack() as stack:
            running = [
                (check, stack.enter_context(_mllp_sink(ctx, check))) for check in self.sink_checks
            ]
            driver = drivers.build("mllp", ctx.endpoints, self.entry)
            started = time.time()
            send_errors = [i.error for i in driver.inject(payloads) if i.error]
            if len(send_errors) == self.count:
                return ScenarioResult(
                    self, False, f"could not send to mllp endpoint {self.entry!r}: {send_errors[0]}"
                )
            ok, detail = self._verify_channels(ctx, control_ids, started)
            wanted = set(control_ids)
            for check, sink in running:
                # Settled channels mean the deliveries are done; a failed one means do not wait.
                records = sink.wait_for(
                    functools.partial(_all_arrived, check, wanted), ctx.timeout if ok else 0.0
                )
                got = check.arrived([r.payload for r in records], wanted)
                what = "ACKs for" if check.expect_ack else "copies of"
                detail += f"; {len(got)}/{len(wanted)} {what} them at sink {check.endpoint}"
                ok = ok and got >= wanted
        return ScenarioResult(self, ok, detail + _send_error_suffix(send_errors))

    def _verify_channels(
        self, ctx: ScenarioContext, control_ids: list[str], started: float
    ) -> tuple[bool, str]:
        statuses: dict[tuple[str, str], str] = {}
        # message id -> MSH-10 of its body; a body never changes, so each is read once.
        body_cids: dict[str, str | None] = {}
        deadline = time.monotonic() + ctx.timeout
        while True:
            try:
                for channel in self.channels:
                    if all(statuses.get((channel, cid)) in _TERMINAL for cid in control_ids):
                        continue  # settled: stop listing (and, by body, re-reading) this channel
                    if channel in self.by_body:
                        found = _statuses_by_body(ctx.client, channel, started, body_cids)
                    else:
                        pending = [
                            cid
                            for cid in control_ids
                            if statuses.get((channel, cid)) not in _TERMINAL
                        ]
                        found = _statuses_by_control_id(ctx.client, channel, pending)
                    statuses.update(((channel, cid), status) for cid, status in found.items())
            except ApiError as exc:
                return False, f"API error: {exc}"
            settled = all(
                statuses.get((channel, cid)) in _TERMINAL
                for channel in self.channels
                for cid in control_ids
            )
            if settled or time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        ok = True
        parts: list[str] = []
        for channel in self.channels:
            seen = [statuses.get((channel, cid)) for cid in control_ids]
            matched = seen.count(_PROCESSED)
            part = f"{channel}: {matched}/{self.count} {_PROCESSED}"
            others = sorted({s for s in seen if s is not None and s != _PROCESSED})
            if others:
                part += f" (seen {others})"
            missing = seen.count(None)
            if missing:
                part += f" ({missing} not found)"
            parts.append(part)
            ok = ok and matched == self.count
        return ok, "; ".join(parts)


def _statuses_by_control_id(
    client: EngineClient, channel: str, control_ids: list[str]
) -> dict[str, str]:
    """Each control id's status on ``channel``, looked up by the control id the engine recorded."""
    found: dict[str, str] = {}
    for cid in control_ids:
        listing = client.list_messages(channel_id=channel, control_id=cid, limit=1)
        if listing.messages:
            found[cid] = listing.messages[0].status
    return found


def _statuses_by_body(
    client: EngineClient, channel: str, started: float, body_cids: dict[str, str | None]
) -> dict[str, str]:
    """Status by control id for ``channel`` records received since ``started``, the control id read
    from each record's BODY. For a channel whose records carry no recorded control id; each body is
    fetched once (an audited read, attributed to the harness) and cached in ``body_cids``."""
    found: dict[str, str] = {}
    for message in client.list_messages(channel_id=channel, limit=200).messages:
        if message.received_at < started:
            continue
        if message.id not in body_cids:
            raw = client.get_message_body(message.id, surface="harness").raw
            body_cids[message.id] = control_id_of(raw.encode("utf-8"))
        cid = body_cids[message.id]
        if cid is not None:
            found[cid] = message.status
    return found


def _all_arrived(check: SinkCheck, wanted: set[str], records: list[sinks.Record]) -> bool:
    return check.arrived([r.payload for r in records], wanted) >= wanted


def _mllp_sink(ctx: ScenarioContext, check: SinkCheck) -> MLLPSink:
    # sinks.build cannot pass ``reply``; the host is MLLPSink's default, sinks.LOOPBACK.
    return MLLPSink(port=ctx.endpoints.port(check.endpoint), reply=check.reply)


TIMER = TimerScenario(
    "internal_timer",
    "TIMER fires a fixed ADT^A08 -> PROCESSED on IB_Internal_Timer, and archived to a file sink",
)

PASSTHROUGH = HopScenario(
    "internal_passthrough",
    "MLLP -> Send into PT_Internal_Relay -> re-ingressed PROCESSED there, and forwarded to a sink",
    entry="internal_pt_in",
    channels=(names.PT_ENTRY_INBOUND, names.PT_INBOUND),
    # The engine records a PassThrough child with no control id (the store inserts it with
    # control_id=None and does not peek the body, unlike a Loopback re-ingress), so the child is
    # found by its body. tests/test_harness_internal.py pins that gap with a strict xfail.
    by_body=(names.PT_INBOUND,),
    sink_checks=(SinkCheck("internal_pt_sink"),),
    kinds=("passthrough",),
)

LOOPBACK = HopScenario(
    "internal_loopback",
    "MLLP -> capturing outbound; the sink's ACK re-enters LB_Internal_Reply -> PROCESSED, forwarded",
    entry="internal_lb_in",
    channels=(names.LB_ENTRY_INBOUND, names.LB_INBOUND),
    sink_checks=(SinkCheck("internal_lb_query"), SinkCheck("internal_lb_reply", expect_ack=True)),
    kinds=("loopback",),
)

SCENARIOS = (TIMER, PASSTHROUGH, LOOPBACK)
