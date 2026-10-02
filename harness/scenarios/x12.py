# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""X12 scenarios against ``harness/config/tcp_x12.py`` (vault BACKLOG #2674).

**The engine records no control id for an X12 message.** A non-HL7 inbound commits its body
verbatim with ``control_id=None`` (``RegistryRunner._handle_inbound``, the ADR 0004 payload-agnostic
branch), so the per-control-id lookup the HL7 scenarios use cannot find these rows. The interchange
does carry its own identity, ISA13, and every run sends fresh ones. So these scenarios list the X12
inbound's newest messages, open the body of each one not seen before (``GET /messages/{id}/raw``,
an audited read naming the ``harness`` surface), read its ISA13, and keep the rows whose ISA13 this
run sent. The body is read only to take ISA13 and is never logged or put in a result.

That is honest under concurrent traffic with one limit: the listing is a newest-first page, so a
burst of other traffic large enough to push this run's rows off it would read as "not found",
never as a false pass.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

from harness import drivers
from harness.drivers._x12_interchange import fresh_control_number, interchange
from harness.scenarios._core import (
    _TERMINAL,
    INBOUND,
    OUTBOUND,
    BaseScenario,
    Coverage,
    ScenarioContext,
    ScenarioResult,
    _send_error_suffix,
)
from harness.sinks import LOOPBACK, Record
from harness.sinks.x12 import X12Sink, isa13_of
from messagefoundry.apiclient import ApiError, EngineClient

INBOUND_NAME = "IB_Harness_X12"
OUTBOUND_NAME = "OB_Harness_X12"

#: The API's own ceiling on one page of GET /messages.
_MAX_PAGE = 500


class X12Rows:
    """Maps this run's ISA13s to the engine's message rows on one inbound, opening each new row's
    body at most once.

    :attr:`by_isa13` is rebuilt from the current page on every refresh, so a row that has left the
    page reads as not found rather than keeping a stale status. Call :meth:`snapshot` BEFORE
    injecting: the rows already on the page are then never opened, so a run reads the bodies of
    its own rows (and of anything sent alongside it), not of a long-lived store's history."""

    def __init__(self, client: EngineClient, channel: str, wanted: Iterable[str]) -> None:
        self.client = client
        self.channel = channel
        self.wanted = set(wanted)
        self._isa13_by_id: dict[str, str | None] = {}
        self.by_isa13: dict[str, tuple[str, str]] = {}  # ISA13 -> (message id, status)

    @property
    def _page(self) -> int:
        return min(_MAX_PAGE, max(100, 4 * len(self.wanted)))

    def snapshot(self) -> None:
        """Mark every row on the page now as not this run's, without opening any body."""
        listing = self.client.list_messages(channel_id=self.channel, limit=self._page)
        self._isa13_by_id.update(dict.fromkeys((row.id for row in listing.messages), None))

    def refresh(self) -> None:
        listing = self.client.list_messages(channel_id=self.channel, limit=self._page)
        self.by_isa13 = {}
        for row in listing.messages:
            if row.id not in self._isa13_by_id:
                body = self.client.get_message_body(row.id, surface="harness")
                self._isa13_by_id[row.id] = isa13_of(body.raw)
            control = self._isa13_by_id[row.id]
            if control in self.wanted:
                self.by_isa13[control] = (row.id, row.status)


@dataclass(frozen=True)
class X12Scenario(BaseScenario):
    """Send ``count`` synthetic interchanges (fresh ISA13s) through the X12 driver and expect each to
    reach ``expect`` -- ``processed`` / ``error`` / ``dead_letter`` (for the graph's X12 outbound).

    ``corrupt`` sends envelopes whose IEA02 disagrees with ISA13. With ``sink_ta1`` set, an X12 sink
    answering that TA104 listens on ``x12_out`` for the whole run, and every interchange must reach
    it ``deliveries`` times, byte-for-byte. A dead-letter run also requires the engine to report
    exactly ``deliveries`` attempts per row, which with ``deliveries=1`` pins that a TA1*R is a
    permanent reject and is not retried."""

    name: str
    description: str
    count: int = 3
    expect: str = "processed"  # processed | error | dead_letter
    corrupt: bool = False
    sink_ta1: str | None = None
    deliveries: int = 1
    inbound: str = "x12_in"
    sink_endpoint: str = "x12_out"

    def __post_init__(self) -> None:
        if not 1 <= self.count <= _MAX_PAGE // 4:
            raise ValueError(f"scenario {self.name!r}: count must be 1..{_MAX_PAGE // 4}")
        if self.expect not in ("processed", "error", "dead_letter"):
            raise ValueError(f"scenario {self.name!r}: unknown expect {self.expect!r}")
        if self.expect == "dead_letter" and self.sink_ta1 is None:
            raise ValueError(f"scenario {self.name!r}: a dead-letter run needs a sink to refuse")

    @property
    def covers(self) -> frozenset[Coverage]:
        pairs: set[Coverage] = {("x12", INBOUND)}
        if self.sink_ta1 is not None:
            pairs.add(("x12", OUTBOUND))
        return frozenset(pairs)

    def payloads(self) -> tuple[list[bytes], list[str]]:
        controls: list[str] = []
        while len(controls) < self.count:
            control = fresh_control_number()
            if control not in controls:
                controls.append(control)
        return [interchange(c, corrupt_trailer=self.corrupt) for c in controls], controls

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        payloads, controls = self.payloads()
        if self.sink_ta1 is None:
            return self._inject_and_verify(ctx, payloads, controls)
        sink = X12Sink(LOOPBACK, ctx.endpoints.port(self.sink_endpoint), ta1=self.sink_ta1)
        with sink:
            result = self._inject_and_verify(ctx, payloads, controls)
            if not result.ok:
                return result
            sent = dict(zip(controls, payloads, strict=True))

            def settled(records: list[Record]) -> bool:
                return verify_interchanges(sent, records, self.deliveries)[0]

            records = sink.wait_for(settled, ctx.timeout)
        ok, detail = verify_interchanges(sent, records, self.deliveries)
        return ScenarioResult(self, ok, f"{result.detail}; {detail}")

    def _inject_and_verify(
        self, ctx: ScenarioContext, payloads: list[bytes], controls: list[str]
    ) -> ScenarioResult:
        rows = X12Rows(ctx.client, INBOUND_NAME, controls)
        try:
            rows.snapshot()
        except ApiError as exc:
            return ScenarioResult(self, False, f"API error: {exc}")
        injections = drivers.build("x12", ctx.endpoints, self.inbound).inject(payloads)
        send_errors = [i.error for i in injections if i.error]
        if len(send_errors) == self.count:
            return ScenarioResult(
                self, False, f"could not send to x12 endpoint {self.inbound!r}: {send_errors[0]}"
            )
        suffix = _send_error_suffix(send_errors)
        try:
            if self.expect == "dead_letter":
                return self._verify_dead_letter(ctx, rows, suffix)
            return self._verify_disposition(ctx, rows, suffix)
        except ApiError as exc:
            return ScenarioResult(self, False, f"API error: {exc}")

    def _verify_disposition(
        self, ctx: ScenarioContext, rows: X12Rows, suffix: str
    ) -> ScenarioResult:
        deadline = time.monotonic() + ctx.timeout
        while True:
            rows.refresh()
            statuses = [status for _, status in rows.by_isa13.values()]
            done = len(statuses) == self.count and all(s in _TERMINAL for s in statuses)
            if done or time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        matched = sum(1 for s in statuses if s == self.expect)
        detail = f"{matched}/{self.count} interchanges reached {self.expect!r} (by ISA13)" + suffix
        if matched != self.count:
            missing = self.count - len(statuses)
            if missing:
                detail += f"; {missing} not found within {ctx.timeout:g}s"
            if statuses:
                detail += f"; statuses seen: {sorted(set(statuses))}"
        return ScenarioResult(self, matched == self.count, detail)

    def _verify_dead_letter(
        self, ctx: ScenarioContext, rows: X12Rows, suffix: str
    ) -> ScenarioResult:
        dead: dict[str, int] = {}  # message id -> attempts
        deadline = time.monotonic() + ctx.timeout
        while True:
            rows.refresh()
            ours = {mid for mid, _ in rows.by_isa13.values()}
            listing = ctx.client.list_dead_letters(destination_name=OUTBOUND_NAME, limit=500)
            dead = {d.message_id: d.attempts for d in listing.dead_letters if d.message_id in ours}
            if len(dead) >= self.count or time.monotonic() >= deadline:
                break
            time.sleep(0.3)
        detail = (
            f"{len(dead)}/{self.count} of this run's interchanges dead-lettered for "
            f"{OUTBOUND_NAME} (attempts: {sorted(set(dead.values()))})" + suffix
        )
        attempts_ok = set(dead.values()) <= {self.deliveries}
        if not attempts_ok:
            detail += f"; expected {self.deliveries} attempt(s) each"
        return ScenarioResult(self, len(dead) >= self.count and attempts_ok, detail)


def verify_interchanges(
    sent: dict[str, bytes], records: list[Record], deliveries: int
) -> tuple[bool, str]:
    """Each sent interchange (by ISA13) must have reached the sink exactly ``deliveries`` times,
    every copy equal to the bytes sent. Returns (ok, detail)."""
    arrived: dict[str, list[bytes]] = {}
    for record in records:
        control = isa13_of(record.payload)
        if control in sent:
            arrived.setdefault(control, []).append(record.payload)
    exact = sum(1 for c in sent if len(arrived.get(c, [])) == deliveries)
    altered = sum(1 for c, copies in arrived.items() if any(x != sent[c] for x in copies))
    detail = f"{exact}/{len(sent)} reached the x12 sink exactly {deliveries}x"
    if altered:
        detail += f"; {altered} arrived altered (not byte-for-byte)"
    return exact == len(sent) and not altered, detail


SCENARIOS = (
    X12Scenario(
        "x12_delivered",
        "X12 interchanges -> PROCESSED, relayed verbatim to an x12 sink that answers TA1*A",
        count=3,
        expect="processed",
        sink_ta1="A",
    ),
    X12Scenario(
        "x12_envelope_rejected",
        "an X12 envelope whose IEA02 does not match ISA13 -> the handler raises -> ERROR",
        count=2,
        expect="error",
        corrupt=True,
    ),
    X12Scenario(
        "x12_ta1_reject_dead_letter",
        "X12 to a sink answering TA1*R -> permanent reject, dead-lettered after one attempt",
        count=2,
        expect="dead_letter",
        sink_ta1="R",
    ),
)
