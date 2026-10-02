# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Raw-TCP scenarios against ``harness/config/tcp_x12.py`` (vault BACKLOG #2674).

The TCP inbound there carries ``hl7v2``, so the engine records each message's MSH-10 as its control
id and answers each frame with a framed HL7 ACK. That is what these scenarios verify by: the
disposition per control id over the API, the ACK code the driver got back, and -- through a raw-TCP
sink on ``tcp_out`` -- every byte the outbound delivered.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import uuid4

from harness import drivers
from harness.scenarios._core import (
    Scenario,
    ScenarioContext,
    ScenarioResult,
    _send_error_suffix,
    _verify_dead_letter,
    _verify_disposition,
    control_id_of,
)
from harness.sinks import LOOPBACK, Record
from harness.sinks.tcp import TcpSink
from messagefoundry.apiclient import ApiError
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import PEEK_READ_FAULTS

#: The inbound and outbound the graph names; the dead-letter and NAK checks query them by name.
INBOUND_NAME = "IB_Harness_TCP"
OUTBOUND_NAME = "OB_Harness_TCP"


def ack_code(reply: bytes | None) -> str | None:
    """MSA-1 of a framed HL7 ACK the inbound answered with, or None when there is none."""
    if not reply:
        return None
    try:
        return Message.parse(reply.decode("utf-8", errors="replace"))["MSA-1"] or None
    except PEEK_READ_FAULTS:  # HL7PeekError is a ValueError; a parser fault is the rest of the set
        return None


def verify_delivered_bytes(
    sent: dict[str, bytes], records: list[Record], deliveries: int
) -> tuple[bool, str]:
    """Each sent message (by control id) must have reached the sink exactly ``deliveries`` times,
    and every copy must equal the bytes sent. Returns (ok, detail). Exact, not at least: a
    duplicate delivery on the happy path, or a retry count that drifts from the graph's policy, is
    a finding."""
    arrived: dict[str, list[bytes]] = {}
    for record in records:
        cid = control_id_of(record.payload)
        if cid in sent:
            arrived.setdefault(cid, []).append(record.payload)
    exact = sum(1 for cid in sent if len(arrived.get(cid, [])) == deliveries)
    altered = sum(1 for cid, copies in arrived.items() if any(x != sent[cid] for x in copies))
    copies = sum(len(v) for v in arrived.values())
    detail = f"{exact}/{len(sent)} reached the tcp sink exactly {deliveries}x ({copies} copies)"
    if altered:
        detail += f"; {altered} arrived altered (not byte-for-byte)"
    return exact == len(sent) and not altered, detail


@dataclass(frozen=True)
class TcpScenario(Scenario):
    """A :class:`Scenario` through the raw-TCP driver that also checks what came back.

    ``reply_code`` is the MSA-1 every driver reply must carry (None skips the check). With a sink,
    ``refuse`` makes it close without answering, and every message must reach it exactly
    ``deliveries`` times, each copy byte-for-byte what was sent. A refusing run's ``deliveries`` is
    the graph's ``max_attempts``, so it pins the retry count as well as the dead letter."""

    driver: str = "tcp"
    inbound: str = "tcp_in"
    reply_code: str | None = "AA"
    refuse: bool = False
    deliveries: int = 1

    def __post_init__(self) -> None:
        super().__post_init__()
        # run() stands up a TcpSink itself, so a claim on any other kind would be coverage it never
        # exercises.
        if self.driver != "tcp" or self.sink not in (None, "tcp"):
            raise ValueError(f"scenario {self.name!r}: a TcpScenario drives and sinks tcp only")
        if self.deliveries < 1 or (self.sink is None and (self.refuse or self.deliveries != 1)):
            raise ValueError(f"scenario {self.name!r}: refuse and deliveries need a sink")

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        payloads, control_ids = self.payloads()
        if self.sink is None:
            return self._inject_check_replies(ctx, payloads, control_ids)
        assert self.sink_endpoint is not None
        sink = TcpSink(LOOPBACK, ctx.endpoints.port(self.sink_endpoint), refuse=self.refuse)
        with sink:
            result = self._inject_check_replies(ctx, payloads, control_ids)
            if not result.ok:
                return result
            sent = dict(zip(control_ids, payloads, strict=True))

            def settled(records: list[Record]) -> bool:
                return verify_delivered_bytes(sent, records, self.deliveries)[0]

            records = sink.wait_for(settled, ctx.timeout)
        ok, detail = verify_delivered_bytes(sent, records, self.deliveries)
        return ScenarioResult(self, ok, f"{result.detail}; {detail}")

    def _inject_check_replies(
        self, ctx: ScenarioContext, payloads: list[bytes], control_ids: list[str]
    ) -> ScenarioResult:
        injections = drivers.build(self.driver, ctx.endpoints, self.inbound).inject(payloads)
        send_errors = [i.error for i in injections if i.error]
        if len(send_errors) == self.count:
            return ScenarioResult(
                self, False, f"could not send to tcp endpoint {self.inbound!r}: {send_errors[0]}"
            )
        replies = ""
        if self.reply_code is not None:
            codes = [ack_code(i.reply) for i in injections if not i.error]
            right = sum(1 for code in codes if code == self.reply_code)
            replies = f"; {right}/{len(codes)} replies were {self.reply_code}"
            if right != len(codes):
                return ScenarioResult(
                    self, False, replies[2:] + f"; codes seen: {sorted(set(map(str, codes)))}"
                )
        if self.expect == "dead_letter":
            verified = _verify_dead_letter(self, ctx.client, control_ids, ctx.timeout, send_errors)
        else:
            verified = _verify_disposition(self, ctx.client, control_ids, ctx.timeout, send_errors)
        return ScenarioResult(self, verified.ok, verified.detail + replies)


@dataclass(frozen=True)
class TcpNakScenario(TcpScenario):
    """Frames that are not HL7 at all. The inbound cannot parse them, so it records ERROR before
    any ingress row and answers each with a framed AR NAK. With no MSH there is no control id to
    match, so this verifies by the NAK code per frame plus the inbound's ERROR rows that carry NO
    control id: at least ``count`` new ones must appear. Rows with a control id (a handler error on
    a parsed message, such as ``tcp_handler_error``) cannot count towards it; other unparseable
    traffic sent at the same moment could, so the row half is a lower bound and the NAK half is the
    per-frame check."""

    reply_code: str | None = "AR"

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        payloads = [f"NOT-HL7 harness frame {uuid4().hex}".encode() for _ in range(self.count)]
        try:
            before = self._unparsed_error_ids(ctx)
        except ApiError as exc:
            return ScenarioResult(self, False, f"API error: {exc}")
        injections = drivers.build(self.driver, ctx.endpoints, self.inbound).inject(payloads)
        send_errors = [i.error for i in injections if i.error]
        codes = [ack_code(i.reply) for i in injections if not i.error]
        naks = sum(1 for code in codes if code == self.reply_code)
        detail = f"{naks}/{self.count} frames answered {self.reply_code}" + _send_error_suffix(
            send_errors
        )
        new = 0
        deadline = time.monotonic() + ctx.timeout
        while True:
            try:
                new = len(self._unparsed_error_ids(ctx) - before)
            except ApiError as exc:
                return ScenarioResult(self, False, f"{detail}; API error: {exc}")
            if new >= self.count or time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        detail += f"; {new} new ERROR row(s) without a control id on {INBOUND_NAME}"
        return ScenarioResult(self, naks == self.count and new >= self.count, detail)

    @staticmethod
    def _unparsed_error_ids(ctx: ScenarioContext) -> set[str]:
        """Ids of the newest ERROR rows on the inbound that carry no control id (nothing parsed)."""
        listing = ctx.client.list_messages(channel_id=INBOUND_NAME, status="error", limit=500)
        return {row.id for row in listing.messages if not row.control_id}


SCENARIOS = (
    TcpScenario(
        "tcp_delivered",
        "ADT^A04 over STX/ETX TCP -> AA ACK, PROCESSED, relayed byte-for-byte to a tcp sink",
        "ADT",
        "A04",
        3,
        "processed",
        sink="tcp",
        sink_endpoint="tcp_out",
    ),
    TcpScenario(
        "tcp_handler_error",
        "ADT^A03 over TCP -> AA ACK on receipt, then the handler raises -> ERROR",
        "ADT",
        "A03",
        2,
        "error",
    ),
    TcpNakScenario(
        "tcp_not_hl7_nak",
        "a frame that is not HL7 -> framed AR NAK, and an ERROR row with no control id",
        "ADT",
        "A04",
        2,
        "error",
    ),
    TcpScenario(
        "tcp_dead_letter",
        "ADT^A01 to a tcp sink that closes without replying -> retried, then dead-lettered",
        "ADT",
        "A01",
        2,
        "dead_letter",
        dead_letter_destination=OUTBOUND_NAME,
        sink="tcp",
        sink_endpoint="tcp_out",
        refuse=True,
        deliveries=3,  # OB_Harness_TCP's RetryPolicy(max_attempts=3)
    ),
)
