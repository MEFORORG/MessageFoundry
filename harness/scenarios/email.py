# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Email scenarios against ``harness/config/email.py``: what the ``Email`` outbound submits to an
SMTP peer, and what the engine does when that peer refuses the recipient.

Both inject through the email graph's MLLP entry inbound, but neither claims MLLP coverage: the MLLP
rows belong to the coverage graph's scenarios, and what these assert is the SMTP side. They claim
``("email", "outbound")`` only, by asserting what the email sink received (or refused).
"""

from __future__ import annotations

from dataclasses import dataclass

from harness.scenarios._core import (
    OUTBOUND,
    BaseScenario,
    Coverage,
    Scenario,
    ScenarioContext,
    ScenarioResult,
    control_id_of,
)
from harness.sinks import LOOPBACK, Record
from harness.sinks.email import KIND, EmailSink, parse
from messagefoundry.apiclient import ApiError, EngineClient

#: The graph's sender and recipients. ``harness/config/email.py`` spells the same literals (a graph
#: imports nothing from the harness); ``tests/test_harness_email.py`` holds the two equal.
SENDER = "engine@harness.invalid"
RECIPIENT = "clinic@harness.invalid"
REFUSED_RECIPIENT = "refused@harness.invalid"


def body_control_id(record: Record) -> str | None:
    """MSH-10 of the plain-text body of a recorded submission, or None when it carries no HL7."""
    part = parse(record).get_body(("plain",))
    if part is None:
        return None
    content = part.get_content()
    if not isinstance(content, str):
        return None
    return control_id_of(content.encode("utf-8"))


@dataclass(frozen=True)
class EmailScenario(BaseScenario):
    """Inject ``count`` ADT^``trigger`` messages at ``inbound`` with an email sink listening on
    ``sink_endpoint``, then assert one of two outcomes.

    ``delivered``: each message reaches PROCESSED, and the sink holds exactly one submission per
    control id, from ``SENDER`` to exactly ``recipient``, on the envelope and in the To header.

    ``rejected``: the sink answers 550 at RCPT for ``recipient``, each message is dead-lettered for
    ``dead_letter_destination``, every attempt the dead letters record met a refusal, and nothing of
    this run reached DATA. It holds whether the engine retries a 550 or dead-letters it at once.
    """

    name: str
    description: str
    trigger: str
    outcome: str  # delivered | rejected
    recipient: str
    count: int = 3
    dead_letter_destination: str | None = None
    inbound: str = "email_in"
    sink_endpoint: str = "email_smtp"

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError(f"scenario {self.name!r} must send at least one message")
        if self.outcome not in ("delivered", "rejected"):
            raise ValueError(f"scenario {self.name!r} has unknown outcome {self.outcome!r}")
        if self.outcome == "rejected" and not self.dead_letter_destination:
            raise ValueError(f"scenario {self.name!r} expects a refusal but names no destination")

    @property
    def covers(self) -> frozenset[Coverage]:
        return frozenset({(KIND, OUTBOUND)})

    def _shape(self) -> Scenario:
        """The generic scenario these messages are: it generates the payloads, injects them and runs
        the API verifier. This class adds only the sink and what the sink must have seen."""
        return Scenario(
            self.name,
            self.description,
            "ADT",
            self.trigger,
            self.count,
            "dead_letter" if self.outcome == "rejected" else "processed",
            inbound=self.inbound,
            dead_letter_destination=self.dead_letter_destination,
        )

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        shape = self._shape()
        payloads, control_ids = shape.payloads()
        reject = (self.recipient,) if self.outcome == "rejected" else ()
        port = ctx.endpoints.port(self.sink_endpoint)
        with EmailSink(LOOPBACK, port, reject=reject) as sink:
            verdict = shape._inject_and_verify(ctx, payloads, control_ids)
            if not verdict.ok:
                return ScenarioResult(self, False, verdict.detail)
            if self.outcome == "rejected":
                return self._check_refused(sink, ctx.client, control_ids, verdict.detail)
            return self._check_delivered(sink, control_ids, ctx.timeout, verdict.detail)

    def _check_delivered(
        self, sink: EmailSink, control_ids: list[str], timeout: float, prior: str
    ) -> ScenarioResult:
        wanted = set(control_ids)

        def mine(records: list[Record]) -> list[tuple[str, Record]]:
            return [(cid, r) for r in records if (cid := body_control_id(r) or "") in wanted]

        records = sink.wait_for(lambda rs: {cid for cid, _ in mine(rs)} >= wanted, timeout)
        found = mine(records)
        got = {cid for cid, _ in found}
        detail = f"{prior}; {len(got)}/{len(wanted)} mailed to the email sink"
        if got < wanted:
            return ScenarioResult(self, False, detail)
        if len(found) != len(wanted):
            # A loopback run that retried nothing has nothing to explain a second copy, so a
            # duplicate here is a regression (a doubled Send, say), not at-least-once at work.
            return ScenarioResult(
                self, False, f"{detail}, but {len(found)} submissions for {len(wanted)} messages"
            )
        for cid, record in found:
            envelope = (record.meta.get("mail_from"), record.meta.get("rcpt_to"))
            if envelope != (SENDER, self.recipient):
                return ScenarioResult(
                    self,
                    False,
                    f"{detail}; {cid}: envelope {envelope}, expected {(SENDER, self.recipient)}",
                )
            header_to = str(parse(record).get("To", ""))
            if header_to != self.recipient:
                return ScenarioResult(
                    self,
                    False,
                    f"{detail}; {cid}: To header {header_to!r}, expected {self.recipient!r}",
                )
        return ScenarioResult(self, True, f"{detail}, each from {SENDER} to {self.recipient}")

    def _check_refused(
        self, sink: EmailSink, client: EngineClient, control_ids: list[str], prior: str
    ) -> ScenarioResult:
        """Every delivery attempt the dead letters record must have met a 550 at the sink. Comparing
        the refusals to the ATTEMPTS, not to the message count, stops one message's retries from
        covering for another that was dead-lettered for some other reason."""
        wanted = set(control_ids)
        try:
            dead = client.list_dead_letters(
                destination_name=self.dead_letter_destination, limit=500
            )
        except ApiError as exc:
            return ScenarioResult(self, False, f"{prior}; API error: {exc}")
        attempts = sum(d.attempts for d in dead.dead_letters if d.control_id in wanted)
        # The sink matches recipients case-insensitively, so count them the same way. A refusal
        # carries no control id (RCPT comes before DATA), so this is a count, and a long-lived engine
        # still retrying an older run's rows can only raise it, never satisfy it falsely low.
        refused = [r for r in sink.rejections() if r.recipient.lower() == self.recipient.lower()]
        detail = (
            f"{prior}; {attempts} delivery attempt(s), the sink refused {self.recipient} "
            f"{len(refused)} time(s)"
        )
        if attempts < self.count or len(refused) < attempts:
            return ScenarioResult(self, False, f"{detail}: an attempt did not end in the 550")
        leaked = [r for r in sink.records() if body_control_id(r) in wanted]
        if leaked:
            return ScenarioResult(self, False, f"{detail}; but {len(leaked)} reached DATA")
        return ScenarioResult(self, True, detail)


SCENARIOS = (
    EmailScenario(
        "email_delivered",
        "ADT^A08 mailed by OB_Harness_Email: a submission per message at the email sink",
        "A08",
        "delivered",
        RECIPIENT,
    ),
    EmailScenario(
        "email_rejected_recipient",
        "ADT^A31 to a recipient the sink refuses (550 at RCPT) -> every attempt refused, dead-lettered",
        "A31",
        "rejected",
        REFUSED_RECIPIENT,
        count=2,
        dead_letter_destination="OB_Harness_Email_Rejected",
    ),
)
