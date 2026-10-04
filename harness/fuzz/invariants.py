# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The invariants a fuzz campaign checks, each one a property CLAUDE.md section 2 states.

**What "ACKed" means here.** A reply frame is an *acknowledgement* when it parses as HL7, its
MSH-9.1 is ``ACK`` and its MSA-1 is one of the six codes (AA AE AR CA CE CR). Two invariants read
acknowledgements, at two strengths, because the engine gives two different guarantees:

* A **positive** acknowledgement (AA or CA) is sent only after ``enqueue_ingress`` commits a row
  carrying the message's control id (ACK-on-receipt). So for each one, the control id the ACK
  echoes in MSA-2 must name a stored row -- a NEW one, when the campaign could predict that id and
  count its rows before sending -- with a disposition. This is the per-message check.
* A **negative** acknowledgement (AE AR CE CR) is sent after the decode, NUL, parse or strict path
  has recorded an ERROR row, but the decode and parse paths record it with no control id, because
  none could be read. So a NAK cannot be matched to its row. It is counted instead: across each
  batch the store must grow by at least the number of acknowledgements of either kind. That lower
  bound holds under unrelated traffic, which only adds rows.

The MLLP transport reads every reply frame until the engine closes, so a case carrying two frames is
counted twice, not once with a surplus row that would hide a missing one later.

Replies are counted against frames. The engine's listener answers every complete frame it decodes,
so an exchange must carry exactly one acknowledgement per complete frame sent (counted with the same
decoder), then a clean close; an incomplete frame owes nothing, so a case whose framing a mutation
broke may end in silence. An inbound configured with ``ack_mode = "none"`` never answers and is not
a target for the MLLP transport. A timeout, a reset, a refused connection, a reply cut off
mid-frame, bytes outside a reply frame or a reply that is not an acknowledgement breaks the reply
invariant. Any API call answering 5xx breaks the API invariant, and ``/health`` must answer ``ok``.

Nothing here quotes a message or reply body: problems name codes, counts and control ids.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

from harness.fuzz.transport import CLOSED, REPLY, Exchange
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.parsing import Peek
from messagefoundry.parsing.peek import PEEK_READ_FAULTS

ACK_CODES = frozenset({"AA", "AE", "AR", "CA", "CE", "CR"})
POSITIVE = frozenset({"AA", "CA"})

#: Every disposition the store records (``MessageStatus``), spelled as the API returns them. The
#: harness may not import the store; ``tests/test_harness_fuzz.py`` holds the two equal.
DISPOSITIONS = frozenset(
    {"received", "routed", "processed", "error", "filtered", "unrouted", "not_deployed"}
)

#: The API's control-id filter accepts at most this many printable characters (api/validation.py).
_MAX_QUERYABLE = 256

#: How much of a control id goes into a printed line.
_SHOWN = 40

#: Back-off for a 429 from the API's per-actor read limit (120 reads a minute by default): long
#: enough in total to outlast one 60-second window, so a rate limit slows a campaign down rather
#: than failing it.
_RATE_LIMIT_WAITS = (1.0, 2.0, 4.0, 8.0, 16.0, 32.0)

#: Between reads while waiting for a row to appear; slow enough not to spend the read limit.
_POLL_SECONDS = 0.25


class ApiFault(Exception):
    """An engine API call failed while the campaign ran.

    ``invariant`` is True for a 5xx, and for no answer at all (``status`` None), which mid-campaign
    means the engine stopped answering. A 4xx (an expired token, a rate limit that outlasted the
    back-off) says nothing about the engine's invariants and is reported as a setup failure."""

    def __init__(self, what: str, exc: ApiError) -> None:
        self.status = exc.status
        self.invariant = exc.status is None or exc.status >= 500
        if exc.status is not None and exc.status >= 500:
            label = f"returned {exc.status} (5xx)"
        else:
            label = f"failed: {exc}"
        super().__init__(f"{what} {label}")


def api[T](what: str, call: Callable[[], T]) -> T:
    """Run one API call, waiting out a 429, and turn an ApiError into an :class:`ApiFault`."""
    for wait in (*_RATE_LIMIT_WAITS, None):
        try:
            return call()
        except ApiError as exc:
            if exc.status != 429 or wait is None:
                raise ApiFault(what, exc) from exc
        time.sleep(wait)
    raise AssertionError("unreachable")  # pragma: no cover -- the loop returns or raises


@dataclass(frozen=True)
class Ack:
    """One acknowledgement: MSA-1 and MSA-2."""

    code: str
    control_id: str | None

    @property
    def positive(self) -> bool:
        return self.code in POSITIVE


@dataclass(frozen=True)
class Judgement:
    """An exchange held to the reply invariant. ``problem`` is empty when it holds."""

    acks: tuple[Ack, ...] = ()
    problem: str = ""


def judge(exchange: Exchange, *, expected: int | None) -> Judgement:
    """Hold an exchange to the reply invariant: one acknowledgement per complete frame sent, then a
    clean close. ``expected`` is that frame count, or None for a transport that cannot say."""
    acks: list[Ack] = []
    for reply in exchange.replies:
        ack, problem = _read_ack(reply)
        if problem:
            return Judgement(tuple(acks), problem)
        assert ack is not None
        acks.append(ack)
    if exchange.outcome not in (REPLY, CLOSED):
        return Judgement(tuple(acks), f"{exchange.outcome}: {exchange.detail}")
    if expected is not None and len(acks) != expected:
        return Judgement(
            tuple(acks),
            f"{expected} complete frame(s) sent but {len(acks)} acknowledgement(s) came back",
        )
    return Judgement(tuple(acks))


def _read_ack(reply: bytes) -> tuple[Ack | None, str]:
    try:
        peek = Peek.parse(reply.decode("utf-8", errors="replace"))
        message_code, msa1, msa2 = peek.message_code, peek.field("MSA-1"), peek.field("MSA-2")
    except PEEK_READ_FAULTS as exc:  # HL7PeekError is a ValueError
        return None, f"reply does not parse as HL7 ({type(exc).__name__})"
    if message_code != "ACK":
        return None, f"reply is not an ACK (MSH-9.1 {shown(message_code)})"
    if msa1 is None or msa1 not in ACK_CODES:
        return None, f"reply MSA-1 is not an acknowledgement code ({shown(msa1)})"
    return Ack(msa1, msa2 or None), ""


def queryable(control_id: str) -> bool:
    """Whether the API's control-id filter can ask for ``control_id`` (printable, bounded)."""
    return 0 < len(control_id) <= _MAX_QUERYABLE and not any(
        ch <= "\x1f" or "\x7f" <= ch <= "\x9f" for ch in control_id
    )


def rows_for(client: EngineClient, control_id: str) -> int:
    """How many stored messages carry ``control_id``."""
    query = partial(client.list_messages, control_id=control_id, limit=1)
    return api("GET /messages?control_id", query).total


def store_total(client: EngineClient) -> int:
    """How many messages the store holds, every status and connection."""
    return api("GET /messages", lambda: client.list_messages(limit=1)).total


def check_health(client: EngineClient) -> str:
    """Empty when ``/health`` answers ``ok``; otherwise the problem."""
    status = api("GET /health", client.health).status
    return "" if status == "ok" else f"/health answered {shown(status)}"


def check_stored(client: EngineClient, control_id: str, before: int, settle: float) -> str:
    """Empty when more than ``before`` stored rows carry ``control_id``, the newest with a
    disposition. Polls for up to ``settle`` seconds: ACK-on-receipt makes the row visible before
    the ACK, so a deploying site's store should need none of it."""
    deadline = time.monotonic() + settle
    query = partial(client.list_messages, control_id=control_id, limit=1)
    while True:
        listing = api("GET /messages?control_id", query)
        if listing.total > before and listing.messages:
            status = listing.messages[0].status
            if status in DISPOSITIONS:
                return ""
            return f"control id {shown(control_id)} is stored with unknown status {shown(status)}"
        if time.monotonic() >= deadline:
            have = f"{listing.total} row(s), {before} before the send"
            return f"positively ACKed control id {shown(control_id)} is not in the store ({have})"
        time.sleep(_POLL_SECONDS)


def shown(value: str | None) -> str:
    """A short, quoted rendering of an identifier for a failure reason, its characters kept raw.

    Raw on purpose: ``Failure.reason`` keeps the value as the peer sent it, and what prints it
    escapes it once, by the shared rule (ASVS 1.1.2): at least ``campaign._Session._fail`` for a
    failure line and ``cli.fail_setup`` for a :class:`~harness.fuzz.campaign.SetupError` built from
    :func:`check_health`. A new sink for a reason must escape it the same way. Escaping here too, as
    ``ascii()`` did, had the failure line escape the escape, so a real ESC printed as the text
    ``\\\\x1b``. The quote is chosen as ``repr`` chooses it, so a value holding one kind still sits
    inside a closed span; a value holding both kinds cannot, and reads as it came."""
    if value is None:
        return "None"
    text = value if len(value) <= _SHOWN else value[:_SHOWN] + "..."
    quote = '"' if "'" in text and '"' not in text else "'"
    return f"{quote}{text}{quote}"
