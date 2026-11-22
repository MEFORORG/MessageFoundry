# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: a captured reply whose body does not decrypt (BACKLOG #4995).

A reply owed to a loopback is a ``Stage.RESPONSE`` token whose ``payload`` references the
``response`` artifact. The re-ingress step reads that artifact's body before the handoff, and a
body that failed to decrypt raised ``CipherError`` out of the step. The worker's fault arm then
re-pended the token at the head of the loopback lane, where it failed again on every pass, so no
later reply on that lane would ever have re-ingressed.

Each case drives the real re-ingress step over a keyed store, with a bad reply at the head of the
lane and a good one behind it. The good one is the control: "the token went DEAD" is also what a
step that dead-letters everything looks like.

Extra-free on the ``_erased_reply_contract`` precedent, so the gated Postgres and SQL Server suites
run the same bodies. ``fetch`` and ``raw`` run one query with ``?`` placeholders outside the store.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Awaitable, Callable, Iterator, Mapping
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.cell_tag import message_cell_aad
from messagefoundry.store.crypto import (
    AADComponentError,
    CipherError,
    CipherUnavailableError,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import QueueOpenFault
from tests._erased_reply_contract import BODY, LOOP, RAW, REPLY, children, status_of
from tests._queue_tag_contract import RawFetch, RawSql, _handoff
from tests._store_audit import no_operator_audit

#: Rewrites the bad origin's ``response.body`` cell so it no longer opens. Takes ``(fetch, raw,
#: bad_mid, good_mid)``.
Spoil = Callable[[RawFetch, RawSql, str, str], Awaitable[None]]
#: One BACKLOG #5727 case, over a keyed store. Takes ``(store, fetch, raw)``.
ContractCase = Callable[[Any, RawFetch, RawSql], Awaitable[None]]


def runner(store: Any) -> RegistryRunner:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            LOOP, Loopback(), router="route_loop", content_type=ContentType.HL7V2
        )
    )
    reg.add_router("route_loop", lambda msg: [])
    return RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )


async def captured(store: Any, *, control: str, now: float, reply: str = REPLY) -> str:
    """A delivered message whose captured reply owes a re-ingress to the loopback. Returns its id."""
    mid = await store.enqueue_message(
        channel_id="IB_REAL", raw=RAW, deliveries=[("OB_X", BODY)], control_id=control, now=now
    )
    [item] = await store.claim_ready(destination_name="OB_X", now=now)
    await store.complete_with_response(
        item.id, body=reply, outcome="accepted", reingress_to=LOOP, now=now
    )
    return str(mid)


async def token_of(fetch: RawFetch, message_id: str) -> dict[str, Any]:
    rows = await fetch(
        "SELECT id, status, payload FROM queue WHERE message_id=? AND stage=?",
        (message_id, Stage.RESPONSE.value),
    )
    assert len(rows) == 1, rows
    return rows[0]


async def spoil_with_a_wrong_cell(fetch: RawFetch, raw: RawSql, bad: str, good: str) -> None:
    """The good reply's sealed body, planted in the bad reply's cell: its tag fails under a key
    this store holds, the shape a tampered or misplaced cell takes."""
    [row] = await fetch("SELECT body FROM response WHERE message_id=?", (good,))
    await raw("UPDATE response SET body=? WHERE message_id=?", (row["body"], bad))


async def spoil_with_a_foreign_key(_fetch: RawFetch, raw: RawSql, bad: str, _good: str) -> None:
    """The right cell, sealed under a key this store was never given. A real unsupplied key would
    also fail the token's payload, sealed in the same transaction, and the claim dead-letters
    that first; this builds the body-only case to pin the arm for a key the store does not hold."""
    foreign = make_cipher(generate_key(), write_v2=True)
    sealed = foreign.encrypt(REPLY, aad=cell_aad("response", "body", bad, "OB_X", 1))
    await raw("UPDATE response SET body=? WHERE message_id=?", (sealed, bad))


async def spoil_with_a_corrupt_marker(_fetch: RawFetch, raw: RawSql, bad: str, _good: str) -> None:
    """A marked value in a format no reader knows: the cipher's plain ``CipherError``, not the
    unauthenticated subclass the other two raise."""
    await raw("UPDATE response SET body=? WHERE message_id=?", ("mfenc:v9:not-a-cell", bad))


async def assert_lane_moves_past_an_undecryptable_reply(
    store: Any, fetch: RawFetch, raw: RawSql, spoil: Spoil
) -> None:
    bad = await captured(store, control="UR-BAD", now=1.0)
    good = await captured(store, control="UR-GOOD", now=2.0)
    await spoil(fetch, raw, bad, good)
    before = await token_of(fetch, bad)

    step = runner(store)
    for _ in range(2):
        item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
        assert item is not None
        await step._process_response_item(LOOP, item)  # the bad head must not raise
    assert await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value) is None

    # The bad token: dead with its reference kept, and ERROR on its origin. No child.
    after = await token_of(fetch, bad)
    assert after["status"] == OutboxStatus.DEAD.value
    assert after["payload"] == before["payload"] and after["payload"] != ""
    assert await status_of(store, bad) == MessageStatus.ERROR.value
    events = await store.events_for(bad)
    assert [e for e in events if e["event"] == "dead" and "undecryptable" in str(e["detail"])]

    # The control behind it re-ingressed: the lane moved.
    assert await status_of(store, good) == MessageStatus.PROCESSED.value
    [child] = await children(fetch)
    message = await store.get_message(child["id"])
    assert message is not None and message["raw"] == REPLY

    # The kept reference leaves the token replayable once the cause is fixed. Here it is not, so
    # the replayed token dead-letters again rather than holding the lane.
    assert await store.replay(bad, now=4.0, audit=no_operator_audit) == 1
    item = await store.claim_next_fifo(LOOP, now=5.0, stage=Stage.RESPONSE.value)
    assert item is not None
    await step._process_response_item(LOOP, item)
    assert (await token_of(fetch, bad))["status"] == OutboxStatus.DEAD.value
    assert len(await children(fetch)) == 1


SPOILS: list[Spoil] = [
    spoil_with_a_wrong_cell,
    spoil_with_a_foreign_key,
    spoil_with_a_corrupt_marker,
]


# BACKLOG #5727: what the handoff contains, and what it must not.


class FaultingCipher:
    """The store's real cipher, except that opening ``target`` raises ``open_error`` and, once
    ``seal_error`` is set, every seal raises it."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.target: str | None = None
        self.open_error: Exception | None = None
        self.seal_error: Exception | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def decrypt(self, stored: Any, *args: Any, **kwargs: Any) -> Any:
        if self.open_error is not None and stored == self.target:
            raise self.open_error
        return self._real.decrypt(stored, *args, **kwargs)

    def encrypt(self, *args: Any, **kwargs: Any) -> Any:
        if self.seal_error is not None:
            raise self.seal_error
        return self._real.encrypt(*args, **kwargs)

    def heal(self) -> None:
        self.open_error = self.seal_error = None


@contextlib.contextmanager
def faulting_cipher(store: Any) -> Iterator[FaultingCipher]:
    real = store._cipher
    fault = FaultingCipher(real)
    store._cipher = fault
    try:
        yield fault
    finally:
        store._cipher = real


async def _plant_metadata(cipher: Any, raw: RawSql, mid: str) -> None:
    """Seal a valid origin metadata cell for ``mid`` under ``cipher``."""
    sealed = cipher.encrypt(
        '{"correlation_depth": 0}',
        aad=message_cell_aad("metadata", message_id=mid, channel_id="IB_REAL"),
    )
    await raw("UPDATE messages SET metadata=? WHERE id=?", (sealed, mid))


async def _claimed_head(store: Any) -> tuple[str, Any]:
    mid = await captured(store, control="HO-HEAD", now=1.0)
    item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
    assert item is not None and item.message_id == mid
    return mid, item


async def _cell(fetch: RawFetch, which: str, mid: str) -> str:
    if which == "ref":
        value = (await token_of(fetch, mid))["payload"]
    else:
        sql = {
            "reply": "SELECT body AS v FROM response WHERE message_id=?",
            "metadata": "SELECT metadata AS v FROM messages WHERE id=?",
        }[which]
        [row] = await fetch(sql, (mid,))
        value = row["v"]
    assert value, which  # a blank cell is never opened, so the fault would not fire
    return str(value)


async def _assert_token_live(store: Any, fetch: RawFetch, mid: str) -> None:
    """Still claimed, with nothing recorded against it: no dead-letter, no child, no ERROR."""
    assert (await token_of(fetch, mid))["status"] == OutboxStatus.INFLIGHT.value
    assert not [e for e in await store.events_for(mid) if e["event"] == "dead"]
    [origin] = await fetch("SELECT status FROM messages WHERE id=?", (mid,))
    assert origin["status"] != MessageStatus.ERROR.value
    assert await children(fetch) == []


def _open_fault_propagates(
    which: str, error: type[CipherError], raised: type[Exception] | None = None
) -> ContractCase:
    async def case(store: Any, fetch: RawFetch, raw: RawSql) -> None:
        mid, item = await _claimed_head(store)
        if which == "metadata":  # a captured message carries none, and NULL is never opened
            await _plant_metadata(store._cipher, raw, mid)
        target = await _cell(fetch, which, mid)
        with faulting_cipher(store) as fault:
            fault.target, fault.open_error = target, error("synthetic")
            with pytest.raises(raised or error) as caught:
                await _handoff(store, item.id, LOOP)
            if raised is not None:  # the raw key-service error must not reach the fault log
                assert caught.value.__cause__ is None and caught.value.__context__ is None
            await _assert_token_live(store, fetch, mid)
            # CONTROL: the same token hands off once the fault clears, so it was the fault.
            fault.heal()
            assert await _handoff(store, item.id, LOOP) is True
        assert len(await children(fetch)) == 1

    case.__name__ = f"handoff_{which}_{error.__name__}_propagates"
    return case


async def worker_read_outage_retries(store: Any, fetch: RawFetch, _raw: RawSql) -> None:
    """The worker's own read of the reply, ahead of the handoff."""
    mid, item = await _claimed_head(store)
    step = runner(store)
    target = await _cell(fetch, "reply", mid)
    with faulting_cipher(store) as fault:
        fault.target, fault.open_error = target, CipherUnavailableError("synthetic")
        with pytest.raises(QueueOpenFault) as caught:
            await step._process_response_item(LOOP, item)
        assert caught.value.__cause__ is None and caught.value.__context__ is None
        await _assert_token_live(store, fetch, mid)
        fault.heal()
        await step._process_response_item(LOOP, item)
    assert len(await children(fetch)) == 1


#: A reply the HL7 loopback's peek refuses, so the worker holds a bounded view of it as well.
REFUSED_REPLY = "SYNTHETIC-REFUSED-REPLY not an HL7 message"
#: A reply with its MSH fields in place, and the control id and message type the worker peeks.
PEEKED_REPLY = "MSH|^~\\&|PARTNER|F|R|RF|20260101||ACK^A01|RSPCTRL|P|2.5.1\rMSA|AA|OUT1\r"
PEEKED_VALUES = ("RSPCTRL", "ACK^A01")


def _holds(value: Any, needles: tuple[str, ...], depth: int = 4) -> bool:
    """Whether ``value``, or a container or dataclass field inside it, holds one of ``needles``."""
    if isinstance(value, str):
        return any(needle in value for needle in needles)
    if isinstance(value, bytes | bytearray):
        return any(needle.encode() in value for needle in needles)
    if depth == 0:
        return False
    if isinstance(value, Mapping):
        return any(
            _holds(k, needles, depth - 1) or _holds(v, needles, depth - 1) for k, v in value.items()
        )
    if isinstance(value, list | tuple | set | frozenset):
        return any(_holds(v, needles, depth - 1) for v in value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return any(
            _holds(getattr(value, f.name, None), needles, depth - 1)
            for f in dataclasses.fields(value)
        )
    return False


def _engine_frames_holding(
    fault: BaseException, needles: tuple[str, ...]
) -> tuple[list[str], list[str]]:
    """The engine frames ``fault``'s traceback passes through, and those with a local holding one
    of ``needles`` as ``function:local``. This module's own frames hold the reply by design."""
    walked: list[str] = []
    holding: list[str] = []
    tb = fault.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if frame.f_code.co_filename != __file__:
            walked.append(frame.f_code.co_name)
            holding += [
                f"{frame.f_code.co_name}:{name}"
                for name, value in frame.f_locals.items()
                if _holds(value, needles)
            ]
        tb = tb.tb_next
    return walked, holding


def _fault_reaches_no_reply(which: str, *, reply: str = PEEKED_REPLY) -> ContractCase:
    """A no-verdict fault at ``which`` leaves the step with no chain to the key-service error and
    no traceback frame holding the reply or a value peeked from it. ``worker`` is the step's own
    read; the others are the handoff's opens, after the step has read the reply."""

    async def case(store: Any, fetch: RawFetch, raw: RawSql) -> None:
        needles = (reply, *PEEKED_VALUES) if reply == PEEKED_REPLY else (reply,)
        # CONTROL: the instrument finds the reply in the shapes the step holds it in.
        assert _holds({"k": [reply]}, needles) and not _holds({"k": ["other"]}, needles)
        mid = await captured(store, control="FR-HEAD", now=1.0, reply=reply)
        item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
        assert item is not None and item.message_id == mid
        if which == "metadata":
            await _plant_metadata(store._cipher, raw, mid)
        target = await _cell(fetch, "reply" if which == "worker" else which, mid)
        step = runner(store)
        real_handoff = store.ingress_handoff
        with faulting_cipher(store) as fault:

            def arm() -> None:
                fault.target, fault.open_error = target, CipherUnavailableError("synthetic")

            async def armed_handoff(**kwargs: Any) -> bool:
                arm()  # after the step's own read, which opens the same reference and reply
                produced: bool = await real_handoff(**kwargs)
                return produced

            if which == "worker":
                arm()
            store.ingress_handoff = armed_handoff
            try:
                with pytest.raises(QueueOpenFault) as caught:
                    await step._process_response_item(LOOP, item)
            finally:
                del store.ingress_handoff
            assert caught.value.__cause__ is None and caught.value.__context__ is None
            walked, holding = _engine_frames_holding(caught.value, needles)
            assert "_process_response_item" in walked  # the frame that read the reply was walked
            assert holding == []
            await _assert_token_live(store, fetch, mid)
            # CONTROL: the same token re-ingresses once the fault clears.
            fault.heal()
            await step._process_response_item(LOOP, item)
        assert len(await children(fetch)) == 1

    suffix = "" if reply == PEEKED_REPLY else "_refused"
    case.__name__ = f"fault_at_{which}{suffix}_reaches_no_reply"
    return case


async def seal_failure_stays_a_hard_stop(store: Any, fetch: RawFetch, _raw: RawSql) -> None:
    """The encrypt's invocation ceiling is a plain ``CipherError`` and is not contained."""
    mid, item = await _claimed_head(store)
    with faulting_cipher(store) as fault:
        fault.seal_error = CipherError("synthetic invocation ceiling")
        with pytest.raises(CipherError, match="invocation ceiling"):
            await _handoff(store, item.id, LOOP)
        fault.heal()
    await _assert_token_live(store, fetch, mid)


async def origin_under_an_unheld_key_dead_letters(store: Any, fetch: RawFetch, raw: RawSql) -> None:
    """A good reply whose origin metadata is sealed under a key this store does not hold. CONTROL:
    the good token behind it re-ingresses, so the handoff did not dead-letter everything."""
    bad = await captured(store, control="HO-BAD", now=1.0)
    good = await captured(store, control="HO-GOOD", now=2.0)
    await _plant_metadata(make_cipher(generate_key(), write_v2=True), raw, bad)
    before = await token_of(fetch, bad)
    step = runner(store)
    for _ in range(2):
        item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
        assert item is not None
        await step._process_response_item(LOOP, item)  # the bad head must not raise
    after = await token_of(fetch, bad)
    assert after["status"] == OutboxStatus.DEAD.value
    assert after["payload"] == before["payload"] and after["payload"] != ""
    # Read raw: a keyed get_message would refuse the spoiled metadata cell itself.
    [origin] = await fetch("SELECT status FROM messages WHERE id=?", (bad,))
    assert origin["status"] == MessageStatus.ERROR.value
    events = await store.events_for(bad)
    assert [
        e for e in events if e["event"] == "dead" and "metadata undecryptable" in str(e["detail"])
    ]
    assert await status_of(store, good) == MessageStatus.PROCESSED.value
    assert len(await children(fetch)) == 1


async def tampered_reply_in_the_handoff_dead_letters(
    store: Any, fetch: RawFetch, raw: RawSql
) -> None:
    """A wrong cell under a key this store holds is a verdict, not an outage. Driven through the
    handoff alone, as a reply spoiled after the worker's read would reach it."""
    bad = await captured(store, control="HO-BAD", now=1.0)
    good = await captured(store, control="HO-GOOD", now=2.0)
    await spoil_with_a_wrong_cell(fetch, raw, bad, good)
    item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
    assert item is not None and item.message_id == bad
    assert await _handoff(store, item.id, LOOP) is True
    assert (await token_of(fetch, bad))["status"] == OutboxStatus.DEAD.value
    events = await store.events_for(bad)
    assert [e for e in events if e["event"] == "dead" and "reply undecryptable" in str(e["detail"])]
    assert await children(fetch) == []


HANDOFF_CASES: list[ContractCase] = [
    origin_under_an_unheld_key_dead_letters,
    tampered_reply_in_the_handoff_dead_letters,
    worker_read_outage_retries,
    seal_failure_stays_a_hard_stop,
    _open_fault_propagates("ref", CipherUnavailableError, QueueOpenFault),
    _open_fault_propagates("reply", CipherUnavailableError, QueueOpenFault),
    _open_fault_propagates("metadata", CipherUnavailableError, QueueOpenFault),
    _open_fault_propagates("reply", AADComponentError),
    _fault_reaches_no_reply("worker"),
    _fault_reaches_no_reply("ref"),
    _fault_reaches_no_reply("reply"),
    _fault_reaches_no_reply("metadata"),
    _fault_reaches_no_reply("ref", reply=REFUSED_REPLY),
    _fault_reaches_no_reply("reply", reply=REFUSED_REPLY),
    _fault_reaches_no_reply("metadata", reply=REFUSED_REPLY),
]
